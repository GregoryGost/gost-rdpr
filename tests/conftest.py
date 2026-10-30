"""Isolated application imports and deterministic DNS network boundaries."""

import asyncio
import importlib
import logging
from base64 import urlsafe_b64decode
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import dotenv
import httpx
import pytest
from pydantic_settings.sources import DotEnvSettingsSource


@pytest.fixture
async def app(tmp_path, monkeypatch):
  """Prevent secret-file reads and production I/O before importing globals."""
  monkeypatch.setattr(dotenv, 'load_dotenv', lambda *args, **kwargs: False)
  monkeypatch.setattr(DotEnvSettingsSource, '_read_env_files', lambda self: {})
  monkeypatch.setenv('DB_BASE_DIR', str(tmp_path))
  monkeypatch.setenv('DB_FILE_NAME', 'import-only.sqlite')
  monkeypatch.setenv('DB_TABLE_PREFIX', 'rdpr_')
  monkeypatch.setenv('DOMAINS_UPDATE_INTERVAL', '172800')
  monkeypatch.setenv('IP_NOT_ALLOWED', '127.0.0.0/8')
  monkeypatch.setenv('ROOT_LOG_LEVEL', 'error')
  monkeypatch.chdir(tmp_path)

  async def reject_http(*args, **kwargs):
    raise AssertionError('Unexpected real HTTP transport')

  async def reject_dns(*args, **kwargs):
    raise AssertionError('Unexpected real DNS transport')

  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', reject_http)
  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', reject_dns)
  root_logger = logging.getLogger()
  previous_handlers = list(root_logger.handlers)
  previous_level = root_logger.level
  config = importlib.import_module('config.config')
  monkeypatch.setattr(config.settings, 'db_base_dir', str(tmp_path))
  monkeypatch.setattr(config.settings, 'db_file_name', 'isolated.sqlite')
  monkeypatch.setattr(config.settings, 'domains_update_interval', 172800)
  monkeypatch.setattr(config.settings, 'ip_not_allowed', '127.0.0.0/8')
  database = importlib.import_module('database.db')
  resolver = importlib.import_module('client.domains_resolving_client')
  dto = importlib.import_module('models.dto.domains_dto')
  server_dto = importlib.import_module('models.dto.dns_server_dto')
  ip_dto = importlib.import_module('models.dto.ip_record_dto')
  ripe = importlib.import_module('client.ripe_stat_client')
  cache = importlib.import_module('cache.cache').ripe_stat_cache
  await cache.clear()
  clients = []

  def make_http(handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    clients.append(client)
    return client

  value = SimpleNamespace(
    database=database, resolver=resolver, dto=dto, settings=config.settings,
    Server=server_dto.DnsServerDto, Ip=ip_dto.IpRecordDto, ripe=ripe,
    make_http=make_http,
  )
  try:
    yield value
  finally:
    for client in clients:
      await client.aclose()
    await cache.clear()
    await cache.cache.close()
    await resolver.HttpClient.close()
    await database.db._DataBase__read_engine.dispose()
    await database.db._DataBase__write_engine.dispose()
    for handler in root_logger.handlers[:]:
      if handler not in previous_handlers:
        root_logger.removeHandler(handler)
        handler.close()
    root_logger.setLevel(previous_level)


@pytest.fixture
def resolver(app):
  instance = app.resolver.DomainsResolver()
  instance._DomainsResolver__semaphore = asyncio.Semaphore(4)
  instance._DomainsResolver__ripe_stat_semaphore = asyncio.Semaphore(1)
  return instance


@pytest.fixture
def repository(app, monkeypatch):
  boundary = SimpleNamespace(
    get_all_ips_for_domain=AsyncMock(return_value=[]),
    put_domain_after_resolve=AsyncMock(),
    put_add_domains_to_queue=AsyncMock(),
    get_dns_servers_for_resolve=AsyncMock(return_value=([], [])),
  )
  monkeypatch.setattr(app.resolver, 'db', boundary)
  return boundary


@pytest.fixture
def dns_message():
  def build(kind='positive', query=None, addresses=('8.8.8.8',)):
    query = query or dns.message.make_query('www.example.test.', 'A')
    message = dns.message.make_response(query)
    owner = query.question[0].name.to_text()

    def add(section, name, rdtype, *values, rdclass='IN'):
      section.append(dns.rrset.from_text(name, 60, rdclass, rdtype, *values))

    if kind in {'positive', 'positive-unrelated', 'nxdomain-positive'}:
      add(message.answer, owner, 'A', *addresses)
    if kind == 'positive-unrelated':
      add(message.answer, 'stranger.invalid.', 'A', '9.9.9.9')
      add(message.additional, owner, 'A', '1.1.1.1')
      add(message.answer, 'stranger.invalid.', 'CNAME', 'bad.invalid.')
    if kind.startswith('alias') or kind == 'cname-only':
      add(message.answer, owner, 'CNAME', 'edge.example.test.')
    if kind == 'alias-positive':
      add(message.answer, 'edge.example.test.', 'A', *addresses)
    if kind in {'nxdomain', 'alias-nxdomain', 'nxdomain-positive', 'nxdomain-ns'}:
      message.set_rcode(dns.rcode.NXDOMAIN)
    if kind in {'nodata', 'alias-nodata', 'unrelated-negative', 'foreign-soa', 'wrong-soa-class'}:
      soa_owner = 'other.invalid.' if kind == 'foreign-soa' else 'example.test.'
      add(
        message.authority, soa_owner, 'SOA',
        'ns.example.test. hostmaster.example.test. 1 60 60 60 60',
        rdclass='CH' if kind == 'wrong-soa-class' else 'IN',
      )
    if kind == 'unrelated-negative':
      add(message.answer, 'stranger.invalid.', 'A', '9.9.9.9')
    if kind in {'referral', 'nxdomain-ns'}:
      add(message.authority, 'example.test.', 'NS', 'ns.example.test.')
    if kind == 'servfail':
      message.set_rcode(dns.rcode.SERVFAIL)
    if kind == 'refused':
      message.set_rcode(dns.rcode.REFUSED)
    if kind == 'wrong-name':
      message.question = dns.message.make_query('other.invalid.', 'A').question
    if kind == 'wrong-type':
      message.question = dns.message.make_query(owner, 'AAAA').question
    if kind == 'wrong-class':
      message.question = dns.message.make_query(owner, 'A', rdclass='CH').question
    if kind == 'multiple-questions':
      message.question += dns.message.make_query('other.invalid.', 'A').question
    if kind == 'no-question':
      message.question = []
    if kind == 'not-response':
      message.flags &= ~dns.flags.QR
    if kind == 'truncated':
      message.flags |= dns.flags.TC
    if kind == 'wrong-opcode':
      message.set_opcode(dns.opcode.UPDATE)
    if kind == 'alias-cycle':
      add(message.answer, 'edge.example.test.', 'CNAME', owner)
    if kind == 'alias-address-collision':
      add(message.answer, owner, 'A', '8.8.4.4')
    if kind in {'alias-conflict', 'alias-duplicate'}:
      target = 'other.example.test.' if kind == 'alias-conflict' else 'edge.example.test.'
      add(message.answer, owner, 'CNAME', target)
      add(message.answer, 'edge.example.test.', 'A', *addresses)
    if kind == 'aaaa-only':
      add(message.answer, owner, 'AAAA', '2001:4860:4860::8888')
    if kind in {'chain-limit', 'chain-below-limit'}:
      length = dns.message.MAX_CHAIN - (kind == 'chain-below-limit')
      current = owner
      for index in range(length):
        target = f'edge{index}.example.test.'
        add(message.answer, current, 'CNAME', target)
        current = target
      add(message.answer, current, 'A', *addresses)
    return message
  return build


@pytest.fixture
def network(app, resolver, dns_message, monkeypatch):
  """Replace DNS/HTTP I/O, leaving the production classifier untouched."""
  requests = []

  def install(kinds, transport='classic', status=200, media='application/dns-message', mutate_wire=None):
    async def classic(boundary, qname, rdtype, **kwargs):
      requests.append((boundary.nameservers[0], rdtype))
      kind = kinds[boundary.nameservers[0]]
      if isinstance(kind, Exception):
        raise kind
      query = dns.message.make_query(qname, rdtype)
      message = dns_message(kind, query=query)
      wire = message.to_wire()
      message = dns.message.from_wire(wire)
      # Resolver.resolve owns transport validation; expose its response envelope.
      if kind in {'nodata', 'alias-nodata', 'empty', 'referral'}:
        raise dns.resolver.NoAnswer(response=message)
      if kind in {'nxdomain', 'alias-nxdomain'}:
        raise dns.resolver.NXDOMAIN(qnames=[query.question[0].name], responses={query.question[0].name: message})
      return SimpleNamespace(response=message)

    def doh(request):
      encoded = request.url.params['dns']
      query = dns.message.from_wire(urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
      requests.append((str(request.url.copy_with(query=None)), query.question[0].rdtype))
      kind = kinds[str(request.url.copy_with(query=None))]
      if isinstance(kind, Exception):
        raise kind
      assert request.method == 'GET'
      assert request.headers['accept'] == 'application/dns-message'
      message = dns_message(kind, query=query)
      wire = message.to_wire()
      if mutate_wire is not None:
        wire = mutate_wire(wire)
      return httpx.Response(status, headers={'Content-Type': media}, content=wire)

    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
    resolver._DomainsResolver__http_client = app.make_http(doh)
    return requests
  return install
