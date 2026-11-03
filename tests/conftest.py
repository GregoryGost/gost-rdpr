"""Fixtures for isolated unit/integration tests and real service E2E processes."""

import asyncio
import ctypes
import importlib
import inspect
import json
import logging
import os
import shutil
import socket
import sys
from base64 import urlsafe_b64decode
from contextlib import closing
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

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

_coverage_migration_directories = set()


def normalize_migration_coverage(data, root, directories):
  """Merge identical migration copies and exclude test-owned migration fault code."""
  from coverage import CoverageData

  root = Path(root).resolve()
  directories = {Path(directory).resolve() for directory in directories}
  paths = {}
  for filename in data.measured_files():
    source = Path(filename).resolve()
    if source.is_relative_to(root) or source.parent not in directories:
      paths[filename] = filename
      continue
    original = root / 'migrations' / source.name
    if (
      original.is_file()
      and source.is_file()
      and sha256(original.read_bytes()).digest() == sha256(source.read_bytes()).digest()
    ):
      paths[filename] = str(original)
  if paths == {filename: filename for filename in data.measured_files()}:
    return

  has_arcs = data.has_arcs()
  read = data.arcs if data.has_arcs() else data.lines
  # Preserve even unexecuted files, branch entry/exit arcs, and exact context names.
  contexts = {}
  for context in data.measured_contexts():
    data.set_query_context(context)
    measurements = contexts[context] = {}
    for filename, target in paths.items():
      values = read(filename)
      if values:
        measurements.setdefault(target, set()).update(values)
  data.set_query_contexts(None)
  tracers = {target: data.file_tracer(filename) for filename, target in paths.items()}
  data.erase()
  # A fresh data object also writes the branch/line metadata after the old file is erased.
  replacement = CoverageData(basename=data.data_filename())
  add = replacement.add_arcs if has_arcs else replacement.add_lines
  add({})
  replacement.touch_files(set(paths.values()))
  replacement.add_file_tracers(tracers)
  for context, measurements in contexts.items():
    replacement.set_context(context)
    add(measurements)
  replacement.write()
  replacement.close()
  data.read()


@pytest.hookimpl(wrapper=True, trylast=True)
def pytest_runtestloop(session):
  """Normalize parent data after fixture teardown, before pytest-cov combines children."""
  result = yield
  from coverage import Coverage

  coverage = Coverage.current()
  if coverage is not None:
    coverage.stop()
    normalize_migration_coverage(
      coverage.get_data(), Path(__file__).resolve().parents[1], _coverage_migration_directories
    )
  return result


@pytest.fixture
async def app(tmp_path, monkeypatch):
  """Prevent secret-file reads and production I/O before importing globals."""
  _coverage_migration_directories.add(tmp_path / 'migrations')
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
    database=database,
    resolver=resolver,
    dto=dto,
    settings=config.settings,
    Server=server_dto.DnsServerDto,
    Ip=ip_dto.IpRecordDto,
    ripe=ripe,
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
        message.authority,
        soa_owner,
        'SOA',
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


class ServiceProcess:
  """Run the real entrypoint with disposable settings and graceful shutdown."""

  def __init__(self, root, directory, environment):
    self.root = root
    self.directory = directory
    self.environment = environment
    self.process = None
    self.log_path = directory / 'application.log'
    self.log = None

  def diagnostics(self):
    return self.log_path.read_text(encoding='utf-8', errors='replace') if self.log_path.exists() else ''

  def resource_snapshot(self, application_pid):
    """Read the actual child's CPU time and resident memory from its operating system."""
    assert self.process is not None
    assert self.process.returncode is None
    pid = application_pid
    if sys.platform == 'win32':
      from ctypes import wintypes

      class MemoryCounters(ctypes.Structure):
        _fields_ = [
          ('cb', wintypes.DWORD),
          ('PageFaultCount', wintypes.DWORD),
          ('PeakWorkingSetSize', ctypes.c_size_t),
          ('WorkingSetSize', ctypes.c_size_t),
          ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
          ('QuotaPagedPoolUsage', ctypes.c_size_t),
          ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
          ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
          ('PagefileUsage', ctypes.c_size_t),
          ('PeakPagefileUsage', ctypes.c_size_t),
        ]

      kernel = ctypes.WinDLL('kernel32', use_last_error=True)
      psapi = ctypes.WinDLL('psapi', use_last_error=True)
      kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
      kernel.OpenProcess.restype = wintypes.HANDLE
      kernel.CloseHandle.argtypes = [wintypes.HANDLE]
      kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
      psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
      handle = kernel.OpenProcess(0x1000 | 0x0010, False, pid)
      if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
      try:
        times = [wintypes.FILETIME() for _ in range(4)]
        memory = MemoryCounters()
        memory.cb = ctypes.sizeof(memory)
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
          raise ctypes.WinError(ctypes.get_last_error())
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), ctypes.sizeof(memory)):
          raise ctypes.WinError(ctypes.get_last_error())
        cpu = sum((value.dwHighDateTime << 32) + value.dwLowDateTime for value in times[2:]) / 10_000_000
        return {
          'pid': pid,
          'cpu_seconds': cpu,
          'rss_bytes': memory.WorkingSetSize,
          'peak_rss_bytes': memory.PeakWorkingSetSize,
          'source': 'Windows process APIs',
        }
      finally:
        kernel.CloseHandle(handle)
    if sys.platform.startswith('linux'):
      process_dir = Path('/proc') / str(pid)
      fields = (process_dir / 'stat').read_text(encoding='ascii').rsplit(')', 1)[1].split()
      status = dict(line.split(':', 1) for line in (process_dir / 'status').read_text(encoding='ascii').splitlines())
      cpu = (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
      rss = int(status['VmRSS'].split()[0]) * 1024
      peak_rss = int(status['VmHWM'].split()[0]) * 1024
      return {
        'pid': pid,
        'cpu_seconds': cpu,
        'rss_bytes': rss,
        'peak_rss_bytes': peak_rss,
        'source': 'Linux procfs process counters',
      }
    raise RuntimeError(f'Child resource sampling is not implemented for {sys.platform}')

  async def health_ready(self):
    """Bound a real health request and own its socket across cancellation."""
    loop = asyncio.get_running_loop()
    port = int(self.environment['APP_PORT'])
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as connection:
      connection.setblocking(False)
      async with asyncio.timeout(0.5):
        await loop.sock_connect(connection, ('127.0.0.1', port))
        await loop.sock_sendall(
          connection,
          f'GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n'.encode('ascii'),
        )
        response = bytearray()
        while chunk := await loop.sock_recv(connection, 4096 - len(response) + 1):
          response.extend(chunk)
          if len(response) > 4096:
            return False
        headers, separator, _ = response.partition(b'\r\n\r\n')
        if not separator:
          return False
        status = bytes(headers).split(b'\r\n', 1)[0].split(b' ', 2)
        return len(status) >= 2 and status[0] in {b'HTTP/1.0', b'HTTP/1.1'} and status[1] == b'200'

  async def start(self):
    # The wrapper only converts test-owned stdin into SIGINT; main.py owns the app.
    bootstrap = (
      'import _thread, os, runpy, sys, threading\n'
      'from pathlib import Path\n'
      'from hashlib import sha256\n' + inspect.getsource(normalize_migration_coverage) + '\n'
      'def stop():\n'
      '  os.read(sys.stdin.fileno(), 1)\n'
      '  _thread.interrupt_main()\n'
      'threading.Thread(target=stop, daemon=True).start()\n'
      'coverage = None\n'
      'if os.environ.get("COVERAGE_PROCESS_START"):\n'
      '  import coverage as coverage_module\n'
      '  coverage = coverage_module.Coverage(config_file=os.environ["COVERAGE_PROCESS_START"], data_suffix=True)\n'
      '  coverage.start()\n'
      'try:\n'
      '  runpy.run_path(sys.argv[1], run_name="__main__")\n'
      'except KeyboardInterrupt:\n'
      '  pass\n'
      'finally:\n'
      '  if coverage is not None:\n'
      '    coverage.stop()\n'
      '    normalize_migration_coverage(coverage.get_data(), Path(sys.argv[1]).parent, [Path.cwd() / "migrations"])\n'
      '    coverage.save()\n'
    )
    self.log = self.log_path.open('ab', buffering=0)
    try:
      self.process = await asyncio.create_subprocess_exec(
        sys.executable,
        '-B',
        '-c',
        bootstrap,
        str(self.root / 'main.py'),
        cwd=self.directory,
        env=self.environment,
        stdin=asyncio.subprocess.PIPE,
        stdout=self.log,
        stderr=asyncio.subprocess.STDOUT,
      )
      async with asyncio.timeout(15):
        while True:
          if self.process.returncode is not None:
            raise AssertionError(f'Application exited before readiness:\n{self.diagnostics()}')
          try:
            if await self.health_ready():
              break
          except OSError, TimeoutError:
            pass
          await asyncio.sleep(0.02)
    except BaseException:
      await self.stop(allow_failure=True)
      raise

  @property
  def url(self):
    return f'http://127.0.0.1:{self.environment["APP_PORT"]}'

  async def stop(self, *, allow_failure=False):
    process, self.process = self.process, None
    try:
      if process is None:
        return
      if process.returncode is None:
        try:
          process.stdin.write(b'\n')
          await process.stdin.drain()
        except BrokenPipeError, ConnectionResetError:
          pass
        try:
          await asyncio.wait_for(process.wait(), timeout=15)
        except TimeoutError:
          process.kill()
          await asyncio.wait_for(process.wait(), timeout=5)
          raise AssertionError(f'Application did not shut down gracefully:\n{self.diagnostics()}') from None
      if not allow_failure:
        assert process.returncode == 0, self.diagnostics()
    finally:
      try:
        if process is not None and process.stdin is not None:
          process.stdin.close()
          await process.stdin.wait_closed()
      finally:
        if self.log is not None:
          self.log.close()
          self.log = None


@pytest.fixture
async def e2e_service(tmp_path, dns_message, request):
  """Keep application logic real and replace only external wire protocols."""
  from coverage import Coverage

  root = Path(__file__).resolve().parents[1]
  _coverage_migration_directories.add(tmp_path / 'migrations')
  shutil.copytree(root / 'migrations', tmp_path / 'migrations', ignore=shutil.ignore_patterns('__pycache__'))
  db_path = tmp_path / 'service.sqlite'

  providers = SimpleNamespace(
    classic='positive',
    doh='positive',
    requests=[],
    http_requests=[],
    errors=[],
    classic_addresses=('8.8.8.8',),
    doh_addresses=('8.8.4.4',),
    addresses_by_domain={},
    delay=0.0,
    unavailable=False,
    hold_dns=False,
    dns_entered=asyncio.Event(),
    dns_release=asyncio.Event(),
  )

  def response_wire(query, transport):
    providers.requests.append((transport, query.question[0].name.to_text(), query.question[0].rdtype))
    kind = getattr(providers, transport) if query.question[0].rdtype == dns.rdatatype.A else 'nodata'
    addresses = providers.addresses_by_domain.get(
      (transport, query.question[0].name.to_text()), getattr(providers, f'{transport}_addresses')
    )
    return dns_message(kind, query=query, addresses=addresses).to_wire()

  class DnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
      self.transport = transport

    def datagram_received(self, data, address):
      query = dns.message.from_wire(data)
      wire = response_wire(query, 'classic')
      if providers.delay:
        loop.call_later(providers.delay, self.transport.sendto, wire, address)
      else:
        self.transport.sendto(wire, address)

    def error_received(self, error):
      providers.errors.append(str(error))

  connections = set()

  async def serve_http(reader, writer):
    connections.add(writer)
    try:
      async with asyncio.timeout(5):
        request_line = (await reader.readline()).decode('ascii').split()
        headers = {}
        while line := await reader.readline():
          if line == b'\r\n':
            break
          key, value = line.decode('ascii').split(':', 1)
          headers[key.lower()] = value.strip()
        method, target, _ = request_line
        url = urlsplit(target)
        params = parse_qs(url.query)
        providers.http_requests.append((method, url.path))
        if providers.delay:
          await asyncio.sleep(providers.delay)
        if providers.unavailable:
          return
        if method == 'GET' and url.path == '/dns-query':
          assert headers.get('accept') == 'application/dns-message'
          encoded = params['dns'][0]
          query = dns.message.from_wire(urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
          body = response_wire(query, 'doh')
          if providers.hold_dns:
            providers.dns_entered.set()
            await providers.dns_release.wait()
          media = 'application/dns-message'
        elif method == 'GET' and url.path == '/data/network-info/data.json':
          providers.requests.append(('ripe', params['resource'][0], None))
          body = json.dumps({'status': 'ok', 'data': {'prefix': None}}).encode()
          media = 'application/json'
        else:
          raise AssertionError(f'Unexpected provider request: {method} {target}')
        writer.write(
          f'HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {len(body)}\r\n'
          'Connection: close\r\n\r\n'.encode()
          + body
        )
        await writer.drain()
    except (AssertionError, KeyError, ValueError, TimeoutError) as error:
      providers.errors.append(repr(error))
    finally:
      writer.close()
      await writer.wait_closed()
      connections.discard(writer)

  loop = asyncio.get_running_loop()
  # Classic DNS has no configurable port. A separate loopback address owns port 53.
  dns_host = f'127.{uuid4().int % 254 + 1}.{uuid4().int % 254 + 1}.{uuid4().int % 254 + 1}'
  dns_transport, _ = await loop.create_datagram_endpoint(DnsProtocol, local_addr=(dns_host, 53))
  http_server = None
  service = None
  try:
    http_server = await asyncio.start_server(serve_http, '127.0.0.1', 0)
    provider_url = f'http://127.0.0.1:{http_server.sockets[0].getsockname()[1]}'
    # Reserve an ephemeral address before handing it to the real HTTP server.
    port_reservation = await asyncio.start_server(lambda reader, writer: writer.close(), '127.0.0.1', 0)
    port = port_reservation.sockets[0].getsockname()[1]
    port_reservation.close()
    await port_reservation.wait_closed()
    environment = {key: os.environ[key] for key in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if key in os.environ}
    environment.update(
      {
        'PYTHONPATH': str(root),
        'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHON_DOTENV_DISABLED': '1',
        'APP_HOST': '127.0.0.1',
        'APP_PORT': str(port),
        'APP_LOG_LEVEL': 'error',
        'ROOT_LOG_LEVEL': 'error',
        'DB_BASE_DIR': str(tmp_path),
        'DB_FILE_NAME': db_path.name,
        'DB_TABLE_PREFIX': 'rdpr_',
        'DB_SAVE_BATCH_TIMEOUT': '0.05',
        'DB_SHUTDOWN_TIMEOUT': '5',
        'RIPE_STAT_BASE_URL': provider_url,
        'REQ_CONNECTION_RETRIES': '0',
        'REQ_TIMEOUT_DEFAULT': '2',
        'REQ_TIMEOUT_CONNECT': '2',
        'REQ_TIMEOUT_READ': '2',
      }
    )
    coverage = Coverage.current()
    if coverage is not None:
      environment['COVERAGE_PROCESS_START'] = str(root / 'pyproject.toml')
      environment['COVERAGE_FILE'] = str(Path(coverage.get_option('run:data_file')).resolve())
    elif os.environ.get('COVERAGE_PROCESS_START'):
      environment['COVERAGE_PROCESS_START'] = os.environ['COVERAGE_PROCESS_START']
      if os.environ.get('COVERAGE_FILE'):
        environment['COVERAGE_FILE'] = os.environ['COVERAGE_FILE']
    service = ServiceProcess(root, tmp_path, environment)
    service.db_path = db_path
    service.providers = providers
    service.dns_host = dns_host
    service.doh_url = f'{provider_url}/dns-query'
    if getattr(request, 'param', True):
      await service.start()
    yield service
  finally:
    providers.dns_release.set()
    try:
      if service is not None:
        await service.stop()
    finally:
      dns_transport.close()
      if http_server is not None:
        http_server.close()
        await http_server.wait_closed()
      for writer in tuple(connections):
        writer.close()
        await writer.wait_closed()
      assert providers.errors == []
