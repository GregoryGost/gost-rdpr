"""DNS evidence, cycle completeness, and conservative reconciliation."""

import asyncio
import dataclasses
import importlib
import logging
import math
import threading
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpx
import pytest
from prometheus_client import REGISTRY

pytestmark = pytest.mark.unit


def metric_total(name, **labels):
  """Read observable samples without resetting shared process collectors."""
  return sum(
    sample.value
    for family in REGISTRY.collect()
    for sample in family.samples
    if sample.name == name and all(sample.labels.get(key) == str(value) for key, value in labels.items())
  )


class HttpObservations:
  """Record transport notifications independently of Prometheus collectors."""

  def __init__(self, *, fail=False):
    self.events = []
    self.fail = fail

  def __getattr__(self, name):
    def record(*args, **kwargs):
      self.events.append((name, args, kwargs))
      if self.fail:
        raise RuntimeError('Synthetic observer failure')

    return record


@pytest.mark.parametrize(
  ('terminal', 'expected', 'phase'),
  [
    ('eof', 'eof', 'body'),
    ('closed', 'closed', 'close'),
    ('timeout', 'timeout', 'body'),
    ('network', 'network_error', 'body'),
    ('protocol', 'protocol_error', 'body'),
    ('cancelled', 'cancelled', 'body'),
    ('close_error', 'network_error', 'close'),
  ],
)
async def test_http_measurement_preserves_stream_and_exactly_one_terminal(app, monkeypatch, terminal, expected, phase):
  module = importlib.import_module('metrics.httpx_metrics')
  clock = SimpleNamespace(value=100.0)
  monkeypatch.setattr(module, 'perf_counter', lambda: clock.value)
  observations = HttpObservations()
  errors = {
    'timeout': httpx.ReadTimeout('synthetic private timeout'),
    'network': httpx.ReadError('synthetic private network'),
    'protocol': httpx.RemoteProtocolError('synthetic private protocol'),
    'cancelled': asyncio.CancelledError(),
    'close_error': httpx.ReadError('synthetic private cleanup'),
  }
  error = errors.get(terminal)
  touches = []

  class Stream(httpx.AsyncByteStream):
    async def __aiter__(self):
      touches.append('iterate')
      yield b'first\x00'
      clock.value = 109.0
      if error is not None:
        raise error
      yield b'second\xff'

    async def aclose(self):
      touches.append('close')
      clock.value = 113.0
      if terminal == 'close_error':
        raise error

  async def upstream(request):
    assert 'x-request-perf-counter' not in request.headers
    assert request.content == b'unchanged request'
    assert request.url.params['token'] == 'dummy-token'
    clock.value = 102.0
    return httpx.Response(503, stream=Stream())

  transport = module.ObservedAsyncTransport(httpx.MockTransport(upstream), integration='dns', metrics=observations)
  async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
    request = client.build_request(
      'POST', 'https://private.example.test/secret?token=dummy-token', content=b'unchanged request'
    )
    response = await client.send(request, stream=True)
    assert touches == []
    assert [event[0] for event in observations.events] == ['started', 'headers']
    if terminal in {'closed', 'close_error'}:
      if terminal == 'closed':
        await response.aclose()
      else:
        with pytest.raises(type(error)) as failure:
          await response.aclose()
        assert failure.value is error
    elif error is None:
      assert await response.aread() == b'first\x00second\xff'
    else:
      with pytest.raises(type(error)) as failure:
        await response.aread()
      assert failure.value is error
      await response.aclose()
    await response.aclose()
  finished = [event for event in observations.events if event[0] == 'finished']
  assert len(finished) == 1
  values = finished[0][2] or dict(
    zip(('integration', 'duration', 'method', 'status_code', 'phase', 'outcome'), finished[0][1], strict=True)
  )
  assert values['outcome'] == expected
  assert values['phase'] == phase
  assert values['status_code'] == 503
  assert values['duration'] == (13.0 if phase == 'close' else 9.0)
  assert touches.count('close') == 1


@pytest.mark.parametrize('failure_kind', ['timeout', 'network', 'protocol', 'cancelled'])
async def test_http_no_response_counts_request_and_preserves_original_failure(app, failure_kind):
  module = importlib.import_module('metrics.httpx_metrics')
  error = {
    'timeout': httpx.ConnectTimeout('dummy-private-value'),
    'network': httpx.ConnectError('dummy-private-value'),
    'protocol': httpx.RemoteProtocolError('dummy-private-value'),
    'cancelled': asyncio.CancelledError(),
  }[failure_kind]
  before = {
    name: metric_total(name)
    for name in (
      'httpx_requests_total',
      'httpx_responses_total',
      'httpx_requests_duration_seconds_count',
      'httpx_exchanges_started_total',
      'httpx_exchanges_terminal_total',
      'httpx_exchanges_in_flight',
    )
  }

  async def unavailable(request):
    raise error

  async with httpx.AsyncClient(
    transport=module.ObservedAsyncTransport(httpx.MockTransport(unavailable), integration='dns'),
    trust_env=False,
  ) as client:
    with pytest.raises(type(error)) as failure:
      await client.get('https://private.example.test/secret-path?token=dummy-private-value')
    assert failure.value is error
  for name in (
    'httpx_requests_total',
    'httpx_requests_duration_seconds_count',
    'httpx_exchanges_started_total',
    'httpx_exchanges_terminal_total',
  ):
    assert metric_total(name) - before[name] == 1
  assert metric_total('httpx_responses_total') == before['httpx_responses_total']
  assert metric_total('httpx_exchanges_in_flight') == before['httpx_exchanges_in_flight']
  samples = [
    sample for family in REGISTRY.collect() for sample in family.samples if sample.name == 'httpx_exceptions_total'
  ]
  assert all(set(sample.labels) == {'method', 'host', 'path', 'status_code', 'error', 'app_name'} for sample in samples)
  assert 'private.example.test' not in repr(samples)
  assert 'secret-path' not in repr(samples)
  assert 'dummy-private-value' not in repr(samples)


@pytest.mark.parametrize('fail_observer', [False, True])
async def test_http_preconsumed_response_and_observer_failure_preserve_payload(app, fail_observer):
  module = importlib.import_module('metrics.httpx_metrics')
  observations = HttpObservations(fail=fail_observer)
  response = httpx.Response(500, content=b'not JSON: \xff\x00')
  async with httpx.AsyncClient(
    transport=module.ObservedAsyncTransport(httpx.MockTransport(lambda request: response), metrics=observations),
    trust_env=False,
  ) as client:
    result = await client.get('https://example.test/')
    assert result is response
    assert result.content == b'not JSON: \xff\x00'
    await result.aclose()
  assert [event[0] for event in observations.events].count('finished') == 1


@pytest.mark.parametrize('body_error', [False, True])
async def test_http_cleanup_after_terminal_is_separate_and_error_status_counts_once(app, body_error):
  module = importlib.import_module('metrics.httpx_metrics')
  before_terminal = metric_total('httpx_exchanges_terminal_total')
  before_errors = metric_total('httpx_exceptions_total')
  before_cleanup = metric_total('httpx_stream_cleanup_errors_total')
  before_http_status = metric_total('httpx_exceptions_total', error='http_status')
  before_network = metric_total('httpx_exceptions_total', error='network_error', method='OTHER')
  cleanup_error = httpx.ReadError('dummy private close error')
  read_error = httpx.ReadError('dummy private body error')

  class Stream(httpx.AsyncByteStream):
    async def __aiter__(self):
      yield b'payload'
      if body_error:
        raise read_error

    async def aclose(self):
      raise cleanup_error

  async with httpx.AsyncClient(
    transport=module.ObservedAsyncTransport(
      httpx.MockTransport(lambda request: httpx.Response(503, stream=Stream())),
      integration='private.example.test',
    ),
    trust_env=False,
  ) as client:
    response = await client.send(client.build_request('PRIVATE-METHOD', 'https://example.test/'), stream=True)
    with pytest.raises(httpx.ReadError) as failure:
      await response.aread()
    assert failure.value is (read_error if body_error else cleanup_error)
    if body_error:
      with pytest.raises(httpx.ReadError) as cleanup:
        await response.aclose()
      assert cleanup.value is cleanup_error
  assert metric_total('httpx_exchanges_terminal_total') - before_terminal == 1
  assert metric_total('httpx_exceptions_total') - before_errors == 1
  assert metric_total('httpx_stream_cleanup_errors_total') - before_cleanup == 1
  assert metric_total('httpx_exceptions_total', error='http_status') - before_http_status == int(not body_error)
  assert metric_total('httpx_exceptions_total', error='network_error', method='OTHER') - before_network == int(
    body_error
  )
  assert metric_total('httpx_exchanges_in_flight', integration='other') == 0


async def test_http_open_stream_conservation_headers_and_redirect_exchange_count(app, monkeypatch):
  module = importlib.import_module('metrics.httpx_metrics')
  clock = SimpleNamespace(value=10.0)
  monkeypatch.setattr(module, 'perf_counter', lambda: clock.value)
  before = {
    name: metric_total(name)
    for name in (
      'httpx_requests_total',
      'httpx_exchanges_terminal_total',
      'httpx_exchanges_in_flight',
      'httpx_request_headers_duration_seconds_sum',
      'httpx_requests_duration_seconds_sum',
    )
  }

  class Stream(httpx.AsyncByteStream):
    async def __aiter__(self):
      yield b'body'

    async def aclose(self):
      clock.value = 20.0

  def upstream(request):
    if request.url.path == '/redirect':
      return httpx.Response(302, headers={'location': '/stream'}, content=b'')
    clock.value = 12.0
    return httpx.Response(200, stream=Stream())

  async with httpx.AsyncClient(
    transport=module.ObservedAsyncTransport(httpx.MockTransport(upstream), integration='file_loader'),
    trust_env=False,
    follow_redirects=True,
  ) as client:
    response = await client.send(client.build_request('GET', 'https://example.test/redirect'), stream=True)
    assert metric_total('httpx_requests_total') - before['httpx_requests_total'] == 2
    assert metric_total('httpx_exchanges_terminal_total') - before['httpx_exchanges_terminal_total'] == 1
    assert metric_total('httpx_exchanges_in_flight') - before['httpx_exchanges_in_flight'] == 1
    assert (
      metric_total('httpx_request_headers_duration_seconds_sum') - before['httpx_request_headers_duration_seconds_sum']
      == 2
    )
    assert metric_total('httpx_requests_duration_seconds_sum') - before['httpx_requests_duration_seconds_sum'] == 0
    await response.aclose()
  assert metric_total('httpx_exchanges_in_flight') == before['httpx_exchanges_in_flight']
  assert metric_total('httpx_exchanges_terminal_total') - before['httpx_exchanges_terminal_total'] == 2
  assert metric_total('httpx_requests_duration_seconds_sum') - before['httpx_requests_duration_seconds_sum'] == 10


@pytest.mark.parametrize('transport', ['classic', 'doh'])
@pytest.mark.parametrize(
  ('kind', 'expected'),
  [
    ('positive', 'ADDRESSES'),
    ('positive-unrelated', 'ADDRESSES'),
    ('alias-positive', 'ADDRESSES'),
    ('alias-duplicate', 'ADDRESSES'),
    ('nxdomain', 'ABSENT'),
    ('nxdomain-ns', 'ABSENT'),
    ('alias-nxdomain', 'ABSENT'),
    ('nodata', 'ABSENT'),
    ('alias-nodata', 'ABSENT'),
    ('empty', 'FAILURE'),
    ('cname-only', 'FAILURE'),
    ('foreign-soa', 'FAILURE'),
    ('wrong-soa-class', 'FAILURE'),
    ('unrelated-negative', 'FAILURE'),
    ('referral', 'FAILURE'),
    ('nxdomain-positive', 'FAILURE'),
    ('servfail', 'FAILURE'),
    ('refused', 'FAILURE'),
    ('wrong-name', 'FAILURE'),
    ('wrong-type', 'FAILURE'),
    ('wrong-class', 'FAILURE'),
    ('multiple-questions', 'FAILURE'),
    ('no-question', 'FAILURE'),
    ('not-response', 'FAILURE'),
    ('truncated', 'FAILURE'),
    ('wrong-opcode', 'FAILURE'),
    ('alias-cycle', 'FAILURE'),
    ('alias-address-collision', 'FAILURE'),
    ('alias-conflict', 'FAILURE'),
    ('aaaa-only', 'FAILURE'),
    ('chain-limit', 'FAILURE'),
    ('chain-below-limit', 'ADDRESSES'),
  ],
)
async def test_query_requires_trustworthy_ipv4_evidence(app, resolver, network, transport, kind, expected):
  server = '192.0.2.53' if transport == 'classic' else 'https://dns.example.test/dns-query'
  network({server: kind}, transport=transport)
  domain = app.dto.DomainResult(id=1, name='WWW.Example.Test')
  method = getattr(resolver, f'_DomainsResolver__{"default" if transport == "classic" else "doh"}_resolver')
  outcome = await method(domain=domain, dns_server=app.Server(server=server), lookup_type=dns.rdatatype.A)
  assert outcome.status == getattr(app.dto.DnsQueryStatus, expected)
  assert outcome.server == server
  assert outcome.server_type == transport
  assert outcome.lookup_type == dns.rdatatype.A
  assert set(outcome.addresses) == ({'8.8.8.8'} if expected == 'ADDRESSES' else set())
  assert domain.result.A == []
  assert domain.result.AAAA == []
  if expected == 'FAILURE':
    assert outcome.reason
  if expected == 'ADDRESSES' and kind == 'positive-unrelated':
    assert outcome.cnames == ()


@pytest.mark.parametrize('exception', [dns.exception.Timeout(), dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN()])
async def test_classic_missing_response_is_failure(app, resolver, network, exception):
  server = '192.0.2.53'
  network({server: exception})
  outcome = await resolver._DomainsResolver__default_resolver(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server=server),
    lookup_type=dns.rdatatype.A,
  )
  assert outcome.status == app.dto.DnsQueryStatus.FAILURE
  assert outcome.addresses == ()


@pytest.mark.parametrize(
  ('status', 'media', 'mutation'),
  [
    (503, 'application/dns-message', None),
    (200, 'application/json', None),
    (200, 'application/dns-message', lambda wire: b'broken'),
    (200, 'application/dns-message', lambda wire: wire + b'trailing'),
    (200, 'application/dns-message', lambda wire: bytes([wire[0] ^ 1]) + wire[1:]),
  ],
)
async def test_doh_rejects_invalid_http_and_wire_contract(app, resolver, network, status, media, mutation):
  server = 'https://dns.example.test/dns-query'
  network({server: 'positive'}, transport='doh', status=status, media=media, mutate_wire=mutation)
  outcome = await resolver._DomainsResolver__doh_resolver(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server=server),
    lookup_type=dns.rdatatype.A,
  )
  assert outcome.status == app.dto.DnsQueryStatus.FAILURE
  assert outcome.addresses == ()


async def test_doh_accepts_normalized_dns_media_type(app, resolver, network):
  server = 'https://dns.example.test/dns-query'
  network({server: 'positive'}, transport='doh', media='Application/DNS-Message; charset=binary')
  outcome = await resolver._DomainsResolver__doh_resolver(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server=server),
    lookup_type=dns.rdatatype.A,
  )
  assert outcome.status == app.dto.DnsQueryStatus.ADDRESSES
  assert outcome.addresses == ('8.8.8.8',)


async def test_doh_failure_does_not_log_body_or_exception_payload(app, resolver, network, caplog):
  server = 'https://dns.example.test/dns-query'
  marker = 'private-upstream-payload'
  network({server: httpx.ReadTimeout(marker)}, transport='doh')
  outcome = await resolver._DomainsResolver__doh_resolver(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server=server),
    lookup_type=dns.rdatatype.A,
  )
  assert outcome.status == app.dto.DnsQueryStatus.FAILURE
  assert marker not in caplog.text
  assert marker not in (outcome.reason or '')


async def test_doh_http_failure_does_not_log_response_body(app, resolver, caplog):
  marker = 'private-upstream-response-body'
  resolver._DomainsResolver__http_client = app.make_http(
    lambda request: httpx.Response(503, content=marker.encode()),
  )
  caplog.set_level(logging.ERROR)
  outcome = await resolver._DomainsResolver__doh_resolver(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server='https://dns.example.test/dns-query'),
    lookup_type=dns.rdatatype.A,
  )
  assert outcome.status == app.dto.DnsQueryStatus.FAILURE
  assert marker not in caplog.text
  assert marker not in (outcome.reason or '')


@pytest.mark.parametrize(
  ('kinds', 'complete', 'ips'),
  [
    (['positive', 'positive'], True, {'8.8.8.8'}),
    (['positive', 'nodata'], False, {'8.8.8.8'}),
    (['positive', 'servfail'], False, {'8.8.8.8'}),
    (['nxdomain', 'nodata'], True, set()),
    (['servfail', 'empty'], False, set()),
    ([], False, set()),
  ],
)
async def test_cycle_completion_controls_mutation(app, resolver, repository, network, kinds, complete, ips):
  servers = [f'192.0.2.{index + 1}' for index in range(len(kinds))]
  network(dict(zip(servers, kinds, strict=True)))
  repository.get_all_ips_for_domain.return_value = [
    app.Ip(id=10, ip_address='9.9.9.9', addr_type=4),
    app.Ip(id=11, ip_address='2001:4860:4860::8888', addr_type=6),
  ]
  domain = app.dto.DomainResult(id=1, name='www.example.test')
  await resolver._DomainsResolver__dns_main_tasker(
    domain=domain,
    default_dns_servers=[app.Server(server=value) for value in servers],
    doh_dns_servers=[],
  )
  assert domain.resolution_complete is complete
  if complete or ips:
    queued = repository.put_domain_after_resolve.await_args.kwargs['domain']
    assert {ip.ip_address for ip in queued.insert.ips_insert} == ips
    assert set(queued.insert.ips_delete) == ({10} if complete else set())
    assert queued.resolution_complete is complete
  else:
    repository.put_domain_after_resolve.assert_not_awaited()


async def test_distinct_server_addresses_are_unioned_before_reconciliation(
  app, resolver, repository, monkeypatch, dns_message
):
  async def classic(boundary, qname, rdtype, **kwargs):
    message = dns_message(query=dns.message.make_query(qname, rdtype), addresses=(boundary.nameservers[0],))
    return SimpleNamespace(response=message)

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  domain = app.dto.DomainResult(id=1, name='www.example.test')
  await resolver._DomainsResolver__dns_main_tasker(
    domain=domain,
    default_dns_servers=[app.Server(server='8.8.8.8'), app.Server(server='9.9.9.9')],
    doh_dns_servers=[],
  )
  queued = repository.put_domain_after_resolve.await_args.kwargs['domain']
  assert queued.resolution_complete is True
  assert {ip.ip_address for ip in queued.insert.ips_insert} == {'8.8.8.8', '9.9.9.9'}


async def test_storage_read_failure_enqueues_nothing(app, resolver, repository, network):
  network({'192.0.2.53': 'positive'})
  repository.get_all_ips_for_domain.side_effect = app.database.DomainIpReadError('Unable to read domain IPs')
  await resolver._DomainsResolver__dns_main_tasker(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    default_dns_servers=[app.Server(server='192.0.2.53')],
    doh_dns_servers=[],
  )
  repository.put_domain_after_resolve.assert_not_awaited()


async def test_storage_mapping_failure_is_typed_and_session_is_released(app, monkeypatch):
  session = AsyncMock(spec=app.database.AsyncSession)
  store = app.database.db
  monkeypatch.setattr(store, '_DataBase__read_connect', AsyncMock(return_value=session))
  monkeypatch.setattr(
    app.database.IpRecordsDbo,
    'get_ips_on_domain_id_extend',
    AsyncMock(return_value=[()]),
  )
  with pytest.raises(app.database.DomainIpReadError) as failure:
    await store.get_all_ips_for_domain(domain_id=1)
  assert isinstance(failure.value.__cause__, IndexError)
  session.rollback.assert_awaited_once()
  session.close.assert_awaited_once()


@pytest.mark.parametrize('complete', [False, True])
async def test_policy_filtering_does_not_change_positive_cycle_status(
  app, resolver, repository, monkeypatch, dns_message, complete
):
  async def classic(boundary, qname, rdtype, **kwargs):
    if boundary.nameservers[0] == '192.0.2.54':
      return SimpleNamespace(response=dns_message('nxdomain', query=dns.message.make_query(qname, rdtype)))
    return SimpleNamespace(response=dns_message(query=dns.message.make_query(qname, rdtype), addresses=('127.0.0.1',)))

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  repository.get_all_ips_for_domain.return_value = [app.Ip(id=10, ip_address='9.9.9.9', addr_type=4)]
  domain = app.dto.DomainResult(id=1, name='www.example.test')
  servers = ['192.0.2.53'] if complete else ['192.0.2.53', '192.0.2.54']
  await resolver._DomainsResolver__dns_main_tasker(
    domain=domain,
    default_dns_servers=[app.Server(server=value) for value in servers],
    doh_dns_servers=[],
  )
  assert domain.resolution_complete is complete
  assert domain.insert.ips_insert == []
  assert domain.insert.ips_delete == ([10] if complete else [])


@pytest.mark.parametrize('stored', ['8.8.8.0', '8.8.8.0/24', '8.8.8.0/25'])
async def test_partial_cycle_preserves_existing_representation_without_enrichment(
  app, resolver, repository, monkeypatch, dns_message, stored
):
  async def classic(boundary, qname, rdtype, **kwargs):
    if boundary.nameservers[0] == '192.0.2.54':
      raise dns.exception.Timeout()
    return SimpleNamespace(response=dns_message(query=dns.message.make_query(qname, rdtype), addresses=('8.8.8.0',)))

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  repository.get_all_ips_for_domain.return_value = [app.Ip(id=10, ip_address=stored, addr_type=4)]
  ripe_boundary = AsyncMock(side_effect=AssertionError('Existing partial-cycle representation must stay untouched'))
  resolver._DomainsResolver__ripe_stat_client = SimpleNamespace(get_prefix=ripe_boundary)
  domain = app.dto.DomainResult(id=1, name='www.example.test')
  await resolver._DomainsResolver__dns_main_tasker(
    domain=domain,
    default_dns_servers=[app.Server(server='192.0.2.53'), app.Server(server='192.0.2.54')],
    doh_dns_servers=[],
  )
  assert domain.insert.ips_insert == []
  assert domain.insert.ips_delete == []
  assert domain.resolution_complete is False
  ripe_boundary.assert_not_awaited()


@pytest.mark.parametrize(
  ('payload', 'expected'),
  [
    ({'status': 'ok', 'data': {'prefix': '8.8.8.0/24'}}, '8.8.8.0/24'),
    ({'status': 'ok', 'data': {'prefix': '8.8.0.0/16'}}, '8.8.8.0'),
    ({'status': 'ok', 'data': {'prefix': None}}, '8.8.8.0'),
    ({'status': 'error', 'message': 'Unavailable'}, '8.8.8.0/25'),
  ],
)
async def test_complete_cycle_keeps_ripe_prefix_and_failure_contract(app, resolver, payload, expected):
  client = app.make_http(lambda request: httpx.Response(200, json=payload))
  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = client
  resolver._DomainsResolver__ripe_stat_client = ripe
  domain = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=True)
  domain.result.A = ['8.8.8.0']
  current = [app.Ip(id=10, ip_address='8.8.8.0/25', addr_type=4)]
  await resolver._DomainsResolver__ips_processing(domain=domain, current_ips=current)
  if expected == '8.8.8.0/25':
    assert domain.insert.ips_insert == []
    assert domain.insert.ips_delete == []
  else:
    assert [item.ip_address for item in domain.insert.ips_insert] == [expected]
    assert domain.insert.ips_delete == [10]


@pytest.mark.parametrize('transport', ['classic', 'doh'])
@pytest.mark.parametrize('kind', ['alias-positive', 'alias-nxdomain'])
async def test_one_shot_preserves_public_shape_and_reachable_alias(app, resolver, repository, network, transport, kind):
  server = '192.0.2.53' if transport == 'classic' else 'https://dns.example.test/dns-query'
  network({server: kind}, transport=transport)
  repository.get_dns_servers_for_resolve.return_value = (
    ([app.Server(server=server)], []) if transport == 'classic' else ([], [app.Server(server=server)])
  )
  result = await resolver.resolve_once('www.example.test.')
  assert result.domain == 'www.example.test'
  assert len(result.results) == 1
  row = dataclasses.asdict(result.results[0])
  assert set(row) == {'server', 'server_type', 'ips_v4', 'ips_v6', 'cnames'}
  assert row['server'] == server
  assert row['server_type'] == transport
  assert row['ips_v4'] == (['8.8.8.8'] if kind == 'alias-positive' else [])
  assert row['ips_v6'] == []
  assert row['cnames'] == ['edge.example.test']


async def test_completion_permission_defaults_to_false(app):
  assert app.dto.DomainResult(id=1, name='www.example.test').resolution_complete is False


@pytest.mark.parametrize('kind', ['alias-conflict', 'alias-duplicate'])
async def test_supplied_message_rrsets_are_validated_without_original_wire(app, dns_message, kind):
  message = dns_message(kind)
  assert message.wire is None
  outcome = app.resolver.classify_dns_response(
    message,
    'www.example.test',
    '192.0.2.53',
    'classic',
  )
  assert outcome.status == (
    app.dto.DnsQueryStatus.FAILURE if kind == 'alias-conflict' else app.dto.DnsQueryStatus.ADDRESSES
  )


async def test_only_reachable_ipv4_records_are_deduplicated(app, dns_message):
  message = dns_message('positive', addresses=('9.9.9.9', '8.8.8.8', '9.9.9.9'))
  message.answer.append(dns.rrset.from_text('www.example.test.', 60, 'IN', 'AAAA', '2001:4860:4860::8888'))
  message.additional.append(dns.rrset.from_text('www.example.test.', 60, 'IN', 'A', '8.8.4.4'))
  outcome = app.resolver.classify_dns_response(message, 'www.example.test', '192.0.2.53', 'classic')
  assert outcome.status == app.dto.DnsQueryStatus.ADDRESSES
  assert set(outcome.addresses) == {'8.8.8.8', '9.9.9.9'}
  assert len(outcome.addresses) == 2


@pytest.mark.parametrize('discover_alias', [False, True])
async def test_stored_resolution_keeps_cname_discovery_best_effort(
  app,
  resolver,
  repository,
  monkeypatch,
  dns_message,
  discover_alias,
):
  requests = []

  async def classic(boundary, qname, rdtype, **kwargs):
    requests.append(rdtype)
    if rdtype == dns.rdatatype.CNAME and not discover_alias:
      raise dns.exception.Timeout()
    kind = 'alias-positive' if discover_alias else 'positive'
    return SimpleNamespace(response=dns_message(kind, query=dns.message.make_query(qname, rdtype)))

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  repository.get_domain_on_id = AsyncMock(
    return_value=SimpleNamespace(id=1, name='www.example.test', domains_list_id=7)
  )
  repository.get_dns_servers_for_resolve.return_value = ([app.Server(server='192.0.2.53')], [])
  await resolver.resolve_stored_domain(domain_id=1)
  queued = repository.put_domain_after_resolve.await_args.kwargs['domain']
  assert queued.resolution_complete is True
  assert [ip.ip_address for ip in queued.insert.ips_insert] == ['8.8.8.8']
  assert sorted(requests) == sorted([dns.rdatatype.A, dns.rdatatype.CNAME])
  if discover_alias:
    added = repository.put_add_domains_to_queue.await_args.kwargs['domains']
    assert [(domain.domain, domain.list_id) for domain in added] == [('edge.example.test', 7)]
  else:
    repository.put_add_domains_to_queue.assert_not_awaited()


@pytest.mark.parametrize('alias_write_fails', [False, True])
async def test_alias_nxdomain_survives_cname_query_and_alias_write_failures(
  app,
  resolver,
  repository,
  monkeypatch,
  dns_message,
  alias_write_fails,
):
  async def classic(boundary, qname, rdtype, **kwargs):
    if rdtype == dns.rdatatype.CNAME:
      raise dns.resolver.NoNameservers()
    query = dns.message.make_query(qname, rdtype)
    response = dns_message('alias-nxdomain', query=query)
    raise dns.resolver.NXDOMAIN(qnames=[query.question[0].name], responses={query.question[0].name: response})

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  repository.get_domain_on_id = AsyncMock(
    return_value=SimpleNamespace(id=1, name='www.example.test', domains_list_id=7)
  )
  repository.get_dns_servers_for_resolve.return_value = ([app.Server(server='192.0.2.53')], [])
  if alias_write_fails:
    repository.put_add_domains_to_queue.side_effect = RuntimeError('Synthetic alias queue failure')
  await resolver.resolve_stored_domain(domain_id=1)
  queued = repository.put_domain_after_resolve.await_args.kwargs['domain']
  assert queued.resolution_complete is True
  assert queued.result.A == []
  aliases = repository.put_add_domains_to_queue.await_args.kwargs['domains']
  assert [(alias.domain, alias.list_id) for alias in aliases] == [('edge.example.test', 7)]
  result = await resolver.resolve_once('www.example.test')
  assert result.results[0].ips_v4 == []
  assert result.results[0].cnames == ['edge.example.test']


@pytest.mark.parametrize('transport', ['classic', 'doh'])
@pytest.mark.parametrize(
  ('kind', 'a_outcome', 'cname_outcome'),
  [
    ('positive', 'addresses', 'no_alias'),
    ('nodata', 'absent', 'no_alias'),
    ('cname-only', 'failure', 'aliases'),
    ('servfail', 'failure', 'failure'),
  ],
)
async def test_dns_metrics_keep_a_and_cname_evidence_separate(
  app,
  resolver,
  network,
  transport,
  kind,
  a_outcome,
  cname_outcome,
):
  server = '192.0.2.53' if transport == 'classic' else 'https://dns.example.test/private-path'
  network({server: kind}, transport=transport)
  labels = {'server_id': '0', 'transport': transport}
  before_a = metric_total('resolution_dns_duration_seconds_count', **labels, record_type='A', outcome=a_outcome)
  before_cname = metric_total(
    'resolution_dns_duration_seconds_count', **labels, record_type='CNAME', outcome=cname_outcome
  )
  domain = app.dto.DomainResult(id=1, name='www.example.test')
  prefix = 'default' if transport == 'classic' else 'doh'
  dns_server = app.Server(server=server, id=0)
  await getattr(resolver, f'_DomainsResolver__{prefix}_resolver')(
    domain=domain,
    dns_server=dns_server,
    lookup_type=dns.rdatatype.A,
  )
  aliases = []
  await getattr(resolver, f'_DomainsResolver__cname_{prefix}_resolver')(
    domain=domain,
    dns_server=dns_server,
    cname_domains=aliases,
  )
  assert (
    metric_total('resolution_dns_duration_seconds_count', **labels, record_type='A', outcome=a_outcome) - before_a == 1
  )
  assert (
    metric_total('resolution_dns_duration_seconds_count', **labels, record_type='CNAME', outcome=cname_outcome)
    - before_cname
    == 1
  )
  assert [alias.domain for alias in aliases] == (['edge.example.test'] if kind == 'cname-only' else [])
  samples = [
    sample for family in REGISTRY.collect() for sample in family.samples if sample.name.startswith('resolution_dns_')
  ]
  assert server not in repr(samples)
  assert 'www.example.test' not in repr(samples)


@pytest.mark.parametrize('record_type', ['A', 'CNAME'])
@pytest.mark.parametrize('transport', ['classic', 'doh'])
async def test_dns_cancelled_semaphore_wait_does_not_invent_a_query(app, resolver, transport, record_type):
  entered = asyncio.Event()

  class HeldSemaphore:
    async def __aenter__(self):
      entered.set()
      await asyncio.Future()

    async def __aexit__(self, *args):
      return False

  resolver._DomainsResolver__semaphore = HeldSemaphore()
  labels = dict(server_id='991', transport=transport, record_type=record_type)
  before_wait = metric_total('resolution_dns_semaphore_wait_seconds_count', **labels, outcome='cancelled')
  before_query = metric_total('resolution_dns_duration_seconds_count', **labels)
  prefix = 'default' if transport == 'classic' else 'doh'
  arguments = dict(
    domain=app.dto.DomainResult(id=1, name='www.example.test'), dns_server=app.Server(server='192.0.2.53', id=991)
  )
  if record_type == 'A':
    method = getattr(resolver, f'_DomainsResolver__{prefix}_resolver')
    arguments['lookup_type'] = dns.rdatatype.A
  else:
    method = getattr(resolver, f'_DomainsResolver__cname_{prefix}_resolver')
    arguments['cname_domains'] = []
  task = asyncio.create_task(method(**arguments))
  await asyncio.wait_for(entered.wait(), timeout=2)
  task.cancel()
  with pytest.raises(asyncio.CancelledError):
    await task
  assert metric_total('resolution_dns_semaphore_wait_seconds_count', **labels, outcome='cancelled') - before_wait == 1
  assert metric_total('resolution_dns_duration_seconds_count', **labels) == before_query


@pytest.mark.parametrize(
  ('kinds', 'expected'),
  [
    (['positive'], 'success'),
    (['nodata'], 'success'),
    (['positive', 'servfail'], 'partial'),
    (['nodata', 'servfail'], 'partial'),
    (['servfail'], 'failure'),
    ([], 'failure'),
  ],
)
async def test_processing_outcomes_do_not_conflate_reliable_absence_partial_and_failure(
  app,
  resolver,
  repository,
  network,
  kinds,
  expected,
):
  metrics = importlib.import_module('metrics.metrics')
  run = metrics.ResolutionRun('new')
  run.select(1)
  observation = run.observe()
  observation.notify('processing_started', run.started_at)
  servers = [f'192.0.2.{index + 1}' for index in range(len(kinds))]
  network(dict(zip(servers, kinds, strict=True)))
  domain = app.dto.DomainResult(id=1, name='www.example.test', observation=observation)
  await resolver._DomainsResolver__dns_main_tasker(domain, [app.Server(server=server) for server in servers], [])
  resolver._DomainsResolver__finish_domain_observation(domain)
  run.finish(True)
  snapshot = run.snapshot()
  assert domain.processing_outcome == expected
  assert snapshot[expected] == snapshot['attempted'] == 1
  assert snapshot['active'] == snapshot['not_started'] == 0
  assert snapshot['success'] + snapshot['partial'] + snapshot['failure'] == 1
  if kinds in (['nodata', 'servfail'], ['servfail'], []):
    repository.get_all_ips_for_domain.assert_not_awaited()
    repository.put_domain_after_resolve.assert_not_awaited()


@pytest.mark.parametrize('failure_kind', ['rejected', 'cancelled'])
async def test_prepared_processing_success_survives_writer_admission_failure(
  app,
  resolver,
  repository,
  network,
  failure_kind,
):
  metrics = importlib.import_module('metrics.metrics')
  run = metrics.ResolutionRun('stored')
  run.select(1)
  observation = run.observe()
  observation.notify('processing_started', run.started_at)
  network({'192.0.2.53': 'nodata'})
  repository.put_domain_after_resolve.side_effect = (
    asyncio.CancelledError()
    if failure_kind == 'cancelled'
    else app.database.WriterClosedError('Synthetic closed writer')
  )
  domain = app.dto.DomainResult(id=1, name='www.example.test', observation=observation)
  if failure_kind == 'cancelled':
    with pytest.raises(asyncio.CancelledError):
      await resolver._DomainsResolver__dns_main_tasker(domain, [app.Server(server='192.0.2.53')], [])
  else:
    await resolver._DomainsResolver__dns_main_tasker(domain, [app.Server(server='192.0.2.53')], [])
  resolver._DomainsResolver__finish_domain_observation(domain)
  assert domain.processing_outcome == 'success'
  assert run.snapshot()['success'] == 1
  assert run.snapshot()['cancelled_processing'] == run.snapshot()['failure'] == 0


async def test_run_generation_and_late_receipts_keep_origin_and_conservation(app, monkeypatch):
  metrics = importlib.import_module('metrics.metrics')
  clock = SimpleNamespace(value=10.0)
  monkeypatch.setattr(metrics, 'perf_counter', lambda: clock.value)
  old = metrics.ResolutionRun('stored')
  old.select(1)
  receipt = old.observe()
  for event in ('processing_started', 'success', 'admission_started', 'admitted', 'processing_finished'):
    receipt.notify(event, clock.value)
  clock.value = 12.0
  old.finish(True)
  assert old.snapshot()['processing_rate'] == 0.5
  assert math.isnan(old.snapshot()['saved_rate'])
  assert old.snapshot()['saved_rate_valid'] is False
  clock.value = 13.0
  newer = metrics.ResolutionRun('stored')
  assert metric_total('resolution_run_snapshot', mode='stored', field='selected') == 0
  receipt.notify('unknown', 14.0)
  assert old.snapshot()['admitted'] == old.snapshot()['unknown'] == 1
  receipt.notify('confirmed', 15.0)
  receipt.notify('confirmed', 16.0)
  receipt.notify('unknown', 17.0)
  assert old.snapshot()['confirmed'] == 1
  assert old.snapshot()['pending'] == old.snapshot()['unknown'] == old.snapshot()['known_not_committed'] == 0
  assert old.snapshot()['persistence_elapsed'] == 5.0
  assert old.snapshot()['saved_rate'] == 0.2
  assert metric_total('resolution_run_snapshot', mode='stored', field='confirmed') == 0
  assert newer.snapshot()['selected'] == 0


@pytest.mark.parametrize('normal', [False, True])
async def test_run_never_fabricates_rate_for_zero_elapsed_or_interruption(app, monkeypatch, normal):
  metrics = importlib.import_module('metrics.metrics')
  monkeypatch.setattr(metrics, 'perf_counter', lambda: 10.0)
  run = metrics.ResolutionRun('new')
  run.select(0)
  run.finish(normal)
  assert run.snapshot()['processing_elapsed'] == 0
  assert run.snapshot()['processing_rate_valid'] is False
  assert run.snapshot()['saved_rate_valid'] is False
  assert math.isnan(run.snapshot()['processing_rate'])
  assert math.isnan(run.snapshot()['saved_rate'])


@pytest.mark.parametrize('prefix', ['8.8.8.0/24', None])
async def test_ripe_direct_cache_hit_never_counts_another_network_lookup(app, prefix):
  calls = []

  def upstream(request):
    calls.append(str(request.url))
    return httpx.Response(200, json={'status': 'ok', 'data': {'prefix': prefix}})

  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  before_network = metric_total('resolution_ripe_duration_seconds_count', phase='network')
  before_hit = metric_total(
    'resolution_ripe_duration_seconds_count',
    phase='lookup',
    source='cache',
    outcome='empty' if prefix is None else 'prefix',
  )
  first = await ripe.get_prefix('8.8.8.8')
  second = await ripe.get_prefix('8.8.8.8')
  assert first.prefix == second.prefix == prefix
  assert len(calls) == 1
  assert metric_total('resolution_ripe_duration_seconds_count', phase='network') - before_network == 1
  assert (
    metric_total(
      'resolution_ripe_duration_seconds_count',
      phase='lookup',
      source='cache',
      outcome='empty' if prefix is None else 'prefix',
    )
    - before_hit
    == 1
  )


async def test_ripe_recheck_hit_is_one_logical_lookup_without_network(app, monkeypatch):
  cache = importlib.import_module('cache.cache').ripe_stat_cache
  reads = []

  async def cache_read(key):
    reads.append(key)
    return None if len(reads) == 1 else '8.8.8.0/24'

  @asynccontextmanager
  async def concurrent_fill(**kwargs):
    yield

  monkeypatch.setattr(cache, 'get', cache_read)
  monkeypatch.setattr(cache, 'lock', concurrent_fill)
  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(lambda request: pytest.fail('A cache recheck hit must not call HTTP'))
  before = metric_total(
    'resolution_ripe_duration_seconds_count', phase='lookup', source='cache_after_lock', outcome='prefix'
  )
  before_network = metric_total('resolution_ripe_duration_seconds_count', phase='network')
  result = await ripe.get_prefix('8.8.8.8')
  assert result.prefix == '8.8.8.0/24'
  assert reads == ['prefix:8.8.8.8', 'prefix:8.8.8.8']
  assert (
    metric_total('resolution_ripe_duration_seconds_count', phase='lookup', source='cache_after_lock', outcome='prefix')
    - before
    == 1
  )
  assert metric_total('resolution_ripe_duration_seconds_count', phase='network') == before_network


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
async def test_dns_metric_observer_failure_preserves_reliable_query(app, resolver, network, monkeypatch, error_type):
  metrics = importlib.import_module('metrics.metrics')

  def fail_observation(**labels):
    raise error_type('Synthetic observer failure')

  monkeypatch.setattr(metrics.dns_duration, 'labels', fail_observation)
  network({'192.0.2.53': 'positive'})
  outcome = await resolver._DomainsResolver__default_resolver(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server='192.0.2.53'),
    lookup_type=dns.rdatatype.A,
  )
  assert outcome.status == app.dto.DnsQueryStatus.ADDRESSES
  assert outcome.addresses == ('8.8.8.8',)


async def test_ripe_failure_then_recovery_is_not_cached_as_success(app):
  calls = []

  def upstream(request):
    calls.append(request)
    return httpx.Response(
      200, json=({'status': 'error'} if len(calls) == 1 else {'status': 'ok', 'data': {'prefix': None}})
    )

  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  before_failure = metric_total('resolution_ripe_duration_seconds_count', phase='network', outcome='failure')
  before_empty = metric_total('resolution_ripe_duration_seconds_count', phase='network', outcome='empty')
  with pytest.raises(app.ripe.RipeStatClientError):
    await ripe.get_prefix('8.8.8.8')
  assert (await ripe.get_prefix('8.8.8.8')).prefix is None
  assert (await ripe.get_prefix('8.8.8.8')).prefix is None
  assert len(calls) == 2
  assert (
    metric_total('resolution_ripe_duration_seconds_count', phase='network', outcome='failure') - before_failure == 1
  )
  assert metric_total('resolution_ripe_duration_seconds_count', phase='network', outcome='empty') - before_empty == 1


@pytest.mark.parametrize('transport', ['classic', 'doh'])
@pytest.mark.parametrize('record_type', ['A', 'CNAME'])
async def test_dns_query_cancellation_is_observed_and_reraised(
  app,
  resolver,
  monkeypatch,
  transport,
  record_type,
):
  entered = asyncio.Event()

  async def blocked(*args, **kwargs):
    entered.set()
    await asyncio.Future()

  if transport == 'classic':
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', blocked)
  else:
    resolver._DomainsResolver__http_client = app.make_http(blocked)
  labels = dict(server_id='992', transport=transport, record_type=record_type, outcome='cancelled')
  before = metric_total('resolution_dns_duration_seconds_count', **labels)
  prefix = 'default' if transport == 'classic' else 'doh'
  arguments = dict(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server='192.0.2.53' if transport == 'classic' else 'https://example.test/dns', id=992),
  )
  if record_type == 'A':
    method = getattr(resolver, f'_DomainsResolver__{prefix}_resolver')
    arguments['lookup_type'] = dns.rdatatype.A
  else:
    method = getattr(resolver, f'_DomainsResolver__cname_{prefix}_resolver')
    arguments['cname_domains'] = []
  task = asyncio.create_task(method(**arguments))
  await asyncio.wait_for(entered.wait(), timeout=2)
  task.cancel()
  with pytest.raises(asyncio.CancelledError):
    await task
  assert metric_total('resolution_dns_duration_seconds_count', **labels) - before == 1


async def test_overlapping_stored_operations_keep_their_own_observations(
  app,
  resolver,
  repository,
  dns_message,
  monkeypatch,
):
  first_entered, release = asyncio.Event(), asyncio.Event()

  async def classic(boundary, qname, rdtype, **kwargs):
    if qname.startswith('first.'):
      first_entered.set()
      await release.wait()
    return SimpleNamespace(response=dns_message('nodata', query=dns.message.make_query(qname, rdtype)))

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  repository.get_domain_on_id = AsyncMock(
    side_effect=lambda id: SimpleNamespace(
      id=id,
      name='first.example.test' if id == 1 else 'second.example.test',
      domains_list_id=None,
    )
  )
  repository.get_dns_servers_for_resolve.return_value = ([app.Server(server='192.0.2.53')], [])
  first = asyncio.create_task(resolver.resolve_stored_domain(1))
  await asyncio.wait_for(first_entered.wait(), timeout=2)
  try:
    await resolver.resolve_stored_domain(2)
    second_command = repository.put_domain_after_resolve.await_args.kwargs['domain']
    assert second_command.id == 2
    assert second_command.observation.run.snapshot()['success'] == 1
    assert metric_total('resolution_run_snapshot', mode='stored', field='selected') == 1
    assert metric_total('resolution_run_snapshot', mode='stored', field='success') == 1
  finally:
    release.set()
    await asyncio.wait_for(first, timeout=2)
  first_command = repository.put_domain_after_resolve.await_args.kwargs['domain']
  assert first_command.id == 1
  assert first_command.observation.run is not second_command.observation.run
  assert first_command.observation.run.snapshot()['success'] == 1
  assert metric_total('resolution_run_snapshot', mode='stored', field='success') == 1
  assert metric_total('resolution_run_snapshot', mode='stored', field='attempted') == 1


async def test_resolve_queue_measures_admission_and_residence_from_successful_put(
  app,
  resolver,
  repository,
  network,
  monkeypatch,
):
  metrics = importlib.import_module('metrics.metrics')
  clock = SimpleNamespace(value=10.0)
  monkeypatch.setattr(metrics, 'perf_counter', lambda: clock.value)
  monkeypatch.setattr(app.resolver, 'perf_counter', lambda: clock.value)
  monkeypatch.setattr(resolver, '_DomainsResolver__stop_domains_resolve_event', threading.Event())
  domain = app.dto.DomainResult(id=1, name='www.example.test')

  class TimedQueue(asyncio.Queue):
    async def put(self, item):
      clock.value = 100.0
      await super().put(item)

    async def get(self):
      item = await super().get()
      clock.value = 125.0
      return item

  resolver.domains_resolve_queue = TimedQueue(maxsize=2)
  network({'192.0.2.53': 'nodata'})
  repository.get_dns_servers_for_resolve.return_value = ([app.Server(server='192.0.2.53')], [])
  before_admission = metric_total('resolution_queue_duration_seconds_sum', queue='resolve', phase='admission')
  before_residence = metric_total('resolution_queue_duration_seconds_sum', queue='resolve', phase='residence')
  await resolver._DomainsResolver__put_domain(domain)
  clock.value = 110.0
  await asyncio.wait_for(resolver._DomainsResolver__task_process_domains_resolve_from_queue(1, 1), timeout=2)
  await asyncio.wait_for(resolver.domains_resolve_queue.join(), timeout=2)
  assert (
    metric_total('resolution_queue_duration_seconds_sum', queue='resolve', phase='admission') - before_admission == 90
  )
  assert (
    metric_total('resolution_queue_duration_seconds_sum', queue='resolve', phase='residence') - before_residence == 25
  )
  assert domain.admitted_at is None
  assert domain.processing_outcome == 'success'
