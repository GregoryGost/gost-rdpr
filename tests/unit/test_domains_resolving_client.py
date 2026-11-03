"""DNS evidence, cycle completeness, and conservative reconciliation."""

import asyncio
import dataclasses
import importlib
import logging
import math
import sys
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

ROS_RETRY_METHODS = frozenset({'GET', 'POST', 'PATCH', 'DELETE'})


@pytest.fixture
async def http_factory(app, monkeypatch):
  """Exercise the production retry chain while replacing only its wire boundary."""
  from httpx_retries import Retry

  module = importlib.import_module('client.http_base_client')
  await module.HttpClient.close()
  monkeypatch.setattr(app.settings, 'req_connection_retries', 3)
  calls, closes = [], []

  async def skip_wait(self, response):
    pass

  monkeypatch.setattr(Retry, 'asleep', skip_wait)

  def install(handler, *, name='default', timeout=None, retry_methods=None, **policy):
    async def send(transport, request):
      calls.append(request)
      result = handler(request)
      if asyncio.iscoroutine(result):
        result = await result
      return result

    async def close(transport):
      closes.append(transport)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', send)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, 'aclose', close)
    kwargs = {} if retry_methods is None else {'retry_methods': retry_methods}
    return module.HttpClient.get_client(name, timeout=timeout, **kwargs, **policy)

  yield SimpleNamespace(install=install, calls=calls, closes=closes, factory=module.HttpClient)
  await module.HttpClient.close()


@pytest.mark.parametrize('method', ['GET', 'POST', 'PATCH', 'DELETE'])
@pytest.mark.parametrize('status', [429, 502, 503, 504])
async def test_router_retryable_methods_recover_from_transient_status(http_factory, method, status):
  def upstream(request):
    assert request.content == b'fixed payload'
    return httpx.Response(status if len(http_factory.calls) == 1 else 200, content=b'result')

  client = http_factory.install(upstream, name='ros', retry_methods=ROS_RETRY_METHODS)
  response = await client.request(method, 'http://router.example.test/rest/ip/route/print', content=b'fixed payload')
  assert response.status_code == 200
  assert response.content == b'result'
  assert len(http_factory.calls) == 2


@pytest.mark.parametrize('method', ['GET', 'POST', 'PATCH', 'DELETE'])
@pytest.mark.parametrize('error_type', [httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteError])
async def test_router_retryable_methods_recover_from_transport_failure(http_factory, method, error_type):
  error = error_type('Synthetic transport failure')

  def upstream(request):
    if len(http_factory.calls) == 1:
      raise error
    return httpx.Response(200, content=b'recovered')

  client = http_factory.install(upstream, name='ros', retry_methods=ROS_RETRY_METHODS)
  assert (await client.request(method, 'http://router.example.test/rest/ip/route/print')).content == b'recovered'
  assert len(http_factory.calls) == 2


@pytest.mark.parametrize('method', ['GET', 'HEAD'])
@pytest.mark.parametrize('failure', [503, httpx.ConnectError])
async def test_general_read_methods_retry_transient_provider_failures(http_factory, method, failure):
  def upstream(request):
    if len(http_factory.calls) == 1:
      if isinstance(failure, type):
        raise failure('Synthetic read attempt failure')
      return httpx.Response(failure)
    return httpx.Response(200)

  client = http_factory.install(upstream)
  assert (await client.request(method, 'https://provider.example.test/')).status_code == 200
  assert len(http_factory.calls) == 2


@pytest.mark.parametrize(
  'failure', [429, 502, 503, 504, httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError]
)
async def test_router_creation_put_is_never_automatically_replayed(http_factory, failure):
  error = failure('Synthetic uncertain creation') if isinstance(failure, type) else None

  def upstream(request):
    if error is not None:
      raise error
    return httpx.Response(failure)

  client = http_factory.install(upstream, name='ros', retry_methods=ROS_RETRY_METHODS)
  if error is None:
    assert (
      await client.put('http://router.example.test/rest/routing/table', json={'name': 'test'})
    ).status_code == failure
  else:
    with pytest.raises(type(error)) as caught:
      await client.put('http://router.example.test/rest/routing/table', json={'name': 'test'})
    assert caught.value is error
  assert len(http_factory.calls) == 1


@pytest.mark.parametrize('failure', [503, httpx.ConnectError])
async def test_retry_count_is_additional_attempts_and_final_outcome_is_preserved(http_factory, failure):
  error = failure('Synthetic unavailable provider') if isinstance(failure, type) else None

  def upstream(request):
    if error is not None:
      raise error
    return httpx.Response(failure, content=b'final provider response')

  client = http_factory.install(upstream)
  before_started = metric_total('httpx_exchanges_started_total')
  before_terminal = metric_total('httpx_exchanges_terminal_total')
  before_in_flight = metric_total('httpx_exchanges_in_flight')
  if error is None:
    response = await client.get('https://provider.example.test/')
    assert response.status_code == 503
    assert response.content == b'final provider response'
  else:
    with pytest.raises(type(error)) as caught:
      await client.get('https://provider.example.test/')
    assert caught.value is error
  assert len(http_factory.calls) == 4
  # Metrics describe one caller-visible exchange, including its hidden retry attempts.
  assert metric_total('httpx_exchanges_started_total') - before_started == 1
  assert metric_total('httpx_exchanges_terminal_total') - before_terminal == 1
  assert metric_total('httpx_exchanges_in_flight') == before_in_flight


@pytest.mark.parametrize('method', ['POST', 'PATCH', 'DELETE', 'PUT', 'OPTIONS'])
async def test_general_clients_do_not_retry_unselected_methods(http_factory, method):
  client = http_factory.install(lambda request: httpx.Response(503))
  assert (await client.request(method, 'https://provider.example.test/')).status_code == 503
  assert len(http_factory.calls) == 1


@pytest.mark.parametrize('status', [400, 401, 403, 404, 409, 422, 500])
async def test_retry_does_not_hide_permanent_http_failures(http_factory, status):
  client = http_factory.install(lambda request: httpx.Response(status, content=b'permanent'))
  response = await client.get('https://provider.example.test/')
  assert response.status_code == status
  assert response.content == b'permanent'
  assert len(http_factory.calls) == 1


@pytest.mark.parametrize(
  'error_type', [httpx.PoolTimeout, httpx.LocalProtocolError, ValueError, asyncio.CancelledError]
)
async def test_retry_does_not_replay_pool_pressure_programming_errors_or_cancellation(http_factory, error_type):
  error = error_type('Synthetic terminal failure')

  def upstream(request):
    raise error

  client = http_factory.install(upstream)
  with pytest.raises(error_type) as caught:
    await client.get('https://provider.example.test/')
  assert caught.value is error
  assert len(http_factory.calls) == 1
  assert metric_total('httpx_exchanges_in_flight') == 0


@pytest.mark.parametrize('terminal', ['eof', 'closed', 'read_error', 'cancelled'])
async def test_retry_chain_never_replays_returned_stream_and_closes_once(http_factory, terminal):
  touches = []
  error = asyncio.CancelledError() if terminal == 'cancelled' else httpx.ReadError('Synthetic body failure')

  class Stream(httpx.AsyncByteStream):
    async def __aiter__(self):
      touches.append('read')
      yield b'prefix'
      if terminal in {'read_error', 'cancelled'}:
        raise error
      yield b'suffix'

    async def aclose(self):
      touches.append('close')

  client = http_factory.install(lambda request: httpx.Response(200, stream=Stream()))
  before = metric_total('httpx_exchanges_terminal_total')
  response = await client.send(client.build_request('GET', 'https://provider.example.test/'), stream=True)
  assert touches == []
  assert metric_total('httpx_exchanges_in_flight') == 1
  if terminal == 'closed':
    await response.aclose()
  elif terminal == 'eof':
    assert await response.aread() == b'prefixsuffix'
  else:
    with pytest.raises(type(error)) as caught:
      await response.aread()
    assert caught.value is error
  await response.aclose()
  await response.aclose()
  assert touches.count('close') == 1
  assert len(http_factory.calls) == 1
  assert metric_total('httpx_exchanges_terminal_total') - before == 1
  assert metric_total('httpx_exchanges_in_flight') == 0


async def test_retry_discards_failed_response_stream_before_next_attempt(http_factory):
  touches = []

  class UnreadFailure(httpx.AsyncByteStream):
    async def __aiter__(self):
      pytest.fail('The discarded transient error body must not be consumed')
      yield b''

    async def aclose(self):
      touches.append('closed')

  def upstream(request):
    if len(http_factory.calls) == 1:
      return httpx.Response(503, stream=UnreadFailure())
    assert touches == ['closed']
    return httpx.Response(200, content=b'final')

  client = http_factory.install(upstream)
  assert (await client.get('https://provider.example.test/')).content == b'final'
  assert touches == ['closed']
  assert len(http_factory.calls) == 2


async def test_named_client_reuse_requires_matching_timeout_and_retry_policy(http_factory):
  timeout = httpx.Timeout(connect=1, read=2, write=3, pool=4)
  first = http_factory.install(lambda request: httpx.Response(200), name='named', timeout=timeout)
  assert http_factory.factory.get_client('named', timeout=httpx.Timeout(connect=1, read=2, write=3, pool=4)) is first
  with pytest.raises(ValueError, match='named'):
    http_factory.factory.get_client('named', timeout=httpx.Timeout(connect=1, read=2, write=3, pool=5))
  with pytest.raises(ValueError, match='named'):
    http_factory.factory.get_client('named', timeout=timeout, retry_methods=ROS_RETRY_METHODS)
  assert (await first.get('https://provider.example.test/')).status_code == 200


async def test_explicit_timeout_reaches_every_request_phase(http_factory):
  timeout = httpx.Timeout(connect=1, read=2, write=3, pool=4)

  def upstream(request):
    assert request.extensions['timeout'] == {'connect': 1, 'read': 2, 'write': 3, 'pool': 4}
    return httpx.Response(200)

  client = http_factory.install(upstream, timeout=timeout)
  assert client.timeout == timeout
  await client.get('https://provider.example.test/')


async def test_named_clients_close_underlying_transport_and_can_be_recreated(http_factory):
  first = http_factory.install(lambda request: httpx.Response(200), name='first')
  second = http_factory.install(lambda request: httpx.Response(200), name='second')
  await http_factory.factory.close()
  assert first.is_closed
  assert second.is_closed
  assert len(http_factory.closes) == 2
  await http_factory.factory.close()
  assert len(http_factory.closes) == 2
  replacement = http_factory.factory.get_client('first')
  assert replacement is not first
  assert not replacement.is_closed


@pytest.mark.parametrize('overrides', [False, True])
async def test_default_timeout_inherits_legacy_write_and_pool_defaults(app, http_factory, monkeypatch, overrides):
  monkeypatch.setattr(app.settings, 'req_timeout_default', 13)
  monkeypatch.setattr(app.settings, 'req_timeout_connect', 2)
  monkeypatch.setattr(app.settings, 'req_timeout_read', 7)
  monkeypatch.setattr(app.settings, 'req_timeout_write', 3 if overrides else None)
  monkeypatch.setattr(app.settings, 'req_timeout_pool', 4 if overrides else None)
  client = http_factory.install(lambda request: httpx.Response(200))
  await client.get('https://provider.example.test/')
  assert http_factory.calls[0].extensions['timeout'] == {
    'connect': 2,
    'read': 7,
    'write': 3 if overrides else 13,
    'pool': 4 if overrides else 13,
  }


@pytest.mark.parametrize(
  ('field', 'invalid'),
  [
    ('req_max_connections', 0),
    ('req_max_keepalive_connections', -1),
    ('req_connection_retries', -1),
    ('req_timeout_default', 0),
    ('req_timeout_connect', -1),
    ('req_timeout_read', math.inf),
    ('req_timeout_write', 0),
    ('req_timeout_pool', math.nan),
    ('req_retry_backoff_factor', -1),
    ('req_retry_backoff_jitter', 1.1),
    ('req_retry_max_backoff_wait', 0),
    ('req_retry_total_timeout', math.inf),
    ('ros_rest_api_default_timeout', 0),
    ('ros_rest_api_read_timeout', math.nan),
    ('ros_rest_api_write_timeout', -1),
    ('ros_rest_api_pool_timeout', 0),
  ],
)
async def test_http_settings_reject_unbounded_or_invalid_resource_policy(app, field, invalid):
  from pydantic import ValidationError

  settings_type = type(app.settings)
  with pytest.raises(ValidationError) as caught:
    settings_type(_env_file=None, **{field: invalid})
  assert field in {error['loc'][0] for error in caught.value.errors()}


async def test_http_settings_allow_disabled_retry_and_keepalive_and_inherited_timeouts(app):
  configured = type(app.settings)(
    _env_file=None,
    req_connection_retries=0,
    req_max_keepalive_connections=0,
    req_retry_backoff_factor=0,
    req_retry_backoff_jitter=0,
    req_timeout_write=None,
    req_timeout_pool=None,
    ros_rest_api_write_timeout=None,
    ros_rest_api_pool_timeout=None,
  )
  assert configured.req_connection_retries == configured.req_max_keepalive_connections == 0
  assert configured.req_timeout_write is configured.req_timeout_pool is None


@pytest.mark.parametrize(
  ('field', 'changed'),
  [
    ('req_max_connections', 8),
    ('req_max_keepalive_connections', 2),
    ('req_ssl_verify', False),
    ('req_connection_retries', 1),
    ('req_retry_backoff_factor', 0.5),
    ('req_retry_backoff_jitter', 0.5),
    ('req_retry_max_backoff_wait', 4),
    ('req_retry_total_timeout', 8),
    ('req_timeout_read', 8),
  ],
)
async def test_named_clients_reject_changed_effective_transport_policy(app, http_factory, monkeypatch, field, changed):
  first = http_factory.install(lambda request: httpx.Response(200), name='policy')
  monkeypatch.setattr(app.settings, field, changed)
  with pytest.raises(ValueError, match='policy'):
    http_factory.factory.get_client('policy')
  assert not first.is_closed
  assert (await first.get('https://provider.example.test/')).status_code == 200


@pytest.mark.parametrize('methods', [frozenset(), frozenset({'PUT'}), frozenset({'GET', 'PUT'})])
async def test_factory_rejects_unsafe_or_empty_retry_method_policy(http_factory, methods):
  with pytest.raises(ValueError, match='method'):
    http_factory.factory.get_client('invalid', retry_methods=methods)
  assert http_factory.calls == []


@pytest.mark.parametrize('overrides', [False, True])
async def test_real_router_client_selects_retry_methods_and_four_timeout_phases(
  app, http_factory, monkeypatch, overrides
):
  monkeypatch.setattr(app.settings, 'req_timeout_connect', 2)
  monkeypatch.setattr(app.settings, 'ros_rest_api_default_timeout', 59)
  monkeypatch.setattr(app.settings, 'ros_rest_api_read_timeout', 58)
  monkeypatch.setattr(app.settings, 'ros_rest_api_write_timeout', 7 if overrides else None)
  monkeypatch.setattr(app.settings, 'ros_rest_api_pool_timeout', 8 if overrides else None)
  # Re-import only the integration class so its import-owned policy uses this test's settings.
  monkeypatch.delitem(sys.modules, 'client.ros_updater_client', raising=False)
  module = importlib.import_module('client.ros_updater_client')
  client = module.RosClient._RosClient__client
  assert client.timeout == httpx.Timeout(connect=2, read=58, write=7 if overrides else 59, pool=8 if overrides else 59)
  outcomes = []

  async def send(transport, request):
    outcomes.append(request.method)
    return httpx.Response(503 if outcomes.count(request.method) == 1 else 200)

  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', send)
  for method in ('GET', 'POST', 'PATCH', 'DELETE'):
    assert (await client.request(method, 'http://router.example.test/rest/ip/route/print')).status_code == 200
    assert outcomes.count(method) == 2
  assert (await client.put('http://router.example.test/rest/routing/table')).status_code == 503
  assert outcomes.count('PUT') == 1


@pytest.mark.parametrize('retry_after', ['999999', 'Wed, 01 Jan 2098 00:00:00 GMT', 'malformed', None])
async def test_retry_after_and_backoff_have_per_wait_and_total_sleep_bounds(app, monkeypatch, retry_after):
  import httpx_retries.retry as retry_module

  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(app.settings, 'req_connection_retries', 10)
  monkeypatch.setattr(app.settings, 'req_retry_backoff_factor', 1)
  monkeypatch.setattr(app.settings, 'req_retry_backoff_jitter', 0)
  monkeypatch.setattr(app.settings, 'req_retry_max_backoff_wait', 2)
  monkeypatch.setattr(app.settings, 'req_retry_total_timeout', 5)
  calls, delays = [], []

  async def fake_sleep(delay):
    delays.append(delay)

  async def upstream(transport, request):
    calls.append(request)
    return httpx.Response(429, headers={} if retry_after is None else {'Retry-After': retry_after}, content=b'limited')

  monkeypatch.setattr(retry_module, 'asyncio', SimpleNamespace(sleep=fake_sleep))
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', upstream)
  try:
    response = await factory.get_client().get('https://provider.example.test/')
    assert response.status_code == 429
    assert response.content == b'limited'
    assert delays == [2, 2, 1]
    assert len(calls) == 4
    if retry_after is not None:
      assert response.headers['Retry-After'] == retry_after
  finally:
    await factory.close()


@pytest.mark.parametrize('fraction', [0.0, 0.5, 1.0])
async def test_retry_jitter_uses_configured_full_range_and_stays_within_wait_caps(app, monkeypatch, fraction):
  import httpx_retries.retry as retry_module

  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(app.settings, 'req_connection_retries', 3)
  monkeypatch.setattr(app.settings, 'req_retry_backoff_factor', 0.25)
  monkeypatch.setattr(app.settings, 'req_retry_backoff_jitter', 1)
  monkeypatch.setattr(app.settings, 'req_retry_max_backoff_wait', 2)
  monkeypatch.setattr(app.settings, 'req_retry_total_timeout', 5)
  draws, delays, calls = [], [], []

  def uniform(low, high):
    draws.append((low, high))
    return low + (high - low) * fraction

  async def fake_sleep(delay):
    delays.append(delay)

  async def upstream(transport, request):
    calls.append(request)
    return httpx.Response(503)

  monkeypatch.setattr(retry_module, 'random', SimpleNamespace(uniform=uniform))
  monkeypatch.setattr(retry_module, 'asyncio', SimpleNamespace(sleep=fake_sleep))
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', upstream)
  try:
    assert (await factory.get_client().get('https://provider.example.test/')).status_code == 503
    assert len(calls) == 4
    assert draws == [(0, 1)] * 3
    assert delays == [0.5 * fraction, fraction, 2 * fraction]
    assert all(0 <= delay <= 2 for delay in delays)
    assert sum(delays) <= 5
  finally:
    await factory.close()


@pytest.mark.parametrize('verify', [False, True])
async def test_transport_preserves_environment_certificate_policy(app, http_factory, monkeypatch, tmp_path, verify):
  """A configured CA file must be honored when verification is enabled."""
  monkeypatch.setenv('SSL_CERT_FILE', str(tmp_path / 'missing-test-ca.pem'))
  monkeypatch.setattr(app.settings, 'req_ssl_verify', verify)
  if verify:
    with pytest.raises(FileNotFoundError):
      http_factory.factory.get_client('certificate-policy')
  else:
    client = http_factory.factory.get_client('certificate-policy')
    assert not client.is_closed


@pytest.mark.parametrize('kind', ['firewall', 'route'])
@pytest.mark.parametrize('final_status', [204, 404, 403])
async def test_router_delete_recovers_lost_response_and_accepts_already_absent(
  app, http_factory, monkeypatch, caplog, kind, final_status
):
  module = importlib.import_module('client.ros_updater_client')
  config_module = importlib.import_module('models.dto.ros_config_dto')
  responses = importlib.import_module('models.http.ros_rest_api_resp')
  config = config_module.RosConfigDto(
    id=1, host='router.example.test', user='dummy-user', passwd='dummy-password', bgp_list_name='test'
  )
  address = (
    responses.RosFirewallIpResp(**{'.id': '*A', 'address': '8.8.8.8', 'list': 'test'})
    if kind == 'firewall'
    else responses.RosRoutingIpResp(**{'.id': '*A', 'dst-address': '8.8.8.8', 'gateway': '1.1.1.1'})
  )

  def upstream(request):
    if len(http_factory.calls) == 1:
      raise httpx.ReadError('Synthetic lost deletion response')
    return httpx.Response(final_status)

  client = http_factory.install(upstream, name='delete', retry_methods=ROS_RETRY_METHODS)
  instance = module.RosClient()
  monkeypatch.setattr(instance, '_RosClient__client', client)

  async def no_pause(delay):
    pass

  monkeypatch.setattr(module, 'sleep', no_pause)
  action = config_module.RosAction.FIREWALL_DELETE if kind == 'firewall' else config_module.RosAction.ROUTING_DELETE
  await instance._RosClient__delete_from_ros(config, action, [address])
  assert len(http_factory.calls) == 2
  assert all(request.method == 'DELETE' and request.url.path.endswith('/*A') for request in http_factory.calls)
  assert ('Delete failed' in caplog.text) is (final_status == 403)


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


async def test_dns_snapshot_elements_reject_mutation(app):
  server = app.Server(server='192.0.2.53', id=42)
  with pytest.raises(dataclasses.FrozenInstanceError):
    server.server = '192.0.2.54'
  with pytest.raises(dataclasses.FrozenInstanceError):
    server.id = 43
  assert dataclasses.asdict(server) == {'server': '192.0.2.53', 'id': 42}


async def test_single_checks_reload_dns_and_explicit_selection_bypasses_configuration(
  app, resolver, repository, network
):
  requests = network({'192.0.2.53': 'positive', '192.0.2.54': 'nodata', '192.0.2.55': 'positive'})
  repository.get_dns_servers_for_resolve.side_effect = [
    ([app.Server(server='192.0.2.53', id=42)], []),
    ([app.Server(server='192.0.2.54', id=43)], []),
  ]
  first = await resolver.resolve_once('www.example.test')
  second = await resolver.resolve_once('www.example.test')
  assert [(row.server, row.ips_v4) for row in first.results] == [('192.0.2.53', ['8.8.8.8'])]
  assert [(row.server, row.ips_v4) for row in second.results] == [('192.0.2.54', [])]
  repository.get_dns_servers_for_resolve.side_effect = RuntimeError('Configuration must be bypassed')
  before = metric_total('resolution_dns_duration_seconds_count', server_id='88', transport='classic')
  selected = SimpleNamespace(id=88, server='192.0.2.55', doh_server=None)
  third = await resolver.resolve_once('www.example.test', selected_dns_servers=[selected])
  assert [(row.server, row.ips_v4) for row in third.results] == [('192.0.2.55', ['8.8.8.8'])]
  assert repository.get_dns_servers_for_resolve.await_count == 2
  assert {server for server, _ in requests} == {'192.0.2.53', '192.0.2.54', '192.0.2.55'}
  assert metric_total('resolution_dns_duration_seconds_count', server_id='88', transport='classic') - before == 2
  repository.put_domain_after_resolve.assert_not_awaited()


@pytest.mark.parametrize('mode', ['new', 'stale'])
async def test_empty_job_does_not_read_dns_or_admit_work(app, resolver, repository, monkeypatch, mode):
  jobs = importlib.import_module('jobs.job_registry')
  monkeypatch.setattr(resolver, 'domains_resolve_queue', asyncio.Queue(maxsize=1))
  repository.get_new_domains_for_resolve = AsyncMock(return_value=[])
  repository.get_stale_domains_for_resolve = AsyncMock(return_value=[])
  repository.get_dns_servers_for_resolve.side_effect = RuntimeError('An empty job needs no configuration')
  await asyncio.wait_for(resolver.domains_resolve(getattr(jobs.Jobs, f'DOMAINS_RESOLVE_{mode.upper()}')), timeout=2)
  repository.get_dns_servers_for_resolve.assert_not_awaited()
  repository.put_domain_after_resolve.assert_not_awaited()
  assert resolver.domains_resolve_queue.qsize() == resolver.domains_resolve_queue._unfinished_tasks == 0


@pytest.mark.parametrize('mode', ['new', 'stale'])
async def test_job_copies_dns_collections_before_network_work(
  app, resolver, repository, monkeypatch, dns_message, mode
):
  jobs = importlib.import_module('jobs.job_registry')
  monkeypatch.setattr(resolver, 'domains_resolve_queue', asyncio.Queue(maxsize=1))
  monkeypatch.setattr(resolver, '_DomainsResolver__stop_domains_resolve_event', threading.Event())
  domains = [app.dto.DomainResult(id=index, name=f'domain-{index}.example.test') for index in (1, 2)]
  repository.get_new_domains_for_resolve = AsyncMock(return_value=domains)
  repository.get_stale_domains_for_resolve = AsyncMock(return_value=domains)
  source_servers = [app.Server(server='192.0.2.53', id=42)]
  repository.get_dns_servers_for_resolve.return_value = (source_servers, [])
  requests = []

  async def classic(boundary, qname, rdtype, **kwargs):
    requests.append((boundary.nameservers[0], qname, rdtype))
    source_servers[:] = [app.Server(server='192.0.2.54', id=43)]
    return SimpleNamespace(response=dns_message('nodata', query=dns.message.make_query(qname, rdtype)))

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  await asyncio.wait_for(resolver.domains_resolve(getattr(jobs.Jobs, f'DOMAINS_RESOLVE_{mode.upper()}')), timeout=2)
  assert set(requests) == {
    ('192.0.2.53', domain.name, record_type)
    for domain in domains
    for record_type in (dns.rdatatype.A, dns.rdatatype.CNAME)
  }
  repository.get_dns_servers_for_resolve.assert_awaited_once_with()
  assert repository.put_domain_after_resolve.await_count == 2
  assert all(domain.resolution_complete for domain in domains)
  assert resolver.domains_resolve_queue._unfinished_tasks == 0


@pytest.mark.parametrize(
  'field',
  [
    'dns_timeout',
    'dns_lifetime',
    'dns_operation_timeout',
    'doh_timeout_connect',
    'doh_timeout_read',
    'doh_timeout_write',
    'doh_timeout_pool',
    'doh_retry_total_timeout',
    'doh_operation_timeout',
    'ripe_stat_timeout_connect',
    'ripe_stat_timeout_read',
    'ripe_stat_timeout_write',
    'ripe_stat_timeout_pool',
    'ripe_stat_retry_total_timeout',
    'ripe_stat_operation_timeout',
  ],
)
@pytest.mark.parametrize('invalid', [0, -1, math.inf, math.nan])
async def test_provider_duration_settings_reject_unbounded_or_nonpositive_values(app, field, invalid):
  from pydantic import ValidationError

  with pytest.raises(ValidationError) as caught:
    type(app.settings)(_env_file=None, **{field: invalid})
  assert field in {error['loc'][0] for error in caught.value.errors()}


@pytest.mark.parametrize('field', ['doh_connection_retries', 'ripe_stat_connection_retries'])
async def test_provider_retry_counts_allow_zero_and_reject_negative_values(app, field):
  from pydantic import ValidationError

  assert getattr(type(app.settings)(_env_file=None, **{field: 0}), field) == 0
  with pytest.raises(ValidationError) as caught:
    type(app.settings)(_env_file=None, **{field: -1})
  assert field in {error['loc'][0] for error in caught.value.errors()}


@pytest.mark.parametrize('value', [0, -1])
async def test_ripe_concurrency_setting_rejects_permanent_admission_deadlock(app, value):
  from pydantic import ValidationError

  with pytest.raises(ValidationError) as caught:
    type(app.settings)(_env_file=None, ripe_stat_requests_semaphore_limit=value)
  assert 'ripe_stat_requests_semaphore_limit' in {error['loc'][0] for error in caught.value.errors()}


async def test_provider_retry_override_is_independent_and_immutable(app, http_factory, monkeypatch):
  monkeypatch.setattr(app.settings, 'req_connection_retries', 9)
  client = http_factory.install(
    lambda request: httpx.Response(503), name='bounded-provider', connection_retries=1, retry_total_timeout=0.5
  )
  assert (await client.get('https://provider.example.test/')).status_code == 503
  assert len(http_factory.calls) == 2
  assert http_factory.factory.get_client('bounded-provider', connection_retries=1, retry_total_timeout=0.5) is client
  for policy in (
    {'connection_retries': 2, 'retry_total_timeout': 0.5},
    {'connection_retries': 1, 'retry_total_timeout': 0.6},
  ):
    with pytest.raises(ValueError, match='bounded-provider'):
      http_factory.factory.get_client('bounded-provider', **policy)


async def test_provider_retry_sleep_override_bounds_backoff_without_changing_general_policy(app, monkeypatch):
  import httpx_retries.retry as retry_module

  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(app.settings, 'req_connection_retries', 9)
  monkeypatch.setattr(app.settings, 'req_retry_total_timeout', 5)
  monkeypatch.setattr(app.settings, 'req_retry_max_backoff_wait', 2)
  delays, calls = [], []

  async def sleep(delay):
    delays.append(delay)

  async def upstream(transport, request):
    calls.append(request)
    return httpx.Response(429, headers={'Retry-After': '999999'})

  monkeypatch.setattr(retry_module, 'asyncio', SimpleNamespace(sleep=sleep))
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', upstream)
  try:
    client = factory.get_client('limited', connection_retries=9, retry_total_timeout=0.5)
    assert (await client.get('https://provider.example.test/')).status_code == 429
    assert delays == [0.5]
    assert len(calls) == 2
    assert app.settings.req_retry_total_timeout == 5
  finally:
    await factory.close()


@pytest.mark.parametrize('provider', ['doh', 'ripe_stat'])
@pytest.mark.parametrize('retries', [0, 2])
async def test_provider_composition_uses_its_own_phase_and_retry_settings(app, monkeypatch, provider, retries):
  from httpx_retries import Retry

  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(app.settings, 'req_connection_retries', 9)
  monkeypatch.setattr(app.settings, f'{provider}_connection_retries', retries)
  phases = dict(connect=0.3, read=0.4, write=0.5, pool=0.6)
  for phase, value in phases.items():
    monkeypatch.setattr(app.settings, f'{provider}_timeout_{phase}', value)
  calls = []

  async def upstream(transport, request):
    calls.append(request)
    return httpx.Response(503)

  async def no_sleep(self, response):
    pass

  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', upstream)
  monkeypatch.setattr(Retry, 'asleep', no_sleep)
  module_name = 'client.domains_resolving_client' if provider == 'doh' else 'client.ripe_stat_client'
  monkeypatch.delitem(sys.modules, module_name, raising=False)
  module = importlib.import_module(module_name)
  client = (
    module.DomainsResolver._DomainsResolver__http_client
    if provider == 'doh'
    else module.RipeStatClient._RipeStatClient__client
  )
  try:
    assert (await client.get('https://provider.example.test/')).status_code == 503
    assert len(calls) == retries + 1
    assert all(request.extensions['timeout'] == phases for request in calls)
  finally:
    await factory.close()


@pytest.mark.parametrize('record_type', ['A', 'CNAME'])
async def test_classic_dns_passes_explicit_timeout_and_lifetime(app, resolver, dns_message, monkeypatch, record_type):
  monkeypatch.setattr(app.settings, 'dns_timeout', 0.4)
  monkeypatch.setattr(app.settings, 'dns_lifetime', 0.9)
  seen = []

  async def classic(boundary, qname, rdtype, **kwargs):
    seen.append((boundary.timeout, kwargs.get('lifetime', boundary.lifetime), rdtype, kwargs['search']))
    return SimpleNamespace(response=dns_message('nodata', query=dns.message.make_query(qname, rdtype)))

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  domain = app.dto.DomainResult(id=1, name='www.example.test')
  server = app.Server(server='192.0.2.53')
  if record_type == 'A':
    result = await resolver._DomainsResolver__default_resolver(domain, server, dns.rdatatype.A)
    assert result.status == app.dto.DnsQueryStatus.ABSENT
  else:
    aliases = []
    await resolver._DomainsResolver__cname_default_resolver(domain, server, aliases)
    assert aliases == []
  assert seen == [(0.4, 0.9, getattr(dns.rdatatype, record_type), False)]


@pytest.mark.parametrize('transport', ['classic', 'doh'])
@pytest.mark.parametrize('record_type', ['A', 'CNAME'])
@pytest.mark.parametrize('phase', ['semaphore', 'query'])
async def test_dns_total_deadline_bounds_admission_and_query_without_external_cancellation(
  app, resolver, monkeypatch, transport, record_type, phase
):
  monkeypatch.setattr(
    app.settings, 'dns_operation_timeout' if transport == 'classic' else 'doh_operation_timeout', 0.02
  )
  entered = asyncio.Event()
  exited = asyncio.Event()
  calls = []

  async def blocked(*args, **kwargs):
    calls.append('query')
    entered.set()
    try:
      await asyncio.Future()
    finally:
      exited.set()

  semaphore = asyncio.Semaphore(1)
  resolver._DomainsResolver__semaphore = semaphore
  if phase == 'semaphore':
    await semaphore.acquire()
  if transport == 'classic':
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', blocked)
  else:
    resolver._DomainsResolver__http_client = app.make_http(blocked)
  prefix = 'default' if transport == 'classic' else 'doh'
  arguments = dict(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    dns_server=app.Server(server='192.0.2.53' if transport == 'classic' else 'https://dns.example.test/'),
  )
  aliases = []
  if record_type == 'A':
    method = getattr(resolver, f'_DomainsResolver__{prefix}_resolver')
    arguments['lookup_type'] = dns.rdatatype.A
  else:
    method = getattr(resolver, f'_DomainsResolver__cname_{prefix}_resolver')
    arguments['cname_domains'] = aliases
  try:
    result = await asyncio.wait_for(method(**arguments), timeout=1)
  finally:
    if phase == 'semaphore':
      semaphore.release()
  if record_type == 'A':
    assert result.status == app.dto.DnsQueryStatus.FAILURE
    assert result.addresses == ()
  else:
    assert aliases == []
  assert calls == (['query'] if phase == 'query' else [])
  assert entered.is_set() is (phase == 'query')
  assert exited.is_set() is (phase == 'query')
  await asyncio.wait_for(semaphore.acquire(), timeout=1)
  semaphore.release()


@pytest.mark.parametrize('provider', ['doh', 'ripe'])
async def test_provider_deadline_closes_a_stalled_response_body(app, resolver, monkeypatch, provider):
  setting = 'doh_operation_timeout' if provider == 'doh' else 'ripe_stat_operation_timeout'
  monkeypatch.setattr(app.settings, setting, 0.02)
  closed = []

  class Stream(httpx.AsyncByteStream):
    async def __aiter__(self):
      yield b'partial'
      await asyncio.Future()

    async def aclose(self):
      closed.append(True)

  client = app.make_http(lambda request: httpx.Response(200, stream=Stream()))
  if provider == 'doh':
    resolver._DomainsResolver__http_client = client
    result = await asyncio.wait_for(
      resolver._DomainsResolver__doh_resolver(
        app.dto.DomainResult(id=1, name='www.example.test'),
        app.Server(server='https://dns.example.test/'),
        dns.rdatatype.A,
      ),
      timeout=1,
    )
    assert result.status == app.dto.DnsQueryStatus.FAILURE
  else:
    ripe = app.ripe.RipeStatClient()
    ripe._RipeStatClient__client = client
    with pytest.raises(app.ripe.RipeStatClientError):
      await asyncio.wait_for(ripe.get_prefix('8.8.8.0'), timeout=1)
  assert closed == [True]


@pytest.mark.parametrize('phase', ['cache_read', 'cache_recheck', 'lock', 'network'])
@pytest.mark.parametrize('cancelled', [False, True])
async def test_ripe_total_deadline_and_external_cancellation_cover_every_wait(app, monkeypatch, phase, cancelled):
  cache = importlib.import_module('cache.cache').ripe_stat_cache
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 1 if cancelled else 0.02)
  entered, exited = asyncio.Event(), asyncio.Event()
  calls, reads, releases = [], [], []

  async def block():
    entered.set()
    try:
      await asyncio.Future()
    finally:
      exited.set()

  async def cache_read(key):
    reads.append(key)
    if phase == 'cache_read' or (phase == 'cache_recheck' and len(reads) == 2):
      await block()
    return None

  @asynccontextmanager
  async def lock(**kwargs):
    if phase == 'lock':
      await block()
    try:
      yield
    finally:
      releases.append(True)

  async def upstream(request):
    calls.append(request)
    await block()

  monkeypatch.setattr(cache, 'get', cache_read)
  monkeypatch.setattr(cache, 'lock', lock)
  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  metric_phase = {
    'cache_read': 'cache_lookup',
    'cache_recheck': 'cache_recheck',
    'lock': 'lock_wait',
    'network': 'network',
  }[phase]
  before_cancelled = metric_total('resolution_ripe_duration_seconds_count', phase=metric_phase, outcome='cancelled')
  before_failure = metric_total('resolution_ripe_duration_seconds_count', phase=metric_phase, outcome='failure')
  task = asyncio.create_task(ripe.get_prefix('8.8.8.0'))
  try:
    await asyncio.wait_for(entered.wait(), timeout=1)
    if cancelled:
      task.cancel()
    with pytest.raises(asyncio.CancelledError if cancelled else app.ripe.RipeStatClientError):
      await asyncio.wait_for(task, timeout=1)
    assert exited.is_set()
    assert len(calls) == int(phase == 'network')
    assert releases == ([True] if phase in {'cache_recheck', 'network'} else [])
    assert metric_total(
      'resolution_ripe_duration_seconds_count', phase=metric_phase, outcome='cancelled'
    ) - before_cancelled == int(cancelled)
    assert metric_total(
      'resolution_ripe_duration_seconds_count', phase=metric_phase, outcome='failure'
    ) - before_failure == int(not cancelled)
  finally:
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def test_ripe_deadline_failure_releases_real_cache_lock_and_is_not_cached(app, monkeypatch):
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 0.02)
  calls = []

  async def upstream(request):
    calls.append(request)
    if len(calls) == 1:
      await asyncio.Future()
    return httpx.Response(200, json={'status': 'ok', 'data': {'prefix': '8.8.8.0/24'}})

  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  with pytest.raises(app.ripe.RipeStatClientError):
    await asyncio.wait_for(ripe.get_prefix('8.8.8.0'), timeout=1)
  assert (await asyncio.wait_for(ripe.get_prefix('8.8.8.0'), timeout=1)).prefix == '8.8.8.0/24'
  assert (await asyncio.wait_for(ripe.get_prefix('8.8.8.0'), timeout=1)).prefix == '8.8.8.0/24'
  assert len(calls) == 2


async def test_ripe_admission_time_consumes_the_same_budget_as_network_wait(app, resolver, monkeypatch):
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 0.6)
  semaphore = asyncio.Semaphore(1)
  await semaphore.acquire()
  resolver._DomainsResolver__ripe_stat_semaphore = semaphore
  entered, exited = asyncio.Event(), asyncio.Event()

  async def upstream(request):
    entered.set()
    try:
      await asyncio.Future()
    finally:
      exited.set()

  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  resolver._DomainsResolver__ripe_stat_client = ripe
  # This controlled admission delay consumes most of the operation's real timer.
  release = asyncio.get_running_loop().call_later(0.4, semaphore.release)
  task = asyncio.create_task(resolver._DomainsResolver__get_ip_address_for_storage('8.8.8.0', []))
  try:
    await asyncio.wait_for(entered.wait(), timeout=1)
    # A fresh network budget would still be blocked after this remaining window.
    assert await asyncio.wait_for(task, timeout=0.4) == '8.8.8.0'
    assert exited.is_set()
  finally:
    release.cancel()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def test_ripe_child_task_owns_deadline_after_parent_budget_scope_exits(app, monkeypatch):
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 0.03)
  entered, exited = asyncio.Event(), asyncio.Event()

  async def upstream(request):
    entered.set()
    try:
      await asyncio.Future()
    finally:
      exited.set()

  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  task = None
  try:
    async with ripe.lookup_budget():
      task = asyncio.create_task(ripe.get_prefix('8.8.8.0'))
      await asyncio.wait_for(entered.wait(), timeout=1)
    with pytest.raises(app.ripe.RipeStatClientError):
      await asyncio.wait_for(task, timeout=1)
    assert exited.is_set()
  finally:
    if task is not None:
      task.cancel()
      await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('cancelled', [False, True])
async def test_resolver_ripe_deadline_and_external_cancellation_keep_distinct_metrics(
  app, resolver, monkeypatch, cancelled
):
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 1 if cancelled else 0.02)
  entered = asyncio.Event()

  async def upstream(request):
    entered.set()
    await asyncio.Future()

  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = app.make_http(upstream)
  resolver._DomainsResolver__ripe_stat_client = ripe
  before_cancelled = metric_total('resolution_ripe_duration_seconds_count', phase='lookup', outcome='cancelled')
  before_failure = metric_total('resolution_ripe_duration_seconds_count', phase='lookup', outcome='failure')
  task = asyncio.create_task(resolver._DomainsResolver__get_ip_address_for_storage('8.8.8.0', []))
  try:
    await asyncio.wait_for(entered.wait(), timeout=1)
    if cancelled:
      task.cancel()
      with pytest.raises(asyncio.CancelledError):
        await task
    else:
      assert await asyncio.wait_for(task, timeout=1) == '8.8.8.0'
    assert metric_total(
      'resolution_ripe_duration_seconds_count', phase='lookup', outcome='cancelled'
    ) - before_cancelled == int(cancelled)
    assert metric_total(
      'resolution_ripe_duration_seconds_count', phase='lookup', outcome='failure'
    ) - before_failure == int(not cancelled)
  finally:
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('stored', [None, '8.8.8.0/25'])
async def test_ripe_semaphore_deadline_preserves_stored_prefix_or_host(app, resolver, monkeypatch, stored):
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 0.02)
  semaphore = asyncio.Semaphore(1)
  await semaphore.acquire()
  resolver._DomainsResolver__ripe_stat_semaphore = semaphore
  boundary = AsyncMock(side_effect=AssertionError('Admission timeout must not call the provider'))
  resolver._DomainsResolver__ripe_stat_client = SimpleNamespace(get_prefix=boundary)
  current = [] if stored is None else [app.Ip(id=10, ip_address=stored, addr_type=4)]
  try:
    result = await asyncio.wait_for(
      resolver._DomainsResolver__get_ip_address_for_storage('8.8.8.0', current), timeout=1
    )
  finally:
    semaphore.release()
  assert result == (stored or '8.8.8.0')
  boundary.assert_not_awaited()
  await asyncio.wait_for(semaphore.acquire(), timeout=1)
  semaphore.release()


async def test_independent_ripe_lookups_overlap_and_share_one_global_limit(app, resolver, monkeypatch):
  monkeypatch.setattr(app.settings, 'ripe_stat_requests_semaphore_limit', 2)
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 2)
  resolver._DomainsResolver__ripe_stat_semaphore = asyncio.Semaphore(2)
  release, overlapped = asyncio.Event(), asyncio.Event()
  active, peak = 0, 0
  addresses = []

  async def upstream(address):
    nonlocal active, peak
    addresses.append(address)
    active += 1
    peak = max(peak, active)
    if active == 2:
      overlapped.set()
    try:
      await release.wait()
      return SimpleNamespace(prefix=f'{address}/24')
    finally:
      active -= 1

  resolver._DomainsResolver__ripe_stat_client = SimpleNamespace(get_prefix=upstream)
  domains = [
    app.dto.DomainResult(id=index, name=f'domain-{index}.example.test', resolution_complete=True) for index in (1, 2)
  ]
  domains[0].result.A = ['8.8.8.0', '8.8.4.0', '8.8.8.0']
  domains[1].result.A = ['9.9.9.0', '1.1.1.0']
  tasks = [asyncio.create_task(resolver._DomainsResolver__ips_processing(domain, [])) for domain in domains]
  try:
    await asyncio.wait_for(overlapped.wait(), timeout=1)
    assert peak == active == 2
    release.set()
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=2)
  finally:
    release.set()
    for task in tasks:
      task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
  assert peak == 2
  assert active == 0
  assert sorted(addresses) == ['1.1.1.0', '8.8.4.0', '8.8.8.0', '9.9.9.0']
  assert [{ip.ip_address for ip in domain.insert.ips_insert} for domain in domains] == [
    {'8.8.8.0/24', '8.8.4.0/24'},
    {'9.9.9.0/24', '1.1.1.0/24'},
  ]
  assert all(domain.insert.ips_delete == [] for domain in domains)


async def test_ripe_worker_cancellation_drains_started_requests_and_releases_global_limit(app, resolver, monkeypatch):
  monkeypatch.setattr(app.settings, 'ripe_stat_requests_semaphore_limit', 2)
  resolver._DomainsResolver__ripe_stat_semaphore = asyncio.Semaphore(2)
  entered = asyncio.Event()
  active = 0

  async def blocked(address):
    nonlocal active
    active += 1
    if active == 2:
      entered.set()
    try:
      await asyncio.Future()
    finally:
      active -= 1

  resolver._DomainsResolver__ripe_stat_client = SimpleNamespace(get_prefix=blocked)
  domain = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=True)
  domain.result.A = [f'8.8.{index}.0' for index in range(64)]
  original_tasks = asyncio.all_tasks()
  task = asyncio.create_task(resolver._DomainsResolver__ips_processing(domain, []))
  try:
    await asyncio.wait_for(entered.wait(), timeout=1)
    # Waiting IPs must not each retain a separate task behind the provider semaphore.
    assert len(asyncio.all_tasks() - original_tasks) <= 3
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
      await task
    assert active == 0
    assert domain.insert.ips_insert == domain.insert.ips_delete == []
    semaphore = resolver._DomainsResolver__ripe_stat_semaphore
    await asyncio.wait_for(semaphore.acquire(), timeout=1)
    await asyncio.wait_for(semaphore.acquire(), timeout=1)
    semaphore.release()
    semaphore.release()
  finally:
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
