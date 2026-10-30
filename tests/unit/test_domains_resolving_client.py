"""DNS evidence, cycle completeness, and conservative reconciliation."""

import dataclasses
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpx
import pytest

pytestmark = pytest.mark.unit


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
