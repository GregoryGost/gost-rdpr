"""SQLite integration and service E2E tests of startup, migrations, API flows, and shutdown."""

import ast
import asyncio
import dataclasses
import importlib
import importlib.metadata
import json
import logging
import math
import os
import platform
import shutil
import sqlite3
import statistics
import sys
from base64 import urlsafe_b64encode
from contextlib import asynccontextmanager, closing, contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiosqlite
import dns.asyncresolver
import dns.message
import dns.rdatatype
import httpx
import pytest
from fastapi import FastAPI
from prometheus_client import REGISTRY
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import event, insert, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.integration

# SQLite persists UTC timestamps without a timezone component.
STALE_CHECKPOINT = datetime(2000, 1, 1, tzinfo=UTC).replace(tzinfo=None)


@pytest.fixture
async def resource_api(app, store, monkeypatch):
  """Wire HTTP handlers to the same isolated real database used by repository tests."""
  api = FastAPI()
  for module_name, class_name in (
    ('domains_lists_router', 'DomainsListsRouter'),
    ('ips_lists_router', 'IpsListsRouter'),
    ('dns_servers_router', 'DnsServersRouter'),
    ('domains_router', 'DomainsRouter'),
    ('ips_router', 'IpsRouter'),
    ('ros_configs_router', 'RosConfigsRouter'),
    ('statistics_router', 'StatisticsRouter'),
  ):
    module = importlib.import_module(f'routers.{module_name}')
    monkeypatch.setattr(module, 'db', store)
    api.include_router(getattr(module, class_name)().get_router())
  transport = httpx.ASGITransport(app=api, raise_app_exceptions=False)
  async with httpx.AsyncClient(transport=transport, base_url='http://service.test', trust_env=False) as client:
    yield client


@pytest.mark.parametrize('count', [0, 1, 3])
async def test_statistics_routeros_total_counts_real_configurations(app, store, resource_api, count):
  if count:
    async with store._DataBase__write_engine.begin() as connection:
      await connection.execute(
        insert(app.database.RosConfigsDbo),
        [
          {
            'host': f'router-{index}.example.test',
            'user': 'dummy-user',
            'passwd': 'dummy-password',
            'bgp_list_name': 'routes',
          }
          for index in range(count)
        ],
      )
  async with AsyncSession(store._DataBase__read_engine) as session:
    assert (await app.database.RosConfigsDbo.get_stats(session)).total == count
  response = await resource_api.get('/stats')
  assert response.status_code == 200
  payload = response.json()
  assert payload['ros'] == {'total': count}
  assert payload['dns'] == {'total': 0, 'classic': 0, 'doh': 0}
  assert payload['domains'] == {'total': 0, 'resolved': 0, 'unresolved': 0, 'lists_total': 0, 'per_list': []}
  assert payload['ips'] == {
    'total': 0,
    'v4_total': 0,
    'v6_total': 0,
    'linked_to_domain': 0,
    'standalone': 0,
    'lists_total': 0,
    'per_list': [],
  }
  assert (await store.stats()).ros.total == count


@pytest.mark.parametrize(('subtype', 'expected'), [(None, 3), (4, 2), (6, 1)])
async def test_statistics_ip_growth_filters_version_in_real_sql(app, store, resource_api, subtype, expected):
  timestamp = datetime(2024, 1, 2, 12, tzinfo=UTC).replace(tzinfo=None)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.IpRecordsDbo),
      [
        {'addr_type': version, 'ip_address': address, 'created_at': timestamp}
        for version, address in [(4, '8.8.8.8'), (4, '9.9.9.9'), (6, '2001:4860:4860::8888')]
      ],
    )
  query = {'entity': 'ips', 'start_date': '2024-01-01 00:00:00', 'end_date': '2024-01-03 23:59:59'}
  direct = await store.stats_growth(
    before_time=perf_counter(),
    entity='ips',
    granularity='day',
    date_field='created_at',
    start_date=query['start_date'],
    end_date=query['end_date'],
    ip_subtype=subtype,
  )
  assert direct.total_in_period == expected
  if subtype is not None:
    query['ip_subtype'] = subtype
  response = await resource_api.get('/stats/growth', params=query)
  assert response.status_code == 200
  payload = response.json()
  assert payload['ip_subtype'] == subtype
  assert payload['total_in_period'] == expected
  assert payload['payload'] == [
    {'date': '2024-01-01', 'count': 0},
    {'date': '2024-01-02', 'count': expected},
    {'date': '2024-01-03', 'count': 0},
  ]
  assert [point.to_dict() for point in direct.payload] == payload['payload']


@pytest.mark.parametrize(
  ('path', 'records', 'field', 'search'),
  [
    (
      '/domains/lists',
      [
        {'name': 'first-domain-list', 'url': 'https://lists.example.test/first'},
        {'name': 'second-domain-list', 'url': 'https://lists.example.test/second', 'description': 'Second list'},
      ],
      'name',
      'second-domain',
    ),
    (
      '/ips/lists',
      [
        {'name': 'first-ip-list', 'url': 'https://lists.example.test/first'},
        {'name': 'second-ip-list', 'url': 'https://lists.example.test/second', 'description': 'Second list'},
      ],
      'name',
      'second-ip',
    ),
    ('/dns', [{'server': '8.8.8.8'}, {'doh_server': 'https://dns.example.test/second'}], 'doh_server', 'second'),
    (
      '/ros',
      [
        {
          'host': f'router-{name}.example.test',
          'user': 'dummy-user',
          'user_password': 'dummy-password',
          'bgp_list_name': 'routes',
        }
        for name in ('first', 'second')
      ],
      'host',
      'router-second',
    ),
    (
      '/domains',
      [{'domain': 'first.example.test'}, {'domain': 'second.example.test', 'ros_comment': 'Second domain'}],
      'name',
      'second',
    ),
    (
      '/ips',
      [{'addr': '8.8.8.8'}, {'addr': '9.9.9.9', 'use_default_gw': True, 'ros_comment': 'Second address'}],
      'addr',
      '9.9.9',
    ),
  ],
)
async def test_resource_http_crud_reaches_real_writer_and_committed_reads(
  app, store, resource_api, monkeypatch, path, records, field, search
):
  """HTTP success acknowledges admission; queue.join supplies the commit boundary for reads."""
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(insert(app.database.DomainsDbo).values(id=0, name='default'))
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  await store.start_writer()
  empty = await resource_api.get(path)
  assert empty.status_code == 200
  assert empty.json()['count'] == (1 if path == '/domains' else 0)
  response = await resource_api.post(path, json=records)
  assert (response.status_code, response.json()) == (200, {'result': 'OK'})
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  response = await resource_api.get(f'{path}/search', params={'text': search})
  assert response.status_code == 200
  found = response.json()
  assert found['count'] == 1
  record = found['payload'][0]
  assert record[field] == (records[1].get(field) or records[1]['domain'])
  assert record['id'] > 0
  assert record['updated_at'] is None
  assert record['updated_at_hum'] is None
  assert isinstance(record['created_at'], (int, float))
  created = datetime.strptime(record['created_at_hum'], '%Y-%m-%d %H:%M:%S')  # noqa: DTZ007
  assert created.strftime('%Y-%m-%d %H:%M:%S') == record['created_at_hum']
  detail = await resource_api.get(f'{path}/{record["id"]}')
  assert (detail.status_code, detail.json()) == (200, record)
  page = await resource_api.get(path, params={'limit': 1, 'offset': 1})
  assert page.status_code == 200
  assert (page.json()['limit'], page.json()['offset'], page.json()['count']) == (1, 1, 1)
  assert page.json()['total'] == (3 if path == '/domains' else 2)
  removed = await resource_api.delete(f'{path}/{record["id"]}')
  assert (removed.status_code, removed.json()) == (200, {'result': 'OK'})
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  missing = await resource_api.get(f'{path}/{record["id"]}')
  assert missing.status_code == 404
  assert missing.json()['error'] == 'NOT_FOUND'
  cleared = await resource_api.delete(path)
  assert (cleared.status_code, cleared.json()) == (200, {'result': 'OK'})
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  remaining = (await resource_api.get(path)).json()
  assert remaining['count'] == (1 if path == '/domains' else 0)
  assert store.writer_failure is None
  assert store._DataBase__read_engine.pool.checkedout() == 0


@pytest.mark.parametrize('path', ['/domains/lists', '/ips/lists', '/dns', '/ros', '/domains', '/ips'])
async def test_resource_http_rejects_empty_or_invalid_writes_before_queue_admission(store, resource_api, path):
  response = await resource_api.post(path, json=[])
  assert (response.status_code, response.json()) == (400, {'status': 'No Data'})
  response = await resource_api.post(path, json=[{}])
  assert response.status_code == 422
  assert response.json()['detail'][0]['loc'][0] == 'body'
  assert store.db_save_queue.qsize() == 0


@pytest.mark.parametrize('path', ['/domains/lists', '/ips/lists', '/dns', '/ros', '/domains', '/ips'])
@pytest.mark.parametrize('params', [{'limit': 0}, {'offset': -1}, {'start_date': '2024-02-30 00:00:00'}])
async def test_resource_http_validates_query_boundaries(resource_api, path, params):
  response = await resource_api.get(path, params=params)
  assert response.status_code == 422
  assert response.json()['detail'][0]['loc'][0] == 'query'


@pytest.mark.parametrize('path', ['/domains/lists', '/ips/lists', '/dns', '/ros', '/domains', '/ips'])
async def test_resource_http_reports_unknown_records_and_invalid_identifiers(resource_api, path):
  response = await resource_api.get(f'{path}/987654')
  assert response.status_code == 404
  assert response.json()['error'] == 'NOT_FOUND'
  assert '987654' in response.json()['resolution']
  response = await resource_api.get(f'{path}/not-an-id')
  assert response.status_code == 422
  assert response.json()['detail'][0]['loc'] == ['path', 'id']


@pytest.fixture
async def catalog_store(app, store):
  """Fixed dates and mixed nullable metadata make SQL filter results independently predictable."""
  first = datetime(2024, 1, 1, 12, tzinfo=UTC).replace(tzinfo=None)
  second = datetime(2024, 1, 2, 12, tzinfo=UTC).replace(tzinfo=None)
  last = datetime(2024, 1, 4, 12, tzinfo=UTC).replace(tzinfo=None)
  async with store._DataBase__write_engine.begin() as connection:
    for model in (app.database.DomainsListsDbo, app.database.IpsListsDbo):
      await connection.execute(
        insert(model),
        [
          {
            'id': index,
            'name': f'list-{index}',
            'url': f'https://lists.example.test/source-{index}',
            'description': None if index == 1 else f'Description {index}',
            'attempts': index - 1,
            'created_at': timestamp,
            'updated_at': None if index == 1 else last,
            'hash': None if index == 1 else 'known-hash',
          }
          for index, timestamp in [(1, first), (2, second), (3, last)]
        ],
      )
    await connection.execute(
      insert(app.database.DomainsDbo),
      [
        {
          'id': index,
          'name': f'domain-{index}.example.test',
          'domain_list_id': 2 if index else None,
          'resolved': index == 2,
          'created_at': timestamp,
          'updated_at': None if index == 1 else last,
          'last_resolved_at': last if index == 2 else None,
          'ros_comment': 'Domain comment' if index == 2 else None,
        }
        for index, timestamp in [(0, first), (1, first), (2, second), (3, last)]
      ],
    )
    await connection.execute(
      insert(app.database.IpRecordsDbo),
      [
        {
          'id': index,
          'ip_address': address,
          'addr_type': version,
          'domain_id': 2,
          'ip_list_id': 2,
          'use_default_gw': index == 2,
          'created_at': timestamp,
          'updated_at': None if index == 1 else last,
          'ros_comment': 'IP comment' if index == 1 else None,
        }
        for index, address, version, timestamp in [
          (1, '8.8.8.8', 4, first),
          (2, '9.9.9.9', 4, second),
          (3, '2001:4860:4860::8888', 6, last),
        ]
      ],
    )
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [{'ip_record_id': index, 'domain_id': 2, 'ip_list_id': 2} for index in (1, 2, 3)],
    )
    await connection.execute(
      insert(app.database.DnsServersDbo),
      [
        {
          'id': index,
          'server': server,
          'doh_server': doh,
          'created_at': timestamp,
          'updated_at': None if index == 1 else last,
        }
        for index, server, doh, timestamp in [
          (0, '1.1.1.1', None, first),
          (1, '8.8.8.8', None, first),
          (2, None, 'https://dns.example.test/source-2', second),
        ]
      ],
    )
    await connection.execute(
      insert(app.database.RosConfigsDbo),
      [
        {
          'id': index,
          'host': f'router-{index}.example.test',
          'user': f'dummy-user-{index}',
          'passwd': 'dummy-password',
          'bgp_list_name': f'routes-{index}',
          'created_at': timestamp,
          'updated_at': None if index == 1 else last,
        }
        for index, timestamp in [(0, first), (1, first), (2, second), (3, last)]
      ],
    )
  return store


@pytest.mark.parametrize(
  ('path', 'params', 'expected_ids'),
  [
    ('/domains/lists', {'attempts': 1}, {2}),
    ('/ips/lists', {'attempts': 1}, {2}),
    ('/domains/lists/search', {'text': 'source-2'}, {2}),
    ('/ips/lists/search', {'text': 'source-2'}, {2}),
    ('/domains/lists/search', {'text': 'list-3', 'attempts': 1}, set()),
    ('/ips/lists/search', {'text': 'list-3', 'attempts': 1}, set()),
    ('/ips', {'type': 6}, {3}),
    ('/ips', {'type': 4, 'default_gw': 'true'}, {2}),
    ('/ips', {'type': 4, 'default_gw': 'false'}, {1}),
    ('/ips/search', {'text': '8.8'}, {1}),
    ('/domains', {'resolved': 'true'}, {2}),
    ('/domains/search', {'text': 'domain-1', 'resolved': 'false'}, {1}),
    ('/dns', {'default': 'false'}, {1, 2}),
    ('/dns', {'default': 'true'}, {0, 1, 2}),
    ('/dns/search', {'text': 'source-2'}, {2}),
    ('/ros/search', {'text': 'router-2'}, {2}),
    ('/ros/search', {'text': 'dummy-user-2'}, {2}),
    ('/ros/search', {'text': 'routes-2'}, {2}),
  ],
)
async def test_catalog_http_filters_select_only_matching_sql_rows(
  catalog_store, resource_api, path, params, expected_ids
):
  response = await resource_api.get(path, params=params)
  assert response.status_code == 200
  payload = response.json()
  assert payload['count'] == len(expected_ids)
  assert {item['id'] for item in payload['payload']} == expected_ids
  assert catalog_store._DataBase__read_engine.pool.checkedout() == 0


@pytest.mark.parametrize('path', ['/domains/lists', '/ips/lists', '/dns', '/ros', '/domains', '/ips'])
@pytest.mark.parametrize('mode', ['start', 'end', 'both'])
async def test_catalog_http_date_filters_preserve_timestamp_metadata(catalog_store, resource_api, path, mode):
  query = {}
  if mode in {'start', 'both'}:
    query['start_date'] = '2024-01-02 00:00:00'
  if mode in {'end', 'both'}:
    query['end_date'] = '2024-01-03 23:59:59'
  response = await resource_api.get(path, params=query)
  assert response.status_code == 200
  rows = response.json()['payload']
  expected = {2, 3} if mode == 'start' else {1, 2}
  if path == '/dns' and mode == 'start':
    expected = {2}
  if path in {'/dns', '/ros', '/domains'} and mode == 'end':
    expected.add(0)
  if mode == 'both':
    expected = {2}
  assert {row['id'] for row in rows} == expected
  for row in rows:
    detail = await resource_api.get(f'{path}/{row["id"]}')
    if path == '/ros' and row['id'] == 0:
      # The repository supports default exclusion; individual HTTP configurations start at ID 1.
      assert detail.status_code == 422
      continue
    assert (detail.status_code, detail.json()) == (200, row)
    if row['id'] == 2:
      assert row['created_at_hum'] == '2024-01-02 12:00:00'
      assert row['updated_at_hum'] == '2024-01-04 12:00:00'


@pytest.mark.parametrize('kind', ['domains', 'ips'])
@pytest.mark.parametrize('forced', [False, True])
async def test_list_refresh_selection_honors_attempt_limit_and_force(app, store, monkeypatch, kind, forced):
  monkeypatch.setattr(app.settings, 'attempts_limit', 3)
  monkeypatch.setattr(app.settings, 'lists_update_interval_sec', 3600)
  model = app.database.DomainsListsDbo if kind == 'domains' else app.database.IpsListsDbo
  past = datetime(2000, 1, 1, tzinfo=UTC).replace(tzinfo=None)
  future = datetime(2999, 1, 1, tzinfo=UTC).replace(tzinfo=None)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(model),
      [
        {
          'id': index,
          'name': f'list-{index}',
          'url': f'https://lists.example.test/{index}',
          'attempts': attempts,
          'updated_at': timestamp,
        }
        for index, attempts, timestamp in [(1, 0, None), (2, 2, past), (3, 0, future), (4, 3, None), (5, 4, past)]
      ],
    )
  async with AsyncSession(store._DataBase__read_engine) as session:
    selected = await model.get_for_update(session, forced=forced)
  assert {row.id for row in selected} == ({1, 2, 3} if forced else {1, 2})
  assert {row.id: row.attempts for row in selected} == ({1: 0, 2: 2, 3: 0} if forced else {1: 0, 2: 2})
  assert next(row for row in selected if row.id == 1).updated_at is None
  assert next(row for row in selected if row.id == 2).updated_at == past


async def test_catalog_related_counts_and_router_update_projections(app, catalog_store):
  domain_list = await catalog_store.get_domains_list_on_id(2)
  ip_list = await catalog_store.get_ips_list_on_id(2)
  assert domain_list.elements_count == 3
  assert (ip_list.ip_v4_count, ip_list.ip_v6_count) == (2, 1)
  assert (await catalog_store.get_domains_list_on_id(1)).elements_count == 0
  empty = await catalog_store.get_ips_list_on_id(1)
  assert (empty.ip_v4_count, empty.ip_v6_count) == (0, 0)
  assert {item.name for item in await catalog_store.get_all_domains_on_domains_list(2)} == {
    'domain-1.example.test',
    'domain-2.example.test',
    'domain-3.example.test',
  }
  assert {item.ip_address for item in await catalog_store.get_all_ips_on_ips_list(2)} == {
    '8.8.8.8',
    '9.9.9.9',
    '2001:4860:4860::8888',
  }
  for version, expected in [
    (None, {'8.8.8.8', '9.9.9.9', '2001:4860:4860::8888'}),
    (4, {'8.8.8.8', '9.9.9.9'}),
    (6, {'2001:4860:4860::8888'}),
  ]:
    records = await catalog_store.get_all_ips_for_update(addr_type=version)
    assert {item.ip_address for item in records} == expected
    assert {item.ip_address: item.comment for item in records} == {
      address: ('IP comment' if address == '8.8.8.8' else 'Domain comment') for address in expected
    }
  configs = await catalog_store.get_all_configs_for_ros_update()
  assert {item.host for item in configs} == {f'router-{index}.example.test' for index in range(4)}
  assert all(item.passwd == 'dummy-password' for item in configs)


@pytest.mark.parametrize('entity', ['domains', 'ips', 'lists'])
@pytest.mark.parametrize('date_field', ['created_at', 'updated_at'])
async def test_growth_daily_series_zero_fills_gaps_and_ignores_null_dates(
  catalog_store, resource_api, entity, date_field
):
  response = await resource_api.get(
    '/stats/growth',
    params={
      'entity': entity,
      'date_filter_field': date_field,
      'start_date': '2024-01-01 00:00:00',
      'end_date': '2024-01-05 23:59:59',
    },
  )
  assert response.status_code == 200
  expected = {
    ('domains', 'created_at'): [2, 1, 0, 1, 0],
    ('ips', 'created_at'): [1, 1, 0, 1, 0],
    ('lists', 'created_at'): [2, 2, 0, 2, 0],
    ('domains', 'updated_at'): [0, 0, 0, 3, 0],
    ('ips', 'updated_at'): [0, 0, 0, 2, 0],
    ('lists', 'updated_at'): [0, 0, 0, 4, 0],
  }[entity, date_field]
  payload = response.json()
  assert payload['total_in_period'] == sum(expected)
  assert payload['payload'] == [
    {'date': f'2024-01-0{index}', 'count': count} for index, count in enumerate(expected, start=1)
  ]
  assert payload['entity'] == entity
  assert payload['granularity'] == 'day'


@pytest.mark.parametrize('entity', ['domains', 'ips', 'lists'])
@pytest.mark.parametrize('granularity', ['minute', 'hour', 'week', 'month', 'year'])
async def test_growth_supported_granularities_group_actual_rows(catalog_store, resource_api, entity, granularity):
  ranges = {
    'minute': (
      '2024-01-02 12:00:00',
      '2024-01-02 12:02:00',
      ['2024-01-02 12:00', '2024-01-02 12:01', '2024-01-02 12:02'],
    ),
    'hour': ('2024-01-02 12:00:00', '2024-01-02 14:00:00', ['2024-01-02 12', '2024-01-02 13', '2024-01-02 14']),
    'week': ('2024-01-01 00:00:00', '2024-01-15 00:00:00', ['2024-01', '2024-02', '2024-03']),
    'month': ('2024-01-01 00:00:00', '2024-03-01 00:00:00', ['2024-01', '2024-02', '2024-03']),
    'year': ('2024-01-01 00:00:00', '2026-01-01 00:00:00', ['2024', '2025', '2026']),
  }
  start, end, labels = ranges[granularity]
  count = (
    (2 if entity == 'lists' else 1)
    if granularity in {'minute', 'hour'}
    else {'domains': 4, 'ips': 3, 'lists': 6}[entity]
  )
  response = await resource_api.get(
    '/stats/growth',
    params={
      'entity': entity,
      'granularity': granularity,
      'start_date': start,
      'end_date': end,
    },
  )
  assert response.status_code == 200
  payload = response.json()
  assert payload['payload'] == [
    {'date': label, 'count': count if index == 0 else 0} for index, label in enumerate(labels)
  ]
  assert payload['total_in_period'] == count


async def test_growth_resolution_checkpoints_use_their_own_date_field(catalog_store, resource_api):
  response = await resource_api.get(
    '/stats/growth',
    params={
      'entity': 'domains',
      'date_filter_field': 'last_resolved_at',
      'start_date': '2024-01-03 00:00:00',
      'end_date': '2024-01-05 23:59:59',
    },
  )
  assert response.status_code == 200
  assert response.json()['total_in_period'] == 1
  assert response.json()['payload'] == [
    {'date': '2024-01-03', 'count': 0},
    {'date': '2024-01-04', 'count': 1},
    {'date': '2024-01-05', 'count': 0},
  ]


@pytest.mark.parametrize('entity', ['domains', 'ips', 'lists'])
async def test_growth_weekly_series_stays_within_requested_bucket_range(catalog_store, resource_api, entity):
  response = await resource_api.get(
    '/stats/growth',
    params={
      'entity': entity,
      'granularity': 'week',
      'start_date': '2024-01-01 00:00:00',
      'end_date': '2024-01-10 23:59:59',
    },
  )
  assert response.status_code == 200
  assert response.json()['payload'] == [
    {'date': '2024-01', 'count': {'domains': 4, 'ips': 3, 'lists': 6}[entity]},
    {'date': '2024-02', 'count': 0},
  ]


@pytest.mark.parametrize('entity', ['domains', 'ips', 'lists'])
@pytest.mark.parametrize(
  ('dates', 'expected'),
  [
    (['2024-01-03', '2024-01-07', '2024-01-08'], [('2024-01', 2), ('2024-02', 1)]),
    (
      ['2024-12-30', '2025-01-01', '2025-01-06', '2025-01-07'],
      [('2024-53', 1), ('2025-00', 1), ('2025-01', 2)],
    ),
  ],
)
async def test_growth_weekly_series_covers_partial_weeks_and_calendar_year_boundaries(
  app, store, resource_api, entity, dates, expected
):
  """The established %Y-%W labels split a calendar week at January 1."""
  model = {
    'domains': app.database.DomainsDbo,
    'ips': app.database.IpRecordsDbo,
    'lists': app.database.DomainsListsDbo,
  }[entity]
  records = []
  for index, date in enumerate(dates, start=1):
    row = {'created_at': datetime.fromisoformat(f'{date}T12:00:00+00:00').replace(tzinfo=None)}
    if entity == 'ips':
      row.update(addr_type=4, ip_address=f'8.8.8.{index}')
    else:
      row['name'] = f'record-{index}.example.test'
      if entity == 'lists':
        row['url'] = f'https://lists.example.test/{index}'
    records.append(row)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(insert(model), records)
  response = await resource_api.get(
    '/stats/growth',
    params={
      'entity': entity,
      'granularity': 'week',
      'start_date': f'{dates[0]} 00:00:00',
      'end_date': f'{dates[-1]} 23:59:59',
    },
  )
  assert response.status_code == 200
  assert response.json()['total_in_period'] == len(dates)
  assert response.json()['payload'] == [{'date': date, 'count': count} for date, count in expected]


@pytest.mark.parametrize(
  'query',
  [
    {'entity': 'unknown'},
    {'entity': 'domains', 'ip_subtype': 4},
    {'entity': 'ips', 'ip_subtype': 5},
    {'entity': 'lists', 'date_filter_field': 'last_resolved_at'},
    {'entity': 'ips', 'granularity': 'second'},
    {'entity': 'domains', 'start_date': '2024-01-03 00:00:00', 'end_date': '2024-01-01 00:00:00'},
  ],
)
async def test_growth_http_rejects_invalid_filter_combinations(resource_api, query):
  response = await resource_api.get('/stats/growth', params=query)
  assert response.status_code == 422
  assert response.json()['detail'][0]['loc'][0] == 'query'


async def test_catalog_statistics_aggregate_all_resources_and_per_list_counts(catalog_store, resource_api):
  response = await resource_api.get('/stats')
  assert response.status_code == 200
  payload = response.json()
  assert payload['dns'] == {'total': 3, 'classic': 2, 'doh': 1}
  assert payload['ros'] == {'total': 4}
  assert {key: value for key, value in payload['domains'].items() if key != 'per_list'} == {
    'total': 4,
    'resolved': 1,
    'unresolved': 3,
    'lists_total': 3,
  }
  assert {key: value for key, value in payload['ips'].items() if key != 'per_list'} == {
    'total': 3,
    'v4_total': 2,
    'v6_total': 1,
    'linked_to_domain': 3,
    'standalone': 0,
    'lists_total': 3,
  }
  assert sorted(payload['domains']['per_list'], key=lambda row: row['list_id']) == [
    {
      'list_id': index,
      'list_name': f'list-{index}',
      'attempts': index - 1,
      'total': 3 if index == 2 else 0,
      'resolved': 1 if index == 2 else 0,
      'unresolved': 2 if index == 2 else 0,
    }
    for index in (1, 2, 3)
  ]
  assert sorted(payload['ips']['per_list'], key=lambda row: row['list_id']) == [
    {
      'list_id': index,
      'list_name': f'list-{index}',
      'attempts': index - 1,
      'total': 3 if index == 2 else 0,
      'v4_count': 2 if index == 2 else 0,
      'v6_count': 1 if index == 2 else 0,
    }
    for index in (1, 2, 3)
  ]


@pytest.mark.parametrize('method', ['get_all_domains', 'get_all_dns_servers', 'get_all_ros_configs'])
@pytest.mark.parametrize('default', [None, False, True])
async def test_catalog_repository_default_filters_preserve_public_totals(catalog_store, method, default):
  response = await getattr(catalog_store, method)(before_time=perf_counter(), limit=10, offset=0, default=default)
  expected = {0, 1, 2} if method == 'get_all_dns_servers' else {0, 1, 2, 3}
  assert response.total == len(expected)
  if default is False:
    expected.remove(0)
  assert {row.id for row in response.payload} == expected


@pytest.mark.parametrize('kind', ['domains', 'ips'])
async def test_list_loader_reconciles_changed_hashes_and_retires_unavailable_lists(app, store, monkeypatch, kind):
  """Use the real downloader/parser and SQL writer; only the upstream HTTP transport is synthetic."""
  monkeypatch.setattr(app.settings, 'attempts_limit', 3)
  registry_module = importlib.import_module('jobs.job_registry')
  registry = registry_module.JobRegistry()
  monkeypatch.setattr(app.database, 'job_registry', registry)
  assert await registry.try_start(registry_module.Jobs.LISTS_LOAD)
  model = app.database.DomainsListsDbo if kind == 'domains' else app.database.IpsListsDbo
  content = 'retained.example.test\nadded.example.test\n' if kind == 'domains' else '8.8.8.8\n8.8.4.4\n'
  unchanged = 'unchanged.example.test\n' if kind == 'domains' else '1.1.1.1\n'
  requests = []

  def upstream(request):
    requests.append((request.method, request.url.path))
    if request.url.path in {'/3', '/4'}:
      return httpx.Response(404)
    assert request.url.host == 'lists.example.test'
    return httpx.Response(200, text=unchanged if request.url.path == '/2' else content)

  monkeypatch.setattr(store.file_loader_client, '_FileLoaderClient__client', app.make_http(upstream))
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(model),
      [
        {
          'id': index,
          'name': f'list-{index}',
          'url': f'https://lists.example.test/{index}',
          'attempts': 2 if index == 3 else 0,
          'hash': sha256(unchanged.encode()).hexdigest().upper() if index == 2 else None,
        }
        for index in (1, 2, 3, 4)
      ],
    )
    await connection.execute(insert(app.database.DomainsDbo).values(id=0, name='default'))
    if kind == 'domains':
      await connection.execute(
        insert(app.database.DomainsDbo),
        [
          {'id': index, 'name': name, 'domain_list_id': list_id}
          for index, name, list_id in [
            (1, 'retained.example.test', 1),
            (2, 'obsolete.example.test', 1),
            (3, 'unchanged.example.test', 2),
            (4, 'retired.example.test', 3),
          ]
        ],
      )
    else:
      await connection.execute(
        insert(app.database.IpRecordsDbo),
        [
          {'id': index, 'ip_address': address, 'addr_type': 4, 'domain_id': 0, 'ip_list_id': list_id}
          for index, address, list_id in [(1, '8.8.8.8', 1), (2, '9.9.9.9', 1), (3, '1.1.1.1', 2), (4, '4.4.4.4', 3)]
        ],
      )
      await connection.execute(
        insert(app.database.IpSupportDbo),
        [
          {'ip_record_id': index, 'domain_id': 0, 'ip_list_id': list_id}
          for index, list_id in [(1, 1), (2, 1), (3, 2), (4, 3)]
        ],
      )
  await store.lists_load(forced=True)
  assert not await registry.is_active(registry_module.Jobs.LISTS_LOAD)
  assert requests == [('HEAD', '/1'), ('GET', '/1'), ('HEAD', '/2'), ('GET', '/2'), ('HEAD', '/3'), ('HEAD', '/4')]
  await flush_queue(store)
  getter = store.get_domains_list_on_id if kind == 'domains' else store.get_ips_list_on_id
  assert await getter(3) is None
  assert (await getter(1)).hash == sha256(content.encode()).hexdigest().upper()
  assert (await getter(2)).hash == sha256(unchanged.encode()).hexdigest().upper()
  assert (await getter(4)).attempts == 1
  assert (await getter(4)).updated_at is not None
  if kind == 'domains':
    rows = await store.get_all_domains(before_time=perf_counter(), limit=10, offset=0)
    assert {row.name for row in rows.payload} == {
      'default',
      'retained.example.test',
      'added.example.test',
      'unchanged.example.test',
    }
    assert next(row for row in rows.payload if row.name == 'retained.example.test').id == 1
  else:
    rows = await store.get_all_ips(before_time=perf_counter(), limit=10, offset=0)
    assert {row.addr for row in rows.payload} == {'8.8.8.8', '8.8.4.4', '1.1.1.1'}
    assert next(row for row in rows.payload if row.addr == '8.8.8.8').id == 1


@pytest.mark.parametrize('path', ['/domains/lists', '/ips/lists', '/dns', '/ros', '/domains', '/ips'])
async def test_catalog_empty_search_and_out_of_range_page_do_not_change_storage(catalog_store, resource_api, path):
  response = await resource_api.get(f'{path}/search', params={'text': "' OR 1=1 --"})
  assert response.status_code == 200
  assert response.json()['payload'] == []
  assert response.json()['count'] == 0
  page = await resource_api.get(path, params={'limit': 1, 'offset': 999})
  assert page.status_code == 200
  assert page.json()['payload'] == []
  assert page.json()['count'] == 0
  all_rows = await resource_api.get(path)
  assert all_rows.status_code == 200
  assert all_rows.json()['count'] == all_rows.json()['total']
  assert all_rows.json()['count'] == (4 if path in {'/domains', '/ros'} else 3)


@pytest.mark.parametrize(
  ('path', 'method'),
  [
    ('/domains/lists', 'get_all_domains_lists'),
    ('/domains/lists/search?text=known', 'get_all_domains_lists'),
    ('/domains/lists/1', 'get_domains_list_on_id'),
    ('/ips/lists', 'get_all_ips_lists'),
    ('/ips/lists/search?text=known', 'get_all_ips_lists'),
    ('/ips/lists/1', 'get_ips_list_on_id'),
    ('/dns', 'get_all_dns_servers'),
    ('/dns/search?text=known', 'get_all_dns_servers'),
    ('/dns/1', 'get_dns_server_on_id'),
    ('/ros', 'get_all_ros_configs'),
    ('/ros/search?text=known', 'get_all_ros_configs'),
    ('/ros/1', 'get_ros_config_on_id'),
    ('/ips', 'get_all_ips'),
    ('/ips/search?text=known', 'get_all_ips'),
    ('/ips/1', 'get_ip_record_on_id'),
    ('/domains', 'get_all_domains'),
    ('/domains/search?text=known', 'get_all_domains'),
    ('/domains/1', 'get_domain_on_id'),
    ('/stats', 'stats'),
    ('/stats/growth?entity=domains', 'stats_growth'),
  ],
)
async def test_resource_http_maps_repository_failure_to_json_error(app, store, resource_api, monkeypatch, path, method):
  """The repository boundary fails here; these assertions cover HTTP error mapping, not SQL execution."""
  failure = app.database.DatabaseReadError('Cannot read domain records')
  monkeypatch.setattr(store, method, AsyncMock(side_effect=failure))
  response = await resource_api.get(path)
  assert response.status_code == 500
  assert response.headers['content-type'].startswith('application/json')
  assert response.json() == {'error': 'Cannot read domain records'}
  assert store.db_save_queue.qsize() == 0


@pytest.mark.parametrize(
  ('path', 'body', 'status_code', 'message'),
  [
    ('/domains/resolve/check', {'id': 999}, 404, "Domain with ID '999' not found in local db"),
    ('/domains/resolve/check', {'id': 2, 'dns_server_ids': [999]}, 404, "DNS server ID '999' not found in local db"),
    ('/ips/ripe/check', {'id': 999}, 404, "IP address with ID '999' not found in local db"),
    ('/ips/ripe/check', {'id': 3}, 422, 'Only IPv4 addresses are supported by this check'),
  ],
)
async def test_catalog_lookup_checks_reject_missing_or_incompatible_records_without_network(
  catalog_store, resource_api, path, body, status_code, message
):
  response = await resource_api.post(path, json=body)
  assert response.status_code == status_code
  assert response.json() == (
    {'error': 'NOT_FOUND', 'resolution': message} if status_code == 404 else {'error': message, 'resolution': None}
  )
  assert catalog_store.db_save_queue.qsize() == 0


async def test_lists_command_runs_real_empty_job_and_respects_existing_reservation(app, store, monkeypatch):
  module = importlib.import_module('routers.commands_router')
  registry_module = importlib.import_module('jobs.job_registry')
  registry = registry_module.JobRegistry()
  monkeypatch.setattr(module, 'db', store)
  monkeypatch.setattr(module, 'job_registry', registry)
  monkeypatch.setattr(app.database, 'job_registry', registry)
  api = FastAPI()
  api.include_router(module.CommandsRouter().get_router())
  async with httpx.AsyncClient(
    transport=httpx.ASGITransport(app=api), base_url='http://service.test', trust_env=False
  ) as client:
    response = await client.post('/commands/lists/load', params={'forced': True})
    assert (response.status_code, response.json()) == (200, {'result': 'OK'})
    assert not await registry.is_active(registry_module.Jobs.LISTS_LOAD)
    assert await registry.try_start(registry_module.Jobs.LISTS_LOAD)
    response = await client.post('/commands/lists/load')
    assert (response.status_code, response.json()) == (200, {'result': 'Job lists_load is Run'})
    assert await registry.is_active(registry_module.Jobs.LISTS_LOAD)
  assert store.db_save_queue.qsize() == 0


def sqlite_snapshot(path):
  """Capture physical schema and data, including every historical row."""
  with closing(sqlite3.connect(path)) as connection:
    return tuple(connection.iterdump())


def create_history(connection):
  connection.execute("""
    CREATE TABLE rdpr_migrations (
      id INTEGER NOT NULL PRIMARY KEY, name TEXT NOT NULL CHECK (name != ''),
      checksum TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
      applied_at TIMESTAMP
    )
  """)


def create_legacy_database(path):
  """Represent the complete business schema of the historical dbInit contract."""
  with closing(sqlite3.connect(path)) as connection, connection:
    connection.executescript("""
      CREATE TABLE dns_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, server TEXT UNIQUE CHECK (server != ''),
        doh_server TEXT UNIQUE CHECK (doh_server != ''), description TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE ros_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL UNIQUE CHECK (host != ''),
        user TEXT NOT NULL CHECK (user != ''), pass TEXT NOT NULL,
        bgp_list_name TEXT NOT NULL CHECK (bgp_list_name != ''), description TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE domains_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE CHECK (name != ''),
        url TEXT NOT NULL CHECK (url != ''), description TEXT, hash TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP
      );
      CREATE TABLE ip_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE CHECK (name != ''),
        url TEXT NOT NULL CHECK (url != ''), description TEXT, hash TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP
      );
      CREATE TABLE domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT, domain_list_id INTEGER,
        resolved INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL UNIQUE CHECK (name != ''),
        ros_comment TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP,
        FOREIGN KEY (domain_list_id) REFERENCES domains_lists(id) ON DELETE CASCADE
      );
      CREATE TABLE ip_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip_list_id INTEGER, domain_id INTEGER NOT NULL,
        addr_type INTEGER NOT NULL, ip_address TEXT NOT NULL UNIQUE CHECK (ip_address != ''),
        ros_comment TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
        FOREIGN KEY (ip_list_id) REFERENCES ip_lists(id) ON DELETE CASCADE
      );
      CREATE TABLE jobs (
        job_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL CHECK (name != ''),
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, end_at TIMESTAMP
      );
      INSERT INTO dns_servers VALUES (-1, '9.9.9.9', NULL, 'custom default', '2001-02-03 04:05:06');
      INSERT INTO dns_servers VALUES (4, NULL, 'https://dns.example.test/query', 'DoH', '2001-02-03 04:05:06');
      INSERT INTO ros_configs VALUES (6, 'router.example.test', 'dummy-user', 'dummy-password',
                                     'routes', 'router', '2001-02-03 04:05:06');
      INSERT INTO domains_lists VALUES (5, 'domains', 'https://lists.example.test/domains',
                                       'domain list', 'domain-hash', '2001-02-03 04:05:06', '2002-03-04 05:06:07');
      INSERT INTO ip_lists VALUES (8, 'ips', 'https://lists.example.test/ips',
                                  'ip list', 'ip-hash', '2001-02-03 04:05:06', '2002-03-04 05:06:07');
      INSERT INTO domains VALUES (-1, NULL, 1, 'default', 'custom domain', '2001-02-03 04:05:06', NULL);
      INSERT INTO domains VALUES (7, 5, 1, 'legacy.example.test', 'domain comment',
                                  '2001-02-03 04:05:06', '2002-03-04 05:06:07');
      INSERT INTO ip_records VALUES (11, 8, -1, 4, '8.8.8.8', 'default link', '2001-02-03 04:05:06');
      INSERT INTO ip_records VALUES (12, NULL, 7, 6, '2001:4860:4860::8888', 'domain link', '2001-02-03 04:05:06');
      INSERT INTO jobs (name) VALUES ('retired historical job');
    """)


def assert_legacy_import(path):
  with closing(sqlite3.connect(path)) as connection:
    assert connection.execute(
      'SELECT id, server, doh_server, description, created_at, updated_at FROM rdpr_dns_servers ORDER BY id'
    ).fetchall() == [
      (0, '9.9.9.9', None, 'custom default', '2001-02-03 04:05:06', None),
      (4, None, 'https://dns.example.test/query', 'DoH', '2001-02-03 04:05:06', None),
    ]
    assert connection.execute(
      'SELECT id, domain_list_id, resolved, name, ros_comment, created_at, updated_at, last_resolved_at '
      'FROM rdpr_domains ORDER BY id'
    ).fetchall() == [
      (0, None, 1, 'default', 'custom domain', '2001-02-03 04:05:06', None, None),
      (
        7,
        5,
        1,
        'legacy.example.test',
        'domain comment',
        '2001-02-03 04:05:06',
        '2002-03-04 05:06:07',
        '2002-03-04 05:06:07',
      ),
    ]
    assert connection.execute(
      'SELECT id, ip_list_id, domain_id, addr_type, ip_address, ros_comment, use_default_gw, created_at, updated_at '
      'FROM rdpr_ip_records ORDER BY id'
    ).fetchall() == [
      (11, 8, 0, 4, '8.8.8.8', 'default link', 0, '2001-02-03 04:05:06', None),
      (12, None, 7, 6, '2001:4860:4860::8888', 'domain link', 0, '2001-02-03 04:05:06', None),
    ]
    for query, expected in [
      (
        'SELECT id, name, url, description, hash, attempts, created_at, updated_at FROM rdpr_domains_lists',
        (5, 'domains', 'https://lists.example.test/domains', 'domain list', 'domain-hash'),
      ),
      (
        'SELECT id, name, url, description, hash, attempts, created_at, updated_at FROM rdpr_ips_lists',
        (8, 'ips', 'https://lists.example.test/ips', 'ip list', 'ip-hash'),
      ),
    ]:
      assert connection.execute(query).fetchall() == [(*expected, 0, '2001-02-03 04:05:06', '2002-03-04 05:06:07')]
    assert connection.execute(
      'SELECT id, host, user, passwd, bgp_list_name, description, created_at, updated_at FROM rdpr_ros_configs'
    ).fetchall() == [
      (6, 'router.example.test', 'dummy-user', 'dummy-password', 'routes', 'router', '2001-02-03 04:05:06', None)
    ]
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert connection.execute(
      'SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports ORDER BY ip_record_id'
    ).fetchall() == [(11, 0, 8), (12, 7, None)]
    assert (
      connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
        "('dns_servers','ros_configs','domains_lists','ip_lists','domains','ip_records','jobs')"
      ).fetchall()
      == []
    )


@pytest.fixture
async def startup_store(app, tmp_path):
  """Do not precreate tables or mark storage ready before the real setup."""
  root = Path(__file__).resolve().parents[2]
  shutil.copytree(
    root / 'migrations', tmp_path / 'migrations', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__')
  )
  database = app.database.DataBase()
  try:
    yield database
  finally:
    try:
      await database.close(timeout=2)
    except app.database.DatabaseWriteError:
      assert database.writer_task is None or database.writer_task.done()
    finally:
      await database._DataBase__read_engine.dispose()
      await database._DataBase__write_engine.dispose()


@pytest.fixture
async def store(app, monkeypatch):
  database = app.database.DataBase()
  database._DataBase__state = True
  monkeypatch.setattr(app.resolver, 'db', database)
  async with database._DataBase__write_engine.begin() as connection:
    await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
  try:
    yield database
  finally:
    try:
      await database.close(timeout=2)
    except app.database.DatabaseWriteError:
      # Failure scenarios deliberately retain unacknowledged work.
      if database.writer_task is not None:
        try:
          await asyncio.wait_for(asyncio.shield(database.writer_task), timeout=2)
        except asyncio.CancelledError:
          pass
    finally:
      await database._DataBase__read_engine.dispose()
      await database._DataBase__write_engine.dispose()


async def seed(app, store, *, resolved=False, checkpoint=None):
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo).values(
        id=1,
        name='www.example.test',
        resolved=resolved,
        last_resolved_at=checkpoint,
      )
    )
    await connection.execute(
      insert(app.database.IpRecordsDbo),
      [
        {'id': 10, 'domain_id': 1, 'addr_type': 4, 'ip_address': '9.9.9.9'},
        {'id': 11, 'domain_id': 1, 'addr_type': 6, 'ip_address': '2001:4860:4860::8888'},
        {'id': 12, 'domain_id': 1, 'addr_type': 4, 'ip_address': '8.8.8.0/24'},
        {'id': 13, 'domain_id': 1, 'addr_type': 4, 'ip_address': '8.8.8.0'},
        {'id': 14, 'domain_id': 1, 'addr_type': 4, 'ip_address': '8.8.8.0/25'},
      ],
    )
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [{'ip_record_id': value, 'domain_id': 1, 'ip_list_id': None} for value in range(10, 15)],
    )


@pytest.fixture
async def domain_page_store(app, store):
  """Keep support order different from global IP order, including shared and list-only sources."""
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [{'id': value, 'name': f'domain-{value}.example.test', 'resolved': value < 2} for value in (3, 2, 1, 0)],
    )
    await connection.execute(
      insert(app.database.IpsListsDbo),
      [{'id': value, 'name': f'list-{value}', 'url': f'https://lists.example.test/{value}'} for value in (1, 2)],
    )
    await connection.execute(
      insert(app.database.IpRecordsDbo),
      [
        {'id': 40, 'domain_id': 2, 'ip_list_id': 2, 'addr_type': 6, 'ip_address': '2001:4860:4860::8844'},
        {'id': 30, 'domain_id': 0, 'ip_list_id': None, 'addr_type': 4, 'ip_address': '1.1.1.1'},
        {'id': 20, 'domain_id': 1, 'ip_list_id': None, 'addr_type': 6, 'ip_address': '2001:4860:4860::8888'},
        {'id': 10, 'domain_id': 0, 'ip_list_id': 1, 'addr_type': 4, 'ip_address': '9.9.9.9'},
      ],
    )
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [
        {'ip_record_id': ip_id, 'domain_id': domain_id, 'ip_list_id': list_id}
        for ip_id, domain_id, list_id in (
          (40, 2, 2),
          (30, 0, None),
          (20, 2, 2),
          (20, 1, None),
          (10, 1, None),
          (10, 1, 2),
          (10, 1, 1),
          (10, 0, 1),
        )
      ],
    )
  return store, {
    0: (['9.9.9.9', '1.1.1.1'], []),
    1: (['9.9.9.9'], ['2001:4860:4860::8888']),
    2: ([], ['2001:4860:4860::8888', '2001:4860:4860::8844']),
    3: ([], []),
  }


@pytest.mark.parametrize(
  ('domain_ids', 'maximum_queries'),
  [([], 0), ([2, 1, 0, 1, 3], 1), ([*range(1001), 0, 1, 2], 3)],
  ids=['empty', 'shared-addresses', 'large-page'],
)
async def test_domain_ip_batch_preserves_order_and_bounds_queries(app, domain_page_store, domain_ids, maximum_queries):
  store, expected = domain_page_store
  queries = []

  def observe(connection, cursor, statement, parameters, context, many):
    if statement.lstrip().upper().startswith('SELECT'):
      queries.append(statement)

  engine = store._DataBase__read_engine
  event.listen(engine.sync_engine, 'before_cursor_execute', observe)
  try:
    async with AsyncSession(engine) as session:
      raw = await (await session.connection()).get_raw_connection()
      driver = raw.driver_connection
      previous = await driver._execute(driver._conn.setlimit, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
      try:
        observed = await app.database.IpRecordsDbo.get_ips_on_domain_ids(session, domain_ids)
      finally:
        await driver._execute(driver._conn.setlimit, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous)
    assert observed == {value: expected.get(value, ([], [])) for value in domain_ids}
    assert len(queries) <= maximum_queries
  finally:
    event.remove(engine.sync_engine, 'before_cursor_execute', observe)


@pytest.mark.parametrize(
  ('options', 'expected_ids', 'query_total'),
  [
    ({'limit': 2, 'offset': 0}, [0, 1], 4),
    ({'limit': 2, 'offset': 1}, [1, 2], 4),
    ({'limit': 4, 'offset': 0, 'resolved': True}, [0, 1], 2),
    ({'limit': 4, 'offset': 0, 'resolved': False}, [2, 3], 2),
    ({'limit': 4, 'offset': 0, 'search_text': 'domain-1'}, [1], 1),
    ({'limit': 4, 'offset': 0, 'search_text': 'absent'}, [], 0),
  ],
)
async def test_domain_page_reads_ips_together_without_changing_payload(
  domain_page_store, options, expected_ids, query_total
):
  store, expected = domain_page_store
  queries = []

  def observe(connection, cursor, statement, parameters, context, many):
    if statement.lstrip().upper().startswith('SELECT'):
      queries.append(statement)

  engine = store._DataBase__read_engine
  event.listen(engine.sync_engine, 'before_cursor_execute', observe)
  try:
    response = await store.get_all_domains(before_time=perf_counter(), **options)
  finally:
    event.remove(engine.sync_engine, 'before_cursor_execute', observe)
  assert (response.total, response.total_resolved, response.total_query, response.count) == (
    4,
    2,
    query_total,
    len(expected_ids),
  )
  assert [domain.id for domain in response.payload] == expected_ids
  for domain in response.payload:
    ipv4, ipv6 = expected[domain.id]
    assert (domain.ips_v4, domain.ips_v6) == (ipv4 or None, ipv6 or None)
    assert domain.name == f'domain-{domain.id}.example.test'
  assert len(queries) <= (5 if expected_ids else 4)


@pytest.mark.parametrize('scenario', ['empty', 'unlisted', 'listed', 'mixed'])
async def test_ip_statistics_preserve_global_counts_and_distinct_list_members(app, store, scenario):
  """List membership excludes domain-only supports and counts a shared address once per list."""
  ip_lists = [
    {'id': 0, 'name': 'zero', 'url': 'https://lists.example.test/zero', 'attempts': 1},
    {'id': 7, 'name': 'shared', 'url': 'https://lists.example.test/shared', 'attempts': 2},
    {'id': 9, 'name': 'empty', 'url': 'https://lists.example.test/empty', 'attempts': 3},
  ]
  records = []
  supports = []
  if scenario != 'empty':
    records = [
      {'id': 10, 'domain_id': 1, 'ip_list_id': None, 'addr_type': 4, 'ip_address': '8.8.8.8'},
      {'id': 11, 'domain_id': 0, 'ip_list_id': None, 'addr_type': 6, 'ip_address': '2001:4860:4860::8888'},
    ]
    if scenario != 'listed':
      records.extend(
        [
          {'id': 12, 'domain_id': 2, 'ip_list_id': None, 'addr_type': 4, 'ip_address': '9.9.9.9'},
          {'id': 13, 'domain_id': 0, 'ip_list_id': None, 'addr_type': 6, 'ip_address': '2001:4860:4860::8844'},
        ]
      )
      supports.extend({'ip_record_id': row['id'], 'domain_id': row['domain_id'], 'ip_list_id': None} for row in records)
    if scenario != 'unlisted':
      for row in records[:2]:
        row['ip_list_id'] = 0
        for list_id in (0, 7):
          supports.append({'ip_record_id': row['id'], 'domain_id': row['domain_id'], 'ip_list_id': list_id})
      # Independent domains can support the same address in both lists.
      supports.extend({'ip_record_id': 10, 'domain_id': 2, 'ip_list_id': list_id} for list_id in (0, 7))
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [{'id': value, 'name': f'domain-{value}.example.test'} for value in range(3)],
    )
    await connection.execute(insert(app.database.IpsListsDbo), ip_lists)
    if records:
      await connection.execute(insert(app.database.IpRecordsDbo), records)
      await connection.execute(insert(app.database.IpSupportDbo), supports)
  async with AsyncSession(store._DataBase__read_engine) as session:
    row = await app.database.IpRecordsDbo.get_stats(session)
  observed = dict(row._mapping)
  per_list = sorted(json.loads(observed.pop('per_list')), key=lambda item: item['list_id'])
  count = {'empty': 0, 'unlisted': 4, 'listed': 2, 'mixed': 4}[scenario]
  half = count // 2 if count else None
  assert observed == {
    'total': count,
    'v4_total': half,
    'v6_total': half,
    'linked_to_domain': half,
    'standalone': half,
    'lists_total': 3,
  }
  members = 2 if scenario in {'listed', 'mixed'} else 0
  assert per_list == [
    {
      'list_id': row['id'],
      'list_name': row['name'],
      'total': members if row['id'] != 9 else 0,
      'v4_count': members // 2 if row['id'] != 9 else 0,
      'v6_count': members // 2 if row['id'] != 9 else 0,
      'attempts': row['attempts'],
    }
    for row in ip_lists
  ]


async def support_snapshot(store):
  """Read source ownership independently of the compatibility owner projection."""
  async with store._DataBase__read_engine.connect() as connection:
    rows = await connection.execute(
      text(
        'SELECT ip.ip_address, s.domain_id, s.ip_list_id FROM rdpr_ip_supports AS s '
        'JOIN rdpr_ip_records AS ip ON ip.id=s.ip_record_id'
      )
    )
    return set(rows.all())


async def queue_resolution(app, store, domain_id, addresses, *, complete=True):
  """Admit explicit completed evidence for domain_id, addresses and completeness.

  app supplies DTOs and store owns the isolated queue; completion time is provided
  by this test producer rather than fabricated by the writer.
  """
  # command models one processing result completed at a fixed UTC instant.
  command = app.dto.DomainResult(
    id=domain_id,
    name=f'domain-{domain_id}.example.test',
    resolution_complete=complete,
    last_attempt_at=datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC),
    storage_ips=tuple(addresses),
  )
  await store.put_domain_after_resolve(command)
  return command


async def add_support_domains(app, store):
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [{'id': value, 'name': f'domain-{value}.example.test', 'resolved': False} for value in (0, 1, 2)],
    )


@pytest.mark.parametrize('order', [(1, 2), (2, 1)])
async def test_shared_address_union_survives_independent_complete_withdrawal(app, store, order):
  """A complete negative withdraws one source, not a globally shared address."""
  await add_support_domains(app, store)
  for domain_id in order:
    await queue_resolution(app, store, domain_id, ['8.8.8.8'])
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 1, None), ('8.8.8.8', 2, None)}
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      text(
        "UPDATE rdpr_ip_records SET ros_comment='incumbent metadata', use_default_gw=1, "
        "created_at='2001-02-03 04:05:06', updated_at='2002-03-04 05:06:07' WHERE ip_address='8.8.8.8'"
      )
    )
  async with store._DataBase__read_engine.connect() as connection:
    before = (
      await connection.execute(
        text(
          'SELECT id, addr_type, ip_address, ros_comment, use_default_gw, created_at, updated_at FROM rdpr_ip_records'
        )
      )
    ).one()
  for domain_id in (1, 2):
    assert [row.ip_address for row in await store.get_all_ips_for_domain(domain_id)] == ['8.8.8.8']
  await queue_resolution(app, store, order[0], [])
  await flush_queue(store)
  assert await store.get_all_ips_for_domain(order[0]) == []
  assert [row.ip_address for row in await store.get_all_ips_for_domain(order[1])] == ['8.8.8.8']
  async with store._DataBase__read_engine.connect() as connection:
    after = (
      await connection.execute(
        text(
          'SELECT id, addr_type, ip_address, ros_comment, use_default_gw, created_at, updated_at FROM rdpr_ip_records'
        )
      )
    ).one()
    owner = (await connection.execute(text('SELECT domain_id, ip_list_id FROM rdpr_ip_records'))).one()
  assert after == before
  assert tuple(owner) == (order[1], None)
  await queue_resolution(app, store, order[1], [])
  await flush_queue(store)
  assert await support_snapshot(store) == set()
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(select(app.database.IpRecordsDbo.id))).all() == []


@pytest.mark.parametrize('withdraw_first', [True, False])
async def test_same_batch_dns_handoff_keeps_global_identity_and_metadata(app, store, withdraw_first):
  await add_support_domains(app, store)
  await queue_resolution(app, store, 1, ['8.8.8.8'])
  await flush_queue(store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text("UPDATE rdpr_ip_records SET ros_comment='retained', use_default_gw=1"))
  async with store._DataBase__read_engine.connect() as connection:
    before = (await connection.execute(text('SELECT * FROM rdpr_ip_records'))).one()
  actions = [(1, ()), (2, ('8.8.8.8',))]
  for domain_id, addresses in actions if withdraw_first else reversed(actions):
    await queue_resolution(app, store, domain_id, addresses)
  await flush_queue(store)
  async with store._DataBase__read_engine.connect() as connection:
    after = (await connection.execute(text('SELECT * FROM rdpr_ip_records'))).one()
  assert after[0] == before[0]
  assert after[3:] == before[3:]
  assert await support_snapshot(store) == {('8.8.8.8', 2, None)}


async def test_same_domain_full_payload_is_fifo_and_frozen_at_admission(app, store):
  await add_support_domains(app, store)
  first = await queue_resolution(app, store, 1, ['8.8.8.8', '9.9.9.9'])
  await queue_resolution(app, store, 1, ['9.9.9.9'])
  last = await queue_resolution(app, store, 1, ['1.1.1.1'], complete=False)
  first.id = 2
  first.storage_ips = ('4.2.2.2',)
  last.storage_ips = ()
  last.resolution_complete = True
  # Obsolete ID deltas cannot remove a different source or replace the full payload.
  last.insert.ips_delete = [999]
  await flush_queue(store)
  assert await support_snapshot(store) == {('9.9.9.9', 1, None), ('1.1.1.1', 1, None)}
  async with store._DataBase__read_engine.connect() as connection:
    rows = (await connection.execute(text('SELECT id, resolved, last_resolved_at FROM rdpr_domains ORDER BY id'))).all()
  assert [(row[0], row[1], row[2] is not None) for row in rows] == [(0, 0, False), (1, 1, True), (2, 0, False)]


@pytest.mark.parametrize('incumbent_list', [None, 8], ids=['without-list', 'with-list'])
async def test_valid_incumbent_survives_lower_support_then_falls_back_without_metadata_changes(
  app, store, incumbent_list
):
  """An earlier representative is eligible only after the incumbent context disappears."""
  await add_support_domains(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.IpsListsDbo),
      [{'id': value, 'name': f'list-{value}', 'url': f'https://lists.example.test/{value}'} for value in (7, 8)],
    )
    await connection.execute(
      insert(app.database.IpRecordsDbo).values(
        id=17,
        domain_id=2,
        ip_list_id=incumbent_list,
        addr_type=4,
        ip_address='8.8.8.8',
        ros_comment='retained metadata',
        use_default_gw=True,
        created_at=datetime(2001, 2, 3, tzinfo=UTC),
        updated_at=datetime(2002, 3, 4, tzinfo=UTC),
      )
    )
    contexts = {(1, None), (2, 7), (2, incumbent_list)}
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [{'ip_record_id': 17, 'domain_id': domain, 'ip_list_id': source} for domain, source in contexts],
    )
  async with store._DataBase__read_engine.connect() as connection:
    before = (await connection.execute(text('SELECT * FROM rdpr_ip_records'))).one()
  receipt = await queue_resolution(app, store, 1, [], complete=False)
  await flush_queue(store)
  assert receipt.write_receipt.outcome.value == 'confirmed'
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(text('SELECT * FROM rdpr_ip_records'))).one() == before
  if incumbent_list is None:
    await queue_resolution(app, store, 2, [])
  else:
    await store.put_withdraw_ip_list_records_to_queue(incumbent_list, [17])
  await flush_queue(store)
  async with store._DataBase__read_engine.connect() as connection:
    after = (await connection.execute(text('SELECT * FROM rdpr_ip_records'))).one()
  assert after[0] == before[0]
  assert after[1:3] == (None, 1)
  assert after[3:] == before[3:]
  if incumbent_list is not None:
    await store.put_withdraw_ip_list_records_to_queue(7, [17])
  await queue_resolution(app, store, 1, [])
  await flush_queue(store)
  assert await support_snapshot(store) == set()
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(text('SELECT * FROM rdpr_ip_records'))).all() == []


@contextmanager
def writer_variable_limit(store, limit):
  """Lower each disposable physical writer connection on its owning aiosqlite thread."""
  engine = store._DataBase__write_engine.sync_engine
  actual = []

  def connected(connection, record):
    async def configure(driver):
      await driver._execute(driver._conn.setlimit, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, limit)
      actual.append(await driver._execute(driver._conn.getlimit, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER))

    connection.run_async(configure)

  event.listen(engine, 'connect', connected)
  try:
    yield actual
  finally:
    event.remove(engine, 'connect', connected)


@pytest.mark.parametrize('limit', [41, 900])
async def test_dns_reconciliation_uses_bounded_explicit_multivalues_not_row_dispatch(app, store, limit):
  """The approved SQL contract requires bounded statements, not an ORM executemany disguise."""
  await add_support_domains(app, store)
  addresses = [str(IPv4Address('12.0.0.0') + index) for index in range(241)]
  first = await queue_resolution(app, store, 2, [*addresses[:161], addresses[0]])
  second = await queue_resolution(app, store, 1, addresses[80:])
  engine = store._DataBase__write_engine.sync_engine
  dispatched = []

  def observed(connection, cursor, statement, parameters, context, executemany):
    dispatched.append((statement, parameters, executemany))

  event.listen(engine, 'before_cursor_execute', observed)
  try:
    with writer_variable_limit(store, limit) as native_limits:
      await flush_queue(store)
  finally:
    event.remove(engine, 'before_cursor_execute', observed)
  assert native_limits == [limit]
  assert await support_snapshot(store) == {
    *((address, 2, None) for address in addresses[:161]),
    *((address, 1, None) for address in addresses[80:]),
  }
  assert first.write_receipt.outcome.value == second.write_receipt.outcome.value == 'confirmed'
  for table in ('rdpr_ip_records', 'rdpr_ip_supports'):
    statements = [row for row in dispatched if row[0].upper().startswith(f'INSERT OR IGNORE INTO {table}'.upper())]
    assert statements, table
    assert all(not many for _, _, many in statements), (table, 'Per-row executemany dispatch is forbidden')
    assert any('), (' in statement.partition('VALUES')[2] for statement, _, _ in statements), table
  for statement, parameters, many in dispatched:
    parameter_sets = parameters if many else [parameters]
    assert all(len(values) <= min(limit, 900) for values in parameter_sets), statement
  if limit == 900:
    # 241 distinct globals and 322 supports must not require one dispatch per address.
    assert len(dispatched) < 30, len(dispatched)
  async with store._DataBase__read_engine.connect() as connection:
    owners = dict((await connection.execute(text('SELECT ip_address, domain_id FROM rdpr_ip_records'))).all())
  assert all(owners[address] == 2 for address in addresses[:161])
  assert all(owners[address] == 1 for address in addresses[161:])


async def test_large_complete_set_withdraws_all_obsolete_list_contexts_without_chunk_loss(app, store):
  """The full desired set, all list contexts and IPv6 define the independent withdrawal oracle."""
  await add_support_domains(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.IpsListsDbo),
      [{'id': value, 'name': f'list-{value}', 'url': f'https://lists.example.test/{value}'} for value in (7, 8)],
    )
    old = [str(IPv4Address('13.0.0.0') + index) for index in range(1103)]
    await connection.execute(
      insert(app.database.IpRecordsDbo),
      [{'id': index + 1, 'domain_id': 1, 'addr_type': 4, 'ip_address': address} for index, address in enumerate(old)]
      + [{'id': 2000, 'domain_id': 1, 'addr_type': 6, 'ip_address': '2001:4860::8888'}],
    )
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [
        {'ip_record_id': index + 1, 'domain_id': 1, 'ip_list_id': owner}
        for index in range(len(old))
        for owner in (7, 8)
      ]
      + [
        {'ip_record_id': 1, 'domain_id': 2, 'ip_list_id': 7},
        {'ip_record_id': 2000, 'domain_id': 1, 'ip_list_id': 8},
      ],
    )
  desired = old[60:1063]
  await queue_resolution(app, store, 1, desired)
  with writer_variable_limit(store, 41):
    await flush_queue(store)
  assert await support_snapshot(store) == {
    *((address, 1, owner) for address in desired for owner in (None, 7, 8)),
    (old[0], 2, 7),
    ('2001:4860::8888', 1, 8),
  }
  async with store._DataBase__read_engine.connect() as connection:
    rows = dict((await connection.execute(text('SELECT ip_address,id FROM rdpr_ip_records'))).all())
    assert (await connection.execute(text('PRAGMA foreign_key_check'))).all() == []
  assert rows == {**{address: old.index(address) + 1 for address in desired}, old[0]: 1, '2001:4860::8888': 2000}


async def test_insufficient_native_variable_budget_fails_before_begin_without_confirmation(app, store, monkeypatch):
  await add_support_domains(app, store)
  before = await support_snapshot(store)
  result = await queue_resolution(app, store, 1, ['8.8.8.8'])
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  statements = []
  engine = store._DataBase__write_engine.sync_engine

  def observed(connection, cursor, statement, parameters, context, executemany):
    statements.append(statement)

  event.listen(engine, 'before_cursor_execute', observed)
  try:
    with writer_variable_limit(store, 3):
      await store.start_writer()
      await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=3)
  finally:
    event.remove(engine, 'before_cursor_execute', observed)
  assert store.writer_state == 'FAILED'
  assert isinstance(store.writer_failure, app.database.DatabaseWriteError)
  assert store.writer_failure.committed is False
  assert result.write_receipt.outcome.value == 'known_not_committed'
  assert not any(statement.upper().startswith('BEGIN') for statement in statements)
  assert await support_snapshot(store) == before


@pytest.mark.parametrize('complete_tail', [True, False])
async def test_repeated_domains_split_groups_without_reassigning_first_shared_owner(app, store, complete_tail):
  await add_support_domains(app, store)
  receipts = [
    await queue_resolution(app, store, 2, ['8.8.8.8', '9.9.9.9']),
    await queue_resolution(app, store, 1, ['8.8.8.8']),
    await queue_resolution(app, store, 2, []),
    await queue_resolution(app, store, 1, ['1.1.1.1'], complete=complete_tail),
    await queue_resolution(app, store, 2, ['8.8.8.8'], complete=False),
  ]
  await flush_queue(store)
  expected = {('1.1.1.1', 1, None), ('8.8.8.8', 2, None)}
  if not complete_tail:
    expected.add(('8.8.8.8', 1, None))
  assert await support_snapshot(store) == expected
  assert all(result.write_receipt.outcome.value == 'confirmed' for result in receipts)
  async with store._DataBase__read_engine.connect() as connection:
    owner = (
      await connection.execute(text("SELECT domain_id FROM rdpr_ip_records WHERE ip_address='8.8.8.8'"))
    ).scalar_one()
  assert owner == 2


@pytest.mark.parametrize('selector', ['domain', 'domain_list'])
async def test_parent_deletion_removes_only_its_supports(app, store, selector):
  await add_support_domains(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsListsDbo).values(id=5, name='source list', url='https://lists.example.test/domains')
    )
    await connection.execute(text('UPDATE rdpr_domains SET domain_list_id=5 WHERE id=1'))
  for domain_id in (1, 2):
    await queue_resolution(app, store, domain_id, ['8.8.8.8'])
  await flush_queue(store)
  if selector == 'domain':
    await store.put_delete_domains_to_queue(id=1)
  else:
    await store.put_delete_domains_list_to_queue(id=5)
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 2, None)}
  assert [row.ip_address for row in await store.get_all_ips_for_domain(2)] == ['8.8.8.8']


async def test_list_withdrawal_is_scoped_but_explicit_ip_deletion_is_global(app, store):
  await add_support_domains(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.IpsListsDbo),
      [{'id': value, 'name': f'list-{value}', 'url': f'https://lists.example.test/{value}'} for value in (7, 8)],
    )
  await queue_resolution(app, store, 1, ['8.8.8.8'])
  await flush_queue(store)
  async with store._DataBase__write_engine.begin() as connection:
    ip_id = (await connection.execute(select(app.database.IpRecordsDbo.id))).scalar_one()
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [
        {'ip_record_id': ip_id, 'domain_id': 1, 'ip_list_id': 7},
        {'ip_record_id': ip_id, 'domain_id': 2, 'ip_list_id': 8},
      ],
    )
  assert [row.ip_address for row in await store.get_all_ips_on_ips_list(7)] == ['8.8.8.8']
  await store.put_withdraw_ip_list_records_to_queue(7, [ip_id])
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 1, None), ('8.8.8.8', 2, 8)}
  assert await store.get_all_ips_on_ips_list(7) == []
  await store.put_delete_ips_list_to_queue(id=8)
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 1, None)}
  await store.put_delete_ips_to_queue(ip_id)
  await flush_queue(store)
  assert await support_snapshot(store) == set()
  assert await store.get_all_ips_for_domain(1) == []


async def test_domain_complete_withdraws_manual_list_support_without_pinning_it(app, store):
  await add_support_domains(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.IpsListsDbo).values(id=7, name='manual list', url='https://lists.example.test/ips')
    )
  request = importlib.import_module('models.http.ips_req').IpsPostElementReq
  await store.put_add_ips_to_queue([request(addr='8.8.8.8', domain_id=1, list_id=7)])
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 1, 7)}
  await queue_resolution(app, store, 1, ['8.8.8.8'])
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 1, 7), ('8.8.8.8', 1, None)}
  await queue_resolution(app, store, 1, [])
  await flush_queue(store)
  assert await support_snapshot(store) == set()


async def test_manual_none_and_supported_duplicate_never_create_ownership(app, store):
  await add_support_domains(app, store)
  request = importlib.import_module('models.http.ips_req').IpsPostElementReq
  await store.put_add_ips_to_queue(
    [
      request(addr='8.8.8.8', domain_id=1, ros_comment='incumbent', use_default_gw=True),
      request(addr='8.8.8.8', domain_id=2, ros_comment='duplicate'),
      request(addr='9.9.9.9', domain_id=None),
    ]
  )
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 1, None)}
  async with store._DataBase__read_engine.connect() as connection:
    assert (
      await connection.execute(text('SELECT ip_address, domain_id, ros_comment, use_default_gw FROM rdpr_ip_records'))
    ).all() == [('8.8.8.8', 1, 'incumbent', 1)]


async def test_explicit_creation_replaces_only_targeted_transient_orphan(app, store):
  await add_support_domains(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsListsDbo).values(id=5, name='retiring list', url='https://lists.example.test/domains')
    )
    await connection.execute(text('UPDATE rdpr_domains SET domain_list_id=5 WHERE id=1'))
  await queue_resolution(app, store, 1, ['8.8.8.8', '9.9.9.9'])
  await flush_queue(store)
  request = importlib.import_module('models.http.ips_req').IpsPostElementReq
  await store.put_delete_domains_list_to_queue(id=5)
  await store.put_add_ips_to_queue(
    [request(addr='8.8.8.8', domain_id=2, ros_comment='explicit replacement', use_default_gw=True)]
  )
  await flush_queue(store)
  assert await support_snapshot(store) == {('8.8.8.8', 2, None)}
  async with store._DataBase__read_engine.connect() as connection:
    assert (
      await connection.execute(text('SELECT ip_address, domain_id, ros_comment, use_default_gw FROM rdpr_ip_records'))
    ).all() == [('8.8.8.8', 2, 'explicit replacement', 1)]


async def test_missing_parent_cannot_hide_behind_an_existing_shared_address(app, store, monkeypatch):
  await add_support_domains(app, store)
  await queue_resolution(app, store, 2, ['8.8.8.8'])
  await flush_queue(store)
  await store.put_delete_domains_to_queue(id=1)
  await flush_queue(store)
  before = await support_snapshot(store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  await queue_resolution(app, store, 1, ['8.8.8.8'], complete=False)
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert store.writer_state == 'FAILED'
  assert isinstance(store.writer_failure, app.database.DatabaseWriteError)
  assert store.writer_failure.committed is False
  assert await support_snapshot(store) == before


async def test_complete_and_direct_domain_delete_roll_back_the_entire_batch(app, store, monkeypatch):
  await seed(app, store)
  before, supports = await snapshot(app, store), await support_snapshot(store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 2)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 3600)
  await store.put_delete_domains_to_queue(id=1)
  await queue_resolution(app, store, 1, ['8.8.4.4'])
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert store.writer_state == 'FAILED'
  assert store.pending_count == 2
  assert store.unknown_count == 0
  assert await snapshot(app, store) == before
  assert await support_snapshot(store) == supports


async def test_full_real_writer_queue_backpressures_pool_and_retains_admitted_command_on_cancel(
  app, store, resolver, network, monkeypatch
):
  """Caller cancellation preserves the already-admitted completion date and drops waiting work.

  app/store/resolver/network isolate real coordination and persistence; monkeypatch
  constrains the writer queue to one entry so both cancellation boundaries are visible.
  """
  # jobs selects NEW; waiting announces a second producer blocked by the admitted command.
  jobs = importlib.import_module('jobs.job_registry')
  monkeypatch.setattr(app.settings, 'domains_resolve_worker_limit', 2)
  monkeypatch.setattr(app.settings, 'queue_max_size', 1)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  waiting = asyncio.Event()

  class WriterQueue(asyncio.Queue):
    """Observe full-queue backpressure while preserving standard put semantics."""

    async def put(self, item):
      """Notify waiting when item must await capacity before real admission."""
      if self.full():
        waiting.set()
      await super().put(item)

  store.db_save_queue = WriterQueue(maxsize=1)
  # connection seeds disposable membership; value identifies each finite selected domain.
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [{'id': value, 'name': f'queued-{value}.example.test', 'resolved': False} for value in range(1, 65)],
    )
    await connection.execute(insert(app.database.DnsServersDbo).values(id=42, server='192.0.2.53'))
  # requests records actual DNS calls; task owns the public saving pass.
  requests = network({'192.0.2.53': 'positive'})
  task = asyncio.create_task(resolver.domains_resolve(jobs.Jobs.DOMAINS_RESOLVE_NEW))
  try:
    await asyncio.wait_for(waiting.wait(), timeout=2)
    assert store.writer_task is None
    assert store.db_save_queue.qsize() == 1
    assert len(requests) <= 3
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
      await asyncio.wait_for(task, timeout=2)
    # Admission already transferred exactly one result to the database writer.
    assert store.db_save_queue.qsize() == vars(store.db_save_queue)['_unfinished_tasks'] == 1
    assert store.pending_count == 1
    assert await support_snapshot(store) == set()
    await store.start_writer()
    await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
    # supports identifies the one completed, admitted source result after caller cancellation.
    supports = await support_snapshot(store)
    assert len(supports) == 1
    # address and list_id are the surviving support's address and optional list context.
    assert {(address, list_id) for address, _, list_id in supports} == {('8.8.8.8', None)}
    # domain_id is the sole surviving source identity; _ discards its checked address/list metadata.
    for _, domain_id, _ in supports:
      assert (await attempt_state(app, store, domain_id))[0] is not None
    async with store._DataBase__read_engine.connect() as connection:
      assert (
        await connection.execute(text('SELECT COUNT(*) FROM rdpr_domains WHERE last_attempt_at IS NOT NULL'))
      ).scalar_one() == 1
    assert store.pending_count == store.unknown_count == 0
    assert store.writer_state == 'RUNNING'
  finally:
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def snapshot(app, store):
  async with store._DataBase__read_engine.connect() as connection:
    domain = (
      await connection.execute(
        select(
          app.database.DomainsDbo.resolved,
          app.database.DomainsDbo.last_resolved_at,
        ).where(app.database.DomainsDbo.id == 1)
      )
    ).one()
    ips = (
      await connection.execute(
        select(
          app.database.IpRecordsDbo.id,
          app.database.IpRecordsDbo.ip_address,
        ).where(app.database.IpRecordsDbo.domain_id == 1)
      )
    ).all()
  return tuple(domain), dict(ips)


async def flush_queue(store):
  elements = []
  while not store.db_save_queue.empty():
    elements.append(store.db_save_queue.get_nowait())
  if elements:
    try:
      await store._DataBase__batch_items_commit(elements)
    finally:
      # This manual test consumer owns queue accounting even when the batch rolls back.
      for _ in elements:
        store.db_save_queue.task_done()
  return elements


@pytest.mark.parametrize(
  ('resolved', 'checkpoint'),
  [
    (False, None),
    (True, STALE_CHECKPOINT),
  ],
)
@pytest.mark.parametrize('second_kind', ['servfail', 'nodata'])
async def test_partial_cycle_adds_reliable_ip_and_postpones_retry(
  app,
  store,
  resolver,
  network,
  resolved,
  checkpoint,
  second_kind,
):
  """A completed partial cycle postpones selection while retaining IP/checkpoint evidence.

  app/store/resolver/network isolate real persistence; resolved/checkpoint describe
  prior successful state and second_kind supplies conflicting DNS evidence.
  """
  await seed(app, store, resolved=resolved, checkpoint=checkpoint)
  # before captures the unchanged successful state and existing IP identities.
  before = await snapshot(app, store)
  network({'192.0.2.53': 'positive', '192.0.2.54': second_kind})
  await resolver._DomainsResolver__dns_main_tasker(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    default_dns_servers=[app.Server(server='192.0.2.53'), app.Server(server='192.0.2.54')],
    doh_dns_servers=[],
  )
  # commands are admitted results; after holds the committed checkpoint/IP state.
  commands = await flush_queue(store)
  assert len(commands) == 1
  assert commands[0].elements[0].resolution_complete is False
  after = await snapshot(app, store)
  assert after[0] == before[0]
  # key is each preexisting IP identity whose address must remain intact.
  assert {key: after[1][key] for key in before[1]} == before[1]
  assert set(after[1].values()) == set(before[1].values()) | {'8.8.8.8'}
  # eligible must be empty in both automatic modes until the attempt interval passes.
  eligible = await (
    store.get_new_domains_for_resolve() if checkpoint is None else store.get_stale_domains_for_resolve()
  )
  assert eligible == []
  assert await store.get_new_domains_for_resolve() == []
  assert await store.get_stale_domains_for_resolve() == []


@pytest.mark.parametrize('kind', ['nxdomain', 'nodata', 'positive'])
async def test_complete_cycle_reconciles_only_ipv4_and_checkpoints_atomically(app, store, resolver, network, kind):
  await seed(app, store)
  network({'192.0.2.53': kind})
  await resolver._DomainsResolver__dns_main_tasker(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    default_dns_servers=[app.Server(server='192.0.2.53')],
    doh_dns_servers=[],
  )
  assert (await snapshot(app, store))[0] == (False, None)
  commands = await flush_queue(store)
  assert len(commands) == 1
  assert commands[0].elements[0].resolution_complete is True
  domain, ips = await snapshot(app, store)
  assert domain[0] is True
  assert isinstance(domain[1], datetime)
  expected = {'2001:4860:4860::8888'} | ({'8.8.8.8'} if kind == 'positive' else set())
  assert set(ips.values()) == expected
  assert await store.get_new_domains_for_resolve() == []
  assert await store.get_stale_domains_for_resolve() == []


@pytest.mark.parametrize('complete', [False, True])
async def test_writer_independently_gates_deletion_and_checkpoint(app, store, complete):
  """Only complete evidence may withdraw IPv4 or advance successful state; both forms save an explicit attempt.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # before is checkpoint and IP state before the saving command.
  # command is the explicitly completed source result.
  # domain is committed successful-checkpoint fields.
  # ips is persisted IP identities and addresses.
  # key is one original IP identity.
  await seed(app, store)
  before = await snapshot(app, store)
  command = app.dto.DomainResult(
    id=1, name='www.example.test', resolution_complete=complete, last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC)
  )
  command.storage_ips = ('8.8.4.4',)
  command.insert.ips_insert = [app.Ip(ip_address='8.8.4.4', addr_type=4)]
  command.insert.ips_delete = [10, 12, 13, 14]
  await store.put_domain_after_resolve(command)
  await flush_queue(store)
  domain, ips = await snapshot(app, store)
  if complete:
    assert domain[0] is True
    assert isinstance(domain[1], datetime)
    assert set(ips.values()) == {'8.8.4.4', '2001:4860:4860::8888'}
  else:
    assert domain == before[0]
    assert {key: ips[key] for key in before[1]} == before[1]
    assert set(ips.values()) == set(before[1].values()) | {'8.8.4.4'}


async def test_checkpoint_failure_rolls_back_ip_addition_and_deletion(app, store, monkeypatch):
  """A rejected successful checkpoint rolls back the attempt and all IP changes in the same transaction.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # before is the original successful state and IP identity map.
  # connection is the disposable writer connection installing the failure trigger.
  # command is the explicitly completed authoritative result.
  await seed(app, store)
  before = await snapshot(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      text(
        'CREATE TRIGGER refuse_checkpoint BEFORE UPDATE OF resolved ON rdpr_domains '
        "BEGIN SELECT RAISE(ABORT, 'synthetic checkpoint rejection'); END"
      )
    )
  command = app.dto.DomainResult(
    id=1, name='www.example.test', resolution_complete=True, last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC)
  )
  command.storage_ips = ('8.8.4.4',)
  command.insert.ips_insert = [app.Ip(ip_address='8.8.4.4', addr_type=4)]
  command.insert.ips_delete = [10]
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  await store.put_domain_after_resolve(command)
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert store.writer_state == 'FAILED'
  assert isinstance(store.writer_failure, app.database.DatabaseWriteError)
  assert store.pending_count == 1
  assert store.db_save_queue._unfinished_tasks == 1
  assert await snapshot(app, store) == before


async def test_successful_empty_read_is_distinct_from_storage_failure(app, store):
  assert await store.get_all_ips_for_domain(domain_id=1) == []
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text('DROP TABLE rdpr_ip_records'))
  with pytest.raises(app.database.DomainIpReadError):
    await store.get_all_ips_for_domain(domain_id=1)


async def test_connection_open_failure_remains_typed_without_uninitialized_cleanup(app, store, monkeypatch):
  async def fail_connect():
    raise RuntimeError('Synthetic connection failure')

  monkeypatch.setattr(store, '_DataBase__read_connect', fail_connect)
  with pytest.raises(app.database.DomainIpReadError) as failure:
    await store.get_all_ips_for_domain(domain_id=1)
  assert isinstance(failure.value.__cause__, RuntimeError)


@pytest.mark.parametrize('kind', ['servfail', 'empty'])
async def test_all_failure_cycle_saves_marker_without_changing_ips_or_checkpoint(app, store, resolver, network, kind):
  """A terminal DNS failure saves one attempt and preserves prior successful data.

  app/store/resolver/network isolate persistence and kind chooses untrustworthy evidence.
  """
  await seed(app, store, resolved=True, checkpoint=STALE_CHECKPOINT)
  # before is the independent checkpoint and IP preservation oracle.
  before = await snapshot(app, store)
  network({'192.0.2.53': kind})
  await resolver._DomainsResolver__dns_main_tasker(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    default_dns_servers=[app.Server(server='192.0.2.53')],
    doh_dns_servers=[],
  )
  assert len(await flush_queue(store)) == 1
  assert await snapshot(app, store) == before
  assert await store.get_stale_domains_for_resolve() == []
  assert await store.get_new_domains_for_resolve() == []


async def enqueue_names(app, store, names):
  for name in names:
    await store.put_add_domains_to_queue(
      [
        app.database.DomainsPostElementReq(domain=name),
      ]
    )


async def stored_names(app, store):
  async with store._DataBase__read_engine.connect() as connection:
    return (
      (
        await connection.execute(
          select(app.database.DomainsDbo.name).order_by(app.database.DomainsDbo.name),
        )
      )
      .scalars()
      .all()
    )


def instrument_sessions(store, monkeypatch, *, fault=None, before_commit=None):
  """Inject faults at the driver boundary while retaining real SQL and cleanup."""
  evidence = SimpleNamespace(
    begins=0,
    commits=0,
    rollbacks=0,
    closes=0,
    sessions=[],
    commit_queues=[],
  )

  class ObservedSession(AsyncSession):
    async def execute(self, statement, *args, **kwargs):
      if str(statement) == 'BEGIN IMMEDIATE':
        evidence.begins += 1
        if fault is not None:
          await fault('begin', evidence)
      result = await super().execute(statement, *args, **kwargs)
      if str(statement).startswith('INSERT') and fault is not None:
        await fault('after_insert', evidence)
      return result

    async def commit(self):
      evidence.commits += 1
      evidence.commit_queues.append(store.db_save_queue.qsize())
      if before_commit is not None:
        await before_commit()
      if fault is not None:
        await fault('commit', evidence)
      await super().commit()
      if fault is not None:
        await fault('after_commit', evidence)

    async def rollback(self):
      evidence.rollbacks += 1
      await super().rollback()
      if fault is not None:
        await fault('rollback', evidence)

    async def close(self):
      evidence.closes += 1
      await super().close()
      if fault is not None:
        await fault('close', evidence)

  factory = async_sessionmaker(
    bind=store._DataBase__write_engine,
    class_=ObservedSession,
    expire_on_commit=False,
  )

  def observed_factory():
    session = factory()
    evidence.sessions.append(session)
    return session

  monkeypatch.setattr(store, '_DataBase__write_session_factory', observed_factory)
  return evidence


def lock_error(code=sqlite3.SQLITE_BUSY):
  error = sqlite3.OperationalError('synthetic private SQL payload')
  error.sqlite_errorcode = code
  return OperationalError('synthetic private SQL statement', {}, error)


@pytest.mark.parametrize(
  ('batch_size', 'count'),
  [
    (3, 2),
    (3, 3),
    (3, 4),
    (1, 1),
    (1, 4),
    (3, 9),
    (3, 10),
  ],
)
async def test_writer_persists_every_admitted_event_across_batch_boundaries(
  app,
  store,
  monkeypatch,
  batch_size,
  count,
):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', batch_size)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 0.01)
  names = [f'batch-{index}.example.test' for index in range(count)]
  await enqueue_names(app, store, names)
  assert await stored_names(app, store) == []
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == sorted(names)
  assert store.pending_count == 0
  assert store.writer_state == 'RUNNING'


async def test_full_batch_commits_without_waiting_for_another_event(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 3)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 3600.0)
  names = ['first.example.test', 'second.example.test', 'third.example.test']
  await enqueue_names(app, store, names)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == sorted(names)


class ControlledWriterClock:
  """Advance only writer queue timeouts, leaving the event loop and SQLite real."""

  def __init__(self, app, store, monkeypatch):
    self.value = 10.0
    self.waits = asyncio.Queue()
    self.current = None
    self.dequeued = []
    clock = self

    class ObservedQueue(asyncio.Queue):
      async def get(self):
        item = await super().get()
        clock.dequeued.append(item)
        return item

    store.db_save_queue = ObservedQueue(maxsize=10)
    monkeypatch.setattr(app.database, 'monotonic', lambda: self.value)
    monkeypatch.setattr(app.database, 'wait_for', self.wait_for)

  async def wait_for(self, awaitable, *, timeout):
    # Shutdown uses a shielded Future and must retain its real safety deadline.
    if asyncio.isfuture(awaitable):
      return await asyncio.wait_for(awaitable, timeout=timeout)
    get = asyncio.create_task(awaitable)
    expired = asyncio.get_running_loop().create_future()
    request = SimpleNamespace(timeout=timeout, deadline=self.value + timeout, expired=expired)
    self.current = request
    self.waits.put_nowait(request)
    try:
      done, _ = await asyncio.wait((get, expired), return_when=asyncio.FIRST_COMPLETED)
      if get in done:
        return await get
      raise TimeoutError
    finally:
      if self.current is request:
        self.current = None
      expired.cancel()
      if not get.done():
        get.cancel()
      await asyncio.gather(get, return_exceptions=True)

  async def next_wait(self):
    request = await asyncio.wait_for(self.waits.get(), timeout=2)
    assert request.timeout == pytest.approx(1.0)
    return request

  def advance(self, interval):
    self.value += interval
    request = self.current
    if request is not None and self.value >= request.deadline and not request.expired.done():
      request.expired.set_result(None)


@pytest.mark.parametrize('gaps', [(0.4, 0.4, 0.4, 0.4), (0.75, 0.125, 0.625)])
async def test_batch_idle_timeout_resets_after_every_dequeue(app, store, monkeypatch, gaps):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 100)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 1.0)
  clock = ControlledWriterClock(app, store, monkeypatch)
  evidence = instrument_sessions(store, monkeypatch)
  names = [f'idle-{index}.example.test' for index in range(len(gaps) + 1)]
  await enqueue_names(app, store, names[:1])
  await store.start_writer()
  await clock.next_wait()
  for gap, name in zip(gaps, names[1:], strict=True):
    clock.advance(gap)
    await enqueue_names(app, store, [name])
    await clock.next_wait()

  # The stream exceeds the original interval, but no idle interval has elapsed.
  assert clock.value > 11.0
  assert evidence.begins == evidence.commits == 0
  assert await stored_names(app, store) == []
  assert len(clock.dequeued) == len(names)
  assert {item.receipt.outcome for item in clock.dequeued} == {app.database.WriteOutcome.PENDING}
  clock.advance(0.875)
  assert evidence.commits == 0
  assert store.pending_count == len(names)
  clock.advance(0.125)
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == sorted(names)
  assert evidence.begins == evidence.commits == evidence.closes == 1
  assert evidence.rollbacks == 0
  assert len({id(item) for item in clock.dequeued}) == len(names)
  assert {item.receipt.outcome for item in clock.dequeued} == {app.database.WriteOutcome.CONFIRMED}
  assert store.pending_count == 0


async def test_next_batch_gets_fresh_idle_timeout_after_partial_flush(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 100)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 1.0)
  clock = ControlledWriterClock(app, store, monkeypatch)
  evidence = instrument_sessions(store, monkeypatch)
  await enqueue_names(app, store, ['earlier.example.test'])
  await store.start_writer()
  await clock.next_wait()
  clock.advance(1.0)
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert evidence.commits == 1
  clock.advance(100.0)
  await enqueue_names(app, store, ['later.example.test'])
  await clock.next_wait()
  clock.advance(0.875)
  assert evidence.commits == 1
  assert await stored_names(app, store) == ['earlier.example.test']
  clock.advance(0.125)
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == ['earlier.example.test', 'later.example.test']
  assert evidence.begins == evidence.commits == evidence.closes == 2
  assert evidence.rollbacks == 0
  assert len(clock.dequeued) == 2
  assert {item.receipt.outcome for item in clock.dequeued} == {app.database.WriteOutcome.CONFIRMED}
  assert store.pending_count == 0


async def test_start_is_idempotent_and_idle_close_restarts_with_fresh_queue(app, store):
  original_queue = store.db_save_queue
  await store.start_writer()
  task = store.writer_task
  await store.start_writer()
  assert store.writer_task is task
  await store.close(timeout=2)
  assert task.done()
  assert store.writer_state == 'STOPPED'
  assert store.pending_count == 0
  with pytest.raises(app.database.WriterClosedError):
    await enqueue_names(app, store, ['late.example.test'])
  await store.start_writer()
  assert store.db_save_queue is not original_queue
  assert store.writer_task is not task
  await enqueue_names(app, store, ['restart.example.test'])
  await store.close(timeout=2)
  assert await stored_names(app, store) == ['restart.example.test']


async def test_instances_have_independent_queues_and_lifecycles(app, store, monkeypatch):
  other = app.database.DataBase()
  other._DataBase__state = True
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  try:
    assert other.db_save_queue is not store.db_save_queue
    await enqueue_names(app, store, ['owned.example.test'])
    await enqueue_names(app, other, ['independent.example.test'])
    assert store.db_save_queue.qsize() == 1
    assert other.db_save_queue.qsize() == 1
    await store.start_writer()
    await store.close(timeout=2)
    assert other.db_save_queue.qsize() == 1
    assert other.writer_state == 'NEW'
    await other.start_writer()
    await other.close(timeout=2)
    assert await stored_names(app, store) == ['independent.example.test', 'owned.example.test']
  finally:
    await other.close(timeout=2)


async def test_close_flushes_pending_tail_and_queued_events(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 2)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 3600.0)
  entered = asyncio.Event()
  release = asyncio.Event()

  async def hold_commit():
    entered.set()
    await release.wait()

  instrument_sessions(store, monkeypatch, before_commit=hold_commit)
  names = [f'shutdown-{index}.example.test' for index in range(5)]
  await enqueue_names(app, store, names)
  await store.start_writer()
  await asyncio.wait_for(entered.wait(), timeout=2)
  closing = asyncio.create_task(store.close(timeout=2))
  try:
    # A queued callback runs after close has reached its first await.
    settled = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(settled.set_result, None)
    await settled
    assert not closing.done()
    assert store.pending_count == 5
    with pytest.raises(app.database.WriterClosedError):
      await enqueue_names(app, store, ['rejected.example.test'])
  finally:
    release.set()
  await asyncio.wait_for(closing, timeout=2)
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == sorted(names)
  assert store.pending_count == 0
  assert store.writer_state == 'STOPPED'


async def test_shutdown_wakes_blocked_producer_without_admitting_its_event(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  entered = asyncio.Event()
  release = asyncio.Event()
  blocked = asyncio.Event()

  class AdmissionQueue(asyncio.Queue):
    async def put(self, item):
      if self.full():
        blocked.set()
      await super().put(item)

  async def hold_commit():
    entered.set()
    await release.wait()

  store.db_save_queue = AdmissionQueue(maxsize=1)
  instrument_sessions(store, monkeypatch, before_commit=hold_commit)
  await enqueue_names(app, store, ['accepted-first.example.test'])
  await store.start_writer()
  await asyncio.wait_for(entered.wait(), timeout=2)
  await enqueue_names(app, store, ['accepted-second.example.test'])
  producer = asyncio.create_task(enqueue_names(app, store, ['blocked.example.test']))
  await asyncio.wait_for(blocked.wait(), timeout=2)
  assert not producer.done()
  assert await store.put_delete_ip_records_to_queue([10]) is False
  assert await store.put_delete_ip_records_to_queue([]) is True
  closing = asyncio.create_task(store.close(timeout=2))
  try:
    with pytest.raises(app.database.WriterClosedError):
      await asyncio.wait_for(producer, timeout=2)
    assert store.pending_count == 2
  finally:
    release.set()
  await asyncio.wait_for(closing, timeout=2)
  assert await stored_names(app, store) == [
    'accepted-first.example.test',
    'accepted-second.example.test',
  ]
  assert await store.put_delete_ip_records_to_queue([10]) is False
  assert await store.put_delete_ip_records_to_queue([]) is True


@pytest.mark.parametrize(
  'method_name',
  [
    'put_add_dns_servers_to_queue',
    'put_delete_dns_servers_to_queue',
    'put_add_domains_lists_to_queue',
    'put_delete_domains_list_to_queue',
    'put_add_domains_to_queue',
    'put_delete_domains_to_queue',
    'put_add_ips_lists_to_queue',
    'put_delete_ips_list_to_queue',
    'put_add_ips_to_queue',
    'put_delete_ips_to_queue',
    'put_add_ros_configs_to_queue',
    'put_delete_ros_configs_to_queue',
    'put_domain_after_resolve',
  ],
)
async def test_producer_methods_propagate_closed_admission(app, store, method_name):
  """Each producer reports a closed writer without retaining unadmitted work.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # method is the selected real queue producer.
  # arguments is valid producer inputs, including an explicit resolution completion time.
  await store.close(timeout=2)
  method = getattr(store, method_name)
  if method_name == 'put_domain_after_resolve':
    arguments = [
      app.dto.DomainResult(id=1, name='closed.example.test', last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC))
    ]
  elif method_name.startswith('put_add_'):
    arguments = [[]]
  else:
    arguments = []
  with pytest.raises(app.database.WriterClosedError):
    await method(*arguments)
  assert store.pending_count == 0


@pytest.mark.parametrize(
  'code',
  [
    sqlite3.SQLITE_BUSY,
    sqlite3.SQLITE_LOCKED,
    sqlite3.SQLITE_BUSY | (2 << 8),
    sqlite3.SQLITE_LOCKED | (1 << 8),
  ],
)
async def test_known_precommit_lock_retries_same_batch_then_persists(app, store, monkeypatch, code):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  delays = []

  async def fault(stage, evidence):
    if stage == 'begin' and evidence.begins < 3:
      raise lock_error(code)

  async def record_delay(delay):
    delays.append(delay)

  monkeypatch.setattr(app.database, 'sleep', record_delay)
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['locked-first.example.test', 'newer.example.test'])
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == ['locked-first.example.test', 'newer.example.test']
  assert evidence.begins == 4
  assert evidence.rollbacks == 2
  assert evidence.commits == 2
  assert len(evidence.sessions) == 4
  assert delays == [0.1, 0.2]
  assert evidence.commit_queues[0] == 1


@pytest.mark.parametrize(
  ('stage', 'error_kind', 'expected_attempts'),
  [
    ('begin', 'lock', 3),
    ('begin', 'generic', 1),
    ('after_insert', 'generic', 1),
    ('after_insert', 'cancelled', 1),
    ('commit', 'lock', 1),
    ('after_commit', 'lock', 1),
  ],
)
async def test_terminal_write_failure_retains_work_and_never_replays_ambiguity(
  app,
  store,
  monkeypatch,
  stage,
  error_kind,
  expected_attempts,
):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  delays = []

  async def fault(current_stage, evidence):
    if current_stage == stage:
      if error_kind == 'lock':
        raise lock_error()
      if error_kind == 'cancelled':
        raise asyncio.CancelledError()
      raise RuntimeError('synthetic private SQL payload')

  async def record_delay(delay):
    delays.append(delay)

  monkeypatch.setattr(app.database, 'sleep', record_delay)
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['failed.example.test', 'queued.example.test'])
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert store.writer_state == 'FAILED'
  assert evidence.begins == expected_attempts
  assert evidence.commits == (1 if stage in {'commit', 'after_commit'} else 0)
  assert store.pending_count == 2
  assert store.db_save_queue._unfinished_tasks == 2
  assert store.unknown_count == (1 if stage in {'commit', 'after_commit'} else 0)
  assert store.writer_failure.retryable is False
  assert 'private' not in str(store.writer_failure)
  assert 'SQL' not in str(store.writer_failure)
  assert await stored_names(app, store) == (['failed.example.test'] if stage == 'after_commit' else [])
  with pytest.raises(app.database.WriterFailedError):
    await store.close(timeout=2)
  with pytest.raises(app.database.WriterFailedError) as restart_failure:
    await store.start_writer()
  assert restart_failure.value.pending_count == store.pending_count == 2
  assert restart_failure.value.unknown_count == store.unknown_count
  assert restart_failure.value.outcome_unknown is bool(store.unknown_count)
  with pytest.raises(app.database.WriterFailedError):
    await enqueue_names(app, store, ['late.example.test'])
  assert await store.put_delete_ip_records_to_queue([10]) is False
  assert delays == ([0.1, 0.2] if expected_attempts == 3 else [])


@pytest.mark.parametrize('cleanup_stage', ['rollback', 'close'])
async def test_failed_precommit_cleanup_prevents_lock_retry(app, store, monkeypatch, caplog, cleanup_stage):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  async def fault(stage, evidence):
    if stage == 'begin':
      raise lock_error()
    if stage == cleanup_stage:
      raise lock_error()

  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['cleanup.example.test'])
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert evidence.begins == 1
  assert evidence.commits == 0
  assert store.writer_state == 'FAILED'
  assert store.pending_count == 1
  assert await stored_names(app, store) == []
  assert 'Database batch' in caplog.text
  assert 'synthetic private SQL payload' not in caplog.text
  assert 'synthetic private SQL statement' not in caplog.text
  assert 'synthetic private' not in str(store.writer_failure)


async def test_known_commit_with_close_failure_is_acknowledged_without_replay(app, store, monkeypatch, caplog):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  async def fault(stage, evidence):
    if stage == 'close':
      raise lock_error()

  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['committed.example.test'])
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert await stored_names(app, store) == ['committed.example.test']
  assert evidence.commits == 1
  assert store.writer_state == 'FAILED'
  assert store.pending_count == 0
  assert store.unknown_count == 0
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert store.writer_failure.committed is True
  assert 'Database batch session cleanup failed' in caplog.text
  assert 'synthetic private' not in caplog.text
  assert 'synthetic private' not in str(store.writer_failure)
  with pytest.raises(app.database.WriterFailedError):
    await store.close(timeout=2)
  assert evidence.commits == 1


async def test_session_open_failure_is_typed_without_uninitialized_cleanup(app, store, monkeypatch):
  def unavailable_session():
    raise RuntimeError('synthetic private path')

  monkeypatch.setattr(store, '_DataBase__write_session_factory', unavailable_session)
  element = app.database.QueueElementDto(
    target=app.database.TargetAction.DOMAINS_ADD,
    elements=[app.database.DomainsPostElementReq(domain='unavailable.example.test')],
  )
  with pytest.raises(app.database.BatchWriteError) as failure:
    await store._DataBase__batch_items_commit([element])
  assert failure.value.retryable is False
  assert failure.value.outcome_unknown is False
  assert 'private' not in str(failure.value)
  assert isinstance(failure.value.__cause__, RuntimeError)


async def test_setup_failure_never_starts_writer_and_keeps_original_cause(app, store, monkeypatch):
  async def unavailable_storage():
    raise RuntimeError('synthetic private startup path')

  monkeypatch.setattr(store, '_DataBase__create_tables', unavailable_storage)
  with pytest.raises(app.database.DatabaseWriteError) as failure:
    await store.setup()
  assert isinstance(failure.value.__cause__, RuntimeError)
  assert store.writer_task is None
  assert store.writer_state == 'FAILED'
  assert 'private' not in str(failure.value)


@pytest.mark.parametrize('cleanup_stage', ['session', 'engine'])
async def test_initialization_cleanup_diagnostics_hide_native_errors(app, store, monkeypatch, caplog, cleanup_stage):
  class FailingReadSession(AsyncSession):
    async def execute(self, *args, **kwargs):
      await super().execute(*args, **kwargs)
      raise lock_error()

    async def close(self):
      await super().close()
      if cleanup_stage == 'session':
        raise lock_error()

  with monkeypatch.context() as startup_patch:
    startup_patch.setattr(
      store,
      '_DataBase__read_session_factory',
      async_sessionmaker(bind=store._DataBase__read_engine, class_=FailingReadSession),
    )
    if cleanup_stage == 'engine':
      engine_type = type(store._DataBase__write_engine)
      original_dispose = engine_type.dispose

      async def fail_dispose(engine, *args, **kwargs):
        await original_dispose(engine, *args, **kwargs)
        if engine is store._DataBase__write_engine:
          raise lock_error()

      startup_patch.setattr(engine_type, 'dispose', fail_dispose)

    # Existing isolated tables are sufficient; this fault belongs to startup cleanup.
    async def ready_tables():
      pass

    startup_patch.setattr(store, '_DataBase__create_tables', ready_tables)
    with pytest.raises(app.database.DatabaseWriteError) as failure:
      await store.setup()
  assert store.writer_state == 'FAILED'
  assert store.writer_task is None
  assert store.pending_count == store.unknown_count == 0
  assert isinstance(failure.value.__cause__, OperationalError)
  assert 'synthetic private' not in str(failure.value)
  assert f'Database initialization {cleanup_stage} cleanup failed' in caplog.text
  assert 'synthetic private' not in caplog.text


async def test_shutdown_engine_cleanup_diagnostics_hide_native_errors(app, store, monkeypatch, caplog):
  engine_type = type(store._DataBase__write_engine)
  original_dispose = engine_type.dispose

  async def fail_dispose(engine, *args, **kwargs):
    await original_dispose(engine, *args, **kwargs)
    if engine is store._DataBase__write_engine:
      raise lock_error()

  with monkeypatch.context() as cleanup_patch:
    cleanup_patch.setattr(engine_type, 'dispose', fail_dispose)
    with pytest.raises(app.database.WriterFailedError) as failure:
      await store.close(timeout=2)
  assert store.writer_state == 'FAILED'
  assert store.pending_count == store.unknown_count == 0
  assert 'Database engine cleanup failed' in caplog.text
  assert 'synthetic private' not in caplog.text
  assert 'synthetic private' not in str(failure.value)


async def test_lock_after_insert_rolls_back_before_retrying(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  failed = False
  rolled_back_names = []

  async def fault(stage, evidence):
    nonlocal failed
    if stage == 'after_insert' and not failed:
      failed = True
      raise lock_error()
    if stage == 'rollback':
      rolled_back_names.append(await stored_names(app, store))

  async def immediate_retry(delay):
    assert delay == 0.1

  monkeypatch.setattr(app.database, 'sleep', immediate_retry)
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['rollback.example.test'])
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert rolled_back_names == [[]]
  assert evidence.rollbacks == 1
  assert evidence.begins == 2
  assert await stored_names(app, store) == ['rollback.example.test']


@pytest.mark.parametrize('interruption', ['deadline', 'caller_cancel', 'writer_cancel'])
async def test_inflight_commit_retains_ownership_until_cleanup(app, store, monkeypatch, interruption):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  entered = asyncio.Event()
  release = asyncio.Event()

  async def hold_commit():
    entered.set()
    await release.wait()

  evidence = instrument_sessions(store, monkeypatch, before_commit=hold_commit)
  write_engine = store._DataBase__write_engine
  engine_type = type(write_engine)
  original_dispose = engine_type.dispose
  disposed = []

  async def observe_dispose(engine, *args, **kwargs):
    if engine is write_engine:
      disposed.append(engine)
    await original_dispose(engine, *args, **kwargs)

  monkeypatch.setattr(engine_type, 'dispose', observe_dispose)
  await enqueue_names(app, store, ['inflight.example.test', 'queued-after-inflight.example.test'])
  await store.start_writer()
  await asyncio.wait_for(entered.wait(), timeout=2)
  try:
    if interruption == 'writer_cancel':
      store.writer_task.cancel()
      checkpoint = asyncio.get_running_loop().create_future()
      asyncio.get_running_loop().call_soon(checkpoint.set_result, None)
      await checkpoint
      assert store.writer_state == 'FAILED'
    elif interruption == 'deadline':
      with pytest.raises(app.database.DatabaseShutdownError) as failure:
        await store.close(timeout=0)
      assert failure.value.pending_count == 2
      assert failure.value.unknown_count == 1
    else:
      closing = asyncio.create_task(store.close(timeout=2))
      checkpoint = asyncio.get_running_loop().create_future()
      asyncio.get_running_loop().call_soon(checkpoint.set_result, None)
      await checkpoint
      closing.cancel()
      with pytest.raises(app.database.DatabaseShutdownError):
        await closing
    assert store.writer_task is not None
    assert not store.writer_task.done()
    assert store.pending_count == 2
    assert store.unknown_count == 1
    assert disposed == []
  finally:
    release.set()
  with pytest.raises(asyncio.CancelledError):
    await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert await stored_names(app, store) == ['inflight.example.test']
  assert evidence.commits == 1
  assert store.writer_state == 'FAILED'
  assert store.pending_count == 1
  with pytest.raises(app.database.WriterFailedError):
    await store.start_writer()
  with pytest.raises(app.database.WriterFailedError):
    await store.close(timeout=2)
  assert evidence.commits == 1
  assert disposed == [write_engine]


@pytest.mark.parametrize('failure_stage', [None, 'setup', 'start', 'body', 'stop', 'close', 'finish'])
async def test_lifespan_always_attempts_database_and_http_cleanup(app, monkeypatch, failure_stage):
  server = importlib.import_module('server.server')
  events = []
  failure = RuntimeError('synthetic lifespan failure')

  async def setup():
    events.append('setup')
    if failure_stage == 'setup':
      raise failure

  async def close():
    events.append('database_close')
    if failure_stage == 'close':
      raise failure

  async def http_close():
    events.append('http_close')

  async def start():
    events.append('coordinator_start')
    if failure_stage == 'start':
      raise failure

  async def stop():
    events.append('coordinator_stop')
    if failure_stage == 'stop':
      raise failure

  async def finish_close():
    events.append('coordinator_finish')
    if failure_stage == 'finish':
      raise failure

  monkeypatch.setattr(server, 'db', SimpleNamespace(setup=setup, close=close))
  monkeypatch.setattr(server, 'saving_coordinator', SimpleNamespace(start=start, stop=stop, finish_close=finish_close))
  monkeypatch.setattr(server.HttpClient, 'close', http_close)
  instance = server.AppServer()

  async def run_lifespan():
    async with instance.app.router.lifespan_context(instance.app):
      events.append('body')
      if failure_stage == 'body':
        raise failure

  if failure_stage is None:
    await run_lifespan()
  else:
    with pytest.raises(RuntimeError) as raised:
      await run_lifespan()
    assert raised.value is failure
  expected = ['setup']
  if failure_stage != 'setup':
    expected.append('coordinator_start')
    if failure_stage != 'start':
      expected.append('body')
  assert events == [*expected, 'coordinator_stop', 'database_close', 'coordinator_finish', 'http_close']


async def test_waiting_producer_is_admitted_when_capacity_becomes_available(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  entered = asyncio.Event()
  blocked = asyncio.Event()
  release = asyncio.Event()

  class AdmissionQueue(asyncio.Queue):
    async def put(self, item):
      if self.full():
        blocked.set()
      await super().put(item)

  async def hold_commit():
    entered.set()
    await release.wait()

  store.db_save_queue = AdmissionQueue(maxsize=1)
  instrument_sessions(store, monkeypatch, before_commit=hold_commit)
  await enqueue_names(app, store, ['capacity-first.example.test'])
  await store.start_writer()
  await asyncio.wait_for(entered.wait(), timeout=2)
  await enqueue_names(app, store, ['capacity-second.example.test'])
  producer = asyncio.create_task(enqueue_names(app, store, ['capacity-third.example.test']))
  try:
    await asyncio.wait_for(blocked.wait(), timeout=2)
    assert not producer.done()
  finally:
    release.set()
  await asyncio.wait_for(producer, timeout=2)
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == [
    'capacity-first.example.test',
    'capacity-second.example.test',
    'capacity-third.example.test',
  ]


async def test_nonblocking_deletion_acknowledges_admission_before_commit(app, store, monkeypatch):
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  assert await store.put_delete_ip_records_to_queue([10]) is True
  assert 10 in (await snapshot(app, store))[1]
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert (await snapshot(app, store))[1] == {
    11: '2001:4860:4860::8888',
    12: '8.8.8.0/24',
    13: '8.8.8.0',
    14: '8.8.8.0/25',
  }


@pytest.mark.parametrize(
  ('selector', 'removed_ids'),
  [
    (10, {10}),
    ('10', {10}),
    ('9.9.9.9', {10}),
    ('2001:4860:4860::8888', {11}),
    ('8.8.8.0/24', {12}),
    (None, {10, 11, 12, 13, 14}),
    ('', set()),
    ('invalid-address', set()),
    ('9.9.9.999', set()),
  ],
)
async def test_ip_deletion_selectors_admit_only_valid_commands(app, store, caplog, selector, removed_ids):
  await seed(app, store)
  before_domain, before_ips = await snapshot(app, store)
  await store.put_delete_ips_to_queue(selector)
  assert store.pending_count == int(bool(removed_ids))
  assert await snapshot(app, store) == (before_domain, before_ips)
  await store.close(timeout=2)
  assert await snapshot(app, store) == (
    before_domain,
    {key: value for key, value in before_ips.items() if key not in removed_ids},
  )
  assert store.pending_count == 0
  assert 'UnboundLocalError' not in caplog.text


async def test_idle_writer_waits_for_queue_without_opening_sessions(app, store, monkeypatch):
  waiting = asyncio.Event()

  class IdleQueue(asyncio.Queue):
    async def get(self):
      if self.empty():
        waiting.set()
      return await super().get()

  async def unexpected_polling(delay):
    raise AssertionError('Idle writer must await queue admission')

  store.db_save_queue = IdleQueue(maxsize=1)
  monkeypatch.setattr(app.database, 'sleep', unexpected_polling)
  evidence = instrument_sessions(store, monkeypatch)
  await store.start_writer()
  await asyncio.wait_for(waiting.wait(), timeout=2)
  assert not store.writer_task.done()
  assert evidence.sessions == []
  await store.close(timeout=2)
  assert store.pending_count == 0
  assert evidence.sessions == []


@pytest.mark.parametrize('interruption', ['deadline', 'writer_cancel'])
async def test_backoff_interruption_retains_known_uncommitted_work(
  app,
  store,
  monkeypatch,
  interruption,
):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  entered = asyncio.Event()
  release = asyncio.Event()
  delays = []

  async def fault(stage, evidence):
    if stage == 'begin':
      raise lock_error()

  async def hold_backoff(delay):
    delays.append(delay)
    entered.set()
    await release.wait()

  monkeypatch.setattr(app.database, 'sleep', hold_backoff)
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['backoff.example.test', 'queued.example.test'])
  await store.start_writer()
  await asyncio.wait_for(entered.wait(), timeout=2)
  try:
    # The failed attempt has released ownership before this retry delay begins.
    assert (evidence.begins, evidence.commits, evidence.rollbacks, evidence.closes) == (1, 0, 1, 1)
    assert not evidence.sessions[0].in_transaction()
    if interruption == 'deadline':
      with pytest.raises(app.database.DatabaseShutdownError):
        await store.close(timeout=0)
    else:
      store.writer_task.cancel()
      checkpoint = asyncio.get_running_loop().create_future()
      asyncio.get_running_loop().call_soon(checkpoint.set_result, None)
      await checkpoint
    assert store.writer_state == 'FAILED'
  finally:
    release.set()
  with pytest.raises(asyncio.CancelledError):
    await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  with pytest.raises(app.database.WriterFailedError):
    await store.close(timeout=2)
  assert await stored_names(app, store) == []
  assert (evidence.begins, evidence.commits, evidence.rollbacks, evidence.closes) == (1, 0, 1, 1)
  assert delays == [0.1]
  assert store.pending_count == 2
  assert store.db_save_queue.qsize() == 1
  assert store.db_save_queue._unfinished_tasks == 2
  # No commit was entered, so the retained commands have a known outcome.
  assert (store.unknown_count, store.writer_failure.unknown_count, store.writer_failure.outcome_unknown) == (
    0,
    0,
    False,
  )


@pytest.mark.parametrize('parent', ['domain', 'domain_list'])
async def test_writer_parent_deletion_cascades_linked_ips(app, store, monkeypatch, parent):
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsListsDbo).values(
        id=5,
        name='linked',
        url='https://example.test/domains',
      )
    )
  await seed(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text('UPDATE rdpr_domains SET domain_list_id=5 WHERE id=1'))
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  evidence = instrument_sessions(store, monkeypatch)
  if parent == 'domain':
    await store.put_delete_domains_to_queue(id=1)
  else:
    await store.put_delete_domains_list_to_queue(id=5)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(select(app.database.DomainsDbo.id))).all() == []
    assert (await connection.execute(select(app.database.IpRecordsDbo.id))).all() == []
    assert (await connection.execute(select(app.database.DomainsListsDbo.id))).scalars().all() == (
      [5] if parent == 'domain' else []
    )
    assert (await connection.execute(text('PRAGMA foreign_key_check'))).all() == []
  assert evidence.commits == 1
  assert store.pending_count == store.unknown_count == 0
  assert store.writer_state == 'RUNNING'


async def test_mixed_domain_delete_and_partial_resolution_preserve_grouping(app, store, monkeypatch):
  """A partial resolution and direct deletion retain the existing successful mixed-batch contract.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # command is the completed partial result admitted beside its parent deletion.
  # evidence is real transaction boundary observations.
  # connection is the read connection checking cleanup and foreign keys.
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 3)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 3600.0)
  command = app.dto.DomainResult(
    id=1, name='www.example.test', resolution_complete=False, last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC)
  )
  command.storage_ips = ('8.8.4.4',)
  command.insert.ips_insert = [app.Ip(ip_address='8.8.4.4', addr_type=4)]
  # Existing grouping inserts resolved IPs before deleting domains in one batch.
  await store.put_delete_domains_to_queue(id=1)
  await store.put_domain_after_resolve(command)
  await enqueue_names(app, store, ['survivor.example.test'])
  evidence = instrument_sessions(store, monkeypatch)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == ['survivor.example.test']
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(select(app.database.IpRecordsDbo.id))).all() == []
    assert (await connection.execute(text('PRAGMA foreign_key_check'))).all() == []
  assert evidence.commits == 1
  assert store.pending_count == store.unknown_count == 0


async def test_late_resolution_after_parent_deletion_fails_without_orphan_or_replay(
  app,
  store,
  monkeypatch,
):
  """A completed resolution cannot recreate a deleted parent or orphan its IP data.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # command is the completed result for an already-deleted domain.
  # evidence is real commit and cleanup observations.
  # connection is the connection checking durable orphan absence.
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  evidence = instrument_sessions(store, monkeypatch)
  await store.put_delete_domains_to_queue(id=1)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  command = app.dto.DomainResult(
    id=1, name='www.example.test', resolution_complete=True, last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC)
  )
  command.storage_ips = ('8.8.4.4',)
  command.insert.ips_insert = [app.Ip(ip_address='8.8.4.4', addr_type=4)]
  await store.put_domain_after_resolve(command)
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(select(app.database.DomainsDbo.id))).all() == []
    assert (await connection.execute(select(app.database.IpRecordsDbo.id))).all() == []
  assert (evidence.begins, evidence.commits, evidence.rollbacks) == (2, 1, 1)
  assert store.writer_state == 'FAILED'
  assert isinstance(store.writer_failure, app.database.WriterFailedError)
  assert store.writer_failure.retryable is False
  assert store.writer_failure.committed is False
  assert store.writer_failure.outcome_unknown is False
  assert store.writer_failure.pending_count == store.pending_count == 1
  assert store.writer_failure.unknown_count == store.unknown_count == 0
  assert store.db_save_queue._unfinished_tasks == 1
  with pytest.raises(app.database.WriterFailedError):
    await store.start_writer()
  with pytest.raises(app.database.WriterFailedError):
    await store.close(timeout=2)
  assert (evidence.begins, evidence.commits) == (2, 1)


@pytest.mark.parametrize('failure_stage', [None, 'migration', 'history_read', 'history_write'])
async def test_setup_observes_runner_failures_and_preserves_migration_history(
  app,
  store,
  monkeypatch,
  tmp_path,
  failure_stage,
):
  paths = []
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text('CREATE TABLE migration_steps (step TEXT NOT NULL)'))
  for name in ['migration_b.py', 'migration_a.py']:
    path = tmp_path / 'migrations' / name
    failure = "  raise RuntimeError('synthetic migration failure')\n" if failure_stage == 'migration' else ''
    path.write_text(
      '\n'.join(
        [
          'from sqlalchemy import text',
          f'STEP = {name!r}',
          'async def upgrade(conn):',
          '  await conn.execute(text("INSERT INTO migration_steps VALUES (:step)"), {"step": STEP + ":up"})',
          failure.rstrip('\n'),
          'async def downgrade(conn):',
          '  await conn.execute(text("INSERT INTO migration_steps VALUES (:step)"), {"step": STEP + ":down"})',
          '',
        ]
      ),
      encoding='utf-8',
    )
    paths.append(path)
  if failure_stage == 'history_read':

    async def unavailable_history(cls, conn):
      raise RuntimeError('synthetic history failure')

    monkeypatch.setattr(app.database.MigrationsDbo, 'get_all', classmethod(unavailable_history))
  elif failure_stage == 'history_write':
    original_execute = app.database.AsyncConnection.execute

    async def reject_history(connection, statement, *args, **kwargs):
      if str(statement).startswith('INSERT') and 'rdpr_migrations' in str(statement):
        raise RuntimeError('synthetic history persistence failure')
      return await original_execute(connection, statement, *args, **kwargs)

    monkeypatch.setattr(app.database.AsyncConnection, 'execute', reject_history)
  if failure_stage is None:
    await store.setup()
    assert store.writer_state == 'RUNNING'
    await store.close(timeout=2)
  else:
    with pytest.raises(app.database.DatabaseWriteError, match='Database initialization failed'):
      await store.setup()
    assert store._DataBase__initialization_failed is True
    assert store.writer_task is None
    assert store.writer_state == 'FAILED'
    assert store.pending_count == store.unknown_count == 0
  if failure_stage is None:
    async with store._DataBase__read_engine.connect() as connection:
      steps = (await connection.execute(text('SELECT step FROM migration_steps ORDER BY rowid'))).scalars().all()
      history = (
        await connection.execute(
          select(
            app.database.MigrationsDbo.name,
            app.database.MigrationsDbo.checksum,
            app.database.MigrationsDbo.applied_at,
          ).order_by(app.database.MigrationsDbo.name)
        )
      ).all()
    assert steps == [
      f'{name}:{direction}' for name in ['migration_a.py', 'migration_b.py'] for direction in ['up', 'down']
    ]
    assert [(row.name, row.checksum) for row in history] == [
      (path.name, app.database.calculate_checksum(file_path=path)) for path in sorted(paths)
    ]
    assert all(row.applied_at is not None for row in history)
  else:
    # Failed startup must not commit earlier hooks, history, defaults, or DDL.
    async with store._DataBase__read_engine.connect() as connection:
      assert (await connection.execute(text('SELECT step FROM migration_steps'))).all() == []
      assert (await connection.execute(select(app.database.MigrationsDbo.id))).all() == []
      assert (await connection.execute(select(app.database.DomainsDbo.id))).all() == []


async def test_lifespan_database_error_keeps_priority_when_http_cleanup_also_fails(app, monkeypatch, caplog):
  server = importlib.import_module('server.server')
  events = []
  database_failure = app.database.DatabaseShutdownError('synthetic database shutdown failure')
  http_failure = RuntimeError('synthetic private HTTP payload')

  async def setup():
    events.append('setup')

  async def close():
    events.append('database_close')
    raise database_failure

  async def http_close():
    events.append('http_close')
    raise http_failure

  with monkeypatch.context() as cleanup_patch:
    cleanup_patch.setattr(server, 'db', SimpleNamespace(setup=setup, close=close))
    cleanup_patch.setattr(
      server,
      'saving_coordinator',
      SimpleNamespace(start=AsyncMock(), stop=AsyncMock(), finish_close=AsyncMock()),
    )
    cleanup_patch.setattr(server.HttpClient, 'close', http_close)
    instance = server.AppServer()
    with pytest.raises(app.database.DatabaseShutdownError) as raised:
      async with instance.app.router.lifespan_context(instance.app):
        events.append('body')
  assert raised.value is database_failure
  assert events == ['setup', 'body', 'database_close', 'http_close']
  assert 'Additional application cleanup failed' in caplog.text
  assert 'synthetic private HTTP payload' not in caplog.text
  assert 'synthetic private HTTP payload' not in str(raised.value)


@pytest.mark.parametrize('state', ['stopping', 'writer_failed'])
@pytest.mark.parametrize(
  'path', ['/commands/domains/resolve/new', '/commands/domains/resolve/stale', '/domains/1/resolve']
)
async def test_saving_request_rejection_preserves_error_json(app, store, monkeypatch, state, path):
  """Real saving routes preserve stable error JSON for a stopping coordinator or failed writer.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # commands is the public command router module.
  # domains is the public domain router module.
  # coordinator is the real saving coordinator.
  # expected is the public failure message for the selected lifecycle state.
  # api is the actual routes under an in-process ASGI boundary.
  # transport is the in-process HTTP transport.
  # client is the bounded synthetic HTTP client.
  # response is the returned public error response.
  commands = importlib.import_module('routers.commands_router')
  domains = importlib.import_module('routers.domains_router')
  coordinator = app.resolver.saving_coordinator
  await coordinator.start()
  if state == 'stopping':
    await coordinator.stop()
    expected = 'Saving coordinator is stopping'
  else:
    monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
    await store.put_domain_after_resolve(
      app.dto.DomainResult(
        id=999,
        name='missing-parent.example.test',
        resolution_complete=True,
        last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC),
      )
    )
    await store.start_writer()
    await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
    assert store.writer_failure is not None
    expected = 'Saving coordinator stopped after database writer failure'
  api = FastAPI()
  api.include_router(commands.CommandsRouter().get_router())
  api.include_router(domains.DomainsRouter().get_router())
  transport = httpx.ASGITransport(app=api, raise_app_exceptions=False)
  async with httpx.AsyncClient(transport=transport, base_url='http://service.test', trust_env=False) as client:
    response = await client.post(path)
  assert response.status_code == 500
  assert response.headers['content-type'].startswith('application/json')
  assert response.json() == {'error': expected}
  assert str(app.settings.db_path) not in response.text
  assert store._DataBase__read_engine.pool.checkedout() == 0


async def configure_public_domain(service, *, resolved=True):
  """Create the domain and provider settings through the actual writer/API."""
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/dns', json=[{'server': service.dns_host}, {'doh_server': service.doh_url}])
    assert response.status_code == 200, response.text
    response = await client.post('/domains', json=[{'domain': 'www.example.test'}])
    assert response.status_code == 200, response.text
    async with asyncio.timeout(5):
      while True:
        domains = await client.get('/domains')
        dns_servers = await client.get('/dns', params={'default': 'false'})
        assert domains.status_code == dns_servers.status_code == 200
        records = [row for row in domains.json()['payload'] if row['name'] == 'www.example.test']
        configured = dns_servers.json()['payload']
        if records and len(configured) == 2:
          domain_id = records[0]['id']
          break
        await asyncio.sleep(0.02)
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(
      'UPDATE rdpr_domains SET resolved=?, last_resolved_at=? WHERE id=?',
      (int(resolved), '2000-01-01 00:00:00' if resolved else None, domain_id),
    )
    connection.executemany(
      'INSERT INTO rdpr_ip_records (domain_id, addr_type, ip_address, ros_comment, use_default_gw) '
      'VALUES (?, ?, ?, ?, ?)',
      [
        (domain_id, 4, '9.9.9.9', 'existing IPv4', 1),
        (domain_id, 6, '2001:4860:4860::8888', 'existing IPv6', 1),
      ],
    )
    connection.execute(
      'INSERT INTO rdpr_ip_supports (ip_record_id, domain_id, ip_list_id) '
      'SELECT id, domain_id, ip_list_id FROM rdpr_ip_records WHERE domain_id=?',
      (domain_id,),
    )
  return domain_id


def public_flow_snapshot(service, domain_id):
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    domain = connection.execute(
      'SELECT resolved, last_resolved_at FROM rdpr_domains WHERE id=?',
      (domain_id,),
    ).fetchone()
    rows = connection.execute(
      'SELECT id, addr_type, ip_address, ros_comment, use_default_gw, created_at, updated_at '
      'FROM rdpr_ip_records WHERE domain_id=? ORDER BY id',
      (domain_id,),
    ).fetchall()
  return domain, {row[2]: row for row in rows}


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('total', [1, 4])
async def test_public_large_progress_budget_preserves_completion_and_http_responsiveness(e2e_service, total):
  """Finish a small public NEW pass with a huge valid logging budget.

  e2e_service owns the real application subprocess, disposable SQLite, bounded
  requests and local DNS/DoH/RIPE providers. total selects one or a few domains;
  neither case may make the HTTP event loop traverse unused logging intervals.
  """
  # service starts only after its isolated environment contains the large valid budget.
  service = e2e_service
  service.environment['RESOLVE_DOMAINS_LOG_EVERY'] = '1000000000'
  service.environment['ROOT_LOG_LEVEL'] = 'info'
  await service.start()
  # names is the finite public selection; value supplies distinct synthetic domain names.
  names = [f'progress-{value}.example.test' for value in range(total)]
  # client bounds each public request so an event-loop stall cannot wedge the test runner.
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (
      await client.post('/dns', json=[{'server': service.dns_host}, {'doh_server': service.doh_url}])
    ).status_code == 200
    # name is one synthetic domain submitted through the real HTTP admission path.
    assert (await client.post('/domains', json=[{'domain': name} for name in names])).status_code == 200
    async with asyncio.timeout(5):
      while True:
        # rows contains committed NEW domains, excluding the seeded resolved default; dns_rows confirms DNS setup.
        rows = (await client.get('/domains', params={'resolved': 'false'})).json()['payload']
        dns_rows = (await client.get('/dns', params={'default': 'false'})).json()['payload']
        if {row['name'] for row in rows} == set(names) and len(dns_rows) == 2:  # row is one committed domain.
          break
        await asyncio.sleep(0.01)
    assert (await client.post('/commands/domains/resolve/new')).status_code == 200
    # samples retains the public metric samples; fields contains this NEW pass's settled counters.
    samples, fields = await completed_metrics(client, mode='new', selected=total)
    assert fields['selected'] == fields['attempted'] == fields['covered'] == total
    assert fields['success'] == fields['admitted'] == fields['confirmed'] == total
    assert fields['failure'] == fields['pending'] == fields['unknown'] == 0
    assert sample_total(samples, 'resolution_run_elapsed_seconds_count', mode='new') == 1
    assert (await client.get('/health')).status_code == 200
    # row identifies each selected domain whose IP result must be visible after real commit.
    for row in rows:
      # response is the public persisted result for this domain.
      response = await client.get(f'/domains/{row["id"]}')
      assert response.status_code == 200
      assert set(response.json()['ips_v4']) == {'8.8.8.8', '8.8.4.4'}
  await service.stop()
  # progress holds only intermediate INFO lines; line is one captured child-process log line.
  progress = [line for line in service.diagnostics().splitlines() if 'Resolution progress run_id=' in line]
  assert len(progress) <= total - 1
  assert bool(progress) is (total > 1)
  assert service.diagnostics().count('Resolution processing run_id=') == 1
  assert service.diagnostics().count('Resolution persistence run_id=') == 1


@pytest.mark.e2e
async def test_public_bulk_shared_addresses_keep_surviving_domain_and_durable_union(e2e_service):
  service = e2e_service
  names = ['first-shared.example.test', 'second-shared.example.test']
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (
      await client.post('/dns', json=[{'server': service.dns_host}, {'doh_server': service.doh_url}])
    ).status_code == 200
    assert (await client.post('/domains', json=[{'domain': name} for name in names])).status_code == 200
    async with asyncio.timeout(5):
      while True:
        rows = (await client.get('/domains')).json()['payload']
        ids = {row['name']: row['id'] for row in rows if row['name'] in names}
        dns_rows = (await client.get('/dns', params={'default': 'false'})).json()['payload']
        if len(ids) == 2 and len(dns_rows) == 2:
          break
        await asyncio.sleep(0.01)
    assert (await client.post('/commands/domains/resolve/new')).status_code == 200
    _, fields = await completed_metrics(client, mode='new', selected=2)
    assert fields['success'] == fields['admitted'] == fields['confirmed'] == 2
    for domain_id in ids.values():
      response = await client.get(f'/domains/{domain_id}')
      assert response.status_code == 200
      assert set(response.json()['ips_v4']) == {'8.8.8.8', '8.8.4.4'}
    with closing(sqlite3.connect(service.db_path)) as connection:
      original_ips = connection.execute('SELECT * FROM rdpr_ip_records ORDER BY id').fetchall()
      assert len(original_ips) == 2
      assert connection.execute('SELECT COUNT(*) FROM rdpr_ip_supports').fetchone() == (4,)
    assert (await client.delete(f'/domains/{ids[names[0]]}')).status_code == 200
    async with asyncio.timeout(5):
      while (await client.get(f'/domains/{ids[names[0]]}')).status_code != 404:
        await asyncio.sleep(0.01)
    response = await client.get(f'/domains/{ids[names[1]]}')
    assert response.status_code == 200
    assert set(response.json()['ips_v4']) == {'8.8.8.8', '8.8.4.4'}
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    surviving = connection.execute('SELECT * FROM rdpr_ip_records ORDER BY id').fetchall()
    assert [row[0] for row in surviving] == [row[0] for row in original_ips]
    assert [row[3:] for row in surviving] == [row[3:] for row in original_ips]
    assert connection.execute('SELECT domain_id,COUNT(*) FROM rdpr_ip_supports GROUP BY domain_id').fetchall() == [
      (ids[names[1]], 2)
    ]
  before = sqlite_snapshot(service.db_path)
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.get(f'/domains/{ids[names[1]]}')
    assert response.status_code == 200
    assert set(response.json()['ips_v4']) == {'8.8.8.8', '8.8.4.4'}
  await service.stop()
  assert sqlite_snapshot(service.db_path) == before


@pytest.mark.e2e
@pytest.mark.parametrize('kind', ['alias-chain-positive', 'cname-only', 'servfail', 'alias-cycle'])
async def test_public_a_alias_discovery_persists_only_reachable_aliases_without_granting_ip_deletion(e2e_service, kind):
  """Reachable aliases persist without permitting failed A evidence to replace IPs; all completed attempts confirm.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # service is the isolated real application and local providers.
  # domain_id is the stored source domain identity.
  # before is pre-operation checkpoint and IP metadata.
  # aliases is the reachable names authorized by the wire scenario.
  # client is the bounded real HTTP client.
  # checked is the public no-save diagnostic response.
  # row is one public result or provider request row.
  # listed is the committed domain catalogue before saving.
  # _ is unused elapsed-metric samples.
  # fields is the stored run processing and persistence counters.
  # after is durable checkpoint and IP metadata after shutdown.
  # connection is the disposable database connection checking alias membership.
  # names is the final domain catalogue.
  # name is one expected source or alias name.
  # transport is the classic or DoH provider kind.
  # record_type is one captured DNS record type.
  # source is one provider request transport.
  service = e2e_service
  domain_id = await configure_public_domain(service)
  before = public_flow_snapshot(service, domain_id)
  service.providers.classic = service.providers.doh = kind
  service.providers.cname_kinds = dict.fromkeys(
    ('classic', 'doh'), 'alias-cycle' if kind == 'alias-cycle' else 'cname-only'
  )
  aliases = (
    ['edge.example.test', 'terminal.example.test']
    if kind == 'alias-chain-positive'
    else ['edge.example.test']
    if kind in {'cname-only', 'servfail'}
    else []
  )
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    checked = await client.post('/domains/resolve/check', json={'domain': 'www.example.test'})
    assert checked.status_code == 200
    assert [row['cnames'] for row in checked.json()['results']] == [aliases, aliases]
    assert public_flow_snapshot(service, domain_id) == before
    listed = (await client.get('/domains')).json()['payload']
    assert {row['name'] for row in listed} == {'default', 'www.example.test'}
    service.providers.requests.clear()
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    _, fields = await completed_metrics(client, mode='stored', selected=1)
    assert fields['success' if kind == 'alias-chain-positive' else 'failure'] == 1
    assert fields['confirmed'] == 1
  await service.stop()
  after = public_flow_snapshot(service, domain_id)
  if kind == 'alias-chain-positive':
    assert after[0][1] != before[0][1]
    assert set(after[1]) == {'8.8.8.8', '8.8.4.4', '2001:4860:4860::8888'}
    assert after[1]['2001:4860:4860::8888'] == before[1]['2001:4860:4860::8888']
  else:
    assert after == before
  with closing(sqlite3.connect(service.db_path)) as connection:
    names = connection.execute('SELECT name FROM rdpr_domains ORDER BY name').fetchall()
  assert names == sorted((name,) for name in ['default', 'www.example.test', *aliases])
  for transport in ('classic', 'doh'):
    assert [record_type for source, _, record_type in service.providers.requests if source == transport] == (
      [dns.rdatatype.A, dns.rdatatype.CNAME] if kind in {'servfail', 'alias-cycle'} else [dns.rdatatype.A]
    )


@pytest.mark.e2e
@pytest.mark.parametrize(
  ('classic', 'doh', 'complete', 'addresses'),
  [
    ('positive', 'positive', True, {'8.8.8.8', '8.8.4.4'}),
    ('nxdomain', 'nodata', True, set()),
    ('nodata', 'nxdomain', True, set()),
    ('positive', 'servfail', False, {'8.8.8.8'}),
    ('servfail', 'positive', False, {'8.8.4.4'}),
    ('positive', 'nodata', False, {'8.8.8.8'}),
    ('nxdomain', 'positive', False, {'8.8.4.4'}),
    ('servfail', 'empty', False, set()),
  ],
)
async def test_public_resolution_reconciles_only_complete_trustworthy_ipv4(
  e2e_service,
  classic,
  doh,
  complete,
  addresses,
):
  """Preserve checkpoint/IP evidence and postpone incomplete attempts until their interval expires.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # service is the isolated real application and providers.
  # domain_id is the stored source domain identity.
  # before_domain is pre-operation successful checkpoint fields.
  # before_ips is pre-operation IP identities and metadata.
  # connection is the disposable fixture connection.
  # row is one database or API result.
  # history is completed migration metadata.
  # migrations is migration source paths in the selected app snapshot.
  # path is one migration source path.
  # client is the bounded real HTTP client.
  # response is one public response.
  # payload is the diagnostic JSON object.
  # by_transport is diagnostic results keyed by classic or DoH.
  # transport is one selected provider protocol.
  # kind is the provider evidence scenario.
  # server is the expected configured provider address.
  # expected is the expected diagnostic IPv4 values.
  # domain is post-operation successful-checkpoint fields.
  # ips is post-operation IP identity and metadata map.
  # address is one original IP address whose metadata must survive.
  # record_type is one required DNS record type.
  service = e2e_service
  service.providers.classic, service.providers.doh = classic, doh
  domain_id = await configure_public_domain(service)
  before_domain, before_ips = public_flow_snapshot(service, domain_id)
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    assert 'use_default_gw' in {row[1] for row in connection.execute('PRAGMA table_info(rdpr_ip_records)')}
    history = connection.execute('SELECT name, checksum, applied_at FROM rdpr_migrations ORDER BY name').fetchall()
  migrations = sorted((service.root / 'migrations').glob('migration_*.py'))
  assert [(row[0], row[1]) for row in history] == [
    (path.name, sha256(path.read_text(encoding='utf-8').encode()).hexdigest()) for path in migrations
  ]
  assert all(row[2] is not None for row in history)

  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/domains/resolve/check', json={'domain': 'www.example.test.'})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == {'domain', 'results'}
    assert payload['domain'] == 'www.example.test'
    by_transport = {row['server_type']: row for row in payload['results']}
    assert set(by_transport) == {'classic', 'doh'}
    for transport, kind, server, expected in [
      ('classic', classic, service.dns_host, ['8.8.8.8']),
      ('doh', doh, service.doh_url, ['8.8.4.4']),
    ]:
      assert by_transport[transport] == {
        'server': server,
        'server_type': transport,
        'ips_v4': expected if kind == 'positive' else [],
        'ips_v6': [],
        'cnames': [],
      }
    assert public_flow_snapshot(service, domain_id) == (before_domain, before_ips)
    service.providers.requests.clear()
    response = await client.post(f'/domains/{domain_id}/resolve')
    assert response.status_code == 202, response.text
    assert response.json()['result'] == 'Domain resolving accepted'
  # Uvicorn awaits the real background task; lifespan then drains the writer.
  await service.stop()
  domain, ips = public_flow_snapshot(service, domain_id)
  assert ips['2001:4860:4860::8888'] == before_ips['2001:4860:4860::8888']
  if complete:
    assert domain[0] == 1
    assert domain[1] != before_domain[1]
    assert datetime.fromisoformat(domain[1]).replace(tzinfo=UTC) > STALE_CHECKPOINT.replace(tzinfo=UTC)
    assert set(ips) == {'2001:4860:4860::8888'} | addresses
  else:
    assert domain == before_domain
    assert {address: ips[address] for address in before_ips} == before_ips
    assert set(ips) == set(before_ips) | addresses
  assert {(row[0], row[2]) for row in service.providers.requests} == {
    (transport, record_type)
    for transport, kind in [('classic', classic), ('doh', doh)]
    for record_type in (
      (dns.rdatatype.A,) if kind in {'positive', 'nodata', 'nxdomain'} else (dns.rdatatype.A, dns.rdatatype.CNAME)
    )
  }

  if not complete:
    # A fresh attempt postpones the public stale pass despite an old successful checkpoint.
    service.providers.classic = service.providers.doh = 'positive'
    service.providers.requests.clear()
    await service.start()
    async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
      response = await client.post('/commands/domains/resolve/stale')
      assert response.status_code == 200, response.text
    await service.stop()
    assert service.providers.requests == []
    assert public_flow_snapshot(service, domain_id)[0] == before_domain
    # Expire only the attempt; the next real automatic pass must now recover.
    with closing(sqlite3.connect(service.db_path)) as connection, connection:
      connection.execute('UPDATE rdpr_domains SET last_attempt_at=? WHERE id=?', ('2000-01-01 00:00:00', domain_id))
    await service.start()
    async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
      response = await client.post('/commands/domains/resolve/stale')
      assert response.status_code == 200, response.text
      async with asyncio.timeout(5):
        while public_flow_snapshot(service, domain_id)[0][1] == before_domain[1]:
          await asyncio.sleep(0.02)
      response = await client.get(f'/domains/{domain_id}')
      assert response.status_code == 200, response.text
      assert set(response.json()['ips_v4']) == {'8.8.8.8', '8.8.4.4'}
      assert response.json()['ips_v6'] == ['2001:4860:4860::8888']
    await service.stop()
    assert set(public_flow_snapshot(service, domain_id)[1]) == {
      '8.8.8.8',
      '8.8.4.4',
      '2001:4860:4860::8888',
    }


@pytest.mark.e2e
async def test_failed_new_domain_waits_interval_but_manual_resolution_bypasses_it(e2e_service):
  """Persist failed NEW attempts across restart, preserve diagnostic no-save and allow manual recovery.

  e2e_service owns the actual app, migrations, writer, temporary SQLite and local
  DNS/DoH providers. All resolution and read assertions cross public HTTP boundaries.
  """
  # service controls local providers; domain_id identifies the unresolved stored domain.
  service = e2e_service
  service.providers.classic = 'servfail'
  service.providers.doh = 'empty'
  domain_id = await configure_public_domain(service, resolved=False)
  # before contains successful checkpoint and IP evidence that a failure cannot replace.
  before = public_flow_snapshot(service, domain_id)
  # client bounds real API requests; response is each public acknowledgement or date payload.
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.get(f'/domains/{domain_id}')
    assert response.json()['last_attempt_at'] is response.json()['last_attempt_at_hum'] is None
    assert (await client.post('/domains/resolve/check', json={'domain': 'www.example.test'})).status_code == 200
    assert (await client.get(f'/domains/{domain_id}')).json()['last_attempt_at'] is None
    service.providers.requests.clear()
    response = await client.post('/commands/domains/resolve/new')
    assert response.status_code == 200, response.text
    # fields confirms failed processing and the marker's real commit; _ discards unused metric samples.
    _, fields = await completed_metrics(client, mode='new', selected=1)
    assert fields['failure'] == fields['admitted'] == fields['confirmed'] == 1
    # failed stores the public nullable date pair after this terminal failure.
    failed = (await client.get(f'/domains/{domain_id}')).json()
    assert isinstance(failed['last_attempt_at'], (int, float))
    assert (
      datetime.fromisoformat(failed['last_attempt_at_hum']).strftime('%Y-%m-%d %H:%M:%S')
      == failed['last_attempt_at_hum']
    )
  await service.stop()
  assert public_flow_snapshot(service, domain_id) == before
  # row is one captured local-provider request, including protocol and DNS record type.
  assert {(row[0], row[2]) for row in service.providers.requests} == {
    ('classic', dns.rdatatype.A),
    ('classic', dns.rdatatype.CNAME),
    ('doh', dns.rdatatype.A),
    ('doh', dns.rdatatype.CNAME),
  }
  service.providers.classic = service.providers.doh = 'positive'
  service.providers.requests.clear()
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.get(f'/domains/{domain_id}')).json()['last_attempt_at'] == failed['last_attempt_at']
    response = await client.post('/commands/domains/resolve/new')
    assert response.status_code == 200, response.text
    assert (await client.post('/commands/domains/resolve/stale')).status_code == 200
  await service.stop()
  assert service.providers.requests == []
  assert public_flow_snapshot(service, domain_id) == before
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    # _ again discards unused samples; fields now describes manual recovery rather than NEW.
    _, fields = await completed_metrics(client, mode='stored', selected=1)
    assert fields['success'] == fields['confirmed'] == 1
  await service.stop()
  # domain and ips are durable state after manual bypass and real lifespan drain.
  domain, ips = public_flow_snapshot(service, domain_id)
  assert domain[0] == 1
  assert set(ips) == {'8.8.8.8', '8.8.4.4', '2001:4860:4860::8888'}
  assert ips['2001:4860:4860::8888'] == before[1]['2001:4860:4860::8888']


@pytest.mark.e2e
async def test_public_queue_tail_is_persisted_by_real_lifespan_shutdown(e2e_service):
  service = e2e_service
  await service.stop()
  service.environment['DB_SAVE_BATCH_TIMEOUT'] = '3600'
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/domains', json=[{'domain': 'tail.example.test'}])
    assert response.status_code == 200, response.text
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    assert connection.execute('SELECT name FROM rdpr_domains WHERE name=?', ('tail.example.test',)).fetchall() == []
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    assert connection.execute('SELECT name FROM rdpr_domains WHERE name=?', ('tail.example.test',)).fetchall() == [
      ('tail.example.test',),
    ]


@pytest.mark.e2e
async def test_public_new_acceptance_precedes_next_stale_worker(e2e_service):
  """Exercise HTTP acceptance, real coordinator priority and durable writer effects together."""
  service = e2e_service
  first_id = await configure_public_domain(service)
  names = ['www.example.test', 'stale-second.example.test', 'stale-third.example.test']
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post('/domains', json=[{'domain': name} for name in names[1:]])).status_code == 200
    async with asyncio.timeout(5):
      while True:
        records = (await client.get('/domains')).json()['payload']
        ids = [record['id'] for record in records if record['name'] in names]
        if len(ids) == 3:
          break
        await asyncio.sleep(0.01)
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.executemany(
      "UPDATE rdpr_domains SET resolved=1,last_resolved_at='2000-01-01 00:00:00' WHERE id=?",
      [(value,) for value in ids],
    )
  service.environment['DOMAINS_RESOLVE_WORKER_LIMIT'] = '1'
  service.providers.hold_dns_names.add('www.example.test')
  entered = service.providers.dns_entered_by_name['www.example.test'] = asyncio.Event()
  release = service.providers.dns_release_by_name['www.example.test'] = asyncio.Event()
  service.providers.requests.clear()
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post('/commands/domains/resolve/stale')).status_code == 200
    await asyncio.wait_for(entered.wait(), timeout=3)
    repeated = await client.post('/commands/domains/resolve/stale')
    assert repeated.status_code == 200
    assert 'active' in repeated.json()['result']
    assert (await client.post('/domains', json=[{'domain': 'new-priority.example.test'}])).status_code == 200
    async with asyncio.timeout(3):
      while True:
        records = (await client.get('/domains')).json()['payload']
        fresh = [record for record in records if record['name'] == 'new-priority.example.test']
        if fresh:
          break
        await asyncio.sleep(0.01)
    assert (await client.post('/commands/domains/resolve/new')).status_code == 200
    assert {name for _, name, _ in service.providers.requests} == {'www.example.test.'}
    release.set()
    async with asyncio.timeout(5):
      while True:
        records = (await client.get('/domains')).json()['payload']
        completed = [record for record in records if record['id'] in [*ids, fresh[0]['id']]]
        if len(completed) == 4 and all(
          record['last_resolved_at'] and record['last_resolved_at'] != '2000-01-01 00:00:00' for record in completed
        ):
          break
        await asyncio.sleep(0.01)
  await service.stop()
  query_order = list(
    dict.fromkeys(name.rstrip('.') for _, name, rdtype in service.providers.requests if rdtype == dns.rdatatype.A)
  )
  assert query_order == ['www.example.test', 'new-priority.example.test', *names[1:]]
  assert first_id in ids
  with closing(sqlite3.connect(service.db_path)) as connection:
    supports = connection.execute(
      'SELECT ip.ip_address,s.domain_id FROM rdpr_ip_supports AS s '
      'JOIN rdpr_ip_records AS ip ON ip.id=s.ip_record_id WHERE ip.addr_type=4'
    ).fetchall()
    assert set(supports) == {(address, value) for value in [*ids, fresh[0]['id']] for address in ('8.8.8.8', '8.8.4.4')}
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []


@pytest.mark.e2e
async def test_public_repeated_saved_id_requests_are_distinct_fresh_operations(e2e_service):
  service = e2e_service
  domain_id = await configure_public_domain(service)
  service.providers.hold_dns_names.add('www.example.test')
  entered = service.providers.dns_entered_by_name['www.example.test'] = asyncio.Event()
  release = service.providers.dns_release_by_name['www.example.test'] = asyncio.Event()
  service.providers.requests.clear()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    before = parse_samples((await client.get('/metrics')).text)
    first = await client.post(f'/domains/{domain_id}/resolve')
    assert first.status_code == 202
    await asyncio.wait_for(entered.wait(), timeout=3)
    for _ in range(2):
      response = await client.post(f'/domains/{domain_id}/resolve')
      assert response.status_code == 202
      assert response.json()['result'] == 'Domain resolving accepted'
    assert sum(kind == dns.rdatatype.A and transport == 'doh' for transport, _, kind in service.providers.requests) == 1
    service.providers.classic_addresses = ('1.1.1.1',)
    service.providers.doh_addresses = ('1.0.0.1',)
    service.providers.hold_dns_names.clear()
    release.set()
    async with asyncio.timeout(5):
      while True:
        samples = parse_samples((await client.get('/metrics')).text)
        if (
          sample_total(samples, 'resolution_run_elapsed_seconds_count', mode='stored')
          - sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stored')
          == 3
          and sample_total(samples, 'resolution_run_events_total', event='confirmed', mode='stored')
          - sample_total(before, 'resolution_run_events_total', event='confirmed', mode='stored')
          == 3
        ):
          break
        await asyncio.sleep(0.01)
  await service.stop()
  for transport in ('classic', 'doh'):
    assert (
      sum(
        source == transport and name == 'www.example.test.' and kind == dns.rdatatype.A
        for source, name, kind in service.providers.requests
      )
      == 3
    )
  domain, ips = public_flow_snapshot(service, domain_id)
  assert domain[0] == 1
  assert set(ips) == {'1.1.1.1', '1.0.0.1', '2001:4860:4860::8888'}


@pytest.mark.e2e
async def test_public_shutdown_cancels_unadmitted_dns_before_database_close(e2e_service):
  service = e2e_service
  domain_id = await configure_public_domain(service)
  before = public_flow_snapshot(service, domain_id)
  service.providers.hold_dns_names.add('www.example.test')
  entered = service.providers.dns_entered_by_name['www.example.test'] = asyncio.Event()
  release = service.providers.dns_release_by_name['www.example.test'] = asyncio.Event()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    await asyncio.wait_for(entered.wait(), timeout=3)
  try:
    await asyncio.wait_for(service.stop(), timeout=3)
    assert public_flow_snapshot(service, domain_id) == before
  finally:
    service.providers.hold_dns_names.clear()
    release.set()
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    async with asyncio.timeout(5):
      while public_flow_snapshot(service, domain_id)[0][1] == before[0][1]:
        await asyncio.sleep(0.01)
  await service.stop()
  assert set(public_flow_snapshot(service, domain_id)[1]) == {'8.8.8.8', '8.8.4.4', '2001:4860:4860::8888'}


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('prefix', ['rdpr_', ''])
async def test_public_empty_startup_and_restart_preserve_schema_defaults_and_history(e2e_service, prefix):
  service = e2e_service
  service.environment['DB_TABLE_PREFIX'] = prefix
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute('SELECT name FROM sqlite_master').fetchall() == []
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.get('/health')).status_code == 200
    dns_servers = await client.get('/dns')
    assert dns_servers.status_code == 200
    assert [(row['id'], row['server']) for row in dns_servers.json()['payload']] == [(0, '1.1.1.1')]
    response = await client.post('/domains', json=[{'domain': 'persisted.example.test'}])
    assert response.status_code == 200, response.text
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    columns = [
      row for row in connection.execute(f'PRAGMA table_info({prefix}ip_records)') if row[1] == 'use_default_gw'
    ]
    assert [row[2:] for row in columns] == [('BOOLEAN', 1, '0', 0)]
    history_query, domain_query = {
      'rdpr_': (
        'SELECT name, checksum, applied_at FROM rdpr_migrations ORDER BY name',
        'SELECT name FROM rdpr_domains ORDER BY id',
      ),
      '': ('SELECT name, checksum, applied_at FROM migrations ORDER BY name', 'SELECT name FROM domains ORDER BY id'),
    }[prefix]
    history = connection.execute(history_query).fetchall()
    assert [(row[0], row[1]) for row in history] == [
      (path.name, sha256(path.read_text(encoding='utf-8').encode()).hexdigest())
      for path in sorted((service.root / 'migrations').glob('migration_*.py'))
    ]
    assert all(row[2] is not None for row in history)
    assert connection.execute(domain_query).fetchall() == [
      ('default',),
      ('persisted.example.test',),
    ]
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    supports_query = {'rdpr_': 'SELECT * FROM rdpr_ip_supports', '': 'SELECT * FROM ip_supports'}[prefix]
    assert connection.execute(supports_query).fetchall() == []
    assert {(row[3], row[6]) for row in connection.execute(f'PRAGMA foreign_key_list({prefix}ip_records)')} == {
      ('domain_id', 'SET NULL'),
      ('ip_list_id', 'SET NULL'),
    }
  before = sqlite_snapshot(service.db_path)
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    domains = await client.get('/domains')
    assert domains.status_code == 200
    assert 'persisted.example.test' in {row['name'] for row in domains.json()['payload']}
  await service.stop()
  assert sqlite_snapshot(service.db_path) == before
  assert service.providers.requests == []


IP_REFERENCE_REPAIR_MIGRATION = 'migration_202618042122_repair_ip_references.py'
IP_OWNERSHIP_MIGRATION = 'migration_202618042123.py'
CHECKSUM_REFRESH_MIGRATION = 'migration_202618042124.py'
IP_SUPPORT_LOOKUP_INDEX = 'ix__rdpr_ip_supports__ip_record_id_ip_list_id_domain_id'


def replace_with_previous_ip_schema(connection, prefix, unique_form):
  connection.execute(f'DROP TABLE {prefix}ip_supports')
  connection.execute(f'DROP TABLE {prefix}ip_records')
  unique = ' UNIQUE' if unique_form == 'inline' else ''
  connection.execute(f"""
    CREATE TABLE {prefix}ip_records (
      id INTEGER NOT NULL PRIMARY KEY, ip_list_id INTEGER, domain_id INTEGER NOT NULL,
      addr_type INTEGER NOT NULL, ip_address TEXT NOT NULL{unique}, ros_comment TEXT,
      use_default_gw BOOLEAN DEFAULT 0 NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
      updated_at TIMESTAMP, CHECK (ip_address != ''),
      FOREIGN KEY (domain_id) REFERENCES {prefix}domains(id) ON DELETE CASCADE,
      FOREIGN KEY (ip_list_id) REFERENCES {prefix}ips_lists(id) ON DELETE CASCADE
    )
  """)
  for column in ('domain_id', 'ip_list_id', 'ip_address'):
    if column == 'ip_address' and unique_form == 'inline':
      continue
    index_unique = 'UNIQUE ' if column == 'ip_address' and unique_form == 'index' else ''
    connection.execute(f'CREATE {index_unique}INDEX ix_{prefix}ip_records_{column} ON {prefix}ip_records ({column})')


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('prefix', ['rdpr_', ''])
@pytest.mark.parametrize('unique_form', ['inline', 'index'])
async def test_public_current_schema_upgrade_backfills_source_and_preserves_rows_and_history(
  e2e_service, prefix, unique_form
):
  """Represent the previous supported owner schema, including its two UNIQUE forms."""
  service = e2e_service
  service.environment['DB_TABLE_PREFIX'] = prefix
  queries = {
    'rdpr_': (
      'DELETE FROM rdpr_migrations WHERE name IN (?,?)',
      'SELECT * FROM rdpr_migrations ORDER BY id',
      'INSERT INTO rdpr_ip_records VALUES (17,NULL,0,4,?,?,?,?,?)',
      'SELECT * FROM rdpr_ip_records',
      'SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports',
    ),
    '': (
      'DELETE FROM migrations WHERE name IN (?,?)',
      'SELECT * FROM migrations ORDER BY id',
      'INSERT INTO ip_records VALUES (17,NULL,0,4,?,?,?,?,?)',
      'SELECT * FROM ip_records',
      'SELECT ip_record_id,domain_id,ip_list_id FROM ip_supports',
    ),
  }[prefix]
  pending = (IP_REFERENCE_REPAIR_MIGRATION, IP_OWNERSHIP_MIGRATION)
  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(queries[0], pending)
    old_history = connection.execute(queries[1]).fetchall()
    replace_with_previous_ip_schema(connection, prefix, unique_form)
    connection.execute(
      queries[2],
      ('8.8.8.0/24', 'preserved legacy metadata', 1, '2001-02-03 04:05:06', '2002-03-04 05:06:07'),
    )
    before_ip = connection.execute(queries[3]).fetchall()
  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute(queries[3]).fetchall() == before_ip
    history = connection.execute(queries[1]).fetchall()
    assert history[: len(old_history)] == old_history
    assert tuple(row[1] for row in history[len(old_history) :]) == pending
    assert connection.execute(queries[4]).fetchall() == [(17, 0, None)]
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
  upgraded = sqlite_snapshot(service.db_path)
  await service.start()
  await service.stop()
  assert sqlite_snapshot(service.db_path) == upgraded


async def seed_previous_ip_volume(service, *, keep_default):
  """Create previous-release IP ownership with both missing and valid foreign-key targets.

  service owns disposable SQLite and actual startup; keep_default determines whether
  the old standalone domain already exists. Domain fixtures explicitly name legacy
  fields so a new nullable column does not change this historical data contract.
  """
  await service.start()
  await service.stop()
  # created and updated preserve deliberately distinct historical row dates.
  created = '2001-02-03 04:05:06'
  updated = '2002-03-04 05:06:07'
  # connection prepares the stopped fixture; objects records its pre-upgrade schema inventory.
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    objects = connection.execute('SELECT type,name FROM sqlite_master ORDER BY type,name').fetchall()
    connection.execute(
      'DELETE FROM rdpr_migrations WHERE name IN (?,?,?)',
      (IP_REFERENCE_REPAIR_MIGRATION, IP_OWNERSHIP_MIGRATION, CHECKSUM_REFRESH_MIGRATION),
    )
    replace_with_previous_ip_schema(connection, 'rdpr_', 'index')
    if keep_default:
      connection.execute(
        "UPDATE rdpr_domains SET ros_comment='existing standalone domain',updated_at=? WHERE id=0",
        (updated,),
      )
    else:
      connection.execute('DELETE FROM rdpr_domains WHERE id=0')
    connection.execute("""
      INSERT INTO rdpr_domains_lists (id,name,url,description,hash,attempts)
      VALUES (5,'domain list','https://provider.example.test/domains','domain list metadata','domain hash',2)
    """)
    connection.execute("""
      INSERT INTO rdpr_ips_lists (id,name,url,description,hash,attempts)
      VALUES (6,'IP list','https://provider.example.test/ips','IP list metadata','IP hash',3)
    """)
    connection.executemany(
      'INSERT INTO rdpr_domains '
      '(id,domain_list_id,resolved,name,ros_comment,created_at,updated_at,last_resolved_at) VALUES (?,?,?,?,?,?,?,?)',
      [
        (-1, None, 1, 'existing-negative.example.test', 'valid negative ID', created, updated, updated),
        (7, 5, 1, 'listed.example.test', 'valid list', created, updated, updated),
        (8, 50, 0, 'missing-list.example.test', 'missing list', created, updated, None),
      ],
    )
    connection.executemany(
      'INSERT INTO rdpr_ip_records VALUES (?,?,?,?,?,?,?,?,?)',
      [
        (17, 6, 71, 4, '192.0.2.0/24', 'valid IP list', 1, created, updated),
        (18, 60, 72, 6, '2001:db8::18', 'both targets missing', 0, created, None),
        (19, 61, -1, 4, '198.51.100.19', 'valid negative owner', 1, created, updated),
        (20, 6, 7, 4, '198.51.100.20', 'both targets valid', 0, created, updated),
        (21, None, 8, 4, '198.51.100.21', 'retained domain', 0, created, None),
        (22, None, 0, 4, '198.51.100.22', None, 0, created, updated),
      ],
    )
  return objects


def previous_ip_volume_rows(connection):
  return (
    connection.execute('SELECT * FROM rdpr_ip_records ORDER BY id').fetchall(),
    connection.execute('SELECT * FROM rdpr_domains ORDER BY id').fetchall(),
    connection.execute('SELECT * FROM rdpr_ips_lists ORDER BY id').fetchall(),
    connection.execute('SELECT * FROM rdpr_domains_lists ORDER BY id').fetchall(),
    connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall(),
  )


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('keep_default', [True, False], ids=['preserve-standalone-domain', 'seed-standalone-domain'])
async def test_public_previous_ip_volume_repairs_dangling_references_and_restarts(e2e_service, keep_default):
  service = e2e_service
  expected_objects = await seed_previous_ip_volume(service, keep_default=keep_default)
  with closing(sqlite3.connect(service.db_path)) as connection:
    before_ips, before_domains, before_ip_lists, before_domain_lists, before_history = previous_ip_volume_rows(
      connection
    )
    assert {(row[0], row[1], row[2]) for row in connection.execute('PRAGMA foreign_key_check')} == {
      ('rdpr_ip_records', 17, 'rdpr_domains'),
      ('rdpr_ip_records', 18, 'rdpr_domains'),
      ('rdpr_ip_records', 18, 'rdpr_ips_lists'),
      ('rdpr_ip_records', 19, 'rdpr_ips_lists'),
      ('rdpr_domains', 8, 'rdpr_domains_lists'),
    } | (set() if keep_default else {('rdpr_ip_records', 22, 'rdpr_domains')})

  async def assert_public_standalone_ips():
    async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
      assert (await client.get('/health')).status_code == 200
      response = await client.get('/domains/0')
      assert response.status_code == 200, response.text
      assert set(response.json()['ips_v4']) == {'192.0.2.0/24', '198.51.100.22'}
      assert response.json()['ips_v6'] == ['2001:db8::18']

  await service.start()
  await assert_public_standalone_ips()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    ips, domains, ip_lists, domain_lists, history = previous_ip_volume_rows(connection)
    expected_supports = [(17, 0, 6), (18, 0, None), (19, -1, None), (20, 7, 6), (21, 8, None), (22, 0, None)]
    assert ips == [
      (ip_id, ip_list_id, domain_id, *row[3:])
      for (ip_id, domain_id, ip_list_id), row in zip(expected_supports, before_ips, strict=True)
    ]
    assert (
      connection.execute(
        'SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports ORDER BY ip_record_id'
      ).fetchall()
      == expected_supports
    )
    assert [row for row in domains if keep_default or row[0] != 0] == [
      (row[0], None if row[0] == 8 else row[1], *row[2:]) for row in before_domains
    ]
    if not keep_default:
      standalone = next(row for row in domains if row[0] == 0)
      assert standalone[:5] == (0, None, 1, 'default', 'Default Domain')
      assert standalone[5] == standalone[7]
      assert standalone[5]
      assert standalone[6] is None
    assert ip_lists == before_ip_lists
    assert domain_lists == before_domain_lists
    assert history[: len(before_history)] == before_history
    added = history[len(before_history) :]
    assert [row[1] for row in added] == [
      IP_REFERENCE_REPAIR_MIGRATION,
      IP_OWNERSHIP_MIGRATION,
      CHECKSUM_REFRESH_MIGRATION,
    ]
    for _, name, checksum, created_at, applied_at in added:
      assert checksum == sha256((service.root / 'migrations' / name).read_text(encoding='utf-8').encode()).hexdigest()
      assert created_at is not None
      assert applied_at is not None
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    assert connection.execute('SELECT type,name FROM sqlite_master ORDER BY type,name').fetchall() == expected_objects
  upgraded = sqlite_snapshot(service.db_path)
  # A completed migration must be skipped even when importing its source would fail.
  (service.directory / 'migrations' / IP_REFERENCE_REPAIR_MIGRATION).write_text(
    'raise RuntimeError("completed reference repair was imported again")\n', encoding='utf-8'
  )
  await service.start()
  await assert_public_standalone_ips()
  await service.stop()
  assert sqlite_snapshot(service.db_path) == upgraded
  assert service.providers.requests == []
  assert service.providers.http_requests == []


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('failure', ['ip-trigger', 'domain-trigger', 'default-name-conflict', 'later-migration'])
async def test_public_previous_ip_volume_leaves_database_intact_on_failed_upgrade(e2e_service, failure):
  service = e2e_service
  await seed_previous_ip_volume(service, keep_default=False)
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    if failure == 'ip-trigger':
      connection.execute("""
        CREATE TRIGGER ip_domain_change AFTER UPDATE OF domain_id ON "RDPR_IP_RECORDS"
        BEGIN
          UPDATE rdpr_ip_records SET ros_comment='trigger changed metadata' WHERE id=NEW.id;
        END
      """)
      assert connection.execute("SELECT tbl_name FROM sqlite_master WHERE name='ip_domain_change'").fetchone() == (
        'RDPR_IP_RECORDS',
      )
    elif failure == 'domain-trigger':
      connection.execute("""
        CREATE TRIGGER domain_list_change AFTER UPDATE OF domain_list_id ON "RDPR_DOMAINS"
        BEGIN
          UPDATE rdpr_domains SET ros_comment='trigger changed metadata' WHERE id=NEW.id;
        END
      """)
      assert connection.execute("SELECT tbl_name FROM sqlite_master WHERE name='domain_list_change'").fetchone() == (
        'RDPR_DOMAINS',
      )
    elif failure == 'default-name-conflict':
      connection.execute("UPDATE rdpr_domains SET name='default' WHERE id=7")
  later = service.directory / 'migrations' / 'migration_999999999999.py'
  if failure == 'later-migration':
    later.write_text(
      '\n'.join(
        (
          'from sqlalchemy import text',
          'async def upgrade(conn):',
          '  query = text("SELECT domain_id,ip_list_id FROM rdpr_ip_supports WHERE ip_record_id=17")',
          '  refs = await conn.execute(query)',
          '  assert refs.one() == (0, 6)',
          '  query = text("SELECT name FROM rdpr_migrations WHERE name IN (:repair,:owner) ORDER BY id")',
          f'  stamps = await conn.execute(query, {{"repair": {IP_REFERENCE_REPAIR_MIGRATION!r},',
          f'                                      "owner": {IP_OWNERSHIP_MIGRATION!r}}})',
          f'  assert list(stamps.scalars()) == {[IP_REFERENCE_REPAIR_MIGRATION, IP_OWNERSHIP_MIGRATION]!r}',
          '  raise RuntimeError("synthetic failure after reference repair was stamped")',
          '',
        )
      ),
      encoding='utf-8',
    )

  before = sqlite_snapshot(service.db_path)
  with pytest.raises(AssertionError, match='Application exited before readiness'):
    await service.start()
  assert service.process is None
  assert sqlite_snapshot(service.db_path) == before
  diagnostic = {
    'ip-trigger': 'RuntimeError: Legacy IP upgrade cannot safely repair references with table triggers',
    'domain-trigger': 'RuntimeError: Legacy IP upgrade cannot safely repair references with table triggers',
    'default-name-conflict': 'UNIQUE constraint failed: rdpr_domains.name',
    'later-migration': 'RuntimeError: synthetic failure after reference repair was stamped',
  }[failure]
  assert diagnostic in service.diagnostics()
  if failure == 'later-migration':
    later.unlink()
    await service.start()
    async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
      assert (await client.get('/health')).status_code == 200
    await service.stop()
    with closing(sqlite3.connect(service.db_path)) as connection:
      assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
      assert connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)]


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_upgraded_ip_volume_records_reference_repair_without_data_changes(e2e_service):
  service = e2e_service
  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute('DELETE FROM rdpr_migrations WHERE name=?', (IP_REFERENCE_REPAIR_MIGRATION,))
    connection.execute(f'DROP INDEX {IP_SUPPORT_LOOKUP_INDEX}')
    connection.execute(
      'INSERT INTO rdpr_ip_records (id,domain_id,addr_type,ip_address,ros_comment,use_default_gw,updated_at) '
      "VALUES (17,0,4,'198.51.100.17','preserved metadata',1,'2002-03-04 05:06:07')"
    )
    connection.execute('INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (17,0)')
    before_history = connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall()

  def business_snapshot():
    return tuple(
      line
      for line in sqlite_snapshot(service.db_path)
      if not line.startswith(('INSERT INTO "rdpr_migrations"', f'CREATE INDEX {IP_SUPPORT_LOOKUP_INDEX} '))
    )

  before = business_snapshot()
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.get('/health')).status_code == 200
    response = await client.get('/domains/0')
    assert response.status_code == 200, response.text
    assert response.json()['ips_v4'] == ['198.51.100.17']
  await service.stop()
  assert business_snapshot() == before
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute(
      'SELECT name FROM pragma_index_info(?) ORDER BY seqno', (IP_SUPPORT_LOOKUP_INDEX,)
    ).fetchall() == [('ip_record_id',), ('ip_list_id',), ('domain_id',)]
    assert connection.execute(
      'SELECT "unique", partial FROM pragma_index_list(?) WHERE name=?',
      ('rdpr_ip_supports', IP_SUPPORT_LOOKUP_INDEX),
    ).fetchone() == (0, 0)
    history = connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall()
    assert history[:-1] == before_history
    _, name, checksum, created_at, applied_at = history[-1]
    assert name == IP_REFERENCE_REPAIR_MIGRATION
    assert checksum == sha256((service.root / 'migrations' / name).read_text(encoding='utf-8').encode()).hexdigest()
    assert created_at is not None
    assert applied_at is not None


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_upgraded_ip_volume_rejects_incompatible_support_lookup_index_atomically(e2e_service):
  service = e2e_service
  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute('DELETE FROM rdpr_migrations WHERE name=?', (IP_REFERENCE_REPAIR_MIGRATION,))
    connection.execute(f'DROP INDEX {IP_SUPPORT_LOOKUP_INDEX}')
    connection.execute(f'CREATE INDEX {IP_SUPPORT_LOOKUP_INDEX.upper()} ON rdpr_ip_supports (domain_id, ip_record_id)')
  before = sqlite_snapshot(service.db_path)

  with pytest.raises(AssertionError, match='Application exited before readiness'):
    await service.start()

  assert service.process is None
  assert 'RuntimeError: IP support lookup index is incompatible' in service.diagnostics()
  assert sqlite_snapshot(service.db_path) == before


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('prefix', ['rdpr_', ''])
async def test_public_checksum_refresh_preserves_history_and_data_across_failure_and_restart(e2e_service, prefix):
  service = e2e_service
  service.environment['DB_TABLE_PREFIX'] = prefix
  refresh_name = CHECKSUM_REFRESH_MIGRATION
  # These persisted checksums were independently verified against the previous release sources.
  old_checksums = {
    'migration_202511031501.py': '293ddda35db4553c0174d8ecb07902add5bb664a7137e0ce6f36a05899b83fa7',
    'migration_202602192245.py': '8a271a80e72ba229ca6deabd4e0458bb14170f77398585a7e8e27a8eb24be8e9',
    'migration_202618042122.py': '563a6f0d402a11b7e044b60ec29a64cf81f3216f00f3aacc5da2da82cf72e80c',
  }
  current_checksums = {
    name: sha256((service.root / 'migrations' / name).read_text(encoding='utf-8').encode()).hexdigest()
    for name in (*old_checksums, refresh_name)
  }
  history_query, delete_refresh, insert_history, set_old_checksum, domain_insert, ip_insert, support_insert = {
    'rdpr_': (
      'SELECT * FROM rdpr_migrations ORDER BY id',
      'DELETE FROM rdpr_migrations WHERE name=?',
      'INSERT INTO rdpr_migrations VALUES (?,?,?,?,?)',
      'UPDATE rdpr_migrations SET checksum=?,created_at=?,applied_at=? WHERE name=?',
      'INSERT INTO rdpr_domains (id,name,resolved,ros_comment,created_at,updated_at,last_resolved_at) '
      'VALUES (7,?,?,?,?,?,?)',
      'INSERT INTO rdpr_ip_records (id,domain_id,addr_type,ip_address,ros_comment,use_default_gw,created_at) '
      'VALUES (17,7,4,?,?,1,?)',
      'INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (17,7)',
    ),
    '': (
      'SELECT * FROM migrations ORDER BY id',
      'DELETE FROM migrations WHERE name=?',
      'INSERT INTO migrations VALUES (?,?,?,?,?)',
      'UPDATE migrations SET checksum=?,created_at=?,applied_at=? WHERE name=?',
      'INSERT INTO domains (id,name,resolved,ros_comment,created_at,updated_at,last_resolved_at) '
      'VALUES (7,?,?,?,?,?,?)',
      'INSERT INTO ip_records (id,domain_id,addr_type,ip_address,ros_comment,use_default_gw,created_at) '
      'VALUES (17,7,4,?,?,1,?)',
      'INSERT INTO ip_supports (ip_record_id,domain_id) VALUES (17,7)',
    ),
  }[prefix]

  def business_snapshot():
    return tuple(
      line for line in sqlite_snapshot(service.db_path) if not line.startswith(f'INSERT INTO "{prefix}migrations"')
    )

  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(delete_refresh, (refresh_name,))
    refreshed_ids = set()
    for index, (name, checksum) in enumerate(old_checksums.items()):
      created, applied = '2001-02-03 04:05:06', '2002-03-04 05:06:07'
      connection.execute(set_old_checksum, (checksum, created, applied, name))
      row_id = next(row[0] for row in connection.execute(history_query) if row[1] == name)
      refreshed_ids.update((row_id, 100 + index * 10))
      connection.executemany(
        insert_history,
        [
          (100 + index * 10, name, checksum, created, applied),
          (101 + index * 10, name, checksum, created, None),
          (102 + index * 10, name, 'unknown-source-checksum', created, applied),
          (103 + index * 10, name, current_checksums[name], created, applied),
        ],
      )
    connection.execute(
      insert_history,
      (200, 'retired-migration.py', next(iter(old_checksums.values())), created, applied),
    )
    connection.execute(
      domain_insert,
      ('preserved.example.test', 1, 'domain metadata', created, applied, applied),
    )
    connection.execute(
      ip_insert,
      ('8.8.8.8', 'IP metadata', created),
    )
    connection.execute(support_insert)
    old_history = connection.execute(history_query).fetchall()
  expected_history = [
    (*row[:2], current_checksums[row[1]], *row[3:]) if row[0] in refreshed_ids else row for row in old_history
  ]
  business_before = business_snapshot()
  # A completed migration must never be imported again, even when its source checksum differs.
  for name in old_checksums:
    source = service.directory / 'migrations' / name
    source.write_text(
      source.read_text(encoding='utf-8') + '\nraise RuntimeError("completed migration was replayed")\n',
      encoding='utf-8',
    )
  failure = service.directory / 'migrations' / 'migration_999999999999.py'
  failure.write_text(
    'from sqlalchemy import text\nasync def upgrade(conn):\n'
    '  await conn.execute(text("CREATE TABLE incomplete_refresh (value TEXT)"))\n'
    '  raise RuntimeError("synthetic failure after checksum refresh")\n',
    encoding='utf-8',
  )
  before_failure = sqlite_snapshot(service.db_path)
  with pytest.raises(AssertionError, match='Application exited before readiness'):
    await service.start()
  assert 'synthetic failure after checksum refresh' in service.diagnostics()
  assert service.process is None
  assert sqlite_snapshot(service.db_path) == before_failure
  failure.unlink()

  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.get('/domains/7')
    assert response.status_code == 200, response.text
    assert response.json()['ips_v4'] == ['8.8.8.8']
  await service.stop()
  assert business_snapshot() == business_before
  with closing(sqlite3.connect(service.db_path)) as connection:
    history = connection.execute(history_query).fetchall()
  assert [row for row in history if row[1] != refresh_name] == expected_history
  stamps = [row for row in history if row[1] == refresh_name]
  assert len(stamps) == 1
  assert stamps[0][2] == current_checksums[refresh_name]
  assert stamps[0][3] is not None
  assert stamps[0][4] is not None

  # Reapplying only the refresh must preserve already corrected and unrecognized history.
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(delete_refresh, (refresh_name,))
  await service.start()
  await service.stop()
  assert business_snapshot() == business_before
  with closing(sqlite3.connect(service.db_path)) as connection:
    history = connection.execute(history_query).fetchall()
  assert [row for row in history if row[1] != refresh_name] == expected_history
  assert len([row for row in history if row[1] == refresh_name]) == 1
  before_restart = sqlite_snapshot(service.db_path)
  await service.start()
  await service.stop()
  assert sqlite_snapshot(service.db_path) == before_restart
  assert service.providers.requests == []


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_historical_gateway_upgrade_preserves_old_data_and_all_history(e2e_service):
  """Preserve every legacy domain/IP value and history row while adding the inherited attempt date.

  e2e_service owns the real startup process and disposable historical database.
  The new attempt value must equal the known checkpoint without altering old dates.
  """
  # service owns startup/shutdown; connection prepares and verifies the disposable old schema.
  service = e2e_service
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.executescript("""
      CREATE TABLE rdpr_dns_servers (
        id INTEGER NOT NULL PRIMARY KEY, server TEXT UNIQUE, doh_server TEXT UNIQUE, description TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP
      );
      CREATE TABLE rdpr_domains (
        id INTEGER NOT NULL PRIMARY KEY, domain_list_id INTEGER, resolved BOOLEAN NOT NULL,
        name TEXT NOT NULL UNIQUE, ros_comment TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP, last_resolved_at TIMESTAMP,
        FOREIGN KEY (domain_list_id) REFERENCES rdpr_domains_lists(id) ON DELETE CASCADE
      );
      CREATE TABLE rdpr_ip_records (
        id INTEGER NOT NULL PRIMARY KEY, ip_list_id INTEGER, domain_id INTEGER NOT NULL,
        addr_type INTEGER NOT NULL, ip_address TEXT NOT NULL UNIQUE CHECK (ip_address != ''), ros_comment TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP,
        FOREIGN KEY (ip_list_id) REFERENCES rdpr_ips_lists(id) ON DELETE CASCADE,
        FOREIGN KEY (domain_id) REFERENCES rdpr_domains(id) ON DELETE CASCADE
      );
      INSERT INTO rdpr_dns_servers VALUES (0, '9.9.9.9', NULL, 'custom', '2001-02-03 04:05:06', NULL);
      INSERT INTO rdpr_domains VALUES (7, NULL, 1, 'historical.example.test', 'historical domain',
                                      '2001-02-03 04:05:06', '2002-03-04 05:06:07', '2002-03-04 05:06:07');
      INSERT INTO rdpr_ip_records VALUES (17, NULL, 7, 4, '8.8.8.8', 'historical IP', '2001-02-03 04:05:06', NULL);
    """)
    create_history(connection)
    connection.executemany(
      'INSERT INTO rdpr_migrations VALUES (?, ?, ?, ?, ?)',
      [
        (31, 'migration_202511031501.py', 'stored-original-checksum', '2001-02-03 04:05:06', '2001-02-04 04:05:06'),
        (32, 'migration_202618042122.py', 'failed-checksum-a', '2002-03-04 05:06:07', None),
        (33, 'migration_202618042122.py', 'failed-checksum-b', '2003-04-05 06:07:08', None),
        (34, 'retired-migration.py', 'unrelated-checksum', '2004-05-06 07:08:09', '2004-05-07 07:08:09'),
      ],
    )
    # old_history retains applied and failed rows; old_ip and old_domain retain exact legacy data.
    old_history = connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall()
    old_ip = connection.execute('SELECT * FROM rdpr_ip_records').fetchone()
    old_domain = connection.execute('SELECT * FROM rdpr_domains').fetchone()
  await service.start()
  # client and response verify that the real upgraded public API still exposes the existing address.
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.get('/domains/7')
    assert response.status_code == 200, response.text
    assert response.json()['ips_v4'] == ['8.8.8.8']
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute('SELECT * FROM rdpr_migrations WHERE id<=34 ORDER BY id').fetchall() == old_history
    assert (
      connection.execute(
        'SELECT id,domain_list_id,resolved,name,ros_comment,created_at,updated_at,last_resolved_at '
        'FROM rdpr_domains WHERE id=7'
      ).fetchone()
      == old_domain
    )
    assert connection.execute('SELECT last_attempt_at FROM rdpr_domains WHERE id=7').fetchone() == (
      '2002-03-04 05:06:07',
    )
    assert connection.execute('SELECT * FROM rdpr_ip_records WHERE id=17').fetchone() == (*old_ip, 0)
    assert connection.execute('SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports').fetchall() == [
      (17, 7, None)
    ]
    assert connection.execute('SELECT server, description FROM rdpr_dns_servers WHERE id=0').fetchone() == (
      '9.9.9.9',
      'custom',
    )
    assert connection.execute('SELECT name FROM rdpr_migrations WHERE id>34 ORDER BY id').fetchall() == [
      ('migration_202602192245.py',),
      ('migration_202618042122.py',),
      (IP_REFERENCE_REPAIR_MIGRATION,),
      (IP_OWNERSHIP_MIGRATION,),
      (CHECKSUM_REFRESH_MIGRATION,),
      ('migration_202618042125.py',),
    ]
  # before captures all upgraded schema, history and values for exact completed-restart preservation.
  before = sqlite_snapshot(service.db_path)
  await service.start()
  await service.stop()
  assert sqlite_snapshot(service.db_path) == before


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_legacy_import_failure_rolls_back_and_fresh_process_recovers(e2e_service):
  service = e2e_service
  create_legacy_database(service.db_path)
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    create_history(connection)
    connection.executemany(
      'INSERT INTO rdpr_migrations VALUES (?, ?, ?, ?, NULL)',
      [
        (41, 'migration_202511031501.py', 'old-failure-a', '2001-02-03 04:05:06'),
        (42, 'migration_202511031501.py', 'old-failure-b', '2002-03-04 05:06:07'),
      ],
    )
    old_history = connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall()
  failed_migration = service.directory / 'migrations' / 'migration_999999999999.py'
  failed_migration.write_text(
    'from sqlalchemy import text\n'
    'async def upgrade(conn):\n'
    '  await conn.execute(text("CREATE TABLE incomplete_startup (value TEXT)"))\n'
    '  await conn.execute(text("INSERT INTO incomplete_startup VALUES (\'uncommitted\')"))\n'
    '  raise RuntimeError("synthetic final migration failure")\n',
    encoding='utf-8',
  )
  before = sqlite_snapshot(service.db_path)
  for _ in range(2):
    with pytest.raises(AssertionError, match='Application exited before readiness'):
      await service.start()
    assert sqlite_snapshot(service.db_path) == before
    assert service.process is None
  failed_migration.unlink()
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.get('/domains/7')
    assert response.status_code == 200, response.text
    assert response.json()['ips_v6'] == ['2001:4860:4860::8888']
  await service.stop()
  assert_legacy_import(service.db_path)
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute('SELECT * FROM rdpr_migrations WHERE id<=42 ORDER BY id').fetchall() == old_history
    assert connection.execute('SELECT name FROM rdpr_migrations WHERE id>42 ORDER BY id').fetchall() == [
      (path.name,) for path in sorted((service.root / 'migrations').glob('migration_*.py'))
    ]
  recovered = sqlite_snapshot(service.db_path)
  await service.start()
  await service.stop()
  assert sqlite_snapshot(service.db_path) == recovered


@pytest.mark.parametrize('failure_kind', ['exception', 'cancellation', 'invalid_module'])
async def test_startup_failure_physically_rolls_back_schema_rows_and_history(
  app, startup_store, tmp_path, failure_kind
):
  store = startup_store
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection, connection:
    connection.execute('CREATE TABLE preserved (value TEXT NOT NULL)')
    connection.execute("INSERT INTO preserved VALUES ('original')")
  before = sqlite_snapshot(path)
  migration = tmp_path / 'migrations' / 'migration_000000000000.py'
  migration.write_text(
    'from sqlalchemy import text\n'
    'async def upgrade(conn):\n'
    '  await conn.execute(text("CREATE TABLE startup_probe (value TEXT)"))\n'
    '  await conn.execute(text("INSERT INTO startup_probe VALUES (\'uncommitted\')"))\n'
    '  await conn.execute(text("UPDATE preserved SET value=\'changed\'"))\n',
    encoding='utf-8',
  )
  failure = tmp_path / 'migrations' / 'migration_999999999999.py'
  failure.write_text(
    'invalid syntax !'
    if failure_kind == 'invalid_module'
    else 'from asyncio import CancelledError\n'
    'async def upgrade(conn):\n'
    + (
      '  raise CancelledError()\n' if failure_kind == 'cancellation' else '  raise RuntimeError("synthetic failure")\n'
    ),
    encoding='utf-8',
  )
  later_marker = tmp_path / 'later-migration-ran'
  (tmp_path / 'migrations' / 'migration_9999999999999.py').write_text(
    f'from pathlib import Path\nasync def upgrade(conn):\n  Path({str(later_marker)!r}).touch()\n',
    encoding='utf-8',
  )
  expected = asyncio.CancelledError if failure_kind == 'cancellation' else app.database.DatabaseWriteError
  with pytest.raises(expected):
    await asyncio.wait_for(store.setup(), timeout=5)
  assert store.writer_task is None
  assert store.writer_state == 'FAILED'
  assert store.pending_count == store.unknown_count == 0
  assert sqlite_snapshot(path) == before
  assert not later_marker.exists()


@pytest.mark.parametrize(
  'gateway_shape',
  [
    'use_default_gw INTEGER NOT NULL DEFAULT 0',
    'use_default_gw BOOLEAN DEFAULT 0',
    'use_default_gw BOOLEAN NOT NULL DEFAULT 1',
    'use_default_gw BOOLEAN NOT NULL',
  ],
)
async def test_startup_refuses_incompatible_existing_gateway_without_repair(
  app,
  startup_store,
  gateway_shape,
):
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection, connection:
    connection.execute(f'CREATE TABLE rdpr_ip_records (id INTEGER PRIMARY KEY, {gateway_shape})')
    connection.execute('INSERT INTO rdpr_ip_records VALUES (17, 1)')
  before = sqlite_snapshot(path)
  with pytest.raises(app.database.DatabaseWriteError, match='Database initialization failed'):
    await startup_store.setup()
  assert startup_store.writer_task is None
  assert sqlite_snapshot(path) == before


async def test_completed_startup_does_not_repeat_schema_index_fk_or_support_audits(app, startup_store, monkeypatch):
  """A normal restart trusts completed history while preserving connection constraints."""
  await startup_store.setup()
  await startup_store.close(timeout=2)
  path = Path(app.settings.db_path)
  before = sqlite_snapshot(path)
  fresh = app.database.DataBase()
  statements = []

  def submitted(conn, cursor, statement, parameters, context, executemany):
    statements.append(statement.lower())

  async def unexpected(*args, **kwargs):
    raise AssertionError('Ordinary startup must not execute a completed migration audit')

  for name in ('validate_support_state', 'ip_schema_kind'):
    monkeypatch.setattr(app.database, name, unexpected)
  monkeypatch.setattr(fresh, '_DataBase__gateway_effect', unexpected)
  monkeypatch.setattr(fresh, '_DataBase__check_startup_foreign_keys', unexpected)
  event.listen(fresh._DataBase__write_engine.sync_engine, 'before_cursor_execute', submitted)
  try:
    await fresh.setup()
    assert fresh.writer_state == 'RUNNING'
    async with fresh._DataBase__read_engine.connect() as connection:
      assert (await connection.execute(text('PRAGMA foreign_keys'))).scalar_one() == 1
    await fresh.close(timeout=2)
    assert sqlite_snapshot(path) == before
    assert not any('foreign_key_check' in sql or 'pragma_index_' in sql for sql in statements)
  finally:
    await fresh.close(timeout=2)
    await fresh._DataBase__read_engine.dispose()
    await fresh._DataBase__write_engine.dispose()


@pytest.mark.parametrize('missing_effect', ['support_table', 'owner_fk', 'support_row', 'unique_index'])
async def test_completed_support_history_is_not_a_startup_integrity_audit(app, startup_store, missing_effect):
  await startup_store.setup()
  await startup_store.close(timeout=2)
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection, connection:
    connection.execute("INSERT INTO rdpr_domains (id,name,resolved) VALUES (7,'existing.example.test',1)")
    connection.execute("INSERT INTO rdpr_ip_records (id,domain_id,addr_type,ip_address) VALUES (17,7,4,'8.8.8.8')")
    connection.execute('INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (17,7)')
    if missing_effect == 'support_table':
      connection.execute('DROP TABLE rdpr_ip_supports')
    elif missing_effect == 'support_row':
      connection.execute('DELETE FROM rdpr_ip_supports')
    elif missing_effect == 'unique_index':
      indexes = [row for row in connection.execute('PRAGMA index_list(rdpr_ip_supports)') if row[2] and row[4]]
      assert len(indexes) == 2
      index_name = indexes[0][1]
      assert index_name.replace('_', '').isalnum()
      connection.execute(f'DROP INDEX "{index_name}"')
    else:
      connection.execute('PRAGMA writable_schema=ON')
      ddl = connection.execute("SELECT sql FROM sqlite_master WHERE name='rdpr_ip_records'").fetchone()[0]
      assert 'SET NULL' in ddl
      connection.execute(
        "UPDATE sqlite_master SET sql=? WHERE name='rdpr_ip_records'",
        (ddl.replace('SET NULL', 'CASCADE'),),
      )
      connection.execute('PRAGMA writable_schema=OFF')
  before = sqlite_snapshot(path)
  fresh = app.database.DataBase()
  try:
    await fresh.setup()
    assert fresh.writer_state == 'RUNNING'
    await fresh.close(timeout=2)
    if missing_effect != 'support_table':
      assert sqlite_snapshot(path) == before
    else:
      with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT * FROM rdpr_ip_supports').fetchall() == []
        assert connection.execute('SELECT id,domain_id FROM rdpr_ip_records').fetchall() == [(17, 7)]
  finally:
    await fresh.close(timeout=2)
    await fresh._DataBase__read_engine.dispose()
    await fresh._DataBase__write_engine.dispose()


@pytest.mark.parametrize('corruption', ['foreign_key', 'unsupported_ip'])
async def test_late_new_migration_cannot_commit_invalid_final_state(app, startup_store, tmp_path, corruption):
  """Final checks cover effects introduced after the ownership migration already completed."""
  await startup_store.setup()
  await startup_store.close(timeout=2)
  path = Path(app.settings.db_path)
  before = sqlite_snapshot(path)
  migration = tmp_path / 'migrations' / 'migration_999999999999.py'
  mutation = (
    "INSERT INTO rdpr_domains (id,name,domain_list_id,resolved) VALUES (77,'invalid.example.test',999,0)"
    if corruption == 'foreign_key'
    else "INSERT INTO rdpr_ip_records (id,domain_id,addr_type,ip_address) VALUES (77,0,4,'8.8.8.8')"
  )
  migration.write_text(
    'from sqlalchemy import text\nasync def upgrade(conn):\n'
    '  await conn.execute(text("CREATE TABLE late_migration_probe (value TEXT)"))\n'
    f'  await conn.execute(text({mutation!r}))\n',
    encoding='utf-8',
  )
  fresh = app.database.DataBase()
  try:
    with pytest.raises(app.database.DatabaseWriteError, match='Database initialization failed'):
      await fresh.setup()
    assert fresh.writer_task is None
    assert fresh.writer_state == 'FAILED'
    assert sqlite_snapshot(path) == before
  finally:
    await fresh._DataBase__read_engine.dispose()
    await fresh._DataBase__write_engine.dispose()


async def test_support_schema_enforces_independent_context_uniqueness_and_cascade(app, startup_store):
  await startup_store.setup()
  await startup_store.close(timeout=2)
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection, connection:
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute("INSERT INTO rdpr_domains (id,name,resolved) VALUES (7,'support.example.test',0)")
    connection.execute(
      "INSERT INTO rdpr_ips_lists (id,name,url,attempts) VALUES (8,'source','https://lists.example.test/8',0)"
    )
    connection.execute("INSERT INTO rdpr_ip_records (id,domain_id,addr_type,ip_address) VALUES (17,7,4,'8.8.8.8')")
    connection.execute('INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (17,7)')
    connection.execute('INSERT INTO rdpr_ip_supports (ip_record_id,domain_id,ip_list_id) VALUES (17,7,8)')
    for query in (
      'INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (17,7)',
      'INSERT INTO rdpr_ip_supports (ip_record_id,domain_id,ip_list_id) VALUES (17,7,8)',
      'INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (17,999)',
    ):
      with pytest.raises(sqlite3.IntegrityError):
        connection.execute(query)
    ip_fks = connection.execute('PRAGMA foreign_key_list(rdpr_ip_records)').fetchall()
    assert {(row[3], row[6]) for row in ip_fks} == {('domain_id', 'SET NULL'), ('ip_list_id', 'SET NULL')}
    support_fks = connection.execute('PRAGMA foreign_key_list(rdpr_ip_supports)').fetchall()
    assert {(row[2], row[3], row[6]) for row in support_fks} == {
      ('rdpr_ip_records', 'ip_record_id', 'CASCADE'),
      ('rdpr_domains', 'domain_id', 'CASCADE'),
      ('rdpr_ips_lists', 'ip_list_id', 'CASCADE'),
    }
    connection.execute('DELETE FROM rdpr_ips_lists WHERE id=8')
    assert connection.execute('SELECT domain_id,ip_list_id FROM rdpr_ip_supports').fetchall() == [(7, None)]
    connection.execute('DELETE FROM rdpr_domains WHERE id=7')
    assert connection.execute('SELECT * FROM rdpr_ip_supports').fetchall() == []
    assert connection.execute('SELECT id,domain_id FROM rdpr_ip_records').fetchall() == [(17, None)]
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []


@pytest.mark.parametrize('migration_name', ['migration_202511031501.py', 'migration_202618042122.py'])
async def test_modified_known_migration_never_receives_checksum_compatibility_bypass(
  app,
  startup_store,
  tmp_path,
  migration_name,
):
  migration = tmp_path / 'migrations' / migration_name
  # Modified source cannot receive the pinned compatibility bypass or a success stamp.
  migration.write_text(
    migration.read_text(encoding='utf-8') + '\nraise RuntimeError("modified migration must not be stamped")\n',
    encoding='utf-8',
  )
  path = Path(app.settings.db_path)
  before = sqlite_snapshot(path)
  with pytest.raises(app.database.DatabaseWriteError):
    await startup_store.setup()
  assert sqlite_snapshot(path) == before


@pytest.mark.parametrize(
  'contradiction',
  [
    'incomplete',
    'extra_column',
    'domain_list_orphan',
    'domain_orphan',
    'remapped_parent_orphan',
    'ip_list_orphan',
    'dns_default_collision',
    'domain_default_collision',
    'default_domain_list',
    'populated_target',
    'incompatible_empty_target',
    'copy_changing_trigger',
    'duplicate_source_value',
  ],
)
async def test_legacy_contradictions_fail_without_source_or_history_changes(
  app,
  startup_store,
  contradiction,
):
  path = Path(app.settings.db_path)
  create_legacy_database(path)
  if contradiction in {'populated_target', 'copy_changing_trigger'}:
    async with startup_store._DataBase__write_engine.begin() as connection:
      await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
  with closing(sqlite3.connect(path)) as connection, connection:
    statements = {
      'incomplete': 'DROP TABLE jobs',
      'extra_column': 'ALTER TABLE domains ADD COLUMN unknown_business_data TEXT',
      'domain_list_orphan': 'UPDATE domains SET domain_list_id=99 WHERE id=7',
      'domain_orphan': 'UPDATE ip_records SET domain_id=99 WHERE id=12',
      'remapped_parent_orphan': 'UPDATE ip_records SET domain_id=0 WHERE id=11',
      'ip_list_orphan': 'UPDATE ip_records SET ip_list_id=99 WHERE id=11',
      'dns_default_collision': "INSERT INTO dns_servers (id, server) VALUES (0, '1.0.0.1')",
      'domain_default_collision': "INSERT INTO domains (id, name) VALUES (0, 'another-default')",
      'default_domain_list': 'UPDATE domains SET domain_list_id=5 WHERE id=-1',
      'populated_target': "INSERT INTO rdpr_domains (id, resolved, name) VALUES (55, 0, 'existing.example.test')",
      'incompatible_empty_target': 'CREATE TABLE rdpr_dns_servers (id INTEGER PRIMARY KEY, server TEXT)',
      'copy_changing_trigger': 'CREATE TRIGGER alter_copied_dns AFTER INSERT ON rdpr_dns_servers '
      "BEGIN UPDATE rdpr_dns_servers SET description='changed' WHERE id=NEW.id; END",
    }
    if contradiction in statements:
      connection.execute(statements[contradiction])
    elif contradiction == 'duplicate_source_value':
      # OR IGNORE must never turn two source records into one successfully imported record.
      connection.executescript("""
        CREATE TABLE duplicated_dns (
          id INTEGER PRIMARY KEY, server TEXT, doh_server TEXT, description TEXT,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO duplicated_dns SELECT * FROM dns_servers;
        DROP TABLE dns_servers;
        ALTER TABLE duplicated_dns RENAME TO dns_servers;
        INSERT INTO dns_servers SELECT 99, server, doh_server, description, created_at FROM dns_servers WHERE id=-1;
      """)
  before = sqlite_snapshot(path)
  with pytest.raises(app.database.DatabaseWriteError, match='Database initialization failed'):
    await startup_store.setup()
  assert startup_store.writer_task is None
  assert startup_store.writer_state == 'FAILED'
  assert sqlite_snapshot(path) == before


async def test_completed_legacy_history_preserves_old_sources_and_applies_only_new_migrations(app, startup_store):
  """Completed import history is trusted even when historical source tables remain."""
  path = Path(app.settings.db_path)
  create_legacy_database(path)
  sources = {
    'dns_servers': 'SELECT * FROM dns_servers',
    'ros_configs': 'SELECT * FROM ros_configs',
    'domains_lists': 'SELECT * FROM domains_lists',
    'ip_lists': 'SELECT * FROM ip_lists',
    'domains': 'SELECT * FROM domains',
    'ip_records': 'SELECT * FROM ip_records',
    'jobs': 'SELECT * FROM jobs',
  }
  history = (31, 'migration_202511031501.py', 'preserved-checksum', '2001-02-03 04:05:06', '2001-02-04 04:05:06')
  with closing(sqlite3.connect(path)) as connection, connection:
    create_history(connection)
    connection.execute('INSERT INTO rdpr_migrations VALUES (?,?,?,?,?)', history)
    original = {
      name: (
        connection.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone(),
        connection.execute(query).fetchall(),
      )
      for name, query in sources.items()
    }
  await startup_store.setup()
  assert startup_store.writer_state == 'RUNNING'
  await startup_store.close(timeout=2)
  with closing(sqlite3.connect(path)) as connection:
    for name, query in sources.items():
      assert (
        connection.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone(),
        connection.execute(query).fetchall(),
      ) == original[name]
    assert connection.execute('SELECT * FROM rdpr_migrations WHERE id=31').fetchone() == history
    rows = connection.execute('SELECT name,checksum,applied_at FROM rdpr_migrations WHERE id<>31').fetchall()
    expected = {
      migration.name: sha256(migration.read_text(encoding='utf-8').encode()).hexdigest()
      for migration in (Path.cwd() / 'migrations').glob('migration_*.py')
      if migration.name != history[1]
    }
    assert {name: checksum for name, checksum, applied in rows if applied is not None} == expected
    assert connection.execute('SELECT id,name FROM rdpr_domains').fetchall() == [(0, 'default')]
    assert connection.execute('SELECT * FROM rdpr_ip_records').fetchall() == []


async def test_legacy_import_accepts_empty_compatible_targets_and_preserves_values(app, startup_store):
  path = Path(app.settings.db_path)
  create_legacy_database(path)
  async with startup_store._DataBase__write_engine.begin() as connection:
    await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
  await startup_store.setup()
  assert startup_store.writer_state == 'RUNNING'
  await startup_store.close(timeout=2)
  assert_legacy_import(path)


async def test_pending_gateway_reconciliation_preserves_existing_values_and_failed_history(app, startup_store):
  store = startup_store
  async with store._DataBase__write_engine.begin() as connection:
    await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
    await connection.execute(insert(app.database.DomainsDbo).values(id=7, name='existing.example.test', resolved=True))
    await connection.execute(
      insert(app.database.IpRecordsDbo).values(
        id=17,
        domain_id=7,
        addr_type=4,
        ip_address='8.8.8.8',
        use_default_gw=True,
      )
    )
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection, connection:
    connection.executemany(
      'INSERT INTO rdpr_migrations VALUES (?, ?, ?, ?, NULL)',
      [
        (41, 'migration_202618042122.py', 'old-failure-a', '2001-02-03 04:05:06'),
        (42, 'migration_202618042122.py', 'old-failure-b', '2002-03-04 05:06:07'),
      ],
    )
    old_history = connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall()
    old_ips = connection.execute('SELECT * FROM rdpr_ip_records ORDER BY id').fetchall()
  await store.setup()
  await store.close(timeout=2)
  with closing(sqlite3.connect(path)) as connection:
    assert connection.execute('SELECT * FROM rdpr_ip_records ORDER BY id').fetchall() == old_ips
    assert connection.execute('SELECT * FROM rdpr_migrations WHERE id<=42 ORDER BY id').fetchall() == old_history
    assert connection.execute(
      'SELECT COUNT(*) FROM rdpr_migrations WHERE name=? AND applied_at IS NOT NULL',
      ('migration_202618042122.py',),
    ).fetchone() == (1,)


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_legacy_target_name_overlap_is_refused_without_changes(e2e_service):
  service = e2e_service
  service.environment['DB_TABLE_PREFIX'] = ''
  create_legacy_database(service.db_path)
  before = sqlite_snapshot(service.db_path)
  with pytest.raises(AssertionError, match='Application exited before readiness'):
    await service.start()
  assert sqlite_snapshot(service.db_path) == before
  assert service.process is None
  assert service.providers.requests == []


async def test_startup_error_after_physical_commit_keeps_writer_stopped_and_allows_fresh_recovery(
  app,
  startup_store,
  monkeypatch,
):
  original_commit = app.database.AsyncConnection.commit

  async def commit_then_fail(connection):
    await original_commit(connection)
    raise RuntimeError('synthetic lost commit acknowledgement')

  with monkeypatch.context() as commit_patch:
    commit_patch.setattr(app.database.AsyncConnection, 'commit', commit_then_fail)
    with pytest.raises(app.database.DatabaseWriteError, match='Database initialization failed'):
      await startup_store.setup()
  assert startup_store.writer_task is None
  assert startup_store.writer_state == 'FAILED'
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection:
    assert connection.execute(
      'SELECT name FROM rdpr_migrations WHERE applied_at IS NOT NULL ORDER BY id'
    ).fetchall() == [(source.name,) for source in sorted((path.parent / 'migrations').glob('migration_*.py'))]
    assert connection.execute('SELECT id, name FROM rdpr_domains').fetchall() == [(0, 'default')]
  committed = sqlite_snapshot(path)
  recovered = app.database.DataBase()
  try:
    await recovered.setup()
    assert recovered.writer_state == 'RUNNING'
  finally:
    await recovered.close(timeout=2)
    await recovered._DataBase__read_engine.dispose()
    await recovered._DataBase__write_engine.dispose()
  assert sqlite_snapshot(path) == committed


def measured_domain(app, *, mode='stored', complete=True):
  """Construct one explicitly completed saving result and its real per-domain measurement origin.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # metrics is the production measurement module.
  # run is the source operation owning this result.
  # observation is the per-domain lifecycle observer.
  # command is the result carrying explicit completion time into real admission.
  metrics = importlib.import_module('metrics.metrics')
  run = metrics.ResolutionRun(mode)
  run.select(1)
  observation = run.observe()
  observation.notify('processing_started', perf_counter())
  observation.notify('success' if complete else 'partial', perf_counter())
  command = app.dto.DomainResult(
    id=1,
    name='www.example.test',
    resolution_complete=complete,
    last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC),
    observation=observation,
  )
  return run, command


def run_summary_records(caplog, run, kind):
  """Select final INFO summaries for one run from caplog's captured records.

  run identifies the origin rather than the latest metrics generation, and kind
  distinguishes processing from persistence. Batch DEBUG records are excluded.
  """
  # record is one captured record whose positional arguments identify its origin.
  return [
    record
    for record in caplog.records
    if record.levelno == logging.INFO
    and str(record.msg).startswith(f'Resolution {kind} run_id=')
    and record.args[0] == run.run_id
  ]


@pytest.mark.parametrize('commit_before_processing', [False, True])
async def test_multibatch_run_logs_final_persistence_once_after_both_boundaries(
  app, store, monkeypatch, caplog, commit_before_processing
):
  """Keep batch details at DEBUG and summarize real SQLite commits once per run.

  app/store isolate SQLite; monkeypatch chooses three-item batches, and caplog
  captures actual output. commit_before_processing reverses the terminal event
  order without replacing SQL, receipts, or observation code.
  """
  # metrics supplies the production observer; run owns seven source-domain results.
  metrics = importlib.import_module('metrics.metrics')
  run = metrics.ResolutionRun('new')
  run.select(7)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 3)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 0.01)
  # connection creates only test-owned fixture rows; value gives each selected domain an ID.
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [{'id': value, 'name': f'logged-{value}.example.test'} for value in range(1, 8)],
    )
  # evidence counts real transaction boundaries; commands retains receipt-bearing results.
  evidence = instrument_sessions(store, monkeypatch)
  commands = []
  caplog.set_level(logging.DEBUG)
  caplog.clear()
  # value identifies each result; observation receives production lifecycle notifications.
  for value in range(1, 8):
    observation = run.observe()
    observation.notify('processing_started', perf_counter())
    observation.notify('success', perf_counter())
    # command is a complete empty IPv4 result, which must still advance its checkpoint.
    command = app.dto.DomainResult(
      id=value,
      name=f'logged-{value}.example.test',
      resolution_complete=True,
      last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC),
      observation=observation,
    )
    commands.append(command)
    await store.put_domain_after_resolve(command)
    observation.notify('processing_finished', perf_counter())
  if not commit_before_processing:
    run.finish(True)
    assert len(run_summary_records(caplog, run, 'processing')) == 1
    assert run_summary_records(caplog, run, 'persistence') == []
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=3)
  if commit_before_processing:
    assert run_summary_records(caplog, run, 'persistence') == []
    run.finish(True)
  assert evidence.commits == 3
  assert [command.write_receipt.outcome.value for command in commands] == ['confirmed'] * 7
  # connection reads committed checkpoints through the separate production read engine.
  async with store._DataBase__read_engine.connect() as connection:
    assert (await connection.execute(select(app.database.DomainsDbo.resolved))).scalars().all() == [True] * 7
    assert all(
      checkpoint is not None
      for checkpoint in (await connection.execute(select(app.database.DomainsDbo.last_resolved_at))).scalars()
    )  # checkpoint is each persisted completion timestamp.
  assert len(run_summary_records(caplog, run, 'processing')) == 1
  assert len(run_summary_records(caplog, run, 'persistence')) == 1
  # final copies the final counters from the once-per-run persistence log.
  final = run_summary_records(caplog, run, 'persistence')[0].args[2]
  assert final['admitted'] == final['confirmed'] == 7
  assert final['pending'] == final['unknown'] == final['known_not_committed'] == 0
  # record identifies batch detail records independently of their summary payload text.
  assert len([record for record in caplog.records if str(record.msg) == 'Resolution persistence summary=%s']) == 3
  assert all(
    record.levelno == logging.DEBUG
    for record in caplog.records
    if str(record.msg) == 'Resolution persistence summary=%s'
  )


@pytest.mark.parametrize(('stage', 'expected'), [('begin', 'known_not_committed'), ('after_commit', 'unknown')])
async def test_failed_writer_logs_final_receipt_truth_once(app, store, monkeypatch, caplog, stage, expected):
  """A writer fault reports its final receipt outcome without inventing success.

  app/store use real isolated SQLite; monkeypatch injects the selected driver
  stage, and caplog observes one final summary. expected follows whether SQLite
  definitely did not commit or the commit acknowledgement became ambiguous.
  """
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  # run and command carry real production observations across queue admission and writer cleanup.
  run, command = measured_domain(app)

  async def fault(current, evidence):
    """Fail the requested driver stage; evidence retains real transaction counts."""
    if current == stage:
      raise RuntimeError('Synthetic driver stage failure')

  instrument_sessions(store, monkeypatch, fault=fault)
  caplog.set_level(logging.DEBUG)
  caplog.clear()
  await store.put_domain_after_resolve(command)
  command.observation.notify('processing_finished', perf_counter())
  run.finish(True)
  assert run_summary_records(caplog, run, 'persistence') == []
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=3)
  assert len(run_summary_records(caplog, run, 'processing')) == 1
  assert len(run_summary_records(caplog, run, 'persistence')) == 1
  # final is the receipt-based final summary, independent of whether the row physically committed.
  final = run_summary_records(caplog, run, 'persistence')[0].args[2]
  assert final[expected] == final['admitted'] == 1
  assert final['pending'] == final['confirmed'] == 0
  assert command.write_receipt.outcome.value == ('final_unknown' if expected == 'unknown' else expected)
  # current_domain reflects actual SQLite state; ambiguous acknowledgement may follow a physical commit.
  # _ips is the returned IP snapshot, deliberately unused because this assertion concerns the checkpoint.
  current_domain, _ips = await snapshot(app, store)
  assert current_domain[0] is (stage == 'after_commit')


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
@pytest.mark.parametrize('boundary', ['logger', 'collector'])
async def test_final_summary_observation_failure_preserves_real_commit(
  app, store, monkeypatch, caplog, error_type, boundary
):
  """Optional logging or gauge failures cannot change real commit receipts.

  app/store isolate SQLite; monkeypatch injects error_type at boundary, while
  caplog confirms collector failure still permits independent final logs.
  """
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  # metrics is the production observation module; run/command retain normal source-domain truth.
  metrics = importlib.import_module('metrics.metrics')
  run, command = measured_domain(app)
  # original_info keeps unrelated database lifecycle logging intact during resolution-log fault injection.
  original_info = importlib.import_module('logger.logger').logger.info

  def unavailable(*args, **kwargs):
    """Raise the injected failure; args and kwargs accept any logger or collector call."""
    raise error_type('Synthetic optional observation failure')

  def fail_resolution_info(message, *args, **kwargs):
    """Fail resolution INFO message values; forward other calls with their args and kwargs."""
    if str(message).startswith('Resolution '):
      raise error_type('Synthetic optional resolution logging failure')
    return original_info(message, *args, **kwargs)

  if boundary == 'logger':
    monkeypatch.setattr(importlib.import_module('logger.logger').logger, 'info', fail_resolution_info)
  else:
    monkeypatch.setattr(metrics.run_snapshot, 'labels', unavailable)
  caplog.set_level(logging.INFO)
  caplog.clear()
  await store.put_domain_after_resolve(command)
  command.observation.notify('processing_finished', perf_counter())
  run.finish(True)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=3)
  assert command.write_receipt.outcome.value == 'confirmed'
  assert run.snapshot()['admitted'] == run.snapshot()['confirmed'] == 1
  assert run.snapshot()['pending'] == 0
  # current_domain proves the observed success reached SQLite rather than only a fake receipt.
  # _ips is the returned IP snapshot, deliberately unused because this assertion concerns the checkpoint.
  current_domain, _ips = await snapshot(app, store)
  assert current_domain[0] is True
  assert current_domain[1] is not None
  if boundary == 'collector':
    assert len(run_summary_records(caplog, run, 'processing')) == 1
    assert len(run_summary_records(caplog, run, 'persistence')) == 1


def assert_receipt_conservation(run):
  counts = run.snapshot()
  assert (
    counts['admitted'] == counts['pending'] + counts['confirmed'] + counts['known_not_committed'] + counts['unknown']
  )
  assert counts['selected'] == counts['not_started'] + counts['attempted']
  assert counts['attempted'] == counts['active'] + sum(
    counts[field] for field in ('success', 'partial', 'failure', 'cancelled_processing')
  )
  return counts


@pytest.mark.parametrize(
  ('stage', 'state'),
  [
    (None, 'confirmed'),
    ('close', 'confirmed'),
    ('begin', 'known_not_committed'),
    ('commit', 'unknown'),
    ('after_commit', 'unknown'),
  ],
)
async def test_domain_receipt_is_commit_evidence_and_never_inserted_row_count(app, store, monkeypatch, stage, state):
  """Preserve mandatory commit truth for marker-only results across driver failure stages.

  app/store isolate real SQLite and metrics; monkeypatch configures one command per
  batch. stage chooses the injected driver boundary, and state is its established
  receipt truth, including unknown outcomes that must not be replayed.
  """
  await seed(app, store)
  # before preserves checkpoint and IP state independently of the newly saved attempt marker.
  before = await snapshot(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  # run owns the observation; command is an explicitly completed partial result without additions.
  run, command = measured_domain(app, complete=False)

  async def fault(current, evidence):
    """Raise at current when it matches stage; evidence contains real session boundary counts."""
    if current == stage:
      raise RuntimeError('Synthetic driver failure')

  # evidence observes physical commits; counts retains final processing and persistence counters.
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await store.put_domain_after_resolve(command)
  command.observation.notify('processing_finished', perf_counter())
  run.finish(True)
  assert assert_receipt_conservation(run)['pending'] == 1
  assert run.snapshot()['saved_rate_valid'] is False
  await store.start_writer()
  if stage is None:
    await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  else:
    await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  counts = assert_receipt_conservation(run)
  assert counts[state] == 1
  assert counts['pending'] == 0
  assert counts['partial'] == 1
  assert counts['success'] == counts['failure'] == 0
  assert counts['saved_rate_valid'] is (state != 'unknown')
  if state == 'unknown':
    assert math.isnan(counts['saved_rate'])
  elif state == 'known_not_committed':
    assert counts['saved_rate'] == 0
  else:
    assert counts['saved_rate'] > 0
  assert evidence.commits == int(stage != 'begin')
  # A partial result with no additions confirms one source result without changing IP/checkpoint state.
  assert await snapshot(app, store) == before
  assert store._DataBase__observations == {}


async def test_domain_receipt_retries_are_pending_and_confirm_only_once(app, store, monkeypatch):
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  run, command = measured_domain(app)
  retry_states = []

  async def fault(stage, evidence):
    if stage == 'begin' and evidence.begins < 3:
      raise lock_error()

  async def retry(delay):
    retry_states.append((delay, assert_receipt_conservation(run)))

  monkeypatch.setattr(app.database, 'sleep', retry)
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await store.put_domain_after_resolve(command)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert evidence.begins == 3
  assert evidence.commits == 1
  assert [delay for delay, _ in retry_states] == [0.1, 0.2]
  assert all(
    counts['pending'] == 1 and counts['confirmed'] == counts['unknown'] == counts['known_not_committed'] == 0
    for _, counts in retry_states
  )
  counts = assert_receipt_conservation(run)
  assert counts['confirmed'] == counts['admitted'] == 1
  assert counts['pending'] == 0
  assert store._DataBase__observations == {}


async def test_writer_failure_distinguishes_owned_provisional_unknown_and_unattempted_receipts(app, store, monkeypatch):
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  entered, release = asyncio.Event(), asyncio.Event()

  async def hold_commit():
    entered.set()
    await release.wait()

  instrument_sessions(store, monkeypatch, before_commit=hold_commit)
  first, first_command = measured_domain(app)
  queued, queued_command = measured_domain(app)
  await store.put_domain_after_resolve(first_command)
  await store.put_domain_after_resolve(queued_command)
  await store.start_writer()
  await asyncio.wait_for(entered.wait(), timeout=2)
  try:
    with pytest.raises(app.database.DatabaseShutdownError):
      await store.close(timeout=0)
    assert assert_receipt_conservation(first)['unknown'] == 1
    assert assert_receipt_conservation(queued)['known_not_committed'] == 1
    assert store.db_save_queue.qsize() == 1
    assert store.pending_count == 2
    assert len(store._DataBase__observations) == 1
  finally:
    release.set()
  with pytest.raises(asyncio.CancelledError):
    await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert assert_receipt_conservation(first)['confirmed'] == 1
  assert first.snapshot()['unknown'] == 0
  assert queued.snapshot()['known_not_committed'] == 1
  assert store.pending_count == 1
  assert store.db_save_queue.qsize() == 1
  assert store._DataBase__observations == {}


async def test_writer_blocked_admission_is_not_a_receipt_and_cancellation_preserves_processing(app, store):
  run, command = measured_domain(app)
  entered = asyncio.Event()

  class FullQueue(asyncio.Queue):
    async def put(self, item):
      entered.set()
      await super().put(item)

  store.db_save_queue = FullQueue(maxsize=1)
  await enqueue_names(app, store, ['occupies-capacity.example.test'])
  entered.clear()
  producer = asyncio.create_task(store.put_domain_after_resolve(command))
  await asyncio.wait_for(entered.wait(), timeout=2)
  counts = assert_receipt_conservation(run)
  assert counts['admission_in_progress'] == 1
  assert counts['admitted'] == counts['pending'] == 0
  producer.cancel()
  with pytest.raises(asyncio.CancelledError):
    await producer
  counts = assert_receipt_conservation(run)
  assert counts['not_admitted'] == counts['success'] == 1
  assert counts['admission_in_progress'] == counts['admitted'] == counts['unknown'] == 0
  assert store._DataBase__observations == {}


async def test_dns_row_identity_survives_default_and_configured_union_mapping(app, store):
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(insert(app.database.DnsServersDbo).values(id=0, server='192.0.2.1'))
  classic, doh = await store.get_dns_servers_for_resolve()
  assert [(row.id, row.server) for row in classic] == [(0, '192.0.2.1')]
  assert doh == []
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DnsServersDbo),
      [
        {'id': 42, 'server': '192.0.2.42', 'doh_server': None},
        {'id': 43, 'server': None, 'doh_server': 'https://example.test/dns-query'},
      ],
    )
  classic, doh = await store.get_dns_servers_for_resolve()
  assert [(row.id, row.server) for row in classic] == [(42, '192.0.2.42')]
  assert [(row.id, row.server) for row in doh] == [(43, 'https://example.test/dns-query')]


CONNECTION_PRAGMAS = {
  'foreign_keys': 1,
  'journal_mode': 'wal',
  'temp_store': 2,
  'mmap_size': 1048576,
  'cache_size': -317,
  'wal_autocheckpoint': 7,
  'synchronous': 2,
  'busy_timeout': 37,
}


@pytest.fixture
async def configured_store(app, monkeypatch):
  for name, value in CONNECTION_PRAGMAS.items():
    if name != 'foreign_keys':
      configured = {'temp_store': 'MEMORY', 'synchronous': 'FULL'}.get(name, value)
      monkeypatch.setattr(app.settings, f'db_tune_{name}', configured)
  database = app.database.DataBase()
  database._DataBase__state = True
  try:
    async with database._DataBase__write_engine.begin() as connection:
      await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
    yield database
  finally:
    await database.close(timeout=2)
    await database._DataBase__read_engine.dispose()
    await database._DataBase__write_engine.dispose()


@contextmanager
def physical_connection_observations(engine):
  """Observe driver SQL and effective values on every actual pool checkout."""
  evidence = SimpleNamespace(connections=[], statements=[], checkouts=[], closes=[])

  def connected(connection, record):
    evidence.connections.append(connection)
    statements = []
    evidence.statements.append(statements)
    connection.run_async(lambda driver: driver.set_trace_callback(statements.append))

  def checkout(connection, record, proxy):
    cursor = connection.cursor()
    try:
      values = {}
      for name in CONNECTION_PRAGMAS:
        cursor.execute(f'PRAGMA {name}')
        values[name] = cursor.fetchone()[0]
      evidence.checkouts.append((connection, values))
    finally:
      cursor.close()

  def closed(connection, record):
    evidence.closes.append(connection)

  listeners = [('connect', connected), ('checkout', checkout), ('close', closed)]
  for name, callback in listeners:
    event.listen(engine.sync_engine, name, callback, **({'insert': True} if name == 'connect' else {}))
  try:
    yield evidence
  finally:
    for name, callback in listeners:
      event.remove(engine.sync_engine, name, callback)


def assert_effective_connection_settings(evidence):
  assert evidence.checkouts
  for _connection, actual in evidence.checkouts:
    # SQLite may cap mmap_size to a smaller platform-specific allocation.
    assert 0 <= actual['mmap_size'] <= CONNECTION_PRAGMAS['mmap_size']
    assert {name: value for name, value in actual.items() if name != 'mmap_size'} == {
      name: value for name, value in CONNECTION_PRAGMAS.items() if name != 'mmap_size'
    }


async def test_real_read_connections_are_configured_once_and_after_invalidation_and_recycle(
  app, configured_store, monkeypatch
):
  store = configured_store
  engine = store._DataBase__read_engine
  with physical_connection_observations(engine) as evidence:
    async with engine.connect() as first, engine.connect() as second:
      await first.execute(text('SELECT 11'))
      await second.execute(text('SELECT 22'))
      assert len(evidence.connections) == 2
      assert evidence.connections[0] is not evidence.connections[1]
      await first.invalidate()
      async with engine.connect() as replacement:
        assert (await replacement.execute(text('SELECT 33'))).scalar_one() == 33
      assert len(evidence.connections) == 3
    before = [list(statements) for statements in evidence.statements]
    assert await store.get_all_ips_for_domain(1) == []
    assert await store.get_all_ips_for_domain(2) == []
    assert len(evidence.connections) == 3
    for previous, current in zip(before, evidence.statements, strict=True):
      assert [sql for sql in previous if sql.upper().startswith('PRAGMA') and '=' in sql] == [
        sql for sql in current if sql.upper().startswith('PRAGMA') and '=' in sql
      ]
    monkeypatch.setattr(engine.pool, '_recycle', 0)
    for _ in range(2):
      async with engine.connect() as connection:
        assert (await connection.execute(text('SELECT 44'))).scalar_one() == 44
    assert len(evidence.connections) == 5
    assert_effective_connection_settings(evidence)
    await engine.dispose()
    assert len(evidence.closes) == 5


async def test_reopened_writer_connections_keep_settings_across_batches_and_lock_retry(
  app, configured_store, monkeypatch
):
  store = configured_store
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 0.01)
  failed = False

  async def fault(stage, evidence):
    nonlocal failed
    if stage == 'after_insert' and not failed:
      failed = True
      raise lock_error()

  async def retry(delay):
    assert delay == 0.1

  monkeypatch.setattr(app.database, 'sleep', retry)
  sessions = instrument_sessions(store, monkeypatch, fault=fault)
  names = [f'reopened-{index}.example.test' for index in range(3)]
  with physical_connection_observations(store._DataBase__write_engine) as evidence:
    await enqueue_names(app, store, names)
    await store.start_writer()
    await asyncio.wait_for(store.db_save_queue.join(), timeout=3)
    assert await stored_names(app, store) == names
    assert (sessions.begins, sessions.commits, sessions.rollbacks) == (4, 3, 1)
    assert len(evidence.connections) == len(evidence.closes) == 4
    assert_effective_connection_settings(evidence)
    for statements in evidence.statements:
      assert sum(sql.upper().replace(' ', '').startswith('PRAGMAFOREIGN_KEYS=') for sql in statements) == 1
  assert store.pending_count == store.unknown_count == 0
  assert store.writer_state == 'RUNNING'


@pytest.mark.parametrize('code', [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED], ids=['busy', 'locked'])
@pytest.mark.parametrize('recover', [True, False], ids=['third-attempt-commits', 'three-attempts-exhausted'])
async def test_writer_configuration_locks_release_connections_and_preserve_bounded_retries(
  app, store, monkeypatch, code, recover
):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  engine = store._DataBase__write_engine
  attempts, application_sql, delays = [], [], []
  original_execute = aiosqlite.Cursor.execute

  def connected(connection, record):
    attempt = SimpleNamespace(driver=connection.driver_connection, statements=[], trace=[], failed=False)
    attempts.append(attempt)
    connection.run_async(lambda driver: driver.set_trace_callback(attempt.trace.append))

  async def execute(cursor, statement, *args, **kwargs):
    attempt = next((item for item in attempts if item.driver is cursor._conn), None)
    if attempt is not None:
      attempt.statements.append(statement)
      if statement.upper().replace(' ', '').startswith('PRAGMAJOURNAL_MODE=') and (not recover or len(attempts) <= 2):
        # Fail inside the real configurator at the DBAPI boundary, before BEGIN or INSERT.
        attempt.failed = True
        error = sqlite3.OperationalError('synthetic connection configuration lock')
        error.sqlite_errorcode = code
        raise error
    return await original_execute(cursor, statement, *args, **kwargs)

  def observed_sql(connection, cursor, statement, parameters, context, executemany):
    application_sql.append(statement)

  async def retry(delay):
    delays.append(delay)
    assert application_sql == []
    assert await stored_names(app, store) == []
    for attempt in attempts:
      with pytest.raises(ValueError, match='no active connection'):
        await attempt.driver.execute('SELECT 1')

  monkeypatch.setattr(aiosqlite.Cursor, 'execute', execute)
  monkeypatch.setattr(app.database, 'sleep', retry)
  sessions = instrument_sessions(store, monkeypatch)
  event.listen(engine.sync_engine, 'connect', connected, insert=True)
  event.listen(engine.sync_engine, 'before_cursor_execute', observed_sql)
  try:
    await enqueue_names(app, store, ['configuration-retry.example.test'])
    await store.start_writer()
    if recover:
      await asyncio.wait_for(store.db_save_queue.join(), timeout=3)
    else:
      await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=3)
    assert len(attempts) == 3
    assert delays == [0.1, 0.2]
    assert [attempt.failed for attempt in attempts] == ([True, True, False] if recover else [True] * 3)
    for attempt in attempts:
      assert any(sql.upper().replace(' ', '').startswith('PRAGMAFOREIGN_KEYS=') for sql in attempt.trace)
      if attempt.failed:
        assert all(sql.upper().startswith('PRAGMA') for sql in attempt.trace)
      with pytest.raises(ValueError, match='no active connection'):
        await attempt.driver.execute('SELECT 1')
    committed = int(recover)
    statements = [sql.upper() for attempt in attempts for sql in attempt.trace]
    assert statements.count('BEGIN IMMEDIATE') == statements.count('COMMIT') == committed
    assert sum(sql.startswith('INSERT ') for sql in statements) == committed
    assert (sessions.begins, sessions.commits, sessions.rollbacks, sessions.closes) == (
      committed,
      committed,
      3 - committed,
      3,
    )
    assert await stored_names(app, store) == (['configuration-retry.example.test'] if recover else [])
    assert store.unknown_count == 0
    assert store.pending_count == store.db_save_queue._unfinished_tasks == (0 if recover else 1)
    assert store.writer_state == ('RUNNING' if recover else 'FAILED')
    if not recover:
      assert store.writer_failure.outcome_unknown is False
      with pytest.raises(app.database.WriterFailedError):
        await store.close(timeout=2)
  finally:
    event.remove(engine.sync_engine, 'connect', connected)
    event.remove(engine.sync_engine, 'before_cursor_execute', observed_sql)


async def test_repository_read_session_stays_open_until_query_and_closes_once(app, store, monkeypatch):
  sessions = []

  class OwnedReadSession(AsyncSession):
    close_count = 0

    async def execute(self, statement, *args, **kwargs):
      assert self.close_count == 0, 'Repository query received an already closed session'
      return await super().execute(statement, *args, **kwargs)

    async def close(self):
      self.close_count += 1
      await super().close()

  factory = async_sessionmaker(bind=store._DataBase__read_engine, class_=OwnedReadSession)

  def create_session():
    session = factory()
    sessions.append(session)
    return session

  monkeypatch.setattr(store, '_DataBase__read_session_factory', create_session)
  assert await store.get_all_ips_for_domain(1) == []
  assert len(sessions) == 1
  assert sessions[0].close_count == 1
  assert store._DataBase__read_engine.pool.checkedout() == 0


@pytest.mark.parametrize(
  ('setting', 'value'),
  [
    ('journal_mode', 'OFF'),
    ('journal_mode', 'unrecognized-private-value'),
    ('journal_mode', 'WAL; SELECT 1'),
    ('temp_store', 'unrecognized-private-value'),
    ('synchronous', 'unrecognized-private-value'),
    ('busy_timeout', -1),
    ('wal_autocheckpoint', -1),
    ('cache_size', 'unrecognized-private-value'),
  ],
)
async def test_invalid_connection_settings_fail_before_database_creation(app, monkeypatch, setting, value):
  monkeypatch.setattr(app.settings, f'db_tune_{setting}', value)
  path = Path(app.settings.db_path)
  assert not path.exists()

  async def initialize():
    database = app.database.DataBase()
    try:
      await database.setup()
    finally:
      await database._DataBase__read_engine.dispose()
      await database._DataBase__write_engine.dispose()

  with pytest.raises(app.database.DatabaseConfigurationError) as failure:
    await initialize()
  assert 'private-value' not in str(failure.value)
  assert str(path) not in str(failure.value)
  assert not path.exists()


@pytest.mark.parametrize('mode', ['DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL'])
async def test_supported_journal_modes_are_effective_on_each_owned_engine(app, monkeypatch, mode):
  monkeypatch.setattr(app.settings, 'db_tune_journal_mode', mode.lower())
  database = app.database.DataBase()
  try:
    # Allocate a real file before testing multiple independent physical connections.
    Path(app.settings.db_path).touch()
    for engine in (database._DataBase__read_engine, database._DataBase__write_engine):
      for _ in range(2):
        async with engine.connect() as connection:
          assert (await connection.execute(text('PRAGMA journal_mode'))).scalar_one() == mode.lower()
          assert (await connection.execute(text('PRAGMA foreign_keys'))).scalar_one() == 1
  finally:
    await database._DataBase__read_engine.dispose()
    await database._DataBase__write_engine.dispose()


async def test_negative_mmap_request_uses_fresh_sqlite_default(app, monkeypatch):
  with closing(sqlite3.connect(app.settings.db_path)) as connection:
    expected = connection.execute('PRAGMA mmap_size').fetchone()[0]
  monkeypatch.setattr(app.settings, 'db_tune_mmap_size', -1)
  database = app.database.DataBase()
  try:
    for engine in (database._DataBase__read_engine, database._DataBase__write_engine):
      async with engine.connect() as connection:
        assert (await connection.execute(text('PRAGMA mmap_size'))).scalar_one() == expected
  finally:
    await database._DataBase__read_engine.dispose()
    await database._DataBase__write_engine.dispose()


async def test_real_sqlite_mapping_cap_is_accepted_by_both_owned_engines(app, monkeypatch):
  requested = 2**63 - 1
  with closing(sqlite3.connect(app.settings.db_path)) as connection:
    # SQLite's mmap_size readback reports its build/runtime limit, independently of engine wiring.
    connection.execute(f'PRAGMA mmap_size={requested}')
    effective = connection.execute('PRAGMA mmap_size').fetchone()[0]
    assert 0 <= effective < requested, 'This SQLite build must exercise an actual mapping cap'
    assert connection.execute('SELECT 123').fetchone() == (123,)
  monkeypatch.setattr(app.settings, 'db_tune_mmap_size', requested)
  database = app.database.DataBase()
  try:
    for engine in (database._DataBase__read_engine, database._DataBase__write_engine):
      for _ in range(2):
        async with engine.connect() as connection:
          assert (await connection.execute(text('PRAGMA mmap_size'))).scalar_one() == effective
          assert (await connection.execute(text('SELECT 456'))).scalar_one() == 456
  finally:
    await database._DataBase__read_engine.dispose()
    await database._DataBase__write_engine.dispose()


@pytest.mark.parametrize('engine_name', ['read', 'write'])
async def test_effective_pragma_mismatch_rejects_connection_before_application_sql(app, store, engine_name):
  engine = getattr(store, f'_DataBase__{engine_name}_engine')
  await engine.dispose()
  drivers, application_sql = [], []

  def ignored_setting(action, name, value, database, trigger):
    if action == sqlite3.SQLITE_PRAGMA and name.lower() == 'foreign_keys' and value is not None:
      return sqlite3.SQLITE_IGNORE
    return sqlite3.SQLITE_OK

  def refuse_configuration(connection, record):
    drivers.append(connection.driver_connection)
    connection.run_async(lambda driver: driver.set_authorizer(ignored_setting))

  def observed_sql(connection, cursor, statement, parameters, context, executemany):
    application_sql.append(statement)

  event.listen(engine.sync_engine, 'connect', refuse_configuration, insert=True)
  event.listen(engine.sync_engine, 'before_cursor_execute', observed_sql)
  try:
    with pytest.raises(app.database.DatabaseConfigurationError):
      async with engine.connect() as connection:
        await connection.execute(text('SELECT 987654'))
    assert application_sql == []
    assert len(drivers) == 1
    with pytest.raises(ValueError, match='no active connection'):
      await drivers[0].execute('SELECT 1')
    if engine_name == 'read':
      assert engine.pool.checkedout() == 0
  finally:
    event.remove(engine.sync_engine, 'connect', refuse_configuration)
    event.remove(engine.sync_engine, 'before_cursor_execute', observed_sql)


async def test_startup_fk_override_is_closed_before_runtime_connections(app, startup_store):
  store = startup_store
  with physical_connection_observations(store._DataBase__write_engine) as writes:
    await store.setup()
    assert len(writes.connections) == len(writes.closes) == 1
    statements = [sql.upper().replace(' ', '') for sql in writes.statements[0]]
    enabled = next(
      index for index, sql in enumerate(statements) if sql in {'PRAGMAFOREIGN_KEYS=ON', 'PRAGMAFOREIGN_KEYS=1'}
    )
    assert enabled < statements.index('PRAGMAFOREIGN_KEYS=OFF')
    assert statements.index('PRAGMAFOREIGN_KEYS=OFF') < statements.index('BEGINIMMEDIATE')
    await enqueue_names(app, store, ['after-startup.example.test'])
    await store.close(timeout=2)
    assert len(writes.connections) == len(writes.closes) == 2
    assert all(values['foreign_keys'] == 1 for _, values in writes.checkouts)
    assert not any('FOREIGN_KEYS=OFF' in sql.upper() for sql in writes.statements[1])
  assert await stored_names(app, store) == ['after-startup.example.test', 'default']


@pytest.mark.parametrize('mode', ['new', 'stale'])
async def test_dns_job_reads_once_and_activates_committed_changes_only_for_next_job(
  app, store, resolver, monkeypatch, dns_message, mode
):
  """Keep one immutable DNS snapshot per pass and reload it only for a newly eligible pass.

  app/store/resolver exercise real selection, writer and coordinator behavior;
  monkeypatch/dns_message replace external DNS only, and mode selects NEW or STALE.
  Fixture eligibility is restored only after the preceding receipts are committed.
  """
  # jobs names the public scan modes; connection owns disposable setup and fixture eligibility changes.
  jobs = importlib.import_module('jobs.job_registry')
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(insert(app.database.DnsServersDbo).values(id=42, server='192.0.2.53'))
    await connection.execute(
      insert(app.database.DomainsDbo),
      [
        {
          'id': index,
          'name': f'snapshot-{index}.example.test',
          'resolved': mode == 'stale',
          'last_resolved_at': STALE_CHECKPOINT if mode == 'stale' else None,
        }
        for index in (1, 2)  # index is each domain's stable fixture ID.
      ],
    )
  # entered/release bracket the first DNS query; requests and selections record wire calls and DNS reads.
  entered, release = asyncio.Event(), asyncio.Event()
  requests, selections = [], []

  async def classic(boundary, qname, rdtype, **kwargs):
    """Record boundary's endpoint for qname/rdtype, blocking only the first synthetic answer.

    kwargs carries unused resolver options. The result is a trustworthy empty DNS response.
    """
    requests.append((boundary.nameservers[0], qname, rdtype))
    if len(requests) == 1:
      entered.set()
      await release.wait()
    return SimpleNamespace(response=dns_message('nodata', query=dns.message.make_query(qname, rdtype)))

  def observe_select(connection, cursor, statement, parameters, context, executemany):
    """Record DNS configuration reads from statement without changing SQL execution.

    connection/cursor/parameters/context/executemany are unused SQLAlchemy event metadata.
    """
    if 'UNION ALL' in statement and 'rdpr_dns_servers' in statement:
      selections.append(statement)

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  event.listen(store._DataBase__read_engine.sync_engine, 'before_cursor_execute', observe_select)
  # mode_value chooses the coordinator scan; task owns the first pass until its processing finishes.
  mode_value = getattr(jobs.Jobs, f'DOMAINS_RESOLVE_{mode.upper()}')
  task = asyncio.create_task(resolver.domains_resolve(mode_value))
  try:
    await asyncio.wait_for(entered.wait(), timeout=3)
    assert store._DataBase__read_engine.pool.checkedout() == 0
    assert len(selections) == 1
    # Commit the new endpoint while the first job owns its old configuration.
    async with store._DataBase__write_engine.begin() as connection:
      await connection.execute(text("UPDATE rdpr_dns_servers SET server='192.0.2.54' WHERE id=42"))
  finally:
    release.set()
    await asyncio.wait_for(task, timeout=3)
  try:
    # expected_names is finite membership; index forms each selected domain name.
    # name and record_type form each independently expected DNS query for the first pass.
    expected_names = {f'snapshot-{index}.example.test' for index in (1, 2)}
    assert set(requests) == {
      ('192.0.2.53', name, record_type) for name in expected_names for record_type in (dns.rdatatype.A,)
    }
    assert len(requests) == 2
    assert len(selections) == 1
    assert store.pending_count == 2
    requests.clear()
    # A fresh scan may observe unchanged eligibility, but pending writes retain ID ownership.
    await asyncio.wait_for(resolver.domains_resolve(mode_value), timeout=3)
    assert requests == []
    assert store.pending_count == 2
    # reads_before_next_attempt preserves the DNS-read count while the prior receipts settle.
    reads_before_next_attempt = len(selections)
    await flush_queue(store)
    # Restore eligibility only after the preceding commands have known committed outcomes.
    async with store._DataBase__write_engine.begin() as connection:
      await connection.execute(
        text('UPDATE rdpr_domains SET last_attempt_at=NULL, last_resolved_at=:checkpoint'),
        {'checkpoint': STALE_CHECKPOINT.strftime('%Y-%m-%d %H:%M:%S') if mode == 'stale' else None},
      )
    await asyncio.wait_for(resolver.domains_resolve(mode_value), timeout=3)
    # name and record_type identify each expected query after the new DNS configuration becomes active.
    assert set(requests) == {
      ('192.0.2.54', name, record_type) for name in expected_names for record_type in (dns.rdatatype.A,)
    }
    assert len(requests) == 2
    assert len(selections) == reads_before_next_attempt + 1
    assert store.pending_count == 2
    await flush_queue(store)
    # rows contains final successful state; resolved/checkpoint are each row's flag and committed checkpoint.
    async with store._DataBase__read_engine.connect() as connection:
      rows = (await connection.execute(text('SELECT resolved, last_resolved_at FROM rdpr_domains ORDER BY id'))).all()
    assert len(rows) == 2
    assert all(resolved == 1 and checkpoint is not None for resolved, checkpoint in rows)
  finally:
    event.remove(store._DataBase__read_engine.sync_engine, 'before_cursor_execute', observe_select)


async def test_dns_configuration_ignores_enqueue_and_rollback_until_writer_commit(app, store):
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(insert(app.database.DnsServersDbo).values(id=0, server='192.0.2.1'))
  request = importlib.import_module('models.http.dns_servers_req').DnsPostElementReq
  await store.put_add_dns_servers_to_queue([request(server='192.0.2.42')])

  def values(snapshot):
    return tuple(tuple((server.id, server.server) for server in group) for group in snapshot)

  before = await store.get_dns_servers_for_resolve()
  assert values(before) == (((0, '192.0.2.1'),), ())
  async with store._DataBase__write_engine.connect() as connection:
    await connection.execute(text('BEGIN IMMEDIATE'))
    await connection.execute(text("UPDATE rdpr_dns_servers SET server='192.0.2.99' WHERE id=0"))
    assert values(await store.get_dns_servers_for_resolve()) == (((0, '192.0.2.1'),), ())
    await connection.rollback()
  assert values(await store.get_dns_servers_for_resolve()) == (((0, '192.0.2.1'),), ())
  await flush_queue(store)
  after = await store.get_dns_servers_for_resolve()
  assert values(after) == (((1, '192.0.2.42'),), ())
  assert values(before) == (((0, '192.0.2.1'),), ())
  assert store.pending_count == 0


@pytest.mark.parametrize('mode', ['new', 'stale'])
async def test_dns_read_failure_is_typed_and_prevents_job_admission_and_persistence(
  app, store, resolver, monkeypatch, mode, caplog
):
  jobs = importlib.import_module('jobs.job_registry')
  await seed(app, store, resolved=mode == 'stale', checkpoint=STALE_CHECKPOINT if mode == 'stale' else None)
  before = await snapshot(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text('DROP TABLE rdpr_dns_servers'))
  with pytest.raises(app.database.DnsConfigurationReadError) as failure:
    await store.get_dns_servers_for_resolve()
  assert 'rdpr_dns_servers' not in str(failure.value)
  assert str(app.settings.db_path) not in str(failure.value)
  with pytest.raises(app.database.DnsConfigurationReadError):
    await resolver.resolve_once('www.example.test')
  with pytest.raises(app.database.DnsConfigurationReadError):
    await asyncio.wait_for(resolver.domains_resolve(getattr(jobs.Jobs, f'DOMAINS_RESOLVE_{mode.upper()}')), timeout=3)
  with pytest.raises(app.database.DnsConfigurationReadError):
    await resolver.resolve_stored_domain(1)
  assert store.pending_count == store.unknown_count == 0
  assert await snapshot(app, store) == before
  assert store._DataBase__read_engine.pool.checkedout() == 0
  assert 'no such table' not in caplog.text


@pytest.mark.parametrize('mode', ['new', 'stale'])
@pytest.mark.parametrize('configuration', ['empty', 'unknown-only'])
async def test_successful_dns_selection_without_endpoints_rejects_nonempty_job_before_admission(
  app, store, resolver, monkeypatch, mode, configuration
):
  jobs = importlib.import_module('jobs.job_registry')
  network_calls, admissions, selections = [], [], []

  async def reject_network(*args, **kwargs):
    network_calls.append((args, kwargs))
    raise AssertionError('DNS configuration failure must precede network access')

  def selected(connection, cursor, statement, parameters, context, executemany):
    if 'UNION ALL' in statement and 'rdpr_dns_servers' in statement:
      selections.append(statement)

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', reject_network)
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', reject_network)
  await seed(app, store, resolved=mode == 'stale', checkpoint=STALE_CHECKPOINT if mode == 'stale' else None)
  if configuration == 'unknown-only':
    async with store._DataBase__write_engine.begin() as connection:
      # A configured UNKNOWN row still suppresses the otherwise usable default row.
      await connection.execute(
        insert(app.database.DnsServersDbo),
        [{'id': 0, 'server': '192.0.2.1', 'doh_server': None}, {'id': 42, 'server': None, 'doh_server': None}],
      )
  before = await snapshot(app, store)
  async with store._DataBase__read_session_factory() as session:
    rows = await app.database.DnsServersDbo.get_all_for_resolve(session)
    assert [tuple(row) for row in rows] == ([(None, None, 0, 42)] if configuration == 'unknown-only' else [])
  with pytest.raises(app.database.DnsConfigurationReadError) as repository_failure:
    await store.get_dns_servers_for_resolve()
  assert str(app.settings.db_path) not in str(repository_failure.value)
  assert 'rdpr_dns_servers' not in str(repository_failure.value)
  assert store._DataBase__read_engine.pool.checkedout() == 0
  event.listen(store._DataBase__read_engine.sync_engine, 'after_cursor_execute', selected)
  try:
    with pytest.raises(app.database.DnsConfigurationReadError) as failure:
      await asyncio.wait_for(resolver.domains_resolve(getattr(jobs.Jobs, f'DOMAINS_RESOLVE_{mode.upper()}')), timeout=3)
    assert len(selections) == 1
    assert str(app.settings.db_path) not in str(failure.value)
    assert 'rdpr_dns_servers' not in str(failure.value)
    assert network_calls == admissions == []
    assert store.db_save_queue.qsize() == store.db_save_queue._unfinished_tasks == 0
    assert store.pending_count == store.unknown_count == 0
    assert await snapshot(app, store) == before
    assert store._DataBase__read_engine.pool.checkedout() == 0
  finally:
    event.remove(store._DataBase__read_engine.sync_engine, 'after_cursor_execute', selected)


@pytest.mark.e2e
async def test_public_dns_change_during_job_activates_after_commit_for_next_operation(e2e_service):
  service = e2e_service
  service.providers.addresses_by_domain.update(
    {
      ('classic', 'second.example.test.'): ('11.0.0.1',),
      ('doh', 'second.example.test.'): ('12.0.0.1',),
    }
  )
  await configure_public_domain(service, resolved=False)
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/domains', json=[{'domain': 'second.example.test'}])
    assert response.status_code == 200, response.text
    async with asyncio.timeout(5):
      while True:
        response = await client.get('/domains')
        assert response.status_code == 200, response.text
        if {'www.example.test', 'second.example.test'} <= {row['name'] for row in response.json()['payload']}:
          break
        await asyncio.sleep(0.02)
    response = await client.get('/dns', params={'default': 'false'})
    configured = response.json()['payload']
    classic_id = next(row['id'] for row in configured if row['server'] == service.dns_host)
    doh_id = next(row['id'] for row in configured if row['doh_server'] == service.doh_url)
    service.providers.requests.clear()
    service.providers.hold_dns = True
    try:
      response = await client.post('/commands/domains/resolve/new')
      assert response.status_code == 200, response.text
      await asyncio.wait_for(service.providers.dns_entered.wait(), timeout=3)
      response = await client.delete(f'/dns/{classic_id}')
      assert response.status_code == 200, response.text
      async with asyncio.timeout(5):
        while True:
          response = await client.get('/dns', params={'default': 'false'})
          if {row['id'] for row in response.json()['payload']} == {doh_id}:
            break
          await asyncio.sleep(0.02)
    finally:
      service.providers.hold_dns = False
      service.providers.dns_release.set()
    async with asyncio.timeout(5):
      while True:
        response = await client.get('/domains')
        rows = [row for row in response.json()['payload'] if row['name'] != 'default']
        if len(rows) == 2 and all(row['resolved'] for row in rows):
          break
        await asyncio.sleep(0.02)
    assert {row for row in service.providers.requests if row[0] in {'classic', 'doh'}} == {
      (transport, name + '.', record_type)
      for transport in ('classic', 'doh')
      for name in ('www.example.test', 'second.example.test')
      for record_type in (dns.rdatatype.A,)
    }
    service.providers.requests.clear()
    response = await client.post('/domains/resolve/check', json={'domain': 'next.example.test'})
    assert response.status_code == 200, response.text
    assert [(row['server_type'], row['server'], row['ips_v4']) for row in response.json()['results']] == [
      ('doh', service.doh_url, ['8.8.4.4'])
    ]
    assert {transport for transport, _, _ in service.providers.requests} == {'doh'}
    for row in rows:
      response = await client.get(f'/domains/{row["id"]}')
      assert response.status_code == 200, response.text
      assert set(response.json()['ips_v4']) == (
        {'8.8.8.8', '8.8.4.4'} if row['name'] == 'www.example.test' else {'11.0.0.1', '12.0.0.1'}
      )
  await service.stop()


@pytest.mark.parametrize('error_type', [None, RuntimeError, asyncio.CancelledError])
async def test_receipt_observer_failure_cannot_cancel_real_commit(app, store, monkeypatch, error_type):
  """Optional observation failures cannot prevent a completed result from committing or alter mandatory receipts.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # command is the explicitly completed result and optional faulty observer.
  # domain is committed successful checkpoint fields.
  # _ips is the IP state returned alongside the checkpoint.
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  class BrokenObserver:
    """Raise a selected synthetic error whenever optional observation is attempted."""

    def notify(self, event, at):
      """Raise the selected error_type for optional event/at observation notifications."""
      raise error_type('Synthetic observer failure')

  command = app.dto.DomainResult(
    id=1,
    name='www.example.test',
    resolution_complete=True,
    last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC),
    observation=BrokenObserver() if error_type is not None else None,
  )
  await store.put_domain_after_resolve(command)
  assert command.write_receipt.admitted is True
  assert command.write_receipt.outcome == 'pending'
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert store.pending_count == 0
  assert store.writer_state == 'RUNNING'
  assert command.write_receipt.outcome == 'confirmed'
  domain, _ips = await snapshot(app, store)
  assert domain[0] is True
  assert domain[1] is not None


async def test_writer_phase_durations_follow_admission_dequeue_commit_and_cleanup(app, store, monkeypatch):
  metrics = importlib.import_module('metrics.metrics')
  clock = SimpleNamespace(value=10.0)
  monkeypatch.setattr(metrics, 'perf_counter', lambda: clock.value)
  monkeypatch.setattr(app.database, 'perf_counter', lambda: clock.value)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  def total(name, **labels):
    return sum(
      sample.value
      for family in REGISTRY.collect()
      for sample in family.samples
      if sample.name == name and all(sample.labels.get(key) == value for key, value in labels.items())
    )

  before = {
    phase: total('resolution_writer_duration_seconds_sum', phase=phase)
    for phase in ('attempt', 'transaction', 'commit', 'cleanup', 'batch_dwell')
  }
  before_residence = total('resolution_queue_duration_seconds_sum', queue='writer', phase='residence')
  before_admission = total('resolution_queue_duration_seconds_sum', queue='writer', phase='admission')

  class TimedQueue(asyncio.Queue):
    async def put(self, item):
      clock.value = 100.0
      await super().put(item)

    async def get(self):
      item = await super().get()
      clock.value = 120.0
      return item

  async def fault(stage, evidence):
    clock.value = {'begin': 122.0, 'after_insert': 130.0, 'commit': 132.0, 'after_commit': 134.0, 'close': 140.0}.get(
      stage, clock.value
    )

  store.db_save_queue = TimedQueue(maxsize=2)
  instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['measured.example.test'])
  clock.value = 110.0
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert await stored_names(app, store) == ['measured.example.test']
  assert total('resolution_queue_duration_seconds_sum', queue='writer', phase='admission') - before_admission == 90
  assert total('resolution_queue_duration_seconds_sum', queue='writer', phase='residence') - before_residence == 20
  assert total('resolution_writer_duration_seconds_sum', phase='attempt') - before['attempt'] == 20
  assert total('resolution_writer_duration_seconds_sum', phase='transaction') - before['transaction'] == 14
  assert total('resolution_writer_duration_seconds_sum', phase='commit') - before['commit'] == 4
  assert total('resolution_writer_duration_seconds_sum', phase='cleanup') - before['cleanup'] == 6
  assert total('resolution_writer_duration_seconds_sum', phase='batch_dwell') - before['batch_dwell'] == 0


def parse_samples(body):
  return {
    (sample.name, tuple(sorted(sample.labels.items()))): sample.value
    for family in text_string_to_metric_families(body)
    for sample in family.samples
  }


def sample_total(samples, name, **labels):
  return sum(
    value
    for (sample_name, sample_labels), value in samples.items()
    if sample_name == name and all(dict(sample_labels).get(key) == str(value) for key, value in labels.items())
  )


def registry_samples():
  return {
    (sample.name, tuple(sorted(sample.labels.items()))): sample.value
    for family in REGISTRY.collect()
    for sample in family.samples
  }


async def test_writer_sql_metrics_count_actual_dispatch_methods_and_failed_submitted_sets(app, store):
  """A logical insertmanyvalues executemany flag is not the DBAPI method; failed sets remain attempts."""
  engine = store._DataBase__write_engine
  async with engine.begin() as connection:
    await connection.execute(text('CREATE TABLE dispatch_probe (id INTEGER PRIMARY KEY, value TEXT UNIQUE)'))
  before = registry_samples()
  observed = []

  def execute(cursor, statement, parameters, context):
    observed.append(('execute', 1))

  def many(cursor, statement, parameters, context):
    observed.append(('executemany', len(parameters)))

  def no_params(cursor, statement, context):
    observed.append(('execute_no_params', 1))

  listeners = (('do_execute', execute), ('do_executemany', many), ('do_execute_no_params', no_params))
  for name, callback in listeners:
    event.listen(engine.sync_engine, name, callback)
  try:
    async with engine.begin() as connection:
      assert (await connection.execute(text('SELECT 7'))).scalar_one() == 7
      assert (await connection.execute(text('SELECT 8').execution_options(no_parameters=True))).scalar_one() == 8
      await connection.execute(
        text('INSERT INTO dispatch_probe (id,value) VALUES (:id,:value)'),
        [{'id': 1, 'value': 'a'}, {'id': 2, 'value': 'b'}],
      )
      await connection.execute(
        insert(app.database.DomainsDbo).returning(app.database.DomainsDbo.id),
        [{'name': 'dispatch-a.example.test'}, {'name': 'dispatch-b.example.test'}],
      )
    with pytest.raises(IntegrityError):
      async with engine.begin() as connection:
        await connection.execute(
          text('INSERT INTO dispatch_probe (id,value) VALUES (:id,:value)'),
          [{'id': 3, 'value': 'c'}, {'id': 4, 'value': 'a'}],
        )
  finally:
    for name, callback in listeners:
      event.remove(engine.sync_engine, name, callback)
  after = registry_samples()
  for method in ('execute', 'executemany', 'execute_no_params'):
    dispatches = sum(name == method for name, _ in observed)
    sets = sum(count for name, count in observed if name == method)
    assert dispatches > 0
    assert (
      sample_total(after, 'resolution_writer_sql_dispatches_total', method=method)
      - sample_total(before, 'resolution_writer_sql_dispatches_total', method=method)
      == dispatches
    )
    assert (
      sample_total(after, 'resolution_writer_sql_parameter_sets_total', method=method)
      - sample_total(before, 'resolution_writer_sql_parameter_sets_total', method=method)
      == sets
    )
  assert [count for method, count in observed if method == 'executemany'] == [2, 2]
  async with engine.connect() as connection:
    assert (await connection.execute(text('SELECT id,value FROM dispatch_probe ORDER BY id'))).all() == [
      (1, 'a'),
      (2, 'b'),
    ]


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
@pytest.mark.parametrize('boundary', ['callback', 'collector'])
async def test_optional_writer_observation_failures_never_change_commit_receipts(
  app, store, monkeypatch, error_type, boundary
):
  await add_support_domains(app, store)
  metrics = importlib.import_module('metrics.metrics')

  def unavailable(*args, **kwargs):
    raise error_type('Synthetic optional observer failure')

  if boundary == 'callback':
    monkeypatch.setattr(app.database, 'observe_writer_sql_dispatch', unavailable)
    monkeypatch.setattr(app.database, 'observe_writer_batch_size', unavailable)
  else:
    for collector in (
      metrics.writer_sql_dispatches,
      metrics.writer_sql_parameter_sets,
      metrics.writer_batch_size,
      metrics.writer_duration,
    ):
      monkeypatch.setattr(collector, 'labels', unavailable)
  result = await queue_resolution(app, store, 1, ['8.8.8.8'])
  await flush_queue(store)
  assert result.write_receipt.outcome.value == 'confirmed'
  assert await support_snapshot(store) == {('8.8.8.8', 1, None)}


async def test_writer_phase_and_input_size_metrics_include_repeated_intents(app, store):
  await add_support_domains(app, store)
  before = registry_samples()
  await queue_resolution(app, store, 1, ['8.8.8.8', '8.8.8.8'])
  await queue_resolution(app, store, 1, ['9.9.9.9'], complete=False)
  await queue_resolution(app, store, 2, [])
  await flush_queue(store)
  after = registry_samples()
  for kind, expected in (('commands', 3), ('intents', 3), ('addresses', 3)):
    assert (
      sample_total(after, 'resolution_writer_batch_size_sum', kind=kind)
      - sample_total(before, 'resolution_writer_batch_size_sum', kind=kind)
      == expected
    )
    assert (
      sample_total(after, 'resolution_writer_batch_size_count', kind=kind)
      - sample_total(before, 'resolution_writer_batch_size_count', kind=kind)
      == 1
    )
  for phase in ('prepare', 'reconcile', 'finish'):
    assert (
      sample_total(after, 'resolution_writer_duration_seconds_count', phase=phase, outcome='complete')
      - sample_total(before, 'resolution_writer_duration_seconds_count', phase=phase, outcome='complete')
      == 1
    )


def run_fields(samples, mode):
  return {
    dict(labels)['field']: value
    for (name, labels), value in samples.items()
    if name == 'resolution_run_snapshot' and dict(labels).get('mode') == mode
  }


def application_pid(samples):
  pids = {int(dict(labels)['pid']) for name, labels in samples if name == 'fastapi_app_info'}
  assert len(pids) == 1
  return pids.pop()


async def completed_metrics(client, *, mode, selected, previous_completed=0):
  async with asyncio.timeout(10):
    while True:
      response = await client.get('/metrics')
      assert response.status_code == 200
      samples = parse_samples(response.text)
      fields = run_fields(samples, mode)
      if (
        fields.get('selected') == selected
        and sample_total(samples, 'resolution_run_elapsed_seconds_count', mode=mode) > previous_completed
        and fields.get('processing_complete') == 1
        and fields.get('active') == 0
        and fields.get('pending') == 0
        and fields.get('admission_in_progress') == 0
      ):
        return samples, fields
      await asyncio.sleep(0.01)


@pytest.mark.e2e
@pytest.mark.parametrize(
  ('classic', 'doh', 'outcome', 'adds_address'),
  [
    ('positive', 'positive', 'success', True),
    ('positive', 'servfail', 'partial', True),
    ('nodata', 'servfail', 'partial', False),
    ('servfail', 'servfail', 'failure', False),
  ],
)
async def test_public_metrics_separate_processing_admission_and_real_persistence(
  e2e_service,
  classic,
  doh,
  outcome,
  adds_address,
):
  """Count one persisted saving attempt for terminal success, partial-empty and failed DNS.

  e2e_service owns the real app and local classic/DoH providers. classic/doh select
  wire evidence, outcome is its processing classification and adds_address states
  independently whether positive DNS authorizes new IP evidence. Zero new IPs
  still confirms a source result and contributes a positive saved rate.
  """
  # service and domain_id identify the real process and stored source domain.
  service = e2e_service
  domain_id = await configure_public_domain(service)
  # before retains successful-checkpoint and IP metadata independently of the new attempt marker.
  before = public_flow_snapshot(service, domain_id)
  service.providers.classic, service.providers.doh = classic, doh
  # client bounds HTTP calls; response acknowledges the real stored saving request.
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post(f'/domains/{domain_id}/resolve')
    assert response.status_code == 202
    # samples holds public Prometheus values; fields is the settled stored-run measurement.
    samples, fields = await completed_metrics(client, mode='stored', selected=1)
    assert fields['attempted'] == fields[outcome] == 1
    assert fields['success'] + fields['partial'] + fields['failure'] == 1
    assert fields['admitted'] == fields['confirmed'] == 1
    assert fields['pending'] == fields['unknown'] == fields['known_not_committed'] == 0
    assert fields['processing_rate_valid'] == fields['saved_rate_valid'] == 1
    assert fields['processing_elapsed'] > 0
    assert fields['persistence_elapsed'] >= fields['processing_elapsed']
    assert fields['processing_rate'] > 0
    assert fields['saved_rate'] > 0
    # saved is the actual public stored date pair, independent of the metric acknowledgement.
    saved = (await client.get(f'/domains/{domain_id}')).json()
    assert isinstance(saved['last_attempt_at'], (float, int))
    assert (
      datetime.fromisoformat(saved['last_attempt_at_hum']).strftime('%Y-%m-%d %H:%M:%S') == saved['last_attempt_at_hum']
    )
    assert sample_total(samples, 'resolution_dns_duration_seconds_count', record_type='A') == 2
    # kind is one configured wire outcome whose failure requires the existing CNAME fallback.
    assert sample_total(samples, 'resolution_dns_duration_seconds_count', record_type='CNAME') == sum(
      kind == 'servfail' for kind in (classic, doh)
    )
    assert sample_total(samples, 'httpx_exchanges_in_flight') == 0
    assert sample_total(samples, 'httpx_exchanges_started_total') == sample_total(
      samples, 'httpx_exchanges_terminal_total'
    )
    # dns_samples retains only DNS metrics; name/labels/value are each public sample's coordinates and count.
    dns_samples = {
      (name, labels): value for (name, labels), value in samples.items() if name.startswith('resolution_dns_')
    }
    assert 'www.example.test' not in repr(dns_samples)
    assert service.dns_host not in repr(dns_samples)
    assert service.doh_url not in repr(dns_samples)
  # after is durable checkpoint/IP state; marker admission does not itself authorize IP changes.
  after = public_flow_snapshot(service, domain_id)
  if not adds_address:
    assert after == before
  else:
    assert '8.8.8.8' in after[1]
    assert ('9.9.9.9' in after[1]) is (outcome == 'partial')
  # This must be the application process, not the pytest coordinator.
  # resources is operating-system evidence for the actual child process, rather than the pytest runner.
  resources = service.resource_snapshot(application_pid(samples))
  assert resources['pid'] == application_pid(samples)
  assert resources['pid'] != os.getpid()
  assert resources['rss_bytes'] > 0
  assert resources['peak_rss_bytes'] >= resources['rss_bytes']
  assert resources['cpu_seconds'] > 0


def histogram_percentiles(samples, before, name, **selected_labels):
  """Interpolate observed histogram buckets; report estimates, never raw-event quantiles."""
  buckets = {}
  for (sample_name, labels), value in samples.items():
    if sample_name == f'{name}_bucket' and all(
      dict(labels).get(key) == value for key, value in selected_labels.items()
    ):
      boundary = float(dict(labels)['le'])
      buckets[boundary] = buckets.get(boundary, 0) + value - before.get((sample_name, labels), 0)
  total = buckets.get(math.inf, 0)
  result = {'count': total, 'method': 'linear interpolation of Prometheus cumulative histogram buckets'}
  for label, quantile in [('p50', 0.5), ('p95', 0.95), ('p99', 0.99)]:
    result[label] = None
    if not total:
      continue
    previous_bound, previous_count = 0.0, 0.0
    for boundary, count in sorted(buckets.items()):
      if count >= total * quantile:
        if math.isinf(boundary):
          result[f'{label}_lower_bound'] = previous_bound
        else:
          result[label] = previous_bound + (boundary - previous_bound) * (total * quantile - previous_count) / (
            count - previous_count
          )
        break
      previous_bound, previous_count = boundary, count
  return result


@pytest.mark.e2e
@pytest.mark.e2e_load
async def test_reproducible_local_measurement_baseline(e2e_service, tmp_path):
  """Compare bounded workers with identical persisted sources and controlled protocols."""
  service = e2e_service
  first_id = await configure_public_domain(service, resolved=False)
  names = ['www.example.test', *[f'baseline-{index}.example.test' for index in range(15)]]
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/domains', json=[{'domain': name} for name in names[1:]])
    assert response.status_code == 200
    async with asyncio.timeout(5):
      while True:
        rows = (await client.get('/domains')).json()['payload']
        ids = [row['id'] for row in rows if row['name'] in names]
        if len(ids) == len(names):
          break
        await asyncio.sleep(0.01)
  assert first_id in ids
  service.providers.classic_addresses = ('8.8.8.0',)
  service.providers.doh_addresses = ('8.8.4.0',)
  service.environment.update(
    {
      'DB_SAVE_BATCH_SIZE': '1000',
      'DOMAINS_RESOLVE_NEW_BATCH_SIZE': '500',
      'DOMAINS_RESOLVE_SEMAPHORE_LIMIT': '20',
      'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT': '5',
      'RIPE_STAT_PREFIX_CACHE_TTL_SEC': '28800',
      'RIPE_STAT_EMPTY_PREFIX_CACHE_TTL_SEC': '3600',
      'RIPE_STAT_CACHE_LOCK_TTL_SEC': '120',
      'RIPE_STAT_CACHE_SIZE': '10000',
      'QUEUE_MAX_SIZE': '4',
      'TEST_TASK_MEASUREMENTS': str(tmp_path / 'application-task-measurements.json'),
    }
  )
  scenarios = []
  settings = {
    key: value
    for key, value in service.environment.items()
    if key.startswith(('DB_', 'REQ_', 'DNS_', 'DOH_', 'DOMAINS_', 'QUEUE_', 'RIPE_'))
  }
  with closing(sqlite3.connect(service.db_path)) as connection:
    initial_ips = connection.execute(
      'SELECT id,ip_list_id,domain_id,addr_type,ip_address,ros_comment,use_default_gw,created_at,updated_at '
      'FROM rdpr_ip_records ORDER BY id'
    ).fetchall()
    initial_supports = connection.execute('SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports').fetchall()
  for schedule, delay, unavailable, worker_limit in [
    (schedule, delay, unavailable, worker_limit)
    for schedule, delay, unavailable in [('fast', 0.0, False), ('slow', 0.02, False), ('unavailable', 0.0, True)]
    for worker_limit in (1, 4)
  ]:
    await service.stop()
    with closing(sqlite3.connect(service.db_path)) as connection, connection:
      connection.execute('DELETE FROM rdpr_ip_supports')
      connection.execute('DELETE FROM rdpr_ip_records')
      connection.executemany(
        'INSERT INTO rdpr_ip_records '
        '(id,ip_list_id,domain_id,addr_type,ip_address,ros_comment,use_default_gw,created_at,updated_at) '
        'VALUES (?,?,?,?,?,?,?,?,?)',
        initial_ips,
      )
      connection.executemany(
        'INSERT INTO rdpr_ip_supports (ip_record_id,domain_id,ip_list_id) VALUES (?,?,?)', initial_supports
      )
    service.environment['DOMAINS_RESOLVE_WORKER_LIMIT'] = str(worker_limit)
    service.providers.delay = delay
    service.providers.unavailable = unavailable
    service.providers.classic = 'servfail' if unavailable else 'positive'
    await service.start()
    async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
      for temperature in ('cold', 'warm'):
        # This disposable setup runs after the preceding job and its receipts are terminal.
        with closing(sqlite3.connect(service.db_path)) as connection, connection:
          connection.executemany(
            'UPDATE rdpr_domains SET resolved=0, last_resolved_at=NULL WHERE id=?', [(value,) for value in ids]
          )
          before_rows = connection.execute(
            'SELECT id, domain_id, addr_type, ip_address FROM rdpr_ip_records ORDER BY id'
          ).fetchall()
        assert service.providers.dns_active == 0
        service.providers.dns_peak_active = 0
        before = parse_samples((await client.get('/metrics')).text)
        request_offset = len(service.providers.requests)
        http_offset = len(service.providers.http_requests)
        child_pid = application_pid(before)
        resources = [service.resource_snapshot(child_pid)]
        done = asyncio.Event()

        async def sample_child(done=done, resources=resources, child_pid=child_pid):
          while not done.is_set():
            resources.append(service.resource_snapshot(child_pid))
            try:
              await asyncio.wait_for(done.wait(), timeout=0.01)
            except TimeoutError:
              pass

        sampler = asyncio.create_task(sample_child())
        started = perf_counter()
        try:
          response = await client.post('/commands/domains/resolve/new')
          assert response.status_code == 200
          samples, fields = await completed_metrics(
            client,
            mode='new',
            selected=len(names),
            previous_completed=sample_total(before, 'resolution_run_elapsed_seconds_count', mode='new'),
          )
        finally:
          done.set()
          await sampler
        elapsed = perf_counter() - started
        resources.append(service.resource_snapshot(child_pid))
        assert fields['failure' if unavailable else 'success'] == len(names)
        assert fields['confirmed'] == (0 if unavailable else len(names))
        assert fields['admitted'] == fields['confirmed']
        assert fields['pending'] == fields['unknown'] == 0
        assert fields['saved_rate_valid'] == fields['processing_rate_valid'] == 1
        with closing(sqlite3.connect(service.db_path)) as connection:
          actual_rows = connection.execute(
            'SELECT id, domain_id, addr_type, ip_address FROM rdpr_ip_records ORDER BY id'
          ).fetchall()
          checkpoints = connection.execute(
            'SELECT id, resolved, last_resolved_at FROM rdpr_domains WHERE id>0 ORDER BY id'
          ).fetchall()
          actual_supports = connection.execute(
            'SELECT ip.ip_address,s.domain_id,s.ip_list_id FROM rdpr_ip_supports AS s '
            'JOIN rdpr_ip_records AS ip ON ip.id=s.ip_record_id ORDER BY ip.ip_address,s.domain_id'
          ).fetchall()
          assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        if unavailable:
          assert actual_rows == before_rows
          assert set(actual_supports) == {
            (address, domain_id, list_id)
            for ip_id, domain_id, list_id in initial_supports
            for row_id, _, _, _, address, *_ in initial_ips
            if row_id == ip_id
          }
          assert all(row[1:] == (0, None) for row in checkpoints)
        else:
          assert {row[3] for row in actual_rows} == {'8.8.8.0', '8.8.4.0', '2001:4860:4860::8888'}
          assert set(actual_supports) == {
            (address, domain_id, None) for domain_id in ids for address in ('8.8.8.0', '8.8.4.0')
          } | {('2001:4860:4860::8888', first_id, None)}
          assert all(row[1] == 1 and row[2] is not None for row in checkpoints)
        network_count = sample_total(samples, 'resolution_ripe_duration_seconds_count', phase='network') - sample_total(
          before, 'resolution_ripe_duration_seconds_count', phase='network'
        )
        if not unavailable:
          assert network_count == (2 if temperature == 'cold' else 0)
        else:
          assert network_count == 0
        distributions = {
          'httpx_exchange_duration_seconds': histogram_percentiles(samples, before, 'httpx_exchange_duration_seconds'),
          'resolution_dns_duration_seconds': histogram_percentiles(samples, before, 'resolution_dns_duration_seconds'),
          **{
            f'resolution_ripe_{phase}_seconds': histogram_percentiles(
              samples, before, 'resolution_ripe_duration_seconds', phase=phase
            )
            for phase in ('lookup', 'network')
          },
          **{
            f'resolution_{queue}_queue_{phase}_seconds': histogram_percentiles(
              samples, before, 'resolution_queue_duration_seconds', queue=queue, phase=phase
            )
            for queue in ('writer', 'resolve')
            for phase in ('admission', 'residence')
          },
          **{
            f'resolution_writer_{phase}_seconds': histogram_percentiles(
              samples, before, 'resolution_writer_duration_seconds', phase=phase
            )
            for phase in ('attempt', 'transaction', 'commit')
          },
        }
        assert distributions['resolution_dns_duration_seconds']['count'] == len(names) * (4 if unavailable else 2)
        scenarios.append(
          {
            'schedule': schedule,
            'worker_limit': worker_limit,
            'actual_supports': actual_supports,
            'peak_provider_dns_queries': service.providers.dns_peak_active,
            'dns_query_limit': 20,
            'cache': temperature,
            'provider_delay_seconds': delay,
            'http_provider_disconnects': unavailable,
            'classic_rcode': 'SERVFAIL' if unavailable else 'NOERROR',
            'wall_elapsed_seconds': elapsed,
            'run': fields,
            'histogram_percentile_estimates': distributions,
            'actual_classic_calls': sum(row[0] == 'classic' for row in service.providers.requests[request_offset:]),
            'actual_dns_calls': [row for row in service.providers.requests[request_offset:] if row[0] != 'ripe'],
            'controlled_dns_ttls_seconds': sorted(
              {ttl for response in service.providers.response_ttls for ttl in response}
            ),
            'actual_http_calls': service.providers.http_requests[http_offset:],
            'ripe_network_calls': network_count,
            'actual_ip_rows': actual_rows,
            'actual_checkpoints': checkpoints,
            'child_pid': child_pid,
            'launcher_pid': service.process.pid,
            'resource_source': resources[0]['source'],
            'child_cpu_seconds': resources[-1]['cpu_seconds'] - resources[0]['cpu_seconds'],
            'child_peak_rss_bytes': max(sample['peak_rss_bytes'] for sample in resources),
            'child_max_sampled_rss_bytes': max(sample['rss_bytes'] for sample in resources),
            'resource_sample_count': len(resources),
          }
        )
    await service.stop()
    task_measurements = json.loads(Path(service.environment['TEST_TASK_MEASUREMENTS']).read_text(encoding='utf-8'))
    assert 0 < task_measurements['peak_active_tasks'] < 100
    assert service.providers.dns_active == 0
    for scenario in scenarios[-2:]:
      scenario['child_task_measurements_for_cold_and_warm_process'] = task_measurements
      assert 0 < scenario['peak_provider_dns_queries'] <= min(20, worker_limit * 2)
  source_paths = [
    'main.py',
    'pyproject.toml',
    'poetry.lock',
    'config/config.py',
    'server/server.py',
    'metrics/httpx_metrics.py',
    'metrics/metrics.py',
    'client/http_base_client.py',
    'client/domains_resolving_client.py',
    'client/ripe_stat_client.py',
    'database/db.py',
    'models/dto/queue_dto.py',
    'models/dto/domains_dto.py',
    'models/dto/dns_server_dto.py',
    'models/db/dns_servers_dbo.py',
    'tests/conftest.py',
    'tests/unit/test_domains_resolving_client.py',
    'tests/integration/test_domain_resolution_persistence.py',
  ]
  artifact = tmp_path / 'measurement-baseline.json'
  artifact.write_text(
    json.dumps(
      {
        'scope': 'local controlled worker1/worker4 comparison with real confirmed source persistence',
        'dataset': names,
        'settings': settings,
        'python': sys.version,
        'invocation': [sys.executable, '-B', '-m', 'pytest', *sys.argv[1:]],
        'versions': {
          name: importlib.metadata.version(name)
          for name in ('httpx', 'sqlalchemy', 'aiosqlite', 'prometheus-client', 'cashews', 'dnspython')
        },
        'source_sha256': {name: sha256((service.root / name).read_bytes()).hexdigest() for name in source_paths},
        'scenarios': scenarios,
      },
      indent=2,
      allow_nan=False,
    ),
    encoding='utf-8',
  )
  assert len(scenarios) == 12


@pytest.mark.parametrize('mode', ['new', 'stale'])
async def test_resolution_selection_is_complete_lightweight_ordered_and_detached(app, store, monkeypatch, mode):
  """Legacy run limits cannot truncate a finite pass or allocate processing state eagerly."""
  monkeypatch.setattr(app.settings, 'domains_resolve_new_batch_size', 1)
  monkeypatch.setattr(app.settings, 'domains_resolve_stale_batch_size', 1)
  expected_ids = list(range(1, 2106))
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [
        {
          'id': value,
          'name': f'finite-{value}.example.test',
          'resolved': mode == 'stale',
          'last_resolved_at': STALE_CHECKPOINT if mode == 'stale' else None,
        }
        for value in expected_ids
      ]
      + [
        {'id': 0, 'name': 'default', 'resolved': False, 'last_resolved_at': None},
        {
          'id': 3000,
          'name': 'ineligible.example.test',
          'resolved': True,
          'last_resolved_at': datetime.now(UTC),
        },
      ],
    )
  tasks_before = asyncio.all_tasks()
  selected = await getattr(store, f'get_{mode}_domains_for_resolve')()
  assert [row.id for row in selected] == expected_ids
  assert [(row.name, row.list_id) for row in selected] == [
    (f'finite-{value}.example.test', None) for value in expected_ids
  ]
  assert all(not isinstance(row, app.dto.DomainResult) for row in selected)
  assert all(not hasattr(row, 'observation') and not hasattr(row, 'result') for row in selected)
  assert store._DataBase__read_engine.pool.checkedout() == 0
  assert asyncio.all_tasks() == tasks_before
  with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
    selected[0].name = 'mutated.example.test'
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text('DELETE FROM rdpr_domains WHERE id=1'))
    await connection.execute(
      insert(app.database.DomainsDbo).values(
        id=4000,
        name='later.example.test',
        resolved=mode == 'stale',
        last_resolved_at=STALE_CHECKPOINT if mode == 'stale' else None,
      )
    )
  assert [row.id for row in selected] == expected_ids
  assert selected[0].name == 'finite-1.example.test'
  later = await getattr(store, f'get_{mode}_domains_for_resolve')()
  assert [row.id for row in later] == [*expected_ids[1:], 4000]


@pytest.mark.parametrize('mode', ['new', 'stale'])
async def test_resolution_selection_failure_is_explicit_and_releases_read_session(app, store, mode, caplog):
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(text('DROP TABLE rdpr_domains'))
  with pytest.raises(app.database.DatabaseReadError) as failure:
    await getattr(store, f'get_{mode}_domains_for_resolve')()
  assert 'rdpr_domains' not in str(failure.value)
  assert str(app.settings.db_path) not in str(failure.value)
  assert store._DataBase__read_engine.pool.checkedout() == 0
  assert 'no such table' not in caplog.text


async def test_http_pool_enforces_capacity_and_cancelled_stream_releases_connection(app, monkeypatch):
  """Use real sockets: a MockTransport cannot establish connection-pool admission."""
  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', app.real_http_send)
  monkeypatch.setattr(app.settings, 'req_max_connections', 2)
  monkeypatch.setattr(app.settings, 'req_max_keepalive_connections', 1)
  monkeypatch.setattr(app.settings, 'req_connection_retries', 0)
  # Custom transports historically bypass ambient proxies; keep local admission direct.
  for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
    monkeypatch.setenv(key, 'http://127.0.0.1:1')
  monkeypatch.setenv('NO_PROXY', '')
  accepted, writers, handlers = [], set(), set()
  release = asyncio.Event()

  async def serve(reader, writer):
    task = asyncio.current_task()
    handlers.add(task)
    writers.add(writer)
    try:
      async with asyncio.timeout(5):
        await reader.readuntil(b'\r\n\r\n')
        accepted.append(writer)
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx')
        await writer.drain()
        await release.wait()
        writer.write(b'y')
        await writer.drain()
    except ConnectionError:
      pass
    finally:
      writer.close()
      await writer.wait_closed()
      writers.discard(writer)
      handlers.discard(task)

  server = await asyncio.start_server(serve, '127.0.0.1', 0)
  url = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}/'
  client = factory.get_client('default', timeout=httpx.Timeout(connect=1, read=2, write=1, pool=0.05))
  pool = client._transport._transport._async_transport._pool
  assert pool._max_connections == 2
  assert pool._max_keepalive_connections == 1
  assert pool._retries == 0
  opened = [asyncio.Event(), asyncio.Event()]

  async def hold(index):
    async with client.stream('GET', url) as response:
      assert response.status_code == 200
      opened[index].set()
      await asyncio.Future()

  tasks = [asyncio.create_task(hold(index)) for index in range(2)]
  try:
    await asyncio.wait_for(asyncio.gather(*(event.wait() for event in opened)), timeout=2)
    assert len(accepted) == 2
    with pytest.raises(httpx.PoolTimeout):
      await asyncio.wait_for(client.get(url), timeout=1)
    assert len(accepted) == 2
    tasks[0].cancel()
    with pytest.raises(asyncio.CancelledError):
      await tasks[0]
    response = await asyncio.wait_for(client.send(client.build_request('GET', url), stream=True), timeout=1)
    assert response.status_code == 200
    assert len(accepted) == 3
    await response.aclose()
  finally:
    for task in tasks:
      task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    release.set()
    await factory.close()
    server.close()
    await server.wait_closed()
    for writer in tuple(writers):
      writer.close()
    if handlers:
      await asyncio.wait_for(asyncio.gather(*tuple(handlers)), timeout=2)
  assert client.is_closed
  assert (
    sum(
      sample.value
      for family in REGISTRY.collect()
      for sample in family.samples
      if sample.name == 'httpx_exchanges_in_flight'
    )
    == 0
  )


async def load_wait_writer_backlog(client, selected, timeout, *, all_admitted=False):
  """Require observed accepted, unconfirmed STALE writes before injecting priority or shutdown."""
  async with asyncio.timeout(timeout):
    while True:
      response = await client.get('/metrics')
      assert response.status_code == 200
      fields = run_fields(parse_samples(response.text), 'stale')
      if fields.get('selected') == selected:
        assert fields.get('unknown', 0) == fields.get('known_not_committed', 0) == 0, fields
        if fields.get('pending', 0) > 0 and fields['admitted'] > fields['confirmed']:
          if not all_admitted or (fields['admitted'] == selected and fields['processing_complete'] == 1):
            return {'observed_at_monotonic': perf_counter(), 'run': fields}
        assert not (fields.get('processing_complete') == 1 and fields.get('pending') == 0), (
          'Source drained before the required backlog observation',
          fields,
        )
      await asyncio.sleep(0.01)


async def load_wait_priority_commit(client, observations, domain_id, addresses, mode, previous, timeout):
  """Confirm the priority operation's own receipt and exact public result, rather than old bulk state."""
  async with asyncio.timeout(timeout):
    while True:
      response = await client.get('/metrics')
      assert response.status_code == 200
      samples = parse_samples(response.text)
      confirmed = sample_total(samples, 'resolution_run_events_total', mode=mode, event='confirmed') - previous
      if confirmed:
        assert confirmed == 1, (mode, confirmed)
        fields = run_fields(samples, mode)
        assert fields['attempted'] == fields['success'] == fields['admitted'] == fields['confirmed'] == 1, fields
        assert fields['pending'] == fields['unknown'] == fields['known_not_committed'] == 0, fields
        row = (await load_api_request(client, observations, 'read', 'GET', f'/domains/{domain_id}', timeout=5)).json()
        assert row['resolved'] is True, row
        assert row['last_resolved_at'] is not None, row
        assert set(row['ips_v4'] or []) == set(addresses), row
        assert not row['ips_v6'], row
        return row
      await asyncio.sleep(0.05)


@pytest.mark.parametrize('outcome', ['backlog', 'drained', 'http_error', 'no_response', 'timeout'])
async def test_load_writer_backlog_requires_real_pending_receipts_and_preserves_failures(outcome):
  fields = {
    'selected': 8192,
    'admitted': 1000,
    'confirmed': 0,
    'pending': 1000,
    'processing_complete': 0,
    'unknown': 0,
    'known_not_committed': 0,
  }
  if outcome == 'drained':
    fields.update(admitted=8192, confirmed=8192, pending=0, processing_complete=1)
  metrics = '\n'.join(f'resolution_run_snapshot{{mode="stale",field="{key}"}} {value}' for key, value in fields.items())
  failure = httpx.ReadError('Synthetic metrics transport failure')
  client = SimpleNamespace(
    get=AsyncMock(return_value=httpx.Response(503 if outcome == 'http_error' else 200, text=metrics))
  )
  if outcome == 'no_response':
    client.get.side_effect = failure
  elif outcome == 'timeout':
    client.get.return_value = httpx.Response(200, text='')
  if outcome == 'backlog':
    observed = await load_wait_writer_backlog(client, 8192, 1)
    assert observed['run'] == fields
    assert observed['observed_at_monotonic'] > 0
  elif outcome == 'no_response':
    with pytest.raises(httpx.ReadError) as raised:
      await load_wait_writer_backlog(client, 8192, 1)
    assert raised.value is failure
  else:
    with pytest.raises(TimeoutError if outcome == 'timeout' else AssertionError):
      await load_wait_writer_backlog(client, 8192, 0.02)


@pytest.mark.parametrize('outcome', ['committed', 'old_payload', 'no_receipt', 'http_error', 'no_response'])
async def test_load_priority_commit_requires_own_confirmation_and_fresh_payload(outcome):
  fields = dict.fromkeys(('attempted', 'success', 'admitted', 'confirmed'), 1)
  fields.update(pending=0, unknown=0, known_not_committed=0)
  metrics = '\n'.join(
    f'resolution_run_snapshot{{mode="stored",field="{key}"}} {value}' for key, value in fields.items()
  )
  metrics += '\nresolution_run_events_total{mode="stored",event="confirmed"} ' + (
    '5' if outcome == 'no_receipt' else '6'
  )
  row = {
    'resolved': True,
    'last_resolved_at': 123,
    'ips_v4': ['8.8.4.4' if outcome == 'old_payload' else '1.1.1.1'],
    'ips_v6': [],
  }
  failure = httpx.ReadError('Synthetic metrics transport failure')
  client = SimpleNamespace(
    get=AsyncMock(return_value=httpx.Response(503 if outcome == 'http_error' else 200, text=metrics)),
    request=AsyncMock(return_value=httpx.Response(200, json=row)),
  )
  if outcome == 'no_response':
    client.get.side_effect = failure
    with pytest.raises(httpx.ReadError) as raised:
      await load_wait_priority_commit(client, {}, 9, {'1.1.1.1'}, 'stored', 5, 1)
    assert raised.value is failure
  elif outcome == 'committed':
    assert await load_wait_priority_commit(client, {}, 9, {'1.1.1.1'}, 'stored', 5, 1) == row
  else:
    with pytest.raises(TimeoutError if outcome == 'no_receipt' else AssertionError):
      await load_wait_priority_commit(client, {}, 9, {'1.1.1.1'}, 'stored', 5, 0.02)
    if outcome == 'no_receipt':
      client.request.assert_not_awaited()


def load_assert_api_limits(observations):
  """Reject HTTP latency failures before a measured phase can become successful."""
  quantiles = {key: load_quantiles(values) for key, values in observations.items()}
  for label, values in quantiles.items():
    assert values['max'] <= 5, (label, values)
    assert values['p99'] <= 1, (label, values)
  return quantiles


@pytest.mark.parametrize('test_name', ['priority', 'shutdown'])
async def test_load_backlog_setup_failure_is_preserved_in_artifact(tmp_path, monkeypatch, test_name):
  """A failed startup must retain its original error and never publish a successful run."""
  failure = RuntimeError('Synthetic startup failure')
  events = []

  @contextmanager
  def cpu_profile(profile):
    events.append(('enter', profile))
    try:
      yield
    finally:
      events.append(('exit', profile))

  service = SimpleNamespace(
    root=Path(__file__).resolve().parents[2],
    start=AsyncMock(side_effect=failure),
    cpu_profile=cpu_profile,
    cpu_evidence={'profile': 'performance'},
    startup_attempts=[],
  )
  monkeypatch.setenv('GOST_LOAD_CONFIG', json.dumps({'profile': 'smoke', 'n': 8192, 'cpu_profile': 'performance'}))
  operation = (
    test_resolution_load_priority_during_stale_writer_backlog
    if test_name == 'priority'
    else test_resolution_load_shutdown_drains_accepted_writer_backlog
  )
  arguments = (service, tmp_path, 'healthy') if test_name == 'priority' else (service, tmp_path)
  with pytest.raises(RuntimeError) as raised:
    await operation(*arguments)
  assert raised.value is failure
  filename = 'priority-backlog.json' if test_name == 'priority' else 'shutdown-backlog.json'
  result = json.loads((tmp_path / filename).read_text(encoding='utf-8'))
  assert result['status'] == 'failed'
  assert result['stage'] == 'initial_startup'
  assert result['failure'] == {'type': 'RuntimeError', 'message': 'Synthetic startup failure'}
  assert events == [('enter', 'performance'), ('exit', 'performance')]


@pytest.mark.parametrize('seconds', [0.2, 1.01, 5.01])
def test_load_api_limits_reject_http_tail_and_maximum(seconds):
  observations = {'stored_resolve': [0.01, seconds]}
  if seconds <= 1:
    result = load_assert_api_limits(observations)
    assert result['stored_resolve']['count'] == 2
    assert result['stored_resolve']['p99'] == seconds
  else:
    with pytest.raises(AssertionError, match='stored_resolve'):
      load_assert_api_limits(observations)


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.parametrize('schedule', ['healthy', 'degraded'])
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True}], indirect=True)
async def test_resolution_load_priority_during_stale_writer_backlog(e2e_service, tmp_path, schedule):
  """Measure missing NEW/stored lifecycles at 8192 without replaying historical performance matrices."""
  service = e2e_service
  configuration = resolution_load_configuration()
  dataset = ResolutionLoadDataset(8192, configuration)
  dataset.schedule = schedule
  snapshot = load_source_evidence(service.root)
  artifact = {
    'status': 'in_progress',
    'schedule': schedule,
    'source_sha256': snapshot,
    'phases': [],
    'bounds': {'http_seconds': 5, 'route_p99_seconds': 1, 'source_and_lifecycle_seconds': 1800},
  }
  artifact_path = tmp_path / 'priority-backlog.json'
  artifact['stage'] = 'cpu_profile'
  try:
    with service.cpu_profile(configuration['cpu_profile']):
      artifact['stage'] = 'initial_startup'
      await service.start()
      artifact['stage'] = 'dns_setup'
      await load_public_setup(service, 30)
      artifact['stage'] = 'initial_stop'
      await service.stop()
      artifact['stage'] = 'offline_seed'
      load_prepare_offline(service, dataset, stale=True)
      service.environment['DOMAINS_UPDATE_INTERVAL'] = '0'
      service.providers.response_factory = dataset.response
      artifact['effective_settings'] = load_effective_settings(service)
      artifact['stage'] = 'seeded_startup'
      await service.start()
      async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
        for cycle, temperature in enumerate(('cold', 'warm')):
          await load_begin_provider_cycle(service.providers, cycle)
          artifact['stage'] = f'{temperature}_phase'
          phase = {'cache': temperature, 'status': 'in_progress', 'dataset': dataset.manifest()}
          artifact['phases'].append(phase)
          observations = LoadApiObservations(diagnostic=True)
          finished = asyncio.Event()
          tasks = []
          name = f'priority-{cycle}.load.example.test'
          try:
            before = parse_samples((await client.get('/metrics')).text)
            started = perf_counter()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 1800
            async with asyncio.timeout_at(deadline):
              await load_api_request(client, observations, 'job', 'POST', '/commands/domains/resolve/stale', timeout=5)

            async def source(before=before, started=started, phase=phase, deadline=deadline, loop=loop):
              samples, fields = await load_wait_idle(
                client,
                'stale',
                dataset.count,
                sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stale'),
                max(0, deadline - loop.time()),
              )
              elapsed = perf_counter() - started
              phase.update(wall_seconds_to_known_writer_outcomes=elapsed, run=fields)
              assert elapsed <= 1800
              expected = dataset.manifest()['categories']
              assert fields['success'] == expected['success'] + expected['empty'], fields
              assert fields['partial'] == expected['partial'], fields
              assert fields['failure'] == expected['failure'], fields
              assert fields['confirmed'] == dataset.count - expected['failure'], fields
              phase['ripe_network_requests'] = sample_total(
                samples, 'resolution_ripe_duration_seconds_count', phase='network'
              ) - sample_total(before, 'resolution_ripe_duration_seconds_count', phase='network')

            async def priority(
              phase=phase,
              observations=observations,
              before=before,
              name=name,
              cycle=cycle,
              deadline=deadline,
              loop=loop,
            ):
              phase['creation_injection'] = await load_wait_writer_backlog(
                client, dataset.count, max(0, deadline - loop.time())
              )
              created = perf_counter()
              await load_api_request(
                client, observations, 'write', 'POST', '/domains', timeout=5, json=[{'domain': name}]
              )
              async with asyncio.timeout_at(deadline):
                while True:
                  found = (
                    await load_api_request(
                      client,
                      observations,
                      'search',
                      'GET',
                      '/domains/search',
                      timeout=5,
                      params={'text': name},
                    )
                  ).json()['payload']
                  if found:
                    assert len(found) == 1, found
                    assert found[0]['name'] == name, found
                    assert found[0]['last_resolved_at'] is None, found
                    domain_id = found[0]['id']
                    break
                  await asyncio.sleep(0.05)
              phase.update(priority_domain_id=domain_id, creation_confirmed_seconds=perf_counter() - created)
              phase['new_injection'] = await load_wait_writer_backlog(
                client, dataset.count, max(0, deadline - loop.time())
              )
              assert phase['new_injection']['run']['not_started'] + phase['new_injection']['run']['active'] > 0
              new_started = perf_counter()
              await load_api_request(client, observations, 'new', 'POST', '/commands/domains/resolve/new', timeout=5)
              new_row = await load_wait_priority_commit(
                client,
                observations,
                domain_id,
                {'8.8.4.4'},
                'new',
                sample_total(before, 'resolution_run_events_total', mode='new', event='confirmed'),
                max(0, deadline - loop.time()),
              )
              phase.update(new_lifecycle_seconds=perf_counter() - new_started, new_result=new_row)
              for transport in ('classic', 'doh'):
                service.providers.schedule[(transport, name, dns.rdatatype.A, cycle)] = (
                  {'kind': 'positive', 'addresses': ('1.1.1.1',)},
                )
              service.providers.schedule[('ripe', '1.1.1.1', None, cycle)] = ({'kind': 'empty'},)
              phase['stored_injection'] = await load_wait_writer_backlog(
                client, dataset.count, max(0, deadline - loop.time())
              )
              assert phase['stored_injection']['run']['not_started'] + phase['stored_injection']['run']['active'] > 0
              stored_started = perf_counter()
              await load_api_request(
                client,
                observations,
                'stored_resolve',
                'POST',
                f'/domains/{domain_id}/resolve',
                timeout=5,
                statuses=(202,),
              )
              stored_row = await load_wait_priority_commit(
                client,
                observations,
                domain_id,
                {'1.1.1.1'},
                'stored',
                sample_total(before, 'resolution_run_events_total', mode='stored', event='confirmed'),
                max(0, deadline - loop.time()),
              )
              phase.update(stored_lifecycle_seconds=perf_counter() - stored_started, stored_result=stored_row)
              assert stored_row['last_resolved_at'] >= new_row['last_resolved_at']

            async def monitor(
              before=before,
              phase=phase,
              finished=finished,
              observations=observations,
            ):
              pid = application_pid(before)
              phase['resources'] = []
              while not finished.is_set():
                phase['resources'].append(service.resource_snapshot(pid))
                for label, path in (
                  ('read', f'/domains/{dataset.count + 1}'),
                  ('list', '/domains?limit=10'),
                  ('stats', '/stats'),
                ):
                  await load_api_request(client, observations, label, 'GET', path, timeout=5)
                try:
                  await asyncio.wait_for(finished.wait(), timeout=0.25)
                except TimeoutError:
                  pass

            source_task = asyncio.create_task(source())
            priority_task = asyncio.create_task(priority())
            monitor_task = asyncio.create_task(monitor())
            tasks = [source_task, priority_task, monitor_task]
            async with asyncio.timeout_at(deadline):
              while not (source_task.done() and priority_task.done()):
                done, _ = await asyncio.wait(
                  [task for task in tasks if not task.done()],
                  return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                  await task
              await source_task
              await priority_task
              finished.set()
              await monitor_task
            domain_id = phase['priority_domain_id']
            phase['priority_before_restart'] = (await client.get(f'/domains/{domain_id}')).json()
            resources = phase['resources']
            assert max(row['peak_rss_bytes'] for row in resources) <= configuration['rss_limit_mb'] * 1024 * 1024
            cpu_percent = (
              100 * (resources[-1]['cpu_seconds'] - resources[0]['cpu_seconds']) / (perf_counter() - started)
            )
            phase['cpu_percent_one_core'] = cpu_percent
            assert cpu_percent <= configuration['cpu_percent_limit']
            # Retain the same process/cache across cold and warm phases, then verify the final probe after restart.
            if temperature == 'warm':
              await service.stop()
              await service.start()
              assert (await client.get(f'/domains/{domain_id}')).json() == phase['priority_before_restart']
              phase['priority_restart_verified'] = True
            await load_api_request(client, observations, 'delete', 'DELETE', f'/domains/{domain_id}', timeout=5)
            async with asyncio.timeout(1800):
              while True:
                response = await load_api_request(
                  client,
                  observations,
                  'read',
                  'GET',
                  f'/domains/{domain_id}',
                  timeout=5,
                  statuses=(200, 404),
                )
                if response.status_code == 404:
                  break
                await asyncio.sleep(0.05)
            phase['verification'] = await load_verify_public(client, dataset, 1800)
            phase['providers'] = service.providers.evidence()
            phase['http'] = load_assert_api_limits(observations)
            phase['status'] = 'passed'
          except BaseException as error:
            phase.update(status='failed', failure={'type': type(error).__name__, 'message': str(error)[:4000]})
            raise
          finally:
            finished.set()
            for task in tasks:
              if not task.done():
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            phase['http'] = {key: load_quantiles(values) for key, values in observations.items()}
            phase['http_exchanges'] = observations.requests
            phase['http_failures'] = observations.failures
            load_write_artifact(artifact_path, artifact)
        assert load_source_evidence(service.root) == snapshot
        artifact['stage'] = 'final_stop'
        await service.stop()
        artifact['status'] = 'passed'
  except BaseException as error:
    artifact.update(status='failed', failure={'type': type(error).__name__, 'message': str(error)[:4000]})
    raise
  finally:
    artifact['cpu_profile'] = service.cpu_evidence
    artifact['startup_attempts'] = service.startup_attempts
    load_write_artifact(artifact_path, artifact)


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True}], indirect=True)
async def test_resolution_load_shutdown_drains_accepted_writer_backlog(e2e_service, tmp_path):
  """Stop only after every source command is admitted but real receipts remain pending."""
  service = e2e_service
  configuration = resolution_load_configuration()
  dataset = ResolutionLoadDataset(8192, configuration)
  snapshot = load_source_evidence(service.root)
  artifact = {'status': 'in_progress', 'source_sha256': snapshot, 'dataset': dataset.manifest(), 'stage': 'cpu_profile'}
  artifact_path = tmp_path / 'shutdown-backlog.json'
  try:
    with service.cpu_profile(configuration['cpu_profile']):
      artifact['stage'] = 'initial_startup'
      await service.start()
      artifact['stage'] = 'dns_setup'
      await load_public_setup(service, 30)
      artifact['stage'] = 'initial_stop'
      await service.stop()
      artifact['stage'] = 'offline_seed'
      load_prepare_offline(service, dataset, stale=True)
      service.providers.response_factory = dataset.response
      artifact['effective_settings'] = load_effective_settings(service)
      assert float(artifact['effective_settings']['DB_SHUTDOWN_TIMEOUT']) == 20
      artifact['stage'] = 'seeded_startup'
      await service.start()
      async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
        observations = LoadApiObservations(diagnostic=True)
        started = perf_counter()
        deadline = asyncio.get_running_loop().time() + 1800
        artifact['stage'] = 'admission_and_shutdown'
        async with asyncio.timeout_at(deadline):
          await load_api_request(client, observations, 'job', 'POST', '/commands/domains/resolve/stale', timeout=5)
          backlog = await load_wait_writer_backlog(
            client,
            dataset.count,
            max(0, deadline - asyncio.get_running_loop().time()),
            all_admitted=True,
          )
          # No file write or further HTTP request may turn this into an idle-stop test.
          artifact['pre_signal'] = backlog
          signalled = perf_counter()
          try:
            await service.stop()
          finally:
            artifact.update(
              snapshot_to_stop_seconds=signalled - backlog['observed_at_monotonic'],
              shutdown_seconds=perf_counter() - signalled,
              admission_and_shutdown_seconds=perf_counter() - started,
              http_exchanges=observations.requests,
            )
          assert artifact['admission_and_shutdown_seconds'] <= 1800
          assert 'DatabaseShutdownError' not in service.diagnostics()
          assert 'Application shutdown failed' not in service.diagnostics()
        artifact['stage'] = 'restart'
        await service.start()
        artifact['restart_verification'] = await load_verify_public(client, dataset, 1800)
        artifact['http'] = load_assert_api_limits(observations)
        assert load_source_evidence(service.root) == snapshot
        artifact['stage'] = 'final_stop'
        await service.stop()
        artifact['status'] = 'passed'
  except BaseException as error:
    artifact.update(status='failed', failure={'type': type(error).__name__, 'message': str(error)[:4000]})
    raise
  finally:
    artifact['cpu_profile'] = service.cpu_evidence
    artifact['startup_attempts'] = service.startup_attempts
    load_write_artifact(artifact_path, artifact)


def resolution_load_configuration():
  """Require explicit smoke selection; the normal load command uses the observed full scale."""
  supplied = json.loads(os.environ.get('GOST_LOAD_CONFIG', '{}'))
  assert isinstance(supplied, dict)
  configuration = {
    'profile': 'full',
    'n': 156298,
    'headroom': 0.2,
    'seed': 20261104,
    'repetitions': 3,
    'pass_timeout': 1800,
    'verify_timeout': 3600,
    'rss_limit_mb': 2048,
    'cpu_percent_limit': 200,
    'unique_ip_ratio': 0.7,
    'alias_every': 10,
    'provider_delay': 0.001,
    'warmup_size': 1024,
    'soak_cycles': 3,
    'probe_interval': 0.25,
    'baseline_samples': 20,
    'latency_factor': 10,
    'latency_slack': 0.1,
    'stages': ['baseline', 'warmup', 'healthy', 'degraded'],
    'candidate_names': None,
    'repetition_numbers': None,
    'diagnostic': False,
    'diagnostic_cold_only': False,
    'metrics_poll_interval': 0.05,
    'progress_writes': 'original',
    'cpu_profile': 'unrestricted',
    'full_size_stability': False,
    'candidates': [
      {'name': 'defaults', 'environment': {}},
      {
        'name': 'balanced',
        'environment': {
          'DOMAINS_RESOLVE_WORKER_LIMIT': '8',
          'DOMAINS_RESOLVE_SEMAPHORE_LIMIT': '32',
          'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT': '10',
          'REQ_MAX_CONNECTIONS': '16',
          'QUEUE_MAX_SIZE': '512',
          'DB_SAVE_BATCH_SIZE': '256',
          'DB_SAVE_BATCH_TIMEOUT': '0.25',
        },
      },
    ],
  }
  assert set(supplied) <= set(configuration) | {'factors'}, 'Unknown load configuration field'
  configuration.update(supplied)
  assert configuration['profile'] in {'full', 'smoke'}
  assert configuration['cpu_profile'] in {'unrestricted', 'performance', 'efficiency'}
  assert type(configuration['full_size_stability']) is bool
  assert type(configuration['diagnostic']) is bool
  assert type(configuration['diagnostic_cold_only']) is bool
  assert configuration['progress_writes'] in {'original', 'deferred'}
  assert type(configuration['metrics_poll_interval']) in {int, float}
  assert math.isfinite(configuration['metrics_poll_interval'])
  assert 0.05 <= configuration['metrics_poll_interval'] <= 1
  if not configuration['diagnostic']:
    assert not configuration['diagnostic_cold_only']
    assert configuration['progress_writes'] == 'original'
    assert configuration['metrics_poll_interval'] == 0.05
  for key in ('n', 'seed', 'repetitions', 'warmup_size', 'soak_cycles', 'baseline_samples', 'alias_every'):
    assert isinstance(configuration[key], int), key
    assert configuration[key] > 0, key
  for key in (
    'pass_timeout',
    'verify_timeout',
    'rss_limit_mb',
    'cpu_percent_limit',
    'probe_interval',
    'latency_factor',
    'latency_slack',
    'unique_ip_ratio',
  ):
    assert math.isfinite(configuration[key]), key
    assert configuration[key] > 0, key
  assert 0 <= configuration['provider_delay'] <= 1
  assert 0 <= configuration['headroom'] <= 1
  assert configuration['unique_ip_ratio'] <= 1
  assert configuration['pass_timeout'] <= 1800, 'Source passes must finish through known writer outcomes within 1800s'
  assert configuration['n'] <= 1_000_000, 'Increase the explicit dataset safety bound before a larger campaign'
  assert 1 <= len(configuration['candidates']) <= 3
  assert configuration['candidates'][0] == {'name': 'defaults', 'environment': {}}
  names = [candidate['name'] for candidate in configuration['candidates']]
  assert len(set(names)) == len(names)
  assert configuration['stages']
  assert len(set(configuration['stages'])) == len(configuration['stages'])
  assert set(configuration['stages']) <= {'baseline', 'warmup', 'healthy', 'degraded'}
  candidate_names = configuration['candidate_names']
  assert candidate_names is None or (candidate_names and set(candidate_names) <= set(names))
  repetition_numbers = configuration['repetition_numbers']
  assert repetition_numbers is None or (
    repetition_numbers
    and all(isinstance(value, int) and 1 <= value <= configuration['repetitions'] for value in repetition_numbers)
    and len(set(repetition_numbers)) == len(repetition_numbers)
  )
  # Candidates may change performance knobs, never isolation, durability or freshness.
  permitted = {
    'DOMAINS_RESOLVE_WORKER_LIMIT',
    'DOMAINS_RESOLVE_SEMAPHORE_LIMIT',
    'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT',
    'REQ_MAX_CONNECTIONS',
    'REQ_MAX_KEEPALIVE_CONNECTIONS',
    'QUEUE_MAX_SIZE',
    'DB_SAVE_BATCH_SIZE',
    'DB_SAVE_BATCH_TIMEOUT',
    'DNS_TIMEOUT',
    'DNS_LIFETIME',
    'DNS_OPERATION_TIMEOUT',
    'DOH_TIMEOUT_CONNECT',
    'DOH_TIMEOUT_READ',
    'DOH_TIMEOUT_WRITE',
    'DOH_TIMEOUT_POOL',
    'DOH_OPERATION_TIMEOUT',
    'DOH_CONNECTION_RETRIES',
    'DOH_RETRY_TOTAL_TIMEOUT',
    'RIPE_STAT_TIMEOUT_CONNECT',
    'RIPE_STAT_TIMEOUT_READ',
    'RIPE_STAT_TIMEOUT_WRITE',
    'RIPE_STAT_TIMEOUT_POOL',
    'RIPE_STAT_OPERATION_TIMEOUT',
    'RIPE_STAT_CONNECTION_RETRIES',
    'RIPE_STAT_RETRY_TOTAL_TIMEOUT',
    'RIPE_STAT_PREFIX_CACHE_TTL_SEC',
    'RIPE_STAT_EMPTY_PREFIX_CACHE_TTL_SEC',
    'RIPE_STAT_CACHE_LOCK_TTL_SEC',
    'RIPE_STAT_CACHE_SIZE',
  }
  for candidate in configuration['candidates']:
    assert set(candidate) == {'name', 'environment'}
    assert set(candidate['environment']) <= permitted
    assert all(isinstance(value, str) for value in candidate['environment'].values())
  factors = configuration.setdefault('factors', [0.5, 1, 1 + configuration['headroom']])
  assert factors
  assert all(math.isfinite(value) and 0 < value <= 2 for value in factors)
  if configuration['profile'] == 'full':
    assert configuration['repetitions'] >= 3
    assert factors == [0.5, 1, 1 + configuration['headroom']]
    assert configuration['soak_cycles'] >= 3
  if configuration['full_size_stability']:
    assert configuration['profile'] == 'full'
    assert configuration['n'] == 156298
    assert configuration['headroom'] == 0.2
    assert configuration['seed'] == 20261104
    assert configuration['unique_ip_ratio'] == 0.7
    assert configuration['alias_every'] == 10
    assert configuration['provider_delay'] == 0.001
    assert configuration['probe_interval'] == 0.25
    assert set(configuration['stages']) == {'warmup', 'healthy', 'degraded'}
    assert configuration['repetition_numbers'] is None
    assert configuration['soak_cycles'] == 3
    assert not configuration['diagnostic']
    assert configuration['cpu_profile'] != 'unrestricted'
    assert configuration['candidate_names'] is not None
    assert len(configuration['candidate_names']) == 1
    selected_candidate = next(
      candidate for candidate in configuration['candidates'] if candidate['name'] in configuration['candidate_names']
    )
    assert selected_candidate['environment'] == {
      'DOMAINS_RESOLVE_WORKER_LIMIT': '32',
      'DOMAINS_RESOLVE_SEMAPHORE_LIMIT': '64',
      'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT': '16',
      'REQ_MAX_CONNECTIONS': '32',
      'REQ_MAX_KEEPALIVE_CONNECTIONS': '32',
      'QUEUE_MAX_SIZE': '10000',
      'DB_SAVE_BATCH_SIZE': '1000',
      'DB_SAVE_BATCH_TIMEOUT': '0.1',
    }, 'Stability replay must retain the original workload candidate'
  return configuration


@pytest.mark.parametrize(
  'selection',
  [
    {'stages': []},
    {'stages': ['unknown']},
    {'candidate_names': []},
    {'candidate_names': ['missing']},
    {'repetition_numbers': [0]},
    {'repetition_numbers': [4]},
    {'repetition_numbers': [1, 1]},
    {'diagnostic': 'yes'},
    {'diagnostic_cold_only': True},
    {'metrics_poll_interval': 1},
    {'progress_writes': 'deferred'},
    {'diagnostic': True, 'metrics_poll_interval': True},
    {'diagnostic': True, 'metrics_poll_interval': float('nan')},
    {'diagnostic': True, 'metrics_poll_interval': 0.049},
    {'diagnostic': True, 'progress_writes': 'silent'},
  ],
)
def test_resolution_load_replay_rejects_invalid_selection(monkeypatch, selection):
  """Replay may narrow declared cases but cannot silently accept an empty or out-of-range selection."""
  monkeypatch.setenv('GOST_LOAD_CONFIG', json.dumps(selection))
  with pytest.raises(AssertionError):
    resolution_load_configuration()


def test_resolution_load_diagnostic_controls_preserve_workload_and_require_explicit_selection(monkeypatch):
  monkeypatch.setenv('GOST_LOAD_CONFIG', '{}')
  original = resolution_load_configuration()
  controls = {
    'diagnostic': True,
    'diagnostic_cold_only': True,
    'metrics_poll_interval': 1,
    'progress_writes': 'deferred',
  }
  monkeypatch.setenv('GOST_LOAD_CONFIG', json.dumps(controls))
  assert resolution_load_configuration() == original | controls


@pytest.mark.parametrize(
  ('budget', 'elapsed', 'valid'), [(1800, 1800, True), (1800, 1800.001, False), (2, 2.001, False)]
)
def test_resolution_load_source_budget_rejects_late_completion_and_preserves_facts(budget, elapsed, valid):
  measurement = {
    'source_pass_status': 'completed',
    'wall_seconds_to_known_writer_outcomes': elapsed,
    'run': {'confirmed': 1},
  }
  if valid:
    load_assert_source_budget(measurement, {'pass_timeout': budget})
  else:
    with pytest.raises(AssertionError, match='Source pass exceeded'):
      load_assert_source_budget(measurement, {'pass_timeout': budget})
  assert measurement['source_budget']['within_maximum'] is valid
  assert measurement['source_pass_status'] == 'completed'
  assert measurement['run'] == {'confirmed': 1}


@pytest.mark.parametrize(('profile', 'expected'), [('performance', 0b0010), ('efficiency', 0b1100)])
@pytest.mark.parametrize('exit_mode', ['success', 'failure', 'cancel', 'partial_setup'])
@pytest.mark.parametrize('e2e_service', [{'start': False}], indirect=True)
def test_resolution_cpu_profile_scopes_allowed_masks_and_restores_on_every_exit(
  e2e_service, monkeypatch, profile, expected, exit_mode
):
  service = e2e_service
  boundary = sys.modules[type(service).__module__]
  state = {'mask': 0b1110}
  changes = []

  def set_mask(mask):
    state['mask'] = mask
    changes.append(mask)
    if exit_mode == 'partial_setup' and len(changes) == 1:
      raise RuntimeError('Verification failed after setting affinity')
    return mask

  monkeypatch.setattr(boundary, 'load_cpu_mask', lambda: state['mask'])
  monkeypatch.setattr(boundary, 'load_set_cpu_mask', set_mask)
  monkeypatch.setattr(
    boundary,
    'load_cpu_topology',
    lambda: [{'efficiency_class': 3, 'mask': 0b0011}, {'efficiency_class': 1, 'mask': 0b1100}],
  )
  primary = asyncio.CancelledError('cancel CPU scope') if exit_mode == 'cancel' else RuntimeError('scenario failed')

  def exercise():
    with service.cpu_profile(profile) as evidence:
      assert state['mask'] == expected
      assert evidence['requested_mask'] == evidence['effective_mask'] == expected
      assert evidence['runner_pid'] == os.getpid()
      assert json.loads(service.environment['TEST_CPU_PROFILE'])['profile'] == profile
      if exit_mode in {'failure', 'cancel'}:
        raise primary

  if exit_mode == 'success':
    exercise()
  else:
    with pytest.raises(type(primary)) as caught:
      exercise()
    if exit_mode != 'partial_setup':
      assert caught.value is primary
  assert state['mask'] == 0b1110
  assert changes == [expected, 0b1110]
  assert 'TEST_CPU_PROFILE' not in service.environment


@pytest.mark.parametrize(
  ('topology', 'allowed'),
  [
    ([{'efficiency_class': 0, 'mask': 3}], 3),
    ([{'efficiency_class': 0, 'mask': 1}, {'efficiency_class': 1, 'mask': 2}], 1),
  ],
)
@pytest.mark.parametrize('e2e_service', [{'start': False}], indirect=True)
def test_resolution_cpu_profile_rejects_missing_class_or_unavailable_processors(e2e_service, topology, allowed):
  boundary = sys.modules[type(e2e_service).__module__]
  with pytest.raises(RuntimeError, match=r'unavailable|no allowed'):
    boundary.load_cpu_profile_mask('performance', topology, allowed)


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows affinity boundary')
@pytest.mark.parametrize('profile', ['performance', 'efficiency'])
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True}], indirect=True)
async def test_resolution_cpu_profile_applies_to_actual_application_before_startup_and_restart(e2e_service, profile):
  service = e2e_service
  boundary = sys.modules[type(service).__module__]
  original = boundary.load_cpu_mask()
  with service.cpu_profile(profile) as runner:
    for _ in range(2):
      await service.start()
      try:
        async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
          pid = application_pid(parse_samples((await client.get('/metrics')).text))
        actual = service.startup_attempts[-1]['cpu']
        assert actual['application_pid'] == pid
        assert actual['runner_pid'] == os.getpid()
        assert actual['requested_mask'] == actual['application_effective_mask'] == boundary.load_cpu_mask()
        assert runner['requested_mask'] & original == runner['requested_mask']
      finally:
        await service.stop()
  assert runner['restored_mask'] == boundary.load_cpu_mask() == original


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows affinity boundary')
@pytest.mark.parametrize('profile', ['performance', 'efficiency'])
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True}], indirect=True)
async def test_resolution_cpu_profile_small_load_preserves_public_results_and_runner_resources(
  e2e_service, tmp_path, monkeypatch, profile
):
  """Exercise the actual load orchestrator with disposable public API data on each CPU class."""
  supplied = {
    'profile': 'smoke',
    'n': 8,
    'repetitions': 1,
    'factors': [1],
    'soak_cycles': 3,
    'warmup_size': 4,
    'baseline_samples': 2,
    'pass_timeout': 30,
    'verify_timeout': 30,
    'stages': ['warmup', 'healthy', 'degraded'],
    'candidate_names': ['small'],
    'cpu_profile': profile,
    'candidates': [
      {'name': 'defaults', 'environment': {}},
      {'name': 'small', 'environment': {'DB_SAVE_BATCH_TIMEOUT': '0.1'}},
    ],
  }
  monkeypatch.setenv('GOST_LOAD_CONFIG', json.dumps(supplied))
  observed_pids = []
  original_start = e2e_service.start

  async def start_and_observe():
    await original_start()
    async with httpx.AsyncClient(base_url=e2e_service.url, timeout=5, trust_env=False) as client:
      async with asyncio.timeout(5):
        response = await client.get('/metrics')
        assert response.status_code == 200
        observed_pids.append(application_pid(parse_samples(response.text)))

  monkeypatch.setattr(e2e_service, 'start', start_and_observe)
  await test_resolution_load_campaign(e2e_service, tmp_path)
  artifact = json.loads((tmp_path / 'resolution-load-campaign.json').read_text(encoding='utf-8'))
  assert artifact['status'] == 'passed'
  assert artifact['acceptance_scale'] is False
  assert artifact['cpu_profile']['profile'] == profile
  assert artifact['cpu_profile']['restored_mask'] == artifact['cpu_profile']['original_mask']
  startups = artifact['startup_attempts']
  assert len(startups) == len(observed_pids) == 8
  assert all(attempt['status'] == 'ready' for attempt in startups)
  assert [attempt['cpu']['application_pid'] for attempt in startups] == observed_pids
  assert all(
    attempt['cpu']['application_effective_mask'] == artifact['cpu_profile']['requested_mask'] for attempt in startups
  )
  assert artifact['idle_api_baseline']['p99_bounds_seconds'] == dict.fromkeys(
    artifact['idle_api_baseline']['bounds_seconds'], 1.0
  )
  assert [(case['schedule'], case['cache']) for case in artifact['cases'] if case['measured']] == [
    ('healthy', 'cold'),
    ('healthy', 'warm'),
    ('degraded', 'cold'),
    ('degraded', 'warm'),
  ]
  for case in artifact['cases']:
    assert case['status'] == 'passed'
    assert case['verification']['verified_sources'] == case['size']
    assert case['measurement']['source_budget']['within_maximum'] is True
    assert case['measurement']['cpu']['application_pid'] != case['measurement']['cpu']['runner_pid']
    assert len(case['measurement']['runner_resource_samples']) >= 2
    assert case['measurement']['api_status'] == 'passed'
    if case['cache'] == 'warm':
      assert case['restart_verification']['verified_sources'] == case['size']


@pytest.mark.parametrize(
  'override',
  [
    {},
    {'pass_timeout': 1801},
    {'soak_cycles': 4},
    {'repetition_numbers': [1]},
    {'cpu_profile': 'unrestricted'},
    {'n': 10},
    {'stages': ['healthy', 'degraded']},
    {'candidate_names': ['defaults']},
  ],
)
def test_resolution_load_full_size_stability_requires_unchanged_workload_and_complete_repetitions(
  monkeypatch, override
):
  supplied = {
    'full_size_stability': True,
    'cpu_profile': 'performance',
    'stages': ['warmup', 'healthy', 'degraded'],
    'candidate_names': ['original'],
    'candidates': [
      {'name': 'defaults', 'environment': {}},
      {
        'name': 'original',
        'environment': {
          'DOMAINS_RESOLVE_WORKER_LIMIT': '32',
          'DOMAINS_RESOLVE_SEMAPHORE_LIMIT': '64',
          'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT': '16',
          'REQ_MAX_CONNECTIONS': '32',
          'REQ_MAX_KEEPALIVE_CONNECTIONS': '32',
          'QUEUE_MAX_SIZE': '10000',
          'DB_SAVE_BATCH_SIZE': '1000',
          'DB_SAVE_BATCH_TIMEOUT': '0.1',
        },
      },
    ],
  }
  monkeypatch.setenv('GOST_LOAD_CONFIG', json.dumps(supplied | override))
  if override:
    with pytest.raises(AssertionError):
      resolution_load_configuration()
  else:
    configuration = resolution_load_configuration()
    assert configuration['pass_timeout'] == 1800
    assert configuration['repetitions'] == configuration['soak_cycles'] == 3
    assert configuration['factors'] == [0.5, 1, 1.2]
    assert math.ceil(configuration['n'] * max(configuration['factors'])) == 187558


@pytest.mark.parametrize('e2e_service', [{'start': False}], indirect=True)
def test_resolution_cpu_restoration_failure_keeps_original_error_and_diagnostic(e2e_service, monkeypatch):
  service = e2e_service
  boundary = sys.modules[type(service).__module__]
  changes = []

  def set_mask(mask):
    changes.append(mask)
    if len(changes) == 2:
      raise OSError('restore failed')
    return mask

  monkeypatch.setattr(boundary, 'load_cpu_mask', lambda: 3)
  monkeypatch.setattr(
    boundary, 'load_cpu_topology', lambda: [{'efficiency_class': 1, 'mask': 1}, {'efficiency_class': 0, 'mask': 2}]
  )
  monkeypatch.setattr(boundary, 'load_set_cpu_mask', set_mask)
  original = RuntimeError('original failure')
  with pytest.raises(RuntimeError) as caught:
    with service.cpu_profile('performance'):
      raise original
  assert caught.value is original
  assert changes == [1, 3]
  assert service.cpu_evidence['restore_error'] == "OSError('restore failed')"
  assert caught.value.__notes__ == ["CPU affinity restoration failed: OSError('restore failed')"]
  assert 'TEST_CPU_PROFILE' not in service.environment


@pytest.mark.parametrize('e2e_service', [{'start': False}], indirect=True)
async def test_resolution_cpu_profile_startup_failure_restores_mask_and_closes_partial_log(e2e_service, monkeypatch):
  service = e2e_service
  boundary = sys.modules[type(service).__module__]
  state = {'mask': 3}

  def set_mask(mask):
    state['mask'] = mask
    return mask

  monkeypatch.setattr(boundary, 'load_cpu_mask', lambda: state['mask'])
  monkeypatch.setattr(
    boundary, 'load_cpu_topology', lambda: [{'efficiency_class': 1, 'mask': 1}, {'efficiency_class': 0, 'mask': 2}]
  )
  monkeypatch.setattr(boundary, 'load_set_cpu_mask', set_mask)
  primary = OSError('child creation failed')
  monkeypatch.setattr(asyncio, 'create_subprocess_exec', AsyncMock(side_effect=primary))
  with pytest.raises(OSError, match='child creation failed') as caught:
    with service.cpu_profile('performance'):
      await service.start()
  assert caught.value is primary
  assert state['mask'] == 3
  assert service.cpu_evidence['restored_mask'] == 3
  assert service.process is None
  assert service.log is None
  assert service.startup_attempts[-1]['status'] == 'failed'
  assert 'TEST_CPU_PROFILE' not in service.environment


@pytest.mark.parametrize('e2e_service', [{'start': False}], indirect=True)
def test_resolution_cpu_profile_rejects_unsupported_platform_without_mutation(e2e_service, monkeypatch):
  service = e2e_service
  boundary = sys.modules[type(service).__module__]
  with monkeypatch.context() as scoped:
    scoped.setattr(boundary.sys, 'platform', 'unsupported')
    with pytest.raises(RuntimeError, match='require 64-bit Windows'):
      with service.cpu_profile('performance'):
        pytest.fail('Unsupported platforms must not enter a controlled measurement')
  assert service.cpu_evidence['affinity_changed'] is False
  assert 'TEST_CPU_PROFILE' not in service.environment


class ResolutionLoadDataset:
  """Generate independent protocol inputs and expected persisted outcomes without application imports."""

  old_address = '9.9.9.9'
  ipv6 = '2001:4860:4860::8888'

  def __init__(self, count, configuration):
    self.count = count
    self.seed = configuration['seed']
    self.groups = max(1, math.ceil(count * configuration['unique_ip_ratio']))
    self.group_stride = 7919
    while math.gcd(self.group_stride, self.groups) != 1:
      self.group_stride += 1
    self.alias_every = configuration['alias_every']
    self.delay = configuration['provider_delay']
    self.schedule = 'healthy'

  def name(self, index):
    return f'd{index:07d}.s{(index * 31 + self.seed) % 17}.load.example.test'

  def index(self, name):
    if not name.startswith('d') or '.load.example.test' not in name:
      return None
    try:
      index = int(name.split('.', 1)[0][1:])
    except ValueError:
      return None
    return index if 0 <= index < self.count and self.name(index) == name else None

  def addresses(self, index):
    group = (index * self.group_stride + self.seed) % self.groups
    base = int(IPv4Address('11.0.0.0')) + group * 256
    return str(IPv4Address(base)), str(IPv4Address(base + 1)), str(IPv4Address(base + 2))

  def aliases(self, index):
    if self.sentinel(index):
      return ()
    if index % self.alias_every or self.count < 3:
      return ()
    return (self.name((index + 1) % self.count), self.name((index + 2) % self.count))

  def category(self, index):
    if self.sentinel(index) in {'dns-drop', 'dns-malformed'}:
      return 'failure'
    if self.sentinel(index):
      return 'success'
    partition = (index + self.seed) % 20
    if partition in {0, 1}:
      return 'empty'
    if self.schedule == 'degraded' and partition in {2, 4}:
      return 'partial'
    if self.schedule == 'degraded' and partition == 3:
      return 'failure'
    return 'success'

  def expected(self, index):
    sentinel = self.sentinel(index)
    if sentinel in {'dns-drop', 'dns-malformed'}:
      return {self.old_address}, False
    if sentinel.startswith('ripe-'):
      base = f'31.249.{index}.0'
      return {f'{base}/24' if sentinel == 'ripe-slow' else base}, True
    category = self.category(index)
    base, first, second = self.addresses(index)
    prefix = base if int(base.split('.')[2]) % 7 == 0 else f'{base}/24'
    if category == 'empty':
      return set(), True
    if category == 'failure':
      return {self.old_address}, False
    addresses = {prefix, first}
    if category != 'partial' or (index + self.seed) % 20 == 4:
      addresses.add(second)
    if category == 'partial' and (index + self.seed) % 20 == 4:
      addresses = {second}
    if index % 3 == 0 and not (category == 'partial' and (index + self.seed) % 20 == 4):
      addresses.add('8.8.8.8')
    if category == 'partial':
      addresses.add(self.old_address)
    return addresses, category != 'partial'

  def sentinel(self, index):
    """Keep expensive failures fixed in number, independent of the scale ladder."""
    kinds = ('dns-drop', 'dns-malformed', 'dns-slow', 'ripe-drop', 'ripe-malformed', 'ripe-slow')
    return kinds[index] if self.schedule == 'degraded' and index < len(kinds) else ''

  def response(self, transport, name, rdtype, attempt, cycle):
    del cycle
    if transport == 'ripe':
      if name.startswith('31.249.'):
        sentinel = self.sentinel(int(name.split('.')[2]))
        if sentinel in {'ripe-drop', 'ripe-malformed'}:
          return {'kind': sentinel.removeprefix('ripe-')}
        return {'kind': 'positive', 'prefix': f'{name}/24', 'delay': 0.25}
      return {
        'kind': 'empty' if int(name.split('.')[2]) % 7 == 0 else 'positive',
        'prefix': None if int(name.split('.')[2]) % 7 == 0 else f'{name}/24',
        'delay': self.delay * (1 + int(name.split('.')[2]) % 4),
      }
    index = self.index(name)
    if index is None:
      return {'kind': 'positive' if rdtype == dns.rdatatype.A else 'nodata', 'addresses': ('8.8.4.4',)}
    if rdtype != dns.rdatatype.A:
      return {'kind': 'nodata'}
    sentinel = self.sentinel(index)
    if sentinel in {'dns-drop', 'dns-malformed'}:
      return {'kind': sentinel.removeprefix('dns-')}
    if sentinel.startswith('ripe-'):
      return {'kind': 'positive', 'addresses': (f'31.249.{index}.0',)}
    category = self.category(index)
    partition = (index + self.seed) % 20
    step = {'delay': self.delay * (1 + (index * 13 + self.seed) % 5)}
    if sentinel == 'dns-slow':
      step['delay'] = 0.25
    if category == 'empty':
      return {**step, 'kind': 'nodata' if partition == 0 else 'nxdomain'}
    if category == 'failure' or (category == 'partial' and transport == ('doh' if partition == 2 else 'classic')):
      return {**step, 'kind': 'servfail'}
    base, first, second = self.addresses(index)
    addresses = (base, first, *(('8.8.8.8',) if index % 3 == 0 else ())) if transport == 'classic' else (second,)
    aliases = self.aliases(index)
    if self.schedule == 'degraded' and transport == 'doh' and index % 11 == 0 and attempt == 1:
      step.update(status=429, retry_after='0')
    return {
      **step,
      'kind': 'alias-chain-positive' if aliases else 'positive',
      'addresses': addresses,
      'aliases': aliases,
    }

  def manifest(self):
    digest = sha256()
    categories = dict.fromkeys(('success', 'empty', 'partial', 'failure'), 0)
    actual_groups = set()
    for index in range(self.count):
      actual_groups.add(self.addresses(index)[0])
      expected, complete = self.expected(index)
      categories[self.category(index)] += 1
      digest.update(json.dumps([self.name(index), sorted(expected), complete, self.aliases(index)]).encode())
    assert len(actual_groups) == self.groups, (len(actual_groups), self.groups)
    return {
      'count': self.count,
      'unique_ip_groups': self.groups,
      'actual_unique_ip_groups': len(actual_groups),
      'group_stride': self.group_stride,
      'fixed_fault_sentinels': {
        self.name(index): self.sentinel(index) for index in range(min(6, self.count)) if self.sentinel(index)
      },
      'categories': categories,
      'sha256': digest.hexdigest(),
    }


@pytest.mark.parametrize('count', [1, 32, 11312, 15838])
def test_resolution_load_dataset_preserves_declared_ip_diversity(count):
  """Every declared group occurs, including when the old stride divides the group count."""
  configuration = {'seed': 20261104, 'unique_ip_ratio': 0.7, 'alias_every': 10, 'provider_delay': 0.001}
  dataset = ResolutionLoadDataset(count, configuration)
  bases = {dataset.addresses(index)[0] for index in range(count)}
  assert len(bases) == math.ceil(count * 0.7)
  assert dataset.manifest()['actual_unique_ip_groups'] == len(bases)


def load_quantiles(values):
  """Report exact nearest-rank empirical quantiles, retaining a separate maximum."""
  ordered = sorted(values)
  return {
    'count': len(ordered),
    'method': 'nearest-rank empirical samples',
    **{
      name: ordered[max(0, math.ceil(len(ordered) * q) - 1)] if ordered else None
      for name, q in [('p50', 0.5), ('p95', 0.95), ('p99', 0.99), ('max', 1)]
    },
  }


def load_source_evidence(root):
  paths = [root / 'main.py', root / 'pyproject.toml', root / 'poetry.lock']
  for directory in (
    'cache',
    'client',
    'config',
    'database',
    'jobs',
    'logger',
    'metrics',
    'migrations',
    'models',
    'routers',
    'server',
    'utils',
  ):
    paths.extend(sorted((root / directory).rglob('*.py')))
  paths.extend([root / 'tests/conftest.py', root / 'tests/integration' / Path(__file__).name])
  return {path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest() for path in paths}


@pytest.mark.parametrize('material_path', ['cache/cache.py', 'utils/address.py', 'logger/logger.py'])
def test_resolution_load_source_evidence_tracks_material_dependency_changes(tmp_path, material_path):
  """Reproducible measurements must distinguish changes in every application dependency."""
  required = [
    'main.py',
    'pyproject.toml',
    'poetry.lock',
    'tests/conftest.py',
    f'tests/integration/{Path(__file__).name}',
  ]
  for name in [*required, material_path]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('original input\n', encoding='utf-8')
  before = load_source_evidence(tmp_path)
  assert load_source_evidence(tmp_path) == before
  assert material_path in before

  (tmp_path / material_path).write_text('changed input\n', encoding='utf-8')
  after = load_source_evidence(tmp_path)
  assert after != before
  assert {name for name in before if before[name] != after[name]} == {material_path}
  assert set(after) == set(before)


def load_effective_settings(service):
  """Read declarative defaults without importing the composition or secret-loading settings module."""
  tree = ast.parse((service.root / 'config/config.py').read_text(encoding='utf-8'))
  values = {}
  prefixes = ('db_', 'domains_', 'queue_', 'dns_', 'doh_', 'ripe_', 'req_')
  for node in ast.walk(tree):
    if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
      continue
    name = node.target.id
    if not name.startswith(prefixes) or not isinstance(node.value, ast.Call):
      continue
    for keyword in node.value.keywords:
      if keyword.arg == 'default':
        values[name.upper()] = ast.literal_eval(keyword.value)
  return {key: service.environment.get(key, value) for key, value in values.items()}


def load_write_artifact(path, artifact):
  def json_value(value):
    if isinstance(value, float) and not math.isfinite(value):
      return {'nonfinite_metric': str(value)}
    if isinstance(value, dict):
      return {key: json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
      return [json_value(item) for item in value]
    return value

  path.write_text(json.dumps(json_value(artifact), indent=2, allow_nan=False), encoding='utf-8')


def load_prepare_offline(service, dataset, *, stale=False, reset=False):
  """Prepare only this fixture's closed disposable database; never observe runtime outcomes with SQL."""
  assert service.process is None
  assert service.db_path.resolve().is_relative_to(service.directory.resolve())
  assert service.db_path.resolve() != (service.root / 'db/rdpr-db.sqlite').resolve()
  started = perf_counter()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute('PRAGMA foreign_keys=ON')
    if reset:
      connection.execute('DELETE FROM rdpr_ip_supports WHERE domain_id>0')
      connection.execute('DELETE FROM rdpr_ip_records WHERE id>0')
      connection.execute('DELETE FROM rdpr_domains WHERE id>0')
    checkpoint = '2000-01-01 00:00:00' if stale else None
    dataset.initial_checkpoint = checkpoint
    connection.executemany(
      'INSERT INTO rdpr_domains (id,name,resolved,last_resolved_at) VALUES (?,?,?,?)',
      ((index + 1, dataset.name(index), bool(stale), checkpoint) for index in range(dataset.count)),
    )
    connection.execute(
      "INSERT INTO rdpr_domains (id,name,resolved,last_resolved_at) VALUES (?,?,1,'2100-01-01 00:00:00')",
      (dataset.count + 1, 'api-probe.load.example.test'),
    )
    connection.executemany(
      'INSERT INTO rdpr_ip_records (id,domain_id,addr_type,ip_address) VALUES (?,1,?,?)',
      [(1, 4, dataset.old_address), (2, 6, dataset.ipv6)],
    )
    connection.executemany(
      'INSERT INTO rdpr_ip_supports (ip_record_id,domain_id) VALUES (?,?)',
      ((ip_id, index + 1) for index in range(dataset.count) for ip_id in (1, 2)),
    )
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == [], 'Invalid offline fixture'
  return perf_counter() - started


def load_database_input_evidence(service):
  """Observe only the closed disposable fixture before starting its application process."""
  assert service.process is None
  assert service.db_path.resolve().is_relative_to(service.directory.resolve())
  with closing(sqlite3.connect(service.db_path.as_uri() + '?mode=ro', uri=True)) as connection:
    return {
      'bytes': service.db_path.stat().st_size,
      'pragmas': {
        name: connection.execute(f'PRAGMA {name}').fetchone()[0]
        for name in (
          'page_count',
          'freelist_count',
          'page_size',
          'journal_mode',
          'schema_version',
        )
      },
      'ip_read_plan': connection.execute(
        'EXPLAIN QUERY PLAN SELECT id, ip_address, addr_type FROM rdpr_ip_records '
        'WHERE id IN (SELECT ip_record_id FROM rdpr_ip_supports WHERE domain_id=?)',
        (1,),
      ).fetchall(),
      'indexes': connection.execute("SELECT name, sql FROM sqlite_schema WHERE type='index' ORDER BY name").fetchall(),
    }


async def load_public_setup(service, timeout):
  async with httpx.AsyncClient(base_url=service.url, timeout=timeout, trust_env=False) as client:
    response = await client.post('/dns', json=[{'server': service.dns_host}, {'doh_server': service.doh_url}])
    assert response.status_code == 200, response.text
    async with asyncio.timeout(timeout):
      while True:
        rows = (await client.get('/dns', params={'default': 'false'})).json()['payload']
        if len(rows) == 2:
          return
        await asyncio.sleep(0.02)


async def load_metrics_request(client, observer=None, *, scope='metrics'):
  """Keep optional scrape measurements separate from API acceptance samples."""
  if observer is None:
    return await client.get('/metrics')
  started = perf_counter()
  response = None
  failure = None
  try:
    response = await client.get('/metrics')
    assert response.status_code == 200, 'Metrics scrape failed'
    return response
  except BaseException as error:
    failure = type(error).__name__
    raise
  finally:
    ended = perf_counter()
    observer.append(
      {
        'scope': scope,
        'start_monotonic': started,
        'end_monotonic': ended,
        'elapsed_seconds': ended - started,
        'status_code': response.status_code if response is not None else None,
        'body_bytes': len(response.content) if response is not None else None,
        'error_type': failure,
      }
    )


async def load_wait_idle(
  client,
  mode,
  selected,
  previous,
  timeout,
  *,
  on_progress=None,
  metrics_poll_interval=0.05,
  metrics_observer=None,
  diagnostic=None,
):
  next_progress = 0.0
  async with asyncio.timeout(timeout):
    while True:
      before_request = perf_counter() if diagnostic is not None else 0
      response = await load_metrics_request(client, metrics_observer, scope='source_idle_poll')
      assert response.status_code == 200
      before_parse = perf_counter() if diagnostic is not None else 0
      samples = parse_samples(response.text)
      if diagnostic is not None:
        scrape = diagnostic.setdefault('metrics', {'count': 0, 'request_seconds': 0, 'parse_seconds': 0, 'bytes': 0})
        scrape['count'] += 1
        scrape['request_seconds'] += before_parse - before_request
        scrape['parse_seconds'] += perf_counter() - before_parse
        scrape['bytes'] += len(response.content)
      fields = run_fields(samples, mode)
      if on_progress is not None and perf_counter() >= next_progress:
        await on_progress(samples, fields)
        next_progress = perf_counter() + 10
      if (
        sample_total(samples, 'resolution_run_elapsed_seconds_count', mode=mode) > previous
        and fields.get('selected') == selected
        and fields.get('processing_complete') == 1
        and all(fields.get(key) == 0 for key in ('active', 'pending', 'admission_in_progress'))
      ):
        assert fields['unknown'] == fields['known_not_committed'] == fields['not_admitted'] == 0, fields
        assert fields['admitted'] == fields['confirmed'], fields
        assert fields['attempted'] == selected, fields
        return samples, fields
      await asyncio.sleep(metrics_poll_interval)


async def load_verify_public(client, dataset, timeout):
  """Exhaust every source row through the API, including shared ownership and IPv6 retention."""
  started = perf_counter()
  found = set()
  digest = sha256()
  async with asyncio.timeout(timeout):
    offset = 0
    while True:
      response = await client.get('/domains', params={'limit': 100, 'offset': offset})
      assert response.status_code == 200, response.text
      body = response.json()
      assert body['total'] == dataset.count + 2, body
      rows = body['payload']
      if not rows:
        break
      for row in rows:
        index = dataset.index(row['name'])
        if index is None:
          assert row['id'] in {0, dataset.count + 1}, row
          continue
        assert index not in found, row
        found.add(index)
        addresses, complete = dataset.expected(index)
        assert set(row['ips_v4'] or []) == addresses, (row['name'], addresses, row)
        assert set(row['ips_v6'] or []) == {dataset.ipv6}, row
        if complete:
          assert row['resolved'] is True, row
          assert row['last_resolved_at'] is not None, row
        else:
          assert row['last_resolved_at_hum'] == dataset.initial_checkpoint, row
          assert row['resolved'] is bool(dataset.initial_checkpoint), row
        digest.update(json.dumps([row['name'], sorted(addresses), sorted(row['ips_v6'])]).encode())
      offset += len(rows)
    assert found == set(range(dataset.count)), (len(found), dataset.count)
  return {
    'verified_sources': len(found),
    'api_result_sha256': digest.hexdigest(),
    'elapsed_seconds': perf_counter() - started,
  }


class LoadApiObservations(dict):
  """Retain per-route latency samples and diagnostic facts for failed exchanges."""

  def __init__(self, *, diagnostic=False):
    super().__init__()
    self.failures = []
    self.requests = [] if diagnostic else None


async def load_api_request(client, observations, label, method, path, *, timeout, statuses=(200,), **kwargs):
  """Measure and bound one HTTP exchange independently of background persistence."""
  limit = timeout[label] if isinstance(timeout, dict) else timeout
  started = perf_counter()
  response = None
  failure = None
  trace = [] if isinstance(observations, LoadApiObservations) and observations.requests is not None else None
  trace_callback_seconds = 0.0

  async def record_trace(event, info):
    # Event names and clocks suffice; transport info may contain headers or payloads.
    nonlocal trace_callback_seconds
    before = perf_counter()
    del info
    trace.append({'event': event, 'at_monotonic': perf_counter()})
    trace_callback_seconds += perf_counter() - before

  if trace is not None:
    kwargs['extensions'] = {**kwargs.get('extensions', {}), 'trace': record_trace}
  try:
    async with asyncio.timeout(limit):
      response = await client.request(method, path, **kwargs)
  except BaseException as error:
    failure = type(error).__name__
    raise
  finally:
    ended = perf_counter()
    elapsed = ended - started
    if response is not None:
      observations.setdefault(label, []).append(elapsed)
    status = response.status_code if response is not None else None
    if trace is not None:
      before_observation = perf_counter()
      duration = None
      if response is not None:
        try:
          body = response.json()
        except ValueError, UnicodeError:
          body = None
        if isinstance(body, dict) and type(body.get('duration')) in {int, float}:
          duration = body['duration'] if math.isfinite(body['duration']) else None
      observations.requests.append(
        {
          'route': label,
          'method': method,
          'path': path,
          'start_monotonic': started,
          'end_monotonic': ended,
          'elapsed_seconds': elapsed,
          'status_code': status,
          'body_bytes': len(response.content) if response is not None else None,
          'server_duration_seconds': duration,
          'error_type': failure,
          'transport_events': trace,
          'trace_callback_seconds': trace_callback_seconds,
        }
      )
      observations.requests[-1]['observation_seconds'] = perf_counter() - before_observation
    if isinstance(observations, LoadApiObservations) and (failure or elapsed > limit or status not in statuses):
      observations.failures.append(
        {
          'route': label,
          'method': method,
          'path': path,
          'elapsed_seconds': elapsed,
          'limit_seconds': limit,
          'status_code': status,
          'error_type': failure,
        }
      )
  assert elapsed <= limit, (label, method, path, elapsed, limit)
  assert response.status_code in statuses, (label, method, path, response.status_code, response.text)
  return response


async def load_api_round(client, dataset, observations, *, timeout, job_mode='stale'):
  """Keep representative reads and real job admission running independently of writer dwell."""
  operations = (
    ('read', 'GET', f'/domains/{dataset.count + 1}'),
    ('list', 'GET', '/domains?limit=10'),
    ('stats', 'GET', '/stats'),
    ('job', 'POST', f'/commands/domains/resolve/{job_mode}'),
  )
  if getattr(dataset, 'probe_ip_lists', False):
    operations += (('ip_lists', 'GET', '/ips/lists?limit=10'), ('ip_list', 'GET', '/ips/lists/1'))
  for label, method, path in operations:
    response = await load_api_request(client, observations, label, method, path, timeout=timeout)
    if label == 'read':
      assert response.json()['name'] == 'api-probe.load.example.test'
    elif label == 'ip_lists':
      assert [row['name'] for row in response.json()['payload']] == ['probe-addresses']
    elif label == 'ip_list':
      assert response.json()['name'] == 'probe-addresses'


async def load_probe_canaries(client, observations, finished, configuration, *, job_mode, request_timeout=5):
  """Own one domain at a time; bound its HTTP calls separately from its durable lifecycle."""
  lifecycles = []

  async def request(label, method, path, **kwargs):
    return await load_api_request(client, observations, label, method, path, timeout=request_timeout, **kwargs)

  while not finished.is_set() or not lifecycles:
    name = f'api-canary-{len(lifecycles):07d}.load.example.test'
    lifecycle = {'name': name, 'status': 'in_progress'}
    started = perf_counter()
    # Writer backlog may exceed a minute even while every HTTP exchange is fast.
    async with asyncio.timeout(configuration['pass_timeout']):
      await request('write', 'POST', '/domains', json=[{'domain': name}])
      while True:
        response = await request('search', 'GET', '/domains/search', params={'text': name})
        matches = [row for row in response.json()['payload'] if row['name'] == name]
        if matches:
          assert len(matches) == 1, matches
          row = matches[0]
          break
        await asyncio.sleep(0.05)
      lifecycle['id'] = row['id']
      lifecycle['creation_confirmed_seconds'] = perf_counter() - started
      # NEW probes during a STALE source pass own the canary. During NEW/idle,
      # explicit stored resolution avoids creating a successor source scan.
      if job_mode == 'stale':
        await request('stored_resolve', 'POST', f'/domains/{row["id"]}/resolve', statuses=(202,))
      while True:
        response = await request('read', 'GET', f'/domains/{row["id"]}')
        actual = response.json()
        if actual['last_resolved_at'] is not None:
          assert actual['name'] == name
          assert set(actual['ips_v4'] or []) == {'8.8.4.4'}, actual
          break
        if finished.is_set() and job_mode == 'new':
          # The main probe loop may already have ended before creation committed.
          await request('job', 'POST', '/commands/domains/resolve/new')
        await asyncio.sleep(0.05)
      lifecycle['resolution_confirmed_seconds'] = perf_counter() - started
      await request('delete', 'DELETE', f'/domains/{row["id"]}')
      while True:
        response = await request('read', 'GET', f'/domains/{row["id"]}', statuses=(200, 404))
        if response.status_code == 404:
          break
        await asyncio.sleep(0.05)
    lifecycle.update(status='passed', deleted=True, lifecycle_seconds=perf_counter() - started)
    lifecycles.append(lifecycle)
  return lifecycles


async def load_freeze_api_bounds(service, dataset, configuration):
  observations = LoadApiObservations()
  finished = asyncio.Event()
  async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:

    async def sample():
      for _ in range(configuration['baseline_samples']):
        await load_api_round(client, dataset, observations, timeout=5)
        await asyncio.sleep(configuration['probe_interval'])
      finished.set()

    sampler = asyncio.create_task(sample())
    canaries = asyncio.create_task(load_probe_canaries(client, observations, finished, configuration, job_mode='stale'))
    tasks = (sampler, canaries)
    try:
      pending = set(tasks)
      while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
          await task
      lifecycles = canaries.result()
    finally:
      finished.set()
      # Preserve the triggering failure, including cancellation and drain failures.
      for task in tasks:
        if not task.done():
          task.cancel()
      await asyncio.gather(*tasks, return_exceptions=True)
    # The empty stale job exercises real admission without changing the idle dataset.
    async with asyncio.timeout(configuration['pass_timeout']):
      while True:
        fields = run_fields(parse_samples((await client.get('/metrics')).text), 'stale')
        if fields and all(fields.get(key) == 0 for key in ('active', 'pending', 'admission_in_progress')):
          break
        await asyncio.sleep(0.05)
  quantiles = {name: load_quantiles(values) for name, values in observations.items()}
  return {
    'samples': quantiles,
    'canary_lifecycles': lifecycles,
    'bounds_seconds': dict.fromkeys(quantiles, 5.0),
    'p99_bounds_seconds': {name: 1.0 for name, values in quantiles.items()},
    'formula': 'request/max <= 5s; p99 <= 1s',
    'scope': 'finite conservative local campaign guardrails, not deployment or product SLAs',
    'frozen_before_candidate_measurements': True,
  }


@pytest.mark.parametrize(
  ('failure_source', 'cleanup_failure'),
  [
    ('sampler', False),
    ('canary', False),
    ('cancel', False),
    ('sampler', True),
    ('canary', True),
    ('cancel', True),
    ('drain_canary', False),
  ],
)
async def test_resolution_load_baseline_preserves_first_failure_and_retires_all_tasks(
  monkeypatch, failure_source, cleanup_failure
):
  """A baseline error or cancellation must retire its sibling without hiding the cause."""
  started = {name: asyncio.Event() for name in ('sampler', 'canary')}
  ended = {name: asyncio.Event() for name in started}
  sampled = asyncio.Event()
  tasks = {}
  primary = RuntimeError(f'{failure_source} failed first')
  secondary = ValueError('Sibling failed during cleanup')

  async def all_started():
    for ready in started.values():
      await ready.wait()

  async def request(request):
    route = (request.method, request.url.path)
    if route == ('GET', '/domains/2'):
      owner = 'sampler'
    elif route == ('POST', '/domains'):
      owner = 'canary'
    else:
      return httpx.Response(200, json={})
    tasks[owner] = asyncio.current_task()
    if owner == 'sampler':
      tasks[owner].add_done_callback(lambda task: sampled.set())
    started[owner].set()
    try:
      await all_started()
      if failure_source == owner:
        raise primary
      if failure_source == 'drain_canary':
        if owner == 'sampler':
          return httpx.Response(200, json={'name': 'api-probe.load.example.test'})
        await sampled.wait()
        raise primary
      await asyncio.Event().wait()
    except asyncio.CancelledError:
      if cleanup_failure:
        raise secondary from None
      raise
    finally:
      ended[owner].set()

  real_client = httpx.AsyncClient
  transport = httpx.MockTransport(request)
  monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=transport, **kwargs))
  observer = asyncio.create_task(
    load_freeze_api_bounds(
      SimpleNamespace(url='http://observer.test'),
      SimpleNamespace(count=1),
      {'baseline_samples': 1, 'probe_interval': 0, 'pass_timeout': 30},
    )
  )
  try:
    async with asyncio.timeout(1):
      await all_started()
      if failure_source == 'cancel':
        observer.cancel('cancel baseline')
      done, _ = await asyncio.wait((observer,), timeout=0.2)
      assert observer in done, 'Baseline did not promptly retire the pending sibling'
      expected = asyncio.CancelledError if failure_source == 'cancel' else RuntimeError
      with pytest.raises(expected) as caught:
        await observer
    if failure_source == 'cancel':
      assert caught.value.args == ('cancel baseline',)
    else:
      assert caught.value is primary
    assert set(tasks) == set(started)
    assert all(task.done() for task in tasks.values())
    assert all(event.is_set() for event in ended.values())
  finally:
    owned = [observer, *tasks.values()]
    for task in owned:
      if not task.done():
        task.cancel()
    await asyncio.gather(*owned, return_exceptions=True)


async def test_resolution_load_baseline_finishes_canary_lifecycle_before_freezing_bounds(monkeypatch):
  """Idle sampling uses STALE admission and drains the complete stored canary lifecycle."""
  started = {name: asyncio.Event() for name in ('sampler', 'canary')}
  sampled = asyncio.Event()
  deleted = asyncio.Event()
  tasks = {}
  requests = []

  async def request(request):
    route = (request.method, request.url.path)
    requests.append(route)
    if route == ('GET', '/domains/2'):
      tasks['sampler'] = asyncio.current_task()
      tasks['sampler'].add_done_callback(lambda task: sampled.set())
      started['sampler'].set()
      await started['canary'].wait()
    if route == ('POST', '/domains'):
      tasks['canary'] = asyncio.current_task()
      started['canary'].set()
      await sampled.wait()
    if route == ('GET', '/domains/search'):
      return httpx.Response(200, json={'payload': [{'id': 3, 'name': 'api-canary-0000000.load.example.test'}]})
    if route == ('POST', '/domains/3/resolve'):
      return httpx.Response(202, json={})
    if route == ('GET', '/domains/3'):
      return httpx.Response(
        404 if deleted.is_set() else 200,
        json={'name': 'api-canary-0000000.load.example.test', 'last_resolved_at': 'confirmed', 'ips_v4': ['8.8.4.4']},
      )
    if route == ('DELETE', '/domains/3'):
      deleted.set()
    if route == ('GET', '/metrics'):
      assert deleted.is_set()
      assert all(task.done() for task in tasks.values())
      return httpx.Response(
        200,
        text='\n'.join(
          f'resolution_run_snapshot{{mode="stale",field="{key}"}} 0'
          for key in ('active', 'pending', 'admission_in_progress')
        ),
      )
    return httpx.Response(200, json={'name': 'api-probe.load.example.test'})

  real_client = httpx.AsyncClient
  transport = httpx.MockTransport(request)
  monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=transport, **kwargs))
  observer = asyncio.create_task(
    load_freeze_api_bounds(
      SimpleNamespace(url='http://observer.test'),
      SimpleNamespace(count=1),
      {
        'baseline_samples': 1,
        'probe_interval': 0,
        'pass_timeout': 30,
        'latency_factor': 2,
        'latency_slack': 0.5,
      },
    )
  )
  try:
    async with asyncio.timeout(1):
      evidence = await observer
    assert set(tasks) == set(started)
    assert all(task.done() for task in tasks.values())
    assert len(evidence['canary_lifecycles']) == 1
    assert evidence['canary_lifecycles'][0]['status'] == 'passed'
    assert evidence['canary_lifecycles'][0]['deleted'] is True
    labels = {'read', 'list', 'stats', 'job', 'write', 'search', 'delete', 'stored_resolve'}
    assert set(evidence['samples']) == labels
    assert evidence['bounds_seconds'] == dict.fromkeys(labels, 5.0)
    assert all(1 <= bound <= 5 for bound in evidence['p99_bounds_seconds'].values())
    assert evidence['frozen_before_candidate_measurements'] is True
    assert requests.count(('POST', '/domains')) == requests.count(('DELETE', '/domains/3')) == 1
    assert requests.count(('POST', '/commands/domains/resolve/stale')) == 1
    assert ('POST', '/commands/domains/resolve/new') not in requests
  finally:
    owned = [observer, *tasks.values()]
    for task in owned:
      if not task.done():
        task.cancel()
    await asyncio.gather(*owned, return_exceptions=True)


def load_assert_source_budget(measurement, configuration):
  """Reject late completions even when event-loop timer delivery was delayed."""
  elapsed = measurement['wall_seconds_to_known_writer_outcomes']
  budget = min(configuration['pass_timeout'], 1800)
  within = elapsed <= budget
  measurement['source_budget'] = {'maximum_seconds': budget, 'elapsed_seconds': elapsed, 'within_maximum': within}
  assert within, f'Source pass exceeded {budget}s through known writer outcomes: {elapsed}s'


@pytest.mark.parametrize('delayed_stage', ['admission', 'selection'])
async def test_resolution_load_source_deadline_includes_admission_selection_and_retires_tasks(
  monkeypatch, delayed_stage
):
  """Exhaust the source budget before persistence, preserving timeout and cleanup.

  monkeypatch confines the controlled clock and HTTP transport to this test.
  delayed_stage chooses whether admission or selection consumes the budget.
  The next persistence poll is forbidden even if cancellation cleanup takes time.
  """
  # loop supplies a real monotonic base; clock advances only the helper's view of time.
  loop = asyncio.get_running_loop()
  clock = SimpleNamespace(value=loop.time())
  # selected records frozen source membership; completed marks a forbidden later poll.
  selected, completed = asyncio.Event(), asyncio.Event()
  # pending retains both probe tasks; retired records their cancellation cleanup.
  pending, retired = set(), set()
  # probes_ready prevents the first persistence response from racing probe startup.
  probes_ready = asyncio.Event()
  # started distinguishes the initial scrape; source_scrapes counts subsequent source polls.
  started = False
  source_scrapes = 0

  async def request(request):
    """Serve synthetic request routes and consume time at the selected HTTP boundary.

    request contains the HTTP method and URL. Probe requests remain pending until
    cancellation, then fail during cleanup to challenge first-error preservation.
    The selected phase consumes 31 virtual seconds against the 30-second budget.
    """
    nonlocal started, source_scrapes
    # route identifies admission, metrics, or one of the independent API probes.
    route = (request.method, request.url.path)
    if route == ('POST', '/commands/domains/resolve/stale'):
      started = True
      if delayed_stage == 'admission':
        clock.value += 31
        selected.set()
    if route == ('GET', '/metrics'):
      if started:
        if not selected.is_set():
          assert delayed_stage == 'selection'
          clock.value += 31
          selected.set()
        source_scrapes += 1
        if source_scrapes >= 2:
          await probes_ready.wait()
        if source_scrapes >= 3:
          completed.set()
          raise AssertionError('Persistence received a renewed deadline')
      # fields exposes selection but withholds persistence completion for the first idle poll.
      fields = {
        'selected': int(selected.is_set()),
        'processing_complete': int(completed.is_set()),
        'active': int(not completed.is_set()),
        'pending': 0,
        'admission_in_progress': 0,
        'admitted': 1,
        'confirmed': 1,
        'attempted': 1,
        'unknown': 0,
        'known_not_committed': 0,
        'not_admitted': 0,
      }
      return httpx.Response(
        200,
        text='\n'.join(
          [
            'fastapi_app_info{pid="7"} 1',
            f'resolution_run_elapsed_seconds_count{{mode="stale"}} {int(completed.is_set())}',
            # key names a run field; value is its synthetic metric value.
            *(f'resolution_run_snapshot{{mode="stale",field="{key}"}} {value}' for key, value in fields.items()),
          ]
        ),
      )
    if route in {('GET', '/domains/2'), ('POST', '/domains')}:
      # task is one probe whose retirement must precede the helper's return.
      task = asyncio.current_task()
      pending.add(task)
      if len(pending) == 2:
        probes_ready.set()
      try:
        await asyncio.Event().wait()
      except asyncio.CancelledError:
        raise ValueError('Probe failed during cancellation cleanup') from None
      finally:
        retired.add(task)
    return httpx.Response(200, json={})

  # real_client retains HTTPX construction; transport confines all requests to the fake above.
  real_client = httpx.AsyncClient
  transport = httpx.MockTransport(request)
  # The client factory forwards kwargs unchanged while injecting the isolated transport.
  monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=transport, **kwargs))
  # module owns the helper's asyncio binding; clocked_asyncio delegates all real asyncio operations.
  module = sys.modules[__name__]
  clocked_asyncio = SimpleNamespace(**vars(asyncio))
  # The time callback exposes controlled monotonic seconds; get_running_loop returns only that clock view.
  clock.time = lambda: clock.value
  clocked_asyncio.get_running_loop = lambda: clock
  monkeypatch.setattr(module, 'asyncio', clocked_asyncio)
  # service reports constant synthetic resources; its callback accepts the observed pid without OS access.
  service = SimpleNamespace(
    url='http://deadline.test',
    resource_snapshot=lambda pid: {'rss_bytes': 1, 'peak_rss_bytes': 1, 'cpu_seconds': 0, 'source': 'controlled OS'},
  )
  # measurement retains the helper's source failure and API verdict after cleanup.
  measurement = {}
  async with asyncio.timeout(1):
    with pytest.raises(TimeoutError):
      await load_measure_pass(
        service,
        SimpleNamespace(count=1),
        {
          'pass_timeout': 30,
          'probe_interval': 1,
          'metrics_poll_interval': 0,
          'rss_limit_mb': 1,
          'cpu_percent_limit': 100,
        },
        {'read': 5, 'list': 5, 'stats': 5, 'job': 5, 'write': 5},
        mode='stale',
        measurement=measurement,
      )
  assert selected.is_set()
  assert source_scrapes == 2
  assert not completed.is_set()
  assert measurement['source_budget_seconds'] == 30
  assert measurement['source_pass_status'] == 'failed'
  assert measurement['source_failure']['type'] == 'TimeoutError'
  assert measurement.get('api_status') != 'passed'
  assert len(pending) == 2
  assert retired == pending
  # task ranges over the retained probes, including cleanup failures already gathered by the helper.
  assert all(task.done() for task in pending)
  assert all(isinstance(task.exception(), ValueError) for task in pending)
  assert {task.exception().args for task in pending} == {('Probe failed during cancellation cleanup',)}


async def load_measure_pass(
  service,
  dataset,
  configuration,
  bounds,
  *,
  mode,
  p99_bounds=None,
  on_progress=None,
  measurement=None,
  observations=None,
  metrics_observer=None,
):
  measurement = {} if measurement is None else measurement
  observed = LoadApiObservations() if observations is None else observations
  diagnostic = {} if configuration.get('diagnostic', False) else None
  capture_runner = diagnostic is not None or configuration.get('cpu_profile', 'unrestricted') != 'unrestricted'
  runner_resources = []
  if diagnostic is not None:
    measurement['diagnostic'] = diagnostic
    diagnostic.update(runner_pid=os.getpid(), runner_parent_pid=os.getppid(), runner_executable=sys.executable)
  finished = asyncio.Event()
  async with httpx.AsyncClient(base_url=service.url, timeout=max(bounds.values()), trust_env=False) as client:
    before = parse_samples((await load_metrics_request(client, metrics_observer, scope='source_before')).text)
    pid = application_pid(before)
    if getattr(service, 'cpu_evidence', None) is not None:
      cpu = service.startup_attempts[-1]['cpu']
      assert cpu['application_pid'] == pid, 'CPU evidence must describe the actual application process'
      if cpu['requested_mask'] is not None:
        assert cpu['application_effective_mask'] == cpu['effective_mask'] == cpu['requested_mask']
      measurement['cpu'] = cpu
    resources = [service.resource_snapshot(pid)]
    last_api_at = None

    async def monitor():
      nonlocal last_api_at
      while not finished.is_set():
        resources.append(service.resource_snapshot(pid))
        if capture_runner:
          runner_resources.append(
            {'elapsed_seconds': perf_counter() - started, **service.resource_snapshot(os.getpid())}
          )
          assert runner_resources[-1]['rss_bytes'] <= configuration['rss_limit_mb'] * 1024 * 1024
        assert resources[-1]['rss_bytes'] <= configuration['rss_limit_mb'] * 1024 * 1024
        await load_api_round(client, dataset, observed, timeout=bounds, job_mode='new' if mode == 'stale' else 'stale')
        last_api_at = perf_counter()
        try:
          await asyncio.wait_for(finished.wait(), timeout=configuration['probe_interval'])
        except TimeoutError:
          pass

    async def report_progress(samples, fields):
      if on_progress is not None:
        on_progress(
          {
            'observed_at_utc': datetime.now(UTC).isoformat(),
            'elapsed_seconds': perf_counter() - started,
            'run': fields,
            'resource': service.resource_snapshot(application_pid(samples)),
            'last_api_round_elapsed_seconds': last_api_at - started if last_api_at is not None else None,
            'api_sample_counts': {name: len(values) for name, values in observed.items()},
            **({'diagnostic': diagnostic} if diagnostic is not None else {}),
          }
        )

    monitor_task = None
    canary_task = None
    pass_task = None
    loop_task = None
    loop = asyncio.get_running_loop()
    source_budget = min(configuration['pass_timeout'], 1800)
    started = perf_counter()
    deadline = loop.time() + source_budget
    measurement.update(source_budget_seconds=source_budget, source_pass_status='in_progress')

    async def watch_loop():
      lag = diagnostic['loop_lag'] = {'count': 0, 'sum_seconds': 0, 'max_seconds': 0, 'over_50ms': 0}
      while True:
        scheduled = perf_counter() + 0.02
        await asyncio.sleep(0.02)
        seconds = max(0, perf_counter() - scheduled)
        lag['count'] += 1
        lag['sum_seconds'] += seconds
        lag['max_seconds'] = max(lag['max_seconds'], seconds)
        lag['over_50ms'] += seconds > 0.05

    try:
      if capture_runner:
        runner_resources.append({'elapsed_seconds': 0, **service.resource_snapshot(os.getpid())})
      if diagnostic is not None:
        loop_task = asyncio.create_task(watch_loop())
      monitor_task = asyncio.create_task(monitor())
      async with asyncio.timeout_at(deadline):
        await load_api_request(client, observed, 'job', 'POST', f'/commands/domains/resolve/{mode}', timeout=5)
        # Freeze source membership before any public canary can enter selection.
        async with asyncio.timeout_at(deadline):
          while (
            run_fields(
              parse_samples((await load_metrics_request(client, metrics_observer, scope='source_selection')).text), mode
            ).get('selected')
            != dataset.count
          ):
            await asyncio.sleep(0.01)
        canary_task = asyncio.create_task(
          load_probe_canaries(
            client,
            observed,
            finished,
            configuration,
            job_mode='new' if mode == 'stale' else 'stale',
            request_timeout=bounds,
          )
        )

        async def observe_source():
          samples, fields = await load_wait_idle(
            client,
            mode,
            dataset.count,
            sample_total(before, 'resolution_run_elapsed_seconds_count', mode=mode),
            max(0, deadline - loop.time()),
            on_progress=report_progress,
            **({'diagnostic': diagnostic} if diagnostic is not None else {}),
            **(
              {'metrics_poll_interval': configuration['metrics_poll_interval'], 'metrics_observer': metrics_observer}
              if 'metrics_poll_interval' in configuration
              else {}
            ),
          )
          source_elapsed = perf_counter() - started
          measurement.update(
            source_pass_status='completed',
            wall_seconds_to_known_writer_outcomes=source_elapsed,
            source_population=dataset.count,
            run=fields,
          )
          load_assert_source_budget(measurement, configuration)
          return samples, fields

        pass_task = asyncio.create_task(observe_source())
        done, _ = await asyncio.wait((pass_task, monitor_task, canary_task), return_when=asyncio.FIRST_COMPLETED)
        for task in done:
          if task is not pass_task:
            await task
        samples, fields = await pass_task
        elapsed = measurement['wall_seconds_to_known_writer_outcomes']
      resources.append(service.resource_snapshot(pid))
    except BaseException as error:
      if measurement['source_pass_status'] != 'completed':
        measurement.update(
          source_pass_status='failed',
          wall_seconds_to_failure=perf_counter() - started,
          source_failure={'type': type(error).__name__, 'message': str(error)[:4000]},
        )
      raise
    finally:
      try:
        finished.set()
        if sys.exception() is not None:
          # Preserve the first failure; fixture teardown owns the disposable process.
          tasks = [task for task in (pass_task, monitor_task, canary_task) if task is not None]
          for task in tasks:
            if not task.done():
              task.cancel()
          await asyncio.gather(*tasks, return_exceptions=True)
        else:
          try:
            if monitor_task is not None:
              await monitor_task
            if canary_task is not None:
              lifecycles = await canary_task
              measurement['canary_lifecycles'] = lifecycles
          finally:
            tasks = [task for task in (pass_task, monitor_task, canary_task) if task is not None]
            for task in tasks:
              if not task.done():
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
      finally:
        if loop_task is not None:
          loop_task.cancel()
          await asyncio.gather(loop_task, return_exceptions=True)
        if capture_runner:
          try:
            runner_resources.append(
              {'elapsed_seconds': perf_counter() - started, **service.resource_snapshot(os.getpid())}
            )
          except (OSError, AssertionError) as error:
            measurement['runner_final_resource_error'] = type(error).__name__
          measurement['runner_resource_samples'] = runner_resources
          if diagnostic is not None:
            diagnostic['runner_resource_samples'] = runner_resources
        measurement['api_latency_measured'] = {name: load_quantiles(values) for name, values in observed.items()}
        measurement['api_latency_samples_seconds'] = {name: list(values) for name, values in observed.items()}
        measurement['resource_samples'] = resources
        measurement['api_bounds_frozen_seconds'] = bounds
        measurement['api_failures'] = observed.failures
    await load_drain_stored(
      client,
      configuration['pass_timeout'],
      **({'metrics_observer': metrics_observer} if metrics_observer is not None else {}),
    )
    async with asyncio.timeout(configuration['pass_timeout']):
      while True:
        current = parse_samples((await load_metrics_request(client, metrics_observer, scope='auxiliary_drain')).text)
        auxiliary = run_fields(current, 'new' if mode == 'stale' else 'stale')
        if all(auxiliary.get(key, 0) == 0 for key in ('active', 'pending', 'admission_in_progress')):
          break
        await asyncio.sleep(0.05)
    assert (await client.get('/domains', params={'limit': 1})).json()['total'] == dataset.count + 2
    probe_drain_elapsed = perf_counter() - started
    source_run_count = sample_total(current, 'resolution_run_elapsed_seconds_count', mode=mode) - sample_total(
      before, 'resolution_run_elapsed_seconds_count', mode=mode
    )
    assert source_run_count == 1, ('Unexpected successor source pass', source_run_count)
    measurement.update(
      auxiliary_drain_status='completed',
      wall_seconds_including_auxiliary_drain=probe_drain_elapsed,
      source_run_count=source_run_count,
    )
    assert max(row['peak_rss_bytes'] for row in resources) <= configuration['rss_limit_mb'] * 1024 * 1024
    expected = dataset.manifest()['categories']
    assert fields['success'] == expected['success'] + expected['empty'], fields
    assert fields['partial'] == expected['partial'], fields
    assert fields['failure'] == expected['failure'], fields
    assert fields['confirmed'] == dataset.count - expected['failure'], fields
    assert sample_total(samples, 'httpx_exchanges_in_flight') >= 0
    cpu_seconds = resources[-1]['cpu_seconds'] - resources[0]['cpu_seconds']
    cpu_percent = 100 * cpu_seconds / elapsed
    assert cpu_percent <= configuration['cpu_percent_limit'], cpu_percent
    latency = {name: load_quantiles(values) for name, values in observed.items()}
    measurement.update(
      {
        'wall_seconds_to_known_writer_outcomes': elapsed,
        'wall_seconds_including_auxiliary_drain': probe_drain_elapsed,
        'canary_lifecycles': lifecycles,
        'maximum_live_canaries': 1,
        'source_population': dataset.count,
        'source_run_count': source_run_count,
        'confirmed_domains_per_second': fields['confirmed'] / elapsed,
        'processed_domains_per_second': fields['attempted'] / elapsed,
        'run': fields,
        'api_latency_measured': latency,
        'api_bounds_frozen_seconds': bounds,
        'resources': {
          'pid': pid,
          'source': resources[0]['source'],
          'cpu_seconds': cpu_seconds,
          'cpu_percent_one_core': cpu_percent,
          'peak_rss_bytes': max(row['peak_rss_bytes'] for row in resources),
          'max_sampled_rss_bytes': max(row['rss_bytes'] for row in resources),
          'samples': len(resources),
        },
        'histogram_percentile_estimates': {
          'dns': histogram_percentiles(samples, before, 'resolution_dns_duration_seconds'),
          **{
            f'ripe_{phase}': histogram_percentiles(samples, before, 'resolution_ripe_duration_seconds', phase=phase)
            for phase in ('lookup', 'network', 'lock_wait', 'semaphore_wait')
          },
          **{
            f'{queue}_{phase}': histogram_percentiles(
              samples, before, 'resolution_queue_duration_seconds', queue=queue, phase=phase
            )
            for queue in ('resolve', 'writer')
            for phase in ('admission', 'residence')
          },
          **{
            f'writer_{phase}': histogram_percentiles(samples, before, 'resolution_writer_duration_seconds', phase=phase)
            for phase in ('attempt', 'transaction', 'commit', 'batch_dwell')
          },
        },
        'ripe_network_requests': sample_total(samples, 'resolution_ripe_duration_seconds_count', phase='network')
        - sample_total(before, 'resolution_ripe_duration_seconds_count', phase='network'),
      }
    )
    measurement['api_status'] = 'failed'
    assert {'read', 'list', 'stats', 'write', 'job', 'search', 'delete'} <= set(latency)
    for name, values in latency.items():
      assert values['max'] <= bounds[name], (name, values, bounds)
      if p99_bounds is not None:
        assert values['p99'] <= p99_bounds[name], (name, values, p99_bounds)
    measurement['api_status'] = 'passed'
    return measurement


def api_diagnostic_configuration():
  """Require explicit diagnostic selection and preserve the original workload knobs."""
  supplied = json.loads(os.environ['GOST_API_DIAGNOSTIC_CONFIG'])
  defaults = {
    'smoke': False,
    'n': 10000,
    'seed': 20261104,
    'unique_ip_ratio': 0.7,
    'alias_every': 10,
    'provider_delay': 0.001,
    'pass_timeout': 1800,
    'verify_timeout': 180,
    'rss_limit_mb': 2048,
    'cpu_percent_limit': 1600,
    'probe_interval': 0.25,
    'idle_seconds': 15,
    'progress_writes': 'original',
    'independent_probe': True,
    'metrics_poll_interval': 0.05,
    'idle_metrics_polling': False,
    'read_pool_size': None,
  }
  assert isinstance(supplied, dict)
  assert set(supplied) <= set(defaults)
  configuration = defaults | supplied
  assert type(configuration['smoke']) is bool
  assert type(configuration['independent_probe']) is bool
  assert type(configuration['idle_metrics_polling']) is bool
  assert type(configuration['n']) is int
  assert 6 <= configuration['n'] <= 64 if configuration['smoke'] else configuration['n'] == 10000
  for key in ('seed', 'unique_ip_ratio', 'alias_every', 'provider_delay', 'probe_interval'):
    assert configuration[key] == defaults[key], ('Workload knob changed', key)
  for key, maximum in (
    ('pass_timeout', 1800),
    ('verify_timeout', 600),
    ('rss_limit_mb', 2048),
    ('cpu_percent_limit', 1600),
    ('idle_seconds', 60),
  ):
    assert type(configuration[key]) in {int, float}
    assert math.isfinite(configuration[key]), key
    assert 0 < configuration[key] <= maximum, key
  assert configuration['progress_writes'] in {'original', 'deferred'}
  assert type(configuration['metrics_poll_interval']) in {int, float}
  assert math.isfinite(configuration['metrics_poll_interval'])
  assert 0.05 <= configuration['metrics_poll_interval'] <= 1.0
  if configuration['read_pool_size'] is not None:
    assert type(configuration['read_pool_size']) is int
    assert 1 <= configuration['read_pool_size'] <= 64
  return configuration


class ApiDiagnosticRecorder:
  """Keep clocks in memory during requests; measure synchronous artifact work explicitly."""

  def __init__(self):
    self.observations = LoadApiObservations(diagnostic=True)
    self.evidence = {'loop_interval_seconds': 0.02, 'loop_wakeups': [], 'artifact_writes': [], 'metrics_scrapes': []}

  async def watch_loop(self):
    interval = self.evidence['loop_interval_seconds']
    while True:
      scheduled = perf_counter() + interval
      await asyncio.sleep(interval)
      resumed = perf_counter()
      before = perf_counter()
      self.evidence['loop_wakeups'].append(
        {'scheduled_monotonic': scheduled, 'resumed_monotonic': resumed, 'lag_seconds': max(0, resumed - scheduled)}
      )
      self.evidence['loop_wakeups'][-1]['observation_seconds'] = perf_counter() - before

  def write(self, path, artifact):
    started = perf_counter()
    try:
      load_write_artifact(path, artifact)
    finally:
      ended = perf_counter()
      self.evidence['artifact_writes'].append(
        {
          'start_monotonic': started,
          'end_monotonic': ended,
          'elapsed_seconds': ended - started,
          'bytes_after_write': path.stat().st_size if path.exists() else None,
        }
      )


API_DIAGNOSTIC_PROBE = """
import json, os, sys, threading, time
import httpx
stop = threading.Event()
def read_stop():
  os.read(sys.stdin.fileno(), 1)
  stop.set()
threading.Thread(target=read_stop, daemon=True).start()
rows = []
deadline = time.perf_counter() + float(sys.argv[3])
with httpx.Client(base_url=sys.argv[1], timeout=5, trust_env=False) as client:
  print(json.dumps({'ready': True, 'pid': os.getpid(), 'at_monotonic': time.perf_counter()}), flush=True)
  while not stop.is_set() and time.perf_counter() < deadline:
    for path in ('/health', '/ips/lists?limit=10'):
      started = time.perf_counter()
      row = {'path': path, 'start_monotonic': started}
      try:
        response = client.get(path)
        row.update(status_code=response.status_code, body_bytes=len(response.content), error_type=None)
      except httpx.HTTPError as error:
        row.update(status_code=None, body_bytes=None, error_type=type(error).__name__)
      ended = time.perf_counter()
      row.update(end_monotonic=ended, elapsed_seconds=ended-started)
      if row['status_code'] is not None:
        try:
          body = response.json()
        except ValueError:
          body = None
        row['server_duration_seconds'] = body.get('duration') if isinstance(body, dict) else None
      rows.append(row)
      if stop.is_set():
        break
    stop.wait(float(sys.argv[2]))
print(json.dumps({'requests': rows, 'deadline_reached': time.perf_counter() >= deadline}), flush=True)
"""


@asynccontextmanager
async def api_diagnostic_observe(service, configuration, recorder):
  """Own the loop sampler and an optional independent, additional read-only HTTP workload."""
  watcher = asyncio.create_task(recorder.watch_loop())
  process = None
  drain = None
  try:
    if configuration['independent_probe']:
      process = await asyncio.create_subprocess_exec(
        sys.executable,
        '-B',
        '-c',
        API_DIAGNOSTIC_PROBE,
        service.url,
        str(configuration['probe_interval']),
        str(configuration['pass_timeout'] + 30),
        cwd=service.directory,
        env=service.environment,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
      )
      ready = await asyncio.wait_for(process.stdout.readline(), timeout=5)
      recorder.evidence['independent_probe'] = {'ready': json.loads(ready), 'added_http_load': True}
      # Drain concurrently so a full pipe cannot perturb the independent probe's clocks.
      drain = asyncio.create_task(process.stdout.read())
    yield
  finally:
    primary = sys.exception()
    try:
      if process is not None:
        try:
          if process.returncode is None:
            try:
              process.stdin.write(b'\n')
              await process.stdin.drain()
            except BrokenPipeError, ConnectionResetError:
              pass
          await asyncio.wait_for(process.wait(), timeout=6)
          raw = await drain if drain is not None else await process.stdout.read()
          stderr = await process.stderr.read()
          assert process.returncode == 0, stderr.decode(errors='replace')
          result = json.loads(raw)
          recorder.evidence['independent_probe'].update(result, returncode=process.returncode)
          assert not result['deadline_reached'], 'Independent probe reached its safety deadline'
        finally:
          if process.returncode is None:
            process.kill()
            await asyncio.wait_for(process.wait(), timeout=5)
          if drain is not None:
            await asyncio.gather(drain, return_exceptions=True)
          process.stdin.close()
          try:
            await process.stdin.wait_closed()
          except BrokenPipeError, ConnectionResetError:
            pass
    except BaseException as error:
      recorder.evidence['probe_cleanup_failure'] = {'type': type(error).__name__, 'message': str(error)[:1000]}
      if primary is None:
        raise
      primary.add_note(f'Diagnostic probe cleanup also failed: {error!r}')
    finally:
      watcher.cancel()
      await asyncio.gather(watcher, return_exceptions=True)
      recorder.evidence['requests'] = recorder.observations.requests
      recorder.evidence['loop_lag'] = load_quantiles([row['lag_seconds'] for row in recorder.evidence['loop_wakeups']])


async def api_diagnostic_idle(client, dataset, configuration, recorder):
  """Sample reads on the same populated DB only after both saving job modes drain."""
  async with asyncio.timeout(configuration['pass_timeout']):
    while True:
      response = await load_metrics_request(client, recorder.evidence['metrics_scrapes'], scope='idle_before')
      assert response.status_code == 200
      samples = parse_samples(response.text)
      modes = {mode: run_fields(samples, mode) for mode in ('new', 'stale')}
      if all(
        all(fields.get(key) == 0 for key in ('active', 'pending', 'admission_in_progress', 'unknown'))
        for fields in modes.values()
      ):
        break
      await asyncio.sleep(configuration.get('metrics_poll_interval', 0.05))
  recorder.evidence['idle_drained_modes_before'] = modes
  counts = {mode: sample_total(samples, 'resolution_run_elapsed_seconds_count', mode=mode) for mode in modes}
  deadline = perf_counter() + configuration['idle_seconds']
  finished = asyncio.Event()

  async def reads():
    while perf_counter() < deadline:
      for label, path in (
        ('health', '/health'),
        ('read', f'/domains/{dataset.count + 1}'),
        ('list', '/domains?limit=10'),
        ('stats', '/stats'),
        ('ip_lists', '/ips/lists?limit=10'),
        ('ip_list', '/ips/lists/1'),
      ):
        await load_api_request(client, recorder.observations, label, 'GET', path, timeout=5)
      await asyncio.sleep(configuration['probe_interval'])

  async def poll_metrics():
    while not finished.is_set():
      await load_metrics_request(client, recorder.evidence['metrics_scrapes'], scope='idle_poll')
      try:
        await asyncio.wait_for(finished.wait(), timeout=configuration.get('metrics_poll_interval', 0.05))
      except TimeoutError:
        pass

  tasks = [asyncio.create_task(reads())]
  if configuration.get('idle_metrics_polling', False):
    tasks.append(asyncio.create_task(poll_metrics()))
  try:
    async with asyncio.timeout(configuration['idle_seconds'] + 20):
      done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
      for task in done:
        await task
      await tasks[0]
      finished.set()
      if len(tasks) > 1:
        await tasks[1]
  finally:
    finished.set()
    for task in tasks:
      if not task.done():
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
  response = await load_metrics_request(client, recorder.evidence['metrics_scrapes'], scope='idle_after')
  assert response.status_code == 200
  after = parse_samples(response.text)
  assert counts == {mode: sample_total(after, 'resolution_run_elapsed_seconds_count', mode=mode) for mode in modes}
  recorder.evidence['idle_drained_modes_after'] = {mode: run_fields(after, mode) for mode in modes}
  assert all(
    all(fields.get(key) == 0 for key in ('active', 'pending', 'admission_in_progress', 'unknown'))
    for fields in recorder.evidence['idle_drained_modes_after'].values()
  )


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.skipif('GOST_API_DIAGNOSTIC_CONFIG' not in os.environ, reason='Explicit diagnostic configuration required')
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True, 'request_sample_limit': 128}], indirect=True)
async def test_resolution_api_latency_diagnostic(e2e_service, tmp_path):
  """Diagnose degraded cold/warm latency; every result is diagnostic, never campaign acceptance."""
  configuration = api_diagnostic_configuration()
  service = e2e_service
  snapshot = load_source_evidence(service.root)
  artifact_path = tmp_path / 'api-latency-diagnostic.json'
  artifact = {
    'purpose': 'diagnostic only; not acceptance',
    'configuration': configuration,
    'controls': {
      'p99_seconds': 1,
      'http_seconds': 5,
      'startup_seconds': 15,
      'shutdown_seconds': 20,
      'historical_cpu_percent_limit': 1600,
      'historical_verify_timeout_seconds': 180,
      'read_pool_control': 'An explicit test-process DB_POOL_SIZE override; otherwise use the application default',
      'focused_matrix': 'one degraded cold/warm pair, followed by read-only idle on the same populated DB',
      'warmup_prelude': False,
      'independent_probe_added_load': configuration['independent_probe'],
      'timed_request_scope': 'load_api_request exchanges only; metrics polling and verification excluded',
      'server_duration_scope': (
        'Existing response duration is seconds from route entry to DB result construction; '
        'excludes subsequent session close, route serialization and scheduling before route entry'
      ),
      'progress_write_control': 'Original progress cadence; enriched diagnostic artifact content differs from campaign',
      'metrics_poll_interval_seconds': configuration['metrics_poll_interval'],
      'metrics_poll_cadence': 'Sleep after response/parse; request time adds to the interval, not a fixed scrape rate',
      'metrics_sample_scope': (
        'Per-scrape scope tags distinguish phase setup, source observation, idle reads and post-source drain. '
        'stored_drain and auxiliary_drain retain their original cadence and are outside the source wall interval.'
      ),
      'idle_metrics_polling': configuration['idle_metrics_polling'],
      'metrics_control_scope': (
        'Diagnostic comparison only; slower polling changes completion detection granularity, not throughput proof. '
        'Idle scraping cannot rule out nonlinear interaction between metrics exposition and resolver work. '
        'Compare with identical progress_writes and independent_probe controls.'
      ),
      'clock': 'time.perf_counter monotonic seconds; cross-process clocks on the same host',
    },
    'source_sha256': snapshot,
    'cases': [],
  }
  first_failure = None
  service.environment['TEST_SOURCE_EVIDENCE'] = str(tmp_path / 'executed-source.json')
  service.environment.update(batch_comparison_environment({'profile': 'startup'}))
  if configuration.get('read_pool_size') is not None:
    service.environment['DB_POOL_SIZE'] = str(configuration['read_pool_size'])
  load_write_artifact(artifact_path, artifact)
  try:
    await service.start()
    await load_public_setup(service, 5)
    await service.stop()
    dataset = ResolutionLoadDataset(configuration['n'], configuration)
    dataset.schedule = 'degraded'
    dataset.probe_ip_lists = True
    service.providers.response_factory = dataset.response
    artifact['seed_seconds'], artifact['initial_data_sha256'] = batch_comparison_seed(service, dataset)
    artifact['effective_settings'] = load_effective_settings(service)
    await service.start()
    for phase in ('cold', 'warm', 'idle'):
      if phase != 'idle':
        await load_begin_provider_cycle(service.providers, f'diagnostic-degraded-{phase}')
        service.providers.reset_evidence()
      recorder = ApiDiagnosticRecorder()
      entry = {'phase': phase, 'status': 'in_progress', 'measurement': {}}
      artifact['cases'].append(entry)
      async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
        entry['initial_public_state'] = await batch_comparison_public_state(
          client, dataset, configuration['verify_timeout']
        )
        samples = parse_samples(
          (await load_metrics_request(client, recorder.evidence['metrics_scrapes'], scope='phase_before')).text
        )
        load_write_artifact(
          tmp_path / 'current-phase.json',
          {
            'app_pid': application_pid(samples),
            'url': service.url,
            'phase': phase,
            'at_monotonic': perf_counter(),
            'output_directory': str(tmp_path),
          },
        )
        recorder.write(artifact_path, artifact)

        def progress(value, entry=entry, recorder=recorder):
          entry['progress'] = value
          if configuration['progress_writes'] == 'original':
            recorder.write(artifact_path, artifact)

        try:
          async with api_diagnostic_observe(service, configuration, recorder):
            if phase == 'idle':
              await api_diagnostic_idle(client, dataset, configuration, recorder)
            else:
              await load_measure_pass(
                service,
                dataset,
                configuration,
                dict.fromkeys(('read', 'list', 'stats', 'write', 'job', 'search', 'delete', 'ip_lists', 'ip_list'), 5),
                mode='stale',
                on_progress=progress,
                measurement=entry['measurement'],
                observations=recorder.observations,
                metrics_observer=recorder.evidence['metrics_scrapes'],
              )
        except (AssertionError, RuntimeError, ValueError, TimeoutError, OSError, httpx.HTTPError) as error:
          entry['failure'] = {'type': type(error).__name__, 'message': str(error)[:4000]}
          first_failure = error if first_failure is None else first_failure
        finally:
          entry['diagnostic'] = recorder.evidence
          entry['api_latency'] = {name: load_quantiles(values) for name, values in recorder.observations.items()}
          entry['p99_violations'] = {name: values for name, values in entry['api_latency'].items() if values['p99'] > 1}
          entry['api_failures'] = recorder.observations.failures
          entry['providers'] = service.providers.evidence()
          recorder.write(artifact_path, artifact)
        if phase != 'idle':
          if entry['measurement'].get('auxiliary_drain_status') != 'completed':
            if first_failure is not None:
              first_failure.add_note('Warm/idle precondition not established; remaining phases were not started')
              entry['status'] = 'failed'
              raise first_failure
            raise AssertionError('Warm/idle precondition not established')
        entry['verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
        if phase == 'idle':
          final_state = await batch_comparison_public_state(client, dataset, configuration['verify_timeout'])
          assert final_state == entry['initial_public_state'], 'Idle reads changed public state'
        independent = recorder.evidence.get('independent_probe', {}).get('requests', [])
        entry['independent_p99'] = {
          path: load_quantiles([row['elapsed_seconds'] for row in independent if row['path'] == path])
          for path in ('/health', '/ips/lists?limit=10')
        }
        entry['independent_failures'] = [
          row for row in independent if row['status_code'] != 200 or row['elapsed_seconds'] > 5
        ]
        entry['independent_p99_violations'] = {
          path: values
          for path, values in entry['independent_p99'].items()
          if values['p99'] is not None and values['p99'] > 1
        }
        if entry['p99_violations'] or entry['independent_failures'] or entry['independent_p99_violations']:
          first_failure = first_failure or AssertionError(f'Diagnostic latency violation in {phase}')
        entry['status'] = (
          'failed'
          if 'failure' in entry
          or entry['p99_violations']
          or entry['independent_failures']
          or entry['independent_p99_violations']
          else 'passed'
        )
        recorder.write(artifact_path, artifact)
  finally:
    primary = sys.exception()
    started = perf_counter()
    artifact['startup_attempts'] = service.startup_attempts
    try:
      await service.stop(allow_failure=primary is not None)
      artifact['shutdown_seconds'] = perf_counter() - started
      assert artifact['shutdown_seconds'] <= 20
      artifact['executed_source'] = batch_comparison_executed_source(service, snapshot)
    except BaseException as cleanup_error:
      artifact['cleanup_failure'] = {'type': type(cleanup_error).__name__, 'message': str(cleanup_error)[:4000]}
      if primary is None:
        raise
      primary.add_note(f'Diagnostic service cleanup also failed: {cleanup_error!r}')
    finally:
      artifact['status'] = (
        'failed'
        if primary is not None or first_failure is not None or 'cleanup_failure' in artifact
        else 'diagnostic_completed'
      )
      if primary is not None:
        artifact['failure'] = {'type': type(primary).__name__, 'message': str(primary)[:4000]}
      load_write_artifact(artifact_path, artifact)
  if first_failure is not None:
    raise first_failure


@pytest.mark.parametrize(
  'supplied',
  [
    {'n': 9999},
    {'smoke': True, 'n': 65},
    {'smoke': True, 'n': 5},
    {'seed': 1},
    {'provider_delay': 0},
    {'probe_interval': 1},
    {'idle_seconds': float('nan')},
    {'pass_timeout': 1801},
    {'independent_probe': 'yes'},
    {'idle_metrics_polling': 'yes'},
    {'metrics_poll_interval': True},
    {'metrics_poll_interval': 0},
    {'metrics_poll_interval': 0.049},
    {'metrics_poll_interval': 1.001},
    {'metrics_poll_interval': float('nan')},
    {'metrics_poll_interval': float('inf')},
    {'read_pool_size': True},
    {'read_pool_size': 0},
    {'read_pool_size': 65},
    {'read_pool_size': 5.5},
    {'read_pool_size': '32'},
    {'progress_writes': 'silent'},
    {'unknown': 1},
  ],
)
def test_api_diagnostic_configuration_rejects_uncontrolled_comparisons(monkeypatch, supplied):
  """Diagnostics cannot silently weaken workload, isolation bounds or explicit controls."""
  monkeypatch.setenv('GOST_API_DIAGNOSTIC_CONFIG', json.dumps(supplied))
  with pytest.raises(AssertionError):
    api_diagnostic_configuration()


def test_api_diagnostic_metrics_controls_are_explicit_and_preserve_other_defaults(monkeypatch):
  monkeypatch.setenv('GOST_API_DIAGNOSTIC_CONFIG', '{}')
  original = api_diagnostic_configuration()
  assert original['metrics_poll_interval'] == 0.05
  assert original['idle_metrics_polling'] is False
  monkeypatch.setenv('GOST_API_DIAGNOSTIC_CONFIG', '{"metrics_poll_interval": 1, "idle_metrics_polling": true}')
  controlled = api_diagnostic_configuration()
  assert controlled == original | {'metrics_poll_interval': 1, 'idle_metrics_polling': True}


@pytest.mark.parametrize('interval', [None, 1.0])
async def test_load_wait_idle_metrics_control_changes_only_poll_wait(monkeypatch, interval):
  waits, scrapes = [], []
  requests = []
  fields = dict.fromkeys(
    ('active', 'pending', 'admission_in_progress', 'unknown', 'known_not_committed', 'not_admitted'), 0
  )
  fields.update(selected=2, processing_complete=1, admitted=2, confirmed=2, attempted=2)

  async def request(request):
    requests.append((request.method, request.url.path))
    complete = len(requests) == 2
    metrics = [f'resolution_run_elapsed_seconds_count{{mode="stale"}} {int(complete)}']
    metrics.extend(f'resolution_run_snapshot{{mode="stale",field="{key}"}} {value}' for key, value in fields.items())
    return httpx.Response(200, text='\n'.join(metrics))

  async def sleep(seconds):
    waits.append(seconds)

  monkeypatch.setattr(asyncio, 'sleep', sleep)
  kwargs = {} if interval is None else {'metrics_poll_interval': interval, 'metrics_observer': scrapes}
  async with httpx.AsyncClient(base_url='http://test', transport=httpx.MockTransport(request)) as client:
    _, actual = await load_wait_idle(client, 'stale', 2, 0, 1, **kwargs)
  assert actual == fields
  assert requests == [('GET', '/metrics'), ('GET', '/metrics')]
  assert waits == [0.05 if interval is None else 1.0]
  assert len(scrapes) == (0 if interval is None else 2)
  assert all(row['status_code'] == 200 and row['body_bytes'] > 0 for row in scrapes)


async def test_load_metrics_without_observer_returns_original_exchange(monkeypatch):
  response = httpx.Response(503, text='original response')
  client = SimpleNamespace(get=AsyncMock(return_value=response))

  def unexpected_clock():
    raise AssertionError('The ordinary metrics helper must not collect diagnostic clocks')

  monkeypatch.setattr(sys.modules[__name__], 'perf_counter', unexpected_clock)
  assert await load_metrics_request(client) is response
  client.get.assert_awaited_once_with('/metrics')


@pytest.mark.parametrize('outcome', ['success', 'status', 'network'])
async def test_api_diagnostic_metrics_observation_is_separate_and_has_no_payload(outcome):
  recorder = ApiDiagnosticRecorder()
  failure = httpx.ReadError('synthetic scrape failure')

  async def request(request):
    if outcome == 'network':
      raise failure
    return httpx.Response(503 if outcome == 'status' else 200, text='private metric labels')

  async with httpx.AsyncClient(base_url='http://test', transport=httpx.MockTransport(request)) as client:
    if outcome == 'success':
      response = await load_metrics_request(client, recorder.evidence['metrics_scrapes'])
      assert response.text == 'private metric labels'
    else:
      with pytest.raises(AssertionError if outcome == 'status' else httpx.ReadError) as caught:
        await load_metrics_request(client, recorder.evidence['metrics_scrapes'])
      if outcome == 'network':
        assert caught.value is failure
  assert recorder.observations == {}
  assert recorder.observations.requests == []
  assert len(recorder.evidence['metrics_scrapes']) == 1
  row = recorder.evidence['metrics_scrapes'][0]
  assert row['elapsed_seconds'] == row['end_monotonic'] - row['start_monotonic']
  assert row['elapsed_seconds'] >= 0
  assert row['status_code'] == {'success': 200, 'status': 503, 'network': None}[outcome]
  assert row['body_bytes'] == (None if outcome == 'network' else len(b'private metric labels'))
  assert row['error_type'] == {'success': None, 'status': 'AssertionError', 'network': 'ReadError'}[outcome]
  assert 'private metric labels' not in json.dumps(recorder.evidence)


@pytest.mark.parametrize('outcome', ['success', 'status', 'network', 'read', 'cancel'])
async def test_api_diagnostic_idle_metrics_polls_concurrently_and_retires_siblings(monkeypatch, outcome):
  """Idle scrapes are read-only, fail promptly, and cannot outlive the idle observer."""
  clock = [0.0]
  read_started, poll_started = asyncio.Event(), asyncio.Event()
  requests, tasks = [], {}
  metric_requests = 0
  primary = httpx.ReadError('synthetic idle failure')
  metrics = '\n'.join(
    [f'resolution_run_elapsed_seconds_count{{mode="{mode}"}} 0' for mode in ('new', 'stale')]
    + [
      f'resolution_run_snapshot{{mode="{mode}",field="{key}"}} 0'
      for mode in ('new', 'stale')
      for key in ('active', 'pending', 'admission_in_progress', 'unknown')
    ]
  )

  async def request(request):
    nonlocal metric_requests
    requests.append((request.method, request.url.path))
    if request.url.path == '/metrics':
      metric_requests += 1
      if metric_requests == 2:
        tasks['poller'] = asyncio.current_task()
        await read_started.wait()
        poll_started.set()
        if outcome == 'network':
          raise primary
        if outcome == 'status':
          return httpx.Response(503, text='unavailable')
        if outcome in {'read', 'cancel'}:
          try:
            await asyncio.Event().wait()
          finally:
            if outcome == 'read':
              raise ValueError('secondary poller cleanup error')
      return httpx.Response(200, text=metrics)
    if request.url.path == '/health':
      tasks['reader'] = asyncio.current_task()
      read_started.set()
      await poll_started.wait()
      if outcome == 'read':
        raise primary
      if outcome in {'network', 'status', 'cancel'}:
        await asyncio.Event().wait()
    if request.url.path == '/ips/lists/1':
      clock[0] = 1
    return httpx.Response(200, json={})

  monkeypatch.setattr(sys.modules[__name__], 'perf_counter', lambda: clock[0])
  recorder = ApiDiagnosticRecorder()
  configuration = {
    'pass_timeout': 1,
    'idle_seconds': 0.2,
    'probe_interval': 0.001,
    'metrics_poll_interval': 0.05,
    'idle_metrics_polling': True,
  }
  async with httpx.AsyncClient(base_url='http://test', transport=httpx.MockTransport(request)) as client:
    observer = asyncio.create_task(api_diagnostic_idle(client, SimpleNamespace(count=2), configuration, recorder))
    try:
      async with asyncio.timeout(1):
        await poll_started.wait()
        if outcome == 'cancel':
          observer.cancel('cancel idle observer')
        if outcome == 'success':
          await observer
        else:
          expected = (
            asyncio.CancelledError
            if outcome == 'cancel'
            else AssertionError
            if outcome == 'status'
            else httpx.ReadError
          )
          with pytest.raises(expected) as caught:
            await observer
          if outcome in {'read', 'network'}:
            assert caught.value is primary
          if outcome == 'cancel':
            assert caught.value.args == ('cancel idle observer',)
      assert set(tasks) == {'reader', 'poller'}
      assert all(task.done() for task in tasks.values())
      assert all(method == 'GET' for method, _ in requests)
      assert 'metrics' not in recorder.observations
      if outcome == 'success':
        assert metric_requests == 3
        assert recorder.evidence['idle_drained_modes_after'] == recorder.evidence['idle_drained_modes_before']
        assert all(row['status_code'] == 200 for row in recorder.evidence['metrics_scrapes'])
    finally:
      observer.cancel()
      await asyncio.gather(observer, return_exceptions=True)


@pytest.mark.parametrize('failure_type', [TimeoutError, httpx.ReadError])
async def test_api_diagnostic_early_measurement_failure_keeps_original_error_and_blocks_next_phase(
  monkeypatch, tmp_path, failure_type
):
  """Exercise the orchestrator, artifact and cleanup boundary before any completed source pass."""
  module = sys.modules[__name__]
  primary = failure_type('early source observation failed')
  phases = []
  service = SimpleNamespace(
    root=Path(__file__).resolve().parents[2],
    directory=tmp_path,
    environment={},
    startup_attempts=[],
    url='http://test',
    process=None,
    providers=SimpleNamespace(reset_evidence=lambda: None, evidence=lambda: {'errors': []}),
  )

  async def start():
    service.process = object()

  async def stop(**kwargs):
    service.process = None

  async def begin(providers, phase):
    phases.append(phase)

  async def measure(*args, **kwargs):
    raise primary

  async def public_state(*args):
    return {'normalized_sha256': 'unchanged'}

  async def request(request):
    assert (request.method, request.url.path) == ('GET', '/metrics')
    return httpx.Response(200, text='fastapi_app_info{pid="7"} 1')

  service.start, service.stop = start, stop
  real_client = httpx.AsyncClient
  monkeypatch.setenv('GOST_API_DIAGNOSTIC_CONFIG', '{"smoke":true,"n":6,"independent_probe":false}')
  monkeypatch.setattr(
    httpx, 'AsyncClient', lambda **kwargs: real_client(transport=httpx.MockTransport(request), **kwargs)
  )
  monkeypatch.setattr(module, 'load_public_setup', AsyncMock())
  monkeypatch.setattr(module, 'batch_comparison_seed', lambda *args: (0, 'seed'))
  monkeypatch.setattr(module, 'batch_comparison_executed_source', lambda *args: {'stable': True})
  monkeypatch.setattr(module, 'load_begin_provider_cycle', begin)
  monkeypatch.setattr(module, 'load_measure_pass', measure)
  monkeypatch.setattr(module, 'batch_comparison_public_state', public_state)
  verify = AsyncMock()
  monkeypatch.setattr(module, 'load_verify_public', verify)
  async with asyncio.timeout(2):
    with pytest.raises(failure_type) as caught:
      await test_resolution_api_latency_diagnostic(service, tmp_path)
  assert caught.value is primary
  assert any('Warm/idle precondition not established' in note for note in primary.__notes__)
  assert phases == ['diagnostic-degraded-cold']
  verify.assert_not_awaited()
  artifact = json.loads((tmp_path / 'api-latency-diagnostic.json').read_text(encoding='utf-8'))
  assert artifact['status'] == 'failed'
  assert artifact['failure'] == {'type': failure_type.__name__, 'message': str(primary)}
  assert len(artifact['cases']) == 1
  assert artifact['cases'][0]['status'] == 'failed'
  assert artifact['cases'][0]['failure'] == artifact['failure']
  assert service.process is None
  assert not any(
    task.get_coro().__qualname__.startswith('ApiDiagnosticRecorder.watch_loop') for task in asyncio.all_tasks()
  )


@pytest.mark.parametrize('outcome', ['success', 'status', 'network', 'cancel'])
async def test_api_diagnostic_request_records_success_and_first_failure_without_payloads(outcome):
  entered = asyncio.Event()

  async def exchange(request):
    await request.extensions['trace']('http11.receive_response_headers.started', {'private': 'secret payload'})
    entered.set()
    if outcome == 'cancel':
      await asyncio.Event().wait()
    if outcome == 'network':
      raise httpx.ConnectError('synthetic connection failure')
    return httpx.Response(503 if outcome == 'status' else 200, json={'duration': 0.125, 'private': 'secret payload'})

  observations = LoadApiObservations(diagnostic=True)
  async with httpx.AsyncClient(
    transport=httpx.MockTransport(exchange), base_url='http://test', trust_env=False
  ) as client:
    task = asyncio.create_task(load_api_request(client, observations, 'ip_lists', 'GET', '/ips/lists', timeout=5))
    if outcome == 'cancel':
      await asyncio.wait_for(entered.wait(), timeout=1)
      task.cancel()
    if outcome == 'success':
      response = await task
    else:
      expected = {'status': AssertionError, 'network': httpx.ConnectError, 'cancel': asyncio.CancelledError}[outcome]
      with pytest.raises(expected):
        await task
  assert len(observations.requests) == 1
  row = observations.requests[0]
  assert row['elapsed_seconds'] == row['end_monotonic'] - row['start_monotonic']
  assert row['trace_callback_seconds'] >= 0
  assert row['observation_seconds'] >= 0
  assert [event['event'] for event in row['transport_events']] == ['http11.receive_response_headers.started']
  assert row['start_monotonic'] <= row['transport_events'][0]['at_monotonic'] <= row['end_monotonic']
  assert 'secret payload' not in json.dumps(row)
  if outcome in {'success', 'status'}:
    assert row['server_duration_seconds'] == 0.125
    assert row['status_code'] == (200 if outcome == 'success' else 503)
    assert row['body_bytes'] == len(response.content) if outcome == 'success' else row['body_bytes'] > 0
    assert observations['ip_lists'] == [row['elapsed_seconds']]
  else:
    assert row['status_code'] is None
    assert row['body_bytes'] is None
    assert row['error_type'] == ('ConnectError' if outcome == 'network' else 'CancelledError')
    assert 'ip_lists' not in observations
  assert len(observations.failures) == (0 if outcome == 'success' else 1)
  assert LoadApiObservations().requests is None


def test_api_diagnostic_artifact_failure_retains_attempt_and_original_error(monkeypatch, tmp_path):
  recorder = ApiDiagnosticRecorder()
  failure = OSError('synthetic artifact failure')

  def fail(path, artifact):
    raise failure

  monkeypatch.setattr(sys.modules[__name__], 'load_write_artifact', fail)
  with pytest.raises(OSError, match='synthetic artifact failure') as raised:
    recorder.write(tmp_path / 'diagnostic.json', {})
  assert raised.value is failure
  assert len(recorder.evidence['artifact_writes']) == 1
  row = recorder.evidence['artifact_writes'][0]
  assert row['elapsed_seconds'] == row['end_monotonic'] - row['start_monotonic']
  assert row['bytes_after_write'] is None


async def test_api_diagnostic_observer_can_disable_independent_added_load(tmp_path):
  recorder = ApiDiagnosticRecorder()
  # No URL is supplied: the explicit control must avoid starting any HTTP probe.
  async with api_diagnostic_observe(SimpleNamespace(directory=tmp_path), {'independent_probe': False}, recorder):
    await asyncio.sleep(0)
  assert 'independent_probe' not in recorder.evidence
  assert recorder.evidence['requests'] == []
  assert not any(
    task.get_coro().__qualname__.startswith('ApiDiagnosticRecorder.watch_loop') for task in asyncio.all_tasks()
  )


@pytest.mark.parametrize('exit_mode', ['normal', 'failure', 'cancel'])
async def test_api_diagnostic_independent_probe_retires_on_every_observer_exit(tmp_path, exit_mode):
  """The real independent process must stop and retain HTTP facts even when its owner fails."""
  paths = set()
  served = asyncio.Event()
  handlers = set()

  async def serve(reader, writer):
    task = asyncio.current_task()
    handlers.add(task)
    try:
      while True:
        headers = await reader.readuntil(b'\r\n\r\n')
        paths.add(headers.split(b' ', 2)[1].decode())
        body = b'{"duration":0.01}'
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n' + body)
        await writer.drain()
        if paths == {'/health', '/ips/lists?limit=10'}:
          served.set()
    except asyncio.IncompleteReadError, ConnectionError:
      pass
    finally:
      writer.close()
      await writer.wait_closed()
      handlers.discard(task)

  server = await asyncio.start_server(serve, '127.0.0.1', 0)
  service = SimpleNamespace(
    url=f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}', directory=tmp_path, environment=os.environ.copy()
  )
  recorder = ApiDiagnosticRecorder()
  configuration = {'independent_probe': True, 'probe_interval': 0.25, 'pass_timeout': 10}

  async def observe():
    async with api_diagnostic_observe(service, configuration, recorder):
      await asyncio.wait_for(served.wait(), timeout=5)
      if exit_mode == 'failure':
        raise LookupError('original owner failure')
      if exit_mode == 'cancel':
        asyncio.current_task().cancel()
        await asyncio.sleep(0)

  try:
    if exit_mode == 'normal':
      await observe()
    else:
      with pytest.raises(LookupError if exit_mode == 'failure' else asyncio.CancelledError):
        await observe()
    probe = recorder.evidence['independent_probe']
    assert probe['returncode'] == 0
    assert probe['ready']['pid'] != os.getpid()
    assert probe['deadline_reached'] is False
    assert {row['path'] for row in probe['requests']} == paths
    assert all(row['status_code'] == 200 and row['server_duration_seconds'] == 0.01 for row in probe['requests'])
    assert not any(
      task.get_coro().__qualname__.startswith('ApiDiagnosticRecorder.watch_loop') for task in asyncio.all_tasks()
    )
    assert 'probe_cleanup_failure' not in recorder.evidence
  finally:
    server.close()
    await server.wait_closed()
    if handlers:
      await asyncio.wait_for(asyncio.gather(*tuple(handlers)), timeout=2)


@pytest.mark.parametrize('initial_blocker', ['unknown', 'missing'])
async def test_api_diagnostic_idle_waits_for_verified_drain_and_never_triggers_jobs(initial_blocker, monkeypatch):
  """Wait for verified drain before exactly one deterministic, read-only idle sampling cycle.

  initial_blocker chooses an unknown count or a missing metric during the first
  scrape. monkeypatch controls only this test module's monotonic clock, keeping
  task scheduling from exhausting the synthetic idle window before reads start.
  """
  # calls records methods/paths; polls counts before/after metric scrapes.
  calls = []
  polls = 0
  # clock.value is elapsed synthetic seconds; clock.reads counts produced non-metrics responses.
  clock = SimpleNamespace(value=0.0, reads=0)
  # The clock callback returns unchanged time until the sixth mocked read response is produced.
  monkeypatch.setattr(sys.modules[__name__], 'perf_counter', lambda: clock.value)

  async def exchange(request):
    """Return synthetic metrics for request or one read response, advancing time only after six reads."""
    nonlocal polls
    calls.append((request.method, request.url.path))
    if request.url.path == '/metrics':
      polls += 1
      # lines is the public metric body; mode/key enumerate the required drain facts.
      lines = []
      for mode in ('new', 'stale'):
        for key in ('active', 'pending', 'admission_in_progress', 'unknown'):
          if polls == 1 and key == 'unknown' and initial_blocker == 'missing':
            continue
          # value keeps the first scrape blocked and makes the second/final scrapes fully drained.
          value = int(polls == 1 and key == 'unknown')
          lines.append(f'resolution_run_snapshot{{mode="{mode}",field="{key}"}} {value}')
      return httpx.Response(200, text='\n'.join(lines))
    assert polls >= 2, 'Read sampling began before verified drain'
    clock.reads += 1
    if clock.reads == 6:
      clock.value = 0.002
    return httpx.Response(200, json={})

  # recorder collects observed endpoint labels; client preserves the real HTTPX request/response boundary.
  recorder = ApiDiagnosticRecorder()
  async with httpx.AsyncClient(transport=httpx.MockTransport(exchange), base_url='http://test') as client:
    await api_diagnostic_idle(
      client, SimpleNamespace(count=6), {'pass_timeout': 1, 'idle_seconds': 0.001, 'probe_interval': 0.001}, recorder
    )
  assert polls == 3
  # method and path are captured request coordinates; all requests must remain read-only.
  assert all(method == 'GET' for method, path in calls)
  assert set(recorder.observations) == {'health', 'read', 'list', 'stats', 'ip_lists', 'ip_list'}
  assert len(recorder.observations.requests) == 6


async def load_calibrate_providers(service, configuration):
  """Measure local provider wire capacity independently of application processing."""
  saved_factory = service.providers.response_factory
  service.providers.response_factory = lambda transport, name, rdtype, attempt, cycle: {
    'kind': 'positive' if transport == 'ripe' or rdtype == dns.rdatatype.A else 'nodata',
    'addresses': ('11.0.0.0',),
    'prefix': '11.0.0.0/24',
  }
  query = dns.message.make_query('calibration.load.example.test', 'A')
  encoded = urlsafe_b64encode(query.to_wire()).decode().rstrip('=')
  count = min(256, max(32, configuration['warmup_size']))
  results = {}
  try:
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
      for transport in ('classic', 'doh', 'ripe'):
        service.providers.begin_cycle(f'calibration-{transport}')

        async def exchange(transport=transport):
          if transport == 'classic':
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [service.dns_host]
            resolver.timeout = 1
            resolver.lifetime = 2
            answer = await resolver.resolve('calibration.load.example.test', 'A')
            assert {record.address for record in answer} == {'11.0.0.0'}
          elif transport == 'doh':
            response = await client.get(
              service.doh_url, params={'dns': encoded}, headers={'Accept': 'application/dns-message'}
            )
            assert response.status_code == 200
            message = dns.message.from_wire(response.content)
            assert [str(record) for record in message.answer[0]] == ['11.0.0.0']
          else:
            response = await client.get(
              service.provider_url + '/data/network-info/data.json', params={'resource': '11.0.0.0'}
            )
            assert response.status_code == 200
            assert response.json()['data']['prefix'] == '11.0.0.0/24'

        warmup_started = perf_counter()
        await asyncio.gather(*(exchange() for _ in range(16)))
        warmup_seconds = perf_counter() - warmup_started
        durations = []
        for _ in range(3):
          started = perf_counter()
          for offset in range(0, count, 16):
            await asyncio.gather(*(exchange() for _ in range(min(16, count - offset))))
          durations.append(perf_counter() - started)
        elapsed = statistics.median(durations)
        results[transport] = {
          'requests': count,
          'seconds': elapsed,
          'requests_per_second': count / elapsed,
          'measured_repetitions_seconds': durations,
          'connection_warmup_requests': 16,
          'connection_warmup_seconds_excluded': warmup_seconds,
          'concurrency': 16,
          'provider_delay_seconds': 0,
        }
  finally:
    service.providers.response_factory = saved_factory
  return results


async def load_drain_stored(client, timeout, *, metrics_observer=None):
  async with asyncio.timeout(timeout):
    while True:
      fields = run_fields(
        parse_samples((await load_metrics_request(client, metrics_observer, scope='stored_drain')).text), 'stored'
      )
      if not fields or all(fields.get(key) == 0 for key in ('active', 'pending', 'admission_in_progress')):
        return
      await asyncio.sleep(0.05)


async def load_observe_pending(client, dataset, configuration, operation):
  """Assert representative API responsiveness while a real provider-dependent operation is pending."""
  finished = asyncio.Event()
  observations = LoadApiObservations()

  async def monitor():
    while not finished.is_set():
      await load_api_round(client, dataset, observations, timeout=5, job_mode='new')
      try:
        await asyncio.wait_for(finished.wait(), timeout=configuration['probe_interval'])
      except TimeoutError:
        pass

  monitor_task = asyncio.create_task(monitor())
  canary_task = asyncio.create_task(load_probe_canaries(client, observations, finished, configuration, job_mode='new'))
  operation_task = asyncio.create_task(operation)
  try:
    done, _ = await asyncio.wait((operation_task, monitor_task, canary_task), return_when=asyncio.FIRST_COMPLETED)
    for task in done:
      if task is not operation_task:
        await task
    result = await operation_task
  finally:
    finished.set()
    try:
      if sys.exception() is None:
        await monitor_task
        lifecycles = await canary_task
    finally:
      # Cancel and await every sibling even if successful draining raises.
      tasks = (operation_task, monitor_task, canary_task)
      for task in tasks:
        if not task.done():
          task.cancel()
      await asyncio.gather(*tasks, return_exceptions=True)
  return result, {
    'latency': {name: load_quantiles(values) for name, values in observations.items()},
    'canaries': lifecycles,
    'http_failures': observations.failures,
  }


@pytest.mark.parametrize(
  'failure_source', ['operation', 'monitor', 'canary', 'cancel', 'drain_monitor', 'drain_canary']
)
async def test_resolution_load_observer_preserves_first_failure_and_retires_all_tasks(failure_source):
  """No failing probe may leave a writer coroutine using a client after observer teardown."""
  started = {name: asyncio.Event() for name in ('monitor', 'canary', 'operation')}
  ended = {name: asyncio.Event() for name in started}
  operation_done = asyncio.Event()
  release = {name: asyncio.Event() for name in ('monitor', 'canary')}
  tasks = {}
  primary = RuntimeError(f'{failure_source} failed first')
  secondary = ValueError('Sibling failed during cleanup')

  async def all_started():
    for ready in started.values():
      await ready.wait()

  async def request(request):
    if request.method == 'GET' and request.url.path == '/domains/2':
      owner = 'monitor'
    elif request.method == 'POST' and request.url.path == '/domains':
      owner = 'canary'
    else:
      return httpx.Response(200, json={})
    tasks[owner] = asyncio.current_task()
    started[owner].set()
    try:
      await all_started()
      if failure_source == owner:
        raise primary
      await release[owner].wait()
      if failure_source == f'drain_{owner}':
        raise primary
      return httpx.Response(200, json={'name': 'api-probe.load.example.test'})
    finally:
      ended[owner].set()
      if (owner == 'monitor' and failure_source in {'operation', 'canary', 'cancel'}) or (
        owner == 'canary' and failure_source in {'monitor', 'drain_monitor'}
      ):
        raise secondary

  async def operation():
    tasks['operation'] = asyncio.current_task()
    tasks['operation'].add_done_callback(lambda task: operation_done.set())
    started['operation'].set()
    try:
      await all_started()
      if failure_source == 'operation':
        raise primary
      if failure_source.startswith('drain_'):
        return 'operation completed'
      await asyncio.Event().wait()
    finally:
      ended['operation'].set()

  async with httpx.AsyncClient(
    base_url='http://observer.test', transport=httpx.MockTransport(request), timeout=1, trust_env=False
  ) as client:
    observer = asyncio.create_task(
      load_observe_pending(client, SimpleNamespace(count=1), {'probe_interval': 0.01, 'pass_timeout': 1}, operation())
    )
    try:
      async with asyncio.timeout(2):
        await all_started()
        if failure_source == 'cancel':
          observer.cancel()
        if failure_source.startswith('drain_'):
          await operation_done.wait()
          assert tasks['operation'].done()
          release['monitor'].set()
          if failure_source == 'drain_canary':
            release['canary'].set()
        expected_error = asyncio.CancelledError if failure_source == 'cancel' else RuntimeError
        with pytest.raises(expected_error) as caught:
          await observer
      if failure_source != 'cancel':
        assert caught.value is primary
      assert set(tasks) == set(started)
      assert all(task.done() for task in tasks.values())
      assert all(event.is_set() for event in ended.values())
    finally:
      # Retire resources even when a regression causes the assertion itself to fail.
      owned = [observer, *tasks.values()]
      for task in owned:
        if not task.done():
          task.cancel()
      await asyncio.gather(*owned, return_exceptions=True)


async def test_resolution_load_observer_returns_result_after_complete_canary_lifecycle():
  """Successful operation completion still waits for public write/read/delete confirmation."""
  canary_added = asyncio.Event()
  operation_done = asyncio.Event()
  deleted = asyncio.Event()
  requests = []

  async def request(request):
    route = (request.method, request.url.path)
    requests.append(route)
    if route == ('POST', '/domains'):
      canary_added.set()
      await operation_done.wait()
    if route == ('GET', '/domains/search'):
      return httpx.Response(200, json={'payload': [{'id': 3, 'name': 'api-canary-0000000.load.example.test'}]})
    if route == ('GET', '/domains/3'):
      return httpx.Response(
        404 if deleted.is_set() else 200,
        json={'name': 'api-canary-0000000.load.example.test', 'last_resolved_at': 'confirmed', 'ips_v4': ['8.8.4.4']},
      )
    if route == ('DELETE', '/domains/3'):
      deleted.set()
    return httpx.Response(200, json={'name': 'api-probe.load.example.test'})

  async def operation():
    await canary_added.wait()
    asyncio.current_task().add_done_callback(lambda task: operation_done.set())
    return 'completed result'

  async with httpx.AsyncClient(
    base_url='http://observer.test', transport=httpx.MockTransport(request), timeout=1, trust_env=False
  ) as client:
    async with asyncio.timeout(2):
      result, evidence = await load_observe_pending(
        client, SimpleNamespace(count=1), {'probe_interval': 0.01, 'pass_timeout': 1}, operation()
      )
  assert result == 'completed result'
  assert len(evidence['canaries']) == 1
  assert evidence['canaries'][0]['status'] == 'passed'
  assert evidence['canaries'][0]['deleted'] is True
  assert deleted.is_set()
  assert requests.count(('POST', '/domains')) == requests.count(('DELETE', '/domains/3')) == 1
  assert requests.count(('GET', '/domains/3')) == 2
  assert set(evidence['latency']) == {'read', 'list', 'stats', 'job', 'write', 'search', 'delete'}


async def test_resolution_load_observer_keeps_reads_live_during_long_persistence(monkeypatch):
  """A virtual seventy-second persistence wait must not become an HTTP deadline."""
  clock = [0.0]
  real_sleep, real_timeout = asyncio.sleep, asyncio.timeout
  waiting = asyncio.Event()
  reads_while_waiting = asyncio.Event()
  created = asyncio.Event()
  visible = asyncio.Event()
  deleted = asyncio.Event()
  module = sys.modules[__name__]
  canary_name = ['']

  @asynccontextmanager
  async def virtual_timeout(seconds):
    deadline = clock[0] + seconds
    yield
    if clock[0] > deadline:
      raise TimeoutError('Virtual operation deadline exceeded')

  async def advance_persistence(seconds):
    assert seconds == 0.05
    assert not waiting.is_set(), (visible.is_set(), deleted.is_set(), clock[0])
    waiting.set()
    clock[0] += 70
    await reads_while_waiting.wait()
    visible.set()
    await real_sleep(0)

  async def request(request):
    clock[0] += 0.01
    route = (request.method, request.url.path)
    if route == ('POST', '/domains'):
      canary_name[0] = json.loads(request.content)[0]['domain']
      deleted.clear()
      created.set()
      await real_sleep(0)
    if route == ('GET', '/stats') and waiting.is_set():
      reads_while_waiting.set()
    if route == ('GET', '/domains/search'):
      rows = [{'id': 3, 'name': canary_name[0]}] if visible.is_set() else []
      return httpx.Response(200, json={'payload': rows})
    if route == ('GET', '/domains/3'):
      return httpx.Response(
        404 if deleted.is_set() else 200,
        json={'name': canary_name[0], 'last_resolved_at': 'confirmed', 'ips_v4': ['8.8.4.4']},
      )
    if route == ('DELETE', '/domains/3'):
      deleted.set()
    return httpx.Response(200, json={'name': 'api-probe.load.example.test'})

  async def operation():
    await created.wait()
    await visible.wait()
    return 'source persistence completed'

  monkeypatch.setattr(module, 'perf_counter', lambda: clock[0])
  monkeypatch.setattr(asyncio, 'timeout', virtual_timeout)
  monkeypatch.setattr(asyncio, 'sleep', advance_persistence)
  async with httpx.AsyncClient(base_url='http://observer.test', transport=httpx.MockTransport(request)) as client:
    async with real_timeout(2):
      result, evidence = await load_observe_pending(
        client, SimpleNamespace(count=1), {'probe_interval': 0.000001, 'pass_timeout': 120}, operation()
      )
  assert result == 'source persistence completed'
  assert reads_while_waiting.is_set()
  assert deleted.is_set()
  assert evidence['canaries'][0]['lifecycle_seconds'] > 60
  assert evidence['canaries'][0]['deleted'] is True
  assert all(values['max'] < 1 for values in evidence['latency'].values())
  assert evidence['http_failures'] == []


@pytest.mark.parametrize(
  ('label', 'path'),
  [
    ('read', '/domains/2'),
    ('list', '/domains?limit=10'),
    ('stats', '/stats'),
    ('write', '/domains'),
    ('job', '/commands/domains/resolve/new'),
    ('search', '/domains/search'),
    ('delete', '/domains/3'),
    ('stored_resolve', '/domains/3/resolve'),
  ],
)
@pytest.mark.parametrize('failure', ['slow', 'status', 'timeout'])
async def test_resolution_load_http_bounds_reject_each_route_and_keep_failure_facts(monkeypatch, label, path, failure):
  """Fast sibling routes cannot conceal one slow, erroneous, or stalled HTTP exchange."""
  clock = [0.0]

  async def request(request):
    if failure == 'timeout':
      await asyncio.Event().wait()
    clock[0] += 6 if failure == 'slow' else 0.01
    return httpx.Response(503 if failure == 'status' else 200, json={})

  monkeypatch.setattr(sys.modules[__name__], 'perf_counter', lambda: clock[0])
  observations = LoadApiObservations()
  method = 'DELETE' if label == 'delete' else 'POST' if label == 'stored_resolve' else 'GET'
  limit = 0.001 if failure == 'timeout' else 5
  async with httpx.AsyncClient(base_url='http://observer.test', transport=httpx.MockTransport(request)) as client:
    with pytest.raises(TimeoutError if failure == 'timeout' else AssertionError):
      await load_api_request(client, observations, label, method, path, timeout=limit)
  assert len(observations.get(label, [])) == (0 if failure == 'timeout' else 1)
  assert len(observations.failures) == 1
  assert observations.failures == [
    {
      'route': label,
      'method': method,
      'path': path,
      'elapsed_seconds': clock[0],
      'limit_seconds': limit,
      'status_code': None if failure == 'timeout' else 503 if failure == 'status' else 200,
      'error_type': 'TimeoutError' if failure == 'timeout' else None,
    }
  ]


async def test_resolution_load_cancelled_http_request_is_not_a_response_latency_sample():
  """Sibling cleanup records cancellation separately from completed response timings."""
  entered = asyncio.Event()
  observations = LoadApiObservations()

  async def request(request):
    entered.set()
    await asyncio.Event().wait()

  async with httpx.AsyncClient(base_url='http://observer.test', transport=httpx.MockTransport(request)) as client:
    task = asyncio.create_task(load_api_request(client, observations, 'read', 'GET', '/domains/2', timeout=5))
    try:
      async with asyncio.timeout(1):
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
          await task
      assert observations == {}
      assert len(observations.failures) == 1
      failure = observations.failures[0]
      assert failure['route'] == 'read'
      assert failure['path'] == '/domains/2'
      assert failure['error_type'] == 'CancelledError'
      assert failure['status_code'] is None
      assert 0 <= failure['elapsed_seconds'] < 5
    finally:
      task.cancel()
      await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('failure', ['p99', 'drain', 'budget'])
@pytest.mark.parametrize('diagnostic', [False, True])
async def test_resolution_load_measurement_keeps_completed_source_when_later_checks_fail(
  monkeypatch, failure, diagnostic
):
  """A failed API verdict or auxiliary drain retains the completed source measurement."""
  admitted = False
  deleted = False
  source_completed = asyncio.Event()
  real_sleep = asyncio.sleep
  real_client = httpx.AsyncClient
  clock = [0.0]
  metrics_calls, metrics_scrapes = [], []
  fields = dict.fromkeys(
    (
      'active',
      'pending',
      'admission_in_progress',
      'unknown',
      'known_not_committed',
      'not_admitted',
      'partial',
      'failure',
    ),
    0,
  )
  fields.update(selected=1, processing_complete=1, admitted=1, confirmed=1, attempted=1, success=1)

  async def request(request):
    nonlocal admitted, deleted
    clock[0] += 0.01
    await real_sleep(0)
    route = (request.method, request.url.path)
    if route == ('POST', '/commands/domains/resolve/stale'):
      admitted = True
    if route == ('GET', '/metrics'):
      metrics_calls.append(route)
      if failure == 'drain' and deleted and source_completed.is_set():
        raise ValueError('Auxiliary drain failed')
      if admitted:
        source_completed.set()
      if failure == 'budget' and len(metrics_calls) == 3:
        clock[0] = 1801
      metrics = ['fastapi_app_info{pid="7"} 1', f'resolution_run_elapsed_seconds_count{{mode="stale"}} {int(admitted)}']
      metrics.extend(
        f'resolution_run_snapshot{{mode="stale",field="{key}"}} {value if admitted else 0}'
        for key, value in fields.items()
      )
      return httpx.Response(200, text='\n'.join(metrics))
    if route == ('POST', '/domains'):
      deleted = False
    if route == ('GET', '/domains/search'):
      name = request.url.params['text']
      return httpx.Response(200, json={'payload': [{'id': 3, 'name': name}]})
    if route == ('GET', '/domains/3'):
      await source_completed.wait()
      return httpx.Response(
        404 if deleted else 200,
        json={'name': 'api-canary-0000000.load.example.test', 'last_resolved_at': 'confirmed', 'ips_v4': ['8.8.4.4']},
      )
    if route == ('DELETE', '/domains/3'):
      deleted = True
    if route == ('GET', '/domains'):
      return httpx.Response(200, json={'total': 3})
    return httpx.Response(200, json={'name': 'api-probe.load.example.test'})

  transport = httpx.MockTransport(request)
  monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(transport=transport, **kwargs))
  monkeypatch.setattr(sys.modules[__name__], 'perf_counter', lambda: clock[0])
  service = SimpleNamespace(
    url='http://observer.test',
    resource_snapshot=lambda pid: {
      'rss_bytes': 1,
      'peak_rss_bytes': 1,
      'cpu_seconds': 0,
      'source': 'controlled process boundary',
    },
  )
  dataset = SimpleNamespace(
    count=1, manifest=lambda: {'categories': {'success': 1, 'empty': 0, 'partial': 0, 'failure': 0}}
  )
  bounds = dict.fromkeys(('read', 'list', 'stats', 'job', 'write', 'search', 'delete', 'stored_resolve'), 5)
  measurement = {}
  configuration = {'probe_interval': 0.001, 'pass_timeout': 1800, 'rss_limit_mb': 1, 'cpu_percent_limit': 100}
  if diagnostic:
    configuration['metrics_poll_interval'] = 0.05
  async with asyncio.timeout(2):
    with pytest.raises(ValueError if failure == 'drain' else AssertionError):
      await load_measure_pass(
        service,
        dataset,
        configuration,
        bounds,
        mode='stale',
        p99_bounds=dict.fromkeys(bounds, 0.001),
        measurement=measurement,
        metrics_observer=metrics_scrapes if diagnostic else None,
      )
  assert measurement['source_pass_status'] == 'completed'
  assert measurement['wall_seconds_to_known_writer_outcomes'] > 0
  assert measurement['run'] == fields
  if failure == 'budget':
    assert measurement['source_budget']['within_maximum'] is False
    assert measurement['wall_seconds_to_known_writer_outcomes'] > 1800
    assert measurement.get('api_status') != 'passed'
    assert measurement.get('auxiliary_drain_status') is None
    return
  assert {'read', 'list', 'stats', 'job', 'write', 'search', 'delete'} <= set(measurement['api_latency_measured'])
  assert measurement['api_bounds_frozen_seconds'] == bounds
  assert measurement.get('api_status') != 'passed'
  assert measurement['api_failures'] == []
  assert (measurement.get('auxiliary_drain_status') == 'completed') is (failure == 'p99')
  assert len(metrics_scrapes) == (len(metrics_calls) if diagnostic else 0)
  assert 'metrics' not in measurement['api_latency_measured']
  if diagnostic:
    assert all(row['status_code'] == 200 for row in metrics_scrapes[:-1])
    assert metrics_scrapes[-1]['error_type'] == ('ValueError' if failure == 'drain' else None)
    scopes = {row['scope'] for row in metrics_scrapes}
    assert {'source_before', 'source_selection', 'source_idle_poll', 'stored_drain'} <= scopes
    assert ('auxiliary_drain' in scopes) is (failure == 'p99')


async def load_begin_provider_cycle(providers, cycle):
  async with asyncio.timeout(5):
    while providers.dns_active or providers.ripe_active:
      await asyncio.sleep(0.01)
  providers.begin_cycle(cycle)


def load_campaign_summary(cases):
  grouped = {}
  for case in cases:
    if (
      not case.get('measured', False)
      or case.get('status') != 'passed'
      or 'wall_seconds_to_known_writer_outcomes' not in case.get('measurement', {})
    ):
      continue
    key = (
      case['candidate'],
      case['size'],
      case['schedule'],
      case['cache'],
      case['cycle'],
      case['true_production_defaults'],
    )
    grouped.setdefault(key, []).append(case['measurement']['wall_seconds_to_known_writer_outcomes'])
  return [
    {
      'candidate': key[0],
      'size': key[1],
      'schedule': key[2],
      'cache': key[3],
      'cycle': key[4],
      'true_production_defaults': key[5],
      'repetitions': len(values),
      'median_seconds': statistics.median(values),
      'min_seconds': min(values),
      'max_seconds': max(values),
      'spread_seconds': max(values) - min(values),
    }
    for key, values in grouped.items()
  ]


def batch_comparison_snapshot(source, destination):
  """Copy an explicit source whitelist into a new generated artifact; never copy local state."""
  source, destination = Path(source).resolve(), Path(destination).resolve()
  repository = Path(__file__).resolve().parents[2]
  assert destination.is_relative_to(repository / '.pytest_cache')
  assert not destination.exists(), 'A frozen source snapshot must never be overwritten'
  manifest = load_source_evidence(source)
  for relative in manifest:
    path = source / relative
    assert not any(part.startswith('.') for part in Path(relative).parts)
    assert not path.is_symlink()
    assert path.resolve().is_relative_to(source)
  destination.mkdir(parents=True)
  for relative in manifest:
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / relative, target)
  assert load_source_evidence(destination) == manifest
  load_write_artifact(destination / 'source-manifest.json', {'source_sha256': manifest})
  return manifest


def batch_comparison_configuration():
  """Keep this finite comparison independent of the full campaign and require explicit source selection."""
  supplied = json.loads(os.environ.get('GOST_BATCH_COMPARE_CONFIG', '{}'))
  assert isinstance(supplied, dict)
  defaults = {
    'profile': 'historical',
    'variant': None,
    'source_root': None,
    'bounds_path': None,
    'smoke': False,
    'n': 10000,
    'repetitions': 3,
    'warmup_size': 128,
    'schedules': ['healthy', 'degraded'],
    'cache_states': ['cold', 'warm'],
    'seed': 20261106,
    'unique_ip_ratio': 0.7,
    'alias_every': 10,
    'provider_delay': 0.001,
    'pass_timeout': 1800,
    'verify_timeout': 600,
    'rss_limit_mb': 2048,
    'cpu_percent_limit': 200,
    'probe_interval': 0.25,
    'baseline_samples': 20,
    'latency_factor': 10,
    'latency_slack': 0.1,
  }
  assert set(supplied) <= set(defaults), 'Unknown comparison configuration field'
  configuration = defaults | supplied
  assert configuration['profile'] in {'historical', 'startup'}
  assert configuration['schedules'] in (['healthy'], ['degraded'], ['healthy', 'degraded'])
  assert configuration['cache_states'] in (['cold'], ['cold', 'warm'])
  if configuration['profile'] == 'historical':
    assert configuration['schedules'] == defaults['schedules']
    assert configuration['cache_states'] == defaults['cache_states']
  if configuration['profile'] == 'startup' and 'seed' not in supplied:
    configuration['seed'] = 20261104
  assert configuration['variant'] in {'before', 'after', 'smoke'}
  assert type(configuration['smoke']) is bool
  assert configuration['smoke'] == (configuration['variant'] == 'smoke')
  for key in ('n', 'repetitions', 'warmup_size', 'seed', 'alias_every', 'baseline_samples'):
    assert type(configuration[key]) is int, key
    assert configuration[key] > 0, key
  if configuration['smoke']:
    assert configuration['n'] <= 64
    assert configuration['repetitions'] == 1
  else:
    assert configuration['n'] == 10000
    minimum_repetitions = 1 if configuration['profile'] == 'startup' else 3
    assert minimum_repetitions <= configuration['repetitions'] <= 5
  assert configuration['warmup_size'] <= configuration['n']
  for key in (
    'unique_ip_ratio',
    'pass_timeout',
    'verify_timeout',
    'rss_limit_mb',
    'cpu_percent_limit',
    'probe_interval',
    'latency_factor',
    'latency_slack',
  ):
    assert isinstance(configuration[key], int | float)
    assert math.isfinite(configuration[key])
    assert configuration[key] > 0, key
  assert 0 < configuration['unique_ip_ratio'] <= 1
  assert 0 <= configuration['provider_delay'] <= 1
  assert configuration['pass_timeout'] <= 3600
  assert configuration['verify_timeout'] <= 1200
  assert configuration['baseline_samples'] <= 100
  assert configuration['warmup_size'] <= 10000
  if configuration['profile'] == 'startup':
    assert configuration['seed'] == 20261104
    assert configuration['provider_delay'] == 0.001
    assert configuration['unique_ip_ratio'] == 0.7
    assert configuration['alias_every'] == 10
  repository = Path(__file__).resolve().parents[2]
  for key in ('source_root', 'bounds_path'):
    assert isinstance(configuration[key], str), key
    assert configuration[key], key
    path = Path(configuration[key]).resolve()
    assert path.is_relative_to(repository / '.pytest_cache'), key
    configuration[key] = str(path)
  return configuration


def batch_comparison_environment(configuration):
  """Preserve historical replay defaults and select the fixed startup comparison explicitly."""
  if configuration['profile'] == 'historical':
    return {'DB_SAVE_BATCH_SIZE': '256', 'DB_SAVE_BATCH_TIMEOUT': '0.25'}
  return {
    'DOMAINS_RESOLVE_WORKER_LIMIT': '32',
    'DOMAINS_RESOLVE_SEMAPHORE_LIMIT': '64',
    'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT': '16',
    'REQ_MAX_CONNECTIONS': '32',
    'REQ_MAX_KEEPALIVE_CONNECTIONS': '32',
    'QUEUE_MAX_SIZE': '10000',
    'DB_SAVE_BATCH_SIZE': '1000',
    'DB_SAVE_BATCH_TIMEOUT': '0.1',
    'DOMAINS_UPDATE_INTERVAL': '0',
  }


async def batch_comparison_public_state(client, dataset, timeout):
  """Hash exact public ownership and logical checkpoints; retain volatile timestamp evidence separately."""
  rows = []
  async with asyncio.timeout(timeout):
    for offset in range(0, dataset.count + 2, 100):
      response = await client.get('/domains', params={'limit': 100, 'offset': offset})
      assert response.status_code == 200, response.text
      assert response.json()['total'] == dataset.count + 2
      rows.extend(response.json()['payload'])
  assert len(rows) == dataset.count + 2
  rows.sort(key=lambda row: row['id'])
  normalized = [
    [
      row['id'],
      row['name'],
      row['resolved'],
      sorted(row['ips_v4'] or []),
      sorted(row['ips_v6'] or []),
      row['last_resolved_at'] is not None,
    ]
    for row in rows
  ]
  return {
    'normalized_sha256': sha256(json.dumps(normalized).encode()).hexdigest(),
    'normalization': (
      'Exclude volatile timestamp values; preserve checkpoint presence, resolved state, IDs and addresses'
    ),
    'refresh_interval_seconds': 0,
    'raw_public_rows': rows,
  }


def batch_comparison_metric_delta(before, after):
  """Retain all bounded writer series, separating attempted dispatches and parameter sets."""
  prefixes = ('resolution_writer_duration_seconds', 'resolution_writer_batch_size', 'resolution_writer_sql_')
  return [
    {
      'name': name,
      'labels': dict(labels),
      'before': before.get((name, labels), 0),
      'after': value,
      'delta': value - before.get((name, labels), 0),
    }
    for (name, labels), value in after.items()
    if name.startswith(prefixes) and not name.endswith('_created')
  ]


def batch_comparison_executed_source(service, manifest):
  """Check child-reported imports and physical startup migrations after graceful process exit."""
  evidence = json.loads((service.directory / 'executed-source.json').read_text(encoding='utf-8'))
  assert Path(evidence['main']) == service.root / 'main.py'
  assert Path(evidence['pythonpath']) == service.root
  for module in ('config.config', 'database.db', 'metrics.metrics', 'server.server'):
    assert Path(evidence['modules'][module]) == service.root / (module.replace('.', '/') + '.py')
  expected = {Path(name).name: value for name, value in manifest.items() if name.startswith('migrations/')}
  assert evidence['migrations'] == expected
  assert load_source_evidence(service.root) == manifest, 'Measured source snapshot changed'
  return evidence


def batch_comparison_seed(service, dataset):
  elapsed = load_prepare_offline(service, dataset, stale=True, reset=True)
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute('PRAGMA foreign_keys=ON')
    # Startup clocks differ between revisions; retain the standalone row with a fixed checkpoint.
    connection.execute("UPDATE rdpr_domains SET last_resolved_at='2000-01-01 00:00:00' WHERE id=0")
    connection.execute(
      'INSERT INTO rdpr_ips_lists (id,name,url,attempts) '
      "VALUES (1,'probe-addresses','https://lists.example.test/probe',0) ON CONFLICT(id) DO NOTHING"
    )
    connection.execute('INSERT INTO rdpr_ip_supports (ip_record_id,domain_id,ip_list_id) VALUES (2,1,1)')
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    # Hash the full seeded domain checkpoints and ownership data.
    seed_rows = [
      connection.execute(query).fetchall()
      for query in (
        'SELECT id,name,resolved,last_resolved_at FROM rdpr_domains ORDER BY id',
        'SELECT id,domain_id,addr_type,ip_address FROM rdpr_ip_records ORDER BY id',
        'SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports ORDER BY id',
      )
    ]
  return elapsed, sha256(json.dumps(seed_rows).encode()).hexdigest()


async def test_batch_comparison_seed_converges_startup_checkpoints_without_omitting_standalone_domain(
  app, store, tmp_path
):
  """Different startup clocks must yield identical initial data without weakening its hash guard."""
  service = SimpleNamespace(
    process=None,
    db_path=tmp_path / app.settings.db_file_name,
    directory=tmp_path,
    root=Path(__file__).resolve().parents[2],
  )
  configuration = {'seed': 20261106, 'unique_ip_ratio': 0.7, 'alias_every': 10, 'provider_delay': 0.001}
  dataset = ResolutionLoadDataset(3, configuration)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo).values(
        id=0,
        name='default',
        resolved=True,
        ros_comment='Default Domain',
        last_resolved_at=STALE_CHECKPOINT,
      )
    )
  seeded_rows, hashes = [], []
  for checkpoint in ('2026-11-05 23:26:32', '2026-11-05 23:34:38'):
    with closing(sqlite3.connect(service.db_path)) as connection, connection:
      connection.execute('UPDATE rdpr_domains SET last_resolved_at=? WHERE id=0', (checkpoint,))
      assert connection.execute('SELECT last_resolved_at FROM rdpr_domains WHERE id=0').fetchone() == (checkpoint,)
      standalone_before = connection.execute(
        'SELECT id,name,resolved,ros_comment,created_at,updated_at FROM rdpr_domains WHERE id=0'
      ).fetchone()
    _, initial_hash = batch_comparison_seed(service, dataset)
    hashes.append(initial_hash)
    with closing(sqlite3.connect(service.db_path)) as connection:
      assert (
        connection.execute(
          'SELECT id,name,resolved,ros_comment,created_at,updated_at FROM rdpr_domains WHERE id=0'
        ).fetchone()
        == standalone_before
      )
      domains = connection.execute('SELECT id,name,resolved,last_resolved_at FROM rdpr_domains ORDER BY id').fetchall()
      assert domains[0] == (0, 'default', 1, '2000-01-01 00:00:00')
      assert len(domains) == dataset.count + 2
      seeded_rows.append(
        (
          domains,
          connection.execute('SELECT id,domain_id,addr_type,ip_address FROM rdpr_ip_records ORDER BY id').fetchall(),
          connection.execute('SELECT ip_record_id,domain_id,ip_list_id FROM rdpr_ip_supports ORDER BY id').fetchall(),
        )
      )
  assert seeded_rows[0] == seeded_rows[1]
  assert hashes[0] == hashes[1]
  # A real change to the retained standalone row must still invalidate the initial-data guard.
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute("UPDATE rdpr_domains SET name='standalone' WHERE id=0")
  _, changed_hash = batch_comparison_seed(service, dataset)
  assert changed_hash != hashes[0]


@pytest.mark.parametrize(
  'configuration', [{}, {'variant': 'before', 'n': 156298}, {'variant': 'before', 'repetitions': 1}]
)
def test_batch_comparison_requires_explicit_bounded_selection(monkeypatch, configuration):
  monkeypatch.setenv('GOST_BATCH_COMPARE_CONFIG', json.dumps(configuration))
  with pytest.raises(AssertionError):
    batch_comparison_configuration()


@pytest.mark.parametrize('repetitions', [0, 1, 2, 5, 6])
def test_batch_comparison_startup_profile_accepts_explicit_bounded_repetitions(monkeypatch, repetitions):
  root = Path(__file__).resolve().parents[2] / '.pytest_cache'
  supplied = {
    'profile': 'startup',
    'variant': 'before',
    'source_root': str(root / 'source'),
    'bounds_path': str(root / 'bounds.json'),
    'repetitions': repetitions,
  }
  monkeypatch.setenv('GOST_BATCH_COMPARE_CONFIG', json.dumps(supplied))
  if 1 <= repetitions <= 5:
    assert batch_comparison_configuration()['repetitions'] == repetitions
  else:
    with pytest.raises(AssertionError):
      batch_comparison_configuration()


@pytest.mark.parametrize(
  'selection',
  [
    {'schedules': []},
    {'schedules': ['unknown']},
    {'schedules': ['degraded', 'degraded']},
    {'cache_states': []},
    {'cache_states': ['warm']},
    {'cache_states': ['cold', 'cold']},
    {'profile': 'historical', 'schedules': ['degraded']},
    {'profile': 'historical', 'cache_states': ['cold']},
  ],
)
def test_batch_comparison_rejects_invalid_or_unsupported_scenario_selection(monkeypatch, selection):
  root = Path(__file__).resolve().parents[2] / '.pytest_cache'
  supplied = {
    'profile': 'startup',
    'variant': 'before',
    'source_root': str(root / 'source'),
    'bounds_path': str(root / 'bounds.json'),
  }
  monkeypatch.setenv('GOST_BATCH_COMPARE_CONFIG', json.dumps(supplied | selection))
  with pytest.raises(AssertionError):
    batch_comparison_configuration()


def test_batch_comparison_startup_profile_preserves_fixed_workload_and_historical_defaults(monkeypatch):
  root = Path(__file__).resolve().parents[2] / '.pytest_cache'
  supplied = {'variant': 'before', 'source_root': str(root / 'source'), 'bounds_path': str(root / 'bounds.json')}
  monkeypatch.setenv('GOST_BATCH_COMPARE_CONFIG', json.dumps(supplied))
  historical = batch_comparison_configuration()
  assert historical['seed'] == 20261106
  assert batch_comparison_environment(historical) == {'DB_SAVE_BATCH_SIZE': '256', 'DB_SAVE_BATCH_TIMEOUT': '0.25'}
  monkeypatch.setenv('GOST_BATCH_COMPARE_CONFIG', json.dumps(supplied | {'profile': 'startup'}))
  current = batch_comparison_configuration()
  assert (current['n'], current['repetitions'], current['seed']) == (10000, 3, 20261104)
  assert current['schedules'] == ['healthy', 'degraded']
  assert current['cache_states'] == ['cold', 'warm']
  assert current['provider_delay'] == 0.001
  assert (current['unique_ip_ratio'], current['alias_every']) == (0.7, 10)
  assert batch_comparison_environment(current) == {
    'DOMAINS_RESOLVE_WORKER_LIMIT': '32',
    'DOMAINS_RESOLVE_SEMAPHORE_LIMIT': '64',
    'RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT': '16',
    'REQ_MAX_CONNECTIONS': '32',
    'REQ_MAX_KEEPALIVE_CONNECTIONS': '32',
    'QUEUE_MAX_SIZE': '10000',
    'DB_SAVE_BATCH_SIZE': '1000',
    'DB_SAVE_BATCH_TIMEOUT': '0.1',
    'DOMAINS_UPDATE_INTERVAL': '0',
  }


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('failure_type', [ValueError, asyncio.CancelledError])
@pytest.mark.parametrize('cleanup_type', [RuntimeError, ValueError, asyncio.CancelledError])
async def test_process_startup_keeps_primary_error_when_cleanup_also_fails(
  e2e_service, monkeypatch, failure_type, cleanup_type
):
  service = e2e_service
  primary = failure_type('original startup failure')
  cleanup = cleanup_type('secondary cleanup failure')
  monkeypatch.setattr(asyncio, 'create_subprocess_exec', AsyncMock(side_effect=primary))
  original_stop = service.stop
  monkeypatch.setattr(service, 'stop', AsyncMock(side_effect=cleanup))
  try:
    with pytest.raises(failure_type) as caught:
      await service.start()
    assert caught.value is primary
    assert service.startup_attempts == [
      {
        'status': 'failed',
        'elapsed_seconds': service.startup_attempts[0]['elapsed_seconds'],
        'error': repr(primary),
        'cleanup_error': repr(cleanup),
      }
    ]
    assert service.startup_attempts[0]['elapsed_seconds'] >= 0
    assert caught.value.__notes__ == [f'Startup cleanup also failed: {cleanup!r}']
  finally:
    monkeypatch.setattr(service, 'stop', original_stop)
    if service.log is not None:
      service.log.close()
      service.log = None


@pytest.mark.e2e_load
@pytest.mark.skipif('GOST_SUPPORT_COMPONENT_CONFIG' not in os.environ, reason='Explicit component profiling only')
async def test_real_sqlite_support_maintenance_component_profile(app, startup_store, tmp_path):
  """Measure actual component SQL separately from public black-box process measurements."""
  configuration = json.loads(os.environ['GOST_SUPPORT_COMPONENT_CONFIG'])
  assert set(configuration) <= {'n', 'repetitions'}
  count = configuration.get('n', 40001)
  repetitions = configuration.get('repetitions', 3)
  assert type(count) is int
  assert 1 <= count <= 50000
  assert type(repetitions) is int
  assert 3 <= repetitions <= 5
  database_source = Path(app.database.__file__).resolve()
  intended_source_root = Path(__file__).resolve().parents[2]
  assert database_source == intended_source_root / 'database/db.py', 'Component imported an unintended database source'
  store = startup_store
  await store.setup()
  await store.close(timeout=2)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo),
      [{'id': value, 'name': f'domain-{value}.example.test', 'resolved': False} for value in (1, 2)],
    )
    await connection.execute(
      insert(app.database.IpRecordsDbo),
      [
        {
          'id': index + 1,
          'domain_id': 1,
          'addr_type': 4,
          'ip_address': str(IPv4Address(int(IPv4Address('11.0.0.0')) + index)),
        }
        for index in range(count)
      ],
    )
    await connection.execute(
      insert(app.database.IpSupportDbo),
      [{'ip_record_id': index + 1, 'domain_id': 1} for index in range(count)],
    )
  evidence = {
    'boundary': 'component: real disposable SQLite/AsyncSession; not E2E phase timing',
    'configuration': {'n': count, 'repetitions': repetitions, 'excluded_warmups': 1},
    'database_source_path': str(database_source),
    'intended_source_root': str(intended_source_root),
    'database_source_sha256': sha256(database_source.read_bytes()).hexdigest(),
    'sqlite': sqlite3.sqlite_version,
    'trials': [],
  }
  for repetition in range(repetitions + 1):
    async with store._DataBase__write_engine.begin() as connection:
      await connection.execute(text('UPDATE rdpr_ip_records SET domain_id=2 WHERE id=1'))
      await connection.execute(
        insert(app.database.IpRecordsDbo).values(id=count + 1, domain_id=1, addr_type=4, ip_address='9.9.9.9')
      )
    statements = []
    submitted_at = {}

    def before(conn, cursor, statement, parameters, context, executemany, submitted_at=submitted_at):
      submitted_at[id(context)] = perf_counter()

    def after(
      conn, cursor, statement, parameters, context, executemany, statements=statements, submitted_at=submitted_at
    ):
      statements.append(
        {
          'sql': statement,
          'parameters': parameters,
          'rowcount': cursor.rowcount,
          'dbapi_seconds': perf_counter() - submitted_at.pop(id(context)),
        }
      )

    engine = store._DataBase__write_engine.sync_engine
    async with store._DataBase__write_session_factory() as session:
      await session.execute(text('BEGIN IMMEDIATE'))
      event.listen(engine, 'before_cursor_execute', before)
      event.listen(engine, 'after_cursor_execute', after)
      started = perf_counter()
      try:
        await store._DataBase__finish_ip_supports(session)
      finally:
        event.remove(engine, 'before_cursor_execute', before)
        event.remove(engine, 'after_cursor_execute', after)
      finish_seconds = perf_counter() - started
      started = perf_counter()
      await session.commit()
      commit_seconds = perf_counter() - started
    assert len(statements) == 2
    assert statements[0]['sql'].startswith('DELETE FROM')
    assert statements[1]['sql'].startswith('UPDATE ')
    assert [statement['rowcount'] for statement in statements] == [1, 1]
    async with store._DataBase__read_engine.connect() as connection:
      assert (await connection.execute(text('SELECT domain_id FROM rdpr_ip_records WHERE id=1'))).scalar_one() == 1
      assert (await connection.execute(text('SELECT count(*) FROM rdpr_ip_records'))).scalar_one() == count
      for statement in statements:
        result = await connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement['sql'], statement['parameters'])
        statement['explain_query_plan'] = [list(row) for row in result]
    evidence['trials'].append(
      {
        'measured': repetition > 0,
        'statements': statements,
        'finish_seconds': finish_seconds,
        'commit_seconds': commit_seconds,
      }
    )
    load_write_artifact(tmp_path / 'support-maintenance-component.json', evidence)


def test_batch_comparison_snapshot_copies_only_whitelisted_source_and_is_immutable(tmp_path):
  root = Path(__file__).resolve().parents[2]
  source = tmp_path / 'source'
  for relative in (
    'main.py',
    'pyproject.toml',
    'poetry.lock',
    'tests/conftest.py',
    f'tests/integration/{Path(__file__).name}',
    'config/config.py',
    'migrations/example.py',
  ):
    path = source / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('# synthetic source\n', encoding='utf-8')
  (source / '.env').write_text('NOT_A_REAL_SECRET=excluded\n', encoding='utf-8')
  (source / 'user.sqlite').write_bytes(b'excluded')
  with TemporaryDirectory(prefix='source-copy-', dir=root / '.pytest_cache') as directory:
    destination = Path(directory) / 'frozen-source'
    manifest = batch_comparison_snapshot(source, destination)
    assert set(manifest) == {
      'main.py',
      'pyproject.toml',
      'poetry.lock',
      'tests/conftest.py',
      f'tests/integration/{Path(__file__).name}',
      'config/config.py',
      'migrations/example.py',
    }
    assert {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()} == {
      *manifest,
      'source-manifest.json',
    }
    with pytest.raises(AssertionError, match='never be overwritten'):
      batch_comparison_snapshot(source, destination)


async def test_startup_comparison_keeps_restart_failure_and_finishes_independent_cases(monkeypatch, tmp_path):
  """A completed source pass remains measured when its restart fails; the matrix still finishes."""
  module = sys.modules[__name__]
  primary = AssertionError('first restart failed')
  providers = SimpleNamespace(response_factory=None, reset_evidence=lambda: None, evidence=lambda: {'errors': []})
  service = SimpleNamespace(providers=providers, startup_attempts=[], process=None, url='http://unused.test', starts=0)

  async def start():
    service.starts += 1
    service.startup_attempts.append({'status': 'failed' if service.starts == 2 else 'ready'})
    if service.starts == 2:
      raise primary
    service.process = object()

  async def stop(**kwargs):
    service.process = None

  async def begin(*args):
    pass

  async def measure(*args, measurement, **kwargs):
    measurement.update(
      source_pass_status='completed',
      auxiliary_drain_status='completed',
      wall_seconds_to_known_writer_outcomes=1,
      wall_seconds_including_auxiliary_drain=1,
      source_run_count=1,
      ripe_network_requests=0,
      run=dict.fromkeys(
        ('active', 'pending', 'admission_in_progress', 'unknown', 'known_not_committed', 'not_admitted'), 0
      )
      | {'selected': 2, 'attempted': 2, 'processing_complete': 1, 'admitted': 2, 'confirmed': 2},
    )

  async def verify(*args):
    return {'verified_sources': 2}

  async def public_state(*args):
    return {'normalized_sha256': 'logical-state', 'raw_public_rows': []}

  class Client:
    def __init__(self, **kwargs):
      pass

    async def __aenter__(self):
      return self

    async def __aexit__(self, *args):
      pass

    async def get(self, path):
      return httpx.Response(200, text='')

  service.start = start
  service.stop = stop
  monkeypatch.setattr(module, 'batch_comparison_seed', lambda *args: (0, 'same-seed'))
  monkeypatch.setattr(module, 'batch_comparison_executed_source', lambda *args: {'stable': True})
  monkeypatch.setattr(module, 'load_begin_provider_cycle', begin)
  monkeypatch.setattr(module, 'load_measure_pass', measure)
  monkeypatch.setattr(module, 'load_verify_public', verify)
  monkeypatch.setattr(module, 'batch_comparison_public_state', public_state)
  monkeypatch.setattr(httpx, 'AsyncClient', Client)
  configuration = {
    'variant': 'before',
    'bounds_path': str(tmp_path / 'bounds.json'),
    'repetitions': 1,
    'n': 2,
    'warmup_size': 2,
    'seed': 20261104,
    'unique_ip_ratio': 0.7,
    'alias_every': 10,
    'provider_delay': 0.001,
    'verify_timeout': 5,
    'smoke': True,
  }
  shared = {
    'baseline': {'bounds_seconds': {'read': 5}, 'p99_bounds_seconds': {'read': 1}},
    'measured_initial_data_sha256': 'same-seed',
  }
  evidence = {'cases': []}
  with pytest.raises(AssertionError) as caught:
    await batch_comparison_startup_cases(service, configuration, shared, {}, evidence, tmp_path / 'facts.json')
  assert caught.value is primary
  assert len(evidence['cases']) == 8
  assert [case['status'] for case in evidence['cases']] == ['passed', 'failed', *['passed'] * 6]
  assert evidence['cases'][1]['failure']['message'] == 'first restart failed'
  assert evidence['cases'][1]['measurement']['wall_seconds_to_known_writer_outcomes'] == 1
  assert all(row['complete_source_measurements'] == 1 for row in evidence['summary'].values())
  assert service.process is None
  assert evidence['status'] == 'failed'


@pytest.fixture
def startup_comparison_harness(monkeypatch, tmp_path):
  """Control process and measurement boundaries while exercising real matrix orchestration."""
  module = sys.modules[__name__]
  providers = SimpleNamespace(response_factory=None, reset_evidence=lambda: None, evidence=lambda: {'errors': []})
  service = SimpleNamespace(
    providers=providers, startup_attempts=[], process=None, url='http://unused.test', cycle=None
  )
  harness = SimpleNamespace(
    service=service,
    primary=AssertionError('list p99 exceeded 1 second'),
    failure=None,
    measurements=[],
    events=[],
    after_metrics=False,
  )

  async def start():
    assert service.process is None
    service.process = object()
    service.startup_attempts.append({'status': 'ready'})
    harness.events.append(('start', service.cycle, service.process))

  async def stop(**kwargs):
    running = service.process is not None
    harness.events.append(('stop', service.cycle, service.process))
    service.process = None
    if running and harness.failure == 'cleanup' and service.cycle == 'healthy-1-cold':
      raise RuntimeError('secondary cleanup failure')

  async def begin(providers, cycle):
    service.cycle = cycle
    harness.after_metrics = False

  async def measure(*args, measurement, **kwargs):
    harness.measurements.append((service.cycle, service.process))
    fields = dict.fromkeys(
      ('active', 'pending', 'admission_in_progress', 'unknown', 'known_not_committed', 'not_admitted'), 0
    )
    fields.update(selected=2, attempted=2, processing_complete=1, admitted=2, confirmed=2)
    measurement.update(
      source_pass_status='completed',
      auxiliary_drain_status='completed',
      wall_seconds_to_known_writer_outcomes=2,
      wall_seconds_including_auxiliary_drain=3,
      source_run_count=1,
      ripe_network_requests=1,
      run=fields,
      api_status='passed',
    )
    if service.cycle == 'healthy-1-cold' and harness.failure is not None:
      measurement['api_status'] = 'failed'
      if harness.failure in {'incomplete', 'cleanup'}:
        measurement['source_pass_status'] = 'in_progress'
      elif harness.failure == 'drain':
        measurement.pop('auxiliary_drain_status')
      elif harness.failure in {'pending', 'unknown'}:
        fields[harness.failure] = 1
      harness.after_metrics = True
      raise harness.primary

  async def verify(*args):
    if service.cycle == 'healthy-1-cold' and harness.failure == 'verification':
      raise ValueError('public ownership verification failed')
    return {'verified_sources': 2, 'api_result_sha256': 'verified-result'}

  async def public_state(*args):
    return {'normalized_sha256': 'logical-state', 'raw_public_rows': []}

  class Client:
    def __init__(self, **kwargs):
      pass

    async def __aenter__(self):
      return self

    async def __aexit__(self, *args):
      pass

    async def get(self, path):
      if harness.after_metrics and harness.failure == 'metrics':
        raise httpx.ReadError('post-measurement metrics unavailable')
      return httpx.Response(200, text='')

  service.start, service.stop = start, stop
  monkeypatch.setattr(module, 'batch_comparison_seed', lambda *args: (0, 'same-seed'))
  monkeypatch.setattr(module, 'batch_comparison_executed_source', lambda *args: {'stable': True})
  monkeypatch.setattr(module, 'load_begin_provider_cycle', begin)
  monkeypatch.setattr(module, 'load_measure_pass', measure)
  monkeypatch.setattr(module, 'load_verify_public', verify)
  monkeypatch.setattr(module, 'batch_comparison_public_state', public_state)
  monkeypatch.setattr(httpx, 'AsyncClient', Client)
  harness.configuration = {
    'variant': 'before',
    'bounds_path': str(tmp_path / 'bounds.json'),
    'repetitions': 1,
    'n': 2,
    'warmup_size': 2,
    'seed': 20261104,
    'unique_ip_ratio': 0.7,
    'alias_every': 10,
    'provider_delay': 0.001,
    'verify_timeout': 5,
    'smoke': True,
  }
  harness.shared = {
    'baseline': {'bounds_seconds': {'list': 5}, 'p99_bounds_seconds': {'list': 1}},
    'measured_initial_data_sha256': 'same-seed',
  }
  harness.evidence = {'cases': []}
  harness.artifact_path = tmp_path / 'facts.json'
  return harness


@pytest.mark.parametrize(
  'failure', ['p99', 'incomplete', 'drain', 'pending', 'unknown', 'verification', 'metrics', 'cleanup']
)
async def test_startup_comparison_separates_failed_acceptance_from_verified_warm_input(
  startup_comparison_harness, failure
):
  """Only fully verified persisted input may retain a failed cold pass's process for warm measurement."""
  harness = startup_comparison_harness
  harness.failure = failure
  with pytest.raises(AssertionError) as caught:
    await batch_comparison_startup_cases(
      harness.service, harness.configuration, harness.shared, {}, harness.evidence, harness.artifact_path
    )
  assert caught.value is harness.primary
  cases = harness.evidence['cases']
  assert len(cases) == 8
  cold, warm = cases[2:4]
  assert cold['status'] == 'failed'
  assert cold['failure'] == {'type': 'AssertionError', 'message': 'list p99 exceeded 1 second'}
  assert cold['measurement']['wall_seconds_to_known_writer_outcomes'] == 2
  assert cold['measurement']['api_status'] == 'failed'
  assert harness.evidence['status'] == 'failed'
  assert all(case['status'] == 'passed' for case in [*cases[:2], *cases[4:]])
  measurements = dict(harness.measurements)
  if failure == 'p99':
    assert warm['status'] == 'passed'
    assert cold['warm_precondition'] == {
      'source_completed': True,
      'auxiliary_drained': True,
      'known_writer_outcomes': True,
      'public_results_verified': True,
      'status': 'verified',
    }
    assert cold['verification']['verified_sources'] == 2
    assert 'raw_metrics_after' in cold
    assert measurements['healthy-1-cold'] is measurements['healthy-1-warm']
    assert not any(event[:2] == ('stop', 'healthy-1-cold') for event in harness.events)
    assert harness.evidence['summary']['healthy-cold']['fully_passed_cases'] == 0
    assert harness.evidence['summary']['healthy-warm']['fully_passed_cases'] == 1
  else:
    assert warm['status'] == 'blocked'
    assert warm['failure']['type'] == 'PreconditionFailure'
    assert 'healthy-1-warm' not in measurements
    assert cold['warm_precondition']['status'] == 'unverified'
    assert any(event[:2] == ('stop', 'healthy-1-cold') for event in harness.events)
    if failure in {'verification', 'metrics'}:
      assert cold['secondary_failures'][0]['message'] in {
        'public ownership verification failed',
        'post-measurement metrics unavailable',
      }
    if failure == 'cleanup':
      assert 'secondary cleanup failure' in cold['cleanup_error']
  assert harness.service.process is None


@pytest.mark.parametrize('reference', ['missing', 'mismatch'])
async def test_startup_comparison_exercises_missing_reference_but_guards_existing_mismatch(
  startup_comparison_harness, reference
):
  """Absent paired evidence cannot imply acceptance or suppress the current revision's measurements."""
  harness = startup_comparison_harness
  harness.configuration['variant'] = 'after'
  states = {
    f'{schedule}-{repetition}-{temperature}': 'logical-state'
    for schedule in ('healthy', 'degraded')
    for repetition in (0, 1)
    for temperature in ('cold', 'warm')
  }
  key = 'healthy-1-warm' if reference == 'missing' else 'healthy-1-cold'
  if reference == 'missing':
    del states[key]
  else:
    states[key] = 'different-initial-state'
  state_path = Path(harness.configuration['bounds_path']).with_suffix('.initial-states.json')
  load_write_artifact(state_path, states)
  original = state_path.read_bytes()
  with pytest.raises(AssertionError, match='Missing initial state reference' if reference == 'missing' else 'differ'):
    await batch_comparison_startup_cases(
      harness.service, harness.configuration, harness.shared, {}, harness.evidence, harness.artifact_path
    )
  assert state_path.read_bytes() == original
  assert harness.evidence['status'] == 'failed'
  assert len(harness.evidence['cases']) == 8
  measurements = dict(harness.measurements)
  if reference == 'missing':
    assert len(measurements) == 8
    warm = harness.evidence['cases'][3]
    assert warm['status'] == 'failed'
    assert warm['comparison'] == {'status': 'INCOMPARABLE', 'missing_initial_state_reference': key}
    assert warm['measurement']['source_pass_status'] == 'completed'
    assert warm['restart_verification']['verified_sources'] == 2
    assert measurements['healthy-1-cold'] is measurements['healthy-1-warm']
  else:
    assert len(measurements) == 6
    assert 'healthy-1-cold' not in measurements
    assert 'healthy-1-warm' not in measurements
    assert harness.evidence['cases'][2]['measurement'] == {}
    assert harness.evidence['cases'][3]['status'] == 'blocked'
  assert harness.service.process is None


async def test_startup_comparison_cold_only_selection_still_verifies_restart_and_stops(startup_comparison_harness):
  harness = startup_comparison_harness
  harness.configuration.update(schedules=['degraded'], cache_states=['cold'])
  await batch_comparison_startup_cases(
    harness.service, harness.configuration, harness.shared, {}, harness.evidence, harness.artifact_path
  )
  cases = harness.evidence['cases']
  assert [(case['schedule'], case['cache'], case['measured']) for case in cases] == [
    ('degraded', 'cold', False),
    ('degraded', 'cold', True),
  ]
  assert all(case['status'] == 'passed' and case['restart_verification']['verified_sources'] == 2 for case in cases)
  assert [cycle for cycle, process in harness.measurements] == ['degraded-0-cold', 'degraded-1-cold']
  assert set(harness.evidence['summary']) == {'degraded-cold'}
  assert harness.service.process is None


async def batch_comparison_startup_cases(service, configuration, shared, manifest, evidence, artifact_path):
  """Keep independent failure evidence across the complete cold/warm and provider matrix."""
  first_failure = None

  def record_failure(entry, error):
    nonlocal first_failure
    failure = {'type': type(error).__name__, 'message': str(error)[:4000]}
    if 'failure' not in entry:
      entry['failure'] = failure
    elif entry['failure'] != failure:
      entry.setdefault('secondary_failures', []).append(failure)
    entry['status'] = 'failed'
    if first_failure is None:
      first_failure = error

  state_path = Path(configuration['bounds_path']).with_suffix('.initial-states.json')
  initial_states = json.loads(state_path.read_text(encoding='utf-8')) if configuration['variant'] == 'after' else {}
  evidence['maintenance_phase_boundary'] = (
    'Public E2E finish metric combines orphan deletion and incumbent repair. '
    'Separate real SQLite component profile reports their SQL and durations; these are not E2E phase times.'
  )
  schedules = configuration.get('schedules', ('healthy', 'degraded'))
  cache_states = configuration.get('cache_states', ('cold', 'warm'))
  for schedule in schedules:
    for repetition in range(configuration['repetitions'] + 1):
      warmup = repetition == 0
      dataset = ResolutionLoadDataset(configuration['warmup_size'] if warmup else configuration['n'], configuration)
      dataset.schedule = schedule
      dataset.probe_ip_lists = True
      service.providers.response_factory = dataset.response
      await load_begin_provider_cycle(service.providers, f'{schedule}-{repetition}-cold')
      service.providers.reset_evidence()
      seed_seconds, initial_sha = batch_comparison_seed(service, dataset)
      if not warmup:
        assert initial_sha == shared['measured_initial_data_sha256'], 'Cold initial fixture changed'
      source_ok = False
      for temperature in cache_states:
        entry = {
          'schedule': schedule,
          'cache': temperature,
          'repetition': repetition,
          'warmup': warmup,
          'measured': not warmup,
          'status': 'in_progress',
          'dataset': dataset.manifest(),
          'cold_initial_data_sha256': initial_sha,
          'seed_seconds_excluded': seed_seconds,
          'measurement': {},
        }
        evidence['cases'].append(entry)
        try:
          if temperature == 'cold':
            startup_index = len(service.startup_attempts)
            try:
              await service.start()
            finally:
              entry['startup_attempts'] = service.startup_attempts[startup_index:]
          elif not source_ok:
            entry['status'] = 'blocked'
            entry['failure'] = {'type': 'PreconditionFailure', 'message': 'Cold source did not establish warm state'}
            continue
          else:
            await load_begin_provider_cycle(service.providers, f'{schedule}-{repetition}-warm')
            service.providers.reset_evidence()
          async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
            entry['initial_public_state'] = await batch_comparison_public_state(
              client, dataset, configuration['verify_timeout']
            )
            raw_before = (await client.get('/metrics')).text
          key = f'{schedule}-{repetition}-{temperature}'
          state_hash = entry['initial_public_state']['normalized_sha256']
          if configuration['variant'] == 'after':
            if key not in initial_states:
              entry['comparison'] = {'status': 'INCOMPARABLE', 'missing_initial_state_reference': key}
              record_failure(entry, AssertionError(f'Missing initial state reference: {key}'))
            else:
              assert initial_states[key] == state_hash, 'Logical initial ownership/checkpoints differ across revisions'
              entry['comparison'] = {'status': 'matched', 'initial_state_reference': key}
          else:
            initial_states[key] = state_hash
            load_write_artifact(state_path, initial_states)
          entry['raw_metrics_before'] = raw_before
          try:
            await load_measure_pass(
              service,
              dataset,
              configuration,
              shared['baseline']['bounds_seconds'],
              mode='stale',
              p99_bounds=shared['baseline']['p99_bounds_seconds'],
              measurement=entry['measurement'],
              on_progress=lambda progress, entry=entry: (
                entry.update(progress=progress),
                load_write_artifact(artifact_path, evidence),
              ),
            )
          except (AssertionError, RuntimeError, ValueError, TimeoutError, OSError, httpx.HTTPError, KeyError) as error:
            record_failure(entry, error)
          measurement = entry['measurement']
          fields = measurement.get('run', {})
          entry['warm_precondition'] = {
            'source_completed': measurement.get('source_pass_status') == 'completed',
            'auxiliary_drained': (
              measurement.get('auxiliary_drain_status') == 'completed'
              and measurement.get('wall_seconds_including_auxiliary_drain') is not None
              and measurement.get('source_run_count') == 1
            ),
            'known_writer_outcomes': (
              fields.get('selected') == fields.get('attempted') == dataset.count
              and fields.get('processing_complete') == 1
              and fields.get('admitted') is not None
              and fields.get('admitted') == fields.get('confirmed')
              and all(
                fields.get(name) == 0
                for name in (
                  'active',
                  'pending',
                  'admission_in_progress',
                  'unknown',
                  'known_not_committed',
                  'not_admitted',
                )
              )
            ),
            'public_results_verified': False,
            'status': 'unverified',
          }
          precondition = entry['warm_precondition']
          assert all(
            precondition[name] for name in ('source_completed', 'auxiliary_drained', 'known_writer_outcomes')
          ), (
            'Source did not establish drained, known writer outcomes',
            precondition,
          )
          async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
            entry['raw_metrics_after'] = (await client.get('/metrics')).text
            entry['verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
          assert entry['verification']['verified_sources'] == dataset.count, 'Public source verification is incomplete'
          entry['writer_metric_deltas'] = batch_comparison_metric_delta(
            parse_samples(raw_before), parse_samples(entry['raw_metrics_after'])
          )
          precondition.update(public_results_verified=True, status='verified')
          source_ok = True
          if temperature == 'warm':
            cold = evidence['cases'][-2]
            assert entry['measurement']['ripe_network_requests'] <= cold['measurement']['ripe_network_requests']
          if temperature == cache_states[-1]:
            await service.stop()
            entry['executed_source'] = batch_comparison_executed_source(service, manifest)
            startup_index = len(service.startup_attempts)
            try:
              await service.start()
            finally:
              entry['restart_attempts'] = service.startup_attempts[startup_index:]
            async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
              entry['restart_verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
            await service.stop()
            entry['restart_source'] = batch_comparison_executed_source(service, manifest)
          if 'failure' not in entry:
            entry['status'] = 'passed'
        except (AssertionError, RuntimeError, ValueError, TimeoutError, OSError, httpx.HTTPError, KeyError) as error:
          record_failure(entry, error)
        finally:
          entry['providers'] = service.providers.evidence()
          # A failed acceptance verdict can still leave valid warm input in the same process/cache.
          if not source_ok or temperature == cache_states[-1]:
            try:
              await service.stop(allow_failure=entry['status'] != 'passed')
            except (AssertionError, RuntimeError, TimeoutError, OSError) as cleanup_error:
              entry['cleanup_error'] = repr(cleanup_error)
              entry['status'] = 'failed'
              if first_failure is None:
                first_failure = cleanup_error
          load_write_artifact(artifact_path, evidence)
  evidence['summary'] = {}
  for schedule in schedules:
    for temperature in cache_states:
      cases = [
        case
        for case in evidence['cases']
        if case['measured'] and case['schedule'] == schedule and case['cache'] == temperature
      ]
      timings = [
        case['measurement']['wall_seconds_to_known_writer_outcomes']
        for case in cases
        if case['measurement'].get('source_pass_status') == 'completed'
      ]
      evidence['summary'][f'{schedule}-{temperature}'] = {
        'complete_source_measurements': len(timings),
        'fully_passed_cases': sum(case['status'] == 'passed' for case in cases),
        'raw_seconds': timings,
        'median_seconds': statistics.median(timings) if timings else None,
        'acceptance_scale': not configuration['smoke'],
      }
  evidence['status'] = 'failed' if first_failure is not None else 'passed'
  load_write_artifact(artifact_path, evidence)
  if first_failure is not None:
    raise first_failure
  assert all(row['fully_passed_cases'] == configuration['repetitions'] for row in evidence['summary'].values())


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.skipif(
  'GOST_BATCH_COMPARE_CONFIG' not in os.environ,
  reason='The revision comparison requires an explicitly selected configuration',
)
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True, 'request_sample_limit': 128}], indirect=True)
async def test_ip_persistence_revision_comparison(e2e_service, tmp_path):
  """Run one explicitly selected frozen revision with shared guards and no full-campaign defaults."""
  configuration = batch_comparison_configuration()
  service = e2e_service
  source_root = Path(configuration['source_root'])
  manifest = load_source_evidence(source_root)
  assert json.loads((source_root / 'source-manifest.json').read_text(encoding='utf-8'))['source_sha256'] == manifest
  service.select_source(source_root)
  # Fixed test resource settings apply identically to both revisions; no algorithm selector exists.
  service.environment.update(batch_comparison_environment(configuration))
  bounds_path = Path(configuration['bounds_path'])
  artifact_path = tmp_path / 'ip-persistence-comparison.json'
  workload = {
    key: value for key, value in configuration.items() if key not in {'variant', 'source_root', 'bounds_path'}
  }
  evidence = {
    'configuration': configuration,
    'workload': workload,
    'source_sha256': manifest,
    'harness_sha256': {
      name: sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
      for name in ('tests/conftest.py', f'tests/integration/{Path(__file__).name}')
    },
    'environment': {
      'python': sys.version,
      'executable_sha256': sha256(Path(sys.executable).read_bytes()).hexdigest(),
      'sqlite': sqlite3.sqlite_version,
      'platform': platform.platform(),
      'processor': platform.processor(),
      'logical_cpu_count': os.cpu_count(),
      'versions': {
        name: importlib.metadata.version(name)
        for name in ('sqlalchemy', 'aiosqlite', 'httpx', 'fastapi', 'cashews', 'uvicorn', 'pytest')
      },
    },
    'executed_paths': {
      'main': str(source_root / 'main.py'),
      'pythonpath': service.environment['PYTHONPATH'],
      'config': str(source_root / 'config/config.py'),
      'migrations': str(service.directory / 'migrations'),
    },
    'measurement_scope': 'attempted application writer DBAPI dispatch and phase metrics include auxiliary API writes',
    'cache_precondition': (
      'cold process followed by warm pass in the same process; refresh interval zero, volatile checkpoints excluded'
      if configuration['profile'] == 'startup'
      else 'cold process-local cache on every warmup and measured pass'
    ),
    'status': 'in_progress',
    'cases': [],
  }
  assert {name: manifest[name] for name in evidence['harness_sha256']} == evidence['harness_sha256'], (
    'Executed harness differs from the frozen source manifest'
  )
  load_write_artifact(artifact_path, evidence)
  try:
    await service.start()
    await load_public_setup(service, 30)
    await service.stop()
    evidence['startup_source'] = batch_comparison_executed_source(service, manifest)
    effective = load_effective_settings(service)
    evidence['effective_settings'] = effective
    comparable_settings = {
      key: value for key, value in effective.items() if key not in {'DB_BASE_DIR', 'DB_FILE_NAME', 'RIPE_STAT_BASE_URL'}
    }
    compatibility = {
      'workload': workload,
      'effective_settings': comparable_settings,
      'harness_sha256': evidence['harness_sha256'],
      'runtime': evidence['environment'],
      'common_source_sha256': {name: value for name, value in manifest.items() if name != 'database/db.py'},
    }
    if configuration['variant'] == 'after':
      shared = json.loads(bounds_path.read_text(encoding='utf-8'))
      assert shared['compatibility'] == compatibility, 'Settings, harness or workload changed between revisions'
      assert shared['dataset'] == ResolutionLoadDataset(configuration['n'], configuration).manifest()
    else:
      assert not bounds_path.exists(), 'Frozen bounds cannot be overwritten'
      idle = ResolutionLoadDataset(configuration['n'], configuration)
      idle.probe_ip_lists = True
      _, initial_sha = batch_comparison_seed(service, idle)
      # No source domain is stale during the idle baseline; only explicit canaries resolve.
      with closing(sqlite3.connect(service.db_path)) as connection, connection:
        connection.execute("UPDATE rdpr_domains SET last_resolved_at='2100-01-01 00:00:00' WHERE id>0")
      service.providers.response_factory = idle.response
      measured_refresh = service.environment.get('DOMAINS_UPDATE_INTERVAL')
      if configuration['profile'] == 'startup':
        # Idle probes must not reselect a committed canary while its deletion is being confirmed.
        service.environment['DOMAINS_UPDATE_INTERVAL'] = '172800'
        evidence['idle_only_environment_override'] = {'DOMAINS_UPDATE_INTERVAL': '172800'}
        evidence['idle_effective_settings'] = load_effective_settings(service)
      try:
        await service.start()
        baseline = await load_freeze_api_bounds(service, idle, configuration)
        if configuration['profile'] == 'startup':
          baseline['p99_bounds_seconds'] = dict.fromkeys(baseline['bounds_seconds'], 1.0)
          baseline['formula'] = 'request/max <= 5s; p99 <= 1s for every route'
        await service.stop()
      finally:
        if measured_refresh is None:
          service.environment.pop('DOMAINS_UPDATE_INTERVAL', None)
        else:
          service.environment['DOMAINS_UPDATE_INTERVAL'] = measured_refresh
      assert {
        'ip_lists',
        'ip_list',
        'read',
        'list',
        'stats',
        'job',
        'write',
        'search',
        'delete',
        'stored_resolve',
      } <= set(baseline['bounds_seconds'])
      shared = {
        'compatibility': compatibility,
        'baseline': baseline,
        'baseline_source_sha256': manifest,
        'dataset': idle.manifest(),
        'measured_initial_data_sha256': initial_sha,
      }
      bounds_path.parent.mkdir(parents=True, exist_ok=True)
      load_write_artifact(bounds_path, shared)
    evidence['shared_bounds_sha256'] = sha256(bounds_path.read_bytes()).hexdigest()
    evidence['shared_bounds'] = shared
    if configuration['profile'] == 'startup':
      await batch_comparison_startup_cases(service, configuration, shared, manifest, evidence, artifact_path)
      return
    for repetition in range(configuration['repetitions'] + 1):
      warmup = repetition == 0
      dataset = ResolutionLoadDataset(configuration['warmup_size'] if warmup else configuration['n'], configuration)
      dataset.probe_ip_lists = True
      service.providers.response_factory = dataset.response
      await load_begin_provider_cycle(service.providers, f'comparison-{repetition}')
      service.providers.reset_evidence()
      seed_seconds, initial_sha = batch_comparison_seed(service, dataset)
      if not warmup:
        assert initial_sha == shared['measured_initial_data_sha256'], 'Initial data differs from frozen fixture'
      entry = {
        'repetition': repetition,
        'warmup': warmup,
        'measured': not warmup,
        'status': 'in_progress',
        'dataset': dataset.manifest(),
        'initial_data_sha256': initial_sha,
        'seed_seconds_excluded': seed_seconds,
        'measurement': {},
      }
      evidence['cases'].append(entry)
      load_write_artifact(artifact_path, evidence)
      try:
        await service.start()
        async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
          raw_before = (await client.get('/metrics')).text
        entry['raw_metrics_before'] = raw_before
        await load_measure_pass(
          service,
          dataset,
          configuration,
          shared['baseline']['bounds_seconds'],
          mode='stale',
          p99_bounds=shared['baseline']['p99_bounds_seconds'],
          measurement=entry['measurement'],
          on_progress=lambda progress, entry=entry: (
            entry.update(progress=progress),
            load_write_artifact(artifact_path, evidence),
          ),
        )
        async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
          raw_after = (await client.get('/metrics')).text
          entry['verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
        entry['writer_metric_deltas'] = batch_comparison_metric_delta(
          parse_samples(raw_before), parse_samples(raw_after)
        )
        entry['raw_metrics_before'] = raw_before
        entry['raw_metrics_after'] = raw_after
        phases = {
          row['labels'].get('phase')
          for row in entry['writer_metric_deltas']
          if row['name'] == 'resolution_writer_duration_seconds_count' and row['delta'] > 0
        }
        assert {'prepare', 'reconcile', 'finish', 'transaction', 'commit'} <= phases
        assert any(
          row['name'] == 'resolution_writer_sql_dispatches_total' and row['delta'] > 0
          for row in entry['writer_metric_deltas']
        )
        await service.stop()
        entry['executed_source'] = batch_comparison_executed_source(service, manifest)
        await service.start()
        async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
          entry['restart_verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
        await service.stop()
        entry['restart_source'] = batch_comparison_executed_source(service, manifest)
        entry['status'] = 'passed'
      except BaseException as error:
        entry['status'] = 'failed'
        entry['failure'] = {'type': type(error).__name__, 'message': str(error)[:4000]}
        raise
      finally:
        entry['providers'] = service.providers.evidence()
        if service.process is not None:
          try:
            async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
              entry['raw_metrics_at_cleanup'] = (await client.get('/metrics')).text
          except httpx.HTTPError, TimeoutError:
            entry['cleanup_metrics_unavailable'] = True
          await service.stop(allow_failure=True)
        load_write_artifact(artifact_path, evidence)
    measured = [case for case in evidence['cases'] if case['measured'] and case['status'] == 'passed']
    assert len(measured) == configuration['repetitions']
    assert len({case['initial_data_sha256'] for case in measured}) == 1
    elapsed = [case['measurement']['wall_seconds_to_known_writer_outcomes'] for case in measured]
    evidence['summary'] = {
      'complete_measured_passes': len(elapsed),
      'median_seconds': statistics.median(elapsed),
      'min_seconds': min(elapsed),
      'max_seconds': max(elapsed),
      'spread_seconds': max(elapsed) - min(elapsed),
      'acceptance_scale': not configuration['smoke'],
    }
    evidence['status'] = 'passed'
  except BaseException as error:
    evidence['status'] = 'failed'
    evidence['failure'] = {'type': type(error).__name__, 'message': str(error)[:4000]}
    raise
  finally:
    triggering_failure = sys.exception()
    evidence['final_source_sha256'] = load_source_evidence(service.root)
    evidence['source_stable'] = evidence['final_source_sha256'] == manifest
    if not evidence['source_stable']:
      evidence['status'] = 'failed'
      evidence['source_failure'] = 'Source snapshot changed during measurement'
    load_write_artifact(artifact_path, evidence)
    if not evidence['source_stable'] and triggering_failure is None:
      raise AssertionError('Source snapshot changed during measurement')


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True, 'request_sample_limit': 128}], indirect=True)
async def test_resolution_load_campaign(e2e_service, tmp_path):
  configuration = resolution_load_configuration()
  try:
    with e2e_service.cpu_profile(configuration['cpu_profile']):
      await load_run_campaign(e2e_service, tmp_path, configuration)
  finally:
    path = tmp_path / 'resolution-load-campaign.json'
    if path.exists():
      primary = sys.exception()
      try:
        artifact = json.loads(path.read_text(encoding='utf-8'))
        artifact['cpu_profile'] = e2e_service.cpu_evidence
        artifact['startup_attempts'] = e2e_service.startup_attempts
        if primary is not None:
          artifact.update(status='failed', failure={'type': type(primary).__name__, 'message': str(primary)[:4000]})
        load_write_artifact(path, artifact)
      except (OSError, ValueError) as error:
        if primary is None:
          raise
        primary.add_note(f'Final campaign artifact update failed: {error!r}')


async def load_run_campaign(service, tmp_path, configuration):
  """Compare defaults and bounded candidates using complete public flows and frozen API bounds."""
  source_snapshot = load_source_evidence(service.root)
  artifact_path = tmp_path / 'resolution-load-campaign.json'
  sizes = list(dict.fromkeys(math.ceil(configuration['n'] * value) for value in configuration['factors']))
  if configuration['full_size_stability']:
    sizes = [max(sizes)]
  entire_matrix = (
    set(configuration['stages']) == {'baseline', 'warmup', 'healthy', 'degraded'}
    and configuration['candidate_names'] is None
    and configuration['repetition_numbers'] is None
    and not configuration['diagnostic']
    and not configuration['full_size_stability']
  )
  artifact = {
    'profile': configuration['profile'],
    'campaign_scope': 'full_size_cpu_stability' if configuration['full_size_stability'] else 'size_candidate_matrix',
    'cpu_profile': service.cpu_evidence,
    'run_started_at_utc': datetime.now(UTC).isoformat(),
    'acceptance_scale': configuration['profile'] == 'full' and configuration['n'] == 156298 and entire_matrix,
    'scale_basis': 'observed 2026-11-04 domain count' if configuration['n'] == 156298 else 'explicit custom size',
    'entire_matrix_selected': entire_matrix,
    'execution_filters': {key: configuration[key] for key in ('stages', 'candidate_names', 'repetition_numbers')},
    'configuration': configuration,
    'observed_source': {
      'n': 156298,
      'observed_at_utc': '2026-11-04T17:48:24.364638Z',
      'path': 'db/rdpr-db.sqlite',
      'sha256': 'f4d879fdc3c488ca4955f5c4de71d46530e75a57ecf00f5b7c09ba8031132555',
      'scope': 'local read-only observation; not a deployment assertion',
    },
    'environment': {
      'python': sys.version,
      'platform': platform.platform(),
      'machine': platform.machine(),
      'processor': platform.processor(),
      'logical_cpu_count': os.cpu_count(),
      'versions': {
        name: importlib.metadata.version(name)
        for name in (
          'pytest',
          'pytest-asyncio',
          'httpx',
          'httpx-retries',
          'sqlalchemy',
          'aiosqlite',
          'dnspython',
          'cashews',
          'fastapi',
          'uvicorn',
          'pydantic',
          'pydantic-settings',
          'prometheus-client',
        )
      },
      'invocation': [sys.executable, '-m', 'pytest', *sys.argv[1:]],
    },
    'source_sha256': source_snapshot,
    'safety_limits_are_not_external_slas': True,
    'stale_acceptance_budget': {
      'maximum_seconds': 1800,
      'preferred_seconds': 900,
      'scope': 'User-required full STALE pass through known persistence; API guards remain independent',
    },
    'cases': [],
    'planned_stability_cases': [
      {
        'schedule': schedule,
        'repetition': repetition,
        'cycle': cycle,
        'cache': 'cold' if cycle == 0 else 'warm',
        'size': max(sizes),
      }
      for schedule in ('healthy', 'degraded')
      for repetition in range(1, configuration['repetitions'] + 1)
      for cycle in range(3)
    ]
    if configuration['full_size_stability']
    else [],
    'status': 'in_progress',
  }
  load_write_artifact(artifact_path, artifact)
  isolation = dict(service.environment)
  await service.start()
  await load_public_setup(service, 30)
  await service.stop()
  largest = ResolutionLoadDataset(max(sizes), configuration)
  artifact['idle_seed_seconds'] = load_prepare_offline(service, largest)
  service.providers.response_factory = largest.response
  await service.start()
  artifact['provider_calibration'] = await load_calibrate_providers(service, configuration)
  artifact['idle_api_baseline'] = await load_freeze_api_bounds(service, largest, configuration)
  bounds = artifact['idle_api_baseline']['bounds_seconds']
  await service.stop()
  load_write_artifact(artifact_path, artifact)

  async def case(candidate, count, schedule, repetition, *, true_defaults=False, warmup=False):
    dataset = ResolutionLoadDataset(count, configuration)
    dataset.schedule = schedule
    service.environment.clear()
    service.environment.update(isolation)
    service.environment.update(candidate['environment'])
    if configuration['full_size_stability']:
      effective = load_effective_settings(service)
      assert int(effective['DB_POOL_SIZE']) == 5, 'Stability replay must retain the original read pool'
      assert int(effective['RIPE_STAT_CACHE_SIZE']) == 10000, 'Stability replay must retain the original cache size'
    workload = {} if true_defaults else {'DOMAINS_UPDATE_INTERVAL': '0'}
    service.environment.update(workload)
    service.providers.response_factory = dataset.response
    service.providers.begin_cycle(f'{candidate["name"]}-{count}-{schedule}-{repetition}-cold')
    service.providers.reset_evidence()
    seed_seconds = load_prepare_offline(service, dataset, stale=not true_defaults, reset=True)
    database_input = load_database_input_evidence(service) if configuration['diagnostic'] else None
    started = perf_counter()
    manifest = dataset.manifest()
    generator_seconds = perf_counter() - started
    await service.start()
    temperatures = (
      ('cold',)
      if true_defaults or configuration['diagnostic_cold_only']
      else (
        'cold',
        *('warm' for _ in range(configuration['soak_cycles'] - 1 if configuration['profile'] == 'full' else 1)),
      )
    )
    cold_measurement = None
    for cycle, temperature in enumerate(temperatures):
      if temperature == 'warm':
        await load_begin_provider_cycle(
          service.providers, f'{candidate["name"]}-{count}-{schedule}-{repetition}-warm-{cycle}'
        )
        service.providers.reset_evidence()
      entry = {
        'candidate': candidate['name'],
        'size': count,
        'schedule': schedule,
        'repetition': repetition,
        'cache': temperature,
        'cycle': cycle,
        'measured': not warmup,
        'warmup': warmup,
        'true_production_defaults': true_defaults,
        'tuned_environment': candidate['environment'],
        'workload_overrides': workload,
        'effective_settings': load_effective_settings(service),
        'dataset': manifest,
        'seed_seconds_excluded': seed_seconds,
        'generator_seconds_excluded': generator_seconds,
        **({'database_input': database_input} if database_input is not None else {}),
        'status': 'in_progress',
        'cpu': service.startup_attempts[-1].get('cpu'),
      }
      artifact['cases'].append(entry)
      load_write_artifact(artifact_path, artifact)

      def report_progress(progress, entry=entry):
        entry['progress'] = progress
        entry['progress_updates'] = entry.get('progress_updates', 0) + 1
        before_write = perf_counter()
        if configuration['progress_writes'] == 'original':
          load_write_artifact(artifact_path, artifact)
        entry['progress_artifact_write_seconds'] = entry.get('progress_artifact_write_seconds', 0) + (
          perf_counter() - before_write
        )

      entry['measurement'] = {}
      try:
        measurement = await load_measure_pass(
          service,
          dataset,
          configuration,
          bounds,
          mode='new' if true_defaults else 'stale',
          p99_bounds=artifact['idle_api_baseline']['p99_bounds_seconds'],
          on_progress=report_progress,
          measurement=entry['measurement'],
        )
        entry['measurement'] = measurement
        load_assert_source_budget(measurement, configuration)
        if not true_defaults:
          duration = measurement['wall_seconds_to_known_writer_outcomes']
          entry['stale_budget'] = {
            'maximum_seconds': 1800,
            'preferred_seconds': 900,
            'within_maximum': duration <= 1800,
            'within_preferred': duration <= 900,
            'at_least_observed_population': count >= artifact['observed_source']['n'],
            'full_matrix_acceptance_scale': artifact['acceptance_scale'],
          }
        if temperature == 'cold':
          cold_measurement = measurement
        async with httpx.AsyncClient(base_url=service.url, timeout=max(bounds.values()), trust_env=False) as client:
          await load_drain_stored(client, configuration['pass_timeout'])
          entry['verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
        entry['providers'] = service.providers.evidence()
        entry['provider_evidence_scope'] = 'phase-local counters and samples; attempts reset before phase'
        entry['calibrated_provider_capacity_vs_average_demand'] = {}
        for transport, capacity in artifact['provider_calibration'].items():
          actual_requests = sum(
            row['count']
            for row in entry['providers']['counters']
            if row['transport'] == transport and row['record'] not in {'attempt', 'status', 'transport'}
          )
          demand = actual_requests / measurement['wall_seconds_including_auxiliary_drain']
          entry['calibrated_provider_capacity_vs_average_demand'][transport] = {
            'actual_requests': actual_requests,
            'average_requests_per_second': demand,
            'duration_includes_canary_drain': True,
            'calibrated_requests_per_second': capacity['requests_per_second'],
            'capacity_to_average_demand_ratio': capacity['requests_per_second'] / demand if demand else None,
            'limitation': 'average demand does not establish headroom for a short burst',
          }
        if temperature == 'warm':
          assert cold_measurement is not None
          assert measurement['ripe_network_requests'] <= cold_measurement['ripe_network_requests']
        if true_defaults:
          async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
            before = parse_samples((await client.get('/metrics')).text)
            assert (await client.post('/commands/domains/resolve/stale')).status_code == 200
            _, freshness = await load_wait_idle(
              client, 'stale', 0, sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stale'), 10
            )
            assert freshness['attempted'] == freshness['confirmed'] == 0
            entry['default_freshness_excludes_recently_resolved_sources'] = freshness
        entry['status'] = 'passed'
      except BaseException as error:
        entry['status'] = 'failed'
        entry['failure'] = {'type': type(error).__name__, 'message': str(error)[:4000]}
        raise
      finally:
        artifact['summary'] = load_campaign_summary(artifact['cases'])
        load_write_artifact(artifact_path, artifact)
    try:
      await service.stop()
      await service.start()
      async with httpx.AsyncClient(base_url=service.url, timeout=max(bounds.values()), trust_env=False) as client:
        entry['restart_verification'] = await load_verify_public(client, dataset, configuration['verify_timeout'])
      await service.stop()
    except BaseException as error:
      entry.update(status='failed', failure={'type': type(error).__name__, 'message': str(error)[:4000]})
      try:
        await service.stop(allow_failure=True)
      except BaseException as cleanup_error:  # noqa: BLE001 -- Preserve the first restart failure.
        entry['restart_cleanup_error'] = repr(cleanup_error)
        error.add_note(f'Restart cleanup failed: {cleanup_error!r}')
      raise
    load_write_artifact(artifact_path, artifact)

  try:
    # This first complete pass retains the real freshness interval and every production default.
    repetitions = configuration['repetition_numbers'] or list(range(1, configuration['repetitions'] + 1))
    if 'baseline' in configuration['stages']:
      for repetition in repetitions:
        await case(configuration['candidates'][0], sizes[0], 'healthy', repetition, true_defaults=True)
    for candidate in configuration['candidates']:
      if configuration['candidate_names'] is not None and candidate['name'] not in configuration['candidate_names']:
        continue
      if 'warmup' in configuration['stages']:
        await case(candidate, min(configuration['warmup_size'], min(sizes)), 'healthy', 0, warmup=True)
      if 'healthy' in configuration['stages']:
        for count in sizes:
          for repetition in repetitions:
            await case(candidate, count, 'healthy', repetition)
      if 'degraded' in configuration['stages']:
        for repetition in repetitions:
          await case(candidate, max(sizes), 'degraded', repetition)
    artifact['status'] = 'passed'
    assert load_source_evidence(service.root) == source_snapshot, 'Source inputs changed during campaign'
  except BaseException as error:
    artifact['status'] = 'failed'
    artifact['failure'] = {'type': type(error).__name__, 'message': str(error)[:4000]}
    raise
  finally:
    artifact['summary'] = load_campaign_summary(artifact['cases'])
    artifact['uncompleted_stability_cases'] = [
      planned
      for planned in artifact['planned_stability_cases']
      if not any(
        entry['status'] == 'passed'
        and not entry['warmup']
        and all(entry[key] == value for key, value in planned.items())
        for entry in artifact['cases']
      )
    ]
    load_write_artifact(artifact_path, artifact)


@pytest.mark.e2e
@pytest.mark.e2e_load
@pytest.mark.parametrize('e2e_service', [{'start': False, 'load': True, 'request_sample_limit': 256}], indirect=True)
async def test_resolution_load_protocol_failures_recover(e2e_service, tmp_path):
  """Exercise priority, real writes, protocol failures, repeated cycles and shutdown through public boundaries."""
  service = e2e_service
  configuration = resolution_load_configuration()
  dataset = ResolutionLoadDataset(max(8, min(configuration['n'], 128)), configuration)
  snapshot = load_source_evidence(service.root)
  artifact = {
    'profile': configuration['profile'],
    'run_started_at_utc': datetime.now(UTC).isoformat(),
    'scope': 'bounded functional resilience, not scale acceptance',
    'source_sha256': snapshot,
    'scenarios': [],
    'status': 'in_progress',
  }
  artifact_path = tmp_path / 'resolution-load-resilience.json'
  await service.start()
  await load_public_setup(service, 30)
  await service.stop()
  load_prepare_offline(service, dataset, stale=True)
  # These explicit failure-injection budgets are fixed across the functional scenarios.
  service.environment.update(
    {
      'DOMAINS_UPDATE_INTERVAL': '0',
      'QUEUE_MAX_SIZE': '2',
      'DB_SAVE_BATCH_SIZE': '1',
      'DB_SAVE_BATCH_TIMEOUT': '0.02',
      'DNS_TIMEOUT': '0.2',
      'DNS_LIFETIME': '0.5',
      'DNS_OPERATION_TIMEOUT': '1',
      'DOH_OPERATION_TIMEOUT': '1',
      'RIPE_STAT_OPERATION_TIMEOUT': '1',
    }
  )
  service.providers.response_factory = dataset.response
  await service.start()
  load_write_artifact(artifact_path, artifact)
  try:
    async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
      # Hold started STALE work at the external protocol, then inject genuinely new data.
      service.providers.hold_dns_names = {dataset.name(index) for index in range(dataset.count)}
      before = parse_samples((await client.get('/metrics')).text)
      assert (await client.post('/commands/domains/resolve/stale')).status_code == 200
      async with asyncio.timeout(5):
        while len(service.providers.dns_entered_by_name) < 4:
          await asyncio.sleep(0.01)
      created = perf_counter()
      newcomer = 'new-priority.load.example.test'
      assert (await client.post('/domains', json=[{'domain': newcomer}])).status_code == 200
      async with asyncio.timeout(5):
        while True:
          response = await client.get('/domains/search', params={'text': newcomer})
          assert response.status_code == 200
          matches = [row for row in response.json()['payload'] if row['name'] == newcomer]
          if matches:
            new_id = matches[0]['id']
            break
          await asyncio.sleep(0.02)
      write_confirmed_seconds = perf_counter() - created
      assert write_confirmed_seconds <= 5
      for _ in range(3):
        assert (await client.post('/commands/domains/resolve/new')).status_code == 200
      started_stale_names = set(service.providers.dns_entered_by_name)
      for name in started_stale_names:
        service.providers.hold_dns_names.discard(name)
        service.providers.dns_release_by_name[name].set()
      async with asyncio.timeout(5):
        while True:
          response = await client.get(f'/domains/{new_id}')
          assert response.status_code == 200
          if response.json()['last_resolved_at'] is not None:
            assert set(response.json()['ips_v4'] or []) == {'8.8.4.4'}
            priority_snapshot = run_fields(parse_samples((await client.get('/metrics')).text), 'stale')
            assert priority_snapshot['processing_complete'] == 0, priority_snapshot
            assert priority_snapshot['confirmed'] < dataset.count, priority_snapshot
            assert service.providers.hold_dns_names, 'The priority oracle must retain unfinished STALE work'
            assert priority_snapshot['not_started'] + priority_snapshot['active'] > 0, priority_snapshot
            break
          await asyncio.sleep(0.01)
      service.providers.hold_dns_names.clear()
      for release in service.providers.dns_release_by_name.values():
        release.set()
      _, fields = await load_wait_idle(
        client,
        'stale',
        dataset.count,
        sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stale'),
        30,
      )
      artifact['priority_observed_run'] = fields
      artifact['priority_dns_metric_samples'] = [
        {'labels': dict(labels), 'count': value}
        for (metric_name, labels), value in parse_samples((await client.get('/metrics')).text).items()
        if metric_name == 'resolution_dns_duration_seconds_count'
      ]
      load_write_artifact(artifact_path, artifact)
      assert fields['success'] == fields['confirmed'] == dataset.count, fields
      artifact['scenarios'].append(
        {
          'name': 'new_during_stale_and_repeated_new',
          'status': 'passed',
          'new_id': new_id,
          'write_confirmed_seconds': write_confirmed_seconds,
          'stale_at_new_confirmation': priority_snapshot,
          'stale_terminal': fields,
          'queue_capacity': 2,
        }
      )
      load_write_artifact(artifact_path, artifact)
      # Same-ID serialization leaves two unstarted interests behind one held worker.
      # The fourth request must wait for actual capacity, then resume after release.
      await load_begin_provider_cycle(service.providers, 'explicit-backpressure')
      held_name = dataset.name(0)
      service.providers.hold_dns_names = {held_name}
      service.providers.dns_entered_by_name.clear()
      service.providers.dns_release_by_name.clear()
      pressure_before = parse_samples((await client.get('/metrics')).text)
      assert (await client.post('/domains/1/resolve')).status_code == 202
      async with asyncio.timeout(0.75):
        while held_name not in service.providers.dns_entered_by_name:
          await asyncio.sleep(0.01)
      for _ in range(2):
        assert (await client.post('/domains/1/resolve')).status_code == 202
      blocked = asyncio.create_task(client.post('/domains/1/resolve'))
      try:
        async with asyncio.timeout(0.75):
          while True:
            pressure = parse_samples((await client.get('/metrics')).text)
            if sample_total(pressure, 'fastapi_requests_in_progress', method='POST', path='/domains/{id}/resolve') >= 1:
              break
            await asyncio.sleep(0.01)
        assert not blocked.done(), 'Admission bypassed a saturated explicit queue'
        assert (
          sample_total(pressure, 'resolution_queue_duration_seconds_count', queue='resolve', phase='admission')
          - sample_total(pressure_before, 'resolution_queue_duration_seconds_count', queue='resolve', phase='admission')
          == 3
        )
        pressure_api = {}
        await load_api_round(client, dataset, pressure_api, timeout=5, job_mode='new')
        released_at = perf_counter()
        service.providers.hold_dns_names.clear()
        service.providers.dns_release_by_name[held_name].set()
        assert (await asyncio.wait_for(blocked, timeout=5)).status_code == 202
        resumed_seconds = perf_counter() - released_at
      finally:
        service.providers.hold_dns_names.clear()
        for release in service.providers.dns_release_by_name.values():
          release.set()
        if not blocked.done():
          blocked.cancel()
        await asyncio.gather(blocked, return_exceptions=True)
      async with asyncio.timeout(10):
        while True:
          pressure_after = parse_samples((await client.get('/metrics')).text)
          confirmed = sample_total(pressure_after, 'resolution_run_events_total', mode='stored', event='confirmed')
          prior = sample_total(pressure_before, 'resolution_run_events_total', mode='stored', event='confirmed')
          if confirmed - prior == 4:
            break
          await asyncio.sleep(0.02)
      artifact['scenarios'].append(
        {
          'name': 'explicit_admission_backpressure',
          'status': 'passed',
          'queue_capacity': 2,
          'accepted_before_release': 3,
          'confirmed_after_release': 4,
          'blocked_admission_resumed_seconds': resumed_seconds,
          'unrelated_api_latency': {name: load_quantiles(values) for name, values in pressure_api.items()},
        }
      )
      load_write_artifact(artifact_path, artifact)
      # Preserve a public snapshot and prove failure never deletes previous evidence.
      domain_id = 1
      name = dataset.name(0)
      for kind in ('drop', 'malformed', 'disconnect', 'servfail', 'nodata', 'nxdomain'):
        before_row = (await client.get(f'/domains/{domain_id}')).json()
        service.providers.begin_cycle(f'failure-{kind}')
        for transport in ('classic', 'doh'):
          service.providers.schedule[(transport, name, dns.rdatatype.A, service.providers.cycle)] = ({'kind': kind},)
          service.providers.schedule[(transport, name, dns.rdatatype.CNAME, service.providers.cycle)] = (
            {'kind': 'nodata'},
          )
        before = parse_samples((await client.get('/metrics')).text)
        started = perf_counter()
        assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
        (_, outcome), api_observation = await load_observe_pending(
          client,
          dataset,
          configuration,
          load_wait_idle(
            client, 'stored', 1, sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stored'), 5
          ),
        )
        actual = (await client.get(f'/domains/{domain_id}')).json()
        assert actual['ips_v6'] == before_row['ips_v6']
        if kind in {'nodata', 'nxdomain'}:
          assert not actual['ips_v4']
          assert outcome['success'] == outcome['confirmed'] == 1
        else:
          assert actual == before_row, (kind, before_row, actual)
          assert outcome['failure'] == 1
          assert outcome['confirmed'] == 0
        artifact['scenarios'].append(
          {
            'name': kind,
            'status': 'passed',
            'run': outcome,
            'seconds': perf_counter() - started,
            'continuous_api': api_observation,
          }
        )
        # Recovery uses a fresh provider cycle, retaining the real retry/cache owners.
        service.providers.begin_cycle(f'recovery-{kind}')
        before = parse_samples((await client.get('/metrics')).text)
        assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
        _, recovered = await load_wait_idle(
          client,
          'stored',
          1,
          sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stored'),
          5,
        )
        expected, _ = dataset.expected(0)
        actual = (await client.get(f'/domains/{domain_id}')).json()
        assert set(actual['ips_v4'] or []) == expected
        assert recovered['confirmed'] == recovered['success'] == 1
        load_write_artifact(artifact_path, artifact)
      for index, kind in enumerate(('error', 'malformed', 'drop', 'rate-limit')):
        # Fresh eligible network bases prove the real RIPE failure path without cache masking.
        base = f'30.250.{index}.0'
        cycle = f'ripe-{kind}'
        await load_begin_provider_cycle(service.providers, cycle)
        service.providers.reset_evidence()
        for transport in ('classic', 'doh'):
          service.providers.schedule[(transport, name, dns.rdatatype.A, cycle)] = (
            {'kind': 'positive', 'addresses': (base,)},
          )
        ripe_key = ('ripe', base, None, cycle)
        service.providers.schedule[ripe_key] = (
          (
            {'kind': 'positive', 'prefix': f'{base}/24', 'status': 429, 'retry_after': '0'},
            {'kind': 'positive', 'prefix': f'{base}/24'},
          )
          if kind == 'rate-limit'
          else ({'kind': kind},)
        )
        before = parse_samples((await client.get('/metrics')).text)
        assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
        (_, outcome), api_observation = await load_observe_pending(
          client,
          dataset,
          configuration,
          load_wait_idle(
            client, 'stored', 1, sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stored'), 5
          ),
        )
        assert outcome['success'] == outcome['confirmed'] == 1
        actual = (await client.get(f'/domains/{domain_id}')).json()
        assert set(actual['ips_v4'] or []) == {f'{base}/24' if kind == 'rate-limit' else base}
        assert set(actual['ips_v6'] or []) == {dataset.ipv6}
        assert service.providers.attempts[ripe_key] == (2 if kind == 'rate-limit' else 1)
        failure_evidence = service.providers.evidence()
        # Failure must not become a successful empty cache entry; the next lookup learns the prefix.
        await load_begin_provider_cycle(service.providers, f'ripe-recovery-{kind}')
        recovery_cycle = service.providers.cycle
        for transport in ('classic', 'doh'):
          service.providers.schedule[(transport, name, dns.rdatatype.A, recovery_cycle)] = (
            {'kind': 'positive', 'addresses': (base,)},
          )
        service.providers.schedule[('ripe', base, None, recovery_cycle)] = (
          {'kind': 'positive', 'prefix': f'{base}/24'},
        )
        before = parse_samples((await client.get('/metrics')).text)
        assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
        _, recovered = await load_wait_idle(
          client,
          'stored',
          1,
          sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stored'),
          5,
        )
        assert recovered['confirmed'] == 1
        actual = (await client.get(f'/domains/{domain_id}')).json()
        assert set(actual['ips_v4'] or []) == {f'{base}/24'}
        recovery_attempts = service.providers.attempts.get(('ripe', base, None, recovery_cycle), 0)
        assert recovery_attempts == (0 if kind == 'rate-limit' else 1)
        artifact['scenarios'].append(
          {
            'name': f'ripe-{kind}-and-recovery',
            'status': 'passed',
            'failure_evidence': failure_evidence,
            'run': outcome,
            'recovery_run': recovered,
            'recovery_network_attempts': recovery_attempts,
            'continuous_api': api_observation,
          }
        )
        load_write_artifact(artifact_path, artifact)
      # A learned alias is a new domain, independent of whether its source saves addresses.
      alias = 'learned-alias.load.example.test'
      terminal = 'learned-terminal.load.example.test'
      service.providers.begin_cycle('new-alias')
      for transport in ('classic', 'doh'):
        service.providers.schedule[(transport, name, dns.rdatatype.A, service.providers.cycle)] = (
          {'kind': 'alias-chain-positive', 'addresses': ('8.8.8.8',), 'aliases': (alias, terminal)},
        )
      before = parse_samples((await client.get('/metrics')).text)
      checked = await client.post('/domains/resolve/check', json={'id': domain_id})
      assert checked.status_code == 200
      assert [row['cnames'] for row in checked.json()['results']] == [[alias, terminal], [alias, terminal]]
      assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
      await load_wait_idle(
        client, 'stored', 1, sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stored'), 5
      )
      for target in (alias, terminal):
        async with asyncio.timeout(5):
          while True:
            response = await client.get('/domains/search', params={'text': target})
            if [row for row in response.json()['payload'] if row['name'] == target]:
              break
            await asyncio.sleep(0.02)
      artifact['scenarios'].append({'name': 'learned_alias_chain', 'status': 'passed'})
      # Resolve learned NEW rows before STALE soak cycles; no pending work is hidden.
      service.providers.begin_cycle('learned-new')
      before = parse_samples((await client.get('/metrics')).text)
      assert (await client.post('/commands/domains/resolve/new')).status_code == 200
      await load_wait_idle(
        client, 'new', 2, sample_total(before, 'resolution_run_elapsed_seconds_count', mode='new'), 10
      )
      resources = []
      for cycle in range(configuration['soak_cycles']):
        service.providers.begin_cycle(f'soak-{cycle}')
        before = parse_samples((await client.get('/metrics')).text)
        resources.append(service.resource_snapshot(application_pid(before)))
        assert (await client.post('/commands/domains/resolve/stale')).status_code == 200
        _, outcome = await load_wait_idle(
          client,
          'stale',
          dataset.count + 3,
          sample_total(before, 'resolution_run_elapsed_seconds_count', mode='stale'),
          30,
        )
        assert outcome['confirmed'] == dataset.count + 3
        resources.append(service.resource_snapshot(application_pid(before)))
        assert resources[-1]['rss_bytes'] <= configuration['rss_limit_mb'] * 1024 * 1024
        artifact['scenarios'].append({'name': f'soak-{cycle}', 'status': 'passed', 'run': outcome})
        load_write_artifact(artifact_path, artifact)
      # Keep a known durable row while shutdown interrupts a new external wait.
      durable = (await client.get(f'/domains/{new_id}')).json()
      service.providers.begin_cycle('shutdown')
      service.providers.hold_dns = True
      service.providers.dns_entered.clear()
      assert (await client.post('/commands/domains/resolve/stale')).status_code == 200
      await asyncio.wait_for(service.providers.dns_entered.wait(), timeout=5)
      before_shutdown = parse_samples((await client.get('/metrics')).text)
      await service.stop()
      service.providers.hold_dns = False
      service.providers.dns_release.set()
    await service.start()
    async with httpx.AsyncClient(base_url=service.url, timeout=5, trust_env=False) as client:
      after_restart = (await client.get(f'/domains/{new_id}')).json()
      assert after_restart['ips_v4'] == durable['ips_v4']
      assert after_restart['name'] == durable['name']
      assert after_restart['last_resolved_at'] is not None
      for target in (alias, terminal):
        assert any(
          row['name'] == target
          for row in (await client.get('/domains/search', params={'text': target})).json()['payload']
        )
    artifact['scenarios'].append(
      {
        'name': 'shutdown_under_load_and_restart',
        'status': 'passed',
        'observed_before_shutdown': run_fields(before_shutdown, 'stale'),
      }
    )
    artifact['providers'] = service.providers.evidence()
    artifact['resource_samples'] = resources
    assert load_source_evidence(service.root) == snapshot, 'Source inputs changed during resilience checks'
    artifact['status'] = 'passed'
  except BaseException as error:
    artifact['status'] = 'failed'
    artifact['failure'] = {'type': type(error).__name__, 'message': str(error)[:4000]}
    raise
  finally:
    load_write_artifact(artifact_path, artifact)


async def test_router_put_has_no_hidden_native_connect_retries(app, monkeypatch):
  """Fail below HTTPX to detect retries hidden inside the real transport pool."""
  import httpcore
  from httpcore._backends.auto import AutoBackend
  from httpx_retries import Retry

  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', app.real_http_send)
  monkeypatch.setattr(app.settings, 'req_connection_retries', 3)
  calls = []

  async def unavailable(self, *args, **kwargs):
    calls.append((args, kwargs))
    raise httpcore.ConnectError('Synthetic connection refused')

  async def skip_wait(self, response):
    pass

  monkeypatch.setattr(AutoBackend, 'connect_tcp', unavailable)
  monkeypatch.setattr(Retry, 'asleep', skip_wait)
  client = factory.get_client('ros', retry_methods=frozenset({'GET', 'POST', 'PATCH', 'DELETE'}))
  try:
    with pytest.raises(httpx.ConnectError):
      await client.put('http://127.0.0.1:1/rest/routing/table', json={'name': 'test'})
    assert len(calls) == 1
    calls.clear()
    with pytest.raises(httpx.ConnectError):
      await client.get('http://127.0.0.1:1/rest/system/resource')
    assert len(calls) == 4
  finally:
    await factory.close()


@pytest.mark.e2e
@pytest.mark.parametrize('exhausted', [False, True])
async def test_public_http_retries_preserve_resolution_persistence_and_logical_metrics(e2e_service, exhausted):
  """Wire retry exhaustion remains a processing failure while its completed saving attempt commits.

  Fixtures own isolated app/storage resources; scenario parameters select the input or failure boundary.
  """
  # service is the isolated real application and providers.
  # domain_id is the stored source domain identity.
  # before is the prior checkpoint and IP metadata.
  # client is the bounded real HTTP client.
  # response is the public stored-resolution acknowledgement.
  # samples is public Prometheus samples.
  # fields is processing and persistence counters for the completed run.
  # after is durable checkpoint and IP metadata after the attempt.
  service = e2e_service
  await service.stop()
  service.environment.update(
    {'REQ_CONNECTION_RETRIES': '2', 'DOH_CONNECTION_RETRIES': '2', 'REQ_RETRY_BACKOFF_FACTOR': '0'}
  )
  await service.start()
  domain_id = await configure_public_domain(service)
  before = public_flow_snapshot(service, domain_id)
  service.providers.classic = 'servfail' if exhausted else 'positive'
  service.providers.http_statuses['/dns-query'] = [503] * (6 if exhausted else 1)
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post(f'/domains/{domain_id}/resolve')
    assert response.status_code == 202
    samples, fields = await completed_metrics(client, mode='stored', selected=1)
    assert fields['attempted'] == fields['failure' if exhausted else 'success'] == 1
    assert fields['admitted'] == fields['confirmed'] == 1
    assert fields['pending'] == fields['unknown'] == 0
    assert sample_total(samples, 'httpx_exchanges_in_flight') == 0
    assert sample_total(samples, 'httpx_exchanges_started_total') == sample_total(
      samples, 'httpx_exchanges_terminal_total'
    )
    assert sample_total(samples, 'httpx_exchanges_started_total', integration='domains_resolver') == (
      2 if exhausted else 1
    )
  assert service.providers.http_requests.count(('GET', '/dns-query')) == (6 if exhausted else 2)
  assert service.providers.http_statuses['/dns-query'] == []
  after = public_flow_snapshot(service, domain_id)
  if exhausted:
    assert after == before
  else:
    assert after[0][0] == 1
    assert after[0][1] != before[0][1]
    assert set(after[1]) == {'8.8.8.8', '8.8.4.4', '2001:4860:4860::8888'}
    assert after[1]['2001:4860:4860::8888'] == before[1]['2001:4860:4860::8888']


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('slow_transport', ['classic', 'doh'])
async def test_public_dns_deadline_keeps_stale_data_and_retry_checkpoint_then_recovers(e2e_service, slow_transport):
  service = e2e_service
  service.environment['DOH_OPERATION_TIMEOUT'] = '0.15'
  service.environment['DNS_OPERATION_TIMEOUT'] = '0.15'
  service.environment['DNS_TIMEOUT'] = '0.03'
  service.environment['DNS_LIFETIME'] = '0.06'
  await service.start()
  domain_id = await configure_public_domain(service)
  before_domain, before_ips = public_flow_snapshot(service, domain_id)
  service.providers.hold_dns = slow_transport == 'doh'
  service.providers.drop_classic = slow_transport == 'classic'
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    async with asyncio.timeout(3):
      samples, fields = await completed_metrics(client, mode='stored', selected=1)
    if slow_transport == 'doh':
      assert service.providers.dns_entered.is_set()
    assert fields['partial'] == fields['admitted'] == fields['confirmed'] == 1
    assert fields['success'] == fields['failure'] == 0
    assert sample_total(samples, 'httpx_exchanges_in_flight') == 0
    assert (
      sample_total(samples, 'resolution_dns_duration_seconds_count', transport=slow_transport, outcome='failure') == 2
    )
    assert (
      sample_total(samples, 'resolution_dns_duration_seconds_count', transport=slow_transport, outcome='cancelled') == 0
    )
    after_domain, after_ips = public_flow_snapshot(service, domain_id)
    assert after_domain == before_domain
    assert {address: after_ips[address] for address in before_ips} == before_ips
    assert set(after_ips) == set(before_ips) | ({'8.8.8.8'} if slow_transport == 'doh' else {'8.8.4.4'})
    service.providers.hold_dns = False
    service.providers.drop_classic = False
    service.providers.dns_release.set()
    previous = sample_total(samples, 'resolution_run_elapsed_seconds_count', mode='stored')
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    samples, fields = await completed_metrics(client, mode='stored', selected=1, previous_completed=previous)
    assert fields['success'] == fields['confirmed'] == 1
    after_domain, after_ips = public_flow_snapshot(service, domain_id)
    assert after_domain[0] == 1
    assert after_domain[1] != before_domain[1]
    assert set(after_ips) == {'8.8.8.8', '8.8.4.4', '2001:4860:4860::8888'}
    assert after_ips['2001:4860:4860::8888'] == before_ips['2001:4860:4860::8888']


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_ripe_deadline_preserves_existing_cidr_and_adds_host_fallback(e2e_service):
  service = e2e_service
  service.environment['RIPE_STAT_OPERATION_TIMEOUT'] = '0.15'
  await service.start()
  domain_id = await configure_public_domain(service)
  service.providers.classic_addresses = ('8.8.8.0',)
  service.providers.doh_addresses = ('8.8.4.0',)
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(
      'INSERT INTO rdpr_ip_records (domain_id, addr_type, ip_address) VALUES (?, 4, ?)',
      (domain_id, '8.8.8.0/25'),
    )
    connection.execute(
      'INSERT INTO rdpr_ip_supports (ip_record_id, domain_id) '
      'SELECT id, domain_id FROM rdpr_ip_records WHERE ip_address=?',
      ('8.8.8.0/25',),
    )
  before = public_flow_snapshot(service, domain_id)
  service.providers.hold_ripe = True
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    async with asyncio.timeout(3):
      samples, fields = await completed_metrics(client, mode='stored', selected=1)
    assert service.providers.ripe_entered.is_set()
    assert fields['success'] == fields['admitted'] == fields['confirmed'] == 1
    assert (
      sample_total(samples, 'resolution_ripe_duration_seconds_count', phase='fallback', outcome='stored_prefix') == 1
    )
    assert sample_total(samples, 'resolution_ripe_duration_seconds_count', phase='fallback', outcome='host') == 1
    assert sample_total(samples, 'httpx_exchanges_in_flight') == 0
  after_domain, after_ips = public_flow_snapshot(service, domain_id)
  assert after_domain[0] == 1
  assert after_domain[1] != before[0][1]
  assert set(after_ips) == {'8.8.8.0/25', '8.8.4.0', '2001:4860:4860::8888'}
  assert after_ips['8.8.8.0/25'] == before[1]['8.8.8.0/25']
  assert after_ips['2001:4860:4860::8888'] == before[1]['2001:4860:4860::8888']


@pytest.mark.e2e
@pytest.mark.e2e_load
async def test_slow_independent_ripe_requests_share_bounded_capacity(e2e_service, tmp_path):
  """Measure one domain with independent network-base addresses and a slow local RIPE provider."""
  service = e2e_service
  domain_id = await configure_public_domain(service)
  await service.stop()
  service.environment['RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT'] = '2'
  addresses = ('8.8.8.0', '8.8.4.0', '9.9.9.0', '1.1.1.0', '1.0.0.0', '208.67.222.0')
  service.providers.classic_addresses = addresses[:3]
  service.providers.doh_addresses = addresses[3:]
  service.providers.ripe_delay = 0.04
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    samples = parse_samples((await client.get('/metrics')).text)
    pid = application_pid(samples)
    before_resources = service.resource_snapshot(pid)
    started = perf_counter()
    assert (await client.post(f'/domains/{domain_id}/resolve')).status_code == 202
    samples, fields = await completed_metrics(client, mode='stored', selected=1)
    elapsed = perf_counter() - started
    after_resources = service.resource_snapshot(pid)
    assert fields['success'] == fields['confirmed'] == 1
  actual = public_flow_snapshot(service, domain_id)
  assert set(actual[1]) == set(addresses) | {'2001:4860:4860::8888'}
  assert actual[0][0] == 1
  assert actual[0][1] is not None
  ripe_calls = [row[1] for row in service.providers.requests if row[0] == 'ripe']
  assert sorted(ripe_calls) == sorted(addresses)
  assert service.providers.ripe_active == 0
  (tmp_path / 'slow-ripe-measurement.json').write_text(
    json.dumps(
      {
        'dataset': addresses,
        'provider_delay_seconds': service.providers.ripe_delay,
        'concurrency_limit': 2,
        'peak_provider_concurrency': service.providers.ripe_peak_active,
        'wall_elapsed_seconds': elapsed,
        'run': fields,
        'child_cpu_seconds': after_resources['cpu_seconds'] - before_resources['cpu_seconds'],
        'child_peak_rss_bytes': after_resources['peak_rss_bytes'],
        'source_sha256': {
          name: sha256((service.root / name).read_bytes()).hexdigest()
          for name in (
            'config/config.py',
            'client/domains_resolving_client.py',
            'client/ripe_stat_client.py',
            'client/http_base_client.py',
            'tests/conftest.py',
            'tests/integration/test_domain_resolution_persistence.py',
          )
        },
      },
      indent=2,
      allow_nan=False,
    ),
    encoding='utf-8',
  )
  assert service.providers.ripe_peak_active == 2


async def test_ripe_operation_deadline_includes_real_http_pool_wait_and_allows_recovery(app, monkeypatch):
  """A generous pool timeout must not extend the caller's smaller operation budget."""
  factory = importlib.import_module('client.http_base_client').HttpClient
  await factory.close()
  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', app.real_http_send)
  monkeypatch.setattr(app.settings, 'req_max_connections', 1)
  monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 0.03)
  release = asyncio.Event()
  handlers, writers, paths = set(), set(), []

  async def serve(reader, writer):
    task = asyncio.current_task()
    handlers.add(task)
    writers.add(writer)
    try:
      async with asyncio.timeout(3):
        request = await reader.readuntil(b'\r\n\r\n')
        target = request.split(b' ', 2)[1]
        paths.append(target)
        if target == b'/hold':
          writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx')
          await writer.drain()
          await release.wait()
        else:
          body = b'{"status":"ok","data":{"prefix":null}}'
          writer.write(f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
          await writer.drain()
    except ConnectionError:
      pass
    finally:
      writer.close()
      await writer.wait_closed()
      writers.discard(writer)
      handlers.discard(task)

  server = await asyncio.start_server(serve, '127.0.0.1', 0)
  url = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}'
  monkeypatch.setattr(app.settings, 'ripe_stat_base_url', url)
  client = factory.get_client('ripe-pool', timeout=httpx.Timeout(1), connection_retries=0)
  ripe = app.ripe.RipeStatClient()
  ripe._RipeStatClient__client = client
  held = None
  try:
    held = await asyncio.wait_for(client.send(client.build_request('GET', url + '/hold'), stream=True), timeout=1)
    with pytest.raises(app.ripe.RipeStatClientError):
      await asyncio.wait_for(ripe.get_prefix('8.8.8.0'), timeout=0.5)
    assert paths == [b'/hold']
    await held.aclose()
    monkeypatch.setattr(app.settings, 'ripe_stat_operation_timeout', 1)
    result = await asyncio.wait_for(ripe.get_prefix('8.8.8.0'), timeout=1)
    assert result.prefix is None
    assert paths == [b'/hold', b'/data/network-info/data.json?resource=8.8.8.0']
  finally:
    if held is not None:
      await held.aclose()
    release.set()
    await factory.close()
    server.close()
    await server.wait_closed()
    for writer in tuple(writers):
      writer.close()
    if handlers:
      await asyncio.wait_for(asyncio.gather(*tuple(handlers)), timeout=2)


async def attempt_state(app, store, domain_id=1):
  """Read typed attempt, checkpoint and update dates for domain_id in isolated store.

  app supplies mapped columns; this query is independent of API serialization.
  """
  # connection owns the read transaction until the three date fields are copied.
  async with store._DataBase__read_engine.connect() as connection:
    return (
      await connection.execute(
        select(
          app.database.DomainsDbo.last_attempt_at,
          app.database.DomainsDbo.last_resolved_at,
          app.database.DomainsDbo.updated_at,
        ).where(app.database.DomainsDbo.id == domain_id)
      )
    ).one()


@pytest.mark.parametrize('complete', [False, True])
async def test_attempt_marker_and_ips_roll_back_together_on_timestamp_failure(app, store, monkeypatch, complete):
  """Rejecting the attempt UPDATE rolls back IP changes and never confirms its receipt.

  app/store own disposable real SQLite; monkeypatch selects one command per batch,
  and complete covers both additive partial and authoritative complete evidence.
  """
  await seed(app, store, checkpoint=STALE_CHECKPOINT)
  # before and dates preserve independent IP/checkpoint and timestamp rollback oracles.
  before = await snapshot(app, store)
  dates = await attempt_state(app, store)
  # connection installs a fault only in the disposable test database.
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      text(
        'CREATE TRIGGER refuse_attempt BEFORE UPDATE OF last_attempt_at ON rdpr_domains '
        "BEGIN SELECT RAISE(ABORT, 'synthetic attempt rejection'); END"
      )
    )
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  # command would add an IP, and a complete command would also withdraw old supports.
  command = await queue_resolution(app, store, 1, ['8.8.4.4'], complete=complete)
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=3)
  assert store.writer_state == 'FAILED'
  assert store.writer_failure.committed is False
  assert command.write_receipt.outcome.value == 'known_not_committed'
  assert await snapshot(app, store) == before
  assert await attempt_state(app, store) == dates


async def test_latest_admitted_attempt_survives_regrouping_mutation_and_lock_retry(app, store, monkeypatch):
  """Use admission order, preserve the complete checkpoint and retry frozen terminal times.

  app/store provide the real writer and SQLite; monkeypatch injects a precommit
  BUSY fault and controls retry delay without changing reconciliation behavior.
  """
  await add_support_domains(app, store)
  # first and last intentionally reverse wall-clock order: admission order is authoritative.
  first = await queue_resolution(app, store, 1, ['8.8.8.8'])
  last = app.dto.DomainResult(
    id=1,
    name='domain-1.example.test',
    resolution_complete=False,
    storage_ips=('9.9.9.9',),
    last_attempt_at=datetime(2025, 12, 31, 23, 59, 59, 654321, tzinfo=UTC),
  )
  await store.put_domain_after_resolve(last)
  # expected is copied before caller mutation; the writer must not retain the mutable DTO.
  expected = last.last_attempt_at.replace(tzinfo=None)
  first.last_attempt_at = datetime(2040, 1, 1, tzinfo=UTC)
  last.last_attempt_at = datetime(2041, 1, 1, tzinfo=UTC)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 2)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 3600)
  # attempts records actual timestamps visible at each rollback-complete retry boundary.
  attempts = []

  async def fault(stage, evidence):
    """Reject the first insert before commit starts, preserving known rollback/retry semantics."""
    if stage == 'after_insert' and evidence.begins == 1:
      raise lock_error()

  async def retry(delay):
    """Observe rollback state during bounded backoff delay without sleeping."""
    attempts.append(await attempt_state(app, store))

  monkeypatch.setattr(app.database, 'sleep', retry)
  # evidence counts real commits and rollbacks under the controlled driver fault.
  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=3)
  assert evidence.begins == 2
  assert evidence.commits == 1
  assert len(attempts) == 1
  assert attempts[0] == (None, None, None)
  # actual, checkpoint and updated are the committed marker, successful date and runtime update date.
  actual, checkpoint, updated = await attempt_state(app, store)
  assert actual == expected
  assert checkpoint is not None
  assert updated is not None
  assert first.write_receipt.outcome.value == last.write_receipt.outcome.value == 'confirmed'
  assert await support_snapshot(store) == {('8.8.8.8', 1, None), ('9.9.9.9', 1, None)}


async def test_missing_terminal_timestamp_cannot_be_admitted(app, store):
  """Reject a producer contract violation before queue ownership or date mutation.

  app/store provide DTO construction and the real admission boundary.
  """
  await seed(app, store)
  # command deliberately lacks the terminal time required of every saving producer.
  command = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=False)
  with pytest.raises(app.database.DatabaseWriteError):
    await store.put_domain_after_resolve(command)
  assert store.db_save_queue.empty()
  assert store.pending_count == 0
  assert await attempt_state(app, store) == (None, None, None)


async def test_automatic_selection_and_id_helper_share_attempt_boundaries(app, store, monkeypatch):
  """At exactly two days, attempted unresolved rows become STALE in effective-date order.

  app/store exercise real SQL and the by-ID helper; monkeypatch preserves the
  configured default interval. The SQLite clock is fixed on each read connection.
  """
  monkeypatch.setattr(app.settings, 'domains_update_interval', 172800)
  # fixed is SQLite's UTC now; engine owns only test read connections.
  fixed = '2026-01-03 00:00:00'
  engine = store._DataBase__read_engine.sync_engine

  def clock(connection, record):
    """Override CURRENT_TIMESTAMP only on this disposable engine's physical connections."""
    connection.create_function('current_timestamp', 0, lambda: fixed)

  event.listen(engine, 'connect', clock)
  try:
    # rows independently specify NEW, boundary, recent, historical-fallback and precedence cases.
    rows = [
      (0, None, None, False),
      (1, None, None, False),
      (2, '2026-01-01 00:00:00', None, False),
      (3, '2026-01-01 00:00:01', None, False),
      (4, None, '2025-12-31 23:59:59', True),
      (5, '2026-01-02 00:00:00', '2000-01-01 00:00:00', True),
      (6, '2026-01-01 00:00:00', '2026-01-02 00:00:00', True),
      (7, '2025-12-31 23:59:59', None, False),
      (8, None, None, True),
    ]
    # connection seeds raw dates without invoking any ORM update-time hooks.
    async with store._DataBase__write_engine.begin() as connection:
      # identifier, attempt, checkpoint and resolved describe each independent scheduling case.
      for identifier, attempt, checkpoint, resolved in rows:
        await connection.execute(
          text(
            'INSERT INTO rdpr_domains(id,name,resolved,last_attempt_at,last_resolved_at) '
            'VALUES(:id,:name,:resolved,:attempt,:checkpoint)'
          ),
          dict(
            id=identifier,
            name=f'eligibility-{identifier}.example.test',
            resolved=resolved,
            attempt=attempt,
            checkpoint=checkpoint,
          ),
        )
    # row is each detached candidate returned by the two real automatic selection queries.
    assert [row.id for row in await store.get_new_domains_for_resolve()] == [1, 8]
    assert [row.id for row in await store.get_stale_domains_for_resolve()] == [4, 7, 2, 6]
    # identifier selects one seeded case; new chooses the optional helper eligibility mode.
    for identifier in range(9):
      for new in (True, False, None):
        # selected and allowed compare helper behavior to independently enumerated memberships.
        selected = await store.get_domain_candidate_for_resolve(identifier, new=new)
        allowed = identifier in ({1, 8} if new is True else {2, 4, 6, 7} if new is False else set(range(1, 9)))
        assert (selected is not None) is allowed, (identifier, new)
    assert await store.get_domain_candidate_for_resolve(999) is None
  finally:
    event.remove(engine, 'connect', clock)


@pytest.mark.parametrize('attempt', [None, datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)])
async def test_domain_api_lists_search_and_detail_expose_nullable_attempt_dates(app, store, resource_api, attempt):
  """Both domain projections expose the same date pair using existing date conversion.

  app/store seed isolated data; resource_api calls the actual routers and response
  models, and attempt covers explicit NULL and a distinct successful-checkpoint date.
  """
  # checkpoint and updated are distinct controls that expose field-order or projection mistakes.
  checkpoint = datetime(2001, 2, 3, 4, 5, 6, tzinfo=UTC)
  updated = datetime(2002, 3, 4, 5, 6, 7, tzinfo=UTC)
  # expected follows the established naive SQLite timestamp conversion in the current host timezone.
  expected = None if attempt is None else attempt.replace(tzinfo=None).timestamp()
  # connection seeds three distinct dates, including a NULL attempt with a nonNULL successful checkpoint.
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      insert(app.database.DomainsDbo).values(
        id=1,
        name='date-visible.example.test',
        last_attempt_at=attempt,
        last_resolved_at=checkpoint,
        updated_at=updated,
      )
    )
  # path selects each public projection; response and payload hold its serialized domain record.
  for path in ('/domains', '/domains/search?text=date-visible', '/domains/1'):
    response = await resource_api.get(path)
    assert response.status_code == 200, response.text
    payload = response.json()
    if path != '/domains/1':
      payload = payload['payload'][0]
    assert 'last_attempt_at' in payload
    assert 'last_attempt_at_hum' in payload
    assert payload['last_attempt_at'] == expected
    assert payload['last_attempt_at_hum'] == (None if attempt is None else '2026-01-02 03:04:05')
    assert payload['last_resolved_at_hum'] == '2001-02-03 04:05:06'
    assert payload['updated_at_hum'] == '2002-03-04 05:06:07'


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
@pytest.mark.parametrize('prefix', ['rdpr_', ''])
@pytest.mark.parametrize('old_column', [False, True], ids=['fresh-column', 'previous-schema'])
async def test_attempt_migration_backfills_only_eligible_history_and_never_repeats(e2e_service, prefix, old_column):
  """Upgrade previous/fresh schemas, preserving historical updates, defaults and migration history.

  e2e_service owns real startup and disposable SQLite; prefix covers supported names
  and old_column chooses a preexisting schema without the new field.
  """
  # service starts and stops around test-owned physical fixture preparation only.
  service = e2e_service
  service.environment['DB_TABLE_PREFIX'] = prefix
  await service.start()
  await service.stop()
  # migration is the sole pending upgrade; all SQL below enumerates both supported prefix variants.
  migration = 'migration_202618042125.py'
  # connection prepares ordinary dated/undated, default and already-attempted historical rows.
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(
      {'rdpr_': 'DELETE FROM rdpr_migrations WHERE name=?', '': 'DELETE FROM migrations WHERE name=?'}[prefix],
      (migration,),
    )
    connection.execute(
      {
        'rdpr_': (
          "UPDATE rdpr_domains SET last_resolved_at='2001-01-01 01:02:03', updated_at='2002-02-02 02:03:04' WHERE id=0"
        ),
        '': "UPDATE domains SET last_resolved_at='2001-01-01 01:02:03', updated_at='2002-02-02 02:03:04' WHERE id=0",
      }[prefix]
    )
    connection.executemany(
      {
        'rdpr_': (
          'INSERT INTO rdpr_domains(id,name,resolved,last_resolved_at,last_attempt_at,updated_at) VALUES(?,?,?,?,?,?)'
        ),
        '': 'INSERT INTO domains(id,name,resolved,last_resolved_at,last_attempt_at,updated_at) VALUES(?,?,?,?,?,?)',
      }[prefix],
      [
        (1, 'history.example.test', 1, '2003-03-03 03:04:05.123456', None, '2004-04-04 04:05:06'),
        (2, 'undated.example.test', 0, None, None, '2004-04-04 04:05:06'),
        (
          3,
          'retained.example.test',
          0,
          '2005-05-05 05:06:07',
          None if old_column else '2006-06-06 06:07:08',
          '2004-04-04 04:05:06',
        ),
      ],
    )
    if old_column:
      connection.execute(
        {
          'rdpr_': 'ALTER TABLE rdpr_domains DROP COLUMN last_attempt_at',
          '': 'ALTER TABLE domains DROP COLUMN last_attempt_at',
        }[prefix]
      )
    # before captures all old fields and old_history includes complete applied metadata.
    before = connection.execute(
      {
        'rdpr_': 'SELECT id,name,resolved,created_at,updated_at,last_resolved_at FROM rdpr_domains ORDER BY id',
        '': 'SELECT id,name,resolved,created_at,updated_at,last_resolved_at FROM domains ORDER BY id',
      }[prefix]
    ).fetchall()
    old_history = connection.execute(
      {'rdpr_': 'SELECT * FROM rdpr_migrations ORDER BY id', '': 'SELECT * FROM migrations ORDER BY id'}[prefix]
    ).fetchall()
  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    assert (
      connection.execute(
        {
          'rdpr_': 'SELECT id,name,resolved,created_at,updated_at,last_resolved_at FROM rdpr_domains ORDER BY id',
          '': 'SELECT id,name,resolved,created_at,updated_at,last_resolved_at FROM domains ORDER BY id',
        }[prefix]
      ).fetchall()
      == before
    )
    assert connection.execute(
      {
        'rdpr_': 'SELECT id,last_attempt_at FROM rdpr_domains ORDER BY id',
        '': 'SELECT id,last_attempt_at FROM domains ORDER BY id',
      }[prefix]
    ).fetchall() == [
      (0, None),
      (1, '2003-03-03 03:04:05.123456'),
      (2, None),
      (3, '2005-05-05 05:06:07' if old_column else '2006-06-06 06:07:08'),
    ]
    assert (
      connection.execute(
        {
          'rdpr_': 'SELECT * FROM rdpr_migrations WHERE name<>? ORDER BY id',
          '': 'SELECT * FROM migrations WHERE name<>? ORDER BY id',
        }[prefix],
        (migration,),
      ).fetchall()
      == old_history
    )
    # column is SQLite's declared type/nullability/default/PK tuple; row is each inspected PRAGMA result.
    column = next(
      row
      for row in connection.execute(
        {'rdpr_': 'PRAGMA table_info(rdpr_domains)', '': 'PRAGMA table_info(domains)'}[prefix]
      )
      if row[1] == 'last_attempt_at'
    )
    assert column[2:] == ('TIMESTAMP', 0, None, 0)
    assert (
      connection.execute(
        {
          'rdpr_': 'SELECT applied_at FROM rdpr_migrations WHERE name=?',
          '': 'SELECT applied_at FROM migrations WHERE name=?',
        }[prefix],
        (migration,),
      ).fetchone()[0]
      is not None
    )
    # A completed restart cannot backfill a date intentionally cleared after migration completion.
    connection.execute(
      {
        'rdpr_': 'UPDATE rdpr_domains SET last_attempt_at=NULL WHERE id=1',
        '': 'UPDATE domains SET last_attempt_at=NULL WHERE id=1',
      }[prefix]
    )
  # committed includes the cleared attempt and all history/schema evidence before restart.
  committed = sqlite_snapshot(service.db_path)
  await service.start()
  await service.stop()
  assert sqlite_snapshot(service.db_path) == committed


@pytest.mark.parametrize('old_target', [False, True], ids=['new-ddl', 'previous-ddl'])
async def test_pending_legacy_import_accepts_exact_old_or_new_domain_schema(app, startup_store, old_target):
  """The pending legacy preflight accepts both exact approved domain DDL versions.

  app/startup_store run real startup on disposable legacy data; old_target removes
  only the newly introduced column from the empty current target schema.
  """
  # path is the isolated database; connection contexts own fixture setup/verification.
  path = Path(app.settings.db_path)
  create_legacy_database(path)
  async with startup_store._DataBase__write_engine.begin() as connection:
    await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
    if old_target:
      await connection.execute(text('ALTER TABLE rdpr_domains DROP COLUMN last_attempt_at'))
  await startup_store.setup()
  await startup_store.close(timeout=2)
  assert_legacy_import(path)
  with closing(sqlite3.connect(path)) as connection:
    assert connection.execute('SELECT id,last_attempt_at FROM rdpr_domains ORDER BY id').fetchall() == [
      (0, None),
      (7, '2002-03-04 05:06:07'),
    ]


async def test_cancelled_unadmitted_marker_never_changes_date(app, store):
  """Cancelling a full-queue producer leaves no attempt behind after existing work drains.

  app/store provide real admission and SQLite with one disposable occupied queue slot.
  """
  await seed(app, store)
  # entered signals the actual blocked put rather than depending on scheduling sleeps.
  entered = asyncio.Event()

  class FullQueue(asyncio.Queue):
    """Expose entry into a real bounded queue without changing its admission behavior."""

    async def put(self, item):
      """Signal the put of item and preserve the standard cancellable waiting contract."""
      if self.full():
        entered.set()
      await super().put(item)

  store.db_save_queue = FullQueue(maxsize=1)
  await enqueue_names(app, store, ['occupies-capacity.example.test'])
  # command is a completed failure marker; producer owns only its unadmitted enqueue.
  command = app.dto.DomainResult(
    id=1,
    name='www.example.test',
    resolution_complete=False,
    last_attempt_at=datetime(2026, 1, 2, tzinfo=UTC),
  )
  producer = asyncio.create_task(store.put_domain_after_resolve(command))
  try:
    await asyncio.wait_for(entered.wait(), timeout=2)
    producer.cancel()
    with pytest.raises(asyncio.CancelledError):
      await asyncio.wait_for(producer, timeout=2)
    assert command.write_receipt.admitted is False
    await flush_queue(store)
    assert await attempt_state(app, store) == (None, None, None)
    assert store.pending_count == 0
  finally:
    producer.cancel()
    await asyncio.gather(producer, return_exceptions=True)


@pytest.mark.parametrize(
  'column_sql',
  [
    'last_attempt_at TEXT',
    'last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
    "last_attempt_at TIMESTAMP NOT NULL DEFAULT '2000-01-01 00:00:00'",
    'last_attempt_at TIMESTAMP GENERATED ALWAYS AS (last_resolved_at) VIRTUAL',
  ],
)
async def test_incompatible_attempt_column_aborts_startup_atomically(app, startup_store, column_sql):
  """Reject incompatible type/default/nullability/generated shapes without changing history.

  app/startup_store run the real migration owner; column_sql is a fixed synthetic
  DDL variant in the disposable fixture, never user-supplied SQL.
  """
  # connection prepares the incompatible schema before the caller-owned startup transaction.
  async with startup_store._DataBase__write_engine.begin() as connection:
    await connection.run_sync(app.database.DomainsDbo.metadata.create_all)
    await connection.execute(text('ALTER TABLE rdpr_domains DROP COLUMN last_attempt_at'))
    await connection.execute(text('ALTER TABLE rdpr_domains ADD COLUMN ' + column_sql))
  # before includes every physical table, value and migration-history row before rejection.
  before = sqlite_snapshot(app.settings.db_path)
  with pytest.raises(app.database.DatabaseWriteError, match='Database initialization failed'):
    await startup_store.setup()
  assert startup_store.writer_task is None
  assert sqlite_snapshot(app.settings.db_path) == before


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_attempt_backfill_failure_rolls_back_column_and_history_then_recovers(e2e_service):
  """A failed backfill leaves the old schema/data/history intact and a fresh process can retry.

  e2e_service owns the actual startup process and its disposable previous-schema database.
  """
  # service is stopped before fixture SQL so no application connection observes intermediate DDL.
  service = e2e_service
  await service.start()
  await service.stop()
  # connection prepares one historical row and a trigger that rejects the new migration UPDATE.
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute(
      'INSERT INTO rdpr_domains(id,name,resolved,last_resolved_at,updated_at) '
      "VALUES(1,'historical.example.test',1,'2001-02-03 04:05:06','2002-03-04 05:06:07')"
    )
    connection.execute("DELETE FROM rdpr_migrations WHERE name='migration_202618042125.py'")
    connection.execute('ALTER TABLE rdpr_domains DROP COLUMN last_attempt_at')
    connection.execute(
      'CREATE TRIGGER fail_attempt BEFORE UPDATE OF last_attempt_at ON rdpr_domains '
      "BEGIN SELECT RAISE(ABORT,'synthetic historical backfill rejection'); END"
    )
  # before includes the absent column, trigger and all preexisting migration metadata.
  before = sqlite_snapshot(service.db_path)
  with pytest.raises(AssertionError, match='Application exited before readiness'):
    await service.start()
  assert sqlite_snapshot(service.db_path) == before
  with closing(sqlite3.connect(service.db_path)) as connection, connection:
    connection.execute('DROP TRIGGER fail_attempt')
  await service.start()
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute(
      'SELECT last_attempt_at,last_resolved_at,updated_at FROM rdpr_domains WHERE id=1'
    ).fetchone() == (
      '2001-02-03 04:05:06',
      '2001-02-03 04:05:06',
      '2002-03-04 05:06:07',
    )
