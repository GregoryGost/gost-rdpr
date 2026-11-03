"""SQLite integration and service E2E tests of startup, migrations, API flows, and shutdown."""

import asyncio
import importlib
import importlib.metadata
import json
import math
import os
import shutil
import sqlite3
import sys
import threading
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace

import aiosqlite
import dns.rdatatype
import httpx
import pytest
from prometheus_client import REGISTRY
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import event, insert, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.integration

# SQLite persists UTC timestamps without a timezone component.
STALE_CHECKPOINT = datetime(2000, 1, 1, tzinfo=UTC).replace(tzinfo=None)


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
    await store._DataBase__batch_items_commit(elements)
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
async def test_partial_cycle_adds_reliable_ip_without_postponing_retry(
  app,
  store,
  resolver,
  network,
  resolved,
  checkpoint,
  second_kind,
):
  await seed(app, store, resolved=resolved, checkpoint=checkpoint)
  before = await snapshot(app, store)
  network({'192.0.2.53': 'positive', '192.0.2.54': second_kind})
  await resolver._DomainsResolver__dns_main_tasker(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    default_dns_servers=[app.Server(server='192.0.2.53'), app.Server(server='192.0.2.54')],
    doh_dns_servers=[],
  )
  commands = await flush_queue(store)
  assert len(commands) == 1
  assert commands[0].elements[0].resolution_complete is False
  after = await snapshot(app, store)
  assert after[0] == before[0]
  assert {key: after[1][key] for key in before[1]} == before[1]
  assert set(after[1].values()) == set(before[1].values()) | {'8.8.8.8'}
  eligible = await (
    store.get_new_domains_for_resolve() if checkpoint is None else store.get_stale_domains_for_resolve()
  )
  assert [domain.id for domain in eligible] == [1]


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
  await seed(app, store)
  before = await snapshot(app, store)
  command = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=complete)
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
  await seed(app, store)
  before = await snapshot(app, store)
  async with store._DataBase__write_engine.begin() as connection:
    await connection.execute(
      text(
        'CREATE TRIGGER refuse_checkpoint BEFORE UPDATE OF resolved ON rdpr_domains '
        "BEGIN SELECT RAISE(ABORT, 'synthetic checkpoint rejection'); END"
      )
    )
  command = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=True)
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
async def test_all_failure_cycle_never_enqueues_or_changes_storage(app, store, resolver, network, kind):
  await seed(app, store, resolved=True, checkpoint=STALE_CHECKPOINT)
  before = await snapshot(app, store)
  network({'192.0.2.53': kind})
  await resolver._DomainsResolver__dns_main_tasker(
    domain=app.dto.DomainResult(id=1, name='www.example.test'),
    default_dns_servers=[app.Server(server='192.0.2.53')],
    doh_dns_servers=[],
  )
  assert await flush_queue(store) == []
  assert await snapshot(app, store) == before


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


async def test_batch_deadline_does_not_reset_while_events_keep_arriving(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 100)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 1.0)
  clock = SimpleNamespace(value=10.0)
  first_commit = asyncio.Event()
  release = asyncio.Event()

  class AdvancingQueue(asyncio.Queue):
    async def get(self):
      item = await super().get()
      clock.value += 0.4
      return item

  async def hold_commit():
    first_commit.set()
    await release.wait()

  store.db_save_queue = AdvancingQueue(maxsize=10)
  monkeypatch.setattr(app.database, 'monotonic', lambda: clock.value)
  evidence = instrument_sessions(store, monkeypatch, before_commit=hold_commit)
  names = [f'deadline-{index}.example.test' for index in range(8)]
  await enqueue_names(app, store, names)
  await store.start_writer()
  try:
    await asyncio.wait_for(first_commit.wait(), timeout=2)
    # The deadline must flush even though a newer event is ready to receive.
    assert evidence.commit_queues[0] > 0
  finally:
    release.set()
  await store.close(timeout=2)
  assert await stored_names(app, store) == sorted(names)


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
  await store.close(timeout=2)
  method = getattr(store, method_name)
  if method_name == 'put_domain_after_resolve':
    arguments = [app.dto.DomainResult(id=1, name='closed.example.test')]
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


@pytest.mark.parametrize('failure_stage', [None, 'setup', 'body', 'close'])
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

  monkeypatch.setattr(server, 'db', SimpleNamespace(setup=setup, close=close))
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
  expected = ['setup'] + ([] if failure_stage == 'setup' else ['body'])
  assert events == [*expected, 'database_close', 'http_close']


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
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 3)
  monkeypatch.setattr(app.settings, 'db_save_batch_timeout', 3600.0)
  command = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=False)
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
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  evidence = instrument_sessions(store, monkeypatch)
  await store.put_delete_domains_to_queue(id=1)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  command = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=True)
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
    cleanup_patch.setattr(server.HttpClient, 'close', http_close)
    instance = server.AppServer()
    with pytest.raises(app.database.DatabaseShutdownError) as raised:
      async with instance.app.router.lifespan_context(instance.app):
        events.append('body')
  assert raised.value is database_failure
  assert events == ['setup', 'body', 'database_close', 'http_close']
  assert 'HTTP client cleanup failed during database shutdown failure' in caplog.text
  assert 'synthetic private HTTP payload' not in caplog.text
  assert 'synthetic private HTTP payload' not in str(raised.value)


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
    ('classic', dns.rdatatype.A),
    ('classic', dns.rdatatype.CNAME),
    ('doh', dns.rdatatype.A),
    ('doh', dns.rdatatype.CNAME),
  }

  if not complete:
    # A new process runs the public stale job without a manual per-domain override.
    service.providers.classic = service.providers.doh = 'positive'
    service.providers.requests.clear()
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
async def test_failed_new_domain_remains_eligible_for_the_public_new_job(e2e_service):
  service = e2e_service
  service.providers.classic = 'servfail'
  service.providers.doh = 'empty'
  domain_id = await configure_public_domain(service, resolved=False)
  before = public_flow_snapshot(service, domain_id)
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/commands/domains/resolve/new')
    assert response.status_code == 200, response.text
  await service.stop()
  assert public_flow_snapshot(service, domain_id) == before
  assert {(row[0], row[2]) for row in service.providers.requests} == {
    ('classic', dns.rdatatype.A),
    ('classic', dns.rdatatype.CNAME),
    ('doh', dns.rdatatype.A),
    ('doh', dns.rdatatype.CNAME),
  }
  service.providers.classic = service.providers.doh = 'positive'
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post('/commands/domains/resolve/new')
    assert response.status_code == 200, response.text
    async with asyncio.timeout(5):
      while public_flow_snapshot(service, domain_id)[0][1] is None:
        await asyncio.sleep(0.02)
  await service.stop()
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
  before = sqlite_snapshot(service.db_path)
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    domains = await client.get('/domains')
    assert domains.status_code == 200
    assert 'persisted.example.test' in {row['name'] for row in domains.json()['payload']}
  await service.stop()
  assert sqlite_snapshot(service.db_path) == before
  assert service.providers.requests == []


@pytest.mark.e2e
@pytest.mark.parametrize('e2e_service', [False], indirect=True)
async def test_public_historical_gateway_upgrade_preserves_old_data_and_all_history(e2e_service):
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
    old_history = connection.execute('SELECT * FROM rdpr_migrations ORDER BY id').fetchall()
    old_ip = connection.execute('SELECT * FROM rdpr_ip_records').fetchone()
    old_domain = connection.execute('SELECT * FROM rdpr_domains').fetchone()
  await service.start()
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.get('/domains/7')
    assert response.status_code == 200, response.text
    assert response.json()['ips_v4'] == ['8.8.8.8']
  await service.stop()
  with closing(sqlite3.connect(service.db_path)) as connection:
    assert connection.execute('SELECT * FROM rdpr_migrations WHERE id<=34 ORDER BY id').fetchall() == old_history
    assert connection.execute('SELECT * FROM rdpr_domains WHERE id=7').fetchone() == old_domain
    assert connection.execute('SELECT * FROM rdpr_ip_records WHERE id=17').fetchone() == (*old_ip, 0)
    assert connection.execute('SELECT server, description FROM rdpr_dns_servers WHERE id=0').fetchone() == (
      '9.9.9.9',
      'custom',
    )
    assert connection.execute('SELECT COUNT(*) FROM rdpr_migrations').fetchone() == (6,)
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
    assert connection.execute('SELECT COUNT(*) FROM rdpr_migrations').fetchone() == (5,)
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


@pytest.mark.parametrize('missing_effect', ['table', 'column'])
async def test_completed_gateway_history_cannot_mask_missing_original_effect(app, startup_store, missing_effect):
  path = Path(app.settings.db_path)
  with closing(sqlite3.connect(path)) as connection, connection:
    create_history(connection)
    connection.execute(
      'INSERT INTO rdpr_migrations VALUES (31, ?, ?, ?, ?)',
      ('migration_202618042122.py', 'preserved-checksum', '2001-02-03 04:05:06', '2001-02-04 04:05:06'),
    )
    if missing_effect == 'column':
      connection.execute('CREATE TABLE rdpr_ip_records (id INTEGER PRIMARY KEY)')
  before = sqlite_snapshot(path)
  with pytest.raises(app.database.DatabaseWriteError):
    await startup_store.setup()
  assert sqlite_snapshot(path) == before


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
    'completed_import_history',
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
    elif contradiction == 'completed_import_history':
      create_history(connection)
      connection.execute(
        'INSERT INTO rdpr_migrations VALUES (31, ?, ?, ?, ?)',
        (
          'migration_202511031501.py',
          'preserved-checksum',
          '2001-02-03 04:05:06',
          '2001-02-04 04:05:06',
        ),
      )
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
    assert connection.execute('SELECT COUNT(*) FROM rdpr_migrations WHERE applied_at IS NOT NULL').fetchone() == (3,)
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
  """Establish the source-domain result before the real database admission boundary."""
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
    observation=observation,
  )
  return run, command


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
  await seed(app, store)
  before = await snapshot(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)
  run, command = measured_domain(app, complete=False)

  async def fault(current, evidence):
    if current == stage:
      raise RuntimeError('Synthetic driver failure')

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
  # A partial result with no additions is still one committed source result, with no physical row changes.
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
  jobs = importlib.import_module('jobs.job_registry')
  monkeypatch.setattr(resolver, 'domains_resolve_queue', asyncio.Queue(maxsize=1))
  monkeypatch.setattr(resolver, '_DomainsResolver__stop_domains_resolve_event', threading.Event())
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
        for index in (1, 2)
      ],
    )
  entered, release = asyncio.Event(), asyncio.Event()
  requests, selections = [], []

  async def classic(boundary, qname, rdtype, **kwargs):
    requests.append((boundary.nameservers[0], qname, rdtype))
    if len(requests) == 1:
      entered.set()
      await release.wait()
    return SimpleNamespace(response=dns_message('nodata', query=dns.message.make_query(qname, rdtype)))

  def observe_select(connection, cursor, statement, parameters, context, executemany):
    if 'UNION ALL' in statement and 'rdpr_dns_servers' in statement:
      selections.append(statement)

  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
  event.listen(store._DataBase__read_engine.sync_engine, 'before_cursor_execute', observe_select)
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
    expected_names = {f'snapshot-{index}.example.test' for index in (1, 2)}
    assert set(requests) == {
      ('192.0.2.53', name, record_type)
      for name in expected_names
      for record_type in (dns.rdatatype.A, dns.rdatatype.CNAME)
    }
    assert len(requests) == 4
    assert len(selections) == 1
    assert store.pending_count == 2
    requests.clear()
    await asyncio.wait_for(resolver.domains_resolve(mode_value), timeout=3)
    assert set(requests) == {
      ('192.0.2.54', name, record_type)
      for name in expected_names
      for record_type in (dns.rdatatype.A, dns.rdatatype.CNAME)
    }
    assert len(requests) == 4
    assert len(selections) == 2
    assert store.pending_count == 4
    await flush_queue(store)
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
  monkeypatch.setattr(resolver, 'domains_resolve_queue', asyncio.Queue(maxsize=1))
  monkeypatch.setattr(resolver, '_DomainsResolver__stop_domains_resolve_event', threading.Event())
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
  assert resolver.domains_resolve_queue.qsize() == resolver.domains_resolve_queue._unfinished_tasks == 0
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
  queue = asyncio.Queue(maxsize=1)
  original_put = queue.put

  async def put(item):
    admissions.append(item)
    await original_put(item)

  async def reject_network(*args, **kwargs):
    network_calls.append((args, kwargs))
    raise AssertionError('DNS configuration failure must precede network access')

  def selected(connection, cursor, statement, parameters, context, executemany):
    if 'UNION ALL' in statement and 'rdpr_dns_servers' in statement:
      selections.append(statement)

  monkeypatch.setattr(queue, 'put', put)
  monkeypatch.setattr(resolver, 'domains_resolve_queue', queue)
  monkeypatch.setattr(resolver, '_DomainsResolver__stop_domains_resolve_event', threading.Event())
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
    assert queue.qsize() == queue._unfinished_tasks == 0
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
      for record_type in (dns.rdatatype.A, dns.rdatatype.CNAME)
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


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
async def test_receipt_observer_failure_cannot_cancel_real_commit(app, store, monkeypatch, error_type):
  await seed(app, store)
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  class BrokenObserver:
    def notify(self, event, at):
      raise error_type('Synthetic observer failure')

  command = app.dto.DomainResult(id=1, name='www.example.test', resolution_complete=True, observation=BrokenObserver())
  await store.put_domain_after_resolve(command)
  await store.start_writer()
  await asyncio.wait_for(store.db_save_queue.join(), timeout=2)
  assert store.pending_count == 0
  assert store.writer_state == 'RUNNING'
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
  ('classic', 'doh', 'outcome', 'admitted'),
  [
    ('positive', 'positive', 'success', 1),
    ('positive', 'servfail', 'partial', 1),
    ('nodata', 'servfail', 'partial', 0),
    ('servfail', 'servfail', 'failure', 0),
  ],
)
async def test_public_metrics_separate_processing_admission_and_real_persistence(
  e2e_service,
  classic,
  doh,
  outcome,
  admitted,
):
  service = e2e_service
  domain_id = await configure_public_domain(service)
  before = public_flow_snapshot(service, domain_id)
  service.providers.classic, service.providers.doh = classic, doh
  async with httpx.AsyncClient(base_url=service.url, trust_env=False, timeout=5) as client:
    response = await client.post(f'/domains/{domain_id}/resolve')
    assert response.status_code == 202
    samples, fields = await completed_metrics(client, mode='stored', selected=1)
    assert fields['attempted'] == fields[outcome] == 1
    assert fields['success'] + fields['partial'] + fields['failure'] == 1
    assert fields['admitted'] == fields['confirmed'] == admitted
    assert fields['pending'] == fields['unknown'] == fields['known_not_committed'] == 0
    assert fields['processing_rate_valid'] == fields['saved_rate_valid'] == 1
    assert fields['processing_elapsed'] > 0
    assert fields['persistence_elapsed'] >= fields['processing_elapsed']
    assert fields['processing_rate'] > 0
    assert (fields['saved_rate'] > 0) is bool(admitted)
    assert sample_total(samples, 'resolution_dns_duration_seconds_count', record_type='A') == 2
    assert sample_total(samples, 'resolution_dns_duration_seconds_count', record_type='CNAME') == 2
    assert sample_total(samples, 'httpx_exchanges_in_flight') == 0
    assert sample_total(samples, 'httpx_exchanges_started_total') == sample_total(
      samples, 'httpx_exchanges_terminal_total'
    )
    dns_samples = {
      (name, labels): value for (name, labels), value in samples.items() if name.startswith('resolution_dns_')
    }
    assert 'www.example.test' not in repr(dns_samples)
    assert service.dns_host not in repr(dns_samples)
    assert service.doh_url not in repr(dns_samples)
  after = public_flow_snapshot(service, domain_id)
  if not admitted:
    assert after == before
  else:
    assert '8.8.8.8' in after[1]
    assert ('9.9.9.9' in after[1]) is (outcome == 'partial')
  # This must be the application process, not the pytest coordinator.
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
  """Measure fixed local work with real DNS/HTTP, app lifespan, queue, and SQLite."""
  service = e2e_service
  first_id = await configure_public_domain(service, resolved=False)
  names = ['www.example.test', *[f'baseline-{index}.example.test' for index in range(3)]]
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
      'QUEUE_MAX_SIZE': '1000',
    }
  )
  scenarios = []
  settings = {
    key: value
    for key, value in service.environment.items()
    if key.startswith(('DB_', 'REQ_', 'DOMAINS_', 'QUEUE_', 'RIPE_'))
  }
  for schedule, delay, unavailable in [('fast', 0.0, False), ('slow', 0.02, False), ('unavailable', 0.0, True)]:
    await service.stop()
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
          assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        if unavailable:
          assert actual_rows == before_rows
          assert all(row[1:] == (0, None) for row in checkpoints)
        else:
          assert {'8.8.8.0', '8.8.4.0'} <= {row[3] for row in actual_rows}
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
        assert distributions['resolution_dns_duration_seconds']['count'] == len(names) * 4
        scenarios.append(
          {
            'schedule': schedule,
            'cache': temperature,
            'provider_delay_seconds': delay,
            'http_provider_disconnects': unavailable,
            'classic_rcode': 'SERVFAIL' if unavailable else 'NOERROR',
            'wall_elapsed_seconds': elapsed,
            'run': fields,
            'histogram_percentile_estimates': distributions,
            'actual_classic_calls': sum(row[0] == 'classic' for row in service.providers.requests[request_offset:]),
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
        'scope': 'local controlled protocol baseline; not production performance or a speedup comparison',
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
  assert len(scenarios) == 6


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
  """Drive production wiring and writer against transient or exhausted wire-level failures."""
  service = e2e_service
  await service.stop()
  service.environment.update({'REQ_CONNECTION_RETRIES': '2', 'REQ_RETRY_BACKOFF_FACTOR': '0'})
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
    assert fields['admitted'] == fields['confirmed'] == int(not exhausted)
    assert fields['pending'] == fields['unknown'] == 0
    assert sample_total(samples, 'httpx_exchanges_in_flight') == 0
    assert sample_total(samples, 'httpx_exchanges_started_total') == sample_total(
      samples, 'httpx_exchanges_terminal_total'
    )
    assert sample_total(samples, 'httpx_exchanges_started_total', integration='domains_resolver') == 2
  assert service.providers.http_requests.count(('GET', '/dns-query')) == (6 if exhausted else 3)
  assert service.providers.http_statuses['/dns-query'] == []
  after = public_flow_snapshot(service, domain_id)
  if exhausted:
    assert after == before
  else:
    assert after[0][0] == 1
    assert after[0][1] != before[0][1]
    assert set(after[1]) == {'8.8.8.8', '8.8.4.4', '2001:4860:4860::8888'}
    assert after[1]['2001:4860:4860::8888'] == before[1]['2001:4860:4860::8888']
