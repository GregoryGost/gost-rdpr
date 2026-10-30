"""SQLite integration and service E2E tests of startup, migrations, API flows, and shutdown."""

import asyncio
import importlib
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from hashlib import sha256
from types import SimpleNamespace

import dns.rdatatype
import httpx
import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.integration

# SQLite persists UTC timestamps without a timezone component.
STALE_CHECKPOINT = datetime(2000, 1, 1, tzinfo=UTC).replace(tzinfo=None)


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
  with pytest.raises(app.database.WriterFailedError):
    await store.start_writer()
  with pytest.raises(app.database.WriterFailedError):
    await enqueue_names(app, store, ['late.example.test'])
  assert await store.put_delete_ip_records_to_queue([10]) is False
  assert delays == ([0.1, 0.2] if expected_attempts == 3 else [])


@pytest.mark.parametrize('cleanup_stage', ['rollback', 'close'])
async def test_failed_precommit_cleanup_prevents_lock_retry(app, store, monkeypatch, cleanup_stage):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  async def fault(stage, evidence):
    if stage == 'begin':
      raise lock_error()
    if stage == cleanup_stage:
      raise RuntimeError('synthetic cleanup failure')

  evidence = instrument_sessions(store, monkeypatch, fault=fault)
  await enqueue_names(app, store, ['cleanup.example.test'])
  await store.start_writer()
  await asyncio.wait_for(asyncio.shield(store.writer_task), timeout=2)
  assert evidence.begins == 1
  assert evidence.commits == 0
  assert store.writer_state == 'FAILED'
  assert store.pending_count == 1
  assert await stored_names(app, store) == []


async def test_known_commit_with_close_failure_is_acknowledged_without_replay(app, store, monkeypatch):
  monkeypatch.setattr(app.settings, 'db_save_batch_size', 1)

  async def fault(stage, evidence):
    if stage == 'close':
      raise RuntimeError('synthetic close failure')

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
  if failure_stage in {None, 'migration'}:
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
      f'{name}:{direction}'
      for name in ['migration_a.py', 'migration_b.py']
      for direction in (['up'] if failure_stage else ['up', 'down'])
    ]
    assert [(row.name, row.checksum) for row in history] == [
      (path.name, app.database.calculate_checksum(file_path=path)) for path in sorted(paths)
    ]
    assert [row.applied_at is None for row in history] == [bool(failure_stage)] * 2


async def test_lifespan_database_error_keeps_priority_when_http_cleanup_also_fails(app, monkeypatch):
  server = importlib.import_module('server.server')
  events = []
  database_failure = app.database.DatabaseShutdownError('synthetic database shutdown failure')
  http_failure = RuntimeError('synthetic HTTP cleanup failure')

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
