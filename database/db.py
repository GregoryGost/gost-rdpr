import logging
from asyncio import (
  CancelledError,
  Queue,
  QueueFull,
  QueueShutDown,
  Task,
  create_task,
  shield,
  sleep,
  to_thread,
  wait_for,
)
from datetime import UTC, datetime, timezone
from enum import StrEnum
from importlib.machinery import ModuleSpec
from importlib.util import module_from_spec, spec_from_file_location
from json import loads
from pathlib import Path
from re import findall
from sqlite3 import SQLITE_BUSY, SQLITE_LOCKED
from sqlite3 import Error as SQLiteError
from time import monotonic, perf_counter
from types import ModuleType
from typing import Any, Dict, List, Optional, Self, Sequence, Tuple, cast

from aiosqlite import __version__ as aiosqlite_version
from sqlalchemy import Result, Row, delete, event, exists, func, insert, select, text, update
from sqlalchemy import __version__ as sqlalchemy_version
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool
from sqlalchemy.schema import CreateIndex, CreateTable

from client.file_loader_client import FileLoaderClient
from config.config import settings
from jobs.job_registry import Jobs, job_registry
from logger.logger import Logger, logger
from metrics.metrics import (
  log_persistence_summaries,
  observe_duration,
  persistence_summaries,
  queue_duration,
  writer_duration,
)
from migrations.migration_202618042123 import ip_schema_kind, validate_support_schema, validate_support_state
from models.db.dns_servers_dbo import DnsServersDbo
from models.db.domains_dbo import DomainsDbo
from models.db.domains_lists_dbo import DomainsListsDbo
from models.db.ip_records_dbo import IpRecordsDbo, IpSupportDbo
from models.db.ips_lists_dbo import IpsListsDbo
from models.db.migrations_dbo import MigrationsDbo
from models.db.ros_configs_dbo import RosConfigsDbo
from models.dto.dns_server_dto import DnsServerDto, DnsServerType
from models.dto.domains_dto import DomainResult
from models.dto.domains_lists_dto import DomainsListDto
from models.dto.ip_record_dto import IpRecordDto
from models.dto.ips_lists_dto import IpsListDto
from models.dto.migrations_dto import MigrationsDto
from models.dto.queue_dto import (
  DomainResolutionIntent,
  IpListWithdrawal,
  QueueElementDto,
  TargetAction,
  notify_observation,
)
from models.dto.ros_config_dto import RosConfigDto
from models.http.dns_servers_req import DnsPostElementReq
from models.http.dns_servers_resp import DnsElementResp, DnsPayloadResp

#
from models.http.domains_lists_req import DomainsListsPostElementReq
from models.http.domains_lists_resp import DomainsListElementResp, DomainsListsPayloadResp

#
from models.http.domains_req import DomainsPostElementReq
from models.http.domains_resp import DomainElementResp, DomainsPayloadResp

#
from models.http.ips_lists_req import IpsListsPostElementReq
from models.http.ips_lists_resp import IpsListElementResp, IpsListsPayloadResp

#
from models.http.ips_req import IpsPostElementReq
from models.http.ips_resp import IpsElementResp, IpsPayloadResp

#
from models.http.ros_configs_req import RosConfigsPostElementReq
from models.http.ros_configs_resp import RosConfigElementResp, RosConfigPayloadResp

#
from models.http.statistics_req import DATE_FORMAT, GrowthDateField, GrowthEntity, GrowthGranularity
from models.http.statistics_resp import (
  StatsDnsData,
  StatsDomainsData,
  StatsDomainsListItem,
  StatsGrowthPoint,
  StatsGrowthResp,
  StatsIpsData,
  StatsIpsListItem,
  StatsResp,
  StatsRosData,
)
from utils.utils import calculate_checksum, check_ip_allow, get_ip_version

LEGACY_IMPORT_MIGRATION = 'migration_202511031501.py'
GATEWAY_MIGRATION = 'migration_202618042122.py'
IP_SUPPORT_MIGRATION = 'migration_202618042123.py'
STARTUP_MIGRATION_CHECKSUMS = {
  LEGACY_IMPORT_MIGRATION: '293ddda35db4553c0174d8ecb07902add5bb664a7137e0ce6f36a05899b83fa7',
  GATEWAY_MIGRATION: '563a6f0d402a11b7e044b60ec29a64cf81f3216f00f3aacc5da2da82cf72e80c',
}
LEGACY_BUSINESS_COLUMNS = {
  'dns_servers': ('id', 'server', 'doh_server', 'description', 'created_at'),
  'ros_configs': ('id', 'host', 'user', 'pass', 'bgp_list_name', 'description', 'created_at'),
  'domains_lists': ('id', 'name', 'url', 'description', 'hash', 'created_at', 'updated_at'),
  'ip_lists': ('id', 'name', 'url', 'description', 'hash', 'created_at', 'updated_at'),
  'domains': ('id', 'domain_list_id', 'resolved', 'name', 'ros_comment', 'created_at', 'updated_at'),
  'ip_records': ('id', 'ip_list_id', 'domain_id', 'addr_type', 'ip_address', 'ros_comment', 'created_at'),
}


class DomainIpReadError(RuntimeError):
  """The current IP snapshot for a domain could not be read safely."""


class DnsConfigurationReadError(RuntimeError):
  """The committed DNS configuration could not be read safely."""


class DatabaseWriteError(RuntimeError):
  """A sanitized failure of database initialization or queued persistence."""

  def __init__(
    self,
    message: str,
    *,
    retryable: bool = False,
    committed: bool = False,
    outcome_unknown: bool = False,
    pending_count: int = 0,
    unknown_count: int = 0,
  ) -> None:
    super().__init__(message)
    self.retryable = retryable
    self.committed = committed
    self.outcome_unknown = outcome_unknown
    self.pending_count = pending_count
    self.unknown_count = unknown_count


class DatabaseConfigurationError(DatabaseWriteError):
  """SQLite connection settings are invalid or could not be established."""


class BatchWriteError(DatabaseWriteError):
  """A batch failed or its committed transaction could not be cleaned up."""


class WriterClosedError(DatabaseWriteError):
  """The writer no longer admits commands in this lifecycle."""


class WriterFailedError(DatabaseWriteError):
  """The writer stopped after a terminal persistence failure."""


class DatabaseShutdownError(WriterFailedError):
  """Shutdown could not confirm a complete drain within its wait budget."""


class WriterState(StrEnum):
  NEW = 'NEW'
  RUNNING = 'RUNNING'
  STOPPING = 'STOPPING'
  STOPPED = 'STOPPED'
  FAILED = 'FAILED'


class DataBase:
  """
  Bulk ORM DELETE not supported right now
  https://docs.sqlalchemy.org/en/20/orm/queryguide/dml.html#orm-queryguide-update-delete-where
  """

  __state: bool = False
  __read_engine: AsyncEngine
  __write_engine: AsyncEngine
  __read_session_factory: async_sessionmaker[AsyncSession]
  __write_session_factory: async_sessionmaker[AsyncSession]
  __migrations_path: Path = Path('migrations')

  def __init__(self: Self) -> None:
    self.__connection_pragmas = self.__validated_connection_pragmas()
    self.__state = False
    self.__initialization_failed = False
    self.db_save_queue: Queue[QueueElementDto] = Queue(maxsize=settings.queue_max_size)
    self.__pending_batch: list[QueueElementDto] = []
    self.__observations: dict[int, QueueElementDto] = {}
    self.__failure_summaries: dict[str, dict] = {}
    self.__writer_state = WriterState.NEW
    self.__writer_task: Task[None] | None = None
    self.__batch_task: Task[None] | None = None
    self.__close_task: Task[None] | None = None
    self.__writer_failure: WriterFailedError | None = None
    self.__unknown_count = 0
    self.__session_cleanup_failed = False
    logging.getLogger('sqlalchemy.engine').setLevel(Logger.LOGGER_LEVEL[settings.db_log_level])
    logging.getLogger('sqlalchemy.pool').setLevel(Logger.LOGGER_LEVEL[settings.db_log_level])
    #
    logger.debug(f'SQLAlchemy version="{sqlalchemy_version}"')
    logger.debug(f'aiosqlite version="{aiosqlite_version}"')
    logger.debug(f'db_connection="{settings.db_connection}"')
    self.__migrations_path.mkdir(exist_ok=True)
    self.__read_engine: AsyncEngine = create_async_engine(
      url=settings.db_connection,
      connect_args={'timeout': settings.db_timeout},
      pool_timeout=settings.db_pool_timeout,
      pool_size=settings.db_pool_size,
      pool_recycle=settings.db_pool_recycle,
      max_overflow=settings.db_pool_size_overflow,
      poolclass=AsyncAdaptedQueuePool,
      pool_pre_ping=True,
    )
    self.__write_engine: AsyncEngine = create_async_engine(
      url=settings.db_connection, connect_args={'timeout': settings.db_timeout}, poolclass=NullPool
    )
    event.listen(self.__read_engine.sync_engine, 'connect', self.__configure_connection)
    event.listen(self.__write_engine.sync_engine, 'connect', self.__configure_connection)
    self.__read_engine.dialect.identifier_preparer.initial_quote = ''
    self.__read_engine.dialect.identifier_preparer.final_quote = ''
    self.__write_engine.dialect.identifier_preparer.initial_quote = ''
    self.__write_engine.dialect.identifier_preparer.final_quote = ''
    self.__read_session_factory = async_sessionmaker(
      bind=self.__read_engine, expire_on_commit=False, autocommit=False, autoflush=True
    )
    self.__write_session_factory = async_sessionmaker(
      bind=self.__write_engine, expire_on_commit=False, autocommit=False, autoflush=True
    )
    self.file_loader_client: FileLoaderClient = FileLoaderClient()
    logger.debug(f'{self.__class__.__name__} INIT OK')

  @property
  def __db_read_session(self: Self) -> async_sessionmaker[AsyncSession]:
    return self.__read_session_factory

  @property
  def __db_write_session(self: Self) -> async_sessionmaker[AsyncSession]:
    return self.__write_session_factory

  @property
  def read_pool_status(self: Self) -> str:
    return self.__read_engine.pool.status()

  @property
  def writer_state(self) -> WriterState:
    return self.__writer_state

  @property
  def writer_task(self) -> Task[None] | None:
    return self.__writer_task

  @property
  def writer_failure(self) -> WriterFailedError | None:
    return self.__writer_failure

  @property
  def pending_count(self) -> int:
    """Count admitted commands that have not been positively committed."""
    return self.db_save_queue.qsize() + len(self.__pending_batch)

  @property
  def unknown_count(self) -> int:
    return self.__unknown_count

  #

  @staticmethod
  def __validated_connection_pragmas() -> tuple[tuple[str, int | str], ...]:
    """Normalize fixed SQLite settings before any connection or startup SQL."""
    if not all(
      isinstance(value, str)
      for value in (settings.db_tune_journal_mode, settings.db_tune_temp_store, settings.db_tune_synchronous)
    ):
      raise DatabaseConfigurationError('Invalid SQLite connection mode')
    journal_mode = settings.db_tune_journal_mode.strip().upper()
    if journal_mode not in {'DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL'}:
      raise DatabaseConfigurationError('Unsupported SQLite journal mode')
    temp_modes = {'DEFAULT': 0, 'FILE': 1, 'MEMORY': 2, '0': 0, '1': 1, '2': 2}
    sync_modes = {'OFF': 0, 'NORMAL': 1, 'FULL': 2, 'EXTRA': 3, '0': 0, '1': 1, '2': 2, '3': 3}
    temp_store = temp_modes.get(settings.db_tune_temp_store.strip().upper())
    synchronous = sync_modes.get(settings.db_tune_synchronous.strip().upper())
    if temp_store is None or synchronous is None:
      raise DatabaseConfigurationError('Unsupported SQLite connection mode')
    integers = (
      ('busy_timeout', settings.db_tune_busy_timeout, 0, 2**31 - 1),
      ('mmap_size', settings.db_tune_mmap_size, -(2**63), 2**63 - 1),
      ('cache_size', settings.db_tune_cache_size, -(2**31), 2**31 - 1),
      ('wal_autocheckpoint', settings.db_tune_wal_autocheckpoint, 0, 2**31 - 1),
    )
    for _, value, minimum, maximum in integers:
      if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DatabaseConfigurationError('Invalid SQLite connection setting')
    # Timeout precedes lock-sensitive journal setup; all values below are validated.
    return (
      ('busy_timeout', settings.db_tune_busy_timeout),
      ('foreign_keys', 1),
      ('journal_mode', journal_mode.lower()),
      ('temp_store', temp_store),
      ('mmap_size', max(-1, settings.db_tune_mmap_size)),
      ('cache_size', settings.db_tune_cache_size),
      ('wal_autocheckpoint', settings.db_tune_wal_autocheckpoint),
      ('synchronous', synchronous),
    )

  def __configure_connection(self, dbapi_connection: Any, connection_record: Any) -> None:
    """Configure and verify each fresh physical connection outside transactions."""
    try:
      cursor = dbapi_connection.cursor()
      try:
        for name, expected in self.__connection_pragmas:
          effective_expected = expected
          if name == 'mmap_size' and isinstance(expected, int) and expected < 0:
            # A negative request restores the fresh connection's platform default.
            cursor.execute('PRAGMA mmap_size')
            initial = cursor.fetchone()
            if initial is None or not isinstance(initial[0], int) or initial[0] < 0:
              raise DatabaseConfigurationError('SQLite mapping default is unavailable')
            effective_expected = initial[0]
          cursor.execute(f'PRAGMA {name}={expected}')
          cursor.execute(f'PRAGMA {name}')
          row = cursor.fetchone()
          if row is None:
            raise DatabaseConfigurationError('SQLite connection setting is unavailable')
          actual = row[0]
          if (
            name == 'mmap_size'
            and isinstance(actual, int)
            and isinstance(effective_expected, int)
            and 0 <= actual < effective_expected
          ):
            # SQLite may cap mappings, including disabling them in its build.
            logger.debug(f'SQLite mmap_size capped to {actual} bytes')
          elif actual != effective_expected:
            raise DatabaseConfigurationError('SQLite connection setting could not be established')
      finally:
        cursor.close()
    except Exception as err:
      raise DatabaseConfigurationError('Cannot configure SQLite connection') from err

  async def __create_tables(self: Self) -> None:
    """Initialize schema, migrations, imported data and defaults atomically."""
    self.__initialization_failed = False
    # NullPool closes this dedicated connection, including its temporary FK mode.
    async with self.__write_engine.connect() as conn:
      try:
        await conn.execute(text('PRAGMA foreign_keys=OFF'))
        if (await conn.execute(text('PRAGMA foreign_keys'))).scalar_one() != 0:
          raise DatabaseWriteError('Cannot configure schema initialization')
        # Driver legacy transaction control does not begin transactions for DDL.
        await conn.execute(text('BEGIN IMMEDIATE'))
        original_schema = {
          row.name: (row.type, row.sql)
          for row in (
            await conn.execute(text("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table', 'view')"))
          )
        }
        applied = (
          await self.__get_all_applied_migrations(conn) if MigrationsDbo.__tablename__ in original_schema else []
        )
        completed = {migration.name for migration in applied if migration.applied_at is not None}
        if GATEWAY_MIGRATION in completed:
          if IpRecordsDbo.__tablename__ not in original_schema or not await self.__gateway_effect(conn):
            raise DatabaseWriteError('Completed gateway migration has an incompatible schema')
        if IP_SUPPORT_MIGRATION in completed:
          if await ip_schema_kind(conn) != 'current':
            raise DatabaseWriteError('Completed IP ownership migration has an incompatible schema')
          await validate_support_schema(conn)
          await validate_support_state(conn)
        elif IpSupportDbo.__tablename__ in original_schema:
          await validate_support_schema(conn)
        legacy_counts, remap_default_domain = await self.__startup_legacy_preflight(conn, original_schema, completed)
        await conn.run_sync(MigrationsDbo.metadata.create_all)
        await self.__main_migrations(
          conn,
          completed=completed,
          legacy_counts=legacy_counts,
          remap_default_domain=remap_default_domain,
        )
        if not (await conn.execute(select(DnsServersDbo.id).where(DnsServersDbo.id == 0))).first():
          await conn.execute(
            insert(DnsServersDbo).values(id=0, server='1.1.1.1', description='Cloudflare DNS - Default')
          )
        if not (await conn.execute(select(DomainsDbo.id).where(DomainsDbo.id == 0))).first():
          await conn.execute(
            insert(DomainsDbo).values(
              id=0, resolved=True, name='default', ros_comment='Default Domain', last_resolved_at=func.now()
            )
          )
        await self.__check_startup_foreign_keys(conn)
        await validate_support_state(conn)
        await conn.commit()
      except BaseException:
        self.__initialization_failed = True
        # Release rolls back pre-commit failures; commit errors can have unknown outcomes.
        logger.error('Database schema initialization failed')
        raise

  @staticmethod
  def __startup_identifier(name: str) -> str:
    """Quote an internal SQLite identifier independently of engine formatting."""
    return '"' + name.replace('"', '""') + '"'

  @staticmethod
  def __startup_sql_tokens(sql: str) -> list[str]:
    """Compare conservative DDL signatures without changing string literals."""
    tokens = findall(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|\w+|[^\s]", sql)
    return [token if token.startswith("'") else token.lower() for token in tokens]

  @staticmethod
  def __legacy_targets() -> dict[str, str]:
    return {
      'dns_servers': DnsServersDbo.__tablename__,
      'ros_configs': RosConfigsDbo.__tablename__,
      'domains_lists': DomainsListsDbo.__tablename__,
      'ip_lists': IpsListsDbo.__tablename__,
      'domains': DomainsDbo.__tablename__,
      'ip_records': IpRecordsDbo.__tablename__,
    }

  async def __compatible_current_table(self, conn: AsyncConnection, name: str, sql: str | None) -> bool:
    if name == IpRecordsDbo.__tablename__:
      try:
        await ip_schema_kind(conn, allow_missing_gateway=True)
      except RuntimeError:
        return False
      return True
    table = MigrationsDbo.metadata.tables[name]
    if sql is None or self.__startup_sql_tokens(sql) != self.__startup_sql_tokens(
      str(CreateTable(table).compile(dialect=conn.dialect))
    ):
      return False
    expected_unique_indexes = {
      tuple(self.__startup_sql_tokens(str(CreateIndex(index).compile(dialect=conn.dialect))))
      for index in table.indexes
      if index.unique
    }
    indexes = (
      await conn.execute(text('SELECT name, origin FROM pragma_index_list(:name) WHERE "unique" = 1'), {'name': name})
    ).all()
    actual_unique_indexes = set()
    for index in indexes:
      if index.origin == 'u':
        # Inline UNIQUE constraints are already covered by the exact table DDL.
        continue
      index_sql = (
        await conn.execute(
          text("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = :name"), {'name': index.name}
        )
      ).scalar_one()
      if index_sql is None:
        return False
      actual_unique_indexes.add(tuple(self.__startup_sql_tokens(index_sql)))
    return actual_unique_indexes == expected_unique_indexes

  async def __startup_legacy_preflight(
    self,
    conn: AsyncConnection,
    original_schema: dict[str, tuple[str, str | None]],
    completed: set[str],
  ) -> tuple[dict[str, int], bool]:
    targets = self.__legacy_targets()
    sources = set(LEGACY_BUSINESS_COLUMNS) | {'jobs'}
    present = sources & original_schema.keys()
    overlap = sources & set(targets.values())
    if overlap:
      # Current names alone cannot establish the presence of old source data.
      if present - overlap:
        raise DatabaseWriteError('Legacy source and target tables overlap')
      for name in present:
        kind, sql = original_schema[name]
        if kind != 'table' or not await self.__compatible_current_table(conn, name, sql):
          raise DatabaseWriteError('Overlapping schema cannot be identified safely')
      return {}, False
    if not present:
      return {}, False
    if present != sources or any(original_schema[name][0] != 'table' for name in sources):
      raise DatabaseWriteError('Legacy schema is incomplete or unsupported')
    if LEGACY_IMPORT_MIGRATION in completed:
      raise DatabaseWriteError('Completed legacy migration still has source tables')
    for name, columns in LEGACY_BUSINESS_COLUMNS.items():
      shape = (await conn.execute(text('SELECT * FROM pragma_table_xinfo(:name)'), {'name': name})).all()
      if {column.name for column in shape} != set(columns) or any(column.hidden for column in shape):
        raise DatabaseWriteError('Legacy business columns are unsupported')
      for column in shape:
        expected_type = (
          'INTEGER'
          if column.name in {'id', 'domain_list_id', 'ip_list_id', 'domain_id', 'resolved', 'addr_type'}
          else 'TIMESTAMP'
          if column.name in {'created_at', 'updated_at'}
          else 'TEXT'
        )
        if column.type.upper() != expected_type or column.pk != (1 if column.name == 'id' else 0):
          raise DatabaseWriteError('Legacy business column format is unsupported')
      # Source identities must remain real integers rather than generated target IDs.
      invalid_ids_query = (
        'SELECT 1 FROM ' + self.__startup_identifier(name) + " WHERE typeof(id) != 'integer' LIMIT 1"  # noqa: S608
      )
      invalid_ids = await conn.execute(text(invalid_ids_query))
      if invalid_ids.first():
        raise DatabaseWriteError('Legacy business identities are unsupported')
    for query in (
      'SELECT 1 FROM domains c WHERE c.domain_list_id IS NOT NULL AND NOT EXISTS '
      '(SELECT 1 FROM domains_lists p WHERE p.id = c.domain_list_id) LIMIT 1',
      'SELECT 1 FROM ip_records c WHERE c.domain_id IS NULL OR NOT EXISTS '
      '(SELECT 1 FROM domains p WHERE p.id = c.domain_id) LIMIT 1',
      'SELECT 1 FROM ip_records c WHERE c.ip_list_id IS NOT NULL AND NOT EXISTS '
      '(SELECT 1 FROM ip_lists p WHERE p.id = c.ip_list_id) LIMIT 1',
      'SELECT 1 FROM domains WHERE id = -1 AND domain_list_id IS NOT NULL LIMIT 1',
    ):
      if (await conn.execute(text(query))).first():
        raise DatabaseWriteError('Legacy parent identities are inconsistent')
    for name in ('dns_servers', 'domains'):
      query = 'SELECT count(*) FROM ' + self.__startup_identifier(name) + ' WHERE id IN (-1, 0)'  # noqa: S608
      result = await conn.execute(text(query))
      if result.scalar_one() == 2:
        raise DatabaseWriteError('Legacy default identities conflict')
    affected = sources | set(targets.values())
    triggers = (await conn.execute(text("SELECT tbl_name FROM sqlite_master WHERE type = 'trigger'"))).scalars()
    if any(name in affected for name in triggers):
      raise DatabaseWriteError('Legacy import cannot preserve data with table triggers')
    for name in targets.values():
      if name in original_schema:
        kind, sql = original_schema[name]
        if kind != 'table' or not await self.__compatible_current_table(conn, name, sql):
          raise DatabaseWriteError('Legacy target schema is incompatible')
        if await self.__startup_count(conn, name):
          raise DatabaseWriteError('Legacy import requires empty target tables')
    counts = {name: await self.__startup_count(conn, name) for name in targets}
    remap_default_domain = (await conn.execute(text('SELECT 1 FROM domains WHERE id = -1'))).first() is not None
    return counts, remap_default_domain

  async def __startup_count(self, conn: AsyncConnection, name: str) -> int:
    # The name comes from the fixed source map or ORM metadata and is quoted.
    query = 'SELECT count(*) FROM ' + self.__startup_identifier(name)  # noqa: S608
    result = await conn.execute(text(query))
    return result.scalar_one()

  async def __check_startup_foreign_keys(self, conn: AsyncConnection) -> None:
    for name in (*self.__legacy_targets().values(), IpSupportDbo.__tablename__):
      result = await conn.execute(text('SELECT * FROM pragma_foreign_key_check(:name)'), {'name': name})
      if result.first() is not None:
        raise DatabaseWriteError('Managed database foreign key integrity check failed')

  async def __gateway_effect(self, conn: AsyncConnection) -> bool:
    table = await conn.execute(
      text("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = :name"),
      {'name': IpRecordsDbo.__tablename__},
    )
    if table.first() is None:
      return False
    result = await conn.execute(
      text('SELECT type, "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(:name) WHERE name = :column'),
      {'name': IpRecordsDbo.__tablename__, 'column': 'use_default_gw'},
    )
    column = result.one_or_none()
    if column is None:
      return False
    default = str(column.dflt_value).strip()
    # SQLite preserves parentheses and quoting in reflected defaults.
    while default.startswith('(') and default.endswith(')'):
      default = default[1:-1].strip()
    if (
      column.type.upper() != 'BOOLEAN'
      or column.notnull != 1
      or column.pk
      or column.hidden
      or default not in {'0', "'0'", '"0"'}
    ):
      raise DatabaseWriteError('Gateway column has an incompatible contract')
    return True

  async def __read_connect(self: Self) -> AsyncSession:
    if not self.__state:
      raise Exception('Database not ready to work')
    return self.__db_read_session()

  async def __write_connect(self: Self) -> AsyncSession:
    if not self.__state:
      raise DatabaseWriteError('Database is not ready for writes')
    # The batch owns this session, including connection failures and cancellation.
    return self.__db_write_session()

  async def setup(self: Self) -> None:
    """Initialize storage before starting the owned writer task."""
    if self.__writer_state == WriterState.RUNNING:
      return
    if self.__writer_state in (WriterState.FAILED, WriterState.STOPPING):
      raise WriterClosedError('Database writer cannot be initialized in this state')
    db_session: AsyncSession | None = None
    try:
      await self.__create_tables()
      if self.__initialization_failed:
        raise DatabaseWriteError('Database migrations did not complete')
      db_session = self.__db_read_session()
      result: Result = await db_session.execute(text('SELECT sqlite_version() AS version'))
      logger.info(f'SQLite version="{str(result.scalar())}"')
      await db_session.close()
      db_session = None
    except (Exception, CancelledError) as err:
      if db_session is not None:
        try:
          await db_session.close()
        except Exception, CancelledError:
          self.__session_cleanup_failed = True
          logger.error(
            'Database initialization session cleanup failed',
            exc_info=DatabaseWriteError('Database initialization session cleanup failed'),
          )
      failure = WriterFailedError('Database initialization failed', pending_count=self.pending_count)
      self.__fail_writer(failure)
      if not self.__session_cleanup_failed:
        try:
          await self.__dispose_engines()
        except Exception, CancelledError:
          logger.error(
            'Database initialization engine cleanup failed',
            exc_info=DatabaseWriteError('Database initialization engine cleanup failed'),
          )
      if isinstance(err, CancelledError):
        raise
      raise DatabaseWriteError('Database initialization failed') from err
    self.__state = True
    await self.start_writer()

  async def start_writer(self) -> None:
    """Start one writer after readiness; a failed lifecycle cannot restart."""
    if self.__writer_state == WriterState.RUNNING:
      return
    if self.__writer_state == WriterState.FAILED:
      if self.__writer_failure is not None:
        raise self.__writer_failure
      raise WriterFailedError(
        'Database writer has failed',
        pending_count=self.pending_count,
        unknown_count=self.unknown_count,
        outcome_unknown=bool(self.unknown_count),
      )
    if self.__writer_state == WriterState.STOPPING or not self.__state:
      raise WriterClosedError('Database writer is not ready to start')
    if self.__writer_state == WriterState.STOPPED:
      if self.pending_count or (self.__close_task is not None and not self.__close_task.done()):
        raise WriterClosedError('Database writer has not finished shutdown')
      self.db_save_queue = Queue(maxsize=settings.queue_max_size)
      self.__close_task = None
    self.__writer_state = WriterState.RUNNING
    self.__writer_task = create_task(self.__task_process_commit_db_from_queue(), name='database_writer')
    self.__writer_task.add_done_callback(self.__observe_writer)

  def __observe_writer(self, task: Task[None]) -> None:
    if task.cancelled() or task.exception() is not None:
      self.__fail_writer(
        WriterFailedError(
          'Database writer terminated unexpectedly',
          pending_count=self.pending_count,
          unknown_count=self.unknown_count,
          outcome_unknown=bool(self.unknown_count),
        )
      )

  def __check_admission(self) -> None:
    if self.__writer_state == WriterState.FAILED:
      raise WriterFailedError(
        'Database writer has failed',
        pending_count=self.pending_count,
        unknown_count=self.unknown_count,
        outcome_unknown=bool(self.unknown_count),
      )
    if self.__writer_state not in (WriterState.NEW, WriterState.RUNNING):
      raise WriterClosedError('Database writer is closed', pending_count=self.pending_count)

  def __notify_item(self, item: QueueElementDto, event: str, *, final: bool = False) -> None:
    for observation in item.observations:
      notify_observation(observation, event, perf_counter())
    if final:
      self.__observations.pop(id(item), None)
      item.observations = ()

  def __notify_batch(self, items: list[QueueElementDto], event: str, *, final: bool = False) -> None:
    for item in items:
      self.__notify_item(item, event, final=final)

  def __admitted(self, item: QueueElementDto) -> None:
    item.admitted_at = perf_counter()
    if item.observations:
      self.__observations[id(item)] = item
    self.__notify_item(item, 'admitted')

  async def __put_write(self, item: QueueElementDto) -> None:
    started = perf_counter()
    outcome = 'rejected'
    self.__notify_item(item, 'admission_started')
    try:
      self.__check_admission()
      try:
        await self.db_save_queue.put(item)
      except QueueShutDown:
        self.__check_admission()
        raise WriterClosedError('Database writer queue is closed') from None
      self.__admitted(item)
      outcome = 'admitted'
    except CancelledError:
      outcome = 'cancelled'
      raise
    finally:
      if outcome != 'admitted':
        self.__notify_item(item, 'not_admitted', final=True)
      observe_duration(queue_duration, started, queue='writer', phase='admission', outcome=outcome)

  def __put_write_nowait(self, item: QueueElementDto) -> None:
    started = perf_counter()
    outcome = 'rejected'
    self.__notify_item(item, 'admission_started')
    try:
      self.__check_admission()
      try:
        self.db_save_queue.put_nowait(item)
      except QueueShutDown:
        self.__check_admission()
        raise WriterClosedError('Database writer queue is closed') from None
      self.__admitted(item)
      outcome = 'admitted'
    finally:
      if outcome != 'admitted':
        self.__notify_item(item, 'not_admitted', final=True)
      observe_duration(queue_duration, started, queue='writer', phase='admission', outcome=outcome)

  def __fail_writer(self, failure: WriterFailedError) -> None:
    self.__writer_state = WriterState.FAILED
    if self.__writer_failure is None:
      self.__writer_failure = failure
    self.db_save_queue.shutdown(immediate=False)
    active = (
      {id(item) for item in self.__pending_batch}
      if self.__batch_task is not None and not self.__batch_task.done()
      else set()
    )
    observations = tuple(observation for item in self.__observations.values() for observation in item.observations)
    for key, item in tuple(self.__observations.items()):
      if key in active:
        self.__notify_item(item, 'unknown')
      else:
        self.__notify_item(item, 'known_not_committed', final=True)
    self.__failure_summaries.update(persistence_summaries(observations))
    logger.error(f'Database writer failed; pending={self.pending_count}, unknown={self.unknown_count}')

  async def __dispose_engines(self) -> None:
    try:
      await self.__read_engine.dispose()
    finally:
      await self.__write_engine.dispose()

  async def __finish_close(self) -> None:
    try:
      if self.__writer_task is not None:
        try:
          await self.__writer_task
        except CancelledError:
          if self.__writer_failure is None:
            self.__fail_writer(
              WriterFailedError(
                'Database writer was cancelled',
                pending_count=self.pending_count,
                unknown_count=self.unknown_count,
              )
            )
      if self.__writer_failure is None:
        if self.pending_count:
          self.__fail_writer(
            WriterFailedError(
              'Database writer stopped with pending commands',
              pending_count=self.pending_count,
            )
          )
        else:
          await self.db_save_queue.join()
      if self.__writer_failure is not None:
        raise self.__writer_failure
    finally:
      # A cancelled caller must not dispose an engine still used by the writer.
      if not self.__session_cleanup_failed:
        try:
          await self.__dispose_engines()
        except Exception:
          failure = WriterFailedError(
            'Database engine cleanup failed',
            pending_count=self.pending_count,
          )
          logger.error('Database engine cleanup failed', exc_info=failure)
          self.__fail_writer(failure)
      if self.__writer_failure is None:
        self.__writer_state = WriterState.STOPPED

  @staticmethod
  def __observe_close(task: Task[None]) -> None:
    if not task.cancelled():
      task.exception()

  async def close(self, timeout: float | None = None) -> None:
    """Stop admission, drain accepted writes and release idle engines.

    A timeout reports failure immediately while the owned task finishes native
    work and cleanup. It does not imply that in-memory commands are durable.
    """
    if self.__close_task is None:
      if self.__writer_state == WriterState.NEW and self.pending_count and self.__state:
        await self.start_writer()
      if self.__writer_state != WriterState.FAILED:
        self.__writer_state = WriterState.STOPPING
      self.db_save_queue.shutdown(immediate=False)
      self.__close_task = create_task(self.__finish_close(), name='database_close')
      self.__close_task.add_done_callback(self.__observe_close)
    try:
      await wait_for(
        shield(self.__close_task),
        timeout=settings.db_shutdown_timeout if timeout is None else timeout,
      )
    except (TimeoutError, CancelledError) as err:
      if self.__batch_task is not None and not self.__batch_task.done():
        self.__unknown_count = len(self.__pending_batch)
      failure = DatabaseShutdownError(
        'Database shutdown did not confirm a complete drain',
        pending_count=self.pending_count,
        unknown_count=self.unknown_count,
        outcome_unknown=bool(self.unknown_count),
      )
      self.__fail_writer(failure)
      if self.__writer_task is not None and not self.__writer_task.done():
        self.__writer_task.cancel()
      raise failure from err
    if self.__writer_failure is not None:
      raise self.__writer_failure

  # Migrations

  async def __get_migrations_files(self: Self) -> List[Path]:
    logger.debug(f'Try get migrations files ...')
    migration_files: List[Path] = []
    try:
      for file_path in self.__migrations_path.glob('*.py'):
        if file_path.name != '__init__.py' and not file_path.name.startswith('__pycache__'):
          migration_files.append(file_path)
      migration_files.sort(key=lambda x: x.name)
      logger.debug(f'{migration_files=}')
      return migration_files
    except Exception as err:
      raise err

  async def __get_all_applied_migrations(self: Self, conn: AsyncConnection) -> list[MigrationsDto]:
    migrations = await MigrationsDbo.get_all(conn=conn)
    return [
      MigrationsDto(id=migration[0], name=migration[1], checksum=migration[2], applied_at=migration[3])
      for migration in migrations
    ]

  async def __run_migration(self: Self, migration_file: Path, conn: AsyncConnection) -> bool:
    spec: ModuleSpec | None = spec_from_file_location(name=migration_file.stem, location=migration_file)
    if spec is None or spec.loader is None:
      raise DatabaseWriteError('Migration module cannot be loaded')
    migration_module: ModuleType = module_from_spec(spec=spec)
    spec.loader.exec_module(module=migration_module)
    if hasattr(migration_module, 'upgrade'):
      await migration_module.upgrade(conn=conn)
    if hasattr(migration_module, 'downgrade'):
      await migration_module.downgrade(conn=conn)
    return True

  async def __main_migrations(
    self,
    conn: AsyncConnection,
    *,
    completed: set[str],
    legacy_counts: dict[str, int],
    remap_default_domain: bool,
  ) -> None:
    migration_files = await self.__get_migrations_files()
    if legacy_counts and LEGACY_IMPORT_MIGRATION not in {migration.name for migration in migration_files}:
      raise DatabaseWriteError('Legacy import migration is unavailable')
    for migration in migration_files:
      if migration.name in completed:
        continue
      checksum = calculate_checksum(file_path=migration)
      expected_checksum = STARTUP_MIGRATION_CHECKSUMS.get(migration.name)
      if expected_checksum is not None and checksum != expected_checksum:
        raise DatabaseWriteError('Known startup migration source has changed')
      if migration.name == LEGACY_IMPORT_MIGRATION:
        if legacy_counts:
          await self.__run_migration(migration_file=migration, conn=conn)
          if remap_default_domain:
            await conn.execute(
              update(IpRecordsDbo).where(IpRecordsDbo.domain_id == -1).values(domain_id=0, updated_at=None)
            )
          for source, target in self.__legacy_targets().items():
            if await self.__startup_count(conn, target) != legacy_counts[source]:
              raise DatabaseWriteError('Legacy import did not preserve every business row')
          await self.__check_startup_foreign_keys(conn)
      elif migration.name == GATEWAY_MIGRATION:
        if not await self.__gateway_effect(conn):
          await self.__run_migration(migration_file=migration, conn=conn)
        if not await self.__gateway_effect(conn):
          raise DatabaseWriteError('Gateway migration did not establish its column')
      else:
        await self.__run_migration(migration_file=migration, conn=conn)
      await conn.execute(
        insert(MigrationsDbo).values(
          name=migration.name,
          checksum=checksum,
          applied_at=datetime.now(UTC),
        )
      )

  # DNS servers

  async def get_all_dns_servers(
    self: Self,
    before_time: float,
    limit: int,
    offset: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    default: Optional[bool] = None,
    search_text: Optional[str] = None,
  ) -> DnsPayloadResp:
    logger.debug(f'Try get all DNS servers ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {default=}, {search_text=}')
    payload: List[DnsElementResp] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      #
      total: int = await DnsServersDbo.get_total(db_session=db_session)
      if total > 0:
        dns_servers: Sequence[
          Row[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]]
        ] = await DnsServersDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          start_date=start_date,
          end_date=end_date,
          default=default,
          search_text=search_text,
        )
        #
        for server in dns_servers:
          payload.append(
            DnsElementResp(
              id=server[0],
              server=server[1],
              doh_server=server[2],
              description=server[3],
              created_at=server[4].timestamp(),
              created_at_hum=server[4].strftime('%Y-%m-%d %H:%M:%S'),
              updated_at=None if server[5] == None else server[5].timestamp(),
              updated_at_hum=None if server[5] == None else server[5].strftime('%Y-%m-%d %H:%M:%S'),
            )
          )
      return DnsPayloadResp(
        limit=limit, offset=offset, total=total, count=len(payload), duration=monotonic() - before_time, payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all DNS servers failed : {err}', exc_info=True)
      await db_session.rollback()
      return DnsPayloadResp(
        limit=limit, offset=offset, total=0, count=0, duration=monotonic() - before_time, payload=payload
      )
    finally:
      await db_session.close()

  async def get_dns_server_on_id(self: Self, id: int) -> DnsElementResp | None:
    logger.debug(f'Try get DNS server on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__read_connect()
      dns_server: (
        Row[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] | None
      ) = await DnsServersDbo.get_on_id(db_session=db_session, id=id)
      if dns_server != None:
        return DnsElementResp(
          id=dns_server[0],
          server=dns_server[1],
          doh_server=dns_server[2],
          description=dns_server[3],
          created_at=dns_server[4].timestamp(),
          created_at_hum=dns_server[4].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if dns_server[5] == None else dns_server[5].timestamp(),
          updated_at_hum=None if dns_server[5] == None else dns_server[5].strftime('%Y-%m-%d %H:%M:%S'),
        )
      return None
    except Exception as err:
      logger.error(f'Try get DNS server on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def put_add_dns_servers_to_queue(self: Self, dns_servers: List[DnsPostElementReq]) -> None:
    logger.debug(f'Try send DNS servers to Queue ...')
    try:
      dns_server_element: QueueElementDto = QueueElementDto(target=TargetAction.DNS_SERVERS_ADD, elements=dns_servers)
      await self.__put_write(item=dns_server_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send DNS servers {dns_servers=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send DNS servers to Queue : {err}', exc_info=True)

  async def put_delete_dns_servers_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted DNS servers to Queue ...')
    try:
      if id != None:
        logger.debug(f'Once DNS server delete {id=}')
        dns_server_element: QueueElementDto = QueueElementDto(target=TargetAction.DNS_SERVERS_DELETE, elements=[id])
      else:
        dns_server_element: QueueElementDto = QueueElementDto(target=TargetAction.DNS_SERVERS_DELETE_ALL, elements=[])
      await self.__put_write(item=dns_server_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send deleted DNS servers to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted DNS servers to Queue : {err}', exc_info=True)

  async def get_dns_servers_for_resolve(self: Self) -> Tuple[List[DnsServerDto], List[DnsServerDto]]:
    """Read custom-or-default DNS from one committed query, closing before return."""
    try:
      async with await self.__read_connect() as db_session:
        try:
          rows = await DnsServersDbo.get_all_for_resolve(db_session=db_session)
          servers = (
            [DnsServerDto(server=cast(str, row[0]), id=row[3]) for row in rows if row[2] == DnsServerType.DEFAULT],
            [DnsServerDto(server=cast(str, row[1]), id=row[3]) for row in rows if row[2] == DnsServerType.DOH],
          )
          if not any(servers):
            raise DnsConfigurationReadError('Cannot read DNS configuration')
          return servers
        except Exception:
          await db_session.rollback()
          raise
    except Exception as err:
      logger.error('DNS configuration read failed')
      raise DnsConfigurationReadError('Cannot read DNS configuration') from err

  # Domains Lists

  async def get_all_domains_lists(
    self: Self,
    before_time: float,
    limit: int,
    offset: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search_text: Optional[str] = None,
    attempts: Optional[int] = None,
  ) -> DomainsListsPayloadResp:
    logger.debug(f'Try get all Domains lists ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[DomainsListElementResp] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      total: int = await DomainsListsDbo.get_total(db_session=db_session)
      if total > 0:
        domains_lists: Sequence[
          Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]]
        ] = await DomainsListsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          start_date=start_date,
          end_date=end_date,
          search_text=search_text,
          attempts=attempts,
        )
        #
        for list in domains_lists:
          elements_count: int = await DomainsDbo.get_total_on_domains_list(
            db_session=db_session, domains_list_id=list[0]
          )
          payload.append(
            DomainsListElementResp(
              id=list[0],
              name=list[1],
              url=list[2],
              description=list[3],
              hash=list[4],
              attempts=list[5],
              elements_count=elements_count,
              created_at=list[6].timestamp(),
              created_at_hum=list[6].strftime('%Y-%m-%d %H:%M:%S'),
              updated_at=None if list[7] == None else list[7].timestamp(),
              updated_at_hum=None if list[7] == None else list[7].strftime('%Y-%m-%d %H:%M:%S'),
            )
          )
      return DomainsListsPayloadResp(
        limit=limit, offset=offset, total=total, count=len(payload), duration=monotonic() - before_time, payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all Domains lists failed : {err}', exc_info=True)
      await db_session.rollback()
      return DomainsListsPayloadResp(
        limit=limit, offset=offset, total=0, count=0, duration=monotonic() - before_time, payload=payload
      )
    finally:
      await db_session.close()

  async def get_domains_list_on_id(self: Self, id: int) -> DomainsListElementResp | None:
    logger.debug(f'Try get Domains list on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__read_connect()
      domains_list: (
        Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] | None
      ) = await DomainsListsDbo.get_on_id(db_session=db_session, id=id)
      if domains_list != None:
        elements_count: int = await DomainsDbo.get_total_on_domains_list(db_session=db_session, domains_list_id=id)
        return DomainsListElementResp(
          id=domains_list[0],
          name=domains_list[1],
          url=domains_list[2],
          description=domains_list[3],
          hash=domains_list[4],
          attempts=domains_list[5],
          elements_count=elements_count,
          created_at=domains_list[6].timestamp(),
          created_at_hum=domains_list[6].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if domains_list[7] == None else domains_list[7].timestamp(),
          updated_at_hum=None if domains_list[7] == None else domains_list[7].strftime('%Y-%m-%d %H:%M:%S'),
        )
      return None
    except Exception as err:
      logger.error(f'Try get Domains list on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def put_add_domains_lists_to_queue(self: Self, domains_lists: List[DomainsListsPostElementReq]) -> None:
    logger.debug(f'Try send Domains lists to Queue ...')
    try:
      domains_lists_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DOMAINS_LISTS_ADD, elements=domains_lists
      )
      await self.__put_write(item=domains_lists_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send domains lists {domains_lists=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send domains lists to Queue : {err}', exc_info=True)

  async def put_delete_domains_list_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Domains list to Queue ...')
    try:
      if id != None:
        logger.debug(f'One Domains list delete {id=}')
        domains_list_element: QueueElementDto = QueueElementDto(target=TargetAction.DOMAINS_LISTS_DELETE, elements=[id])
      else:
        domains_list_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_LISTS_DELETE_ALL, elements=[]
        )
      await self.__put_write(item=domains_list_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Domains list to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Domains list to Queue : {err}', exc_info=True)

  async def update_domains_lists(self: Self, domains_lists: List[DomainsListDto]) -> None:
    logger.debug(f'Try send update Domains lists to Queue ...')
    try:
      logger.debug(f'One Domains lists update {domains_lists=}')
      domains_list_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DOMAINS_LISTS_UPDATE, elements=domains_lists
      )
      await self.__put_write(item=domains_list_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send update Domains lists to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send update Domains lists to Queue : {err}', exc_info=True)

  # Domains

  async def get_all_domains(
    self: Self,
    before_time: float,
    limit: int,
    offset: int,
    resolved: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    default: Optional[bool] = None,
    search_text: Optional[str] = None,
  ) -> DomainsPayloadResp:
    logger.debug(f'Try get all Domains ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[DomainElementResp] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      total: int = await DomainsDbo.get_total(db_session=db_session)
      resolved_count: int = await DomainsDbo.get_total_resolved(db_session=db_session)
      if total > 0:
        domains_and_query: Tuple[
          Sequence[Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]]], int
        ] = await DomainsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          resolved=resolved,
          start_date=start_date,
          end_date=end_date,
          default=default,
          search_text=search_text,
        )
        #
        domains: Sequence[
          Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]]
        ] = domains_and_query[0]
        query_total: int = domains_and_query[1]
        for domain in domains:
          ip_addr_v4, ip_addr_v6 = await IpRecordsDbo.get_ips_on_domain_id(db_session=db_session, domain_id=domain[0])
          payload.append(
            DomainElementResp(
              id=domain[0],
              domains_list_id=domain[1],
              resolved=domain[2],
              name=domain[3],
              ros_comment=domain[4],
              ips_v4=ip_addr_v4 if len(ip_addr_v4) > 0 else None,
              ips_v6=ip_addr_v6 if len(ip_addr_v6) > 0 else None,
              created_at=domain[5].timestamp(),
              created_at_hum=domain[5].strftime('%Y-%m-%d %H:%M:%S'),
              updated_at=None if domain[6] == None else domain[6].timestamp(),
              updated_at_hum=None if domain[6] == None else domain[6].strftime('%Y-%m-%d %H:%M:%S'),
              last_resolved_at=None if domain[7] == None else domain[7].timestamp(),
              last_resolved_at_hum=None if domain[7] == None else domain[7].strftime('%Y-%m-%d %H:%M:%S'),
            )
          )
      return DomainsPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        total_resolved=resolved_count,
        total_query=query_total,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload,
      )
    except Exception as err:
      logger.error(f'Try get all Domains failed : {err}', exc_info=True)
      await db_session.rollback()
      return DomainsPayloadResp(
        limit=limit, offset=offset, total=0, count=0, duration=monotonic() - before_time, payload=payload
      )
    finally:
      await db_session.close()

  async def get_domain_on_id(self: Self, id: int) -> DomainElementResp | None:
    logger.debug(f'Try get Domain on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__read_connect()
      domain: (
        Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] | None
      ) = await DomainsDbo.get_on_id(db_session=db_session, id=id)
      if domain != None:
        ip_addr_v4, ip_addr_v6 = await IpRecordsDbo.get_ips_on_domain_id(db_session=db_session, domain_id=domain[0])
        return DomainElementResp(
          id=domain[0],
          domains_list_id=domain[1],
          resolved=domain[2],
          name=domain[3],
          ros_comment=domain[4],
          ips_v4=ip_addr_v4 if len(ip_addr_v4) > 0 else None,
          ips_v6=ip_addr_v6 if len(ip_addr_v6) > 0 else None,
          created_at=domain[5].timestamp(),
          created_at_hum=domain[5].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if domain[6] == None else domain[6].timestamp(),
          updated_at_hum=None if domain[6] == None else domain[6].strftime('%Y-%m-%d %H:%M:%S'),
          last_resolved_at=None if domain[7] == None else domain[7].timestamp(),
          last_resolved_at_hum=None if domain[7] == None else domain[7].strftime('%Y-%m-%d %H:%M:%S'),
        )
      return None
    except Exception as err:
      logger.error(f'Try get Domain on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def put_add_domains_to_queue(self: Self, domains: List[DomainsPostElementReq]) -> None:
    logger.debug(f'Try send Domains to Queue ...')
    try:
      filtered_domains: List[DomainsPostElementReq] = [
        domain for domain in domains if len(domain.domain) > settings.domains_filtered_min_len
      ]
      if settings.domains_not_allowed_pattern != None:
        clear_domains: List[DomainsPostElementReq] = [
          domain for domain in filtered_domains if settings.domains_not_allowed_pattern.search(domain.domain) == None
        ]
        domains_element: QueueElementDto = QueueElementDto(target=TargetAction.DOMAINS_ADD, elements=clear_domains)
      else:
        domains_element: QueueElementDto = QueueElementDto(target=TargetAction.DOMAINS_ADD, elements=filtered_domains)
      await self.__put_write(item=domains_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send domains {domains=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send domains to Queue : {err}', exc_info=True)

  async def put_delete_domains_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Domains to Queue ...')
    try:
      if id != None:
        logger.debug(f'One Domains delete {id=}')
        domains_element: QueueElementDto = QueueElementDto(target=TargetAction.DOMAINS_DELETE, elements=[id])
      else:
        domains_element: QueueElementDto = QueueElementDto(target=TargetAction.DOMAINS_DELETE_ALL, elements=[])
      await self.__put_write(item=domains_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Domains to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Domains to Queue : {err}', exc_info=True)

  async def get_new_domains_for_resolve(self: Self) -> List[DomainResult]:
    logger.debug(f'Try get new domains for resolve ...')
    domains: List[DomainResult] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      # get domains for resolve
      domains_for_resolve: Sequence[Row[Tuple[int, str, int | None, int]]] = await DomainsDbo.get_new_for_resolve(
        db_session=db_session, limit=settings.domains_resolve_new_batch_size
      )
      domains = [DomainResult(id=domain[0], name=domain[1], list_id=domain[2]) for domain in domains_for_resolve]
      logger.debug(f'New domains for resolve: {len(domains)}')
      return domains
    except Exception as err:
      logger.error(f'Try get new domains for resolve failed : {err}', exc_info=True)
      await db_session.rollback()
      return domains
    finally:
      await db_session.close()

  async def get_stale_domains_for_resolve(self: Self) -> List[DomainResult]:
    logger.debug(f'Try get stale domains for resolve ...')
    domains: List[DomainResult] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      # get domains for resolve
      domains_for_resolve: Sequence[Row[Tuple[int, str, int | None, int]]] = await DomainsDbo.get_stale_for_resolve(
        db_session=db_session, limit=settings.domains_resolve_stale_batch_size
      )
      domains = [DomainResult(id=domain[0], name=domain[1], list_id=domain[2]) for domain in domains_for_resolve]
      logger.debug(f'Stale domains for resolve: {len(domains)}')
      return domains
    except Exception as err:
      logger.error(f'Try get stale domains for resolve failed : {err}', exc_info=True)
      await db_session.rollback()
      return domains
    finally:
      await db_session.close()

  async def get_all_domains_on_domains_list(self: Self, domains_list_id: int) -> List[DomainResult]:
    logger.debug(f'Try get Domains on domains list {domains_list_id=} ...')
    domains: List[DomainResult] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      # get domains
      domains_on_list: Sequence[Row[Tuple[int, str]]] = await DomainsDbo.get_all_on_domains_list(
        db_session=db_session, domains_list_id=domains_list_id
      )
      domains = [DomainResult(id=domain[0], name=domain[1], list_id=domains_list_id) for domain in domains_on_list]
      logger.debug(f'Domains on domains list {domains_list_id=}: {domains=}')
      return domains
    except Exception as err:
      logger.error(f'Try get Domains on domains list {domains_list_id=} failed : {err}', exc_info=True)
      await db_session.rollback()
      return domains
    finally:
      await db_session.close()

  async def put_domain_after_resolve(self: Self, domain: DomainResult) -> None:
    logger.debug(f'Try send insert ips, delete ips, update domains to Queue ...')
    try:
      domains_resolved_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DOMAINS_RESOLVED,
        elements=[DomainResolutionIntent(domain.id, domain.resolution_complete, tuple(domain.storage_ips))],
        observations=(domain.observation,) if domain.observation is not None else (),
      )
      await self.__put_write(item=domains_resolved_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send domains {domain=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send domains to Queue : {err}', exc_info=True)

  # Ip Address Lists

  async def get_all_ips_lists(
    self: Self,
    before_time: float,
    limit: int,
    offset: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search_text: Optional[str] = None,
    attempts: Optional[int] = None,
  ) -> IpsListsPayloadResp:
    logger.debug(f'Try get all IP address lists ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[IpsListElementResp] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      total: int = await IpsListsDbo.get_total(db_session=db_session)
      if total > 0:
        ips_lists: Sequence[
          Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]]
        ] = await IpsListsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          start_date=start_date,
          end_date=end_date,
          search_text=search_text,
          attempts=attempts,
        )
        for list in ips_lists:
          ip_v4_count, ip_v6_count = await IpRecordsDbo.get_total_ips_on_ips_list(
            db_session=db_session, ip_list_id=list[0]
          )
          payload.append(
            IpsListElementResp(
              id=list[0],
              name=list[1],
              url=list[2],
              description=list[3],
              hash=list[4],
              attempts=list[5],
              ip_v4_count=ip_v4_count,
              ip_v6_count=ip_v6_count,
              created_at=list[6].timestamp(),
              created_at_hum=list[6].strftime('%Y-%m-%d %H:%M:%S'),
              updated_at=None if list[7] == None else list[7].timestamp(),
              updated_at_hum=None if list[7] == None else list[7].strftime('%Y-%m-%d %H:%M:%S'),
            )
          )
      return IpsListsPayloadResp(
        limit=limit, offset=offset, total=total, count=len(payload), duration=monotonic() - before_time, payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all IP address lists failed : {err}', exc_info=True)
      await db_session.rollback()
      return IpsListsPayloadResp(
        limit=limit, offset=offset, total=0, count=0, duration=monotonic() - before_time, payload=payload
      )
    finally:
      await db_session.close()

  async def get_ips_list_on_id(self: Self, id: int) -> IpsListElementResp | None:
    logger.debug(f'Try get Ips list on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__read_connect()
      ips_list: (
        Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] | None
      ) = await IpsListsDbo.get_on_id(db_session=db_session, id=id)
      if ips_list != None:
        ip_v4_count, ip_v6_count = await IpRecordsDbo.get_total_ips_on_ips_list(
          db_session=db_session, ip_list_id=ips_list[0]
        )
        return IpsListElementResp(
          id=ips_list[0],
          name=ips_list[1],
          url=ips_list[2],
          description=ips_list[3],
          hash=ips_list[4],
          attempts=ips_list[5],
          ip_v4_count=ip_v4_count,
          ip_v6_count=ip_v6_count,
          created_at=ips_list[6].timestamp(),
          created_at_hum=ips_list[6].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if ips_list[7] == None else ips_list[7].timestamp(),
          updated_at_hum=None if ips_list[7] == None else ips_list[7].strftime('%Y-%m-%d %H:%M:%S'),
        )
      return None
    except Exception as err:
      logger.error(f'Try get Ips list on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def put_add_ips_lists_to_queue(self: Self, ips_lists: List[IpsListsPostElementReq]) -> None:
    logger.debug(f'Try send Ips lists to Queue ...')
    try:
      ips_lists_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_LISTS_ADD, elements=ips_lists)
      await self.__put_write(item=ips_lists_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send ips lists {ips_lists=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send ips lists to Queue : {err}', exc_info=True)

  async def put_delete_ips_list_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Ips list to Queue ...')
    try:
      if id != None:
        logger.debug(f'One Ips list delete {id=}')
        ips_list_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_LISTS_DELETE, elements=[id])
      else:
        ips_list_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_LISTS_DELETE_ALL, elements=[])
      await self.__put_write(item=ips_list_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Ips list to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Ips list to Queue : {err}', exc_info=True)

  async def update_ips_lists(self: Self, ips_lists: List[IpsListDto]) -> None:
    logger.debug(f'Try send update Ips lists to Queue ...')
    try:
      logger.debug(f'One Ips lists update {ips_lists=}')
      ips_list_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_LISTS_UPDATE, elements=ips_lists)
      await self.__put_write(item=ips_list_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send update Ips lists to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send update Ips lists to Queue : {err}', exc_info=True)

  # IP address records

  async def get_all_ips(
    self: Self,
    before_time: float,
    limit: int,
    offset: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search_text: Optional[str] = None,
    addr_type: Optional[int] = None,
    use_default_gw: Optional[bool] = None,
  ) -> IpsPayloadResp:
    logger.debug(f'Try get all IP address records ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[IpsElementResp] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      total: int = await IpRecordsDbo.get_total(db_session=db_session)
      if total > 0:
        ips: Sequence[
          Row[Tuple[int, int | None, str, int | None, str, int, str, str | None, bool, datetime, datetime | None]]
        ] = await IpRecordsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          start_date=start_date,
          end_date=end_date,
          search_text=search_text,
          addr_type=addr_type,
          use_default_gw=use_default_gw,
        )
        #
        for ip in ips:
          payload.append(
            IpsElementResp(
              id=ip[0],
              type=ip[5],
              addr=ip[6],
              ip_list_id=ip[1],
              ip_list_name=ip[2],
              domain_id=ip[3],
              domain_name=ip[4],
              ros_comment=ip[7],
              use_default_gw=ip[8],
              created_at=ip[9].timestamp(),
              created_at_hum=ip[9].strftime('%Y-%m-%d %H:%M:%S'),
              updated_at=None if ip[10] == None else ip[10].timestamp(),
              updated_at_hum=None if ip[10] == None else ip[10].strftime('%Y-%m-%d %H:%M:%S'),
            )
          )
      return IpsPayloadResp(
        limit=limit, offset=offset, total=total, count=len(payload), duration=monotonic() - before_time, payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all Domains failed : {err}', exc_info=True)
      await db_session.rollback()
      return IpsPayloadResp(
        limit=limit, offset=offset, total=0, count=0, duration=monotonic() - before_time, payload=payload
      )
    finally:
      await db_session.close()

  async def get_ip_record_on_id(self: Self, id: int) -> IpsElementResp | None:
    logger.debug(f'Try get IP address record on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__read_connect()
      ip_address_record: (
        Row[Tuple[int, int | None, str, int | None, str, str, int, str | None, bool, datetime, datetime | None]] | None
      ) = await IpRecordsDbo.get_on_id(db_session=db_session, id=id)
      if ip_address_record != None:
        return IpsElementResp(
          id=ip_address_record[0],
          ip_list_id=ip_address_record[1],
          ip_list_name=ip_address_record[2],
          domain_id=ip_address_record[3],
          domain_name=ip_address_record[4],
          addr=ip_address_record[5],
          type=ip_address_record[6],
          ros_comment=ip_address_record[7],
          use_default_gw=ip_address_record[8],
          created_at=ip_address_record[9].timestamp(),
          created_at_hum=ip_address_record[9].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if ip_address_record[10] == None else ip_address_record[10].timestamp(),
          updated_at_hum=None if ip_address_record[10] == None else ip_address_record[10].strftime('%Y-%m-%d %H:%M:%S'),
        )
      return None
    except Exception as err:
      logger.error(f'Try get IP address record on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def get_not_allowed_ip_record_ids(self: Self) -> List[int]:
    logger.debug('Try get IP address records blocked by IP_NOT_ALLOWED ...')
    db_session: AsyncSession | None = None
    try:
      db_session = await self.__read_connect()
      ip_records: Sequence[Row[Tuple[int, str]]] = await IpRecordsDbo.get_all_ids_and_addresses(db_session=db_session)
      result = await to_thread(lambda: [record[0] for record in ip_records if not check_ip_allow(record[1])])
      logger.debug(f'IP address records blocked by IP_NOT_ALLOWED: {len(result)}')
      return result
    except Exception as err:
      logger.error(f'Try get IP address records blocked by IP_NOT_ALLOWED failed : {err}', exc_info=True)
      if db_session is not None:
        await db_session.rollback()
      raise err
    finally:
      if db_session is not None:
        await db_session.close()

  async def put_add_ips_to_queue(self: Self, ips: List[IpsPostElementReq]) -> None:
    logger.debug(f'Try send Ips to Queue ...')
    try:
      ips_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_ADD, elements=ips)
      await self.__put_write(item=ips_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send ips {ips=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send ips to Queue : {err}', exc_info=True)

  async def put_delete_ips_to_queue(self: Self, id_or_ip: Optional[int | str] = None) -> None:
    logger.debug(f'Try send deleted Ips to Queue ...')
    try:
      if id_or_ip != None:
        try:
          id: int = int(id_or_ip)
        except TypeError, ValueError:
          try:
            get_ip_version(str(id_or_ip))
          except ValueError:
            return
          logger.debug(f'IP address delete is ADDRESS {id_or_ip=}')
          ips_element = QueueElementDto(target=TargetAction.IPS_DELETE_ADDR, elements=[id_or_ip])
        else:
          logger.debug(f'IP address delete is ID {id=}')
          ips_element = QueueElementDto(target=TargetAction.IPS_DELETE_ID, elements=[id])
      else:
        ips_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_DELETE_ALL, elements=[])
      await self.__put_write(item=ips_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Domains to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Domains to Queue : {err}', exc_info=True)

  async def put_delete_ip_records_to_queue(self: Self, ids: List[int]) -> bool:
    logger.debug('Try send IP address records for deletion to Queue ...')
    if len(ids) < 1:
      return True
    try:
      ips_element: QueueElementDto = QueueElementDto(target=TargetAction.IPS_DELETE_ID, elements=ids)
      logger.debug(f'Put IP address records for deletion to Queue: {len(ids)}')
      self.__put_write_nowait(item=ips_element)
      return True
    except QueueFull, DatabaseWriteError:
      logger.error('Queue is full for IP address records deletion')
      return False
    except Exception as err:
      logger.error(f'Unexpected error - Try send IP address records for deletion to Queue : {err}', exc_info=True)
      return False

  async def put_withdraw_ip_list_records_to_queue(self, list_id: int, ids: list[int]) -> None:
    """Wait for admission of a source-scoped IP-list membership withdrawal."""
    if ids:
      await self.__put_write(
        QueueElementDto(
          target=TargetAction.IPS_LIST_WITHDRAW,
          elements=[IpListWithdrawal(list_id, tuple(ids))],
        )
      )

  async def cleanup_not_allowed_ip_records(self: Self) -> None:
    logger.debug('Start cleanup of IP address records blocked by IP_NOT_ALLOWED')
    try:
      ids: List[int] = await self.get_not_allowed_ip_record_ids()
      is_queued: bool = await self.put_delete_ip_records_to_queue(ids)
      if is_queued:
        logger.info(f'IP address records blocked by IP_NOT_ALLOWED queued for deletion: {len(ids)}')
    except Exception as err:
      logger.error(f'Cleanup of IP address records blocked by IP_NOT_ALLOWED failed : {err}', exc_info=True)

  async def get_all_ips_for_domain(self: Self, domain_id: int) -> List[IpRecordDto]:
    logger.debug(f'Try get all IP address records for Domain {domain_id=} ...')
    result: List[IpRecordDto] = []
    db_session: AsyncSession | None = None
    read_error: Exception | None = None
    try:
      db_session = await self.__read_connect()
      ips_result: Sequence[Row[Tuple[int, str, int]]] = await IpRecordsDbo.get_ips_on_domain_id_extend(
        db_session=db_session, domain_id=domain_id
      )
      result = [IpRecordDto(id=ip[0], ip_address=ip[1], addr_type=ip[2]) for ip in ips_result]
    except Exception as err:
      read_error = err
      if db_session is not None:
        try:
          await db_session.rollback()
        except Exception:
          logger.error('Rollback of domain IP snapshot read failed')
    finally:
      if db_session is not None:
        try:
          await db_session.close()
        except Exception as err:
          if read_error is None:
            read_error = err
          logger.error('Closing the domain IP snapshot read session failed')
    if read_error is not None:
      raise DomainIpReadError('Unable to read domain IP records') from read_error
    return result

  async def get_all_ips_on_ips_list(self: Self, ips_list_id: int) -> List[IpRecordDto]:
    logger.debug(f'Try get all IP address records for ips list {ips_list_id=} ...')
    result: List[IpRecordDto] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      ips_result: Sequence[Row[Tuple[int, str]]] = await IpRecordsDbo.get_all_on_ips_list(
        db_session=db_session, ip_list_id=ips_list_id
      )
      result = [IpRecordDto(id=ip[0], ip_address=ip[1]) for ip in ips_result]
      return result
    except Exception as err:
      logger.error(f'Try get all IP address records for ips list {ips_list_id=} failed : {err}', exc_info=True)
      await db_session.rollback()
      return result
    finally:
      await db_session.close()

  async def get_all_ips_for_update(self: Self, addr_type: int | None = None) -> List[IpRecordDto]:
    logger.debug(f'Try get all IP address for update ...')
    ips: List[IpRecordDto] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      all_ips: Sequence[Row[Tuple[str, str, bool, int]]] = await IpRecordsDbo.get_all_for_update(
        db_session=db_session, addr_type=addr_type
      )
      ips = [IpRecordDto(ip_address=ip[0], comment=ip[1], use_default_gw=ip[2], addr_type=ip[3]) for ip in all_ips]
      return ips
    except Exception as err:
      logger.error(f'Try get all IP address for update failed : {err}', exc_info=True)
      await db_session.rollback()
      return ips
    finally:
      await db_session.close()

  # Router OS configs

  async def get_all_ros_configs(
    self: Self,
    before_time: float,
    limit: int,
    offset: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    default: Optional[bool] = None,
    search_text: Optional[str] = None,
  ) -> RosConfigPayloadResp:
    logger.debug(f'Try get all RoS configs ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {default=}, {search_text=}')
    payload: List[RosConfigElementResp] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      #
      total: int = await RosConfigsDbo.get_total(db_session=db_session)
      if total > 0:
        ros_configs: Sequence[
          Row[Tuple[int, str, str, str, str, str | None, datetime, datetime | None]]
        ] = await RosConfigsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          start_date=start_date,
          end_date=end_date,
          default=default,
          search_text=search_text,
        )
        #
        for config in ros_configs:
          payload.append(
            RosConfigElementResp(
              id=config[0],
              host=config[1],
              user=config[2],
              password=config[3],
              bgp_list_name=config[4],
              description=config[5],
              created_at=config[6].timestamp(),
              created_at_hum=config[6].strftime('%Y-%m-%d %H:%M:%S'),
              updated_at=None if config[7] == None else config[7].timestamp(),
              updated_at_hum=None if config[7] == None else config[7].strftime('%Y-%m-%d %H:%M:%S'),
            )
          )
      return RosConfigPayloadResp(
        limit=limit, offset=offset, total=total, count=len(payload), duration=monotonic() - before_time, payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all RoS configs failed : {err}', exc_info=True)
      await db_session.rollback()
      return RosConfigPayloadResp(
        limit=limit, offset=offset, total=0, count=0, duration=monotonic() - before_time, payload=payload
      )
    finally:
      await db_session.close()

  async def get_ros_config_on_id(self: Self, id: int) -> RosConfigElementResp | None:
    logger.debug(f'Try get RoS config on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__read_connect()
      ros_config: (
        Row[Tuple[int, str, str, str, str, str | None, datetime, datetime | None]] | None
      ) = await RosConfigsDbo.get_on_id(db_session=db_session, id=id)
      if ros_config != None:
        return RosConfigElementResp(
          id=ros_config[0],
          host=ros_config[1],
          user=ros_config[2],
          password=ros_config[3],
          bgp_list_name=ros_config[4],
          description=ros_config[5],
          created_at=ros_config[6].timestamp(),
          created_at_hum=ros_config[6].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if ros_config[7] == None else ros_config[7].timestamp(),
          updated_at_hum=None if ros_config[7] == None else ros_config[7].strftime('%Y-%m-%d %H:%M:%S'),
        )
      return None
    except Exception as err:
      logger.error(f'Try get RoS config on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def put_add_ros_configs_to_queue(self: Self, ros_configs: List[RosConfigsPostElementReq]) -> None:
    logger.debug(f'Try send RoS configs to Queue ...')
    try:
      ros_configs_element: QueueElementDto = QueueElementDto(target=TargetAction.ROS_CONFIG_ADD, elements=ros_configs)
      await self.__put_write(item=ros_configs_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send RoS configs {ros_configs=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send RoS configs to Queue : {err}', exc_info=True)

  async def put_delete_ros_configs_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Router OS configs to Queue ...')
    try:
      if id != None:
        logger.debug(f'One Router OS config delete {id=}')
        ros_configs_element: QueueElementDto = QueueElementDto(target=TargetAction.ROS_CONFIG_DELETE, elements=[id])
      else:
        ros_configs_element: QueueElementDto = QueueElementDto(target=TargetAction.ROS_CONFIG_DELETE_ALL, elements=[])
      await self.__put_write(item=ros_configs_element)
    except DatabaseWriteError:
      raise
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Router OS configs to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Router OS configs to Queue : {err}', exc_info=True)

  async def get_all_configs_for_ros_update(self: Self) -> List[RosConfigDto]:
    logger.debug(f'Try get all RoS configs for update ...')
    configs: List[RosConfigDto] = []
    try:
      db_session: AsyncSession = await self.__read_connect()
      ros_configs: Sequence[Row[Tuple[int, str, str, str, str]]] = await RosConfigsDbo.get_all_for_update(
        db_session=db_session
      )
      configs: List[RosConfigDto] = [
        RosConfigDto(id=config[0], host=config[1], user=config[2], passwd=config[3], bgp_list_name=config[4])
        for config in ros_configs
      ]
      return configs
    except Exception as err:
      logger.error(f'Try get all RoS configs for update failed : {err}', exc_info=True)
      await db_session.rollback()
      return configs
    finally:
      await db_session.close()

  # Job

  async def lists_load(self: Self, forced: bool) -> None:
    logger.info(f'Lists load - START {forced=}')
    db_session: AsyncSession | None = None
    try:
      db_session = await self.__read_connect()
      domains_lists_total: int = await DomainsListsDbo.get_total(db_session=db_session)
      ips_lists_total: int = await IpsListsDbo.get_total(db_session=db_session)
      if domains_lists_total > 0:
        logger.debug(f'Load Domains lists {domains_lists_total=} ...')
        domains_lists: List[DomainsListDto] = await DomainsListsDbo.get_for_update(db_session=db_session, forced=forced)
        logger.debug(f'{domains_lists=}')
        await self.file_loader_client.get_domains_from_lists(lists=domains_lists)
        unactive_domains_lists: List[DomainsListDto] = [
          list for list in domains_lists if list.attempts >= settings.attempts_limit
        ]
        active_domains_lists: List[DomainsListDto] = [
          list for list in domains_lists if list.attempts < settings.attempts_limit
        ]
        # delete unactive domains lists
        if len(unactive_domains_lists) > 0:
          for list in unactive_domains_lists:
            await self.put_delete_domains_list_to_queue(id=list.id)
        # add domains
        if len(active_domains_lists) > 0:
          domains_add: List[DomainsPostElementReq] = []
          domains_delete: List[DomainResult] = []
          for list in active_domains_lists:
            if list.found_elements == None:
              continue  # if hash not change in get_domains_from_lists - found_elements is None
            current_domains: List[DomainResult] = await self.get_all_domains_on_domains_list(domains_list_id=list.id)
            current_domains_list: List[str] = [domain.name for domain in current_domains]
            [
              domains_add.append(DomainsPostElementReq(domain=domain, list_id=list.id))
              for domain in list.found_elements
              if domain not in current_domains_list
            ]
            [domains_delete.append(domain) for domain in current_domains if domain.name not in list.found_elements]
          await self.put_add_domains_to_queue(domains=domains_add)
          for domain in domains_delete:
            await self.put_delete_domains_to_queue(id=domain.id)
          await self.update_domains_lists(domains_lists=active_domains_lists)
      if ips_lists_total > 0:
        logger.debug(f'Load IPs lists {ips_lists_total=} ...')
        ips_lists: List[IpsListDto] = await IpsListsDbo.get_for_update(db_session=db_session, forced=forced)
        logger.debug(f'{ips_lists=}')
        await self.file_loader_client.get_ips_from_lists(lists=ips_lists)
        unactive_ips_lists: List[IpsListDto] = [list for list in ips_lists if list.attempts >= settings.attempts_limit]
        active_ips_lists: List[IpsListDto] = [list for list in ips_lists if list.attempts < settings.attempts_limit]
        # delete unactive ips lists
        if len(unactive_ips_lists) > 0:
          for list in unactive_ips_lists:
            await self.put_delete_ips_list_to_queue(id=list.id)
        # add ips
        if len(active_ips_lists) > 0:
          ips_add: List[IpsPostElementReq] = []
          withdrawals: list[tuple[int, list[int]]] = []
          for list in active_ips_lists:
            if list.found_elements == None:
              continue  # if hash not change in get_ips_from_lists - found_elements is None
            current_ips: List[IpRecordDto] = await self.get_all_ips_on_ips_list(ips_list_id=list.id)
            current_ips_list: List[str] = [ip.ip_address for ip in current_ips]
            [
              ips_add.append(IpsPostElementReq(addr=ip, list_id=list.id))
              for ip in list.found_elements
              if ip not in current_ips_list
            ]
            withdrawals.append(
              (list.id, [ip.id for ip in current_ips if ip.id is not None and ip.ip_address not in list.found_elements])
            )
          await self.put_add_ips_to_queue(ips=ips_add)
          for list_id, ids in withdrawals:
            await self.put_withdraw_ip_list_records_to_queue(list_id, ids)
          await self.update_ips_lists(ips_lists=active_ips_lists)
    except DatabaseWriteError:
      raise
    except Exception as err:
      logger.error(f'Try Lists load failed : {err}', exc_info=True)
      if db_session is not None:
        await db_session.rollback()
    finally:
      try:
        if db_session is not None:
          await db_session.close()
      finally:
        await job_registry.finish(Jobs.LISTS_LOAD)

  # Stats

  async def stats(self: Self) -> StatsResp:
    logger.debug(f'Try get all statistics ...')
    result: StatsResp = StatsResp(
      generated_at=datetime.now().strftime(DATE_FORMAT),
      dns=StatsDnsData(),
      domains=StatsDomainsData(),
      ips=StatsIpsData(),
      ros=StatsRosData(),
    )
    try:
      db_session: AsyncSession = await self.__read_connect()
      #
      dns_stats: Row[Tuple[int, int, int]] = await DnsServersDbo.get_stats(db_session=db_session)
      domains_stats: Row[Tuple[int, int, int, int, Any]] = await DomainsDbo.get_stats(db_session=db_session)
      ips_stats: Row[Tuple[int, int, int, int, int, int, Any]] = await IpRecordsDbo.get_stats(db_session=db_session)
      ros_stats: Row[Tuple[int]] = await RosConfigsDbo.get_stats(db_session=db_session)
      #
      result.dns = StatsDnsData(total=dns_stats.total, classic=dns_stats.classic, doh=dns_stats.doh)
      result.domains = StatsDomainsData(
        total=domains_stats.total,
        resolved=domains_stats.resolved,
        unresolved=domains_stats.unresolved,
        lists_total=domains_stats.lists_total,
        per_list=[StatsDomainsListItem(**item) for item in loads(domains_stats.per_list or '[]')],
      )
      result.ips = StatsIpsData(
        total=ips_stats.total,
        v4_total=ips_stats.v4_total,
        v6_total=ips_stats.v6_total,
        linked_to_domain=ips_stats.linked_to_domain,
        standalone=ips_stats.standalone,
        lists_total=ips_stats.lists_total,
        per_list=[StatsIpsListItem(**item) for item in loads(ips_stats.per_list or '[]')],
      )
      result.ros = StatsRosData(total=ros_stats.total)
      #
      return result
    except Exception as err:
      logger.error(f'Try get all statistics failed : {err}', exc_info=True)
      await db_session.rollback()
      return result
    finally:
      await db_session.close()

  async def stats_growth(
    self: Self,
    before_time: float,
    entity: GrowthEntity,
    granularity: GrowthGranularity,
    date_field: GrowthDateField,
    start_date: str | None = None,
    end_date: str | None = None,
    ip_subtype: int | None = None,
  ) -> StatsGrowthResp:
    logger.debug(f'Try get aggregated metrics ...')
    result: StatsGrowthResp = StatsGrowthResp(
      entity=entity,
      granularity=granularity,
      start_date=start_date,
      end_date=end_date,
      ip_subtype=ip_subtype,
      duration=monotonic() - before_time,
    )
    logger.debug(f'{entity=} {granularity=} {start_date=} {end_date=} {ip_subtype=}')
    try:
      db_session: AsyncSession = await self.__read_connect()
      if entity == GrowthEntity.DOMAINS:
        domains_stats_growth: Sequence[Row[Tuple[str, int]]] = await DomainsDbo.get_stats_growth(
          db_session=db_session,
          granularity=granularity,
          start_date=start_date,
          end_date=end_date,
          date_field=date_field,
        )
        result.payload = [StatsGrowthPoint(date=row[0], count=row[1]) for row in domains_stats_growth]
        result.total_in_period = sum(row[1] for row in domains_stats_growth)
        result.duration = monotonic() - before_time
      elif entity == GrowthEntity.LISTS:
        # ALL LISTS - DOMAINS AND IPS !!!
        all_lists_stats_growth: Sequence[Row[Tuple[str, int]]] = await DomainsListsDbo.get_stats_growth(
          db_session=db_session,
          granularity=granularity,
          start_date=start_date,
          end_date=end_date,
          date_field=date_field,
        )
        result.payload = [StatsGrowthPoint(date=row[0], count=row[1]) for row in all_lists_stats_growth]
        result.total_in_period = sum(row[1] for row in all_lists_stats_growth)
        result.duration = monotonic() - before_time
      elif entity == GrowthEntity.IPS:
        ips_stats_growth: Sequence[Row[Tuple[str, int]]] = await IpRecordsDbo.get_stats_growth(
          db_session=db_session,
          granularity=granularity,
          start_date=start_date,
          end_date=end_date,
          date_field=date_field,
        )
        result.payload = [StatsGrowthPoint(date=row[0], count=row[1]) for row in ips_stats_growth]
        result.total_in_period = sum(row[1] for row in ips_stats_growth)
        result.duration = monotonic() - before_time
      return result
    except Exception as err:
      logger.error(f'Try get aggregated metrics failed : {err}', exc_info=True)
      await db_session.rollback()
      return result
    finally:
      await db_session.close()

  #

  def __acknowledge_batch(self) -> None:
    self.__notify_batch(self.__pending_batch, 'confirmed', final=True)
    for _ in self.__pending_batch:
      self.db_save_queue.task_done()
    self.__pending_batch.clear()
    self.__unknown_count = 0
    if self.__writer_failure is not None:
      self.__writer_failure.committed = True
      self.__writer_failure.outcome_unknown = False
      self.__writer_failure.pending_count = self.pending_count
      self.__writer_failure.unknown_count = 0

  async def __commit_pending(self) -> None:
    observations = tuple(observation for item in self.__pending_batch for observation in item.observations)
    for item in self.__pending_batch:
      if not item.dwell_observed and item.dequeued_at is not None:
        observe_duration(writer_duration, item.dequeued_at, phase='batch_dwell', outcome='attempted')
        item.dwell_observed = True
    try:
      for attempt in range(3):
        if self.__writer_state == WriterState.FAILED:
          # Earlier retryable failures have already been rolled back and released.
          raise BatchWriteError('Database batch stopped before the next write attempt')
        try:
          await self.__batch_items_commit(self.__pending_batch)
          return
        except BatchWriteError as err:
          if not err.retryable or attempt == 2:
            raise
          retry_started = perf_counter()
          retry_outcome = 'complete'
          try:
            await sleep(0.1 * (attempt + 1))
          except CancelledError:
            retry_outcome = 'cancelled'
            raise
          finally:
            observe_duration(writer_duration, retry_started, phase='retry_wait', outcome=retry_outcome)
    except BatchWriteError as err:
      event = 'confirmed' if err.committed else 'final_unknown' if err.outcome_unknown else 'known_not_committed'
      self.__notify_batch(self.__pending_batch, event, final=True)
      raise
    except Exception, CancelledError:
      self.__notify_batch(self.__pending_batch, 'final_unknown', final=True)
      raise
    finally:
      summaries = persistence_summaries(observations)
      for key, summary in summaries.items():
        if key in self.__failure_summaries:
          self.__failure_summaries[key] = summary
      log_persistence_summaries(summaries)

  async def __flush_pending(self) -> None:
    if not self.__pending_batch:
      return
    self.__batch_task = create_task(self.__commit_pending(), name='database_batch')
    try:
      await shield(self.__batch_task)
    except CancelledError:
      # Native SQLite work may continue after cancellation of its awaiter.
      self.__unknown_count = len(self.__pending_batch)
      self.__fail_writer(
        WriterFailedError(
          'Database writer was cancelled',
          pending_count=self.pending_count,
          unknown_count=self.unknown_count,
          outcome_unknown=True,
        )
      )
      while not self.__batch_task.done():
        try:
          await shield(self.__batch_task)
        except CancelledError:
          pass
        except Exception:
          logger.error(
            'Database batch failed during writer cancellation',
            exc_info=DatabaseWriteError('Database batch failed during writer cancellation'),
          )
          break
      try:
        self.__batch_task.result()
      except DatabaseWriteError as err:
        if err.committed:
          self.__acknowledge_batch()
        elif not err.outcome_unknown:
          self.__unknown_count = 0
          if self.__writer_failure is not None:
            self.__writer_failure.outcome_unknown = False
            self.__writer_failure.unknown_count = 0
      except Exception, CancelledError:
        logger.error(
          'Database batch outcome could not be confirmed after cancellation',
          exc_info=DatabaseWriteError('Database batch outcome could not be confirmed after cancellation'),
        )
      else:
        self.__acknowledge_batch()
      raise
    except BatchWriteError as err:
      if err.committed:
        self.__acknowledge_batch()
      elif err.outcome_unknown:
        self.__unknown_count = len(self.__pending_batch)
      raise
    else:
      self.__acknowledge_batch()

  async def __task_process_commit_db_from_queue(self: Self) -> None:
    logger.info('Database writer started')
    deadline = 0.0
    try:
      while self.__writer_state != WriterState.FAILED:
        if self.__pending_batch and (
          len(self.__pending_batch) >= max(1, settings.db_save_batch_size) or monotonic() >= deadline
        ):
          await self.__flush_pending()
          deadline = 0.0
        try:
          if self.__pending_batch:
            queue_element = await wait_for(self.db_save_queue.get(), timeout=max(0.0, deadline - monotonic()))
          else:
            queue_element = await self.db_save_queue.get()
        except TimeoutError:
          await self.__flush_pending()
          deadline = 0.0
          continue
        except QueueShutDown:
          await self.__flush_pending()
          break
        queue_element.dequeued_at = perf_counter()
        if queue_element.admitted_at is not None:
          observe_duration(
            queue_duration, queue_element.admitted_at, queue='writer', phase='residence', outcome='dequeued'
          )
          queue_element.admitted_at = None
        self.__pending_batch.append(queue_element)
        if len(self.__pending_batch) == 1:
          deadline = monotonic() + settings.db_save_batch_timeout
    except CancelledError:
      self.__fail_writer(
        WriterFailedError(
          'Database writer was cancelled',
          pending_count=self.pending_count,
          unknown_count=self.unknown_count,
          outcome_unknown=bool(self.unknown_count),
        )
      )
      raise
    except DatabaseWriteError as err:
      self.__fail_writer(
        WriterFailedError(
          'Database batch persistence failed',
          pending_count=self.pending_count,
          unknown_count=self.unknown_count,
          outcome_unknown=bool(self.unknown_count),
          committed=err.committed,
        )
      )
    except Exception:
      failure = WriterFailedError(
        'Database writer failed unexpectedly',
        pending_count=self.pending_count,
        unknown_count=self.unknown_count,
        outcome_unknown=bool(self.unknown_count),
      )
      logger.error('Database writer failed unexpectedly', exc_info=failure)
      self.__fail_writer(failure)
    finally:
      if self.__writer_state != WriterState.FAILED:
        self.__writer_state = WriterState.STOPPED
      log_persistence_summaries(self.__failure_summaries)
      self.__failure_summaries.clear()
      logger.info('Database writer stopped')

  async def __add_explicit_ips(self, session: AsyncSession, items: list[dict[str, Any]]) -> None:
    """Create explicit records while preserving supported duplicate semantics."""
    for item in items:
      if item['domain_id'] is None:
        continue
      current = (
        await session.execute(select(IpRecordsDbo.id).where(IpRecordsDbo.ip_address == item['ip_address']))
      ).scalar_one_or_none()
      if current is not None:
        supported = (
          await session.execute(select(IpSupportDbo.id).where(IpSupportDbo.ip_record_id == current).limit(1))
        ).first()
        if supported is not None:
          continue
      # Validate context before replacing a transient orphan. Domain 0 is real.
      if not (await session.execute(select(DomainsDbo.id).where(DomainsDbo.id == item['domain_id']))).first():
        raise DatabaseWriteError('Explicit IP domain is unavailable')
      if (
        item['ip_list_id'] is not None
        and not (await session.execute(select(IpsListsDbo.id).where(IpsListsDbo.id == item['ip_list_id']))).first()
      ):
        raise DatabaseWriteError('Explicit IP list is unavailable')
      if current is not None:
        await session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.id == current))
      created = (
        await session.execute(insert(IpRecordsDbo).values(**item).prefix_with('OR IGNORE').returning(IpRecordsDbo.id))
      ).scalar_one_or_none()
      if created is not None:
        await session.execute(
          insert(IpSupportDbo).values(ip_record_id=created, domain_id=item['domain_id'], ip_list_id=item['ip_list_id'])
        )

  async def __reconcile_domain(self, session: AsyncSession, intent: DomainResolutionIntent) -> None:
    """Apply a complete prepared set or additive partial evidence in writer order."""
    if intent.id <= 0 or not (await session.execute(select(DomainsDbo.id).where(DomainsDbo.id == intent.id))).first():
      raise DatabaseWriteError('Resolved domain is unavailable')
    addresses = tuple(dict.fromkeys(intent.storage_ips))
    for address in addresses:
      addr_type = get_ip_version(address)
      if addr_type != 4:
        raise DatabaseWriteError('Resolved storage payload must contain IPv4 addresses')
      await session.execute(
        insert(IpRecordsDbo)
        .values(ip_address=address, domain_id=intent.id, addr_type=addr_type)
        .prefix_with('OR IGNORE')
      )
      ip_id = (await session.execute(select(IpRecordsDbo.id).where(IpRecordsDbo.ip_address == address))).scalar_one()
      await session.execute(
        insert(IpSupportDbo).values(ip_record_id=ip_id, domain_id=intent.id, ip_list_id=None).prefix_with('OR IGNORE')
      )
    if intent.resolution_complete:
      obsolete = select(IpRecordsDbo.id).where(IpRecordsDbo.addr_type == 4)
      if addresses:
        obsolete = obsolete.where(IpRecordsDbo.ip_address.not_in(addresses))
      await session.execute(
        delete(IpSupportDbo).where(IpSupportDbo.domain_id == intent.id, IpSupportDbo.ip_record_id.in_(obsolete))
      )

  async def __finish_ip_supports(self, session: AsyncSession) -> None:
    """Delete final orphans and repair only vanished incumbent projections."""
    has_support = exists().where(IpSupportDbo.ip_record_id == IpRecordsDbo.id)
    await session.execute(delete(IpRecordsDbo).where(~has_support))
    incumbent = exists().where(
      IpSupportDbo.ip_record_id == IpRecordsDbo.id,
      IpSupportDbo.domain_id == IpRecordsDbo.domain_id,
      IpSupportDbo.ip_list_id.is_not_distinct_from(IpRecordsDbo.ip_list_id),
    )
    representative = (
      select(IpSupportDbo.domain_id, IpSupportDbo.ip_list_id)
      .where(IpSupportDbo.ip_record_id == IpRecordsDbo.id)
      .order_by(IpSupportDbo.domain_id, IpSupportDbo.ip_list_id.is_not(None), IpSupportDbo.ip_list_id)
      .limit(1)
      .correlate(IpRecordsDbo)
    )
    await session.execute(
      update(IpRecordsDbo)
      .where(~incumbent)
      .values(
        domain_id=representative.with_only_columns(IpSupportDbo.domain_id).scalar_subquery(),
        ip_list_id=representative.with_only_columns(IpSupportDbo.ip_list_id).scalar_subquery(),
        updated_at=IpRecordsDbo.updated_at,
      )
    )

  async def __batch_items_commit(self: Self, queue_elements: List[QueueElementDto]) -> None:
    """Persist one atomic batch and translate all persistence failures."""
    logger.debug(f'Try prepare elements count={len(queue_elements)} ...')
    attempt_started = perf_counter()
    transaction_started: float | None = None
    transaction_outcome = 'failure'
    db_session: AsyncSession | None = None
    commit_started = False
    committed = False
    failure: Exception | CancelledError | None = None
    rollback_ok = True
    release_ok = True
    try:
      # Prepare elements
      # DNS SERVERS
      dns_servers_add: List[Dict[str, str | None]] = [
        {
          DnsServersDbo.server.property.key: item.server,
          DnsServersDbo.doh_server.property.key: item.doh_server,
          DnsServersDbo.description.property.key: item.description,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DNS_SERVERS_ADD
        for item in queue_element.elements
      ]
      dns_servers_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DNS_SERVERS_DELETE
        for item in queue_element.elements
      ]
      dns_servers_delete_all: list[QueueElementDto] = [
        queue_element for queue_element in queue_elements if queue_element.target == TargetAction.DNS_SERVERS_DELETE_ALL
      ]
      # DOMAINS LISTS
      domains_lists_add: List[Dict[str, str | None]] = [
        {
          DomainsListsDbo.name.property.key: item.name,
          DomainsListsDbo.url.property.key: item.url,
          DomainsListsDbo.description.property.key: item.description,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_LISTS_ADD
        for item in queue_element.elements
      ]
      domains_lists_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_LISTS_DELETE
        for item in queue_element.elements
      ]
      domains_lists_delete_all: list[QueueElementDto] = [
        queue_element
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_LISTS_DELETE_ALL
      ]
      domains_lists_update: List[Dict[str, str | int | None]] = [
        {
          DomainsListsDbo.id.property.key: item.id,
          DomainsListsDbo.name.property.key: item.name,
          DomainsListsDbo.url.property.key: item.url,
          DomainsListsDbo.description.property.key: item.description,
          DomainsListsDbo.hash.property.key: item.hash,
          DomainsListsDbo.attempts.property.key: item.attempts,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_LISTS_UPDATE
        for item in queue_element.elements
      ]
      # DOMAINS
      domains_add: List[Dict[str, str | None]] = [
        {
          DomainsDbo.name.property.key: item.domain,
          DomainsDbo.domain_list_id.property.key: item.list_id,
          DomainsDbo.ros_comment.property.key: item.ros_comment,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_ADD
        for item in queue_element.elements
      ]
      domains_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_DELETE
        for item in queue_element.elements
      ]
      domains_delete_all: list[QueueElementDto] = [
        queue_element for queue_element in queue_elements if queue_element.target == TargetAction.DOMAINS_DELETE_ALL
      ]
      domains_resolved_update: List[Dict[str, int | bool | datetime]] = [
        {
          DomainsDbo.id.property.key: domain.id,
          DomainsDbo.resolved.property.key: True,
          DomainsDbo.last_resolved_at.property.key: datetime.now(timezone.utc),
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_RESOLVED
        for domain in queue_element.elements  # item = DomainResult
        if domain.resolution_complete
      ]
      # IPS LISTS
      ips_lists_add: List[Dict[str, str | None]] = [
        {
          IpsListsDbo.name.property.key: item.name,
          IpsListsDbo.url.property.key: item.url,
          IpsListsDbo.description.property.key: item.description,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_LISTS_ADD
        for item in queue_element.elements
      ]
      ips_lists_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_LISTS_DELETE
        for item in queue_element.elements
      ]
      ips_lists_delete_all: list[QueueElementDto] = [
        queue_element for queue_element in queue_elements if queue_element.target == TargetAction.IPS_LISTS_DELETE_ALL
      ]
      ips_lists_update: List[Dict[str, str | int | None]] = [
        {
          IpsListsDbo.id.property.key: item.id,
          IpsListsDbo.name.property.key: item.name,
          IpsListsDbo.url.property.key: item.url,
          IpsListsDbo.description.property.key: item.description,
          IpsListsDbo.hash.property.key: item.hash,
          IpsListsDbo.attempts.property.key: item.attempts,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_LISTS_UPDATE
        for item in queue_element.elements
      ]
      # IPS
      ips_add: List[Dict[str, str | int]] = [
        {
          IpRecordsDbo.ip_address.property.key: item.addr,
          IpRecordsDbo.ip_list_id.property.key: item.list_id,
          IpRecordsDbo.domain_id.property.key: item.domain_id,
          IpRecordsDbo.addr_type.property.key: get_ip_version(item.addr),
          IpRecordsDbo.ros_comment.property.key: item.ros_comment,
          IpRecordsDbo.use_default_gw.property.key: item.use_default_gw,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_ADD
        for item in queue_element.elements  # item = IpsPostElementReq
      ]
      resolution_intents: list[DomainResolutionIntent] = [
        intent
        for element in queue_elements
        if element.target == TargetAction.DOMAINS_RESOLVED
        for intent in element.elements
      ]
      list_withdrawals: list[IpListWithdrawal] = [
        withdrawal
        for element in queue_elements
        if element.target == TargetAction.IPS_LIST_WITHDRAW
        for withdrawal in element.elements
      ]
      ips_id_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_DELETE_ID
        for item in queue_element.elements
      ]
      ips_addr_delete: List[str] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_DELETE_ADDR
        for item in queue_element.elements
      ]
      ips_delete_all: list[QueueElementDto] = [
        queue_element for queue_element in queue_elements if queue_element.target == TargetAction.IPS_DELETE_ALL
      ]
      # ROS CONFIGS
      ros_configs_add: List[Dict[str, str | None]] = [
        {
          RosConfigsDbo.host.property.key: item.host,
          RosConfigsDbo.user.property.key: item.user,
          RosConfigsDbo.passwd.property.key: item.user_password,
          RosConfigsDbo.bgp_list_name.property.key: item.bgp_list_name,
          RosConfigsDbo.description.property.key: item.description,
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.ROS_CONFIG_ADD
        for item in queue_element.elements  # item = RosConfigsPostElementReq
      ]
      ros_configs_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.ROS_CONFIG_DELETE
        for item in queue_element.elements
      ]
      ros_configs_delete_all: list[QueueElementDto] = [
        queue_element for queue_element in queue_elements if queue_element.target == TargetAction.ROS_CONFIG_DELETE_ALL
      ]
      #
      #
      db_session = await self.__write_connect()
      # Connection setup precedes the timed explicit write transaction.
      await db_session.connection()
      # Recording with immediate write lock
      transaction_started = perf_counter()
      await db_session.execute(text('BEGIN IMMEDIATE'))
      # DNS SERVERS
      if len(dns_servers_add) > 0:
        await DnsServersDbo.add_batch(db_session=db_session, items=dns_servers_add)
      if len(dns_servers_delete) > 0:
        await db_session.execute(delete(DnsServersDbo).where(DnsServersDbo.id.in_(dns_servers_delete)))
      if len(dns_servers_delete_all) > 0:
        await db_session.execute(delete(DnsServersDbo).where(DnsServersDbo.id > 0))
      # DOMAINS LISTS
      if len(domains_lists_add) > 0:
        await DomainsListsDbo.add_batch(db_session=db_session, items=domains_lists_add)
      if len(domains_lists_delete) > 0:  # ATTEMPTS
        await db_session.execute(delete(DomainsListsDbo).where(DomainsListsDbo.id.in_(domains_lists_delete)))
      if len(domains_lists_delete_all) > 0:
        await db_session.execute(delete(DomainsListsDbo).where(DomainsListsDbo.id > 0))
      if len(domains_lists_update) > 0:
        await db_session.execute(update(DomainsListsDbo), domains_lists_update)
      # IPS LISTS
      if len(ips_lists_add) > 0:
        await IpsListsDbo.add_batch(db_session=db_session, items=ips_lists_add)
      if len(ips_lists_delete) > 0:  # ATTEMPTS
        await db_session.execute(delete(IpsListsDbo).where(IpsListsDbo.id.in_(ips_lists_delete)))
      if len(ips_lists_delete_all) > 0:
        await db_session.execute(delete(IpsListsDbo).where(IpsListsDbo.id > 0))
      if len(ips_lists_update) > 0:
        await db_session.execute(update(IpsListsDbo), ips_lists_update)
      # IPS
      if ips_add:
        await self.__add_explicit_ips(db_session, ips_add)
      for intent in resolution_intents:
        await self.__reconcile_domain(db_session, intent)
      for withdrawal in list_withdrawals:
        await db_session.execute(
          delete(IpSupportDbo).where(
            IpSupportDbo.ip_list_id == withdrawal.list_id,
            IpSupportDbo.ip_record_id.in_(withdrawal.ip_record_ids),
          )
        )
      if len(ips_id_delete) > 0:
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.id.in_(ips_id_delete)))
      if len(ips_addr_delete) > 0:
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.ip_address.in_(ips_addr_delete)))
      if len(ips_delete_all) > 0:
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.id > 0))
      # DOMAINS (after ips processing)
      if len(domains_add) > 0:
        await DomainsDbo.add_batch(db_session=db_session, items=domains_add)
      if len(domains_delete) > 0:
        await db_session.execute(delete(DomainsDbo).where(DomainsDbo.id.in_(domains_delete)))
      if len(domains_delete_all) > 0:
        await db_session.execute(delete(DomainsDbo).where(DomainsDbo.id > 0))
      if len(domains_resolved_update) > 0:
        await db_session.execute(update(DomainsDbo), domains_resolved_update)
      # ROS CONFIGS
      if len(ros_configs_add) > 0:
        await RosConfigsDbo.add_batch(db_session=db_session, items=ros_configs_add)
      if len(ros_configs_delete) > 0:
        await db_session.execute(delete(RosConfigsDbo).where(RosConfigsDbo.id.in_(ros_configs_delete)))
      if len(ros_configs_delete_all) > 0:
        await db_session.execute(delete(RosConfigsDbo).where(RosConfigsDbo.id > 0))
      #
      await self.__finish_ip_supports(db_session)
      # Any failure from commit itself has an ambiguous physical outcome.
      commit_started = True
      commit_timer = perf_counter()
      commit_outcome = 'unknown'
      try:
        await db_session.commit()
        committed = True
        commit_outcome = 'confirmed'
      finally:
        observe_duration(writer_duration, commit_timer, phase='commit', outcome=commit_outcome)
      transaction_outcome = 'confirmed'
      observe_duration(writer_duration, transaction_started, phase='transaction', outcome=transaction_outcome)
      transaction_started = None
      self.__notify_batch(queue_elements, 'confirmed', final=True)
    except (Exception, CancelledError) as err:
      failure = err
      if transaction_started is not None:
        transaction_outcome = (
          'unknown' if commit_started else 'cancelled' if isinstance(err, CancelledError) else 'failure'
        )
        observe_duration(writer_duration, transaction_started, phase='transaction', outcome=transaction_outcome)
        transaction_started = None
      if db_session is not None:
        rollback_started = perf_counter()
        try:
          await db_session.rollback()
        except Exception, CancelledError:
          rollback_ok = False
          logger.error(
            'Database batch rollback failed',
            exc_info=DatabaseWriteError('Database batch rollback failed'),
          )
        finally:
          observe_duration(
            writer_duration, rollback_started, phase='rollback', outcome='complete' if rollback_ok else 'failure'
          )
    finally:
      if db_session is not None:
        cleanup_started = perf_counter()
        try:
          await db_session.close()
        except (Exception, CancelledError) as err:
          release_ok = False
          self.__session_cleanup_failed = True
          if failure is None:
            failure = err
          logger.error(
            'Database batch session cleanup failed',
            exc_info=DatabaseWriteError('Database batch session cleanup failed'),
          )
        finally:
          observe_duration(
            writer_duration, cleanup_started, phase='cleanup', outcome='complete' if release_ok else 'failure'
          )
      observe_duration(
        writer_duration,
        attempt_started,
        phase='attempt',
        outcome=(
          'confirmed'
          if committed
          else 'unknown'
          if commit_started
          else 'failure'
          if failure is not None
          else 'complete'
        ),
      )
    if failure is not None:
      # SQLite extended result codes retain the primary code in the low byte.
      original = getattr(failure, 'orig', failure)
      while isinstance(original, DatabaseConfigurationError) and original.__cause__ is not None:
        original = original.__cause__
      sqlite_code = getattr(original, 'sqlite_errorcode', None)
      retryable = (
        not commit_started
        and rollback_ok
        and release_ok
        and isinstance(original, SQLiteError)
        and isinstance(sqlite_code, int)
        and sqlite_code & 0xFF in (SQLITE_BUSY, SQLITE_LOCKED)
        and not isinstance(failure, CancelledError)
      )
      raise BatchWriteError(
        'Database batch cleanup failed after commit' if committed else 'Database batch could not be committed',
        retryable=retryable,
        committed=committed,
        outcome_unknown=commit_started and not committed,
      ) from failure


# Init DataBase
try:
  db: DataBase = DataBase()
except Exception as err:
  raise err
