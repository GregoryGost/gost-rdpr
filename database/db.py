import logging
from asyncio import (
  sleep,
  wait_for,
  create_task,
  Queue,
  QueueFull,
  TimeoutError,
  CancelledError
)
from sqlalchemy import (
  __version__ as sqlalchemy_version,
  func,
  text,
  insert,
  delete,
  update,
  Result,
  Row
)
from aiosqlite import __version__ as aiosqlite_version
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, async_sessionmaker, AsyncSession, AsyncConnection
from sqlalchemy.pool import AsyncAdaptedQueuePool
from datetime import datetime, timezone
from time import monotonic
from threading import Event
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec
from importlib.machinery import ModuleSpec
from typing import Self, Tuple, Optional, Dict, List, Sequence
from types import ModuleType

from config.config import settings
from logger.logger import logger, Logger
from client.file_loader_client import FileLoaderClient

from utils.utils import get_ip_version, calculate_checksum

from models.db.dns_servers_dbo import DnsServersDbo
from models.db.domains_lists_dbo import DomainsListsDbo
from models.db.ips_lists_dbo import IpsListsDbo
from models.db.domains_dbo import DomainsDbo
from models.db.ip_records_dbo import IpRecordsDbo
from models.db.ros_configs_dbo import RosConfigsDbo
from models.db.migrations_dbo import MigrationsDbo

from models.http.dns_servers_req import DnsPostElementReq
from models.http.dns_servers_resp import DnsPayloadResp, DnsElementResp
#
from models.http.domains_lists_req import DomainsListsPostElementReq
from models.http.domains_lists_resp import DomainsListsPayloadResp, DomainsListElementResp
from models.dto.domains_lists_dto import DomainsListDto
#
from models.http.domains_req import DomainsPostElementReq
from models.http.domains_resp import DomainsPayloadResp, DomainElementResp
#
from models.http.ips_lists_req import IpsListsPostElementReq
from models.http.ips_lists_resp import IpsListsPayloadResp, IpsListElementResp
from models.dto.ips_lists_dto import IpsListDto
#
from models.http.ips_req import IpsPostElementReq
from models.http.ips_resp import IpsPayloadResp, IpsElementResp
#
from models.http.ros_configs_req import RosConfigsPostElementReq
from models.http.ros_configs_resp import RosConfigPayloadResp, RosConfigElementResp

from models.dto.queue_dto import QueueElementDto, TargetAction
from models.dto.domains_dto import DomainResult
from models.dto.dns_server_dto import DnsServerType, DnsServerDto
from models.dto.ip_record_dto import IpRecordDto
from models.dto.ros_config_dto import RosConfigDto
from models.dto.migrations_dto import MigrationsDto

from cache.cache import jobs_cache, Jobs

class DataBase:
  '''
  Bulk ORM DELETE not supported right now  
  https://docs.sqlalchemy.org/en/20/orm/queryguide/dml.html#orm-queryguide-update-delete-where
  '''

  __state: bool = False
  __engine: AsyncEngine
  __session_factory: async_sessionmaker[AsyncSession]
  __stop_db_save_event: Event = Event()
  __queue_sleep_timeout: float = settings.queue_sleep_timeout
  __queue_get_timeout: float = settings.queue_get_timeout
  __task_exception_error_timeout: float = 10.0
  __migrations_path: Path = Path('migrations')

  db_save_queue: Queue = Queue(maxsize=settings.queue_max_size)

  def __init__(self: Self) -> None:
    logging.getLogger('sqlalchemy.engine').setLevel(Logger.LOGGER_LEVEL[settings.db_log_level])
    logging.getLogger('sqlalchemy.pool').setLevel(Logger.LOGGER_LEVEL[settings.db_log_level])
    #
    logger.debug(f'SQLAlchemy version="{sqlalchemy_version}"')
    logger.debug(f'aiosqlite version="{aiosqlite_version}"')
    logger.debug(f'db_connection="{settings.db_connection}"')
    self.__migrations_path.mkdir(exist_ok=True)
    self.__engine: AsyncEngine = create_async_engine(
      url=settings.db_connection,
      pool_timeout=settings.db_timeout,
      pool_size=settings.db_pool_size,
      max_overflow=settings.db_pool_size_overflow,
      pool_recycle=settings.db_pool_recycle_sec,
      pool_pre_ping=True,
      poolclass=AsyncAdaptedQueuePool
    )
    self.__engine.dialect.identifier_preparer.initial_quote = ''
    self.__engine.dialect.identifier_preparer.final_quote = ''
    self.__session_factory = async_sessionmaker(
      bind=self.__engine,
      expire_on_commit=False
    )
    self.file_loader_client: FileLoaderClient = FileLoaderClient()
    logger.debug(f'{self.__class__.__name__} init ...')

  @property
  def db_session(self: Self) -> async_sessionmaker[AsyncSession]:
    return self.__session_factory
  
  @property
  def pool_status(self: Self) -> str:
    return self.__engine.pool.status()
  
  #

  async def __create_tables(self: Self) -> None:
    logger.debug('Try create all tables ...')
    async with self.__engine.begin() as conn:
      try:
        await conn.run_sync(MigrationsDbo.metadata.create_all)
        await conn.run_sync(DnsServersDbo.metadata.create_all)
        await conn.execute(
          insert(DnsServersDbo).prefix_with('OR IGNORE').values(
            id=0,
            server='1.1.1.1',
            description='Cloudflare DNS - Default'
          )
        )
        await conn.run_sync(DomainsListsDbo.metadata.create_all)
        await conn.run_sync(IpsListsDbo.metadata.create_all)
        await conn.run_sync(DomainsDbo.metadata.create_all)
        await conn.execute(
          insert(DomainsDbo).prefix_with('OR IGNORE').values(
            id=0,
            resolved=True,
            name='default',
            ros_comment='Default Domain',
            last_resolved_at=func.now()
          )
        )
        await conn.run_sync(IpRecordsDbo.metadata.create_all)
        await conn.run_sync(RosConfigsDbo.metadata.create_all)
        # Run migrations
        await self.__main_migrations(conn=conn)
        await conn.commit()
      except Exception as err:
        logger.error(f'Try create all tables failed : {err}')
        await conn.rollback()
      finally:
        await conn.close()

  async def __connect(self: Self) -> AsyncSession:
    if self.__state == False: raise Exception('Database not ready to work')
    async with self.db_session() as session:
      try:
        await session.execute(text('PRAGMA foreign_keys=ON'))
        return session
      except Exception as err:
        await session.rollback()
        logger.error(f'Try DB connect failed : {settings.db_path} : {err}')
        raise err
      finally:
        await session.close()

  async def setup(self: Self) -> None:
    '''
    Table creates automatically
    '''
    logger.debug(f'Try SQLite setup on db link: {settings.db_connection}')
    try:
      await self.__create_tables()
      self.__state = True
      db_session: AsyncSession = await self.__connect()
      result: Result = await db_session.execute(text('SELECT sqlite_version() AS version'))
      logger.info(f'SQLite version="{str(result.scalar())}"')
      logger.debug(f'SQLite pool_status="{self.pool_status}"')
      #
      logger.debug('Start tasks flows for DataBase')
      # ONE FLOW FOR SAVE TO DB
      self.__stop_db_save_event.clear()
      create_task(
        coro=self.__task_process_commit_db_from_queue(),
        name='task_save_to_db_queue'
      )
      #
      logger.debug('Setup DataBase - OK')
    except Exception as err:
      logger.error(f'Try DB setup failed at {settings.db_connection} : {err}')
      await db_session.rollback()
      raise err
    finally:
      await db_session.close()

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
    
  async def __get_all_applied_migrations(self: Self, conn: AsyncConnection) -> List[MigrationsDto]:
    logger.debug(f'Try get applied migrations ...')
    applied_migrations: List[MigrationsDto] = []
    try:
      migrations: Sequence[Row[Tuple[int, str, str, datetime]]] = await MigrationsDbo.get_all(conn=conn)
      applied_migrations = [
        MigrationsDto(id=migration[0], name=migration[1], checksum=migration[2], applied_at=migration[3])
        for migration in migrations
      ]
      return applied_migrations
    except Exception as err:
      logger.error(f'Try get applied migrations failed : {err}', exc_info=True)
      await conn.rollback()
      return applied_migrations

  async def __run_migration(self: Self, migration_file: Path, conn: AsyncConnection) -> bool:
    logger.debug(f'Run migration "{migration_file.name}" ...')
    try:
      spec: ModuleSpec | None = spec_from_file_location(name=migration_file.stem, location=migration_file)
      if spec != None:
        migration_module: ModuleType = module_from_spec(spec=spec)
        if spec.loader != None:
          spec.loader.exec_module(module=migration_module)
          if hasattr(migration_module, 'upgrade'):
            await migration_module.upgrade(conn=conn)
          if hasattr(migration_module, 'downgrade'):
            await migration_module.downgrade(conn=conn)
      return True
    except Exception as err:
      logger.error(f'Try run migration "{migration_file.name}" failed : {err}', exc_info=True)
      return False

  async def __main_migrations(self: Self, conn: AsyncConnection) -> None:
    logger.debug(f'Start migrations ...')
    try:
      # get applied migrations
      applied_migrations: List[MigrationsDto] = await self.__get_all_applied_migrations(conn=conn)
      # get migrations files
      migration_files: List[Path] = await self.__get_migrations_files()
      # filter migrations
      target_migrations: List[Path] = [
        migration
        for migration in migration_files
        if migration.name not in [migration.name for migration in applied_migrations if migration.applied_at != None]
      ]
      for migration in target_migrations:
        migration_state: bool = await self.__run_migration(migration_file=migration, conn=conn)
        if migration_state == True:
          await conn.execute(insert(MigrationsDbo).prefix_with('OR IGNORE').values(
            name=migration.name,
            checksum=calculate_checksum(file_path=migration),
            applied_at=datetime.now(timezone.utc)
          ))
        if migration_state == False:
          await conn.execute(insert(MigrationsDbo).prefix_with('OR IGNORE').values(
            name=migration.name,
            checksum=calculate_checksum(file_path=migration)
          ))
    except Exception as err:
      logger.error(f'Migrations failed : {err}', exc_info=True)

  # DNS servers

  async def get_all_dns_servers(
      self: Self,
      before_time: float,
      limit: int,
      offset: int,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      default: Optional[bool] = None,
      search_text: Optional[str] = None
  ) -> DnsPayloadResp:
    logger.debug(f'Try get all DNS servers ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {default=}, {search_text=}')
    payload: List[DnsElementResp] = []
    try:
      db_session: AsyncSession = await self.__connect()
      #
      total: int = await DnsServersDbo.get_total(db_session=db_session)
      if total > 0:
        dns_servers: Sequence[Row[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]]] = \
          await DnsServersDbo.get_all(
            db_session=db_session,
            limit=limit,
            offset=offset,
            start_date=start_date,
            end_date=end_date,
            default=default,
            search_text=search_text
          )
        #
        for server in dns_servers:
          payload.append(DnsElementResp(
            id=server[0],
            server=server[1],
            doh_server=server[2],
            description=server[3],
            created_at=server[4].timestamp(),
            created_at_hum=server[4].strftime('%Y-%m-%d %H:%M:%S'),
            updated_at=None if server[5] == None else server[5].timestamp(),
            updated_at_hum=None if server[5] == None else server[5].strftime('%Y-%m-%d %H:%M:%S')
          ))
      return DnsPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all DNS servers failed : {err}', exc_info=True)
      await db_session.rollback()
      return DnsPayloadResp(
        limit=limit,
        offset=offset,
        total=0,
        count=0,
        duration=monotonic() - before_time,
        payload=payload
      )
    finally:
      await db_session.close()

  async def get_dns_server_on_id(self: Self, id: int) -> DnsElementResp | None:
    logger.debug(f'Try get DNS server on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__connect()
      dns_server: Row[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] | None = \
        await DnsServersDbo.get_on_id(db_session=db_session, id=id)
      if dns_server != None:
        return DnsElementResp(
          id=dns_server[0],
          server=dns_server[1],
          doh_server=dns_server[2],
          description=dns_server[3],
          created_at=dns_server[4].timestamp(),
          created_at_hum=dns_server[4].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if dns_server[5] == None else dns_server[5].timestamp(),
          updated_at_hum=None if dns_server[5] == None else dns_server[5].strftime('%Y-%m-%d %H:%M:%S')
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
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      dns_server_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DNS_SERVERS_ADD,
        elements=dns_servers
      )
      logger.debug(f'Put dns servers element {dns_server_element=} to Queue')
      self.db_save_queue.put_nowait(item=dns_server_element)
    except QueueFull:
      logger.error(f'Queue is full for try send DNS servers {dns_servers=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send DNS servers to Queue : {err}', exc_info=True)

  async def put_delete_dns_servers_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted DNS servers to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      if id != None:
        logger.debug(f'Once DNS server delete {id=}')
        dns_server_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DNS_SERVERS_DELETE,
          elements=[id]
        )
      else:
        dns_server_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DNS_SERVERS_DELETE_ALL,
          elements=[]
        )
      logger.debug(f'Put delete dns servers element {dns_server_element=} to Queue')
      self.db_save_queue.put_nowait(item=dns_server_element)
    except QueueFull:
      logger.error(f'Queue is full for try send deleted DNS servers to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted DNS servers to Queue : {err}', exc_info=True)

  async def get_dns_servers_for_resolve(self: Self) -> Tuple[List[DnsServerDto], List[DnsServerDto]]:
    logger.debug(f'Try get DNS servers for resolve ...')
    dns_servers: Tuple[List[DnsServerDto], List[DnsServerDto]] = ([], [])
    try:
      db_session: AsyncSession = await self.__connect()
      # get dns servers for resolve
      dns_servers_for_resolve: Sequence[Row[Tuple[str | None, str | None, DnsServerType]]] = await DnsServersDbo.get_all_for_resolve(db_session=db_session)
      dns_servers_default: List[DnsServerDto] = [DnsServerDto(server=dns_server[0]) for dns_server in dns_servers_for_resolve if dns_server[2] == DnsServerType.DEFAULT]
      dns_servers_doh: List[DnsServerDto] = [DnsServerDto(server=dns_server[1]) for dns_server in dns_servers_for_resolve if dns_server[2] == DnsServerType.DOH]
      logger.debug(f'DNS servers for resolve: {dns_servers_default=}, {dns_servers_doh=}')
      dns_servers = (dns_servers_default, dns_servers_doh)
      return dns_servers
    except Exception as err:
      logger.error(f'Try get Domains for resolve failed : {err}', exc_info=True)
      await db_session.rollback()
      return dns_servers
    finally:
      await db_session.close()

  # Domains Lists

  async def get_all_domains_lists(
      self: Self,
      before_time: float,
      limit: int,
      offset: int,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      search_text: Optional[str] = None,
      attempts: Optional[int] = None
  ) -> DomainsListsPayloadResp:
    logger.debug(f'Try get all Domains lists ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[DomainsListElementResp] = []
    try:
      db_session: AsyncSession = await self.__connect()
      total: int = await DomainsListsDbo.get_total(db_session=db_session)
      if total > 0:
        domains_lists: Sequence[Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]]] = \
          await DomainsListsDbo.get_all(
            db_session=db_session,
            limit=limit,
            offset=offset,
            start_date=start_date,
            end_date=end_date,
            search_text=search_text,
            attempts=attempts
          )
        #
        for list in domains_lists:
          elements_count: int = await DomainsDbo.get_total_on_domains_list(
            db_session=db_session,
            domains_list_id=list[0]
          )
          payload.append(DomainsListElementResp(
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
            updated_at_hum=None if list[7] == None else list[7].strftime('%Y-%m-%d %H:%M:%S')
          ))
      return DomainsListsPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all Domains lists failed : {err}', exc_info=True)
      await db_session.rollback()
      return DomainsListsPayloadResp(
        limit=limit,
        offset=offset,
        total=0,
        count=0,
        duration=monotonic() - before_time,
        payload=payload
      )
    finally:
      await db_session.close()

  async def get_domains_list_on_id(self: Self, id: int) -> DomainsListElementResp | None:
    logger.debug(f'Try get Domains list on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__connect()
      domains_list: Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] | None = \
        await DomainsListsDbo.get_on_id(db_session=db_session, id=id)
      if domains_list != None:
        elements_count: int = await DomainsDbo.get_total_on_domains_list(
          db_session=db_session,
          domains_list_id=id
        )
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
          updated_at_hum=None if domains_list[7] == None else domains_list[7].strftime('%Y-%m-%d %H:%M:%S')
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
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      domains_lists_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DOMAINS_LISTS_ADD,
        elements=domains_lists
      )
      logger.debug(f'Put domains lists element {domains_lists_element=} to Queue')
      self.db_save_queue.put_nowait(item=domains_lists_element)
    except QueueFull:
      logger.error(f'Queue is full for try send domains lists {domains_lists=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send domains lists to Queue : {err}', exc_info=True)

  async def put_delete_domains_list_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Domains list to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      if id != None:
        logger.debug(f'One Domains list delete {id=}')
        domains_list_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_LISTS_DELETE,
          elements=[id]
        )
      else:
        domains_list_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_LISTS_DELETE_ALL,
          elements=[]
        )
      logger.debug(f'Put delete domains list element {domains_list_element=} to Queue')
      self.db_save_queue.put_nowait(item=domains_list_element)
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Domains list to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Domains list to Queue : {err}', exc_info=True)

  async def update_domains_lists(self: Self, domains_lists: List[DomainsListDto]) -> None:
    logger.debug(f'Try send update Domains lists to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      logger.debug(f'One Domains lists update {domains_lists=}')
      domains_list_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DOMAINS_LISTS_UPDATE,
        elements=domains_lists
      )
      logger.debug(f'Put update domains lists element {domains_list_element=} to Queue')
      self.db_save_queue.put_nowait(item=domains_list_element)
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
    search_text: Optional[str] = None
  ) -> DomainsPayloadResp:
    logger.debug(f'Try get all Domains ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[DomainElementResp] = []
    try:
      db_session: AsyncSession = await self.__connect()
      total: int = await DomainsDbo.get_total(db_session=db_session)
      resolved_count: int = await DomainsDbo.get_total_resolved(db_session=db_session)
      if total > 0:
        domains: Sequence[Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]]] = \
        await DomainsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          resolved=resolved,
          start_date=start_date,
          end_date=end_date,
          default=default,
          search_text=search_text
        )
        #
        for domain in domains:
          ip_addr_v4, ip_addr_v6 = await IpRecordsDbo.get_ips_on_domain_id(db_session=db_session, domain_id=domain[0])
          payload.append(DomainElementResp(
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
            last_resolved_at_hum=None if domain[7] == None else domain[7].strftime('%Y-%m-%d %H:%M:%S')
          ))
      return DomainsPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        resolved_count=resolved_count,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all Domains failed : {err}', exc_info=True)
      await db_session.rollback()
      return DomainsPayloadResp(
        limit=limit,
        offset=offset,
        total=0,
        count=0,
        duration=monotonic() - before_time,
        payload=payload
      )
    finally:
      await db_session.close()

  async def get_domain_on_id(self: Self, id: int) -> DomainElementResp | None:
    logger.debug(f'Try get Domain on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__connect()
      domain: Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] | None = \
        await DomainsDbo.get_on_id(db_session=db_session, id=id)
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
          last_resolved_at_hum=None if domain[7] == None else domain[7].strftime('%Y-%m-%d %H:%M:%S')
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
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      filtered_domains: List[DomainsPostElementReq] = [
        domain
        for domain in domains
        if len(domain.domain) > settings.domains_filtered_min_len
      ]
      if settings.domains_not_allowed_pattern != None:
        clear_domains: List[DomainsPostElementReq] = [
          domain
          for domain in filtered_domains
          if settings.domains_not_allowed_pattern.search(domain.domain) == None
        ]
        domains_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_ADD,
          elements=clear_domains
        )
      else:
        domains_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_ADD,
          elements=filtered_domains
        )
      logger.debug(f'Put domains element {domains_element=} to Queue')
      self.db_save_queue.put_nowait(item=domains_element)
    except QueueFull:
      logger.error(f'Queue is full for try send domains {domains=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send domains to Queue : {err}', exc_info=True)

  async def put_delete_domains_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Domains to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      if id != None:
        logger.debug(f'One Domains delete {id=}')
        domains_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_DELETE,
          elements=[id]
        )
      else:
        domains_element: QueueElementDto = QueueElementDto(
          target=TargetAction.DOMAINS_DELETE_ALL,
          elements=[]
        )
      logger.debug(f'Put delete domains element {domains_element=} to Queue')
      self.db_save_queue.put_nowait(item=domains_element)
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Domains to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Domains to Queue : {err}', exc_info=True)

  async def get_domains_for_resolve(self: Self) -> List[DomainResult]:
    logger.debug(f'Try get Domains for resolve ...')
    domains: List[DomainResult] = []
    try:
      db_session: AsyncSession = await self.__connect()
      # get domains for resolve
      domains_for_resolve: Sequence[Row[Tuple[int, str, int | None, int]]] = await DomainsDbo.get_all_for_resolve(db_session=db_session)
      domains = [DomainResult(id=domain[0], name=domain[1], list_id=domain[2]) for domain in domains_for_resolve]
      logger.debug(f'Domains for resolve: {domains=}')
      return domains
    except Exception as err:
      logger.error(f'Try get Domains for resolve failed : {err}', exc_info=True)
      await db_session.rollback()
      return domains
    finally:
      await db_session.close()

  async def get_all_domains_on_domains_list(self: Self, domains_list_id: int) -> List[DomainResult]:
    logger.debug(f'Try get Domains on domains list {domains_list_id=} ...')
    domains: List[DomainResult] = []
    try:
      db_session: AsyncSession = await self.__connect()
      # get domains
      domains_on_list: Sequence[Row[Tuple[int, str]]] = await DomainsDbo.get_all_on_domains_list(
        db_session=db_session,
        domains_list_id=domains_list_id
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

  async def put_domains_after_resolve(self: Self, domains: List[DomainResult]) -> None:
    logger.debug(f'Try send insert ips, delete ips, update domains to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      domains_resolved_element: QueueElementDto = QueueElementDto(
        target=TargetAction.DOMAINS_RESOLVED,
        elements=domains
      )
      logger.debug(f'Put domains resolved element {domains_resolved_element=} to Queue')
      self.db_save_queue.put_nowait(item=domains_resolved_element)
    except QueueFull:
      logger.error(f'Queue is full for try send domains {domains=} to Queue')
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
    attempts: Optional[int] = None
  ) -> IpsListsPayloadResp:
    logger.debug(f'Try get all IP address lists ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[IpsListElementResp] = []
    try:
      db_session: AsyncSession = await self.__connect()
      total: int = await IpsListsDbo.get_total(db_session=db_session)
      if total > 0:
        ips_lists: Sequence[Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]]] = \
          await IpsListsDbo.get_all(
            db_session=db_session,
            limit=limit,
            offset=offset,
            start_date=start_date,
            end_date=end_date,
            search_text=search_text,
            attempts=attempts
          )
        for list in ips_lists:
          ip_v4_count, ip_v6_count = await IpRecordsDbo.get_total_ips_on_ips_list(db_session=db_session, ip_list_id=list[0])
          payload.append(IpsListElementResp(
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
            updated_at_hum=None if list[7] == None else list[7].strftime('%Y-%m-%d %H:%M:%S')
          ))
      return IpsListsPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all IP address lists failed : {err}', exc_info=True)
      await db_session.rollback()
      return IpsListsPayloadResp(
        limit=limit,
        offset=offset,
        total=0,
        count=0,
        duration=monotonic() - before_time,
        payload=payload
      )
    finally:
      await db_session.close()

  async def get_ips_list_on_id(self: Self, id: int) -> IpsListElementResp | None:
    logger.debug(f'Try get Ips list on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__connect()
      ips_list: Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] | None = \
        await IpsListsDbo.get_on_id(db_session=db_session, id=id)
      if ips_list != None:
        ip_v4_count, ip_v6_count = await IpRecordsDbo.get_total_ips_on_ips_list(db_session=db_session, ip_list_id=ips_list[0])
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
          updated_at_hum=None if ips_list[7] == None else ips_list[7].strftime('%Y-%m-%d %H:%M:%S')
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
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      ips_lists_element: QueueElementDto = QueueElementDto(
        target=TargetAction.IPS_LISTS_ADD,
        elements=ips_lists
      )
      logger.debug(f'Put ips lists element {ips_lists_element=} to Queue')
      self.db_save_queue.put_nowait(item=ips_lists_element)
    except QueueFull:
      logger.error(f'Queue is full for try send ips lists {ips_lists=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send ips lists to Queue : {err}', exc_info=True)

  async def put_delete_ips_list_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Ips list to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      if id != None:
        logger.debug(f'One Ips list delete {id=}')
        ips_list_element: QueueElementDto = QueueElementDto(
          target=TargetAction.IPS_LISTS_DELETE,
          elements=[id]
        )
      else:
        ips_list_element: QueueElementDto = QueueElementDto(
          target=TargetAction.IPS_LISTS_DELETE_ALL,
          elements=[]
        )
      logger.debug(f'Put delete ips list element {ips_list_element=} to Queue')
      self.db_save_queue.put_nowait(item=ips_list_element)
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Ips list to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Ips list to Queue : {err}', exc_info=True)

  async def update_ips_lists(self: Self, ips_lists: List[IpsListDto]) -> None:
    logger.debug(f'Try send update Ips lists to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      logger.debug(f'One Ips lists update {ips_lists=}')
      ips_list_element: QueueElementDto = QueueElementDto(
        target=TargetAction.IPS_LISTS_UPDATE,
        elements=ips_lists
      )
      logger.debug(f'Put update ips lists element {ips_list_element=} to Queue')
      self.db_save_queue.put_nowait(item=ips_list_element)
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
    search_text: Optional[str] = None
  ) -> IpsPayloadResp:
    logger.debug(f'Try get all IP address records ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {search_text=}')
    payload: List[IpsElementResp] = []
    try:
      db_session: AsyncSession = await self.__connect()
      total: int = await IpRecordsDbo.get_total(db_session=db_session)
      if total > 0:
        ips: Sequence[Row[Tuple[int, int | None, str, int | None, str, int, str, str | None, datetime, datetime | None]]] = \
        await IpRecordsDbo.get_all(
          db_session=db_session,
          limit=limit,
          offset=offset,
          start_date=start_date,
          end_date=end_date,
          search_text=search_text
        )
        #
        for ip in ips:
          payload.append(IpsElementResp(
            id=ip[0],
            type=ip[5],
            addr=ip[6],
            ip_list_id=ip[1],
            ip_list_name=ip[2],
            domain_id=ip[3],
            domain_name=ip[4],
            ros_comment=ip[7],
            created_at=ip[8].timestamp(),
            created_at_hum=ip[8].strftime('%Y-%m-%d %H:%M:%S'),
            updated_at=None if ip[9] == None else ip[9].timestamp(),
            updated_at_hum=None if ip[9] == None else ip[9].strftime('%Y-%m-%d %H:%M:%S')
          ))
      return IpsPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all Domains failed : {err}', exc_info=True)
      await db_session.rollback()
      return IpsPayloadResp(
        limit=limit,
        offset=offset,
        total=0,
        count=0,
        duration=monotonic() - before_time,
        payload=payload
      )
    finally:
      await db_session.close()

  async def get_ip_record_on_id(self: Self, id: int) -> IpsElementResp | None:
    logger.debug(f'Try get IP address record on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__connect()
      ip_address_record: Row[Tuple[int, int | None, str, int | None, str, str, int, str | None, datetime, datetime | None]] | None = \
        await IpRecordsDbo.get_on_id(db_session=db_session, id=id)
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
          created_at=ip_address_record[8].timestamp(),
          created_at_hum=ip_address_record[8].strftime('%Y-%m-%d %H:%M:%S'),
          updated_at=None if ip_address_record[9] == None else ip_address_record[9].timestamp(),
          updated_at_hum=None if ip_address_record[9] == None else ip_address_record[9].strftime('%Y-%m-%d %H:%M:%S')
        )
      return None
    except Exception as err:
      logger.error(f'Try get IP address record on ID={id} failed : {err}', exc_info=True)
      await db_session.rollback()
      return None
    finally:
      await db_session.close()

  async def put_add_ips_to_queue(self: Self, ips: List[IpsPostElementReq]) -> None:
    logger.debug(f'Try send Ips to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      ips_element: QueueElementDto = QueueElementDto(
        target=TargetAction.IPS_ADD,
        elements=ips
      )
      logger.debug(f'Put ips element {ips_element=} to Queue')
      self.db_save_queue.put_nowait(item=ips_element)
    except QueueFull:
      logger.error(f'Queue is full for try send ips {ips=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send ips to Queue : {err}', exc_info=True)

  async def put_delete_ips_to_queue(self: Self, id_or_ip: Optional[int | str] = None) -> None:
    logger.debug(f'Try send deleted Ips to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      if id_or_ip != None:
        try:
          id: int = int(id_or_ip)
          logger.debug(f'IP address delete is ID {id=}')
          ips_element: QueueElementDto = QueueElementDto(
            target=TargetAction.IPS_DELETE_ID,
            elements=[id]
          )
        except:
          try:
            get_ip_version(str(id_or_ip))
            logger.debug(f'IP address delete is ADDRESS {id_or_ip=}')
            ips_element: QueueElementDto = QueueElementDto(
              target=TargetAction.IPS_DELETE_ADDR,
              elements=[id_or_ip]
            )
          except:
            pass
      else:
        ips_element: QueueElementDto = QueueElementDto(
          target=TargetAction.IPS_DELETE_ALL,
          elements=[]
        )
      logger.debug(f'Put delete ips element {ips_element=} to Queue')
      self.db_save_queue.put_nowait(item=ips_element)
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Domains to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Domains to Queue : {err}', exc_info=True)

  async def get_all_ips_for_domain(self: Self, domain_id: int) -> List[IpRecordDto]:
    logger.debug(f'Try get all IP address records for Domain {domain_id=} ...')
    result: List[IpRecordDto] = []
    try:
      db_session: AsyncSession = await self.__connect()
      ips_result: Sequence[Row[Tuple[int, str, int]]] = await IpRecordsDbo.get_ips_on_domain_id_extend(db_session=db_session, domain_id=domain_id)
      result = [IpRecordDto(id=ip[0], ip_address=ip[1], addr_type=ip[2]) for ip in ips_result]
      return result
    except Exception as err:
      logger.error(f'Try get all IP address records for Domain {domain_id=} failed : {err}', exc_info=True)
      await db_session.rollback()
      return result
    finally:
      await db_session.close()

  async def get_all_ips_on_ips_list(self: Self, ips_list_id: int) -> List[IpRecordDto]:
    logger.debug(f'Try get all IP address records for ips list {ips_list_id=} ...')
    result: List[IpRecordDto] = []
    try:
      db_session: AsyncSession = await self.__connect()
      ips_result: Sequence[Row[Tuple[int, str]]] = await IpRecordsDbo.get_all_on_ips_list(
        db_session=db_session,
        ip_list_id=ips_list_id
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
      db_session: AsyncSession = await self.__connect()
      all_ips: Sequence[Row[Tuple[str, str | None]]] = await IpRecordsDbo.get_all_for_update(
        db_session=db_session,
        addr_type=addr_type
      )
      ips = [IpRecordDto(ip_address=ip[0], comment=ip[1]) for ip in all_ips]
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
    search_text: Optional[str] = None
  ) -> RosConfigPayloadResp:
    logger.debug(f'Try get all RoS configs ...')
    logger.debug(f'{limit=}, {offset=}, {start_date=}, {end_date=}, {default=}, {search_text=}')
    payload: List[RosConfigElementResp] = []
    try:
      db_session: AsyncSession = await self.__connect()
      #
      total: int = await RosConfigsDbo.get_total(db_session=db_session)
      if total > 0:
        ros_configs: Sequence[Row[Tuple[int, str, str, str, str, str | None, datetime, datetime | None]]] = \
          await RosConfigsDbo.get_all(
            db_session=db_session,
            limit=limit,
            offset=offset,
            start_date=start_date,
            end_date=end_date,
            default=default,
            search_text=search_text
          )
        #
        for config in ros_configs:
          payload.append(RosConfigElementResp(
            id=config[0],
            host=config[1],
            user=config[2],
            password=config[3],
            bgp_list_name=config[4],
            description=config[5],
            created_at=config[6].timestamp(),
            created_at_hum=config[6].strftime('%Y-%m-%d %H:%M:%S'),
            updated_at=None if config[7] == None else config[7].timestamp(),
            updated_at_hum=None if config[7] == None else config[7].strftime('%Y-%m-%d %H:%M:%S')
          ))
      return RosConfigPayloadResp(
        limit=limit,
        offset=offset,
        total=total,
        count=len(payload),
        duration=monotonic() - before_time,
        payload=payload
      )
    except Exception as err:
      logger.error(f'Try get all RoS configs failed : {err}', exc_info=True)
      await db_session.rollback()
      return RosConfigPayloadResp(
        limit=limit,
        offset=offset,
        total=0,
        count=0,
        duration=monotonic() - before_time,
        payload=payload
      )
    finally:
      await db_session.close()

  async def get_ros_config_on_id(self: Self, id: int) -> RosConfigElementResp | None:
    logger.debug(f'Try get RoS config on ID={id} ...')
    try:
      db_session: AsyncSession = await self.__connect()
      ros_config: Row[Tuple[int, str, str, str, str, str | None, datetime, datetime | None]] | None = \
        await RosConfigsDbo.get_on_id(db_session=db_session, id=id)
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
          updated_at_hum=None if ros_config[7] == None else ros_config[7].strftime('%Y-%m-%d %H:%M:%S')
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
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      ros_configs_element: QueueElementDto = QueueElementDto(
        target=TargetAction.ROS_CONFIG_ADD,
        elements=ros_configs
      )
      logger.debug(f'Put RoS configs element {ros_configs_element=} to Queue')
      self.db_save_queue.put_nowait(item=ros_configs_element)
    except QueueFull:
      logger.error(f'Queue is full for try send RoS configs {ros_configs=} to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send RoS configs to Queue : {err}', exc_info=True)

  async def put_delete_ros_configs_to_queue(self: Self, id: Optional[int] = None) -> None:
    logger.debug(f'Try send deleted Router OS configs to Queue ...')
    try:
      while self.db_save_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      if id != None:
        logger.debug(f'One Router OS config delete {id=}')
        ros_configs_element: QueueElementDto = QueueElementDto(
          target=TargetAction.ROS_CONFIG_DELETE,
          elements=[id]
        )
      else:
        ros_configs_element: QueueElementDto = QueueElementDto(
          target=TargetAction.ROS_CONFIG_DELETE_ALL,
          elements=[]
        )
      logger.debug(f'Put delete Router OS configs element {ros_configs_element=} to Queue')
      self.db_save_queue.put_nowait(item=ros_configs_element)
    except QueueFull:
      logger.error(f'Queue is full for try send deleted Router OS configs to Queue')
    except Exception as err:
      logger.error(f'Unexpected error - Try send deleted Router OS configs to Queue : {err}', exc_info=True)

  async def get_all_configs_for_ros_update(self: Self) -> List[RosConfigDto]:
    logger.debug(f'Try get all RoS configs for update ...')
    configs: List[RosConfigDto] = []
    try:
      db_session: AsyncSession = await self.__connect()
      ros_configs: Sequence[Row[Tuple[int, str, str, str, str]]] = await RosConfigsDbo.get_all_for_update(db_session=db_session)
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
    try:
      await jobs_cache.set(key=Jobs.LISTS_LOAD, value=True)
      db_session: AsyncSession = await self.__connect()
      domains_lists_total: int = await DomainsListsDbo.get_total(db_session=db_session)
      ips_lists_total: int = await IpsListsDbo.get_total(db_session=db_session)
      if domains_lists_total > 0:
        logger.debug(f'Load Domains lists {domains_lists_total=} ...')
        domains_lists: List[DomainsListDto] = await DomainsListsDbo.get_for_update(db_session=db_session)
        logger.debug(f'{domains_lists=}')
        await self.file_loader_client.get_domains_from_lists(lists=domains_lists)
        unactive_domains_lists: List[DomainsListDto] = [list for list in domains_lists if list.attempts >= settings.attempts_limit]
        active_domains_lists: List[DomainsListDto] = [list for list in domains_lists if list.attempts < settings.attempts_limit]
        # delete unactive domains lists
        if len(unactive_domains_lists) > 0:
          for list in unactive_domains_lists:
            await self.put_delete_domains_list_to_queue(id=list.id)
        # add domains
        if len(active_domains_lists) > 0:
          domains_add: List[DomainsPostElementReq] = []
          domains_delete: List[DomainResult] = []
          for list in active_domains_lists:
            if list.found_elements == None: continue # if hash not change in get_domains_from_lists - found_elements is None
            current_domains: List[DomainResult] = await self.get_all_domains_on_domains_list(domains_list_id=list.id)
            current_domains_list: List[str] = [domain.name for domain in current_domains]
            [
              domains_add.append(DomainsPostElementReq(domain=domain, list_id=list.id))
              for domain in list.found_elements
              if domain not in current_domains_list
            ]
            [
              domains_delete.append(domain)
              for domain in current_domains
              if domain.name not in list.found_elements
            ]
          await self.put_add_domains_to_queue(domains=domains_add)
          for domain in domains_delete:
            await self.put_delete_domains_to_queue(id=domain.id)
          await self.update_domains_lists(domains_lists=active_domains_lists)
      if ips_lists_total > 0:
        logger.debug(f'Load IPs lists {ips_lists_total=} ...')
        ips_lists: List[IpsListDto] = await IpsListsDbo.get_for_update(db_session=db_session)
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
          ips_delete: List[IpRecordDto] = []
          for list in active_ips_lists:
            if list.found_elements == None: continue # if hash not change in get_ips_from_lists - found_elements is None
            current_ips: List[IpRecordDto] = await self.get_all_ips_on_ips_list(ips_list_id=list.id)
            current_ips_list: List[str] = [ip.ip_address for ip in current_ips]
            [
              ips_add.append(IpsPostElementReq(addr=ip, list_id=list.id))
              for ip in list.found_elements
              if ip not in current_ips_list
            ]
            [
              ips_delete.append(ip)
              for ip in current_ips
              if ip.ip_address not in list.found_elements
            ]
          await self.put_add_ips_to_queue(ips=ips_add)
          for ip in ips_delete:
            await self.put_delete_ips_to_queue(id_or_ip=ip.id)
          await self.update_ips_lists(ips_lists=active_ips_lists)
    except Exception as err:
      logger.error(f'Try Lists load failed : {err}', exc_info=True)
      await db_session.rollback()
    finally:
      await jobs_cache.set(key=Jobs.LISTS_LOAD, value=False)
      await db_session.close()

  #

  async def __task_process_commit_db_from_queue(self: Self) -> None:
    # save if save batch count >= settings.db_save_batch_size (default 1000)
    # else save timeout >= settings.db_save_batch_timeout (default 500.0 ms)
    logger.info('STARTING A FLOW - Saving information to the database')
    start_timer: float = 0.0
    items_batch: List[QueueElementDto] = []
    while not self.__stop_db_save_event.is_set():
      if self.__state == False:
        await sleep(self.__queue_sleep_timeout)
        continue
      try:
        # queue is empty - skip
        if self.db_save_queue.empty():
          # queue done
          if (
            len(items_batch) > 0 and len(items_batch) < settings.db_save_batch_size
          ) and (monotonic() - start_timer) >= settings.db_save_batch_timeout:
            # save batch if timeout
            await self.__batch_items_commit(items_batch)
            items_batch.clear()
            start_timer = 0.0
          await sleep(self.__queue_sleep_timeout)
          continue
        queue_element: QueueElementDto = await wait_for(
          self.db_save_queue.get(),
          timeout=self.__queue_get_timeout
        )
        if start_timer == 0.0: start_timer = monotonic()
        if len(items_batch) >= settings.db_save_batch_size:
          # save batch if full count
          await self.__batch_items_commit(items_batch)
          items_batch.clear()
          start_timer = 0.0
        else:
          items_batch.append(queue_element)
      except TimeoutError:
        await sleep(self.__queue_sleep_timeout)
        continue
      except CancelledError:
        logger.info('A request was received to stop the flow - Saving information to the database')
        start_timer = 0.0
        break
      except Exception as err:
        logger.error(f'Unexpected error in flow - Saving information to the database : {err}', exc_info=True)
        items_batch.clear()
        start_timer = 0.0
        await sleep(self.__task_exception_error_timeout)
        continue
    logger.warning('STOP FLOW - Saving information to the database')

  async def __batch_items_commit(self: Self, queue_elements: List[QueueElementDto]) -> None:
    '''
    INSERT, DELETE, UPDATE - only single transaction. SQLite DB !!! One file
    '''
    logger.debug(f'Try prepare elements count={len(queue_elements)} ...')
    logger.debug(f'DB save queue batch prepare: {queue_elements=}')
    try:
      # Prepare elements
      # DNS SERVERS
      dns_servers_add: List[Dict[str, str | None]] = [
        {
          DnsServersDbo.server.property.key: item.server,
          DnsServersDbo.doh_server.property.key: item.doh_server,
          DnsServersDbo.description.property.key: item.description
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
        queue_element
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DNS_SERVERS_DELETE_ALL
      ]
      # DOMAINS LISTS
      domains_lists_add: List[Dict[str, str | None]] = [
        {
          DomainsListsDbo.name.property.key: item.name,
          DomainsListsDbo.url.property.key: item.url,
          DomainsListsDbo.description.property.key: item.description
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
          DomainsListsDbo.attempts.property.key: item.attempts
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
          DomainsDbo.ros_comment.property.key: item.ros_comment
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
        queue_element
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_DELETE_ALL
      ]
      domains_resolved_update: List[Dict[str, int | bool | datetime]] = [
        {
          DomainsDbo.id.property.key: domain_result.id,
          DomainsDbo.resolved.property.key: True,
          DomainsDbo.last_resolved_at.property.key: datetime.now(timezone.utc)
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_RESOLVED
        for domain_result in queue_element.elements # item = DomainResult
      ]
      # IPS LISTS
      ips_lists_add: List[Dict[str, str | None]] = [
        {
          IpsListsDbo.name.property.key: item.name,
          IpsListsDbo.url.property.key: item.url,
          IpsListsDbo.description.property.key: item.description
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
        queue_element
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_LISTS_DELETE_ALL
      ]
      ips_lists_update: List[Dict[str, str | int | None]] = [
        {
          IpsListsDbo.id.property.key: item.id,
          IpsListsDbo.name.property.key: item.name,
          IpsListsDbo.url.property.key: item.url,
          IpsListsDbo.description.property.key: item.description,
          IpsListsDbo.hash.property.key: item.hash,
          IpsListsDbo.attempts.property.key: item.attempts
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
          IpRecordsDbo.ros_comment.property.key: item.ros_comment
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_ADD
        for item in queue_element.elements # item = IpsPostElementReq
      ]
      ips_resolved_add: List[Dict[str, str | int]] = [
        {
          IpRecordsDbo.ip_address.property.key: ip_record.ip_address,
          IpRecordsDbo.domain_id.property.key: domain_result.id,
          IpRecordsDbo.addr_type.property.key: ip_record.addr_type
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_RESOLVED
        for domain_result in queue_element.elements # item = DomainResult
        for ip_record in domain_result.insert.ips_insert # ip_record = IpRecordDto
      ]
      ips_resolved_delete: List[int] = [
        ip_id
        for queue_element in queue_elements
        if queue_element.target == TargetAction.DOMAINS_RESOLVED
        for domain_result in queue_element.elements # item = DomainResult
        for ip_id in domain_result.insert.ips_delete # ip_id = int
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
        queue_element
        for queue_element in queue_elements
        if queue_element.target == TargetAction.IPS_DELETE_ALL
      ]
      # ROS CONFIGS
      ros_configs_add: List[Dict[str, str | None]] = [
        {
          RosConfigsDbo.host.property.key: item.host,
          RosConfigsDbo.user.property.key: item.user,
          RosConfigsDbo.passwd.property.key: item.user_password,
          RosConfigsDbo.bgp_list_name.property.key: item.bgp_list_name,
          RosConfigsDbo.description.property.key: item.description
        }
        for queue_element in queue_elements
        if queue_element.target == TargetAction.ROS_CONFIG_ADD
        for item in queue_element.elements # item = RosConfigsPostElementReq
      ]
      ros_configs_delete: List[int] = [
        item
        for queue_element in queue_elements
        if queue_element.target == TargetAction.ROS_CONFIG_DELETE
        for item in queue_element.elements
      ]
      ros_configs_delete_all: list[QueueElementDto] = [
        queue_element
        for queue_element in queue_elements
        if queue_element.target == TargetAction.ROS_CONFIG_DELETE_ALL
      ]
      #
      #
      db_session: AsyncSession = await self.__connect()
      # DNS SERVERS
      if len(dns_servers_add) > 0:
        logger.debug(f'DB save queue batch prepare: {dns_servers_add=}')
        await DnsServersDbo.add_batch(db_session=db_session, items=dns_servers_add)
      if len(dns_servers_delete) > 0:
        logger.debug(f'DB delete queue batch prepare: {dns_servers_delete=}')
        await db_session.execute(delete(DnsServersDbo).where(DnsServersDbo.id.in_(dns_servers_delete)))
      if len(dns_servers_delete_all) > 0:
        logger.debug(f'DB delete queue batch prepare: {dns_servers_delete_all=}')
        await db_session.execute(delete(DnsServersDbo).where(DnsServersDbo.id > 0))
      # DOMAINS LISTS
      if len(domains_lists_add) > 0:
        logger.debug(f'DB save queue batch prepare: {domains_lists_add=}')
        await DomainsListsDbo.add_batch(db_session=db_session, items=domains_lists_add)
      if len(domains_lists_delete) > 0: # ATTEMPTS
        logger.debug(f'DB delete queue batch prepare: {domains_lists_delete=}')
        await db_session.execute(delete(DomainsListsDbo).where(DomainsListsDbo.id.in_(domains_lists_delete)))
      if len(domains_lists_delete_all) > 0:
        logger.debug(f'DB delete queue batch prepare: {domains_lists_delete_all=}')
        await db_session.execute(delete(DomainsListsDbo).where(DomainsListsDbo.id > 0))
      if len(domains_lists_update) > 0:
        logger.debug(f'DB update queue batch prepare: {domains_lists_update=}')
        await db_session.execute(update(DomainsListsDbo), domains_lists_update)
      # IPS LISTS
      if len(ips_lists_add) > 0:
        logger.debug(f'DB save queue batch prepare: {ips_lists_add=}')
        await IpsListsDbo.add_batch(db_session=db_session, items=ips_lists_add)
      if len(ips_lists_delete) > 0: # ATTEMPTS
        logger.debug(f'DB delete queue batch prepare: {ips_lists_delete=}')
        await db_session.execute(delete(IpsListsDbo).where(IpsListsDbo.id.in_(ips_lists_delete)))
      if len(ips_lists_delete_all) > 0:
        logger.debug(f'DB delete queue batch prepare: {ips_lists_delete_all=}')
        await db_session.execute(delete(IpsListsDbo).where(IpsListsDbo.id > 0))
      if len(ips_lists_update) > 0:
        logger.debug(f'DB update queue batch prepare: {ips_lists_update=}')
        await db_session.execute(update(IpsListsDbo), ips_lists_update)
      # IPS
      if len(ips_add) > 0:
        logger.debug(f'DB save queue batch prepare: {ips_add=}')
        await IpRecordsDbo.add_batch(db_session=db_session, items=ips_add)
      if len(ips_resolved_add) > 0:
        logger.debug(f'DB save queue batch prepare: {ips_resolved_add=}')
        await IpRecordsDbo.add_batch(db_session=db_session, items=ips_resolved_add)
      if len(ips_id_delete) > 0:
        logger.debug(f'DB delete queue batch prepare: {ips_id_delete=}')
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.id.in_(ips_id_delete)))
      if len(ips_resolved_delete) > 0:
        logger.debug(f'DB delete queue batch prepare: {ips_resolved_delete=}')
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.id.in_(ips_resolved_delete)))
      if len(ips_addr_delete) > 0:
        logger.debug(f'DB delete queue batch prepare: {ips_addr_delete=}')
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.ip_address.in_(ips_addr_delete)))
      if len(ips_delete_all) > 0:
        logger.debug(f'DB delete queue batch prepare: {ips_delete_all=}')
        await db_session.execute(delete(IpRecordsDbo).where(IpRecordsDbo.id > 0))
      # DOMAINS (after ips processing)
      if len(domains_add) > 0:
        logger.debug(f'DB save queue batch prepare: {domains_add=}')
        await DomainsDbo.add_batch(db_session=db_session, items=domains_add)
      if len(domains_delete) > 0:
        logger.debug(f'DB delete queue batch prepare: {domains_delete=}')
        await db_session.execute(delete(DomainsDbo).where(DomainsDbo.id.in_(domains_delete)))
      if len(domains_delete_all) > 0:
        logger.debug(f'DB delete queue batch prepare: {domains_delete_all=}')
        await db_session.execute(delete(DomainsDbo).where(DomainsDbo.id > 0))
      if len(domains_resolved_update) > 0:
        logger.debug(f'DB delete queue batch prepare: {domains_resolved_update=}')
        await db_session.execute(update(DomainsDbo), domains_resolved_update)
      # ROS CONFIGS
      if len(ros_configs_add) > 0:
        logger.debug(f'DB save queue batch prepare: {ros_configs_add=}')
        await RosConfigsDbo.add_batch(db_session=db_session, items=ros_configs_add)
      if len(ros_configs_delete) > 0:
        logger.debug(f'DB delete queue batch prepare: {ros_configs_delete=}')
        await db_session.execute(delete(RosConfigsDbo).where(RosConfigsDbo.id.in_(ros_configs_delete)))
      if len(ros_configs_delete_all) > 0:
        logger.debug(f'DB delete queue batch prepare: {ros_configs_delete_all=}')
        await db_session.execute(delete(RosConfigsDbo).where(RosConfigsDbo.id > 0))
      #
      await db_session.commit()
    except Exception as err:
      logger.error(f'Try prepare elements failed : {err}', exc_info=True)
      await db_session.rollback()
    finally:
      await db_session.close()

# Init DataBase
try:
  db: DataBase = DataBase()
except Exception as err:
  raise err
