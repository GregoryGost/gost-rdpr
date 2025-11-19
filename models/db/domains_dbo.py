from datetime import datetime
from sqlalchemy import (
  select,
  or_,
  text,
  func,
  Row,
  Select,
  Result,
  CheckConstraint,
  ForeignKeyConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT,
  BOOLEAN
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Tuple, Self, Sequence

from config.config import settings

from .base_dbo import Dbo
from .domains_lists_dbo import DomainsListsDbo

class DomainsDbo(Dbo):
  '''
  Domains table  
  default: Default Domain / ID=0
  '''

  __tablename__ = 'domains'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  domain_list_id: Mapped[Optional[int]] = mapped_column(INTEGER, index=True, nullable=True)

  resolved: Mapped[bool] = mapped_column(BOOLEAN, default=False, nullable=False)
  name: Mapped[str] = mapped_column(TEXT, unique=True, index=True, nullable=False)
  ros_comment: Mapped[Optional[str]] = mapped_column(TEXT, nullable=True)

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)
  last_resolved_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, index=True, nullable=True)

  __table_args__ = (
    CheckConstraint("name != ''", name='name_chk'),
    ForeignKeyConstraint(['domain_list_id'], [DomainsListsDbo.id], name='domain_list_id_fk', ondelete='CASCADE')
  )

  # get_total in Base class
  # add_batch (insert) in Base class

  @classmethod
  async def get_all(
    cls: type[Self],
    db_session: AsyncSession,
    limit: int,
    offset: int,
    resolved: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    default: Optional[bool] = None,
    search_text: Optional[str] = None
  ) -> Tuple[Sequence[Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]]], int]:
    try:
      select_stmt: Select[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] = select(
        cls.id,
        cls.domain_list_id,
        cls.resolved,
        cls.name,
        cls.ros_comment,
        cls.created_at,
        cls.updated_at,
        cls.last_resolved_at
      )
      select_query_total_stmt: Select[Tuple[int]] = select(func.count()).select_from(cls)
      if resolved != None:
        select_stmt = select_stmt.where(cls.resolved == resolved)
        select_query_total_stmt = select_query_total_stmt.where(cls.resolved == resolved)
      if start_date != None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
        select_query_total_stmt = select_query_total_stmt.where(cls.created_at >= start_date)
      if end_date != None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
        select_query_total_stmt = select_query_total_stmt.where(cls.created_at <= end_date)
      if default != None and default == False: # We don't include default in the sample
        select_stmt = select_stmt.where(cls.id > 0)
        select_query_total_stmt = select_query_total_stmt.where(cls.id > 0)
      if search_text != None:
        select_stmt = select_stmt.where(cls.name.contains(search_text))
        select_query_total_stmt = select_query_total_stmt.where(cls.name.contains(search_text))
      select_limit_stmt: Select[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] = \
        select_stmt.limit(limit).offset(offset)
      result_query_total: Result[Tuple[int]] = await db_session.execute(select_query_total_stmt)
      result: Result[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] = \
        await db_session.execute(select_limit_stmt)
      #
      return result.fetchall(), result_query_total.scalar_one()
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self],
    db_session: AsyncSession,
    id: int
  ) -> Row[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] | None:
    try:
      select_stmt: Select[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] = select(
        cls.id,
        cls.domain_list_id,
        cls.resolved,
        cls.name,
        cls.ros_comment,
        cls.created_at,
        cls.updated_at,
        cls.last_resolved_at
      ).where(cls.id == id)
      exec_result: Result[Tuple[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None]] = \
        await db_session.execute(select_stmt)
      return exec_result.fetchone()
    except Exception as err:
      raise err

  @classmethod
  async def get_total_on_domains_list(
    cls: type[Self],
    db_session: AsyncSession,
    domains_list_id: int
  ) -> int:
    try:
      select_stmt: Select[Tuple[int]] = select(func.count()).select_from(cls).where(cls.domain_list_id == domains_list_id)
      exec_result: Result[Tuple[int]] = await db_session.execute(select_stmt)
      return exec_result.scalar_one()
    except Exception as err:
      raise err

  @classmethod
  async def get_total_resolved(
    cls: type[Self],
    db_session: AsyncSession
  ) -> int:
    try:
      select_stmt: Select[Tuple[int]] = select(func.count()).select_from(cls).where(cls.resolved == True)
      exec_result: Result[Tuple[int]] = await db_session.execute(select_stmt)
      return exec_result.scalar_one()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_for_resolve(
    cls: type[Self],
    db_session: AsyncSession
  ) -> Sequence[Row[Tuple[int, str, int | None, int]]]:
    '''
    WHERE id > 0 AND (updated_at IS NULL OR (unixepoch(CURRENT_TIMESTAMP) - unixepoch(updated_at)) >= {DOMAINS_UPDATE_INTERVAL})
    '''
    try:
      select_stmt: Select[Tuple[int, str, int | None, int]] = select(
        cls.id,
        cls.name,
        cls.domain_list_id,
        text(f'COALESCE(unixepoch(CURRENT_TIMESTAMP) - unixepoch({cls.__tablename__}.{cls.last_resolved_at.property.key}), 0) AS elapsed')
      ).where(
        cls.id > 0,
        or_(
          cls.last_resolved_at == None,
          text(f'elapsed >= {settings.domains_update_interval}')
        )
      )
      result: Result[Tuple[int, str, int | None, int]] = \
        await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_on_domains_list(
    cls: type[Self],
    db_session: AsyncSession,
    domains_list_id: int
  ) -> Sequence[Row[Tuple[int, str]]]:
    try:
      select_stmt: Select[Tuple[int, str]] = select(
        cls.id,
        cls.name
      ).where(cls.domain_list_id == domains_list_id)
      result: Result[Tuple[int, str]] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err
