from collections.abc import Sequence
from datetime import datetime
from typing import Self

from sqlalchemy import (
  INTEGER,
  TEXT,
  TIMESTAMP,
  CheckConstraint,
  CompoundSelect,
  Result,
  Row,
  Select,
  case,
  exists,
  func,
  or_,
  select,
  union_all,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from models.dto.dns_server_dto import DnsServerType

from .base_dbo import Dbo


class DnsServersDbo(Dbo):
  """
  DNS servers table
  default: Cloudflare DNS 1.1.1.1 / ID=0
  """

  __tablename__ = 'dns_servers'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)

  server: Mapped[str | None] = mapped_column(TEXT, unique=True, nullable=True)
  doh_server: Mapped[str | None] = mapped_column(TEXT, unique=True, nullable=True)
  description: Mapped[str | None] = mapped_column(TEXT, nullable=True)

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("server != ''", name='server_chk'),
    CheckConstraint("doh_server != ''", name='doh_server_chk'),
  )

  # get_total in Base class
  # add_batch (insert) in Base class

  @classmethod
  async def get_all(
    cls: type[Self],
    db_session: AsyncSession,
    limit: int,
    offset: int,
    start_date: str | None = None,
    end_date: str | None = None,
    default: bool | None = None,
    search_text: str | None = None,
  ) -> Sequence[Row[int, str | None, str | None, str | None, datetime, datetime | None]]:
    try:
      select_stmt: Select[int, str | None, str | None, str | None, datetime, datetime | None] = select(
        cls.id, cls.server, cls.doh_server, cls.description, cls.created_at, cls.updated_at
      )
      if start_date is not None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
      if end_date is not None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
      if default is not None and not default:  # We don't include default in the sample
        select_stmt = select_stmt.where(cls.id > 0)
      if search_text is not None:
        select_stmt = select_stmt.where(or_(cls.server.contains(search_text), cls.doh_server.contains(search_text)))
      select_limit_stmt: Select[int, str | None, str | None, str | None, datetime, datetime | None] = select_stmt.limit(
        limit
      ).offset(offset)
      exec_result: Result[
        int, str | None, str | None, str | None, datetime, datetime | None
      ] = await db_session.execute(select_limit_stmt)
      return exec_result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self], db_session: AsyncSession, id: int
  ) -> Row[int, str | None, str | None, str | None, datetime, datetime | None] | None:
    try:
      select_stmt: Select[int, str | None, str | None, str | None, datetime, datetime | None] = select(
        cls.id, cls.server, cls.doh_server, cls.description, cls.created_at, cls.updated_at
      ).where(cls.id == id)
      exec_result: Result[
        int, str | None, str | None, str | None, datetime, datetime | None
      ] = await db_session.execute(select_stmt)
      return exec_result.fetchone()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_for_resolve(
    cls: type[Self], db_session: AsyncSession
  ) -> Sequence[Row[str | None, str | None, DnsServerType, int]]:
    try:
      # user DNS servers
      select_stmt_normal: Select[str | None, str | None, DnsServerType, int] = select(
        cls.server,
        cls.doh_server,
        case(
          (cls.server.is_not(None), DnsServerType.DEFAULT),
          (cls.doh_server.is_not(None), DnsServerType.DOH),
          else_=DnsServerType.UNKNOWN,
        ).label('type'),
        cls.id,
      ).where(cls.id > 0)
      # default DNS server (one record)
      select_stmt_default = select(
        cls.server,
        cls.doh_server,
        case(
          (cls.server.is_not(None), DnsServerType.DEFAULT),
          (cls.doh_server.is_not(None), DnsServerType.DOH),
          else_=DnsServerType.UNKNOWN,
        ).label('type'),
        cls.id,
      ).where(cls.id == 0, ~exists(select(1).where(cls.id > 0)))
      # union
      select_stmt_union: CompoundSelect[str | None, str | None, DnsServerType, int] = union_all(
        select_stmt_normal, select_stmt_default
      )
      exec_result: Result[str | None, str | None, DnsServerType, int] = await db_session.execute(select_stmt_union)
      return exec_result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_stats(cls: type[Self], db_session: AsyncSession) -> Row[int, int, int]:
    try:
      select_stmt: Select[int, int, int] = select(
        func.count().label('total'), func.count(cls.server).label('classic'), func.count(cls.doh_server).label('doh')
      )
      exec_result: Result[int, int, int] = await db_session.execute(select_stmt)
      return exec_result.one()
    except Exception as err:
      raise err
