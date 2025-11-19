from datetime import datetime
from sqlalchemy import (
  select,
  or_,
  case,
  exists,
  union_all,
  func,
  Row,
  Select,
  Result,
  CompoundSelect,
  CheckConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Tuple, Self, Sequence

from .base_dbo import Dbo

from models.dto.dns_server_dto import DnsServerType

class DnsServersDbo(Dbo):
  '''
  DNS servers table  
  default: Cloudflare DNS 1.1.1.1 / ID=0
  '''

  __tablename__ = 'dns_servers'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)

  server: Mapped[Optional[str]] = mapped_column(TEXT, unique=True, nullable=True)
  doh_server: Mapped[Optional[str]] = mapped_column(TEXT, unique=True, nullable=True)
  description: Mapped[Optional[str]] = mapped_column(TEXT, nullable=True)

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("server != ''", name='server_chk'),
    CheckConstraint("doh_server != ''", name='doh_server_chk')
  )

  # get_total in Base class
  # add_batch (insert) in Base class

  @classmethod
  async def get_all(
    cls: type[Self],
    db_session: AsyncSession,
    limit: int,
    offset: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    default: Optional[bool] = None,
    search_text: Optional[str] = None
  ) -> Sequence[Row[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]]]:
    try:
      select_stmt: Select[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] = select(
        cls.id,
        cls.server,
        cls.doh_server,
        cls.description,
        cls.created_at,
        cls.updated_at
      )
      if start_date != None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
      if end_date != None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
      if default != None and default == False: # We don't include default in the sample
        select_stmt = select_stmt.where(cls.id > 0)
      if search_text != None:
        select_stmt = select_stmt.where(
          or_(
            cls.server.contains(search_text),
            cls.doh_server.contains(search_text)
          )
        )
      select_limit_stmt: Select[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] = \
        select_stmt.limit(limit).offset(offset)
      exec_result: Result[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] = \
        await db_session.execute(select_limit_stmt)
      return exec_result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self],
    db_session: AsyncSession,
    id: int
  ) -> Optional[Row[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]]]:
    try:
      select_stmt: Select[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] = select(
        cls.id,
        cls.server,
        cls.doh_server,
        cls.description,
        cls.created_at,
        cls.updated_at
      ).where(cls.id == id)
      exec_result: Result[Tuple[int, str | None, str | None, str | None, datetime, datetime | None]] = \
        await db_session.execute(select_stmt)
      return exec_result.fetchone()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_for_resolve(
    cls: type[Self],
    db_session: AsyncSession
  ) -> Sequence[Row[Tuple[str | None, str | None, DnsServerType]]]:
    try:
      # user DNS servers
      select_stmt_normal: Select[Tuple[str | None, str | None, DnsServerType]] = select(
        cls.server,
        cls.doh_server,
        case(
          (cls.server != None, DnsServerType.DEFAULT),
          (cls.doh_server != None, DnsServerType.DOH),
          else_ = DnsServerType.UNKNOWN
        ).label('type')
      ).where(cls.id > 0)
      # default DNS server (one record)
      select_stmt_default = select(
        cls.server,
        cls.doh_server,
        case(
          (cls.server != None, DnsServerType.DEFAULT),
          (cls.doh_server != None, DnsServerType.DOH),
          else_ = DnsServerType.UNKNOWN
        ).label('type')
      ).where(cls.id == 0, ~exists(select(1).where(cls.id > 0)))
      # union
      select_stmt_union: CompoundSelect[Tuple[str | None, str | None, DnsServerType]] = \
        union_all(select_stmt_normal, select_stmt_default)
      exec_result: Result[Tuple[str | None, str | None, DnsServerType]] = \
        await db_session.execute(select_stmt_union)
      return exec_result.fetchall()
    except Exception as err:
      raise err
