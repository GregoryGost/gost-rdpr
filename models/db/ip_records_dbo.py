from datetime import datetime
from sqlalchemy import (
  select,
  func,
  Row,
  Select,
  Result,
  CheckConstraint,
  ForeignKeyConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List, Tuple, Self, Sequence

from .base_dbo import Dbo
from .ips_lists_dbo import IpsListsDbo
from .domains_dbo import DomainsDbo

class IpRecordsDbo(Dbo):
  '''
  IP address records table
  '''

  __tablename__ = 'ip_records'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  ip_list_id: Mapped[Optional[int]] = mapped_column(INTEGER, index=True, nullable=True)
  domain_id: Mapped[Optional[int]] = mapped_column(INTEGER, index=True, nullable=False)

  addr_type: Mapped[int] = mapped_column(INTEGER, nullable=False)
  ip_address: Mapped[str] = mapped_column(TEXT, unique=True, index=True, nullable=False)
  ros_comment: Mapped[Optional[str]] = mapped_column(TEXT, nullable=True)

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("ip_address != ''", name='ip_address_chk'),
    ForeignKeyConstraint(['ip_list_id'], [IpsListsDbo.id], name='ip_list_id_fk', ondelete='CASCADE'),
    ForeignKeyConstraint(['domain_id'], [DomainsDbo.id], name='domain_id_fk', ondelete='CASCADE')
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
    search_text: Optional[str] = None
  ) -> Sequence[Row[Tuple[int, int | None, str, int | None, str, int, str, str | None, datetime, datetime | None]]]:
    try:
      select_stmt: Select[Tuple[int, int | None, str, int | None, str, int, str, str | None, datetime, datetime | None]] = select(
        cls.id,
        cls.ip_list_id,
        IpsListsDbo.name,
        cls.domain_id,
        DomainsDbo.name,
        cls.addr_type,
        cls.ip_address,
        cls.ros_comment,
        cls.created_at,
        cls.updated_at
      ).join(
        IpsListsDbo, IpsListsDbo.id == cls.ip_list_id, isouter=True
      ).join(
        DomainsDbo, DomainsDbo.id == cls.domain_id, isouter=True
      )
      if start_date != None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
      if end_date != None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
      if search_text != None:
        select_stmt = select_stmt.where(cls.ip_address.contains(search_text))
      select_limit_stmt: Select[Tuple[int, int | None, str, int | None, str, int, str, str | None, datetime, datetime | None]] = \
        select_stmt.limit(limit).offset(offset)
      result: Result[Tuple[int, int | None, str, int | None, str, int, str, str | None, datetime, datetime | None]] = \
        await db_session.execute(select_limit_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_ips_on_domain_id(
    cls: type[Self],
    db_session: AsyncSession,
    domain_id: int
  ) -> Tuple[List[str], List[str]]:
    try:
      select_stmt: Select[Tuple[str, int]] = select(
        cls.ip_address,
        cls.addr_type
      ).where(cls.domain_id == domain_id)
      exec_result: Result[Tuple[str, int]] = await db_session.execute(select_stmt)
      result: Sequence[Row[Tuple[str, int]]] = exec_result.fetchall()
      ip_addr_v4: List[str] = [ip.ip_address for ip in result if ip.addr_type == 4]
      ip_addr_v6: List[str] = [ip.ip_address for ip in result if ip.addr_type == 6]
      return ip_addr_v4, ip_addr_v6
    except Exception as err:
      raise err
    
  @classmethod
  async def get_total_ips_on_ips_list(
    cls: type[Self],
    db_session: AsyncSession,
    ip_list_id: int
  ) -> Tuple[int, int]:
    try:
      ip_v4_count: int = 0
      ip_v6_count: int = 0
      select_stmt: Select[Tuple[int, int]] = select(
        cls.addr_type,
        func.count()
      ).where(
        cls.ip_list_id == ip_list_id
      ).group_by(cls.addr_type)
      exec_result = await db_session.execute(select_stmt)
      result: Sequence[Row[Tuple[int, int]]] = exec_result.fetchall()
      for type, count in result:
        if type == 4: ip_v4_count += count
        if type == 6: ip_v6_count += count
      return ip_v4_count, ip_v6_count
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self],
    db_session: AsyncSession,
    id: int
  ) -> Row[Tuple[int, int | None, str, int | None, str, str, int, str | None, datetime, datetime | None]] | None:
    try:
      select_stmt: Select[Tuple[int, int | None, str, int | None, str, str, int, str | None, datetime, datetime | None]] = select(
        cls.id,
        cls.ip_list_id,
        IpsListsDbo.name,
        cls.domain_id,
        DomainsDbo.name,
        cls.ip_address,
        cls.addr_type,
        cls.ros_comment,
        cls.created_at,
        cls.updated_at
      ).where(
        cls.id == id
      ).join(
        IpsListsDbo, IpsListsDbo.id == cls.ip_list_id, isouter=True
      ).join(
        DomainsDbo, DomainsDbo.id == cls.domain_id, isouter=True
      )
      exec_result: Result[Tuple[int, int | None, str, int | None, str, str, int, str | None, datetime, datetime | None]] = \
        await db_session.execute(select_stmt)
      result: Row[Tuple[int, int | None, str, int | None, str, str, int, str | None, datetime, datetime | None]] | None = \
        exec_result.fetchone()
      return result
    except Exception as err:
      raise err

  @classmethod
  async def get_ips_on_domain_id_extend(
    cls: type[Self],
    db_session: AsyncSession,
    domain_id: int
  ) -> Sequence[Row[Tuple[int, str, int]]]:
    try:
      select_stmt: Select[Tuple[int, str, int]] = select(
        cls.id,
        cls.ip_address,
        cls.addr_type
      ).where(cls.domain_id == domain_id)
      exec_result: Result[Tuple[int, str, int]] = await db_session.execute(select_stmt)
      result: Sequence[Row[Tuple[int, str, int]]] = exec_result.fetchall()
      return result
    except Exception as err:
      raise err

  @classmethod
  async def get_all_on_ips_list(
    cls: type[Self],
    db_session: AsyncSession,
    ip_list_id: int
  ) -> Sequence[Row[Tuple[int, str]]]:
    try:
      select_stmt: Select[Tuple[int, str]] = select(
        cls.id,
        cls.ip_address
      ).where(cls.ip_list_id == ip_list_id)
      result: Result[Tuple[int, str]] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_for_update(cls: type[Self], db_session: AsyncSession, addr_type: int | None = None):
    try:
      select_stmt: Select[Tuple[str, str | None]] = select(
        cls.ip_address,
        func.coalesce(cls.ros_comment, DomainsDbo.ros_comment, DomainsDbo.name).label('comment')
      ).join(
        DomainsDbo, DomainsDbo.id == cls.domain_id, isouter=True
      )
      if addr_type != None:
        select_stmt = select_stmt.where(cls.addr_type == addr_type)
      result: Result[Tuple[str, str | None]] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err
