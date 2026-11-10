from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import batched
from typing import Any, Self

from sqlalchemy import (
  BOOLEAN,
  CTE,
  INTEGER,
  TEXT,
  TIMESTAMP,
  CheckConstraint,
  ForeignKeyConstraint,
  Index,
  Result,
  Row,
  ScalarSelect,
  Select,
  case,
  func,
  literal,
  select,
  text,
)
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm.attributes import InstrumentedAttribute

from models.http.base import DATE_FORMAT
from models.http.statistics_req import GrowthDateField, GrowthGranularity

from .base_dbo import GRANULARITY_FORMAT, Dbo
from .domains_dbo import DomainsDbo
from .ips_lists_dbo import IpsListsDbo


class IpRecordsDbo(Dbo):
  """
  IP address records table
  """

  __tablename__ = 'ip_records'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  ip_list_id: Mapped[int | None] = mapped_column(INTEGER, index=True, nullable=True)
  domain_id: Mapped[int | None] = mapped_column(INTEGER, index=True, nullable=True)

  addr_type: Mapped[int] = mapped_column(INTEGER, nullable=False)
  ip_address: Mapped[str] = mapped_column(TEXT, unique=True, index=True, nullable=False)
  ros_comment: Mapped[str | None] = mapped_column(TEXT, nullable=True)
  use_default_gw: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text('0'))

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("ip_address != ''", name='ip_address_chk'),
    ForeignKeyConstraint(['ip_list_id'], [IpsListsDbo.id], name='ip_list_id_fk', ondelete='SET NULL'),
    ForeignKeyConstraint(['domain_id'], [DomainsDbo.id], name='domain_id_fk', ondelete='SET NULL'),
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
    search_text: str | None = None,
    addr_type: int | None = None,
    use_default_gw: bool | None = None,
  ) -> Sequence[Row[int, int | None, str, int | None, str, int, str, str | None, bool, datetime, datetime | None]]:
    try:
      select_stmt: Select[
        int, int | None, str, int | None, str, int, str, str | None, bool, datetime, datetime | None
      ] = (
        select(
          cls.id,
          cls.ip_list_id,
          IpsListsDbo.name,
          cls.domain_id,
          DomainsDbo.name,
          cls.addr_type,
          cls.ip_address,
          cls.ros_comment,
          cls.use_default_gw,
          cls.created_at,
          cls.updated_at,
        )
        .join(IpsListsDbo, IpsListsDbo.id == cls.ip_list_id, isouter=True)
        .join(DomainsDbo, DomainsDbo.id == cls.domain_id, isouter=True)
      )
      if use_default_gw is not None:
        select_stmt = select_stmt.where(cls.use_default_gw == use_default_gw)
      if addr_type is not None:
        select_stmt = select_stmt.where(cls.addr_type == addr_type)
      if start_date is not None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
      if end_date is not None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
      if search_text is not None:
        select_stmt = select_stmt.where(cls.ip_address.contains(search_text))
      select_limit_stmt: Select[
        int, int | None, str, int | None, str, int, str, str | None, bool, datetime, datetime | None
      ] = select_stmt.limit(limit).offset(offset)
      result: Result[
        int, int | None, str, int | None, str, int, str, str | None, bool, datetime, datetime | None
      ] = await db_session.execute(select_limit_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_ips_on_domain_id(
    cls: type[Self], db_session: AsyncSession, domain_id: int
  ) -> tuple[list[str], list[str]]:
    try:
      select_stmt: Select[str, int] = select(cls.ip_address, cls.addr_type).where(
        cls.id.in_(select(IpSupportDbo.ip_record_id).where(IpSupportDbo.domain_id == domain_id))
      )
      exec_result: Result[str, int] = await db_session.execute(select_stmt)
      result: Sequence[Row[str, int]] = exec_result.fetchall()
      ip_addr_v4: list[str] = [ip.ip_address for ip in result if ip.addr_type == 4]
      ip_addr_v6: list[str] = [ip.ip_address for ip in result if ip.addr_type == 6]
      return ip_addr_v4, ip_addr_v6
    except Exception as err:
      raise err

  @classmethod
  async def get_ips_on_domain_ids(
    cls: type[Self], db_session: AsyncSession, domain_ids: list[int]
  ) -> dict[int, tuple[list[str], list[str]]]:
    """Read each supported global IP once per domain, preserving global IP order."""
    result: dict[int, tuple[list[str], list[str]]] = {domain_id: ([], []) for domain_id in domain_ids}
    # Bound the parameter count for large configured pages.
    for portion in batched(result, 500, strict=False):
      select_stmt = (
        select(IpSupportDbo.domain_id, cls.id, cls.ip_address, cls.addr_type)
        .select_from(IpSupportDbo)
        .join(cls, cls.id == IpSupportDbo.ip_record_id)
        .where(IpSupportDbo.domain_id.in_(portion))
        .distinct()
        .order_by(IpSupportDbo.domain_id, cls.id)
      )
      rows = await db_session.execute(select_stmt)
      for domain_id, _ip_id, address, addr_type in rows:
        if addr_type == 4:
          result[domain_id][0].append(address)
        elif addr_type == 6:
          result[domain_id][1].append(address)
    return result

  @classmethod
  async def get_total_ips_on_ips_list(cls: type[Self], db_session: AsyncSession, ip_list_id: int) -> tuple[int, int]:
    try:
      ip_v4_count: int = 0
      ip_v6_count: int = 0
      select_stmt: Select[int, int] = (
        select(cls.addr_type, func.count())
        .where(cls.id.in_(select(IpSupportDbo.ip_record_id).where(IpSupportDbo.ip_list_id == ip_list_id)))
        .group_by(cls.addr_type)
      )
      exec_result = await db_session.execute(select_stmt)
      result: Sequence[Row[int, int]] = exec_result.fetchall()
      for type, count in result:
        if type == 4:
          ip_v4_count += count
        if type == 6:
          ip_v6_count += count
      return ip_v4_count, ip_v6_count
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self], db_session: AsyncSession, id: int
  ) -> Row[int, int | None, str, int | None, str, str, int, str | None, bool, datetime, datetime | None] | None:
    try:
      select_stmt: Select[
        int, int | None, str, int | None, str, str, int, str | None, bool, datetime, datetime | None
      ] = (
        select(
          cls.id,
          cls.ip_list_id,
          IpsListsDbo.name,
          cls.domain_id,
          DomainsDbo.name,
          cls.ip_address,
          cls.addr_type,
          cls.ros_comment,
          cls.use_default_gw,
          cls.created_at,
          cls.updated_at,
        )
        .where(cls.id == id)
        .join(IpsListsDbo, IpsListsDbo.id == cls.ip_list_id, isouter=True)
        .join(DomainsDbo, DomainsDbo.id == cls.domain_id, isouter=True)
      )
      exec_result: Result[
        int, int | None, str, int | None, str, str, int, str | None, bool, datetime, datetime | None
      ] = await db_session.execute(select_stmt)
      result: (
        Row[int, int | None, str, int | None, str, str, int, str | None, bool, datetime, datetime | None] | None
      ) = exec_result.fetchone()
      return result
    except Exception as err:
      raise err

  @classmethod
  async def get_all_ids_and_addresses(cls: type[Self], db_session: AsyncSession) -> Sequence[Row[int, str]]:
    try:
      select_stmt: Select[int, str] = select(cls.id, cls.ip_address).order_by(cls.id)
      result: Result[int, str] = await db_session.execute(select_stmt)
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_ips_on_domain_id_extend(
    cls: type[Self], db_session: AsyncSession, domain_id: int
  ) -> Sequence[Row[int, str, int]]:
    try:
      select_stmt: Select[int, str, int] = select(cls.id, cls.ip_address, cls.addr_type).where(
        cls.id.in_(select(IpSupportDbo.ip_record_id).where(IpSupportDbo.domain_id == domain_id))
      )
      exec_result: Result[int, str, int] = await db_session.execute(select_stmt)
      result: Sequence[Row[int, str, int]] = exec_result.fetchall()
      return result
    except Exception as err:
      raise err

  @classmethod
  async def get_all_on_ips_list(cls: type[Self], db_session: AsyncSession, ip_list_id: int) -> Sequence[Row[int, str]]:
    try:
      select_stmt: Select[int, str] = select(cls.id, cls.ip_address).where(
        cls.id.in_(select(IpSupportDbo.ip_record_id).where(IpSupportDbo.ip_list_id == ip_list_id))
      )
      result: Result[int, str] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_for_update(
    cls: type[Self], db_session: AsyncSession, addr_type: int | None = None
  ) -> Sequence[Row[str, str, bool, int]]:
    try:
      select_stmt: Select[str, str, bool, int] = select(
        cls.ip_address,
        func.coalesce(cls.ros_comment, DomainsDbo.ros_comment, DomainsDbo.name).label('comment'),
        cls.use_default_gw,
        cls.addr_type,
      ).join(DomainsDbo, DomainsDbo.id == cls.domain_id, isouter=True)
      if addr_type is not None:
        select_stmt = select_stmt.where(cls.addr_type == addr_type)
      result: Result[str, str, bool, int] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_stats(cls: type[Self], db_session: AsyncSession) -> Row[int, int, int, int, int, int, Any]:
    try:
      #
      # CTE 1
      #
      ip_stats_cte: CTE = select(
        func.count(cls.id).label('total'),
        func.sum(case((cls.addr_type == 4, 1), else_=0)).label('v4_total'),
        func.sum(case((cls.addr_type == 6, 1), else_=0)).label('v6_total'),
        func.sum(case((cls.domain_id != 0, 1), else_=0)).label('linked_to_domain'),
        func.sum(case((cls.domain_id == 0, 1), else_=0)).label('standalone'),
      ).cte('ip_stats')
      #
      # CTE 2
      #
      list_members = (
        select(IpSupportDbo.ip_list_id, IpSupportDbo.ip_record_id)
        .where(IpSupportDbo.ip_list_id.is_not(None))
        .distinct()
        .subquery()
      )
      per_list_stats_cte: CTE = (
        select(
          IpsListsDbo.id.label('list_id'),
          IpsListsDbo.name.label('list_name'),
          IpsListsDbo.attempts.label('attempts'),
          func.count(cls.id).label('total'),
          func.sum(case((cls.addr_type == 4, 1), else_=0)).label('v4_count'),
          func.sum(case((cls.addr_type == 6, 1), else_=0)).label('v6_count'),
        )
        .select_from(IpsListsDbo)
        .join(list_members, list_members.c.ip_list_id == IpsListsDbo.id, isouter=True)
        .join(cls, cls.id == list_members.c.ip_record_id, isouter=True)
        .group_by(IpsListsDbo.id)
        .cte('per_list_stats')
      )
      #
      # Lists total
      #
      lists_total_scalar: ScalarSelect[int] = select(func.count(IpsListsDbo.id)).scalar_subquery()
      #
      # JSON aggregate
      #
      per_list_json_scalar: ScalarSelect[Any] = (
        select(
          func.json_group_array(
            func.json_object(
              'list_id',
              per_list_stats_cte.c.list_id,
              'list_name',
              per_list_stats_cte.c.list_name,
              'total',
              per_list_stats_cte.c.total,
              'v4_count',
              per_list_stats_cte.c.v4_count,
              'v6_count',
              per_list_stats_cte.c.v6_count,
              'attempts',
              per_list_stats_cte.c.attempts,
            )
          )
        )
        .select_from(per_list_stats_cte)
        .scalar_subquery()
      )
      #
      # Final select
      #
      select_stmt: Select[int, int, int, int, int, int, Any] = select(
        ip_stats_cte.c.total,
        ip_stats_cte.c.v4_total,
        ip_stats_cte.c.v6_total,
        ip_stats_cte.c.linked_to_domain,
        ip_stats_cte.c.standalone,
        lists_total_scalar.label('lists_total'),
        per_list_json_scalar.label('per_list'),
      )
      exec_result: Result[int, int, int, int, int, int, Any] = await db_session.execute(select_stmt)
      return exec_result.one()
    except Exception as err:
      raise err

  @classmethod
  async def get_stats_growth(
    cls: type[Self],
    db_session: AsyncSession,
    granularity: GrowthGranularity,
    date_field: GrowthDateField,
    start_date: str | None = None,
    end_date: str | None = None,
    ip_subtype: int | None = None,
  ) -> Sequence[Row[str, int]]:
    try:
      date_col: InstrumentedAttribute = getattr(cls, date_field)
      col_nullable: bool = sa_inspect(cls).columns[date_field].nullable
      now: datetime = datetime.now(UTC).astimezone().replace(tzinfo=None)
      start_dt: datetime = datetime.strptime(start_date, DATE_FORMAT) if start_date else now  # noqa: DTZ007 - SQL uses naive timestamps.
      end_dt: datetime = datetime.strptime(end_date, DATE_FORMAT) if end_date else now  # noqa: DTZ007 - SQL uses naive timestamps.
      raw_fmt, label_fmt, step = GRANULARITY_FORMAT[granularity]
      start_raw: str = start_dt.strftime(raw_fmt)
      end_raw: str = end_dt.strftime(raw_fmt)
      #
      # CTE 1
      #
      date_series_cte: CTE = select(literal(start_raw).label('d')).cte('date_series', recursive=True)
      match granularity:
        case GrowthGranularity.MINUTE | GrowthGranularity.HOUR:
          next_d = func.datetime(date_series_cte.c.d, literal(step))
        case GrowthGranularity.WEEK:
          # Calendar week labels change on Mondays and at the start of each year.
          next_monday = func.date(date_series_cte.c.d, '+1 day', 'weekday 1')
          next_year = func.date(date_series_cte.c.d, 'start of year', '+1 year')
          next_d = func.min(next_monday, func.coalesce(next_year, next_monday))
        case _:
          next_d = func.date(date_series_cte.c.d, literal(step))
      date_series_cte = date_series_cte.union_all(select(next_d.label('d')).where(next_d <= end_raw))
      #
      # CTE 2
      #
      date_expr = func.strftime(label_fmt, date_col)
      counts_stmt: Select[Any, int] = (
        select(date_expr.label('date_label'), func.count(cls.id).label('cnt'))
        .where(date_col >= start_dt)
        .where(date_col <= end_dt)
        .group_by(date_expr)
      )
      if col_nullable:
        counts_stmt = counts_stmt.where(date_col.is_not(None))
      if ip_subtype is not None:
        counts_stmt = counts_stmt.where(cls.addr_type == ip_subtype)
      ips_counts_cte: CTE = counts_stmt.cte('ips_counts')
      #
      # Final: LEFT JOIN date series with domain counts
      #
      date_label_expr = func.strftime(label_fmt, date_series_cte.c.d)
      select_stmt: Select[str, int] = (
        select(date_label_expr.label('date'), func.coalesce(ips_counts_cte.c.cnt, 0).label('count'))
        .outerjoin(
          ips_counts_cte,
          date_label_expr == ips_counts_cte.c.date_label,
        )
        .order_by(date_series_cte.c.d)
      )
      #
      exec_result: Result[str, int] = await db_session.execute(select_stmt)
      return exec_result.all()
    except Exception as err:
      raise err


class IpSupportDbo(Dbo):
  """Independent domain and list sources supporting one global IP entity."""

  __tablename__ = 'ip_supports'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  ip_record_id: Mapped[int] = mapped_column(INTEGER, nullable=False, index=True)
  domain_id: Mapped[int] = mapped_column(INTEGER, nullable=False, index=True)
  ip_list_id: Mapped[int | None] = mapped_column(INTEGER, nullable=True, index=True)

  __table_args__ = (
    ForeignKeyConstraint(['ip_record_id'], [IpRecordsDbo.id], ondelete='CASCADE'),
    ForeignKeyConstraint(['domain_id'], [DomainsDbo.id], ondelete='CASCADE'),
    ForeignKeyConstraint(['ip_list_id'], [IpsListsDbo.id], ondelete='CASCADE'),
    Index(None, 'ip_record_id', 'domain_id', unique=True, sqlite_where=text('ip_list_id IS NULL')),
    Index(None, 'ip_record_id', 'domain_id', 'ip_list_id', unique=True, sqlite_where=text('ip_list_id IS NOT NULL')),
  )
