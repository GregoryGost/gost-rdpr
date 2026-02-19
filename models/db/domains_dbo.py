from datetime import datetime
from sqlalchemy import (
  select,
  or_,
  text,
  case,
  literal,
  func,
  Index,
  Row,
  Select,
  ScalarSelect,
  Result,
  CheckConstraint,
  ForeignKeyConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT,
  BOOLEAN,
  CTE
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy import inspect as sa_inspect
from typing import Optional, Tuple, Self, Sequence, Any

from config.config import settings

from .base_dbo import Dbo, GRANULARITY_FORMAT
from .domains_lists_dbo import DomainsListsDbo

from models.http.base import DATE_FORMAT
from models.http.statistics_req import GrowthGranularity, GrowthDateField

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

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, index=True, server_default=func.now())
  updated_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)
  last_resolved_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, index=True, nullable=True)

  __table_args__ = (
    CheckConstraint("name != ''", name='name_chk'),
    ForeignKeyConstraint(['domain_list_id'], [DomainsListsDbo.id], name='domain_list_id_fk', ondelete='CASCADE'),
    Index(f'ix_{__tablename__}_updated_at', 'updated_at', sqlite_where=text('updated_at IS NOT NULL'))
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

  @classmethod
  async def get_stats(
    cls: type[Self],
    db_session: AsyncSession
  ) -> Row[Tuple[int, int, int, int, Any]]:
    try:
      #
      # CTE 1
      #
      domain_stats_cte: CTE = (
        select(
          func.count(cls.id).label('total'),
          func.sum(
            case((cls.resolved.is_(True), 1), else_=0)
          ).label('resolved'),
          func.sum(
            case((cls.resolved.is_(False), 1), else_=0)
          ).label('unresolved'),
        )
        .cte('domain_stats')
      )
      #
      # CTE 2
      #
      per_list_stats_cte: CTE = (
        select(
          DomainsListsDbo.id.label('list_id'),
          DomainsListsDbo.name.label('list_name'),
          DomainsListsDbo.attempts.label('attempts'),
          func.count(cls.id).label('total'),
          func.sum(
            case((cls.resolved.is_(True), 1), else_=0)
          ).label('resolved'),

          func.sum(
            case((cls.resolved.is_(False), 1), else_=0)
          ).label('unresolved'),
        )
        .select_from(DomainsListsDbo)
        .join(
          cls,
          cls.domain_list_id == DomainsListsDbo.id,
          isouter=True,
        )
        .group_by(DomainsListsDbo.id)
        .cte('per_list_stats')
      )
      #
      # Lists
      #
      lists_total_scalar: ScalarSelect[int] = (
        select(func.count(DomainsListsDbo.id))
        .scalar_subquery()
      )
      #
      # JSON per_list
      #
      per_list_json_scalar: ScalarSelect[Any] = (
        select(
          func.json_group_array(
            func.json_object(
              'list_id', per_list_stats_cte.c.list_id,
              'list_name', per_list_stats_cte.c.list_name,
              'total', per_list_stats_cte.c.total,
              'resolved', per_list_stats_cte.c.resolved,
              'unresolved', per_list_stats_cte.c.unresolved,
              'attempts', per_list_stats_cte.c.attempts,
            )
          )
        )
        .select_from(per_list_stats_cte)
        .scalar_subquery()
      )
      #
      # Final
      #
      select_stmt: Select[Tuple[int, int, int, int, Any]] = select(
        domain_stats_cte.c.total,
        domain_stats_cte.c.resolved,
        domain_stats_cte.c.unresolved,
        lists_total_scalar.label('lists_total'),
        per_list_json_scalar.label('per_list')
      )
      exec_result: Result[Tuple[int, int, int, int, Any]] = await db_session.execute(select_stmt)
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
    end_date: str | None = None
  ) -> Sequence[Row[Tuple[str, int]]]:
    try:
      date_col: InstrumentedAttribute = getattr(cls, date_field)
      col_nullable: bool = sa_inspect(cls).columns[date_field].nullable
      now: datetime = datetime.now()
      start_dt: datetime = (
        datetime.strptime(start_date, DATE_FORMAT)
        if start_date
        else now
      )
      end_dt: datetime = (
        datetime.strptime(end_date, DATE_FORMAT)
        if end_date
        else now
      )
      raw_fmt, label_fmt, step = GRANULARITY_FORMAT[granularity]
      start_raw: str = start_dt.strftime(raw_fmt)
      end_raw: str = end_dt.strftime(raw_fmt)
      #
      # CTE 1
      #
      date_series_cte: CTE = (
        select(literal(start_raw).label('d'))
        .cte('date_series', recursive=True)
      )
      match granularity:
        case GrowthGranularity.MINUTE | GrowthGranularity.HOUR:
          next_d = func.datetime(date_series_cte.c.d, literal(step))
        case _:
          next_d = func.date(date_series_cte.c.d, literal(step))
      date_series_cte = date_series_cte.union_all(
        select(next_d.label('d'))
        .where(date_series_cte.c.d < end_raw)
      )
      #
      # CTE 2
      #
      date_expr = func.strftime(label_fmt, date_col)
      counts_stmt: Select[Tuple[Any, int]] = (
        select(
          date_expr.label('date_label'),
          func.count(cls.id).label('cnt')
        )
        .where(date_col >= start_dt)
        .where(date_col <= end_dt)
        .group_by(date_expr)
      )
      if col_nullable:
        counts_stmt = counts_stmt.where(date_col.is_not(None))
      domain_counts_cte: CTE = counts_stmt.cte('domain_counts')
      #
      # Final: LEFT JOIN date series with domain counts
      #
      date_label_expr = func.strftime(label_fmt, date_series_cte.c.d)
      select_stmt: Select[Tuple[str, int]] = (
        select(
          date_label_expr.label('date'),
          func.coalesce(domain_counts_cte.c.cnt, 0).label('count')
        )
        .outerjoin(
          domain_counts_cte,
          date_label_expr == domain_counts_cte.c.date_label,
        )
        .order_by(date_series_cte.c.d)
      )
      #
      exec_result: Result[Tuple[str, int]] = await db_session.execute(select_stmt)
      return exec_result.all()
    except Exception as err:
      raise err
