from collections.abc import Sequence
from datetime import UTC, datetime
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

from config.config import settings
from models.http.base import DATE_FORMAT
from models.http.statistics_req import GrowthDateField, GrowthGranularity

from .base_dbo import GRANULARITY_FORMAT, Dbo
from .domains_lists_dbo import DomainsListsDbo


class DomainsDbo(Dbo):
  """
  Domains table
  default: Default Domain / ID=0
  """

  # __tablename__ is prefixed by the common mapped base during class creation.
  __tablename__ = 'domains'

  # id is the persistent identity; zero is reserved for the default context.
  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  # domain_list_id associates imported domains with their owning list.
  domain_list_id: Mapped[int | None] = mapped_column(INTEGER, index=True, nullable=True)

  # resolved records that a complete saving resolution has established a checkpoint.
  resolved: Mapped[bool] = mapped_column(BOOLEAN, default=False, nullable=False)
  # name is the unique DNS name used for resolution and lookup.
  name: Mapped[str] = mapped_column(TEXT, unique=True, index=True, nullable=False)
  # ros_comment carries optional RouterOS metadata for this domain.
  ros_comment: Mapped[str | None] = mapped_column(TEXT, nullable=True)

  # created_at is generated at insertion; updated_at retains its existing runtime onupdate behavior.
  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, index=True, server_default=func.now())
  updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)
  # last_resolved_at advances only when complete DNS evidence is committed.
  last_resolved_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, index=True, nullable=True)
  # last_attempt_at is the committed processing completion time, including partial and failed attempts.
  last_attempt_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, nullable=True)

  # __table_args__ preserves domain validity, parent ownership and the partial update-date index.
  __table_args__ = (
    CheckConstraint("name != ''", name='name_chk'),
    ForeignKeyConstraint(['domain_list_id'], [DomainsListsDbo.id], name='domain_list_id_fk', ondelete='CASCADE'),
    Index(f'ix_{__tablename__}_updated_at', 'updated_at', sqlite_where=text('updated_at IS NOT NULL')),
  )

  # get_total in Base class
  # add_batch (insert) in Base class

  @classmethod
  async def get_all(
    cls: type[Self],
    db_session: AsyncSession,
    limit: int,
    offset: int,
    resolved: bool | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    default: bool | None = None,
    search_text: str | None = None,
  ) -> tuple[
    Sequence[Row[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None, datetime | None]],
    int,
  ]:
    """Read a filtered domain page and matching count within the caller's session.

    limit and offset bound the page; resolved, start_date, end_date, default and
    search_text preserve the existing optional filters. The detached projection
    includes both checkpoint and attempt dates for the shared public response.
    """
    try:
      # select_stmt projects the domain fields in the order consumed by the response converter.
      select_stmt: Select[
        int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None, datetime | None
      ] = select(
        cls.id,
        cls.domain_list_id,
        cls.resolved,
        cls.name,
        cls.ros_comment,
        cls.created_at,
        cls.updated_at,
        cls.last_resolved_at,
        cls.last_attempt_at,
      )
      # select_query_total_stmt counts all matches before pagination is applied.
      select_query_total_stmt: Select[int] = select(func.count()).select_from(cls)
      if resolved is not None:
        select_stmt = select_stmt.where(cls.resolved == resolved)
        select_query_total_stmt = select_query_total_stmt.where(cls.resolved == resolved)
      if start_date is not None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
        select_query_total_stmt = select_query_total_stmt.where(cls.created_at >= start_date)
      if end_date is not None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
        select_query_total_stmt = select_query_total_stmt.where(cls.created_at <= end_date)
      if default is not None and not default:  # We don't include default in the sample
        select_stmt = select_stmt.where(cls.id > 0)
        select_query_total_stmt = select_query_total_stmt.where(cls.id > 0)
      if search_text is not None:
        select_stmt = select_stmt.where(cls.name.contains(search_text))
        select_query_total_stmt = select_query_total_stmt.where(cls.name.contains(search_text))
      # select_limit_stmt applies page bounds without changing the count query.
      select_limit_stmt = select_stmt.limit(limit).offset(offset)
      # result_query_total is the full match count; result contains only the selected page.
      result_query_total: Result[int] = await db_session.execute(select_query_total_stmt)
      result: Result[
        int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None, datetime | None
      ] = await db_session.execute(select_limit_stmt)
      #
      return result.fetchall(), result_query_total.scalar_one()
    # err propagates execution failure to the database response boundary.
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self], db_session: AsyncSession, id: int
  ) -> Row[int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None, datetime | None] | None:
    """Read the public domain projection for id, or None when it is absent."""
    try:
      # select_stmt uses the same field order as the paginated domain projection.
      select_stmt: Select[
        int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None, datetime | None
      ] = select(
        cls.id,
        cls.domain_list_id,
        cls.resolved,
        cls.name,
        cls.ros_comment,
        cls.created_at,
        cls.updated_at,
        cls.last_resolved_at,
        cls.last_attempt_at,
      ).where(cls.id == id)
      # exec_result contains at most one row because id is the primary key.
      exec_result: Result[
        int, int | None, bool, str, str | None, datetime, datetime | None, datetime | None, datetime | None
      ] = await db_session.execute(select_stmt)
      return exec_result.fetchone()
    # err propagates execution failure to the database response boundary.
    except Exception as err:
      raise err

  @classmethod
  async def get_total_on_domains_list(cls: type[Self], db_session: AsyncSession, domains_list_id: int) -> int:
    try:
      select_stmt: Select[int] = select(func.count()).select_from(cls).where(cls.domain_list_id == domains_list_id)
      exec_result: Result[int] = await db_session.execute(select_stmt)
      return exec_result.scalar_one()
    except Exception as err:
      raise err

  @classmethod
  async def get_total_resolved(cls: type[Self], db_session: AsyncSession) -> int:
    try:
      select_stmt: Select[int] = select(func.count()).select_from(cls).where(cls.resolved.is_(True))
      exec_result: Result[int] = await db_session.execute(select_stmt)
      return exec_result.scalar_one()
    except Exception as err:
      raise err

  @classmethod
  async def get_stale_for_resolve(
    cls: type[Self], db_session: AsyncSession, limit: int | None = None
  ) -> Sequence[Row[int, str, int | None, int]]:
    """Select domains whose effective attempt date has reached the retry interval.

    db_session belongs to the caller; optional limit bounds this ordered snapshot.
    A historical checkpoint supplies the effective date until an attempt exists.
    """
    try:
      # effective_date prefers the last attempt while retaining historical checkpoint eligibility.
      effective_date = func.coalesce(cls.last_attempt_at, cls.last_resolved_at)
      # elapsed_expr is the elapsed whole seconds used by the existing retry interval.
      elapsed_expr = func.coalesce(func.unixepoch(func.current_timestamp()) - func.unixepoch(effective_date), 0)
      # select_stmt captures eligible nondefault descriptors in effective-date and ID order.
      select_stmt: Select[int, str, int | None, int] = (
        select(cls.id, cls.name, cls.domain_list_id, elapsed_expr.label('elapsed'))
        .where(cls.id > 0, effective_date.is_not(None), elapsed_expr >= settings.domains_update_interval)
        .order_by(effective_date, cls.id)
        .limit(limit)
      )
      # result contains detached descriptors with their scheduling age.
      result: Result[int, str, int | None, int] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    # err is translated by the database selection boundary.
    except Exception as err:
      raise err

  @classmethod
  async def get_new_for_resolve(
    cls: type[Self], db_session: AsyncSession, limit: int | None = None
  ) -> Sequence[Row[int, str, int | None, int]]:
    """Select undated nondefault domains by ID, optionally bounded by limit.

    db_session is caller-owned. A domain with either an attempt or a historical
    checkpoint belongs to interval-based scheduling rather than this NEW set.
    """
    try:
      # select_stmt captures a finite ordered selection with zero elapsed age.
      select_stmt: Select[int, str, int | None, int] = (
        select(cls.id, cls.name, cls.domain_list_id, literal(0).label('elapsed'))
        .where(cls.id > 0, cls.last_attempt_at.is_(None), cls.last_resolved_at.is_(None))
        .order_by(cls.id)
        .limit(limit)
      )
      # result holds the selected lightweight descriptors for the caller.
      result: Result[int, str, int | None, int] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    # err is translated by the database selection boundary.
    except Exception as err:
      raise err

  @classmethod
  async def get_all_on_domains_list(
    cls: type[Self], db_session: AsyncSession, domains_list_id: int
  ) -> Sequence[Row[int, str]]:
    try:
      select_stmt: Select[int, str] = select(cls.id, cls.name).where(cls.domain_list_id == domains_list_id)
      result: Result[int, str] = await db_session.execute(select_stmt)
      #
      return result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_stats(cls: type[Self], db_session: AsyncSession) -> Row[int, int, int, int, Any]:
    try:
      #
      # CTE 1
      #
      domain_stats_cte: CTE = select(
        func.count(cls.id).label('total'),
        func.sum(case((cls.resolved.is_(True), 1), else_=0)).label('resolved'),
        func.sum(case((cls.resolved.is_(False), 1), else_=0)).label('unresolved'),
      ).cte('domain_stats')
      #
      # CTE 2
      #
      per_list_stats_cte: CTE = (
        select(
          DomainsListsDbo.id.label('list_id'),
          DomainsListsDbo.name.label('list_name'),
          DomainsListsDbo.attempts.label('attempts'),
          func.count(cls.id).label('total'),
          func.sum(case((cls.resolved.is_(True), 1), else_=0)).label('resolved'),
          func.sum(case((cls.resolved.is_(False), 1), else_=0)).label('unresolved'),
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
      lists_total_scalar: ScalarSelect[int] = select(func.count(DomainsListsDbo.id)).scalar_subquery()
      #
      # JSON per_list
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
              'resolved',
              per_list_stats_cte.c.resolved,
              'unresolved',
              per_list_stats_cte.c.unresolved,
              'attempts',
              per_list_stats_cte.c.attempts,
            )
          )
        )
        .select_from(per_list_stats_cte)
        .scalar_subquery()
      )
      #
      # Final
      #
      select_stmt: Select[int, int, int, int, Any] = select(
        domain_stats_cte.c.total,
        domain_stats_cte.c.resolved,
        domain_stats_cte.c.unresolved,
        lists_total_scalar.label('lists_total'),
        per_list_json_scalar.label('per_list'),
      )
      exec_result: Result[int, int, int, int, Any] = await db_session.execute(select_stmt)
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
  ) -> Sequence[Row[str, int]]:
    try:
      date_col: InstrumentedAttribute = getattr(cls, date_field)
      col_nullable: bool = sa_inspect(cls).columns[date_field].nullable
      now: datetime = datetime.now(UTC).astimezone().replace(tzinfo=None)
      start_dt: datetime = datetime.strptime(start_date, DATE_FORMAT).replace(tzinfo=UTC) if start_date else now
      end_dt: datetime = datetime.strptime(end_date, DATE_FORMAT).replace(tzinfo=UTC) if end_date else now
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
      domain_counts_cte: CTE = counts_stmt.cte('domain_counts')
      #
      # Final: LEFT JOIN date series with domain counts
      #
      date_label_expr = func.strftime(label_fmt, date_series_cte.c.d)
      select_stmt: Select[str, int] = (
        select(date_label_expr.label('date'), func.coalesce(domain_counts_cte.c.cnt, 0).label('count'))
        .outerjoin(
          domain_counts_cte,
          date_label_expr == domain_counts_cte.c.date_label,
        )
        .order_by(date_series_cte.c.d)
      )
      #
      exec_result: Result[str, int] = await db_session.execute(select_stmt)
      return exec_result.all()
    except Exception as err:
      raise err
