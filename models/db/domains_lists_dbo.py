from datetime import datetime, timedelta
from sqlalchemy import (
  select,
  text,
  or_,
  and_,
  literal,
  union_all,
  func,
  Index,
  Row,
  Select,
  Result,
  CheckConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT,
  CTE
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy import inspect as sa_inspect
from typing import Optional, Tuple, Self, Sequence, List

from config.config import settings

from .base_dbo import Dbo, GRANULARITY_FORMAT
from .ips_lists_dbo import IpsListsDbo

from models.dto.domains_lists_dto import DomainsListDto
from models.http.base import DATE_FORMAT
from models.http.statistics_req import GrowthGranularity, GrowthDateField

class DomainsListsDbo(Dbo):
  '''
  Domains lists table
  '''

  __tablename__ = 'domains_lists'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)

  name: Mapped[str] = mapped_column(TEXT, unique=True, index=True, nullable=False)
  url: Mapped[str] = mapped_column(TEXT, nullable=False)
  description: Mapped[Optional[str]] = mapped_column(TEXT, nullable=True)
  hash: Mapped[Optional[str]] = mapped_column(TEXT, nullable=True)
  attempts: Mapped[int] = mapped_column(INTEGER, nullable=False, default=0) # If attempts > settings(attempts_limit), then the file is no longer available

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, index=True, server_default=func.now())
  updated_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("name != ''", name='name_chk'),
    CheckConstraint("url != ''", name='url_chk'),
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
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search_text: Optional[str] = None,
    attempts: Optional[int] = None
  ) -> Sequence[Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]]]:
    try:
      select_stmt: Select[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = select(
        cls.id,
        cls.name,
        cls.url,
        cls.description,
        cls.hash,
        cls.attempts,
        cls.created_at,
        cls.updated_at
      )
      if start_date != None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
      if end_date != None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
      if search_text != None:
        select_stmt = select_stmt.where(
          or_(
            cls.name.contains(search_text),
            cls.url.contains(search_text)
          )
        )
      if attempts != None:
        select_stmt = select_stmt.where(cls.attempts == attempts)
      select_limit_stmt: Select[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = \
        select_stmt.limit(limit).offset(offset)
      exec_result: Result[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = \
        await db_session.execute(select_limit_stmt)
      #
      return exec_result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_for_update(cls: type[Self], db_session: AsyncSession, forced: bool) -> List[DomainsListDto]:
    try:
      select_stmt: Select[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = select(
        cls.id,
        cls.name,
        cls.url,
        cls.description,
        cls.hash,
        cls.attempts,
        cls.created_at,
        cls.updated_at
      ).where(
        cls.attempts < settings.attempts_limit
      )
      if forced is False:
        elapsed_expr = func.coalesce(
          func.unixepoch(func.current_timestamp()) - func.unixepoch(cls.updated_at),
          settings.lists_update_interval_sec
        )
        select_stmt = select_stmt.where(
          or_(
            cls.updated_at.is_(None),
            elapsed_expr >= settings.lists_update_interval_sec
          )
        )
      #
      exec_result: Result[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = \
        await db_session.execute(select_stmt)
      result: List[DomainsListDto] = [
        DomainsListDto(
          id=row[0],
          name=row[1],
          url=row[2],
          description=row[3],
          hash=row[4],
          attempts=row[5],
          created_at=row[6],
          updated_at=row[7]
        )
        for row in exec_result.fetchall()
      ]
      return result
    except Exception as err:
        raise err

  @classmethod
  async def get_on_id(
    cls: type[Self],
    db_session: AsyncSession,
    id: int
  ) -> Optional[Row[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]]]:
    try:
      select_stmt: Select[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = select(
        cls.id,
        cls.name,
        cls.url,
        cls.description,
        cls.hash,
        cls.attempts,
        cls.created_at,
        cls.updated_at
      ).where(cls.id == id)
      exec_result: Result[Tuple[int, str, str, str | None, str | None, int, datetime, datetime | None]] = \
        await db_session.execute(select_stmt)
      return exec_result.fetchone()
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
      date_domains_lists_col: InstrumentedAttribute = getattr(cls, date_field)
      date_ips_lists_col: InstrumentedAttribute = getattr(IpsListsDbo, date_field)
      domains_lists_stmt = select(date_domains_lists_col.label('dt'))
      ips_lists_stmt = select(date_ips_lists_col.label('dt'))
      if col_nullable:
        domains_lists_stmt = domains_lists_stmt.where(date_domains_lists_col.is_not(None))
        ips_lists_stmt = ips_lists_stmt.where(date_ips_lists_col.is_not(None))
      all_lists_subq = union_all(domains_lists_stmt, ips_lists_stmt).subquery('all_lists')
      #
      date_expr = func.strftime(label_fmt, all_lists_subq.c.dt)
      list_counts_cte: CTE = (
        select(
          date_expr.label('date_label'),
          func.count().label('cnt')
        )
        .where(all_lists_subq.c.dt >= start_dt)
        .where(all_lists_subq.c.dt <= end_dt)
        .group_by(date_expr)
        .cte('list_counts')
      )
      #
      # Final: LEFT JOIN date series with domain counts
      #
      date_label_expr = func.strftime(label_fmt, date_series_cte.c.d)
      select_stmt: Select[Tuple[str, int]] = (
        select(
          date_label_expr.label('date'),
          func.coalesce(list_counts_cte.c.cnt, 0).label('count')
        )
        .outerjoin(
          list_counts_cte,
          date_label_expr == list_counts_cte.c.date_label
        )
        .order_by(date_series_cte.c.d)
      )
      #
      exec_result: Result[Tuple[str, int]] = await db_session.execute(select_stmt)
      return exec_result.all()
    except Exception as err:
      raise err
