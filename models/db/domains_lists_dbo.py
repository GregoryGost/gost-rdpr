from datetime import datetime, timedelta
from sqlalchemy import (
  select,
  or_,
  and_,
  func,
  Row,
  Select,
  Result,
  CheckConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT,
  BOOLEAN
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Tuple, Self, Sequence, List

from config.config import settings

from .base_dbo import Dbo

from models.dto.domains_lists_dto import DomainsListDto

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

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("name != ''", name='name_chk'),
    CheckConstraint("url != ''", name='url_chk')
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
  async def get_for_update(cls: type[Self], db_session: AsyncSession) -> List[DomainsListDto]:
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
        and_(
          cls.attempts < settings.attempts_limit,
          or_(
            cls.updated_at == None,
            cls.updated_at >= (datetime.now() - timedelta(seconds=settings.lists_update_interval_sec))
          )
        )
      )
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
