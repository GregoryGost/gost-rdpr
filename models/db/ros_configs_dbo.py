from collections.abc import Sequence
from datetime import datetime
from typing import Self

from sqlalchemy import INTEGER, TEXT, TIMESTAMP, CheckConstraint, Result, Row, Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from .base_dbo import Dbo


class RosConfigsDbo(Dbo):
  """
  RouterOS configs table
  """

  __tablename__ = 'ros_configs'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)

  host: Mapped[str] = mapped_column(TEXT, unique=True, nullable=False)
  user: Mapped[str] = mapped_column(TEXT, nullable=False)
  passwd: Mapped[str] = mapped_column(TEXT, nullable=False)
  bgp_list_name: Mapped[str] = mapped_column(TEXT, nullable=False)

  description: Mapped[str | None] = mapped_column(TEXT, nullable=True)

  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, onupdate=func.now(), nullable=True)

  __table_args__ = (
    CheckConstraint("host != ''", name='host_chk'),
    CheckConstraint("user != ''", name='user_chk'),
    CheckConstraint("bgp_list_name != ''", name='bgp_list_name_chk'),
  )

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
  ) -> Sequence[Row[int, str, str, str, str, str | None, datetime, datetime | None]]:
    try:
      select_stmt: Select[int, str, str, str, str, str | None, datetime, datetime | None] = select(
        cls.id, cls.host, cls.user, cls.passwd, cls.bgp_list_name, cls.description, cls.created_at, cls.updated_at
      )
      if start_date is not None:
        select_stmt = select_stmt.where(cls.created_at >= start_date)
      if end_date is not None:
        select_stmt = select_stmt.where(cls.created_at <= end_date)
      if default is not None and not default:  # We don't include default in the sample
        select_stmt = select_stmt.where(cls.id > 0)
      if search_text is not None:
        select_stmt = select_stmt.where(
          or_(cls.host.contains(search_text), cls.user.contains(search_text), cls.bgp_list_name.contains(search_text))
        )
      select_limit_stmt: Select[int, str, str, str, str, str | None, datetime, datetime | None] = select_stmt.limit(
        limit
      ).offset(offset)
      exec_result: Result[int, str, str, str, str, str | None, datetime, datetime | None] = await db_session.execute(
        select_limit_stmt
      )
      return exec_result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_on_id(
    cls: type[Self], db_session: AsyncSession, id: int
  ) -> Row[int, str, str, str, str, str | None, datetime, datetime | None] | None:
    try:
      select_stmt: Select[int, str, str, str, str, str | None, datetime, datetime | None] = select(
        cls.id, cls.host, cls.user, cls.passwd, cls.bgp_list_name, cls.description, cls.created_at, cls.updated_at
      ).where(cls.id == id)
      exec_result: Result[int, str, str, str, str, str | None, datetime, datetime | None] = await db_session.execute(
        select_stmt
      )
      return exec_result.fetchone()
    except Exception as err:
      raise err

  @classmethod
  async def get_all_for_update(cls: type[Self], db_session: AsyncSession) -> Sequence[Row[int, str, str, str, str]]:
    try:
      select_stmt: Select[int, str, str, str, str] = select(cls.id, cls.host, cls.user, cls.passwd, cls.bgp_list_name)
      exec_result: Result[int, str, str, str, str] = await db_session.execute(select_stmt)
      return exec_result.fetchall()
    except Exception as err:
      raise err

  @classmethod
  async def get_stats(cls: type[Self], db_session: AsyncSession) -> Row[int]:
    try:
      select_stmt: Select[int] = select(func.count().label('total')).select_from(cls)
      exec_result: Result[int] = await db_session.execute(select_stmt)
      return exec_result.one()
    except Exception as err:
      raise err
