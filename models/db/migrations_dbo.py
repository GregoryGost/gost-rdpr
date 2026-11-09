from collections.abc import Sequence
from datetime import datetime
from typing import Self

from sqlalchemy import INTEGER, TEXT, TIMESTAMP, CheckConstraint, Result, Row, Select, func, select
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.orm import Mapped, mapped_column

from .base_dbo import Dbo


class MigrationsDbo(Dbo):
  """
  Migrations table
  """

  __tablename__ = 'migrations'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  name: Mapped[str] = mapped_column(TEXT, nullable=False)
  checksum: Mapped[str] = mapped_column(TEXT, nullable=False)
  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  applied_at: Mapped[datetime] = mapped_column(TIMESTAMP, nullable=True)

  __table_args__ = (CheckConstraint("name != ''", name='name_chk'),)

  @classmethod
  async def get_all(cls: type[Self], conn: AsyncConnection) -> Sequence[Row[int, str, str, datetime]]:
    try:
      select_stmt: Select[int, str, str, datetime] = select(cls.id, cls.name, cls.checksum, cls.applied_at)
      exec_result: Result[int, str, str, datetime] = await conn.execute(select_stmt)
      return exec_result.fetchall()
    except Exception as err:
      raise err
