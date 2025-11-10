from datetime import datetime
from sqlalchemy import (
  select,
  func,
  Row,
  Select,
  Result,
  CheckConstraint,
  INTEGER,
  TIMESTAMP,
  TEXT
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncConnection
from typing import Self, Tuple, Sequence

from .base_dbo import Dbo

class MigrationsDbo(Dbo):
  '''
  Migrations table
  '''

  __tablename__ = 'migrations'

  id: Mapped[int] = mapped_column(INTEGER, primary_key=True, autoincrement=True, nullable=False)
  name: Mapped[str] = mapped_column(TEXT, nullable=False)
  checksum: Mapped[str] = mapped_column(TEXT, nullable=False)
  created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())
  applied_at: Mapped[datetime] = mapped_column(TIMESTAMP, nullable=True)

  __table_args__ = (
    CheckConstraint("name != ''", name='name_chk'),
  )

  @classmethod
  async def get_all(cls: type[Self], conn: AsyncConnection) -> Sequence[Row[Tuple[int, str, str, datetime]]]:
    try:
      select_stmt: Select[Tuple[int, str, str, datetime]] = select(
        cls.id,
        cls.name,
        cls.checksum,
        cls.applied_at
      )
      exec_result: Result[Tuple[int, str, str, datetime]] = await conn.execute(select_stmt)
      return exec_result.fetchall()
    except Exception as err:
      raise err
