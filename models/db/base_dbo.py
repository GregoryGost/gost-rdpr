from sqlalchemy import select, insert, func, MetaData, Select, Result
from sqlalchemy.orm import Mapped, DeclarativeMeta, registry
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncSession
from typing import Self, Dict, Tuple, List, Any

from config.config import settings

from models.http.statistics_req import GrowthGranularity

# AUTOINCREMENT MAX VALUE = 9223372036854775807 (max 64bit number not unsigned)

GRANULARITY_FORMAT: Dict[GrowthGranularity, Tuple[str, str, str]] = {
  GrowthGranularity.MINUTE: ('%Y-%m-%d %H:%M:00', '%Y-%m-%d %H:%M', '+1 minute'),
  GrowthGranularity.HOUR:   ('%Y-%m-%d %H:00:00', '%Y-%m-%d %H',    '+1 hour'),
  GrowthGranularity.DAY:    ('%Y-%m-%d',          '%Y-%m-%d',       '+1 day'),
  GrowthGranularity.WEEK:   ('%Y-%m-%d',          '%Y-%W',          '+7 days'),
  GrowthGranularity.MONTH:  ('%Y-%m-01',          '%Y-%m',          '+1 month'),
  GrowthGranularity.YEAR:   ('%Y-01-01',          '%Y',             '+1 year'),
}

class PrefixerMeta(DeclarativeMeta):

  def __init__(cls, classname, bases, dict_) -> None:
    if '__tablename__' in dict_:
      cls.__tablename__ = dict_['__tablename__'] = settings.db_table_prefix + dict_['__tablename__']
    super().__init__(classname, bases, dict_)

class BasePrefix(metaclass=PrefixerMeta):
  __abstract__ = True
  registry = registry()

class Dbo(AsyncAttrs, BasePrefix):
  __abstract__ = True

  convention: Dict[str, Any] = {
    'all_column_names': lambda constraint, table: '_'.join(
      [column.name for column in constraint.columns.values()]
    ),
    'ix': 'ix__%(table_name)s__%(all_column_names)s',
    'uq': 'uq__%(table_name)s__%(all_column_names)s',
    'ck': 'ck__%(table_name)s__%(constraint_name)s',
    'fk': 'fk__%(table_name)s__%(all_column_names)s__%(referred_table_name)s',
    'pk': 'pk__%(table_name)s'
  }
  metadata: MetaData = MetaData(
    naming_convention=convention
    # schema=settings.db_schema
  )

  @classmethod
  def get_field_name(cls: type[Self], field: Mapped[Any]) -> str:
    return getattr(field, cls.field.property.key) # type: ignore

  @classmethod
  async def get_total(cls: type[Self], db_session: AsyncSession) -> int:
    try:
      select_stmt: Select[Tuple[int]] = select(func.count()).select_from(cls)
      exec_result: Result[Tuple[int]] = await db_session.execute(select_stmt)
      return exec_result.scalar_one()
    except Exception as err:
      raise err

  @classmethod
  async def add_batch(
    cls: type[Self],
    db_session: AsyncSession,
    items: List[Dict[str, str | None]] | List[Dict[str, str | int]]
  ) -> None:
    try:
      await db_session.execute(insert(cls).prefix_with('OR IGNORE'), items)
      # NOT COMMIT THIS FUNCTION
    except Exception as err:
      raise err
