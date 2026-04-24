# migrations/migration_202618042122.py
'''
Migration: Use default Gateway for ip_record
Author: GregoryGost
Data: 18.04.2026
Description: It is necessary to exclude certain IP addresses from being bypassed
'''

from sqlalchemy import text, CursorResult, Row
from sqlalchemy.ext.asyncio import AsyncConnection
from typing import Sequence

from logger.logger import logger

from models.db.ip_records_dbo import IpRecordsDbo

async def upgrade(conn: AsyncConnection) -> None:
  logger.debug('Use default Gateway for ip_record migration_202618042122.py')
  try:
    await conn.execute(text('PRAGMA foreign_keys=ON'))
    #
    table_exists_result: CursorResult = await conn.execute(text(f"""
      SELECT name
      FROM sqlite_master
      WHERE
        type='table'
        AND name IN ('{IpRecordsDbo.__tablename__}')
    """))
    table_exists: Sequence[Row] = table_exists_result.fetchall()
    if len(table_exists) == 0:
      logger.debug(f'MIGRATION "migration_202618042122.py" NOT NEEDED. TABLE {IpRecordsDbo.__tablename__} NOT FOUND')
      return
    #
    await conn.execute(text(f'''
                            ALTER TABLE {IpRecordsDbo.__tablename__}
                            ADD COLUMN {IpRecordsDbo.use_default_gw.property.key} BOOLEAN NOT NULL DEFAULT 0
    '''))
    #
    logger.debug('MIGRATION "migration_202618042122.py" COMPLETED SUCCESSFULLY')
  except Exception as err:
    raise err

async def downgrade(conn: AsyncConnection) -> None:
  pass
