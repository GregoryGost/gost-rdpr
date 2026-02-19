# migrations/migration_202602192245.py
'''
Migration: Add new indexes for statistics requests
Author: GregoryGost
Data: 19.02.2026
Description: Add new partial indexes for statistics growth requests
'''

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from logger.logger import logger

from models.db.domains_lists_dbo import DomainsListsDbo
from models.db.ips_lists_dbo import IpsListsDbo
from models.db.domains_dbo import DomainsDbo

async def upgrade(conn: AsyncConnection) -> None:
  logger.debug('Add new partial indexes for statistics growth requests migration_202602192245.py')
  # Using raw SQL for data migration
  try:
    await conn.execute(text('PRAGMA foreign_keys=ON'))
    # 1. Add domains index
    await conn.execute(text(f'''CREATE INDEX IF NOT EXISTS
                            ix__{DomainsDbo.__tablename__}__created_at
                            ON {DomainsDbo.__tablename__} ({DomainsDbo.created_at.property.key})'''))
    await conn.execute(text(f'''CREATE INDEX IF NOT EXISTS
                            ix__{DomainsDbo.__tablename__}__updated_at
                            ON {DomainsDbo.__tablename__} ({DomainsDbo.updated_at.property.key})
                            WHERE {DomainsDbo.updated_at.property.key} IS NOT NULL'''))
    # 2. Add domains lists index
    await conn.execute(text(f'''CREATE INDEX IF NOT EXISTS
                            ix__{DomainsListsDbo.__tablename__}__created_at
                            ON {DomainsListsDbo.__tablename__} ({DomainsListsDbo.created_at.property.key})'''))
    await conn.execute(text(f'''CREATE INDEX IF NOT EXISTS
                            ix__{DomainsListsDbo.__tablename__}__updated_at
                            ON {DomainsListsDbo.__tablename__} ({DomainsListsDbo.updated_at.property.key})
                            WHERE {DomainsListsDbo.updated_at.property.key} IS NOT NULL'''))
    # 3. Add ips lists index
    await conn.execute(text(f'''CREATE INDEX IF NOT EXISTS
                            ix__{IpsListsDbo.__tablename__}__created_at
                            ON {IpsListsDbo.__tablename__} ({IpsListsDbo.created_at.property.key})'''))
    await conn.execute(text(f'''CREATE INDEX IF NOT EXISTS
                            ix__{IpsListsDbo.__tablename__}__updated_at
                            ON {IpsListsDbo.__tablename__} ({IpsListsDbo.updated_at.property.key})
                            WHERE {IpsListsDbo.updated_at.property.key} IS NOT NULL'''))
    logger.debug('MIGRATION "migration_202602192245.py" COMPLETED SUCCESSFULLY')
  except Exception as err:
    raise err

async def downgrade(conn: AsyncConnection) -> None:
  pass
