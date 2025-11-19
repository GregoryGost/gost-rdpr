# migrations/migration_202511031501.py
'''
Migration: Move old data to new tables
Author: GregoryGost
Data: 03.11.2025
Description: Migrating data from old tables to new ones and deleting old tables
'''

from sqlalchemy import text, CursorResult, Row
from sqlalchemy.ext.asyncio import AsyncConnection
from typing import List, Sequence

from logger.logger import logger

from models.db.dns_servers_dbo import DnsServersDbo
from models.db.domains_lists_dbo import DomainsListsDbo
from models.db.ips_lists_dbo import IpsListsDbo
from models.db.domains_dbo import DomainsDbo
from models.db.ip_records_dbo import IpRecordsDbo
from models.db.ros_configs_dbo import RosConfigsDbo

async def upgrade(conn: AsyncConnection) -> None:
  logger.debug('Migrating data from old tables to new tables migration_202511031501.py')
  # Using raw SQL for data migration
  try:
    # Check tables if exists
    table_exists_result: CursorResult = await conn.execute(text("""
      SELECT name
      FROM sqlite_master
      WHERE
        type='table'
        AND name IN ('dns_servers', 'ros_configs', 'domains_lists', 'ip_lists', 'ip_records', 'domains', 'jobs')
    """))
    table_exists: Sequence[Row] = table_exists_result.fetchall()
    if len(table_exists) == 0:
      logger.debug('MIGRATION "migration_202511031501.py" NOT NEEDED. OLD TABLES NOT FOUND')
      return
    #
    await conn.execute(text('PRAGMA foreign_keys=ON'))
    # 1. Transfer DNS servers
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {DnsServersDbo.__tablename__} (
        {DnsServersDbo.id.property.key},
        {DnsServersDbo.server.property.key},
        {DnsServersDbo.doh_server.property.key},
        {DnsServersDbo.description.property.key},
        {DnsServersDbo.created_at.property.key}
      )
      SELECT id, server, doh_server, description, created_at 
      FROM dns_servers
      WHERE id != -1
    '''))
    # default ID in OLD = -1 but NEW = 0
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {DnsServersDbo.__tablename__} (
        {DnsServersDbo.id.property.key},
        {DnsServersDbo.server.property.key},
        {DnsServersDbo.doh_server.property.key},
        {DnsServersDbo.description.property.key},
        {DnsServersDbo.created_at.property.key}
      )
      SELECT 0, server, doh_server, description, created_at 
      FROM dns_servers
      WHERE id = -1
    '''))
    # 2. Transferring domain lists
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {DomainsListsDbo.__tablename__} (
        {DomainsListsDbo.id.property.key},
        {DomainsListsDbo.name.property.key},
        {DomainsListsDbo.url.property.key},
        {DomainsListsDbo.description.property.key},
        {DomainsListsDbo.hash.property.key},
        {DomainsListsDbo.attempts.property.key},
        {DomainsListsDbo.created_at.property.key},
        {DomainsListsDbo.updated_at.property.key}
      )
      SELECT id, name, url, description, hash, 0, created_at, updated_at 
      FROM domains_lists
    '''))
    #3. Transferring IP lists
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {IpsListsDbo.__tablename__} (
        {IpsListsDbo.id.property.key},
        {IpsListsDbo.name.property.key},
        {IpsListsDbo.url.property.key},
        {IpsListsDbo.description.property.key},
        {IpsListsDbo.hash.property.key},
        {IpsListsDbo.attempts.property.key},
        {IpsListsDbo.created_at.property.key},
        {IpsListsDbo.updated_at.property.key}
      )
      SELECT id, name, url, description, hash, 0, created_at, updated_at 
      FROM ip_lists
    '''))
    #4. Transferring ROS configs
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {RosConfigsDbo.__tablename__} (
        {RosConfigsDbo.id.property.key},
        {RosConfigsDbo.host.property.key},
        {RosConfigsDbo.user.property.key},
        {RosConfigsDbo.passwd.property.key},
        {RosConfigsDbo.bgp_list_name.property.key},
        {RosConfigsDbo.description.property.key},
        {RosConfigsDbo.created_at.property.key}
      )
      SELECT id, host, user, pass, bgp_list_name, description, created_at 
      FROM ros_configs
    '''))
    # 5. Domain transfer
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {DomainsDbo.__tablename__} (
        {DomainsDbo.id.property.key},
        {DomainsDbo.domain_list_id.property.key},
        {DomainsDbo.resolved.property.key},
        {DomainsDbo.name.property.key},
        {DomainsDbo.ros_comment.property.key},
        {DomainsDbo.created_at.property.key},
        {DomainsDbo.updated_at.property.key},
        {DomainsDbo.last_resolved_at.property.key}
      )
      SELECT id, domain_list_id, resolved, name, ros_comment, created_at, updated_at, updated_at 
      FROM domains
      WHERE id != -1
    '''))
    # default ID in OLD = -1 but NEW = 0
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {DomainsDbo.__tablename__} (
        {DomainsDbo.id.property.key},
        {DomainsDbo.domain_list_id.property.key},
        {DomainsDbo.resolved.property.key},
        {DomainsDbo.name.property.key},
        {DomainsDbo.ros_comment.property.key},
        {DomainsDbo.created_at.property.key},
        {DomainsDbo.updated_at.property.key}
      )
      SELECT 0, NULL, resolved, name, ros_comment, created_at, updated_at 
      FROM domains
      WHERE id = -1
    '''))
    # 6. Transferring IP records
    await conn.execute(text(f'''
      INSERT OR IGNORE INTO {IpRecordsDbo.__tablename__} (
        {IpRecordsDbo.id.property.key},
        {IpRecordsDbo.ip_list_id.property.key},
        {IpRecordsDbo.domain_id.property.key},
        {IpRecordsDbo.addr_type.property.key},
        {IpRecordsDbo.ip_address.property.key},
        {IpRecordsDbo.ros_comment.property.key},
        {IpRecordsDbo.created_at.property.key}
      )
      SELECT id, ip_list_id, domain_id, addr_type, ip_address, ros_comment, created_at 
      FROM ip_records
    '''))
    # 7. Removing old tables
    await conn.execute(text('PRAGMA foreign_keys=OFF'))
    old_tables: List[str] = ['jobs', 'ip_records', 'domains', 'ip_lists', 'domains_lists', 'ros_configs', 'dns_servers']
    for table in old_tables:
      await conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
    await conn.execute(text('PRAGMA foreign_keys=ON'))
    logger.debug('MIGRATION "migration_202511031501.py" COMPLETED SUCCESSFULLY')
  except Exception as err:
    raise err

async def downgrade(conn: AsyncConnection) -> None:
  pass
