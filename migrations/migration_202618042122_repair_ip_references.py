"""Repair dangling references in the previous IP schema before support backfill."""

from sqlalchemy import exists, func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.schema import CreateIndex

from migrations.migration_202618042123 import IP_SUPPORT_TABLE, ip_schema_kind, tokens
from models.db.domains_dbo import DomainsDbo
from models.db.domains_lists_dbo import DomainsListsDbo
from models.db.ip_records_dbo import IpRecordsDbo
from models.db.ips_lists_dbo import IpsListsDbo


async def ensure_support_lookup_index(conn: AsyncConnection) -> None:
  index = next(
    index
    for index in IP_SUPPORT_TABLE.indexes
    if tuple(index.columns.keys()) == ('ip_record_id', 'ip_list_id', 'domain_id')
  )
  create_index = CreateIndex(index)
  stored_sql = (
    await conn.execute(
      text("SELECT sql FROM sqlite_master WHERE type='index' AND name COLLATE NOCASE = :name"),
      {'name': index.name},
    )
  ).scalar_one_or_none()
  if stored_sql is None:
    await conn.execute(create_index)
  elif tokens(stored_sql) != tokens(str(create_index.compile(dialect=conn.dialect))):
    raise RuntimeError('IP support lookup index is incompatible')


async def upgrade(conn: AsyncConnection) -> None:
  schema_kind = await ip_schema_kind(conn)
  await ensure_support_lookup_index(conn)
  if schema_kind != 'previous':
    return

  missing_ip_domain = ~exists().where(DomainsDbo.id == IpRecordsDbo.domain_id).correlate(IpRecordsDbo)
  missing_ip_list = IpRecordsDbo.ip_list_id.is_not(None) & ~(
    exists().where(IpsListsDbo.id == IpRecordsDbo.ip_list_id).correlate(IpRecordsDbo)
  )
  missing_domain_list = DomainsDbo.domain_list_id.is_not(None) & ~(
    exists().where(DomainsListsDbo.id == DomainsDbo.domain_list_id).correlate(DomainsDbo)
  )
  repair_ip_domain, repair_ip_list, repair_domain_list, has_default_domain = (
    await conn.execute(
      select(
        exists().select_from(IpRecordsDbo).where(missing_ip_domain),
        exists().select_from(IpRecordsDbo).where(missing_ip_list),
        exists().select_from(DomainsDbo).where(missing_domain_list),
        exists().where(DomainsDbo.id == 0),
      )
    )
  ).one()
  seed_default_domain = repair_ip_domain and not has_default_domain
  for name, will_write in (
    (IpRecordsDbo.__tablename__, repair_ip_domain or repair_ip_list),
    (DomainsDbo.__tablename__, seed_default_domain or repair_domain_list),
  ):
    if not will_write:
      continue
    trigger = await conn.execute(
      text("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE = :name LIMIT 1"),
      {'name': name},
    )
    if trigger.first():
      raise RuntimeError('Legacy IP upgrade cannot safely repair references with table triggers')

  if seed_default_domain:
    await conn.execute(
      insert(DomainsDbo)
      .prefix_with('OR ABORT')
      .values(id=0, resolved=True, name='default', ros_comment='Default Domain', last_resolved_at=func.now())
    )
  if repair_ip_domain:
    await conn.execute(
      update(IpRecordsDbo).where(missing_ip_domain).values(domain_id=0, updated_at=IpRecordsDbo.updated_at)
    )
  if repair_ip_list:
    await conn.execute(
      update(IpRecordsDbo).where(missing_ip_list).values(ip_list_id=None, updated_at=IpRecordsDbo.updated_at)
    )
  if repair_domain_list:
    await conn.execute(
      update(DomainsDbo)
      .prefix_with('OR ABORT')
      .where(missing_domain_list)
      .values(domain_list_id=None, updated_at=DomainsDbo.updated_at)
    )
