"""Preserve global IP entities and add independent domain/list ownership."""

from re import findall

from sqlalchemy import CheckConstraint, Column, ForeignKeyConstraint, MetaData, Table, exists, insert, select, text
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.schema import CreateIndex, CreateTable, DropTable

from models.db.domains_dbo import DomainsDbo
from models.db.ip_records_dbo import IpRecordsDbo, IpSupportDbo
from models.db.ips_lists_dbo import IpsListsDbo

IP_RECORDS_TABLE: Table = IpRecordsDbo.metadata.tables[IpRecordsDbo.__tablename__]
IP_SUPPORT_TABLE: Table = IpSupportDbo.metadata.tables[IpSupportDbo.__tablename__]
DOMAINS_TABLE: Table = DomainsDbo.metadata.tables[DomainsDbo.__tablename__]
IPS_LISTS_TABLE: Table = IpsListsDbo.metadata.tables[IpsListsDbo.__tablename__]


def identifier(name: str) -> str:
  """Quote an identifier derived exclusively from managed metadata."""
  return '"' + name.replace('"', '""') + '"'


def tokens(sql: str) -> tuple[str, ...]:
  return tuple(
    token if token.startswith("'") else token.strip('"').lower()
    for token in findall(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|\w+|[^\s]", sql)
  )


def normalized_default(value: object) -> str | None:
  if value is None:
    return None
  result = str(value).strip().lower()
  while result.startswith('(') and result.endswith(')'):
    result = result[1:-1].strip()
  return result


async def ip_schema_kind(conn: AsyncConnection, *, allow_missing_gateway: bool = False) -> str:
  """Recognize only the supported previous and target managed IP schemas."""
  name = IpRecordsDbo.__tablename__
  ddl = (
    await conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:name"), {'name': name})
  ).scalar_one_or_none()
  if ddl is None:
    raise RuntimeError('Managed IP table is unavailable')
  shape = (await conn.execute(text('SELECT * FROM pragma_table_xinfo(:name)'), {'name': name})).all()
  expected = set(IP_RECORDS_TABLE.columns.keys())
  actual = {column.name for column in shape}
  if allow_missing_gateway:
    expected.discard('use_default_gw')
    actual.discard('use_default_gw')
  if actual != expected or any(column.hidden for column in shape):
    raise RuntimeError('Managed IP columns are unsupported')
  old = next(column for column in shape if column.name == 'domain_id').notnull == 1
  for column in shape:
    target = IP_RECORDS_TABLE.columns[column.name]
    expected_nullable = False if column.name == 'domain_id' and old else target.nullable
    expected_default = (
      str(target.server_default.arg.compile(dialect=conn.dialect)) if target.server_default is not None else None
    )
    actual_default = normalized_default(column.dflt_value)
    if column.name == 'use_default_gw' and actual_default in {"'0'", '"0"'}:
      actual_default = '0'
    if (
      column.type.upper() != str(target.type).upper()
      or bool(column.notnull) != (not expected_nullable)
      or column.pk != (1 if column.name == 'id' else 0)
      or actual_default != normalized_default(expected_default)
    ):
      raise RuntimeError('Managed IP column contract is unsupported')
  fks = (await conn.execute(text('SELECT * FROM pragma_foreign_key_list(:name)'), {'name': name})).mappings().all()
  expected_fks = {
    ('domain_id', DomainsDbo.__tablename__, 'id', 'CASCADE' if old else 'SET NULL'),
    ('ip_list_id', IpsListsDbo.__tablename__, 'id', 'CASCADE' if old else 'SET NULL'),
  }
  if (
    len(fks) != 2
    or {(fk['from'], fk['table'], fk['to'], fk['on_delete']) for fk in fks} != expected_fks
    or any(fk['on_update'] != 'NO ACTION' or fk['match'] != 'NONE' for fk in fks)
  ):
    raise RuntimeError('Managed IP foreign keys are unsupported')
  # The exact known CHECK is required; constraints beyond the known forms fail closed.
  ddl_tokens = tokens(ddl)
  if ddl_tokens.count('check') != 1:
    raise RuntimeError('Managed IP checks are unsupported')
  check_start = ddl_tokens.index('check')
  if ddl_tokens[check_start : check_start + 7] != ('check', '(', 'ip_address', '!', '=', "''", ')'):
    raise RuntimeError('Managed IP checks are unsupported')
  forbidden = {'collate', 'generated', 'without', 'strict', 'deferrable', 'conflict', 'references'}
  # REFERENCES is expected twice; other additional schema behavior is not supported.
  if (forbidden - {'references'}) & set(ddl_tokens) or ddl_tokens.count('references') != 2:
    raise RuntimeError('Managed IP table options are unsupported')
  indexes = (await conn.execute(text('SELECT * FROM pragma_index_list(:name)'), {'name': name})).all()
  unique_address = False
  allowed_indexes = {
    tuple(column.name for column in index.columns): bool(index.unique) for index in IP_RECORDS_TABLE.indexes
  }
  seen_indexes = set()
  for index in indexes:
    columns = tuple(
      (
        await conn.execute(text('SELECT name FROM pragma_index_info(:name) ORDER BY seqno'), {'name': index.name})
      ).scalars()
    )
    if index.partial or columns not in allowed_indexes or bool(index.unique) != allowed_indexes[columns]:
      raise RuntimeError('Managed IP indexes are unsupported')
    if columns in seen_indexes:
      raise RuntimeError('Managed IP indexes are duplicated')
    seen_indexes.add(columns)
    unique_address |= bool(index.unique) and columns == ('ip_address',)
  if not unique_address:
    raise RuntimeError('Managed IP address uniqueness is unavailable')
  if (
    await conn.execute(text("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name=:name"), {'name': name})
  ).first():
    raise RuntimeError('Managed IP triggers cannot be preserved safely')
  return 'previous' if old else 'current'


async def validate_support_schema(conn: AsyncConnection) -> None:
  """Require the complete registered relation, including both partial indexes."""
  table = IP_SUPPORT_TABLE
  ddl = (
    await conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:name"), {'name': table.name})
  ).scalar_one_or_none()
  if ddl is None or tokens(ddl) != tokens(str(CreateTable(table).compile(dialect=conn.dialect))):
    raise RuntimeError('IP support relation is incompatible')
  expected = {index.name: tokens(str(CreateIndex(index).compile(dialect=conn.dialect))) for index in table.indexes}
  indexes = (
    await conn.execute(
      text("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=:name"), {'name': table.name}
    )
  ).all()
  if {index.name: tokens(index.sql) for index in indexes if index.sql is not None} != expected:
    raise RuntimeError('IP support indexes are incompatible')
  if (
    await conn.execute(
      text("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name=:name"), {'name': table.name}
    )
  ).first():
    raise RuntimeError('IP support triggers are unsupported')


async def validate_support_state(conn: AsyncConnection) -> None:
  """Validate managed FKs and every retained entity's real representative."""
  for table in (IpRecordsDbo.__tablename__, IpSupportDbo.__tablename__):
    if (await conn.execute(text('SELECT * FROM pragma_foreign_key_check(:name)'), {'name': table})).first():
      raise RuntimeError('IP support foreign key integrity failed')
  representative = exists().where(
    IpSupportDbo.ip_record_id == IpRecordsDbo.id,
    IpSupportDbo.domain_id == IpRecordsDbo.domain_id,
    IpSupportDbo.ip_list_id.is_not_distinct_from(IpRecordsDbo.ip_list_id),
  )
  if (await conn.execute(select(IpRecordsDbo.id).where(~representative).limit(1))).first():
    raise RuntimeError('IP entity has no real representative support')


async def upgrade(conn: AsyncConnection) -> None:
  """Upgrade inside the runner's atomic transaction with foreign keys disabled."""
  if (await conn.execute(text('PRAGMA foreign_keys'))).scalar_one() != 0:
    raise RuntimeError('IP ownership migration requires the startup transaction')
  kind = await ip_schema_kind(conn)
  await validate_support_schema(conn)
  if kind == 'previous':
    if (await conn.execute(select(IpSupportDbo.id).limit(1))).first():
      raise RuntimeError('Previous IP schema already contains unsupported ownership')
    original = IpRecordsDbo.__tablename__
    temporary = original + '_ownership_upgrade'
    if (await conn.execute(text('SELECT 1 FROM sqlite_master WHERE name=:name'), {'name': temporary})).first():
      raise RuntimeError('IP migration temporary object already exists')
    # Never rename the old table: existing support FKs must keep the final target.
    objects = (await conn.execute(text("SELECT name,type,sql FROM sqlite_master WHERE type IN ('table','view')"))).all()
    for obj in objects:
      if obj.type == 'view' and original.lower() in tokens(obj.sql or ''):
        raise RuntimeError('IP migration cannot preserve a dependent view')
      if obj.type == 'table' and obj.name not in {original, IpSupportDbo.__tablename__}:
        foreign_keys = (
          await conn.execute(text('SELECT * FROM pragma_foreign_key_list(:name)'), {'name': obj.name})
        ).mappings()
        if any(fk['table'] == original for fk in foreign_keys):
          raise RuntimeError('IP migration cannot preserve an unmanaged dependent table')
    shape = (await conn.execute(text('SELECT * FROM pragma_table_xinfo(:name)'), {'name': original})).all()
    names = [column.name for column in shape]
    old_ddl = (
      await conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:name"), {'name': original})
    ).scalar_one()
    autoincrement = 'autoincrement' in tokens(old_ddl)
    sequence = None
    if autoincrement:
      sequence = (
        await conn.execute(text('SELECT seq FROM sqlite_sequence WHERE name=:name'), {'name': original})
      ).scalar_one_or_none()
    metadata = MetaData()
    DOMAINS_TABLE.to_metadata(metadata)
    IPS_LISTS_TABLE.to_metadata(metadata)
    target = IP_RECORDS_TABLE
    rebuilt = Table(
      temporary,
      metadata,
      *(
        Column(
          name,
          target.c[name].type,
          primary_key=name == 'id',
          nullable=target.c[name].nullable,
          server_default=target.c[name].server_default.arg if target.c[name].server_default is not None else None,
        )
        for name in names
      ),
      CheckConstraint("ip_address != ''", name='ip_address_chk'),
      ForeignKeyConstraint(['domain_id'], [DomainsDbo.__tablename__ + '.id'], ondelete='SET NULL'),
      ForeignKeyConstraint(['ip_list_id'], [IpsListsDbo.__tablename__ + '.id'], ondelete='SET NULL'),
      sqlite_autoincrement=autoincrement,
    )
    await conn.execute(CreateTable(rebuilt))
    source_rows = select(*(target.c[name] for name in names))
    rebuilt_rows = select(*(rebuilt.c[name] for name in names))
    await conn.execute(insert(rebuilt).from_select(names, source_rows))
    if (await conn.execute(source_rows.except_(rebuilt_rows).limit(1))).first() or (
      await conn.execute(rebuilt_rows.except_(source_rows).limit(1))
    ).first():
      raise RuntimeError('IP migration did not preserve stored values')
    await conn.execute(DropTable(target))
    await conn.execute(text('ALTER TABLE ' + identifier(temporary) + ' RENAME TO ' + identifier(original)))
    if sequence is not None:
      await conn.execute(
        text('UPDATE sqlite_sequence SET seq=:sequence WHERE name=:name'), {'sequence': sequence, 'name': original}
      )
    for index in target.indexes:
      await conn.execute(CreateIndex(index))
  # Only this registered migration learns the provable old scalar context.
  await conn.execute(
    insert(IpSupportDbo).from_select(
      ['ip_record_id', 'domain_id', 'ip_list_id'],
      select(IpRecordsDbo.id, IpRecordsDbo.domain_id, IpRecordsDbo.ip_list_id).where(
        ~exists().where(IpSupportDbo.ip_record_id == IpRecordsDbo.id)
      ),
    )
  )
  if await ip_schema_kind(conn) != 'current':
    raise RuntimeError('IP migration did not establish the target schema')
  await validate_support_schema(conn)
  await validate_support_state(conn)
