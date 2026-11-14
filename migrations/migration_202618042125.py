"""Add the nullable saving-attempt date and inherit eligible historical checkpoints."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from models.db.domains_dbo import DomainsDbo


async def upgrade(conn: AsyncConnection) -> None:
  """Upgrade domains within the caller-owned startup transaction.

  Fresh create_all schemas already contain the column. Existing schemas gain a
  nullable TIMESTAMP without a default; incompatible preexisting columns fail.
  Historical checkpoints are copied verbatim only for undated nondefault rows.
  Raw SQL deliberately leaves historical updated_at and every other value intact.
  This migration has no downgrade because the runner invokes every available method.
  """
  # table_name comes only from mapped metadata and supports configured table prefixes.
  table_name = DomainsDbo.__tablename__
  # columns describes the target column, including SQLite-generated/hidden-column flags.
  columns = (
    await conn.execute(
      text('SELECT type, "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(:name) WHERE name = :column'),
      {'name': table_name, 'column': 'last_attempt_at'},
    )
  ).all()
  # quoted_table safely quotes the internal mapped identifier for the fixed migration SQL.
  quoted_table = '"' + table_name.replace('"', '""') + '"'
  if not columns:
    await conn.execute(text('ALTER TABLE ' + quoted_table + ' ADD COLUMN last_attempt_at TIMESTAMP'))
  elif (
    len(columns) != 1
    or columns[0].type.upper() != 'TIMESTAMP'
    or columns[0].notnull != 0
    or columns[0].dflt_value is not None
    or columns[0].pk != 0
    or columns[0].hidden != 0
  ):
    raise RuntimeError('Domain attempt timestamp column is incompatible')
  # backfill_sql uses only the quoted mapped identifier; all predicates and values are fixed.
  backfill_sql = (
    'UPDATE ' + quoted_table + ' SET last_attempt_at = last_resolved_at '  # noqa: S608
    'WHERE id > 0 AND last_attempt_at IS NULL AND last_resolved_at IS NOT NULL'
  )
  await conn.execute(text(backfill_sql))
