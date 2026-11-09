"""Refresh completed migration checksums after source-only quality fixes."""

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncConnection

from models.db.migrations_dbo import MigrationsDbo

SOURCE_CHECKSUM_UPDATES: tuple[tuple[str, str, str], ...] = (
  (
    'migration_202511031501.py',
    '293ddda35db4553c0174d8ecb07902add5bb664a7137e0ce6f36a05899b83fa7',
    '23e09b7e710a02b949a6c429de55dd174fd54ddbd9fbaa386ad80b7be57b1f22',
  ),
  (
    'migration_202602192245.py',
    '8a271a80e72ba229ca6deabd4e0458bb14170f77398585a7e8e27a8eb24be8e9',
    '940cfcac376d3b88edcb8cb5c1040d70c0a7f389a8214beeb7a5fd47a63e1e8c',
  ),
  (
    'migration_202618042122.py',
    '563a6f0d402a11b7e044b60ec29a64cf81f3216f00f3aacc5da2da82cf72e80c',
    '7f6330db2d7fcbe020712ede6b53596570ac93e18786c506c63bec72f984f68b',
  ),
)


async def upgrade(conn: AsyncConnection) -> None:
  # Preserve failed attempts and unknown source versions as historical evidence.
  for name, previous_checksum, checksum in SOURCE_CHECKSUM_UPDATES:
    await conn.execute(
      update(MigrationsDbo)
      .where(
        MigrationsDbo.name == name,
        MigrationsDbo.checksum == previous_checksum,
        MigrationsDbo.applied_at.is_not(None),
      )
      .values(checksum=checksum)
    )
