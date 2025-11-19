from dataclasses import dataclass
from datetime import datetime

@dataclass
class MigrationsDto:
  id: int
  name: str
  checksum: str
  applied_at: datetime
