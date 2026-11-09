from dataclasses import dataclass
from datetime import datetime


@dataclass
class DomainsListDto:
  id: int
  name: str
  url: str
  created_at: datetime
  attempts: int
  hash: str | None = None
  description: str | None = None
  updated_at: datetime | None = None
  #
  found_elements: set[str] | None = None  # for after search process
