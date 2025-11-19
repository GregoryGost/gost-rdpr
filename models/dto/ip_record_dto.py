from dataclasses import dataclass
from typing import List

@dataclass
class IpRecordDto:
  ip_address: str
  comment: str = 'unknown_comment'
  addr_type: int | None = None
  id: int | None = None
