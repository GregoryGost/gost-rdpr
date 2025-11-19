from dataclasses import dataclass
from enum import IntEnum

class DnsServerType(IntEnum):
  UNKNOWN = 0
  DEFAULT = 1
  DOH = 2

@dataclass
class DnsServerDto:
  server: str
