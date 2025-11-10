from dataclasses import dataclass
from enum import IntEnum

class RosAction(IntEnum):
  FIREWALL_DELETE   = 1
  ROUTING_DELETE    = 2
  FIREWALL_ADD      = 3
  ROUTING_ADD       = 4

@dataclass
class RosConfigDto:
  id: int
  host: str
  user: str
  passwd: str
  bgp_list_name: str
  addr_type: int | None = None
