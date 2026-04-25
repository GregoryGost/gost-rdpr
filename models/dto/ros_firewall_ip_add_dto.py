from dataclasses import dataclass

@dataclass
class RosFirewallIpAddDto:
  ip_address: str
  list_name: str
  comment: str = 'unknown_comment'
  addr_type: int | None = None
