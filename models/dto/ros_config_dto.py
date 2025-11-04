from dataclasses import dataclass

@dataclass
class RosConfigDto:
  id: int
  host: str
  user: str
  passwd: str
  bgp_list_name: str
