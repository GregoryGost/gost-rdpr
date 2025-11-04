from dataclasses import dataclass
from typing import List

@dataclass
class IpRecordDto:
  ip_address: str
  addr_type: int | None = None
  id: int | None = None
  comment: str | None = None

  @staticmethod
  def only_address(addr_list: List[IpRecordDto]) -> List[str]:
    return [address.ip_address for address in addr_list]

@dataclass
class RosIpRecordDto:
  id: str
  address: str
  gateway: str | None = None

  @staticmethod
  def only_address(addr_list: List[RosIpRecordDto]) -> List[str]:
    return [address.address for address in addr_list]
