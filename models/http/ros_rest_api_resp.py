from pydantic import Field, model_validator
from typing import Annotated, List, Tuple, Self, Set

from .base import Base

from utils.utils import get_ip_without_prefix

class RosFirewallIpResp(Base):
  id: Annotated[str, Field(alias='.id')]
  address: str
  
  @staticmethod
  def separate_duplicates(addresses: List[RosFirewallIpResp]) -> Tuple[List[RosFirewallIpResp], List[RosFirewallIpResp]]:
    duplicates: List[RosFirewallIpResp] = []
    unique: List[RosFirewallIpResp] = []
    seen: Set[str] = set()

    for record in addresses:
      if record.address in seen:
        duplicates.append(record)
      else:
        unique.append(record)
        seen.add(record.address)

    return duplicates, unique
  
class RosRoutingIpResp(Base):
  id: Annotated[str, Field(alias='.id')]
  address: Annotated[str, Field(alias='dst-address')]
  gateway: str

  @model_validator(mode='after')
  def remove_prefix(self: Self):
    # need remove /32 prefix for dst-address
    self.address = get_ip_without_prefix(ip_address=self.address)
    return self
  
  @staticmethod
  def separate_duplicates(addresses: List[RosRoutingIpResp]) -> Tuple[List[RosRoutingIpResp], List[RosRoutingIpResp]]:
    duplicates: List[RosRoutingIpResp] = []
    unique: List[RosRoutingIpResp] = []
    seen: Set[str] = set()

    for record in addresses:
      if record.address in seen:
        duplicates.append(record)
      else:
        unique.append(record)
        seen.add(record.address)

    return duplicates, unique

class RosIpRouteDefaultGatewayResp(Base):
  gateway: str
  routing_table: Annotated[str, Field(alias='routing-table')]
  immediate_gw: Annotated[str, Field(alias='immediate-gw')]

class RosRoutingTableResp(Base):
  id: Annotated[str, Field(alias='.id')]
  name: str
