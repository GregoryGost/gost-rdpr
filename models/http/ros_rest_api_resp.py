from typing import Annotated, Self

from pydantic import Field, model_validator

from utils.utils import get_ip_version, get_ip_without_prefix

from .base import Base


class RosFirewallIpResp(Base):
  id: Annotated[str, Field(alias='.id')]
  address: str
  list_name: Annotated[str, Field(alias='list')]
  type: int = 4

  @model_validator(mode='after')
  def remove_prefix(self: Self):
    # set type
    self.type = get_ip_version(ip=self.address)
    return self

  @staticmethod
  def separate_duplicates(
    addresses: list[RosFirewallIpResp],
  ) -> tuple[list[RosFirewallIpResp], list[RosFirewallIpResp]]:
    duplicates: list[RosFirewallIpResp] = []
    unique: list[RosFirewallIpResp] = []
    seen: set[tuple[str, str]] = set()

    for record in addresses:
      key: tuple[str, str] = (record.list_name, record.address)
      if key in seen:
        duplicates.append(record)
      else:
        unique.append(record)
        seen.add(key)

    return duplicates, unique


class RosRoutingIpResp(Base):
  id: Annotated[str, Field(alias='.id')]
  address: Annotated[str, Field(alias='dst-address')]
  gateway: str
  type: int = 4

  @model_validator(mode='after')
  def remove_prefix(self: Self):
    # need remove /32 prefix for dst-address
    self.address = get_ip_without_prefix(ip_address=self.address)
    # set type
    self.type = get_ip_version(ip=self.address)
    return self

  @staticmethod
  def separate_duplicates(addresses: list[RosRoutingIpResp]) -> tuple[list[RosRoutingIpResp], list[RosRoutingIpResp]]:
    duplicates: list[RosRoutingIpResp] = []
    unique: list[RosRoutingIpResp] = []
    seen: set[str] = set()

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
