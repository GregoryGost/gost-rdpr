from pydantic import BaseModel, Field, model_validator, field_validator
from typing import Annotated, Self, Optional

from .base import LimitOffsetQuery

from utils.utils import get_ip_version

class IpsQueryReq(LimitOffsetQuery):
  type: Annotated[int | None, Field(
    title='IP address type v4 or v6',
    description='IP address type filter parameter',
    examples=[4, 6]
  )] = None

  @model_validator(mode='after')
  def type_validator(self: Self) -> Self:
    if self.type != None and self.type not in [4,6]:
      raise ValueError('The IP address type must be either 4 or 6 version')
    return self

class IpsSearchQueryReq(LimitOffsetQuery):
  text: Annotated[str, Field(
    title='Search text',
    description='Search text for fields "ip_address"',
    min_length=3
  )]

class IpsPostElementReq(BaseModel):
  addr: Annotated[str, Field(
    title='IP address record',
    examples=['1.1.1.1', '9.9.9.9', '2001:0db8:85a3:0000:0000:8a2e:0370:7334']
  )]
  list_id: Annotated[Optional[int], Field(
    title='Linked ips list ID'
  )] = None
  domain_id: Annotated[Optional[int], Field(
    title='Linked domain ID',
    description='Linked domain ID. Default = `0`',
  )] = 0
  ros_comment: Annotated[Optional[str], Field(
    title='Router OS comment for addr and route',
    min_length=3,
    examples=['discord ip address']
  )] = None

  @field_validator('addr', mode='before')
  @classmethod
  def addr_validator(cls: type[Self], value: str) -> str:
    try:
      get_ip_version(value)
    except Exception:
      raise ValueError('Invalid IP address type. Correct IPv4 or IPv6 address')
    return value
