from pydantic import BaseModel, Field, model_validator
from typing import Annotated, Self

from .base import LimitOffsetQuery

class DnsQueryReq(LimitOffsetQuery):
  default: Annotated[bool | None, Field(
    title='View default DNS',
    description='Whether or not to include the default DNS server in the result',
    examples=[True, False]
  )] = None

class DnsSearchQueryReq(LimitOffsetQuery):
  text: Annotated[str, Field(
    title='Search text',
    description='Search text for fields "server" or "doh_server"',
    min_length=3
  )]

class DnsPostElementReq(BaseModel):
  server: Annotated[str | None, Field(
    title='IPv4, IPv6 DNS server address',
    min_length=3
  )] = None
  doh_server: Annotated[str | None, Field(
    title='DoH server HTTP address',
    min_length=3
  )] = None
  description: Annotated[str | None, Field(
    title='Some description for DNS server',
    min_length=3
  )] = None

  @model_validator(mode='after')
  def server_and_doh_server_validator(self: Self) -> Self:
    if self.server == None and self.doh_server == None:
      raise ValueError('One of server or doh_server must necessarily be specified')
    return self
