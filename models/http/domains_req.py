from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Annotated, Optional, Self

from .base import LimitOffsetQuery

class DomainsQueryReq(LimitOffsetQuery):
  resolved: Annotated[Optional[bool], Field(
    title='View resolved domains'
  )] = None

class DomainsSearchQueryReq(LimitOffsetQuery):
  resolved: Annotated[Optional[bool], Field(
    title='View resolved domains'
  )] = None
  text: Annotated[str, Field(
    title='Search text',
    description='Search text for fields "name"',
    min_length=3
  )]

class DomainsPostElementReq(BaseModel):
  domain: Annotated[str, Field(
    title='Domain name',
    examples=['google.com']
  )]
  list_id: Annotated[Optional[int], Field(
    title='Domains list id'
  )] = None
  ros_comment: Annotated[Optional[str], Field(
    title='Router OS comment for addr-list and route',
    min_length=3,
    examples=['discord domain']
  )] = None

type DnsServerId = Annotated[int, Field(ge=0)]

class DomainResolveReq(BaseModel):
  domain: Annotated[Optional[str], Field(
    title='Domain name',
    description='Domain name for one-time resolving without saving to database',
    min_length=1,
    max_length=253,
    examples=['example.com']
  )] = None
  id: Annotated[Optional[int], Field(
    title='Existing domain ID',
    gt=0,
    examples=[123]
  )] = None
  dns_server_ids: Annotated[Optional[list[DnsServerId]], Field(
    title='DNS server IDs',
    description='Use only specified DNS servers. If omitted, all configured DNS servers are used',
    min_length=1,
    examples=[[1, 2, 5]]
  )] = None

  @field_validator('domain')
  @classmethod
  def normalize_domain(cls, value: str | None) -> str | None:
    if value is None:
      return None
    domain: str = value.strip().rstrip('.')
    if not domain:
      raise ValueError('Domain name must not be empty')
    return domain
  
  @field_validator('dns_server_ids')
  @classmethod
  def validate_dns_server_ids(cls, value: list[int] | None) -> list[int] | None:
    if value is None:
      return None
    if len(value) != len(set(value)):
      raise ValueError('DNS server IDs must be unique')
    return value
  
  @model_validator(mode='after')
  def validate_resolve_source(self: Self) -> Self:
    if (self.domain is None) == (self.id is None):
      raise ValueError('Specify exactly one of "domain" or "id"')
    return self
