from pydantic import BaseModel, Field, field_validator
from typing import Annotated, Optional

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

class DomainResolveReq(BaseModel):
  domain: Annotated[str, Field(
    title='Domain name',
    description='Domain name for one-time resolving without saving to database',
    min_length=1,
    max_length=253,
    examples=['example.com']
  )]

  @field_validator('domain')
  @classmethod
  def normalize_domain(cls, value: str) -> str:
    domain: str = value.strip().rstrip('.')
    if not domain:
      raise ValueError('Domain name must not be empty')
    return domain
  