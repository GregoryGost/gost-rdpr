from pydantic import BaseModel, Field, model_validator
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
