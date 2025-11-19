from pydantic import BaseModel, Field
from typing import Annotated, Optional

from .base import LimitOffsetQuery

class IpsListsQueryReq(LimitOffsetQuery):
  attempts: Annotated[Optional[int], Field(
    title='Attempts count',
    description='Attempts count for ips list'
  )] = None

class IpsListsSearchQueryReq(LimitOffsetQuery):
  text: Annotated[str, Field(
    title='Search text',
    description='Search text for fields "name" or "url"',
    min_length=3
  )]
  attempts: Annotated[Optional[int], Field(
    title='Attempts count',
    description='Attempts count for ips list'
  )] = None

class IpsListsPostElementReq(BaseModel):
  name: Annotated[str, Field(
    title='IP address list name',
    min_length=3,
    examples=['goog.json']
  )]
  url: Annotated[str, Field(
    title='Link to file with IP address lists',
    min_length=5,
    examples=['https://somedomain.som/path/path/path/goog.json']
  )]
  description: Annotated[Optional[str], Field(
    title='Description for record',
    min_length=3
  )] = None
