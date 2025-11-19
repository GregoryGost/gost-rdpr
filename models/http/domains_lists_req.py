from pydantic import BaseModel, Field
from typing import Annotated, Optional

from .base import LimitOffsetQuery

class DomainsListsQueryReq(LimitOffsetQuery):
  attempts: Annotated[Optional[int], Field(
    title='Attempts count',
    description='Attempts count for ips list'
  )] = None

class DomainsListsSearchQueryReq(LimitOffsetQuery):
  text: Annotated[str, Field(
    title='Search text',
    description='Search text for fields "name" or "url"',
    min_length=3
  )]
  attempts: Annotated[Optional[int], Field(
    title='Attempts count',
    description='Attempts count for domains list'
  )] = None

class DomainsListsPostElementReq(BaseModel):
  name: Annotated[str, Field(
    title='Domain list name',
    min_length=3,
    examples=['voice-domains-list']
  )]
  url: Annotated[str, Field(
    title='Link to file with domain lists',
    min_length=5,
    examples=['https://somedomain.som/path/path/path/voice.txt']
  )]
  description: Annotated[str | None, Field(
    title='Description for record',
    min_length=3
  )] = None
