from pydantic import BaseModel, Field, model_validator
from typing import Annotated, Optional

from .base import LimitOffsetQuery

class RosConfigsQueryReq(LimitOffsetQuery):
  pass

class RosConfigsSearchQueryReq(LimitOffsetQuery):
  text: Annotated[str, Field(
    title='Search text',
    description='Search text for fields "name"',
    min_length=3
  )]

class RosConfigsPostElementReq(BaseModel):
  host: Annotated[str, Field(
    title='RouterOS IP address or domain',
    min_length=3
  )]
  user: Annotated[str, Field(
    title='User in RouterOS',
    min_length=3
  )]
  user_password: Annotated[str, Field(
    title="User password. If you don't use a password, why are you doing it?",
    min_length=3
  )]
  bgp_list_name: Annotated[str, Field(
    title='BGP list name',
    description='BGP list name. Used for the list in the Firewall address list and routing table naming',
    min_length=3
  )]
  description: Annotated[Optional[str], Field(
    title='Description for record',
    min_length=3
  )] = None
