from pydantic import BaseModel, Field
from typing import Annotated

class ListsLoadCommandQueryReq(BaseModel):
  forced: Annotated[bool, Field(
    title='Force reload lists',
    description='Force reload lists'
  )] = False

class RosUpdateCommandQueryReq(BaseModel):
  type: Annotated[int | None, Field(
    title='IP address type v4 or v6',
    description='IP address type filter parameter',
    examples=[4, 6]
  )] = None
