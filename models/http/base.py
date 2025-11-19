from pydantic import BaseModel, Field, model_validator
from datetime import datetime
from typing import Optional, Annotated, Self, Dict, Any

from config.config import settings

class Base(BaseModel):
  
  def to_dict(self: Self) -> Dict[str, Any]:
    return self.model_dump(exclude_none=False)
  
  def to_json(self: Self) -> str:
    return self.model_dump_json(exclude_none=False)

class ErrorResp(Base):
  error: str
  resolution: Optional[str] = None

class OkResp(Base):
  result: Annotated[str, Field(title='Result OK')] = 'OK'

class NotFoundResp(ErrorResp):
  error: str = 'NOT_FOUND'

class NoDataResp(Base):
  status: str = 'No Data'

class LimitOffsetQuery(Base):
  limit: Annotated[int, Field(
    gt=0, # Greater than >
    le=settings.req_default_limit, # Less than or equal <=
    title='Limit param',
    description='Number of items to be sampled',
    examples=[settings.req_default_limit],
  )] = settings.req_default_limit
  offset: Annotated[int, Field(
    ge=0, # Greater than or equal >=
    title='Offset param',
    description='Offset quantity to start sampling from',
    examples=[10]
  )] = 0
  start_date: Annotated[str | None, Field(
    title='Start date',
    description='Date from which you want to start sampling',
    examples=['%Y-%m-%d %H:%M:%S', '2024-10-01 15:00:00'],
    min_length=19,
    max_length=19
  )] = None
  end_date: Annotated[str | None, Field(
    title='End date',
    description='Date from which you want to end sampling',
    examples=['%Y-%m-%d %H:%M:%S', '2024-10-01 15:00:00'],
    min_length=19,
    max_length=19
  )] = None

  @model_validator(mode='after')
  def start_date_and_end_date_validator(self: Self) -> Self:
    if self.start_date != None:
      try:
        datetime.strptime(self.start_date, '%Y-%m-%d %H:%M:%S')
      except:
        raise ValueError('Invalid start_date format. Use YYYY-MM-DD HH:MM:SS')
    if self.end_date != None:
      try:
        datetime.strptime(self.end_date, '%Y-%m-%d %H:%M:%S')
      except:
        raise ValueError('Invalid end_date format. Use YYYY-MM-DD HH:MM:SS')
    if self.start_date != None and self.end_date != None:
      startUnixDt = int(datetime.strptime(self.start_date, '%Y-%m-%d %H:%M:%S').timestamp())
      endUnixDt = int(datetime.strptime(self.end_date, '%Y-%m-%d %H:%M:%S').timestamp())
      if startUnixDt >= endUnixDt:
        raise ValueError('The start_date must be less than the end_date')
    return self

class BasePayloadResp(Base):
  limit: int
  offset: int
  duration: float
  count: int = 0
  total: int = 0
