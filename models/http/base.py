from datetime import datetime
from typing import Annotated, Any, Self

from pydantic import BaseModel, Field, model_validator

from config.config import settings

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


class Base(BaseModel):
  def to_dict(self: Self) -> dict[str, Any]:
    return self.model_dump(exclude_none=False)

  def to_json(self: Self) -> str:
    return self.model_dump_json(exclude_none=False)


class ErrorResp(Base):
  error: str
  resolution: str | None = None


class OkResp(Base):
  result: Annotated[str, Field(title='Result OK')] = 'OK'


class NotFoundResp(ErrorResp):
  error: str = 'NOT_FOUND'


class NoDataResp(Base):
  status: str = 'No Data'


class LimitOffsetQuery(Base):
  limit: Annotated[
    int,
    Field(
      gt=0,  # Greater than >
      le=settings.req_default_limit,  # Less than or equal <=
      title='Limit param',
      description='Number of items to be sampled',
      examples=[settings.req_default_limit],
    ),
  ] = settings.req_default_limit
  offset: Annotated[
    int,
    Field(
      ge=0,  # Greater than or equal >=
      title='Offset param',
      description='Offset quantity to start sampling from',
      examples=[10],
    ),
  ] = 0
  start_date: Annotated[
    str | None,
    Field(
      title='Start date',
      description='Date from which you want to start sampling. Example `2024-04-24 00:00:00`',
      examples=[DATE_FORMAT, '2024-10-01 15:00:00'],
      min_length=19,
      max_length=19,
    ),
  ] = None
  end_date: Annotated[
    str | None,
    Field(
      title='End date',
      description='Date from which you want to end sampling. Example `2024-04-24 23:59:59`',
      examples=[DATE_FORMAT, '2024-10-01 15:00:00'],
      min_length=19,
      max_length=19,
    ),
  ] = None

  @model_validator(mode='after')
  def start_date_and_end_date_validator(self: Self) -> Self:
    # The query format is timezone-free; retain the existing naive timestamp interpretation.
    if self.start_date is not None:
      try:
        datetime.strptime(self.start_date, DATE_FORMAT)  # noqa: DTZ007
      except ValueError as exc:
        raise ValueError(f'Invalid start_date format. Use {DATE_FORMAT!r}') from exc
    if self.end_date is not None:
      try:
        datetime.strptime(self.end_date, DATE_FORMAT)  # noqa: DTZ007
      except ValueError as exc:
        raise ValueError(f'Invalid end_date format. Use {DATE_FORMAT!r}') from exc
    if self.start_date is not None and self.end_date is not None:
      startUnixDt = int(datetime.strptime(self.start_date, DATE_FORMAT).timestamp())  # noqa: DTZ007
      endUnixDt = int(datetime.strptime(self.end_date, DATE_FORMAT).timestamp())  # noqa: DTZ007
      if startUnixDt >= endUnixDt:
        raise ValueError('The start_date must be less than the end_date')
    return self


class BasePayloadResp(Base):
  limit: int
  offset: int
  duration: float
  count: int = 0
  total: int = 0
