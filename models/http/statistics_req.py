from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import Annotated, Self
from datetime import datetime
from enum import StrEnum

from .base import DATE_FORMAT

class GrowthEntity(StrEnum):
  DOMAINS = 'domains'
  LISTS = 'lists'
  IPS = 'ips'

class GrowthGranularity(StrEnum):
  MINUTE = 'minute'
  HOUR = 'hour'
  DAY = 'day'
  WEEK = 'week'
  MONTH = 'month'
  YEAR = 'year'

class GrowthDateField(StrEnum):
  CREATED_AT = 'created_at'
  UPDATED_AT = 'updated_at'
  LAST_RESOLVED_AT = 'last_resolved_at'

class StatsGrowthQuery(BaseModel):
  model_config = ConfigDict(use_enum_values=True)

  entity: GrowthEntity = Field(
    description='Data entity to aggregate',
    examples=['domains', 'lists', 'ips']
  )
  granularity: GrowthGranularity = Field(
    default=GrowthGranularity.DAY,
    description='Time grouping granularity',
    examples=['minute', 'hour', 'day', 'week', 'month', 'year']
  )
  start_date: Annotated[str | None, Field(
    title='Start date',
    description=f'Date from which you want to start sampling. Format {DATE_FORMAT!r}',
    examples=['2024-10-01 15:00:00'],
    min_length=19,
    max_length=19
  )] = None
  end_date: Annotated[str | None, Field(
    title='End date',
    description=f'Date from which you want to end sampling. Format {DATE_FORMAT!r}',
    examples=['2024-10-01 15:00:00'],
    min_length=19,
    max_length=19
  )] = None
  ip_subtype: int | None = Field(
    default=None,
    description='IP version filter, only for entity="ips". Allowed: 4 or 6',
    examples=[4, 6]
  )
  date_filter_field: GrowthDateField = Field(
    default=GrowthDateField.CREATED_AT,
    description='Field to filter by date. "last_resolved_at" only for entity="domains"',
    examples=['created_at', 'updated_at', 'last_resolved_at']
  )

  @field_validator('start_date', mode='before')
  @classmethod
  def validate_start_date_format(cls: type[Self], value: str) -> str:
    try:
      datetime.strptime(value, DATE_FORMAT)
    except ValueError:
      raise ValueError(f'Invalid start_date format. Expected: {DATE_FORMAT!r}')
    return value
  
  @field_validator('end_date', mode='before')
  @classmethod
  def validate_end_date_format(cls: type[Self], value: str | None) -> str | None:
    if value is None:
      return value
    try:
      datetime.strptime(value, DATE_FORMAT)
    except ValueError:
      raise ValueError(f'Invalid end_date format. Expected: {DATE_FORMAT!r}')
    return value

  @field_validator('ip_subtype', mode='before')
  @classmethod
  def validate_subtype(cls: type[Self], value: int | None) -> int | None:
    if value is not None and value not in (4, 6):
      raise ValueError('ip_subtype must be 4 (IPv4) or 6 (IPv6)')
    return value

  @model_validator(mode='after')
  def validate_subtype_entity(self: Self) -> Self:
    if self.ip_subtype is not None and self.entity != GrowthEntity.IPS:
      raise ValueError('ip_subtype is only applicable when entity="ips"')
    return self

  @model_validator(mode='after')
  def validate_date_range(self: Self) -> Self:
    if self.start_date and self.end_date:
      start = datetime.strptime(self.start_date, DATE_FORMAT)
      end = datetime.strptime(self.end_date, DATE_FORMAT)
      if start >= end:
        raise ValueError('start_date must be earlier than end_date')
    return self

  @model_validator(mode='after')
  def validate_date_filter_field(self: Self) -> Self:
    if self.date_filter_field == GrowthDateField.LAST_RESOLVED_AT and self.entity != GrowthEntity.DOMAINS:
      raise ValueError('date_filter_field is only applicable when entity="domains"')
    return self
