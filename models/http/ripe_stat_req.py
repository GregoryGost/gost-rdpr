from ipaddress import IPv4Address, ip_address
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Annotated, Self


class RipeStatPrefixCheckReq(BaseModel):
  address: Annotated[str | None, Field(
    title='IPv4 address',
    description='IPv4 address to check in RIPEstat without saving it to the database',
    examples=['8.6.112.0']
  )] = None
  id: Annotated[int | None, Field(
    title='Existing IP address record ID',
    description='Use an existing IP address record from the local database without changing it',
    gt=0,
    examples=[55369745]
  )] = None

  @field_validator('address')
  @classmethod
  def validate_address(cls, value: str | None) -> str | None:
    if value is None:
      return None

    try:
      parsed_address = ip_address(value.strip())
    except ValueError:
      raise ValueError('Invalid IPv4 address')

    if not isinstance(parsed_address, IPv4Address):
      raise ValueError('Only IPv4 addresses are supported by this check')

    return str(parsed_address)

  @model_validator(mode='after')
  def validate_check_source(self: Self) -> Self:
    if (self.address is None) == (self.id is None):
      raise ValueError('Specify exactly one of "address" or "id"')
    return self
