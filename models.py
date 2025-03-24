from pydantic import BaseModel, Field, model_validator, computed_field
from typing import Annotated, Self
from datetime import datetime

from utils import checkIpVersion

DEFAULT_LIMIT = 100

#
# Response standart models
#

class ErrorResp(BaseModel):
  error: str

class HealthResp(BaseModel):
  status: str = 'OK'
  ts: float
  uptime: float

class NoDataResp(BaseModel):
  status: str = 'No Data'

class NotFoundResp(BaseModel):
  error: str = 'Result Error'
  reason: str

class OkStatusResp(BaseModel):
  status: str = 'OK'
  count: int = 0

class LimitOffsetQuery(BaseModel):
  limit: Annotated[int, Field(
    gt=0, # Greater than >
    le=DEFAULT_LIMIT, # Less than or equal <=
    title='Limit param',
    description='Number of items to be sampled',
    examples=[DEFAULT_LIMIT],
  )] = DEFAULT_LIMIT
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
    if (self.start_date != None and self.end_date == None) or (self.start_date == None and self.end_date != None):
      raise ValueError('The second parameter of sampling under date is not set')
    if self.start_date != None and self.end_date != None:
      startUnixDt = int(datetime.strptime(self.start_date, '%Y-%m-%d %H:%M:%S').timestamp())
      endUnixDt = int(datetime.strptime(self.end_date, '%Y-%m-%d %H:%M:%S').timestamp())
      if startUnixDt >= endUnixDt:
        raise ValueError('The start date must be less than the end date')
    return self

####################################################
# Data models
####################################################

#
# DNS
#

class DnsQuery(LimitOffsetQuery):
  default: Annotated[bool | None, Field(
    title='View default DNS',
    description='Whether or not to include the default DNS server in the result',
    examples=[True, False]
  )] = None

class DnsPostElement(BaseModel):
  server: Annotated[str | None, Field(
    title='IPv4, IPv6 DNS server address',
    min_length=3
  )] = None
  doh_server: Annotated[str | None, Field(
    title='DoH server HTTP address',
    min_length=3
  )] = None
  description: Annotated[str | None, Field(
    title='Some description for DNS server',
    min_length=3
  )] = None

  @model_validator(mode='after')
  def server_and_doh_server_validator(self: Self) -> Self:
    if self.server == None and self.doh_server == None:
      raise ValueError('One of server or doh_server must necessarily be specified')
    return self

class DnsPostElementResp(BaseModel):
  name: str
  id: int | None = None
  error: str | None = None

class DnsElementResp(BaseModel):
  id: int
  server: str | None = None
  doh_server: str | None = None
  description: str | None = None
  created_at: int | float

class DnsPayloadResp(BaseModel):
  limit: int
  offset: int
  count: int = 0
  total: int = 0
  payload: list[DnsElementResp] = []

#
# DOMAINS
#

class DomainsQuery(LimitOffsetQuery):
  resolved: Annotated[bool | None, Field(
    title='Domains is resolved param',
    description='Whether to filter processed domains',
    examples=[True]
  )] = None

class DomainElementResp(BaseModel):
  id: int
  domains_list_id: int | None = None
  resolved: bool
  name: str
  ros_comment: str | None = None
  created_at: int | float
  updated_at: int | float | None = None
  ips_v4: list[str] | None = None
  ips_v6: list[str] | None = None

class DomainsPayloadResp(DnsPayloadResp):
  payload: list[DomainElementResp] = []

class DomainsPostElement(BaseModel):
  domain: Annotated[str, Field(
    ...,
    title='Domain name',
    min_length=3,
    examples=['google.com']
  )]
  ros_comment: Annotated[str | None, Field(
    title='Router OS comment for addr-list and route',
    min_length=3,
    examples=['discord domain']
  )] = None

class DomainsPostElementResp(BaseModel):
  domain: str
  id: int | None = None
  error: str | None = None

class DomainDeleteResp(BaseModel):
  status: str = 'OK'
  count_domain: int
  count_ip_address: int

#
# IP
#

class IpsQuery(LimitOffsetQuery):
  type: Annotated[int | None, Field(
    title='IP address type v4 or v6',
    description='IP address type filter parameter',
    examples=[4, 6]
  )] = None

  @model_validator(mode='after')
  def type_validator(self: Self) -> Self:
    if self.type == None:
      return self
    if self.type == 4 or self.type == 6:
      return self
    else:
      raise ValueError('The IP address type must be either version 4 or version 6')

class IpsElementResp(BaseModel):
  id: int
  type: int
  addr: str
  created_at: int | float
  ip_list_id: int | None = None
  ip_list_name: str | None = None
  domain_id: int | None = None
  domain: str | None = None
  ros_comment: str | None = None

class IpsPayloadResp(DnsPayloadResp):
  payload: list[IpsElementResp] = []

class IpsPostElementResp(BaseModel):
  ip: str
  id: int | None = None
  error: str | None = None

class IpsDeleteQuery(BaseModel):
  id: Annotated[int | None, Field(
    gt=0,
    title='IP address ID',
    description='DB ID for IP address',
    examples=[1, 2, 3]
  )] = None
  ip: Annotated[str | None, Field(
    min_length=4,
    title='IP address',
    description='IP address format',
    examples=['1.1.1.1', '::']
  )] = None

  @model_validator(mode='after')
  def id_or_ip_validate(self: Self) -> Self:
    if self.id == None and self.ip == None:
      raise ValueError('One of id or ip must necessarily be specified')
    if self.id != None and self.ip != None:
      raise ValueError('Only one of the parameters must be specified. Not both')
    if self.ip != None:
      if checkIpVersion(self.ip) != True:
        raise ValueError(f"IP '{self.ip}' type incorrect")
    return self

class IpsDeleteResp(BaseModel):
  status: str = 'OK'
  count: int

#
# ROS CONFIGS
#

class RosConnectResult(BaseModel):
  version: str | None = None
  uptime: str | None = None
  connect_error: str | None = None

class RosConfigElementResp(BaseModel):
  id: int
  host: str
  user: str
  password: str
  bgp_list_name: str
  description: str | None = None
  created_at: int | float

class RosConfigPayloadResp(DnsPayloadResp):
  payload: list[RosConfigElementResp] = []

class RosConfigConnElementResp(RosConfigElementResp):
  connect_result: RosConnectResult

class RosConfigsPostElement(BaseModel):
  host: Annotated[str, Field(
    ...,
    title='RouterOS IP or domain address',
    min_length=3
  )]
  user: Annotated[str, Field(
    ...,
    title='User in RouterOS',
    min_length=3
  )]
  user_password: Annotated[str, Field(
    ...,
    title="User password. If you don't use a password, why are you doing it?",
    min_length=3
  )]
  bgp_list_name: Annotated[str, Field(
    ...,
    title='BGP list name',
    description='BGP list name. Used for the list in the Firewall address list and routing table naming',
    min_length=3
  )]
  description: Annotated[str | None, Field(
    title='Description for record',
    min_length=3
  )] = None

class RosConfigsPostElementResp(BaseModel):
  host: str
  id: int | None = None
  error: str | None = None

#
# DOMAINS LISTS
#

class DomainsListsElementResp(BaseModel):
  id: int
  name: str
  url: str
  description: str | None = None
  hash: str | None = None
  created_at: int | float
  updated_at: int | float | None = None

class DomainsListsPayloadResp(DnsPayloadResp):
  payload: list[DomainsListsElementResp] = []

class DomainsListsPostElement(BaseModel):
  name: Annotated[str, Field(
    ...,
    title='Domain list name',
    min_length=3,
    examples=['voice-domains-list']
  )]
  url: Annotated[str, Field(
    ...,
    title='Link to file with domain lists',
    min_length=5,
    examples=['https://somedomain.som/path/path/path/voice.txt']
  )]
  description: Annotated[str | None, Field(
    title='Description for record',
    min_length=3
  )] = None

class DomainsListsPostElementResp(BaseModel):
  name: str
  id: int | None = None
  error: str | None = None

#
# IP ADDRESS LISTS
#

class IpAddrListsElementResp(BaseModel):
  id: int
  name: str
  url: str
  description: str | None = None
  hash: str | None = None
  created_at: int | float
  updated_at: int | float | None = None

class IpAddrListsPayloadResp(DnsPayloadResp):
  payload: list[IpAddrListsElementResp] = []

class IpAddrListsPostElement(BaseModel):
  name: Annotated[str, Field(
    ...,
    title='IP address list name',
    min_length=3,
    examples=['goog.json']
  )]
  url: Annotated[str, Field(
    ...,
    title='Link to file with IP address lists',
    min_length=5,
    examples=['https://somedomain.som/path/path/path/goog.json']
  )]
  description: Annotated[str | None, Field(
    title='Description for record',
    min_length=3
  )] = None

class IpAddrListsPostElementResp(BaseModel):
  name: str
  id: int | None = None
  error: str | None = None

#
# JOBS
#

class JobsLimitOffsetQuery(LimitOffsetQuery):
  in_progress: Annotated[bool | None, Field(
    title='Show only in progress jobs'
  )] = None

class JobsElementResp(BaseModel):
  job_id: int
  name: str
  started_at: int | float
  end_at: int | float | None = None
  # consumed: int | float | None = None

  @computed_field
  @property
  def consumed(self) -> int | float | None:
    if self.end_at != None:
      return self.end_at - self.started_at
    return None

class JobsPayloadResp(DnsPayloadResp):
  payload: list[JobsElementResp] = []

#
# COMMANDS
#

class CommandStatusResp(BaseModel):
  status: str = 'OK'
  jobs: int | None = None
  threads: list | None = None
  threads_count: int | None = None

class RoSCommandQuery(BaseModel):
  type: Annotated[int | None, Field(
    title='IP address type v4 or v6',
    description='IP address type filter parameter',
    examples=[4, 6]
  )] = None

  @model_validator(mode='after')
  def type_validator(self: Self) -> Self:
    if self.type == None:
      return self
    if self.type == 4 or self.type == 6:
      return self
    else:
      raise ValueError('The IP address type must be either version 4 or version 6')

class DomainListsCommandQuery(BaseModel):
  forced: Annotated[bool, Field(
    title='Force reload domains lists',
    description='Force reload domains lists'
  )] = False

class IpAddrListsCommandQuery(BaseModel):
  forced: Annotated[bool, Field(
    title='Force reload IP address lists',
    description='Force reload IP address lists'
  )] = False
