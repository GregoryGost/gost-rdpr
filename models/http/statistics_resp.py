from pydantic import ConfigDict, Field

from .base import Base
from .statistics_req import GrowthEntity, GrowthGranularity

# BASE

class StatsBase(Base):
  model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

# STATS

class StatsRosData(StatsBase):
  total: int = Field(default=0, description='Total RouterOS configurations')

class StatsDnsData(StatsBase):
  total: int = Field(default=0, description='Total DNS server records')
  classic: int = Field(default=0, description='Classic IPv4/IPv6 DNS servers')
  doh: int = Field(default=0, description='DNS-over-HTTPS servers')

class StatsDomainsListItem(StatsBase):
  list_id: int = Field(description='Domain list ID')
  list_name: str = Field(description='Domain list name')
  total: int = Field(default=0, description='Total domains in this list')
  resolved: int = Field(default=0, description='Resolved domains count')
  unresolved: int = Field(default=0, description='Unresolved domains count')
  attempts: int = Field(default=0, description='Download attempts count')

class StatsDomainsData(StatsBase):
  total: int = Field(default=0, description='Total domain records')
  resolved: int = Field(default=0, description='Resolved domains')
  unresolved: int = Field(default=0, description='Unresolved domains')
  lists_total: int = Field(default=0, description='Total domain lists')
  per_list: list[StatsDomainsListItem] = Field(
    default_factory=list,
    description='Per-list breakdown for bar chart'
  )

class StatsIpsListItem(StatsBase):
  list_id: int = Field(description='IP list ID')
  list_name: str = Field(description='IP list name')
  total: int = Field(default=0, description='Total IPs in this list')
  v4_count: int = Field(default=0, description='IPv4 count')
  v6_count: int = Field(default=0, description='IPv6 count')
  attempts: int = Field(default=0, description='Download attempts count')

class StatsIpsData(StatsBase):
  total: int = Field(default=0, description='Total IP address records')
  v4_total: int = Field(default=0, description='Total IPv4 addresses')
  v6_total: int = Field(default=0, description='Total IPv6 addresses')
  linked_to_domain: int = Field(
    default=0,
    description='IPs resolved from domains (domain_id != 0)'
  )
  standalone: int = Field(
    default=0,
    description='IPs added manually (domain_id = 0)'
  )
  lists_total: int = Field(default=0, description='Total IP lists')
  per_list: list[StatsIpsListItem] = Field(
    default_factory=list,
    description='Per-list breakdown for bar chart'
  )

class StatsResp(StatsBase):
  '''
  Example:
  ```json
  {
    "generated_at": "2025-01-15 10:30:00",
    "dns": {
      "total": 5,
      "classic": 3,
      "doh": 2
    },
    "domains": {
      "total": 1500,
      "resolved": 1200,
      "unresolved": 300,
      "lists_total": 4,
      "per_list": [
        { "list_id": 1, "list_name": "voice-domains", "total": 500, "resolved": 450, "unresolved": 50, "attempts": 3 },
        { "list_id": 2, "list_name": "social-domains", "total": 1000, "resolved": 750, "unresolved": 250, "attempts": 1 }
      ]
    },
    "ips": {
      "total": 2000,
      "v4_total": 1800,
      "v6_total": 200,
      "linked_to_domain": 1500,
      "standalone": 500,
      "lists_total": 3,
      "per_list": [
        { "list_id": 1, "list_name": "ips-list", "total": 800, "v4_count": 700, "v6_count": 100 }
      ]
    },
    "ros": {
      "total": 2
    }
  }
  ```
  '''
  generated_at: str = Field(
    description='Timestamp when aggregation was computed',
    examples=['2025-01-15 10:30:00']
  )
  dns: StatsDnsData
  domains: StatsDomainsData
  ips: StatsIpsData
  ros: StatsRosData

# GROWTH

class StatsGrowthPoint(StatsBase):
  date: str = Field(
    description='Aggregated date label (format depends on granularity)',
    examples=['2025-01-15', '2025-03', '2025-01']
  )
  count: int = Field(
    default=0,
    description='Number of records created in this period'
  )

class StatsGrowthResp(StatsBase):
  entity: GrowthEntity = Field(description='Requested entity')
  granularity: GrowthGranularity = Field(description='Applied granularity')
  start_date: str | None = Field(
    default=None,
    description='Applied start date filter'
  )
  end_date: str | None = Field(
    default=None,
    description='Applied end date filter'
  )
  ip_subtype: int | None = Field(
    default=None,
    description='Applied IP version filter (only for entity=ips)'
  )
  total_in_period: int = Field(
    default=0,
    description='Total records in the requested period'
  )
  payload: list[StatsGrowthPoint] = Field(
    default_factory=list,
    description='Time series data points. All dates in range are included, missing dates have count=0'
  )
  duration: float = Field(
    default=0.0,
    description='Time taken to compute the response'
  )
