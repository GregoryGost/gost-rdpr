from pydantic import Field

from .base import Base, BasePayloadResp


class DomainElementResp(Base):
  id: int
  domains_list_id: int | None = None
  resolved: bool
  name: str
  ros_comment: str | None = None
  ips_v4: list[str] | None = None
  ips_v6: list[str] | None = None
  created_at: int | float
  created_at_hum: str
  updated_at: int | float | None = None
  updated_at_hum: str | None = None
  last_resolved_at: int | float | None = None
  last_resolved_at_hum: str | None = None


class DomainsPayloadResp(BasePayloadResp):
  total_resolved: int = 0
  total_query: int = 0
  # Keep the literal default so Pydantic and OpenAPI retain the existing [] default.
  payload: list[DomainElementResp] = []  # noqa: RUF012


class DnsServerResolveResultResp(Base):
  server: str
  server_type: str
  ips_v4: list[str] = Field(default_factory=list)
  ips_v6: list[str] = Field(default_factory=list)
  cnames: list[str] = Field(default_factory=list)


class DomainResolveResp(Base):
  domain: str
  results: list[DnsServerResolveResultResp] = Field(default_factory=list)
