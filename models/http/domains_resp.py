from pydantic import Field

from .base import Base, BasePayloadResp


class DomainElementResp(Base):
  """Expose a stored domain, its supported addresses and nullable lifecycle dates."""

  # id identifies the stored domain, including the default context at zero.
  id: int
  # domains_list_id identifies the owning domain list when one is assigned.
  domains_list_id: int | None = None
  # resolved records whether a complete resolution checkpoint has been saved.
  resolved: bool
  # name is the stored domain name returned by list, search and detail endpoints.
  name: str
  # ros_comment is the optional comment forwarded to RouterOS address entries.
  ros_comment: str | None = None
  # ips_v4 and ips_v6 contain supported addresses, or None when none are present.
  ips_v4: list[str] | None = None
  ips_v6: list[str] | None = None
  # created_at and created_at_hum expose creation as epoch seconds and display text.
  created_at: int | float
  created_at_hum: str
  # updated_at and updated_at_hum expose the most recent recorded domain update.
  updated_at: int | float | None = None
  updated_at_hum: str | None = None
  # last_resolved_at and last_resolved_at_hum expose the complete-resolution checkpoint.
  last_resolved_at: int | float | None = None
  last_resolved_at_hum: str | None = None
  # last_attempt_at and last_attempt_at_hum expose the last completed saving attempt,
  # including partial and failed processing whose marker was committed.
  last_attempt_at: int | float | None = Field(
    default=None,
    description='Last completed saving attempt in epoch seconds; null when no attempt date is recorded.',
  )
  last_attempt_at_hum: str | None = Field(
    default=None,
    description='Last completed saving attempt formatted as YYYY-MM-DD HH:MM:SS; null when no date is recorded.',
  )


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
