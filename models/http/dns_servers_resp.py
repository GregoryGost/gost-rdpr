from .base import Base, BasePayloadResp


class DnsElementResp(Base):
  id: int
  server: str | None = None
  doh_server: str | None = None
  description: str | None = None
  created_at: int | float
  created_at_hum: str
  updated_at: int | float | None = None
  updated_at_hum: str | None = None


class DnsPayloadResp(BasePayloadResp):
  # Keep the literal default so Pydantic and OpenAPI retain the existing [] default.
  payload: list[DnsElementResp] = []  # noqa: RUF012


class DnsPostElementResp(Base):
  name: str
  id: int | None = None
  error: str | None = None
