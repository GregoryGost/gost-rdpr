from .base import Base, BasePayloadResp


class DomainsListElementResp(Base):
  id: int
  name: str
  url: str
  description: str | None = None
  hash: str | None = None
  attempts: int = 0
  elements_count: int = 0
  created_at: int | float
  created_at_hum: str
  updated_at: int | float | None = None
  updated_at_hum: str | None = None


class DomainsListsPayloadResp(BasePayloadResp):
  # Keep the literal default so Pydantic and OpenAPI retain the existing [] default.
  payload: list[DomainsListElementResp] = []  # noqa: RUF012
