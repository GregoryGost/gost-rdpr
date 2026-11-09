from .base import Base, BasePayloadResp


class RosConfigElementResp(Base):
  id: int
  host: str
  user: str
  password: str
  bgp_list_name: str
  description: str | None = None
  created_at: int | float
  created_at_hum: str
  updated_at: int | float | None = None
  updated_at_hum: str | None = None


class RosConfigPayloadResp(BasePayloadResp):
  # Keep the literal default so Pydantic and OpenAPI retain the existing [] default.
  payload: list[RosConfigElementResp] = []  # noqa: RUF012
