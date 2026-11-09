from .base import Base, BasePayloadResp


class IpsElementResp(Base):
  id: int
  type: int
  addr: str
  ip_list_id: int | None = None
  ip_list_name: str | None = None
  domain_id: int | None = None
  domain_name: str | None = None
  ros_comment: str | None = None
  use_default_gw: bool = False
  created_at: int | float
  created_at_hum: str
  updated_at: int | float | None = None
  updated_at_hum: str | None = None


class IpsPayloadResp(BasePayloadResp):
  # Keep the literal default so Pydantic and OpenAPI retain the existing [] default.
  payload: list[IpsElementResp] = []  # noqa: RUF012
