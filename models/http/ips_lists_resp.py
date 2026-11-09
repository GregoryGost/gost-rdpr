from .base import BasePayloadResp
from .domains_lists_resp import DomainsListElementResp


class IpsListElementResp(DomainsListElementResp):
  ip_v4_count: int | None = None
  ip_v6_count: int | None = None


class IpsListsPayloadResp(BasePayloadResp):
  # Keep the literal default so Pydantic and OpenAPI retain the existing [] default.
  payload: list[IpsListElementResp] = []  # noqa: RUF012
