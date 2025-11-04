from typing import List, Optional

from .base import BasePayloadResp

from .domains_lists_resp import DomainsListElementResp

class IpsListElementResp(DomainsListElementResp):
  ip_v4_count: Optional[int] = None
  ip_v6_count: Optional[int] = None

class IpsListsPayloadResp(BasePayloadResp):
  payload: List[IpsListElementResp] = []
