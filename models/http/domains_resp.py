from typing import Optional, List

from .base import Base, BasePayloadResp

class DomainElementResp(Base):
  id: int
  domains_list_id: Optional[int] = None
  resolved: bool
  name: str
  ros_comment: Optional[str] = None
  ips_v4: Optional[List[str]] = None
  ips_v6: Optional[List[str]] = None
  created_at: int | float
  created_at_hum: str
  updated_at: Optional[int | float] = None
  updated_at_hum: Optional[str] = None
  last_resolved_at: Optional[int | float] = None
  last_resolved_at_hum: Optional[str] = None

class DomainsPayloadResp(BasePayloadResp):
  resolved_count: int = 0
  payload: List[DomainElementResp] = []
