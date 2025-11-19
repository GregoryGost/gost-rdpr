from typing import Optional, List

from .base import Base, BasePayloadResp

class IpsElementResp(Base):
  id: int
  type: int
  addr: str
  ip_list_id: Optional[int] = None
  ip_list_name: Optional[str] = None
  domain_id: Optional[int] = None
  domain_name: Optional[str] = None
  ros_comment: Optional[str] = None
  created_at: int | float
  created_at_hum: str
  updated_at: Optional[int | float] = None
  updated_at_hum: Optional[str] = None

class IpsPayloadResp(BasePayloadResp):
  payload: List[IpsElementResp] = []
