from typing import Optional, List

from .base import Base, BasePayloadResp

class RosConfigElementResp(Base):
  id: int
  host: str
  user: str
  password: str
  bgp_list_name: str
  description: Optional[str] = None
  created_at: int | float
  created_at_hum: str
  updated_at: Optional[int | float] = None
  updated_at_hum: Optional[str] = None

class RosConfigPayloadResp(BasePayloadResp):
  payload: List[RosConfigElementResp] = []
