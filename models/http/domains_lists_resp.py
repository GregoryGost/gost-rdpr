from typing import Optional, List

from .base import Base, BasePayloadResp

class DomainsListElementResp(Base):
  id: int
  name: str
  url: str
  description: Optional[str] = None
  hash: Optional[str] = None
  attempts: int = 0
  elements_count: int = 0
  created_at: int | float
  created_at_hum: str
  updated_at: Optional[int | float] = None
  updated_at_hum: Optional[str] = None

class DomainsListsPayloadResp(BasePayloadResp):
  payload: List[DomainsListElementResp] = []
