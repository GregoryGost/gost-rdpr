from typing import Optional, List

from .base import Base, BasePayloadResp

class DnsElementResp(Base):
  id: int
  server: Optional[str] = None
  doh_server: Optional[str] = None
  description: Optional[str] = None
  created_at: int | float
  created_at_hum: str
  updated_at: Optional[int | float] = None
  updated_at_hum: Optional[str] = None

class DnsPayloadResp(BasePayloadResp):
  payload: List[DnsElementResp] = []

class DnsPostElementResp(Base):
  name: str
  id: Optional[int] = None
  error: Optional[str] = None
