from .base import Base


class RipeStatPrefixCheckResp(Base):
  address: str
  prefix: str | None = None
