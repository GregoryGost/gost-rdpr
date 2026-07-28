from dataclasses import dataclass


@dataclass
class RipeStatAddressPrefixDto:
  address: str
  prefix: str | None = None
