from dataclasses import dataclass, field
from dns.rdata import Rdata
from dns.rrset import RRset
from dns.rdatatype import A, AAAA, NS, CNAME

#
# DOMAINS
#

@dataclass
class DomainLookupElement:
  A: list = field(default_factory=list)
  AAAA: list = field(default_factory=list)

@dataclass
class DomainSqlData:
  ips_insert: list = field(default_factory=list)
  ips_delete: list = field(default_factory=list)

@dataclass
class DomainResult:
  id: int
  name: str
  result: DomainLookupElement = field(default_factory=DomainLookupElement)
  insert: DomainSqlData = field(default_factory=DomainSqlData)

  def append_lookup(self, result_list: list[Rdata]):
    for result in result_list:
      if result.rdtype == A:
        self.result.A.append(result.to_text())
      if result.rdtype == AAAA:
        self.result.AAAA.append(result.to_text())
  
  def append_doh_lookup(self, result_list: list[RRset]):
    for result in result_list:
      if result.rdtype == A:
        for value in result:
          self.result.A.append(value.to_text())
      if result.rdtype == AAAA:
        for value in result:
          self.result.AAAA.append(value.to_text())
