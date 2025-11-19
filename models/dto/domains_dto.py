from dataclasses import dataclass, field
from dns.rdata import Rdata
from dns.rrset import RRset
from dns.rdatatype import A, AAAA
from typing import List

from utils.utils import check_ip_allow

from models.dto.ip_record_dto import IpRecordDto

@dataclass
class DomainLookupElement:
  A: List[str] = field(default_factory=list)
  AAAA: List[str] = field(default_factory=list)

@dataclass
class DomainSqlData:
  ips_insert: List[IpRecordDto] = field(default_factory=list) # [IpRecordDto, ...]
  ips_delete: List[int] = field(default_factory=list) # [id, id, id]

@dataclass
class DomainResult:
  id: int
  name: str
  result: DomainLookupElement = field(default_factory=DomainLookupElement)
  insert: DomainSqlData = field(default_factory=DomainSqlData)
  list_id: int | None = None

  def append_lookup(self: DomainResult, result_list: List[Rdata]) -> None:
    for result in result_list:
      if result.rdtype == A:
        self.result.A.append(result.to_text())
      if result.rdtype == AAAA:
        self.result.AAAA.append(result.to_text())
  
  def append_doh_lookup(self: DomainResult, result_list: List[RRset]) -> None:
    for result in result_list:
      if result.rdtype == A:
        for value in result:
          self.result.A.append(value.to_text())
      if result.rdtype == AAAA:
        for value in result:
          self.result.AAAA.append(value.to_text())

  def append_ips_to_insert(self: DomainResult, ips: List[IpRecordDto]) -> None:
    for ip_record in ips:
      if check_ip_allow(ip_record.ip_address):
        self.insert.ips_insert.append(ip_record)

  def append_ips_to_delete(self: DomainResult, ips: List[IpRecordDto]) -> None:
    for ip_record in ips:
      if ip_record.id != None:
        self.insert.ips_delete.append(ip_record.id)
