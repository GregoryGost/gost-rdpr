from dataclasses import dataclass, field
from enum import StrEnum

from dns.rdata import Rdata
from dns.rdatatype import AAAA, A, RdataType
from dns.rrset import RRset

from models.dto.ip_record_dto import IpRecordDto
from models.dto.queue_dto import Observation, WriteReceipt
from utils.utils import check_ip_allow


class ProcessingOutcome(StrEnum):
  SUCCESS = 'success'
  PARTIAL = 'partial'
  FAILURE = 'failure'
  CANCELLED = 'cancelled_processing'


class DnsQueryStatus(StrEnum):
  ADDRESSES = 'ADDRESSES'
  ABSENT = 'ABSENT'
  FAILURE = 'FAILURE'


@dataclass(frozen=True)
class DnsQueryOutcome:
  """Evidence from one server query, before storage policy is applied."""

  server: str
  server_type: str
  lookup_type: RdataType
  status: DnsQueryStatus
  addresses: tuple[str, ...] = ()
  cnames: tuple[str, ...] = ()
  reason: str | None = None


@dataclass
class DomainLookupElement:
  A: list[str] = field(default_factory=list)
  AAAA: list[str] = field(default_factory=list)


@dataclass
class DomainSqlData:
  ips_insert: list[IpRecordDto] = field(default_factory=list)  # [IpRecordDto, ...]
  ips_delete: list[int] = field(default_factory=list)  # [id, id, id]


@dataclass(frozen=True, slots=True)
class DomainCandidate:
  """A detached, compact member of one finite resolution selection."""

  id: int
  name: str
  list_id: int | None = None


@dataclass
class DomainResult:
  id: int
  name: str
  result: DomainLookupElement = field(default_factory=DomainLookupElement)
  insert: DomainSqlData = field(default_factory=DomainSqlData)
  list_id: int | None = None
  resolution_complete: bool = False
  storage_ips: tuple[str, ...] = ()
  processing_outcome: ProcessingOutcome | None = None
  observation: Observation | None = field(default=None, repr=False, compare=False)
  admitted_at: float | None = field(default=None, repr=False, compare=False)
  write_receipt: WriteReceipt | None = field(default=None, repr=False, compare=False)

  def append_lookup(self: DomainResult, result_list: list[Rdata]) -> None:
    for result in result_list:
      if result.rdtype == A:
        self.result.A.append(result.to_text())
      if result.rdtype == AAAA:
        self.result.AAAA.append(result.to_text())

  def append_doh_lookup(self: DomainResult, result_list: list[RRset]) -> None:
    for result in result_list:
      if result.rdtype == A:
        for value in result:
          self.result.A.append(value.to_text())
      if result.rdtype == AAAA:
        for value in result:
          self.result.AAAA.append(value.to_text())

  def append_ips_to_insert(self: DomainResult, ips: list[IpRecordDto]) -> None:
    for ip_record in ips:
      if check_ip_allow(ip_record.ip_address):
        self.insert.ips_insert.append(ip_record)

  def append_ips_to_delete(self: DomainResult, ips: list[IpRecordDto]) -> None:
    for ip_record in ips:
      if ip_record.id is not None:
        self.insert.ips_delete.append(ip_record.id)


@dataclass
class DnsServerResolveResultDto:
  server: str
  server_type: str
  ips_v4: list[str] = field(default_factory=list)
  ips_v6: list[str] = field(default_factory=list)
  cnames: list[str] = field(default_factory=list)


@dataclass
class CheckDomainResultDto:
  domain: str
  results: list[DnsServerResolveResultDto] = field(default_factory=list)
