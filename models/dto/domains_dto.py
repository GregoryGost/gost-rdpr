from dataclasses import dataclass, field
from datetime import datetime
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
  """Hold one saving operation's DNS evidence, prepared writes and admission receipt."""

  # id and name identify the stored domain and the name queried by this operation.
  id: int
  name: str
  # result retains discovered addresses before storage policy is applied.
  result: DomainLookupElement = field(default_factory=DomainLookupElement)
  # insert retains the prepared additions and removals used by existing callers.
  insert: DomainSqlData = field(default_factory=DomainSqlData)
  # list_id carries the domain's list context into discovered aliases.
  list_id: int | None = None
  # resolution_complete distinguishes authoritative replacement from partial additions.
  resolution_complete: bool = False
  # storage_ips freezes the prepared addresses admitted to the writer.
  storage_ips: tuple[str, ...] = ()
  # last_attempt_at remains absent until processing reaches a normal terminal result.
  last_attempt_at: datetime | None = None
  # processing_outcome describes processing separately from persistence confirmation.
  processing_outcome: ProcessingOutcome | None = None
  # observation optionally receives lifecycle metrics without owning the operation.
  observation: Observation | None = field(default=None, repr=False, compare=False)
  # admitted_at records the monotonic admission instant used by existing observations.
  admitted_at: float | None = field(default=None, repr=False, compare=False)
  # write_receipt retains the writer's outcome even if the caller is cancelled.
  write_receipt: WriteReceipt | None = field(default=None, repr=False, compare=False)

  def append_lookup(self: DomainResult, result_list: list[Rdata]) -> None:
    """Append A and AAAA values from the supplied classic DNS records."""
    # result is one record whose type selects the destination address list.
    for result in result_list:
      if result.rdtype == A:
        self.result.A.append(result.to_text())
      if result.rdtype == AAAA:
        self.result.AAAA.append(result.to_text())

  def append_doh_lookup(self: DomainResult, result_list: list[RRset]) -> None:
    """Append address values from the supplied DNS-over-HTTPS record sets."""
    # result is the current record set; value is one address within that set.
    for result in result_list:
      if result.rdtype == A:
        for value in result:
          self.result.A.append(value.to_text())
      if result.rdtype == AAAA:
        for value in result:
          self.result.AAAA.append(value.to_text())

  def append_ips_to_insert(self: DomainResult, ips: list[IpRecordDto]) -> None:
    """Retain only supplied additions accepted by the configured address filter."""
    # ip_record is the candidate addition whose address is checked before retention.
    for ip_record in ips:
      if check_ip_allow(ip_record.ip_address):
        self.insert.ips_insert.append(ip_record)

  def append_ips_to_delete(self: DomainResult, ips: list[IpRecordDto]) -> None:
    """Retain identifiers of supplied persisted records selected for removal."""
    # ip_record is a removal candidate; unsaved candidates have no removable ID.
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
