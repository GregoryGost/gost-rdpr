from asyncio import CancelledError, Event
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class Observation(Protocol):
  """Receive synchronous, optional lifecycle observations without owning work."""

  def notify(self, event: str, at: float) -> None: ...


class WriteOutcome(StrEnum):
  PENDING = 'pending'
  CONFIRMED = 'confirmed'
  KNOWN_NOT_COMMITTED = 'known_not_committed'
  PROVISIONAL_UNKNOWN = 'provisional_unknown'
  FINAL_UNKNOWN = 'final_unknown'


@dataclass(slots=True)
class WriteReceipt:
  """Retain database-owned command truth independently of optional observers."""

  admitted: bool = field(default=False, init=False)
  outcome: WriteOutcome = field(default=WriteOutcome.PENDING, init=False)
  _wakeups: set[Event] = field(default_factory=set, init=False, repr=False, compare=False)

  def add_wakeup(self, wakeup: Event) -> None:
    """Register a shared lifecycle wakeup and replay already available state."""
    self._wakeups.add(wakeup)
    if self.admitted or self.outcome != WriteOutcome.PENDING:
      wakeup.set()

  def remove_wakeup(self, wakeup: Event) -> None:
    self._wakeups.discard(wakeup)

  def mark_admitted(self) -> None:
    if not self.admitted:
      self.admitted = True
      self._wake()

  def set_outcome(self, outcome: WriteOutcome) -> None:
    """Publish monotonic evidence; known outcomes can never be overwritten."""
    if self.outcome in (WriteOutcome.CONFIRMED, WriteOutcome.KNOWN_NOT_COMMITTED, WriteOutcome.FINAL_UNKNOWN):
      return
    if self.outcome == outcome or outcome == WriteOutcome.PENDING:
      return
    self.outcome = outcome
    self._wake()

  def _wake(self) -> None:
    for wakeup in tuple(self._wakeups):
      wakeup.set()


def notify_observation(observation: Observation | None, event: str, at: float) -> None:
  """Keep optional observation failures outside business control flow."""
  if observation is not None:
    with suppress(Exception, CancelledError):
      observation.notify(event, at)


class TargetAction(StrEnum):
  DNS_SERVERS_ADD = 'DNS_SERVERS_ADD'
  DNS_SERVERS_DELETE_ALL = 'DNS_SERVERS_DELETE_ALL'
  DNS_SERVERS_DELETE = 'DNS_SERVERS_DELETE'
  #
  DOMAINS_LISTS_ADD = 'DOMAINS_LISTS_ADD'
  DOMAINS_LISTS_DELETE_ALL = 'DOMAINS_LISTS_DELETE_ALL'
  DOMAINS_LISTS_DELETE = 'DOMAINS_LISTS_DELETE'
  DOMAINS_LISTS_UPDATE = 'DOMAINS_LISTS_UPDATE'
  #
  DOMAINS_ADD = 'DOMAINS_ADD'
  DOMAINS_RESOLVED = 'DOMAINS_RESOLVED'
  DOMAINS_DELETE_ALL = 'DOMAINS_DELETE_ALL'
  DOMAINS_DELETE = 'DOMAINS_DELETE'
  #
  IPS_LISTS_ADD = 'IPS_LISTS_ADD'
  IPS_LISTS_DELETE_ALL = 'IPS_LISTS_DELETE_ALL'
  IPS_LISTS_DELETE = 'IPS_LISTS_DELETE'
  IPS_LISTS_UPDATE = 'IPS_LISTS_UPDATE'
  #
  IPS_ADD = 'IPS_ADD'
  IPS_ADD_RESOLVED = 'IPS_ADD_RESOLVED'
  IPS_DELETE_ALL = 'IPS_DELETE_ALL'
  IPS_DELETE_ID = 'IPS_DELETE_ID'
  IPS_DELETE_ADDR = 'IPS_DELETE_ADDR'
  IPS_LIST_WITHDRAW = 'IPS_LIST_WITHDRAW'
  #
  ROS_CONFIG_ADD = 'ROS_CONFIG_ADD'
  ROS_CONFIG_DELETE_ALL = 'ROS_CONFIG_DELETE_ALL'
  ROS_CONFIG_DELETE = 'ROS_CONFIG_DELETE'


@dataclass(frozen=True)
class DomainResolutionIntent:
  """An immutable prepared storage result captured before queue admission."""

  id: int
  resolution_complete: bool
  storage_ips: tuple[str, ...]


@dataclass(frozen=True)
class IpListWithdrawal:
  """Withdraw one list's ownership of selected global records."""

  list_id: int
  ip_record_ids: tuple[int, ...]


@dataclass
class QueueElementDto:
  target: TargetAction
  elements: list = field(default_factory=list)
  observations: tuple[Observation, ...] = field(default=(), repr=False, compare=False)
  admitted_at: float | None = field(default=None, repr=False, compare=False)
  dequeued_at: float | None = field(default=None, repr=False, compare=False)
  dwell_observed: bool = field(default=False, repr=False, compare=False)
  receipt: WriteReceipt = field(default_factory=WriteReceipt, repr=False, compare=False)
