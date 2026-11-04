from asyncio import CancelledError
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import List, Protocol


class Observation(Protocol):
  """Receive synchronous, optional lifecycle observations without owning work."""

  def notify(self, event: str, at: float) -> None: ...


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
  elements: List = field(default_factory=list)
  observations: tuple[Observation, ...] = field(default=(), repr=False, compare=False)
  admitted_at: float | None = field(default=None, repr=False, compare=False)
  dequeued_at: float | None = field(default=None, repr=False, compare=False)
  dwell_observed: bool = field(default=False, repr=False, compare=False)
