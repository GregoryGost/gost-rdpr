from asyncio import (
  CancelledError,
  Event,
  Semaphore,
  Task,
  TaskGroup,
  create_task,
  current_task,
  gather,
  shield,
  sleep,
  timeout,
)
from base64 import urlsafe_b64encode
from collections import deque
from collections.abc import AsyncGenerator, Coroutine, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from time import perf_counter
from typing import Any, Literal, Self

from dns.asyncresolver import Resolver
from dns.exception import DNSException
from dns.flags import QR, TC
from dns.message import MAX_CHAIN, Message, from_wire, make_query
from dns.name import Name, from_text, root
from dns.opcode import QUERY
from dns.rcode import NOERROR
from dns.rcode import NXDOMAIN as NXDOMAIN_RCODE
from dns.rdataclass import IN
from dns.rdatatype import AAAA, CNAME, NS, NSEC, NSEC3, NSEC3PARAM, RRSIG, SIG, SOA, A, RdataType
from dns.resolver import NXDOMAIN, Answer, NoAnswer
from httpx import AsyncClient, HTTPError, Timeout

from client.http_base_client import HttpClient
from client.ripe_stat_client import RipeStatClient, RipeStatClientError
from config.config import settings
from database.db import DatabaseWriteError, DnsConfigurationReadError, DomainIpReadError, db
from jobs.job_registry import Jobs, job_registry
from logger.logger import logger
from metrics.metrics import (
  ResolutionRun,
  dns_duration,
  dns_labels,
  dns_semaphore_wait,
  observe_duration,
  queue_duration,
  ripe_duration,
)
from models.dto.dns_server_dto import DnsServerDto
from models.dto.domains_dto import (
  CheckDomainResultDto,
  DnsQueryOutcome,
  DnsQueryStatus,
  DnsServerResolveResultDto,
  DomainCandidate,
  DomainResult,
  ProcessingOutcome,
)
from models.dto.ip_record_dto import IpRecordDto
from models.dto.queue_dto import WriteOutcome, WriteReceipt, notify_observation
from models.http.dns_servers_resp import DnsElementResp
from models.http.domains_req import DomainsPostElementReq
from utils.utils import check_ip_allow, get_ip_network_address, get_ip_version

type _DnsServersSnapshot = tuple[tuple[DnsServerDto, ...], tuple[DnsServerDto, ...]]


async def _await_owned[T](operation: Coroutine[Any, Any, T], *, cancel_on_cancel: bool = True) -> T:
  """Retain an operation until its cleanup completes, even after repeated cancellation."""
  task = create_task(operation)
  try:
    return await shield(task)
  except CancelledError:
    if cancel_on_cancel:
      task.cancel()
    completion = gather(task, return_exceptions=True)
    while not completion.done():
      try:
        await shield(completion)
      except CancelledError:
        pass
    raise


async def _gather_owned[T](operations: Sequence[Coroutine[Any, Any, T]]) -> list[T]:
  """Preserve input order and cancel/await every sibling on an abnormal exit."""
  tasks = [create_task(operation) for operation in operations]
  group = gather(*tasks)
  try:
    # Shield running endpoints so this owner controls their cancellation.
    return list(await shield(group))
  finally:
    for task in tasks:
      if not task.done():
        task.cancel()

    async def finish_siblings() -> None:
      await gather(*tasks, return_exceptions=True)
      await gather(group, return_exceptions=True)

    # A later cancellation must not interrupt siblings already running their cleanup.
    await _await_owned(finish_siblings(), cancel_on_cancel=False)


@dataclass(frozen=True)
class _DefaultDnsContext:
  """Own endpoint resolvers and fixed timeout settings for one operation or job."""

  timeout: float
  lifetime: float
  dns_budget: float = field(default_factory=lambda: settings.dns_operation_timeout)
  doh_budget: float = field(default_factory=lambda: settings.doh_operation_timeout)
  resolvers: dict[str, Resolver] = field(default_factory=dict)

  def resolver_for(self, server: str) -> Resolver:
    resolver = self.resolvers.get(server)
    if resolver is None:
      resolver = Resolver(configure=False)
      resolver.nameservers = [server]
      resolver.timeout = self.timeout
      resolver.lifetime = self.lifetime
      self.resolvers[server] = resolver
    return resolver


_saving_dns_context: ContextVar[_DefaultDnsContext | None] = ContextVar('saving_dns_context', default=None)


class _DnsResponseError(ValueError):
  """A DNS response failed a semantic or transport check."""


def _absolute_name(name: Name) -> Name:
  return name.derelativize(root).canonicalize()


def _validated_dns_response(
  response: Message | None, domain_name: str, lookup_type: RdataType, query_id: int | None = None
) -> Message:
  if response is None:
    raise _DnsResponseError('missing_response')
  # Original wire preserves CNAME records merged by dnspython's singleton sets.
  if response.wire is not None:
    response = from_wire(response.wire, one_rr_per_rrset=True)
  if (
    not response.flags & QR
    or response.flags & TC
    or response.opcode() != QUERY
    or len(response.question) != 1
    or (query_id is not None and response.id != query_id)
  ):
    raise _DnsResponseError('invalid_envelope')
  question = response.question[0]
  if (
    _absolute_name(question.name) != _absolute_name(from_text(domain_name))
    or question.rdclass != IN
    or question.rdtype != lookup_type
  ):
    raise _DnsResponseError('unexpected_question')
  if response.rcode() not in (NOERROR, NXDOMAIN_RCODE):
    raise _DnsResponseError('unsuccessful_rcode')
  return response


def _reachable_cnames(response: Message) -> tuple[Name, tuple[str, ...], set[Name]]:
  terminal = _absolute_name(response.question[0].name)
  visited: set[Name] = set()
  owners: set[Name] = set()
  cnames: list[str] = []
  while True:
    if terminal in visited:
      raise _DnsResponseError('cname_cycle')
    visited.add(terminal)
    owner_records = [
      rrset for rrset in response.answer if rrset.rdclass == IN and _absolute_name(rrset.name) == terminal
    ]
    cname_records = [rrset for rrset in owner_records if rrset.rdtype == CNAME]
    if not cname_records:
      return terminal, tuple(cnames), owners
    targets = {_absolute_name(from_text(record.to_text())) for rrset in cname_records for record in rrset}
    if len(targets) != 1 or any(not rrset for rrset in cname_records):
      raise _DnsResponseError('ambiguous_cname')
    if any(rrset.rdtype in (A, AAAA) and rrset for rrset in owner_records):
      raise _DnsResponseError('cname_address_conflict')
    owners.add(terminal)
    terminal = targets.pop()
    cnames.append(terminal.to_text().rstrip('.'))
    if len(cnames) >= MAX_CHAIN:
      raise _DnsResponseError('cname_chain_too_long')


def classify_dns_response(
  response: Message | None,
  domain_name: str,
  server: str,
  server_type: str,
  lookup_type: RdataType = A,
  query_id: int | None = None,
) -> DnsQueryOutcome:
  """Classify one A response without applying address storage policy."""
  try:
    if lookup_type != A:
      raise _DnsResponseError('unsupported_lookup_type')
    response = _validated_dns_response(response, domain_name, lookup_type, query_id)
    terminal, cnames, cname_owners = _reachable_cnames(response)
    addresses = tuple(
      sorted(
        {
          str(IPv4Address(record.to_text()))
          for rrset in response.answer
          if rrset.rdclass == IN and rrset.rdtype == A and _absolute_name(rrset.name) == terminal
          for record in rrset
        }
      )
    )
    if addresses:
      if response.rcode() != NOERROR:
        raise _DnsResponseError('nxdomain_with_addresses')
      return DnsQueryOutcome(
        server, server_type, lookup_type, DnsQueryStatus.ADDRESSES, addresses=addresses, cnames=cnames
      )
    dnssec_metadata = (RRSIG, NSEC, NSEC3, NSEC3PARAM, SIG)
    for rrset in response.answer:
      if rrset.rdtype in dnssec_metadata:
        continue
      if rrset.rdclass == IN and rrset.rdtype == CNAME and _absolute_name(rrset.name) in cname_owners:
        continue
      raise _DnsResponseError('unrelated_negative_answer')
    covering_soa = any(
      rrset.rdclass == IN and rrset.rdtype == SOA and rrset and terminal.is_subdomain(_absolute_name(rrset.name))
      for rrset in response.authority
    )
    if response.rcode() == NOERROR and not covering_soa and any(rrset.rdtype == NS for rrset in response.authority):
      raise _DnsResponseError('referral')
    if response.rcode() == NOERROR and not covering_soa:
      return DnsQueryOutcome(
        server, server_type, lookup_type, DnsQueryStatus.FAILURE, cnames=cnames, reason='unconfirmed_absence'
      )
    return DnsQueryOutcome(server, server_type, lookup_type, DnsQueryStatus.ABSENT, cnames=cnames)
  except _DnsResponseError as err:
    reason = str(err)
  except DNSException, ValueError, TypeError, AttributeError, IndexError:
    reason = 'malformed_response'
  return DnsQueryOutcome(server, server_type, lookup_type, DnsQueryStatus.FAILURE, reason=reason)


class DomainsResolver:
  __semaphore: Semaphore = Semaphore(settings.domains_resolve_semaphore_limit)

  __http_client: AsyncClient = HttpClient.get_client(
    'domains_resolver',
    timeout=Timeout(
      connect=settings.doh_timeout_connect,
      read=settings.doh_timeout_read,
      write=settings.doh_timeout_write,
      pool=settings.doh_timeout_pool,
    ),
    connection_retries=settings.doh_connection_retries,
    retry_total_timeout=settings.doh_retry_total_timeout,
  )

  __ripe_stat_client: RipeStatClient = RipeStatClient()
  __ripe_stat_semaphore: Semaphore = Semaphore(settings.ripe_stat_requests_semaphore_limit)

  def __init__(self: Self) -> None:
    logger.info(f'{self.__class__.__name__} init')

  @staticmethod
  async def __dns_snapshot() -> _DnsServersSnapshot:
    """Copy committed DNS configuration into immutable task-owned values."""
    default, doh = await db.get_dns_servers_for_resolve()
    if not default and not doh:
      raise DnsConfigurationReadError('Cannot read DNS configuration')
    return (
      tuple(DnsServerDto(server=server.server, id=server.id) for server in default),
      tuple(DnsServerDto(server=server.server, id=server.id) for server in doh),
    )

  async def __dns_main_tasker(
    self: Self,
    domain: DomainResult,
    default_dns_servers: Sequence[DnsServerDto],
    doh_dns_servers: Sequence[DnsServerDto],
    discovered_cnames: list[DomainsPostElementReq] | None = None,
    dns_context: _DefaultDnsContext | None = None,
  ) -> None:
    logger.debug(f'START resolve domain {domain=} ...')
    domain.resolution_complete = False
    domain.processing_outcome = None
    domain.storage_ips = ()
    domain.result.A.clear()
    domain.insert.ips_insert.clear()
    domain.insert.ips_delete.clear()
    try:
      if dns_context is None:
        dns_context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
      tasks = [self.__resolve_server(domain, server, 'classic', dns_context) for server in default_dns_servers] + [
        self.__resolve_server(domain, server, 'doh') for server in doh_dns_servers
      ]
      # Run parallel tasks
      outcomes = await _gather_owned(tasks)
      try:
        known_cnames = {_absolute_name(from_text(cname.domain)) for cname in discovered_cnames or []}
        additional_cnames = [
          DomainsPostElementReq(domain=cname, list_id=domain.list_id)
          for cname in dict.fromkeys(cname for outcome in outcomes for cname in outcome.cnames)
          if _absolute_name(from_text(cname)) not in known_cnames
        ]
        if additional_cnames:
          await self.__persist_cnames(additional_cnames)
      except DatabaseWriteError:
        raise
      except Exception as err:
        logger.warning(
          f'[{err.__class__.__name__}]: additional CNAME discovery failed',
          exc_info=RuntimeError('Additional CNAME discovery failed'),
        )
      statuses = {outcome.status for outcome in outcomes}
      complete = bool(outcomes) and statuses in ({DnsQueryStatus.ADDRESSES}, {DnsQueryStatus.ABSENT})
      domain.result.A = sorted(
        {address for outcome in outcomes if outcome.status == DnsQueryStatus.ADDRESSES for address in outcome.addresses}
      )
      if not complete and not domain.result.A:
        domain.processing_outcome = (
          ProcessingOutcome.PARTIAL
          if any(outcome.status != DnsQueryStatus.FAILURE for outcome in outcomes)
          else ProcessingOutcome.FAILURE
        )
        notify_observation(domain.observation, domain.processing_outcome, perf_counter())
        return
      # Ips processing for domain
      current_ips: list[IpRecordDto] = await db.get_all_ips_for_domain(domain_id=domain.id)
      domain.resolution_complete = complete
      # add new ips, remove not resolved ips but current exists
      await self.__ips_processing(domain=domain, current_ips=current_ips)
      domain.processing_outcome = ProcessingOutcome.SUCCESS if complete else ProcessingOutcome.PARTIAL
      notify_observation(domain.observation, domain.processing_outcome, perf_counter())
      # INSERT IPS (send to Queue)
      # DELETE IPS (send to Queue)
      # UPDATE DOMAINS (send to Queue)
      if complete or domain.storage_ips:
        await db.put_domain_after_resolve(domain=domain)
      logger.debug(f'FINAL resolve domain {domain=}')
    except CancelledError:
      if domain.processing_outcome is None:
        domain.processing_outcome = ProcessingOutcome.CANCELLED
      notify_observation(domain.observation, domain.processing_outcome, perf_counter())
      raise
    except DatabaseWriteError:
      raise
    except DomainIpReadError:
      domain.processing_outcome = ProcessingOutcome.FAILURE
      notify_observation(domain.observation, domain.processing_outcome, perf_counter())
      domain.resolution_complete = False
      logger.warning('Domain IP snapshot unavailable; resolving cycle skipped')
    except Exception as err:
      domain.resolution_complete = False
      if domain.processing_outcome is None:
        domain.processing_outcome = ProcessingOutcome.FAILURE
      notify_observation(domain.observation, domain.processing_outcome, perf_counter())
      logger.error(
        f'[{err.__class__.__name__}]: domain resolving cycle failed',
        exc_info=RuntimeError('Domain resolving cycle failed'),
      )

  async def __persist_cnames(self: Self, cnames: list[DomainsPostElementReq]) -> None:
    try:
      await db.put_add_domains_to_queue(domains=cnames)
    except DatabaseWriteError:
      raise
    except Exception as err:
      logger.warning(
        f'[{err.__class__.__name__}]: CNAME discovery could not be queued',
        exc_info=RuntimeError('CNAME discovery could not be queued'),
      )

  async def __resolve_server(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    transport: Literal['classic', 'doh'],
    dns_context: _DefaultDnsContext | None = None,
  ) -> DnsQueryOutcome:
    if transport == 'classic':
      if dns_context is None:
        dns_context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
      outcome = await self.__default_resolver(domain, dns_server, A, dns_context)
    else:
      outcome = await self.__doh_resolver(domain, dns_server, A)
    if outcome.status != DnsQueryStatus.FAILURE or outcome.cnames:
      return outcome
    # Alias evidence cannot authorize IPv4 deletion or a refresh checkpoint.
    cnames: list[DomainsPostElementReq] = []
    if transport == 'classic':
      await self.__cname_default_resolver(domain, dns_server, cnames, dns_context)
    else:
      await self.__cname_doh_resolver(domain, dns_server, cnames)
    return replace(outcome, cnames=tuple(dict.fromkeys(cname.domain for cname in cnames)))

  # Resolvers

  async def __query_doh(self: Self, domain_name: str, dns_server: DnsServerDto, lookup_type: RdataType) -> Message:
    query = make_query(qname=domain_name, rdtype=lookup_type)
    query_base64 = urlsafe_b64encode(query.to_wire()).decode('ascii').rstrip('=')
    response = await self.__http_client.get(
      url=dns_server.server, params={'dns': query_base64}, headers={'Accept': 'application/dns-message'}
    )
    if response.status_code != 200:
      raise _DnsResponseError('http_status')
    media_type = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    if media_type != 'application/dns-message':
      raise _DnsResponseError('unexpected_media_type')
    message = from_wire(response.content, one_rr_per_rrset=True)
    return _validated_dns_response(message, domain_name, lookup_type, query.id)

  async def __query_default(
    self: Self,
    domain_name: str,
    dns_server: DnsServerDto,
    lookup_type: RdataType,
    dns_context: _DefaultDnsContext | None = None,
  ) -> Message:
    if dns_context is None:
      dns_context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
    resolver = dns_context.resolver_for(dns_server.server)
    try:
      answer: Answer = await resolver.resolve(
        qname=domain_name, rdtype=lookup_type, search=False, lifetime=dns_context.lifetime
      )
      response = answer.response
    except NoAnswer as err:
      response = err.response()
    except NXDOMAIN as err:
      response = err.response(from_text(domain_name))
    return _validated_dns_response(response, domain_name, lookup_type)

  @staticmethod
  def __finish_domain_observation(domain: DomainResult) -> None:
    if domain.processing_outcome is None:
      domain.processing_outcome = ProcessingOutcome.FAILURE
    notify_observation(domain.observation, domain.processing_outcome, perf_counter())
    notify_observation(domain.observation, 'processing_finished', perf_counter())

  @asynccontextmanager
  async def __dns_observation(
    self, dns_server: DnsServerDto, transport: str, record_type: str
  ) -> AsyncGenerator[dict[str, str]]:
    wait_started = perf_counter()
    acquired = False
    measurement = dict(outcome='failure', reason='none')
    context = _saving_dns_context.get()
    budget = (
      (context.doh_budget if transport == 'doh' else context.dns_budget)
      if context is not None
      else (settings.doh_operation_timeout if transport == 'doh' else settings.dns_operation_timeout)
    )
    deadline = timeout(budget)
    try:
      async with deadline, self.__semaphore:
        acquired = True
        observe_duration(
          dns_semaphore_wait, wait_started, **dns_labels(dns_server.id, transport, record_type, 'acquired')
        )
        query_started = perf_counter()
        try:
          yield measurement
        except CancelledError:
          measurement.update(
            outcome='failure' if deadline.expired() else 'cancelled',
            reason='Timeout' if deadline.expired() else 'none',
          )
          raise
        finally:
          observe_duration(
            dns_duration,
            query_started,
            **dns_labels(dns_server.id, transport, record_type, measurement['outcome'], measurement['reason']),
          )
    except TimeoutError:
      if not acquired:
        observe_duration(
          dns_semaphore_wait, wait_started, **dns_labels(dns_server.id, transport, record_type, 'timeout')
        )
      raise
    except CancelledError:
      if not acquired:
        observe_duration(
          dns_semaphore_wait, wait_started, **dns_labels(dns_server.id, transport, record_type, 'cancelled')
        )
      raise

  async def __doh_resolver(
    self: Self, domain: DomainResult, dns_server: DnsServerDto, lookup_type: RdataType
  ) -> DnsQueryOutcome:
    try:
      async with self.__dns_observation(dns_server, 'doh', lookup_type.name) as measurement:
        try:
          response = await self.__query_doh(domain.name, dns_server, lookup_type)
          outcome = classify_dns_response(response, domain.name, dns_server.server, 'doh', lookup_type)
          measurement.update(outcome=outcome.status.value.lower(), reason=outcome.reason or 'none')
          return outcome
        except _DnsResponseError as err:
          reason = str(err)
        except Exception as err:
          logger.debug('DNS query failed', exc_info=RuntimeError('DNS query failed'))
          reason = err.__class__.__name__
        measurement.update(reason=reason)
        return DnsQueryOutcome(dns_server.server, 'doh', lookup_type, DnsQueryStatus.FAILURE, reason=reason)
    except TimeoutError:
      return DnsQueryOutcome(dns_server.server, 'doh', lookup_type, DnsQueryStatus.FAILURE, reason='timeout')

  async def __default_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    lookup_type: RdataType,
    dns_context: _DefaultDnsContext | None = None,
  ) -> DnsQueryOutcome:
    try:
      async with self.__dns_observation(dns_server, 'classic', lookup_type.name) as measurement:
        try:
          response = await self.__query_default(domain.name, dns_server, lookup_type, dns_context)
          outcome = classify_dns_response(response, domain.name, dns_server.server, 'classic', lookup_type)
          measurement.update(outcome=outcome.status.value.lower(), reason=outcome.reason or 'none')
          return outcome
        except _DnsResponseError as err:
          reason = str(err)
        except Exception as err:
          logger.debug('DNS query failed', exc_info=RuntimeError('DNS query failed'))
          reason = err.__class__.__name__
        measurement.update(reason=reason)
        return DnsQueryOutcome(dns_server.server, 'classic', lookup_type, DnsQueryStatus.FAILURE, reason=reason)
    except TimeoutError:
      return DnsQueryOutcome(dns_server.server, 'classic', lookup_type, DnsQueryStatus.FAILURE, reason='timeout')

  async def __cname_doh_resolver(
    self: Self, domain: DomainResult, dns_server: DnsServerDto, cname_domains: list[DomainsPostElementReq]
  ) -> None:
    try:
      async with self.__dns_observation(dns_server, 'doh', 'CNAME') as measurement:
        try:
          response = await self.__query_doh(domain.name, dns_server, CNAME)
          _, cnames, _ = _reachable_cnames(response)
          measurement.update(outcome='aliases' if cnames else 'no_alias')
          cname_domains.extend(DomainsPostElementReq(domain=cname, list_id=domain.list_id) for cname in cnames)
        except Exception as err:
          measurement.update(reason=str(err) if isinstance(err, _DnsResponseError) else type(err).__name__)
          logger.debug(
            f'[{err.__class__.__name__}]: DoH CNAME discovery failed',
            exc_info=RuntimeError('DoH CNAME discovery failed'),
          )
    except TimeoutError:
      logger.debug('CNAME discovery operation timed out')

  async def __cname_default_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: list[DomainsPostElementReq],
    dns_context: _DefaultDnsContext | None = None,
  ) -> None:
    try:
      async with self.__dns_observation(dns_server, 'classic', 'CNAME') as measurement:
        try:
          response = await self.__query_default(domain.name, dns_server, CNAME, dns_context)
          _, cnames, _ = _reachable_cnames(response)
          measurement.update(outcome='aliases' if cnames else 'no_alias')
          cname_domains.extend(DomainsPostElementReq(domain=cname, list_id=domain.list_id) for cname in cnames)
        except Exception as err:
          measurement.update(reason=str(err) if isinstance(err, _DnsResponseError) else type(err).__name__)
          logger.debug(
            f'[{err.__class__.__name__}]: classic CNAME discovery failed',
            exc_info=RuntimeError('Classic CNAME discovery failed'),
          )
    except TimeoutError:
      logger.debug('CNAME discovery operation timed out')

  async def __resolve_once_default_server(
    self: Self,
    domain_name: str,
    dns_server: DnsServerDto,
    dns_context: _DefaultDnsContext | None = None,
  ) -> DnsServerResolveResultDto:
    domain: DomainResult = DomainResult(id=0, name=domain_name)
    outcome = await self.__resolve_server(domain, dns_server, 'classic', dns_context)
    return DnsServerResolveResultDto(
      server=dns_server.server,
      server_type='classic',
      ips_v4=list(outcome.addresses),
      ips_v6=domain.result.AAAA,
      cnames=list(outcome.cnames),
    )

  async def __resolve_once_doh_server(
    self: Self, domain_name: str, doh_server: DnsServerDto
  ) -> DnsServerResolveResultDto:
    domain: DomainResult = DomainResult(id=0, name=domain_name)
    outcome = await self.__resolve_server(domain, doh_server, 'doh')
    return DnsServerResolveResultDto(
      server=doh_server.server,
      server_type='doh',
      ips_v4=list(outcome.addresses),
      ips_v6=domain.result.AAAA,
      cnames=list(outcome.cnames),
    )

  # IPS

  @staticmethod
  def __get_current_cidr_for_resolved_ip(resolved_ip: str, current_ip_records: list[IpRecordDto]) -> str | None:
    for record in current_ip_records:
      if '/' not in record.ip_address:
        continue
      if get_ip_network_address(record.ip_address) == resolved_ip:
        return record.ip_address
    return None

  async def __get_ip_address_for_storage(self: Self, resolved_ip: str, current_ip_records: list[IpRecordDto]) -> str:
    parsed_ip = ip_address(resolved_ip)

    if not isinstance(parsed_ip, IPv4Address) or not parsed_ip.is_global:
      return resolved_ip

    if parsed_ip.packed[-1] != 0:
      return resolved_ip

    try:
      wait_started = perf_counter()
      acquired = False
      try:
        async with RipeStatClient.lookup_budget(), self.__ripe_stat_semaphore:
          acquired = True
          observe_duration(ripe_duration, wait_started, phase='semaphore_wait', source='resolver', outcome='acquired')
          ripe_result = await self.__ripe_stat_client.get_prefix(address=resolved_ip)
      except RipeStatClientError:
        if not acquired:
          observe_duration(ripe_duration, wait_started, phase='semaphore_wait', source='resolver', outcome='timeout')
        raise
      except CancelledError:
        if not acquired:
          observe_duration(ripe_duration, wait_started, phase='semaphore_wait', source='resolver', outcome='cancelled')
        raise

      if ripe_result.prefix is None:
        logger.debug(f'RIPEstat prefix not found for {resolved_ip}; keep host route')
        return resolved_ip

      network = ip_network(ripe_result.prefix, strict=True)

      if not isinstance(network, IPv4Network) or network.prefixlen == 32 or network.network_address != parsed_ip:
        logger.debug(f'RIPEstat prefix rejected for {resolved_ip}: {ripe_result.prefix}')
        return resolved_ip

      storage_ip = str(network)
      logger.debug(f'RIPEstat prefix accepted for {resolved_ip}: {storage_ip}')
      return storage_ip
    except (RipeStatClientError, HTTPError, ValueError) as err:
      fallback_started = perf_counter()
      current_cidr = self.__get_current_cidr_for_resolved_ip(
        resolved_ip=resolved_ip, current_ip_records=current_ip_records
      )

      observe_duration(
        ripe_duration,
        fallback_started,
        phase='fallback',
        source='resolver',
        outcome='stored_prefix' if current_cidr is not None else 'host',
      )
      if current_cidr is not None:
        logger.warning(
          f'RIPEstat prefix lookup failed for {resolved_ip}: '
          f'[{err.__class__.__name__}] {err}; '
          f'keep stored prefix {current_cidr}'
        )
        return current_cidr

      logger.warning(
        f'RIPEstat prefix lookup failed for {resolved_ip}: [{err.__class__.__name__}] {err}; keep host route'
      )
      return resolved_ip

  async def __ips_processing(self: Self, domain: DomainResult, current_ips: list[IpRecordDto]) -> None:
    logger.debug(f'IP prepare for {domain.name}')
    logger.debug(f'{domain=}, {current_ips=}')
    try:
      resolved_ips: list[str] = list(dict.fromkeys(str(IPv4Address(address)) for address in domain.result.A))
      current_ips_by_network_address: dict[str, list[IpRecordDto]] = {}
      desired_ips_by_network_address: dict[str, IpRecordDto] = {}
      new_ips: list[IpRecordDto] = []
      remove_ips: list[IpRecordDto] = []

      for record in current_ips:
        if get_ip_version(record.ip_address) != 4:
          continue
        network_address = get_ip_network_address(record.ip_address)
        if network_address not in current_ips_by_network_address:
          current_ips_by_network_address[network_address] = []
        current_ips_by_network_address[network_address].append(record)

      pending_ips = [
        address
        for address in resolved_ips
        if domain.resolution_complete or address not in current_ips_by_network_address
      ]
      prepared_ips = [
        record.ip_address
        for address in resolved_ips
        if not domain.resolution_complete
        for record in current_ips_by_network_address.get(address, [])
      ]
      storage_ips: dict[str, str] = {}
      pending = iter(pending_ips)

      async def enrich_addresses() -> None:
        for address in pending:
          storage_ips[address] = await self.__get_ip_address_for_storage(
            resolved_ip=address, current_ip_records=current_ips_by_network_address.get(address, [])
          )

      # A fixed worker set bounds task allocation as well as shared provider admission.
      async with TaskGroup() as workers:
        for _ in range(min(settings.ripe_stat_requests_semaphore_limit, len(pending_ips))):
          workers.create_task(enrich_addresses())

      for resolved_ip in pending_ips:
        storage_ip = storage_ips[resolved_ip]
        network_address = get_ip_network_address(storage_ip)

        if network_address != resolved_ip:
          logger.warning(f'Invalid storage address for {resolved_ip}: {storage_ip}; keep original IP')
          storage_ip = resolved_ip
          network_address = resolved_ip

        desired_ips_by_network_address[network_address] = IpRecordDto(
          ip_address=storage_ip, addr_type=get_ip_version(storage_ip)
        )

      for network_address, desired_ip in desired_ips_by_network_address.items():
        current_ip_records = current_ips_by_network_address.pop(network_address, [])
        is_current_value_present = False

        for current_ip in current_ip_records:
          if not is_current_value_present and current_ip.ip_address == desired_ip.ip_address:
            is_current_value_present = True
            continue
          if domain.resolution_complete:
            remove_ips.append(current_ip)

        if not is_current_value_present:
          new_ips.append(desired_ip)
        # Retain existing domain representations; filtering still applies to new values.
        if is_current_value_present or check_ip_allow(desired_ip.ip_address):
          prepared_ips.append(desired_ip.ip_address)

      if domain.resolution_complete:
        for stale_ip_records in current_ips_by_network_address.values():
          remove_ips.extend(stale_ip_records)

      if len(new_ips) > 0:
        domain.append_ips_to_insert(ips=new_ips)
      if len(remove_ips) > 0:
        domain.append_ips_to_delete(ips=remove_ips)
      domain.storage_ips = tuple(dict.fromkeys(prepared_ips))
    except Exception as err:
      raise err

  async def domains_resolve(self, job_mode: Jobs) -> None:
    """Wait for this caller's automatic pass without owning other interests."""
    await saving_coordinator.resolve_scan(job_mode, self)

  async def saving_dns_snapshot(self) -> _DnsServersSnapshot:
    """Capture immutable DNS rows for one saving operation."""
    return await self.__dns_snapshot()

  async def process_saving_domain(
    self, domain: DomainResult, servers: _DnsServersSnapshot, context: _DefaultDnsContext
  ) -> None:
    """Run the existing DNS evidence and immutable writer preparation flow."""
    context_token = _saving_dns_context.set(context)
    try:
      await self.__dns_main_tasker(domain, servers[0], servers[1], dns_context=context)
    finally:
      _saving_dns_context.reset(context_token)
      self.__finish_domain_observation(domain)

  async def resolve_once(
    self: Self, domain_name: str, selected_dns_servers: list[DnsElementResp] | None = None
  ) -> CheckDomainResultDto:
    """Resolve configured endpoints in order and await their cleanup before returning."""
    return await _await_owned(self.__resolve_once(domain_name, selected_dns_servers))

  async def __resolve_once(
    self, domain_name: str, selected_dns_servers: list[DnsElementResp] | None
  ) -> CheckDomainResultDto:
    name: str = domain_name.strip().rstrip('.')
    if not name:
      raise ValueError('Domain name must not be empty')
    #
    default_dns_servers: list[DnsServerDto] = []
    doh_dns_servers: list[DnsServerDto] = []
    if selected_dns_servers is None:
      default_dns_servers, doh_dns_servers = await db.get_dns_servers_for_resolve()
    else:
      for selected_dns_server in selected_dns_servers:
        if selected_dns_server.server is not None:
          default_dns_servers.append(DnsServerDto(server=selected_dns_server.server, id=selected_dns_server.id))
        elif selected_dns_server.doh_server is not None:
          doh_dns_servers.append(DnsServerDto(server=selected_dns_server.doh_server, id=selected_dns_server.id))
        else:
          raise RuntimeError(f'DNS server ID={selected_dns_server.id} does not contain a server address')
    #
    tasks: list[Coroutine[Any, Any, DnsServerResolveResultDto]] = []
    dns_context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
    #
    for dns_server in default_dns_servers:
      tasks.append(self.__resolve_once_default_server(domain_name=name, dns_server=dns_server, dns_context=dns_context))
    for dns_server in doh_dns_servers:
      tasks.append(self.__resolve_once_doh_server(domain_name=name, doh_server=dns_server))
    if not tasks:
      raise RuntimeError('DNS servers for resolve not found')
    #
    results = await _gather_owned(tasks)
    #
    return CheckDomainResultDto(domain=name, results=results)

  async def resolve_stored_domain(self, domain_id: int) -> None:
    """Wait for one distinct saved-ID operation and retain cancellation cleanup."""
    await saving_coordinator.resolve_stored(domain_id, self)


@dataclass(eq=False, slots=True)
class _SavingPass:
  mode: Jobs
  resolver: DomainsResolver
  detached: bool
  run: ResolutionRun
  done: Event = field(default_factory=Event)
  callers: int = 0
  servers: _DnsServersSnapshot | None = None
  context: _DefaultDnsContext | None = None
  remaining: int = 0
  adopted: bool = False
  finished: bool = False
  cancelled: bool = False
  error: BaseException | None = None


@dataclass(eq=False, slots=True)
class _SavingOperation:
  token: int
  domain_id: int
  resolver: DomainsResolver
  candidate: DomainCandidate | None = None
  source: _SavingPass | None = None
  interests: list[_SavingPass] = field(default_factory=list)
  explicit: bool = False
  capacity_reserved: bool = False
  stored: bool = False
  detached: bool = False
  priority: bool = False
  started: bool = False
  attempted: bool = False
  processed: bool = False
  cancelled: bool = False
  task: Task[None] | None = None
  receipt: WriteReceipt | None = None
  done: Event | None = None
  error: BaseException | None = None
  queued_at: float | None = None


@dataclass(slots=True)
class _SelectionTicket:
  generation: int
  attempted: set[int]
  changed: set[int] = field(default_factory=set)


class SavingCoordinator:
  """Own saving priority, finite scan membership and per-ID physical lifecycles.

  Control transitions contain no awaits. SQL, DNS, admission and cleanup run
  outside those transitions, so request registration never waits for them.
  """

  def __init__(self) -> None:
    self._running = False
    self._stopping = False
    self._failure: BaseException | None = None
    self._generation = 0
    self._token = 0
    self._owners: dict[int, list[_SavingOperation]] = {}
    self._priority: deque[_SavingOperation] = deque()
    self._stale: deque[_SavingOperation] = deque()
    self._priority_waiting = 0
    self._explicit_count = 0
    self._passes: set[_SavingPass] = set()
    self._scans: deque[_SavingPass] = deque()
    self._new_request: _SavingPass | None = None
    self._current_new: _SavingPass | None = None
    self._ticket: _SelectionTicket | None = None
    self._receipts: dict[int, _SavingOperation] = {}
    self._active: dict[int, _SavingOperation] = {}
    self._workers: list[Task[None]] = []
    self._scan_task: Task[None] | None = None
    self._capture_task: Task[None] | None = None
    self._capturing: _SavingPass | None = None
    self._bookkeeping_task: Task[None] | None = None
    self._ready = Event()
    self._scan_ready = Event()
    self._outcomes = Event()
    self._capacity = Event()
    self._idle = Event()

  async def start(self) -> None:
    """Start one configured worker pool after the database writer is ready."""
    if self._running:
      self._check_open()
      return
    if self._owners:
      raise DatabaseWriteError('Saving coordinator retains unresolved domain ownership')
    self._stopping = False
    self._failure = None
    self._ready = Event()
    self._scan_ready = Event()
    self._outcomes = Event()
    self._capacity = Event()
    self._idle = Event()
    self._idle.set()
    self._running = True
    db.register_writer_failure_wakeup(self._outcomes)
    self._workers = [create_task(self._worker()) for _ in range(settings.domains_resolve_worker_limit)]
    self._scan_task = create_task(self._scan_loop())
    self._bookkeeping_task = create_task(self._bookkeep())
    self._check_open()

  def _check_open(self) -> None:
    failure = self._failure or db.writer_failure
    if failure is not None:
      raise DatabaseWriteError('Saving coordinator stopped after database writer failure') from failure
    if self._stopping:
      raise DatabaseWriteError('Saving coordinator is stopping')

  def _changed(self, domain_id: int) -> None:
    self._generation += 1
    if self._ticket is not None:
      self._ticket.changed.add(domain_id)

  @staticmethod
  def _finish_residence(operation: _SavingOperation, outcome: str) -> None:
    if operation.queued_at is not None:
      observe_duration(queue_duration, operation.queued_at, queue='resolve', phase='residence', outcome=outcome)
      operation.queued_at = None

  def _queue(self, operation: _SavingOperation) -> None:
    if operation.queued_at is None:
      operation.queued_at = perf_counter()
    (self._priority if operation.priority else self._stale).append(operation)
    self._ready.set()
    self._idle.clear()

  def _register_scan(self, mode: Jobs, resolver: DomainsResolver, detached: bool) -> _SavingPass | None:
    self._check_open()
    if mode not in {Jobs.DOMAINS_RESOLVE_NEW, Jobs.DOMAINS_RESOLVE_STALE}:
      raise ValueError(f'Unknown domains resolve mode: {mode}')
    if mode == Jobs.DOMAINS_RESOLVE_STALE and any(item.mode == mode for item in self._passes):
      return None
    if mode == Jobs.DOMAINS_RESOLVE_NEW and self._new_request is not None:
      self._new_request.detached |= detached
      self._new_request.callers += int(not detached)
      return self._new_request
    operation = _SavingPass(
      mode, resolver, detached, ResolutionRun('new' if mode == Jobs.DOMAINS_RESOLVE_NEW else 'stale')
    )
    operation.callers = int(not detached)
    self._passes.add(operation)
    self._scans.append(operation)
    if mode == Jobs.DOMAINS_RESOLVE_NEW:
      self._new_request = operation
    self._idle.clear()
    self._scan_ready.set()
    self._ready.set()
    return operation

  async def submit_scan(self, mode: Jobs, resolver: DomainsResolver | None = None) -> bool:
    """Register HTTP-owned demand before returning acceptance; active STALE returns false."""
    await self.start()
    accepted = self._register_scan(mode, resolver or DomainsResolver(), True) is not None
    if accepted:
      await job_registry.try_start(Jobs.DOMAINS_RESOLVE)
    return accepted

  async def resolve_scan(self, mode: Jobs, resolver: DomainsResolver) -> None:
    """Wait for a caller-owned pass; cancellation removes only that pass's interest."""
    await self.start()
    operation = self._register_scan(mode, resolver, False)
    if operation is None:
      return
    await job_registry.try_start(Jobs.DOMAINS_RESOLVE)
    try:
      await operation.done.wait()
      if operation.error is not None:
        raise operation.error
    except CancelledError:
      operation.callers -= 1
      if not operation.detached and not operation.callers:
        await _await_owned(self._cancel_pass(operation), cancel_on_cancel=False)
      raise
    finally:
      if not self._passes:
        await _await_owned(self._finish_activity(), cancel_on_cancel=False)

  async def _register_stored(self, domain_id: int, resolver: DomainsResolver, detached: bool) -> _SavingOperation:
    started = perf_counter()
    outcome = 'rejected'
    try:
      operation = await self._accept_stored(domain_id, resolver, detached)
      outcome = 'admitted'
      return operation
    except CancelledError:
      outcome = 'cancelled'
      raise
    finally:
      observe_duration(queue_duration, started, queue='resolve', phase='admission', outcome=outcome)

  async def _accept_stored(self, domain_id: int, resolver: DomainsResolver, detached: bool) -> _SavingOperation:
    await self.start()
    while self._explicit_count >= settings.queue_max_size:
      self._capacity.clear()
      self._check_open()
      await self._capacity.wait()
    self._check_open()
    self._explicit_count += 1
    self._idle.clear()
    self._token += 1
    owners = self._owners.get(domain_id)
    if owners and not owners[0].started and not owners[0].explicit and not owners[0].priority:
      # Preserve the automatic interest, but give the replacement a fresh token
      # and stored origin. Promotion itself is never actual-attempt evidence.
      operation = owners[0]
      self._finish_residence(operation, 'promoted')
      operation.token = self._token
      operation.resolver = resolver
      operation.candidate = None
      operation.explicit = True
      operation.capacity_reserved = True
      operation.stored = True
      operation.detached = detached
      operation.priority = True
      operation.done = Event()
      self._priority_waiting += 1
      self._changed(domain_id)
      self._queue(operation)
    else:
      operation = _SavingOperation(
        self._token,
        domain_id,
        resolver,
        explicit=True,
        capacity_reserved=True,
        stored=True,
        detached=detached,
        priority=True,
        done=Event(),
      )
      self._priority_waiting += 1
      if owners is None:
        self._owners[domain_id] = [operation]
        self._queue(operation)
      else:
        operation.queued_at = perf_counter()
        owners.append(operation)
      self._changed(domain_id)
    self._ready.set()
    return operation

  async def submit_stored(self, domain_id: int, resolver: DomainsResolver | None = None) -> None:
    """Accept one distinct saved-ID operation with bounded explicit backpressure."""
    await self._register_stored(domain_id, resolver or DomainsResolver(), True)

  async def resolve_stored(self, domain_id: int, resolver: DomainsResolver) -> None:
    """Wait for processing/admission; writer-admitted work remains database-owned."""
    operation = await self._register_stored(domain_id, resolver, False)
    try:
      if operation.done is not None:
        await operation.done.wait()
      if operation.error is not None:
        raise operation.error
    except CancelledError:
      operation.detached = False
      operation.explicit = False
      await _await_owned(self._cancel_unneeded(operation), cancel_on_cancel=False)
      raise

  def _has_priority(self) -> bool:
    return (
      self._priority_waiting > 0
      or any(operation.priority and not operation.processed for operation in self._active.values())
      or any(item.mode == Jobs.DOMAINS_RESOLVE_NEW and not item.adopted and not item.cancelled for item in self._passes)
    )

  def _take(self) -> _SavingOperation | None:
    for queue in (self._priority, self._stale):
      if queue is self._stale and self._has_priority():
        break
      while queue:
        operation = queue.popleft()
        owners = self._owners.get(operation.domain_id)
        if (
          operation.cancelled
          or operation.started
          or not owners
          or owners[0] is not operation
          or (queue is self._stale and operation.priority)
        ):
          continue
        self._finish_residence(operation, 'dequeued')
        operation.started = True
        self._active[operation.token] = operation
        self._changed(operation.domain_id)
        return operation
    return None

  async def _worker(self) -> None:
    while not self._stopping and self._failure is None:
      operation = self._take()
      if operation is None:
        self._ready.clear()
        await self._ready.wait()
        continue
      operation.task = create_task(self._execute(operation))
      try:
        await gather(operation.task, return_exceptions=True)
      finally:
        # A child cancelled before its first step cannot run its own finally.
        self._finish_operation(operation)

  async def _execute(self, operation: _SavingOperation) -> None:
    domain: DomainResult | None = None
    run: ResolutionRun | None = None
    try:
      self._check_open()
      if operation.stored:
        candidate = await db.get_domain_candidate_for_resolve(operation.domain_id)
        servers = await operation.resolver.saving_dns_snapshot() if candidate is not None else None
        context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
      else:
        candidate = operation.candidate
        source = operation.source
        servers = source.servers if source is not None else None
        context = source.context if source is not None else None
      self._check_open()
      if operation.cancelled:
        return
      if candidate is None:
        if operation.interests:
          operation.error = DatabaseWriteError('Domain disappeared before its saving attempt')
        return
      if servers is None or context is None:
        raise DnsConfigurationReadError('Cannot read DNS configuration')
      domain = DomainResult(id=candidate.id, name=candidate.name, list_id=candidate.list_id)
      run = ResolutionRun('stored') if operation.stored else operation.source.run if operation.source else None
      if run is not None:
        if operation.stored:
          run.select(1)
        domain.observation = run.observe()
      operation.receipt = domain.write_receipt = WriteReceipt()
      operation.receipt.add_wakeup(self._outcomes)
      self._receipts[operation.token] = operation
      # This transition precedes real resolution with no await between them.
      operation.attempted = True
      self._release_capacity(operation)
      if operation.priority:
        self._priority_waiting -= 1
      self._ready.set()
      if self._ticket is not None:
        self._ticket.attempted.add(operation.domain_id)
      self._changed(operation.domain_id)
      for interest in operation.interests:
        interest.run.cover()
      notify_observation(domain.observation, 'processing_started', perf_counter())
      await operation.resolver.process_saving_domain(domain, servers, context)
    except CancelledError:
      operation.error = operation.error or CancelledError()
      raise
    except Exception as err:
      operation.error = err
      if isinstance(err, DatabaseWriteError):
        self._fail(err)
      logger.error(
        'Saving domain operation failed [%s]', type(err).__name__, exc_info=RuntimeError('Saving operation failed')
      )
    finally:
      if run is not None and operation.stored:
        run.finish(operation.error is None)
      self._finish_operation(operation)

  def _finish_operation(self, operation: _SavingOperation) -> None:
    """Finalize a terminated physical task once, including cancellation before entry."""
    if operation.processed:
      return
    if operation.task is not None and operation.task.cancelled():
      operation.error = operation.error or CancelledError()
    if operation.priority and not operation.attempted and not self._failure:
      self._priority_waiting -= 1
    operation.processed = True
    self._release_capacity(operation)
    self._active.pop(operation.token, None)
    self._complete_interests(operation)
    if operation.done is not None:
      operation.done.set()
    self._release_known(operation)
    self._ready.set()
    self._outcomes.set()
    self._update_idle()

  def _complete_interests(self, operation: _SavingOperation) -> None:
    for interest in tuple(operation.interests):
      if operation.error is not None:
        interest.error = interest.error or operation.error
      interest.remaining -= 1
      self._finish_pass(interest)
    operation.interests.clear()

  def _release_capacity(self, operation: _SavingOperation) -> None:
    if operation.capacity_reserved:
      operation.capacity_reserved = False
      self._explicit_count -= 1
      self._capacity.set()

  def _release_known(self, operation: _SavingOperation) -> None:
    if not operation.processed:
      return
    receipt = operation.receipt
    if (
      receipt is not None
      and receipt.admitted
      and receipt.outcome not in {WriteOutcome.CONFIRMED, WriteOutcome.KNOWN_NOT_COMMITTED}
    ):
      return
    self._finish_residence(operation, 'cancelled')
    self._receipts.pop(operation.token, None)
    if receipt is not None:
      receipt.remove_wakeup(self._outcomes)
    owners = self._owners.get(operation.domain_id)
    if not owners or owners[0] is not operation:
      return
    owners.pop(0)
    self._changed(operation.domain_id)
    self._release_capacity(operation)
    if owners:
      if not self._stopping and self._failure is None:
        self._queue(owners[0])
    else:
      del self._owners[operation.domain_id]
    self._ready.set()

  async def _scan_loop(self) -> None:
    while not self._stopping and self._failure is None:
      if not self._scans or (self._new_request is not None and self._current_new is not None):
        self._scan_ready.clear()
        await self._scan_ready.wait()
        continue
      # A pending NEW capture precedes any not-yet-started STALE capture.
      operation = next((item for item in self._scans if item.mode == Jobs.DOMAINS_RESOLVE_NEW), self._scans[0])
      self._scans.remove(operation)
      if operation.cancelled:
        continue
      if self._new_request is operation:
        self._new_request = None
        self._current_new = operation
      self._capturing = operation
      self._capture_task = create_task(self._capture_scan(operation))
      await gather(self._capture_task, return_exceptions=True)
      self._capture_task = None
      self._capturing = None

  async def _capture_scan(self, operation: _SavingPass) -> None:
    await job_registry.try_start(Jobs.DOMAINS_RESOLVE)
    self._ticket = _SelectionTicket(
      self._generation,
      {domain_id for domain_id, owners in self._owners.items() if owners[0].attempted},
    )
    try:
      candidates = await (
        db.get_new_domains_for_resolve()
        if operation.mode == Jobs.DOMAINS_RESOLVE_NEW
        else db.get_stale_domains_for_resolve()
      )
      self._check_open()
      operation.run.select(len(candidates))
      if candidates:
        operation.servers = await operation.resolver.saving_dns_snapshot()
        operation.context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
      for index, candidate in enumerate(candidates):
        self._check_open()
        if operation.cancelled:
          break
        self._adopt(operation, candidate)
        if index % 128 == 127:
          await sleep(0)
    except CancelledError:
      operation.error = operation.error or CancelledError()
      raise
    except Exception as err:
      operation.error = err
      logger.error(
        'Domain membership selection or adoption failed [%s]',
        type(err).__name__,
        exc_info=RuntimeError('Domain membership selection or adoption failed'),
      )
    finally:
      self._ticket = None
      operation.adopted = True
      self._finish_pass(operation)
      self._ready.set()

  def _adopt(self, scan: _SavingPass, candidate: DomainCandidate) -> None:
    started = perf_counter()
    ticket = self._ticket
    if ticket is None:
      raise RuntimeError('Missing domain membership ticket')
    if candidate.id in ticket.attempted:
      scan.run.cover()
      return
    owners = self._owners.get(candidate.id)
    if owners:
      operation = owners[0]
      if scan not in operation.interests:
        operation.interests.append(scan)
        scan.remaining += 1
      if scan.mode == Jobs.DOMAINS_RESOLVE_NEW and not operation.started and not operation.priority:
        operation.priority = True
        self._priority_waiting += 1
        self._queue(operation)
      return
    if candidate.id in ticket.changed:
      scan.error = DatabaseWriteError('Domain membership pass incomplete after an unattempted reservation changed')
      return
    self._token += 1
    operation = _SavingOperation(
      self._token,
      candidate.id,
      scan.resolver,
      candidate=candidate,
      source=scan,
      interests=[scan],
      priority=scan.mode == Jobs.DOMAINS_RESOLVE_NEW,
    )
    scan.remaining += 1
    self._owners[candidate.id] = [operation]
    self._priority_waiting += int(operation.priority)
    self._changed(candidate.id)
    self._queue(operation)
    observe_duration(queue_duration, started, queue='resolve', phase='admission', outcome='admitted')

  def _finish_pass(self, scan: _SavingPass) -> None:
    if not scan.adopted or scan.remaining or scan.finished:
      return
    scan.finished = True
    scan.run.finish(scan.error is None and not scan.cancelled)
    scan.done.set()
    self._passes.discard(scan)
    if self._current_new is scan:
      self._current_new = None
    self._scan_ready.set()
    self._outcomes.set()
    self._update_idle()

  async def _cancel_pass(self, scan: _SavingPass) -> None:
    scan.cancelled = True
    scan.error = CancelledError()
    operations = [operation for owners in self._owners.values() for operation in owners if scan in operation.interests]
    for operation in operations:
      operation.interests.remove(scan)
      scan.remaining -= 1
    # Close every abandoned dispatch slot before awaiting any active cleanup.
    for operation in operations:
      if not operation.interests and not operation.explicit and not operation.detached:
        receipt = operation.receipt
        if receipt is None or not receipt.admitted:
          operation.cancelled = True
          if operation.task is not None and not operation.task.done():
            operation.task.cancel()
    for index, operation in enumerate(operations):
      await self._cancel_unneeded(operation)
      if index % 128 == 127:
        await sleep(0)
    if self._capturing is scan and self._capture_task is not None:
      self._capture_task.cancel()
      await gather(self._capture_task, return_exceptions=True)
    if scan in self._scans:
      self._scans.remove(scan)
      scan.adopted = True
    if self._new_request is scan:
      self._new_request = None
    self._finish_pass(scan)
    self._ready.set()

  async def _cancel_unneeded(self, operation: _SavingOperation) -> None:
    if operation.interests or operation.explicit or operation.detached:
      return
    receipt = operation.receipt
    if receipt is not None and receipt.admitted:
      return
    was_cancelled = operation.cancelled
    operation.cancelled = True
    if operation.task is not None and not operation.task.done():
      if not was_cancelled:
        operation.task.cancel()
      await gather(operation.task, return_exceptions=True)
    if operation.started:
      self._finish_operation(operation)
    elif not operation.processed:
      if operation.priority:
        self._priority_waiting -= 1
      operation.processed = True
      self._release_capacity(operation)
      owners = self._owners.get(operation.domain_id)
      if owners and owners[0] is not operation:
        self._finish_residence(operation, 'cancelled')
        owners.remove(operation)
        self._changed(operation.domain_id)
      else:
        self._release_known(operation)

  def _fail(self, failure: BaseException) -> None:
    if self._failure is not None:
      return
    self._failure = failure
    for scan in tuple(self._passes):
      scan.error = failure
      scan.cancelled = True
      scan.done.set()
    for scan in self._scans:
      scan.adopted = True
      self._finish_pass(scan)
    self._scans.clear()
    self._new_request = None
    for owners in tuple(self._owners.values()):
      for operation in tuple(owners):
        operation.error = failure
        operation.cancelled = True
        if operation.done is not None:
          operation.done.set()
        if operation.task is not None and not operation.task.done():
          if operation.task is not current_task():
            operation.task.cancel()
        elif not operation.started:
          operation.processed = True
          self._complete_interests(operation)
      # Known unstarted successors must fail without waiting behind an unknown fence.
      while len(owners) > 1:
        successor = owners.pop()
        self._finish_residence(successor, 'cancelled')
        self._release_capacity(successor)
      self._release_known(owners[0])
    self._priority.clear()
    self._stale.clear()
    self._priority_waiting = 0
    self._capacity.set()
    self._ready.set()
    self._scan_ready.set()
    self._update_idle()

  async def _bookkeep(self) -> None:
    while True:
      self._outcomes.clear()
      if db.writer_failure is not None:
        self._fail(db.writer_failure)
      for operation in tuple(self._receipts.values()):
        self._release_known(operation)
      if not self._passes:
        await self._finish_activity()
      self._update_idle()
      await self._outcomes.wait()

  async def _finish_activity(self) -> None:
    await job_registry.finish(Jobs.DOMAINS_RESOLVE)
    # Registration may have occurred while an older finish awaited its lock.
    if self._passes:
      await job_registry.try_start(Jobs.DOMAINS_RESOLVE)

  def _update_idle(self) -> None:
    if (
      not self._passes
      and not self._active
      and not any(not operation.processed for owners in self._owners.values() for operation in owners)
    ):
      self._idle.set()

  async def wait_idle(self) -> None:
    """Wait for selection and processing/admission, without waiting for commits."""
    await self._idle.wait()
    if self._failure is not None:
      raise DatabaseWriteError('Saving coordinator failed') from self._failure

  async def stop(self) -> None:
    """Stop new work and retain all preadmission cleanup before database drain."""
    if not self._running:
      return
    self._stopping = True
    self._capacity.set()
    self._ready.set()
    self._scan_ready.set()
    if self._scan_task is not None:
      self._scan_task.cancel()
    for scan in tuple(self._passes):
      scan.cancelled = True
      scan.error = DatabaseWriteError('Saving coordinator stopped before pass completion')
    operations = [operation for owners in self._owners.values() for operation in owners]
    for operation in operations:
      operation.interests.clear()
      if operation.done is not None:
        operation.error = operation.error or DatabaseWriteError(
          'Saving coordinator stopped before processing completed'
        )
        operation.done.set()
      if operation.task is not None and not operation.task.done():
        operation.task.cancel()
      elif not operation.started:
        operation.cancelled = True
        operation.processed = True
    tasks = [operation.task for operation in operations if operation.task is not None]
    if self._scan_task is not None:
      tasks.append(self._scan_task)
    await _await_owned(self._finish_stop(tasks), cancel_on_cancel=False)

  async def _finish_stop(self, tasks: list[Task[None]]) -> None:
    await gather(*tasks, return_exceptions=True)
    for worker in self._workers:
      worker.cancel()
    await gather(*self._workers, return_exceptions=True)
    for scan in tuple(self._passes):
      scan.remaining = 0
      scan.adopted = True
      self._finish_pass(scan)
    self._scans.clear()
    self._new_request = None
    self._priority.clear()
    self._stale.clear()
    self._priority_waiting = 0
    for owners in tuple(self._owners.values()):
      while len(owners) > 1:
        successor = owners.pop()
        self._finish_residence(successor, 'cancelled')
        self._release_capacity(successor)
      self._release_known(owners[0])
    await job_registry.finish(Jobs.DOMAINS_RESOLVE)
    self._outcomes.set()
    self._update_idle()

  async def finish_close(self) -> None:
    """Retire bookkeeping after database drain and retained native cleanup."""
    try:
      await db.wait_closed_cleanup()
    finally:
      for operation in tuple(self._receipts.values()):
        self._release_known(operation)
      await self._retire_bookkeeping()

  async def _retire_bookkeeping(self) -> None:
    if self._receipts:
      logger.error('Saving coordinator retains unresolved database outcomes: %s', len(self._receipts))
    db.unregister_writer_failure_wakeup(self._outcomes)
    if self._bookkeeping_task is not None:
      self._bookkeeping_task.cancel()
      await gather(self._bookkeeping_task, return_exceptions=True)
    self._running = False


saving_coordinator = SavingCoordinator()
