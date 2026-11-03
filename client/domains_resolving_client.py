from asyncio import (
  CancelledError,
  Queue,
  Semaphore,
  TaskGroup,
  create_task,
  gather,
  sleep,
  timeout,
  wait_for,
)
from base64 import urlsafe_b64encode
from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from math import ceil
from threading import Event
from time import perf_counter
from types import CoroutineType
from typing import Dict, List, Literal, Self

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
from database.db import DnsConfigurationReadError, DomainIpReadError, db
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
  DomainResult,
  ProcessingOutcome,
)
from models.dto.ip_record_dto import IpRecordDto
from models.dto.queue_dto import notify_observation
from models.http.dns_servers_resp import DnsElementResp
from models.http.domains_req import DomainsPostElementReq
from models.http.domains_resp import DomainElementResp
from utils.utils import get_ip_network_address, get_ip_version

type _DnsServersSnapshot = tuple[tuple[DnsServerDto, ...], tuple[DnsServerDto, ...]]


@dataclass(frozen=True)
class _DefaultDnsContext:
  """Own endpoint resolvers and fixed timeout settings for one operation or job."""

  timeout: float
  lifetime: float
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
  __stop_domains_resolve_event: Event = Event()
  __queue_sleep_timeout: float = settings.queue_sleep_timeout
  __queue_get_timeout: float = settings.queue_get_timeout
  __task_exception_error_timeout: float = 10.0

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

  domains_resolve_queue: Queue[DomainResult] = Queue(maxsize=settings.queue_max_size)

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

  # Get domains from Queue
  async def __task_process_domains_resolve_from_queue(
    self: Self, count_all: int, log_every: int, dns_servers: _DnsServersSnapshot | None = None
  ) -> None:
    if count_all > 0 and dns_servers is None:
      dns_servers = await self.__dns_snapshot()
    if dns_servers is None:
      return
    dns_context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
    logger.info('STARTING A FLOW - Resolve domains')
    processed: int = 0
    while not self.__stop_domains_resolve_event.is_set() and processed < count_all:
      try:
        domain: DomainResult = await wait_for(self.domains_resolve_queue.get(), timeout=self.__queue_get_timeout)
      except TimeoutError:
        await sleep(self.__queue_sleep_timeout)
        continue
      try:
        if domain.admitted_at is not None:
          observe_duration(queue_duration, domain.admitted_at, queue='resolve', phase='residence', outcome='dequeued')
          domain.admitted_at = None
        notify_observation(domain.observation, 'processing_started', perf_counter())
        logger.debug(f'START resolving domain element {domain=}')
        await self.__dns_main_tasker(
          domain=domain,
          default_dns_servers=dns_servers[0],
          doh_dns_servers=dns_servers[1],
          dns_context=dns_context,
        )
        logger.debug(f'END resolving domain element {domain=}')
      except CancelledError:
        if domain.processing_outcome is None:
          domain.processing_outcome = ProcessingOutcome.CANCELLED
        raise
      except Exception as err:
        logger.error(f'Unexpected error in flow - Resolve domains : {err}', exc_info=True)
        await sleep(self.__task_exception_error_timeout)
      finally:
        self.__finish_domain_observation(domain)
        self.domains_resolve_queue.task_done()
        processed += 1
        residue: int = count_all - processed
        if processed % log_every == 0 or residue == 0:
          logger.info(f'Domains attempted: {processed}, residue: {residue}')
    logger.info('STOP FLOW - Resolve domains')

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
      outcomes: list[DnsQueryOutcome] = list(await gather(*tasks))
      try:
        known_cnames = {_absolute_name(from_text(cname.domain)) for cname in discovered_cnames or []}
        additional_cnames = [
          DomainsPostElementReq(domain=cname, list_id=domain.list_id)
          for cname in dict.fromkeys(cname for outcome in outcomes for cname in outcome.cnames)
          if _absolute_name(from_text(cname)) not in known_cnames
        ]
        if additional_cnames:
          await self.__persist_cnames(additional_cnames)
      except Exception as err:
        logger.warning(f'[{err.__class__.__name__}]: additional CNAME discovery failed')
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
      current_ips: List[IpRecordDto] = await db.get_all_ips_for_domain(domain_id=domain.id)
      domain.resolution_complete = complete
      # add new ips, remove not resolved ips but current exists
      await self.__ips_processing(domain=domain, current_ips=current_ips)
      domain.processing_outcome = ProcessingOutcome.SUCCESS if complete else ProcessingOutcome.PARTIAL
      notify_observation(domain.observation, domain.processing_outcome, perf_counter())
      # INSERT IPS (send to Queue)
      # DELETE IPS (send to Queue)
      # UPDATE DOMAINS (send to Queue)
      if complete or domain.insert.ips_insert:
        await db.put_domain_after_resolve(domain=domain)
      logger.debug(f'FINAL resolve domain {domain=}')
    except CancelledError:
      if domain.processing_outcome is None:
        domain.processing_outcome = ProcessingOutcome.CANCELLED
      notify_observation(domain.observation, domain.processing_outcome, perf_counter())
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
      logger.error(f'[{err.__class__.__name__}]: domain resolving cycle failed')

  async def __persist_cnames(self: Self, cnames: list[DomainsPostElementReq]) -> None:
    try:
      await db.put_add_domains_to_queue(domains=cnames)
    except Exception as err:
      logger.warning(f'[{err.__class__.__name__}]: CNAME discovery could not be queued')

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
    deadline = timeout(settings.doh_operation_timeout if transport == 'doh' else settings.dns_operation_timeout)
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
          reason = err.__class__.__name__
        measurement.update(reason=reason)
        return DnsQueryOutcome(dns_server.server, 'classic', lookup_type, DnsQueryStatus.FAILURE, reason=reason)
    except TimeoutError:
      return DnsQueryOutcome(dns_server.server, 'classic', lookup_type, DnsQueryStatus.FAILURE, reason='timeout')

  async def __cname_doh_resolver(
    self: Self, domain: DomainResult, dns_server: DnsServerDto, cname_domains: List[DomainsPostElementReq]
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
          logger.debug(f'[{err.__class__.__name__}]: DoH CNAME discovery failed')
    except TimeoutError:
      logger.debug('CNAME discovery operation timed out')

  async def __cname_default_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq],
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
          logger.debug(f'[{err.__class__.__name__}]: classic CNAME discovery failed')
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
  def __get_current_cidr_for_resolved_ip(resolved_ip: str, current_ip_records: List[IpRecordDto]) -> str | None:
    for record in current_ip_records:
      if '/' not in record.ip_address:
        continue
      if get_ip_network_address(record.ip_address) == resolved_ip:
        return record.ip_address
    return None

  async def __get_ip_address_for_storage(self: Self, resolved_ip: str, current_ip_records: List[IpRecordDto]) -> str:
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

  async def __ips_processing(self: Self, domain: DomainResult, current_ips: List[IpRecordDto]) -> None:
    logger.debug(f'IP prepare for {domain.name}')
    logger.debug(f'{domain=}, {current_ips=}')
    try:
      resolved_ips: List[str] = list(dict.fromkeys(str(IPv4Address(address)) for address in domain.result.A))
      current_ips_by_network_address: Dict[str, List[IpRecordDto]] = {}
      desired_ips_by_network_address: Dict[str, IpRecordDto] = {}
      new_ips: List[IpRecordDto] = []
      remove_ips: List[IpRecordDto] = []

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

      if domain.resolution_complete:
        for stale_ip_records in current_ips_by_network_address.values():
          remove_ips.extend(stale_ip_records)

      if len(new_ips) > 0:
        domain.append_ips_to_insert(ips=new_ips)
      if len(remove_ips) > 0:
        domain.append_ips_to_delete(ips=remove_ips)
    except Exception as err:
      raise err

  # Job

  # Put domains to Queue
  async def domains_resolve(self: Self, job_mode: Jobs) -> None:
    run = ResolutionRun('new' if job_mode == Jobs.DOMAINS_RESOLVE_NEW else 'stale')
    normal = False
    logger.info(f'Domains resolve mode={job_mode} - START')
    try:
      #
      match job_mode:
        case Jobs.DOMAINS_RESOLVE_NEW:
          domains: List[DomainResult] = await db.get_new_domains_for_resolve()
        case Jobs.DOMAINS_RESOLVE_STALE:
          domains: List[DomainResult] = await db.get_stale_domains_for_resolve()
        case _:
          raise Exception(f'Unknown domains resolve job_mode:{job_mode}')
      len_domains: int = len(domains)
      run.select(len_domains)
      for domain in domains:
        domain.observation = run.observe()
      resolve_domains_log_every: int = settings.resolve_domains_log_every
      log_every: int = max(1, ceil(len_domains / resolve_domains_log_every))
      logger.info(f'Domains for resolve mode={job_mode}: {len_domains}, log_every: {log_every}')
      if len_domains > 0:
        dns_servers = await self.__dns_snapshot()
        #
        logger.debug(f'Start task {job_mode} ...')
        self.__stop_domains_resolve_event.clear()
        create_task(
          coro=self.__task_process_domains_resolve_from_queue(
            count_all=len_domains, log_every=log_every, dns_servers=dns_servers
          ),
          name=f'__task_process_domains_resolve_from_queue_{job_mode}',
        )
        [await self.__put_domain(domain) for domain in domains]
        # STOP domains resolve
        await self.domains_resolve_queue.join()
        self.__stop_domains_resolve_event.set()
        logger.info(f'Domains resolve mode={job_mode} - DONE')
      else:
        logger.info(f'Domains resolve mode={job_mode} - Not found domains for resolve. DONE')
      normal = True
    except DnsConfigurationReadError:
      logger.error('Domains resolve could not read DNS configuration')
      raise
    except Exception as err:
      logger.error(f'Try Domains resolve mode={job_mode} failed [{err.__class__.__name__}] : {err}', exc_info=True)
    finally:
      run.finish(normal)
      await job_registry.finish(Jobs.DOMAINS_RESOLVE)

  async def __put_domain(self, domain: DomainResult) -> None:
    started = perf_counter()
    outcome = 'rejected'
    try:
      await self.domains_resolve_queue.put(item=domain)
      domain.admitted_at = perf_counter()
      outcome = 'admitted'
    except CancelledError:
      outcome = 'cancelled'
      raise
    finally:
      observe_duration(queue_duration, started, queue='resolve', phase='admission', outcome=outcome)

  async def resolve_once(
    self: Self, domain_name: str, selected_dns_servers: List[DnsElementResp] | None = None
  ) -> CheckDomainResultDto:
    name: str = domain_name.strip().rstrip('.')
    if not name:
      raise ValueError('Domain name must not be empty')
    #
    default_dns_servers: List[DnsServerDto] = []
    doh_dns_servers: List[DnsServerDto] = []
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
    tasks: list[CoroutineType] = []
    dns_context = _DefaultDnsContext(settings.dns_timeout, settings.dns_lifetime)
    #
    for dns_server in default_dns_servers:
      tasks.append(self.__resolve_once_default_server(domain_name=name, dns_server=dns_server, dns_context=dns_context))
    for dns_server in doh_dns_servers:
      tasks.append(self.__resolve_once_doh_server(domain_name=name, doh_server=dns_server))
    if not tasks:
      raise RuntimeError('DNS servers for resolve not found')
    #
    results: list[DnsServerResolveResultDto] = list(await gather(*tasks))
    #
    return CheckDomainResultDto(domain=name, results=results)

  async def resolve_stored_domain(self: Self, domain_id: int) -> None:
    run = ResolutionRun('stored')
    domain: DomainResult | None = None
    normal = False
    logger.info(f'Immediate resolving stored domain ID={domain_id} - START')
    try:
      domain_record: DomainElementResp | None = await db.get_domain_on_id(id=domain_id)
      if domain_record is None:
        logger.warning(f'Domain ID={domain_id} not found for resolving')
        normal = True
        return
      domain = DomainResult(id=domain_record.id, name=domain_record.name, list_id=domain_record.domains_list_id)
      run.select(1)
      domain.observation = run.observe()
      notify_observation(domain.observation, 'processing_started', perf_counter())
      #
      default_dns, doh_dns = await self.__dns_snapshot()
      if not default_dns and not doh_dns:
        raise RuntimeError('DNS servers for resolve not found')
      #
      await self.__dns_main_tasker(domain=domain, default_dns_servers=default_dns, doh_dns_servers=doh_dns)
      normal = True
    except CancelledError:
      if domain is not None and domain.processing_outcome is None:
        domain.processing_outcome = ProcessingOutcome.CANCELLED
      raise
    except DnsConfigurationReadError:
      logger.error('Stored domain resolve could not read DNS configuration')
      raise
    except Exception as err:
      normal = domain is not None
      logger.error(f'Resolving domain ID={domain_id} failed: [{err.__class__.__name__}]: {err}', exc_info=True)
    finally:
      if domain is not None:
        self.__finish_domain_observation(domain)
      run.finish(normal)
