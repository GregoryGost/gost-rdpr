from threading import Event
from math import ceil
from asyncio import (
  sleep,
  wait_for,
  create_task,
  gather,
  Queue,
  TimeoutError,
  Semaphore
)
from dns.resolver import Answer, NoAnswer, NXDOMAIN
from dns.asyncresolver import Resolver
from dns.exception import DNSException
from dns.flags import QR, TC
from dns.name import Name, from_text, root
from dns.opcode import QUERY
from dns.rcode import NOERROR, NXDOMAIN as NXDOMAIN_RCODE
from dns.rdataclass import IN
from dns.rdatatype import RdataType, A, AAAA, CNAME, SOA, NS, RRSIG, NSEC, NSEC3, NSEC3PARAM, SIG
from dns.message import Message, MAX_CHAIN, make_query, from_wire
from itertools import product
from base64 import urlsafe_b64encode
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from httpx import AsyncClient, HTTPError
from types import CoroutineType
from typing import Self, List, Tuple, Dict, Literal

from logger.logger import logger
from config.config import settings
from jobs.job_registry import job_registry, Jobs
from database.db import db, DomainIpReadError
from client.http_base_client import HttpClient
from client.ripe_stat_client import RipeStatClient, RipeStatClientError
from utils.utils import get_ip_network_address, get_ip_version

from models.http.domains_req import DomainsPostElementReq
from models.http.domains_resp import DomainElementResp
from models.http.dns_servers_resp import DnsElementResp

from models.dto.domains_dto import (
  DomainResult,
  CheckDomainResultDto,
  DnsServerResolveResultDto,
  DnsQueryOutcome,
  DnsQueryStatus
)
from models.dto.dns_server_dto import DnsServerDto
from models.dto.ip_record_dto import IpRecordDto


class _DnsResponseError(ValueError):
  """A DNS response failed a semantic or transport check."""


def _absolute_name(name: Name) -> Name:
  return name.derelativize(root).canonicalize()


def _validated_dns_response(
  response: Message | None,
  domain_name: str,
  lookup_type: RdataType,
  query_id: int | None = None
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
      rrset for rrset in response.answer
      if rrset.rdclass == IN and _absolute_name(rrset.name) == terminal
    ]
    cname_records = [rrset for rrset in owner_records if rrset.rdtype == CNAME]
    if not cname_records:
      return terminal, tuple(cnames), owners
    targets = {
      _absolute_name(from_text(record.to_text()))
      for rrset in cname_records
      for record in rrset
    }
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
  query_id: int | None = None
) -> DnsQueryOutcome:
  """Classify one A response without applying address storage policy."""
  try:
    if lookup_type != A:
      raise _DnsResponseError('unsupported_lookup_type')
    response = _validated_dns_response(response, domain_name, lookup_type, query_id)
    terminal, cnames, cname_owners = _reachable_cnames(response)
    addresses = tuple(sorted({
      str(IPv4Address(record.to_text()))
      for rrset in response.answer
      if rrset.rdclass == IN and rrset.rdtype == A
      and _absolute_name(rrset.name) == terminal
      for record in rrset
    }))
    if addresses:
      if response.rcode() != NOERROR:
        raise _DnsResponseError('nxdomain_with_addresses')
      return DnsQueryOutcome(
        server, server_type, lookup_type, DnsQueryStatus.ADDRESSES,
        addresses=addresses, cnames=cnames
      )
    dnssec_metadata = (RRSIG, NSEC, NSEC3, NSEC3PARAM, SIG)
    for rrset in response.answer:
      if rrset.rdtype in dnssec_metadata:
        continue
      if (
        rrset.rdclass == IN and rrset.rdtype == CNAME
        and _absolute_name(rrset.name) in cname_owners
      ):
        continue
      raise _DnsResponseError('unrelated_negative_answer')
    covering_soa = any(
      rrset.rdclass == IN and rrset.rdtype == SOA and rrset
      and terminal.is_subdomain(_absolute_name(rrset.name))
      for rrset in response.authority
    )
    if response.rcode() == NOERROR and not covering_soa and any(
      rrset.rdtype == NS for rrset in response.authority
    ):
      raise _DnsResponseError('referral')
    if response.rcode() == NOERROR and not covering_soa:
      raise _DnsResponseError('unconfirmed_absence')
    return DnsQueryOutcome(
      server, server_type, lookup_type, DnsQueryStatus.ABSENT, cnames=cnames
    )
  except _DnsResponseError as err:
    reason = str(err)
  except (DNSException, ValueError, TypeError, AttributeError, IndexError):
    reason = 'malformed_response'
  return DnsQueryOutcome(
    server, server_type, lookup_type, DnsQueryStatus.FAILURE, reason=reason
  )


class DomainsResolver:

  __stop_domains_resolve_event: Event = Event()
  __queue_sleep_timeout: float = settings.queue_sleep_timeout
  __queue_get_timeout: float = settings.queue_get_timeout
  __task_exception_error_timeout: float = 10.0

  __lookup_types: tuple[Literal[RdataType.A]] = (A, ) # (A, AAAA)
  __semaphore: Semaphore = Semaphore(settings.domains_resolve_semaphore_limit)

  __http_client: AsyncClient = HttpClient.get_client('domains_resolver')

  __ripe_stat_client: RipeStatClient = RipeStatClient()
  __ripe_stat_semaphore: Semaphore = Semaphore(
    settings.ripe_stat_requests_semaphore_limit
  )

  domains_resolve_queue: Queue[DomainResult] = Queue(maxsize=settings.queue_max_size)

  def __init__(self: Self) -> None:
    logger.info(f'{self.__class__.__name__} init')

  # Get domains from Queue
  async def __task_process_domains_resolve_from_queue(self: Self, count_all: int, log_every: int) -> None:
    logger.info('STARTING A FLOW - Resolve domains')
    processed: int = 0
    while not self.__stop_domains_resolve_event.is_set() and processed < count_all:
      try:
        domain: DomainResult = await wait_for(
          self.domains_resolve_queue.get(),
          timeout=self.__queue_get_timeout
        )
      except TimeoutError:
        await sleep(self.__queue_sleep_timeout)
        continue
      try:
        logger.debug(f'START resolving domain element {domain=}')
        # get dns servers
        dns_servers: Tuple[List[DnsServerDto], List[DnsServerDto]] = await db.get_dns_servers_for_resolve() # first default, second doh
        # cname
        domain_cname: List[DomainsPostElementReq] = await self.__dns_cname_tasker(
          domain=domain,
          default_dns_servers=dns_servers[0],
          doh_dns_servers=dns_servers[1]
        )
        if len(domain_cname) > 0:
          logger.debug(f'{domain_cname=}')
          await self.__persist_cnames(domain_cname)
        # resolve
        await self.__dns_main_tasker(
          domain=domain,
          default_dns_servers=dns_servers[0],
          doh_dns_servers=dns_servers[1],
          discovered_cnames=domain_cname
        )
        logger.debug(f'END resolving domain element {domain=}')
      except Exception as err:
        logger.error(f'Unexpected error in flow - Resolve domains : {err}', exc_info=True)
        await sleep(self.__task_exception_error_timeout)
      finally:
        self.domains_resolve_queue.task_done()
        processed += 1
        residue: int = count_all - processed
        if processed % log_every == 0 or residue == 0:
          logger.info(f'Domains resolved: {processed}, residue: {residue}')
    logger.info('STOP FLOW - Resolve domains')

  async def __dns_main_tasker(
    self: Self,
    domain: DomainResult,
    default_dns_servers: List[DnsServerDto],
    doh_dns_servers: List[DnsServerDto],
    discovered_cnames: list[DomainsPostElementReq] | None = None
  ) -> None:
    logger.debug(f'START resolve domain {domain=} ...')
    domain.resolution_complete = False
    domain.result.A.clear()
    domain.insert.ips_insert.clear()
    domain.insert.ips_delete.clear()
    try:
      tasks: List[CoroutineType] = []
      # Default DNS
      if len(default_dns_servers) > 0:
        for domain_result, dns_server, lookup_type in product((domain,), default_dns_servers, self.__lookup_types):
          task: CoroutineType = self.__default_resolver(domain=domain_result, dns_server=dns_server, lookup_type=lookup_type)
          tasks.append(task)
      # DoH DNS
      if len(doh_dns_servers) > 0:
        for domain_result, dns_server, lookup_type in product((domain,), doh_dns_servers, self.__lookup_types):
          task: CoroutineType = self.__doh_resolver(domain=domain_result, dns_server=dns_server, lookup_type=lookup_type)
          tasks.append(task)
      # Run parallel tasks
      outcomes: list[DnsQueryOutcome] = list(await gather(*tasks))
      try:
        known_cnames = {
          _absolute_name(from_text(cname.domain))
          for cname in discovered_cnames or []
        }
        additional_cnames = [
          DomainsPostElementReq(domain=cname, list_id=domain.list_id)
          for cname in dict.fromkeys(
            cname for outcome in outcomes
            if outcome.status != DnsQueryStatus.FAILURE
            for cname in outcome.cnames
          )
          if _absolute_name(from_text(cname)) not in known_cnames
        ]
        if additional_cnames:
          await self.__persist_cnames(additional_cnames)
      except Exception as err:
        logger.warning(f'[{err.__class__.__name__}]: additional CNAME discovery failed')
      statuses = {outcome.status for outcome in outcomes}
      complete = bool(outcomes) and statuses in (
        {DnsQueryStatus.ADDRESSES}, {DnsQueryStatus.ABSENT}
      )
      domain.result.A = sorted({
        address for outcome in outcomes
        if outcome.status == DnsQueryStatus.ADDRESSES
        for address in outcome.addresses
      })
      if not complete and not domain.result.A:
        return
      # Ips processing for domain
      current_ips: List[IpRecordDto] = await db.get_all_ips_for_domain(domain_id=domain.id)
      domain.resolution_complete = complete
      # add new ips, remove not resolved ips but current exists
      await self.__ips_processing(domain=domain, current_ips=current_ips)
      # INSERT IPS (send to Queue)
      # DELETE IPS (send to Queue)
      # UPDATE DOMAINS (send to Queue)
      if complete or domain.insert.ips_insert:
        await db.put_domain_after_resolve(domain=domain)
      logger.debug(f'FINAL resolve domain {domain=}')
    except DomainIpReadError:
      domain.resolution_complete = False
      logger.warning('Domain IP snapshot unavailable; resolving cycle skipped')
    except Exception as err:
      domain.resolution_complete = False
      logger.error(f'[{err.__class__.__name__}]: domain resolving cycle failed')

  async def __persist_cnames(self: Self, cnames: list[DomainsPostElementReq]) -> None:
    try:
      await db.put_add_domains_to_queue(domains=cnames)
    except Exception as err:
      logger.warning(f'[{err.__class__.__name__}]: CNAME discovery could not be queued')

  async def __dns_cname_tasker(self: Self, domain: DomainResult, default_dns_servers: List[DnsServerDto], doh_dns_servers: List[DnsServerDto]) -> List[DomainsPostElementReq]:
    logger.debug(f'CNAME resolve for domains ...')
    logger.debug(f'CNAME for {domain=}')
    cname_domains: List[DomainsPostElementReq] = []
    try:
      tasks: List[CoroutineType] = []
      # Default DNS
      if len(default_dns_servers) > 0:
        for domain_result, dns_server in product((domain,), default_dns_servers):
          task: CoroutineType = self.__cname_default_resolver(domain=domain_result, dns_server=dns_server, cname_domains=cname_domains)
          tasks.append(task)
      # DoH DNS
      if len(doh_dns_servers) > 0:
        for domain_result, dns_server in product((domain,), doh_dns_servers):
          task: CoroutineType = self.__cname_doh_resolver(domain=domain_result, dns_server=dns_server, cname_domains=cname_domains)
          tasks.append(task)
      # Run parallel tasks
      await gather(*tasks)
      return cname_domains
    except Exception as err:
      logger.error(f'[{err.__class__.__name__}]: __dns_cname_tasker - {err}', exc_info=True)
      return cname_domains

  # Resolvers

  async def __query_doh(
    self: Self,
    domain_name: str,
    dns_server: DnsServerDto,
    lookup_type: RdataType
  ) -> Message:
    query = make_query(qname=domain_name, rdtype=lookup_type)
    query_base64 = urlsafe_b64encode(query.to_wire()).decode('ascii').rstrip('=')
    response = await self.__http_client.get(
      url=dns_server.server,
      params={'dns': query_base64},
      headers={'Accept': 'application/dns-message'}
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
    lookup_type: RdataType
  ) -> Message:
    resolver = Resolver(configure=False)
    resolver.nameservers = [dns_server.server]
    try:
      answer: Answer = await resolver.resolve(
        qname=domain_name, rdtype=lookup_type, search=False
      )
      response = answer.response
    except NoAnswer as err:
      response = err.response()
    except NXDOMAIN as err:
      response = err.response(from_text(domain_name))
    return _validated_dns_response(response, domain_name, lookup_type)

  async def __doh_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    lookup_type: RdataType
  ) -> DnsQueryOutcome:
    async with self.__semaphore:
      try:
        response = await self.__query_doh(domain.name, dns_server, lookup_type)
        return classify_dns_response(
          response, domain.name, dns_server.server, 'doh', lookup_type
        )
      except _DnsResponseError as err:
        reason = str(err)
      except Exception as err:
        reason = err.__class__.__name__
      return DnsQueryOutcome(
        dns_server.server, 'doh', lookup_type, DnsQueryStatus.FAILURE,
        reason=reason
      )

  async def __default_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    lookup_type: RdataType
  ) -> DnsQueryOutcome:
    async with self.__semaphore:
      try:
        response = await self.__query_default(domain.name, dns_server, lookup_type)
        return classify_dns_response(
          response, domain.name, dns_server.server, 'classic', lookup_type
        )
      except _DnsResponseError as err:
        reason = str(err)
      except Exception as err:
        reason = err.__class__.__name__
      return DnsQueryOutcome(
        dns_server.server, 'classic', lookup_type, DnsQueryStatus.FAILURE,
        reason=reason
      )

  async def __cname_doh_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq]
  ) -> None:
    async with self.__semaphore:
      try:
        response = await self.__query_doh(domain.name, dns_server, CNAME)
        _, cnames, _ = _reachable_cnames(response)
        cname_domains.extend(
          DomainsPostElementReq(domain=cname, list_id=domain.list_id)
          for cname in cnames
        )
      except Exception as err:
        logger.debug(f'[{err.__class__.__name__}]: DoH CNAME discovery failed')

  async def __cname_default_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq]
  ) -> None:
    async with self.__semaphore:
      try:
        response = await self.__query_default(domain.name, dns_server, CNAME)
        _, cnames, _ = _reachable_cnames(response)
        cname_domains.extend(
          DomainsPostElementReq(domain=cname, list_id=domain.list_id)
          for cname in cnames
        )
      except Exception as err:
        logger.debug(f'[{err.__class__.__name__}]: classic CNAME discovery failed')

  async def __resolve_once_default_server(self: Self, domain_name: str, dns_server: DnsServerDto) -> DnsServerResolveResultDto:
    domain: DomainResult = DomainResult(
      id=0,
      name=domain_name
    )
    cname_domains: List[DomainsPostElementReq] = []
    tasks: list[CoroutineType] = [
      self.__default_resolver(
        domain=domain,
        dns_server=dns_server,
        lookup_type=lookup_type
      )
      for lookup_type in self.__lookup_types
    ]
    tasks.append(
      self.__cname_default_resolver(
        domain=domain,
        dns_server=dns_server,
        cname_domains=cname_domains
      )
    )
    outcomes = await gather(*tasks)
    return DnsServerResolveResultDto(
      server=dns_server.server,
      server_type='classic',
      ips_v4=sorted({
        address for outcome in outcomes
        if isinstance(outcome, DnsQueryOutcome)
        and outcome.status == DnsQueryStatus.ADDRESSES
        for address in outcome.addresses
      }),
      ips_v6=domain.result.AAAA,
      cnames=list(dict.fromkeys(
        [cname.domain for cname in cname_domains] + [
          cname for outcome in outcomes
          if isinstance(outcome, DnsQueryOutcome)
          and outcome.status != DnsQueryStatus.FAILURE
          for cname in outcome.cnames
        ]
      ))
    )
  
  async def __resolve_once_doh_server(self: Self, domain_name: str, doh_server: DnsServerDto) -> DnsServerResolveResultDto:
    domain: DomainResult = DomainResult(
      id=0,
      name=domain_name
    )
    cname_domains: List[DomainsPostElementReq] = []
    tasks: list[CoroutineType] = [
      self.__doh_resolver(
        domain=domain,
        dns_server=doh_server,
        lookup_type=lookup_type
      )
      for lookup_type in self.__lookup_types
    ]
    tasks.append(
      self.__cname_doh_resolver(
        domain=domain,
        dns_server=doh_server,
        cname_domains=cname_domains
      )
    )
    outcomes = await gather(*tasks)
    return DnsServerResolveResultDto(
      server=doh_server.server,
      server_type='doh',
      ips_v4=sorted({
        address for outcome in outcomes
        if isinstance(outcome, DnsQueryOutcome)
        and outcome.status == DnsQueryStatus.ADDRESSES
        for address in outcome.addresses
      }),
      ips_v6=domain.result.AAAA,
      cnames=list(dict.fromkeys(
        [cname.domain for cname in cname_domains] + [
          cname for outcome in outcomes
          if isinstance(outcome, DnsQueryOutcome)
          and outcome.status != DnsQueryStatus.FAILURE
          for cname in outcome.cnames
        ]
      ))
    )

  # IPS

  @staticmethod
  def __get_current_cidr_for_resolved_ip(
    resolved_ip: str,
    current_ip_records: List[IpRecordDto]
  ) -> str | None:
    for record in current_ip_records:
      if '/' not in record.ip_address:
        continue
      if get_ip_network_address(record.ip_address) == resolved_ip:
        return record.ip_address
    return None

  async def __get_ip_address_for_storage(
    self: Self,
    resolved_ip: str,
    current_ip_records: List[IpRecordDto]
  ) -> str:
    parsed_ip = ip_address(resolved_ip)

    if not isinstance(parsed_ip, IPv4Address) or not parsed_ip.is_global:
      return resolved_ip

    if parsed_ip.packed[-1] != 0:
      return resolved_ip

    try:
      async with self.__ripe_stat_semaphore:
        ripe_result = await self.__ripe_stat_client.get_prefix(
          address=resolved_ip
        )

      if ripe_result.prefix is None:
        logger.debug(
          f'RIPEstat prefix not found for {resolved_ip}; keep host route'
        )
        return resolved_ip

      network = ip_network(ripe_result.prefix, strict=True)

      if (
        not isinstance(network, IPv4Network)
        or network.prefixlen == 32
        or network.network_address != parsed_ip
      ):
        logger.debug(
          f'RIPEstat prefix rejected for {resolved_ip}: '
          f'{ripe_result.prefix}'
        )
        return resolved_ip

      storage_ip = str(network)
      logger.debug(
        f'RIPEstat prefix accepted for {resolved_ip}: {storage_ip}'
      )
      return storage_ip
    except (RipeStatClientError, HTTPError, ValueError) as err:
      current_cidr = self.__get_current_cidr_for_resolved_ip(
        resolved_ip=resolved_ip,
        current_ip_records=current_ip_records
      )

      if current_cidr is not None:
        logger.warning(
          f'RIPEstat prefix lookup failed for {resolved_ip}: '
          f'[{err.__class__.__name__}] {err}; '
          f'keep stored prefix {current_cidr}'
        )
        return current_cidr

      logger.warning(
        f'RIPEstat prefix lookup failed for {resolved_ip}: '
        f'[{err.__class__.__name__}] {err}; keep host route'
      )
      return resolved_ip

  async def __ips_processing(
    self: Self,
    domain: DomainResult,
    current_ips: List[IpRecordDto]
  ) -> None:
    logger.debug(f'IP prepare for {domain.name}')
    logger.debug(f'{domain=}, {current_ips=}')
    try:
      resolved_ips: List[str] = list(dict.fromkeys(
        str(IPv4Address(address)) for address in domain.result.A
      ))
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

      for resolved_ip in resolved_ips:
        if not domain.resolution_complete and resolved_ip in current_ips_by_network_address:
          continue
        current_ip_records = current_ips_by_network_address.get(
          resolved_ip,
          []
        )
        storage_ip = await self.__get_ip_address_for_storage(
          resolved_ip=resolved_ip,
          current_ip_records=current_ip_records
        )
        network_address = get_ip_network_address(storage_ip)

        if network_address != resolved_ip:
          logger.warning(
            f'Invalid storage address for {resolved_ip}: {storage_ip}; '
            f'keep original IP'
          )
          storage_ip = resolved_ip
          network_address = resolved_ip

        desired_ips_by_network_address[network_address] = IpRecordDto(
          ip_address=storage_ip,
          addr_type=get_ip_version(storage_ip)
        )

      for network_address, desired_ip in desired_ips_by_network_address.items():
        current_ip_records = current_ips_by_network_address.pop(
          network_address,
          []
        )
        is_current_value_present = False

        for current_ip in current_ip_records:
          if (
            not is_current_value_present
            and current_ip.ip_address == desired_ip.ip_address
          ):
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
      resolve_domains_log_every: int = settings.resolve_domains_log_every
      log_every: int = max(1, ceil(len_domains / resolve_domains_log_every))
      logger.info(f'Domains for resolve mode={job_mode}: {len_domains}, log_every: {log_every}')
      if len_domains > 0:
        #
        logger.debug(f'Start task {job_mode} ...')
        self.__stop_domains_resolve_event.clear()
        create_task(
          coro=self.__task_process_domains_resolve_from_queue(count_all=len_domains, log_every=log_every),
          name=f'__task_process_domains_resolve_from_queue_{job_mode}'
        )
        [await self.domains_resolve_queue.put(item=domain) for domain in domains]
        # STOP domains resolve
        await self.domains_resolve_queue.join()
        self.__stop_domains_resolve_event.set()
        logger.info(f'Domains resolve mode={job_mode} - DONE')
      else:
        logger.info(f'Domains resolve mode={job_mode} - Not found domains for resolve. DONE')
    except Exception as err:
      logger.error(f'Try Domains resolve mode={job_mode} failed [{err.__class__.__name__}] : {err}', exc_info=True)
    finally:
      await job_registry.finish(Jobs.DOMAINS_RESOLVE)

  async def resolve_once(
    self: Self,
    domain_name: str,
    selected_dns_servers: List[DnsElementResp] | None = None
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
          default_dns_servers.append(DnsServerDto(server=selected_dns_server.server))
        elif selected_dns_server.doh_server is not None:
          doh_dns_servers.append(DnsServerDto(server=selected_dns_server.doh_server))
        else:
          raise RuntimeError(f'DNS server ID={selected_dns_server.id} does not contain a server address')
    #
    tasks: list[CoroutineType] = []
    #
    for dns_server in default_dns_servers:
      tasks.append(
        self.__resolve_once_default_server(
          domain_name=name,
          dns_server=dns_server
        )
      )
    for dns_server in doh_dns_servers:
      tasks.append(
        self.__resolve_once_doh_server(
          domain_name=name,
          doh_server=dns_server
        )
      )
    if not tasks:
      raise RuntimeError('DNS servers for resolve not found')
    #
    results: list[DnsServerResolveResultDto] = list(
      await gather(*tasks)
    )
    #
    return CheckDomainResultDto(
      domain=name,
      results=results
    )

  async def resolve_stored_domain(self: Self, domain_id: int) -> None:
    logger.info(f'Immediate resolving stored domain ID={domain_id} - START')
    try:
      domain_record: DomainElementResp | None = await db.get_domain_on_id(id=domain_id)
      if domain_record is None:
        logger.warning(f'Domain ID={domain_id} not found for resolving')
        return
      domain: DomainResult = DomainResult(
        id=domain_record.id,
        name=domain_record.name,
        list_id=domain_record.domains_list_id
      )
      #
      default_dns, doh_dns = await db.get_dns_servers_for_resolve()
      if not default_dns and not doh_dns:
        raise RuntimeError('DNS servers for resolve not found')
      #
      cname_domains: List[DomainsPostElementReq] = await self.__dns_cname_tasker(
        domain=domain,
        default_dns_servers=default_dns,
        doh_dns_servers=doh_dns
      )
      if cname_domains:
        await self.__persist_cnames(cname_domains)
      #
      await self.__dns_main_tasker(
        domain=domain,
        default_dns_servers=default_dns,
        doh_dns_servers=doh_dns,
        discovered_cnames=cname_domains
      )
    except Exception as err:
      logger.error(f'Resolving domain ID={domain_id} failed: [{err.__class__.__name__}]: {err}', exc_info=True)
