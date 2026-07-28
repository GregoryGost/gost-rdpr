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
from dns.resolver import Answer, NoAnswer
from dns.asyncresolver import Resolver
from dns.exception import DNSException
from dns.rdata import Rdata
from dns.rdatatype import RdataType, A, CNAME
from dns.message import QueryMessage, make_query, from_wire
from dns.rrset import RRset
from itertools import product
from base64 import urlsafe_b64encode
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from httpx import (
  AsyncClient,
  Response,
  ConnectTimeout,
  ReadError,
  RemoteProtocolError,
  ConnectError,
  HTTPError
)
from types import CoroutineType
from typing import Self, List, Tuple, Dict, Literal

from logger.logger import logger
from config.config import settings
from cache.cache import jobs_cache, Jobs
from database.db import db
from client.http_base_client import HttpClient
from client.ripe_stat_client import RipeStatClient, RipeStatClientError
from utils.utils import get_ip_network_address, get_ip_version

from models.http.domains_req import DomainsPostElementReq
from models.http.domains_resp import DomainElementResp
from models.http.dns_servers_resp import DnsElementResp

from models.dto.domains_dto import DomainResult, CheckDomainResultDto, DnsServerResolveResultDto
from models.dto.dns_server_dto import DnsServerDto
from models.dto.ip_record_dto import IpRecordDto

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
          await db.put_add_domains_to_queue(domains=domain_cname)
        # resolve
        await self.__dns_main_tasker(
          domain=domain,
          default_dns_servers=dns_servers[0],
          doh_dns_servers=dns_servers[1]
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

  async def __dns_main_tasker(self: Self, domain: DomainResult, default_dns_servers: List[DnsServerDto], doh_dns_servers: List[DnsServerDto]) -> None:
    logger.debug(f'START resolve domain {domain=} ...')
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
      await gather(*tasks)
      # Ips processing for domain
      current_ips: List[IpRecordDto] = await db.get_all_ips_for_domain(domain_id=domain.id)
      # add new ips, remove not resolved ips but current exists
      await self.__ips_processing(domain=domain, current_ips=current_ips)
      # INSERT IPS (send to Queue)
      # DELETE IPS (send to Queue)
      # UPDATE DOMAINS (send to Queue)
      await db.put_domain_after_resolve(domain=domain)
      logger.debug(f'FINAL resolve domain {domain=}')
    except Exception as err:
      logger.error(f'[{err.__class__.__name__}]: __dns_main_tasker - {err}', exc_info=True)

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

  async def __doh_resolver(self: Self, domain: DomainResult, dns_server: DnsServerDto, lookup_type: RdataType) -> None:
    '''
    DNS over HTTPS function  
    tested on:  
    - https://dns.adguard-dns.com/dns-query
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
    - https://dns.quad9.net:5053/dns-query
    - https://dns.nextdns.io/dns-query
    '''
    logger.debug(f'Run doh dns resolve ...')
    logger.debug(f'{domain=} {dns_server=} {lookup_type=}')
    async with self.__semaphore:
      try:
        doh_query: QueryMessage = make_query(qname=domain.name, rdtype=lookup_type)
        doh_query_binary: bytes = doh_query.to_wire()
        doh_query_base64: str = urlsafe_b64encode(doh_query_binary).decode('utf-8').rstrip('=')
        params: Dict[str, str] = {
          'dns': doh_query_base64
        }
        headers: Dict[str, str] = {
          'Accept': 'application/dns-message'
        }
        response: Response = await self.__http_client.get(url=dns_server.server, params=params, headers=headers)
        if response.status_code == 200:
          result: List[RRset] = [rrset for rrset in from_wire(response.content).answer]
          if len(result) > 0:
            domain.append_doh_lookup(result)
        else:
          logger.warning(f"__doh_resolver for {domain=} : {response.status_code} - {response.content.decode('utf-8')}")
      except (ConnectTimeout, ReadError, RemoteProtocolError, ConnectError) as err:
        logger.debug(f'[{err.__class__.__name__}] : __doh_resolver warning err : {err}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __doh_resolver unknown err : {err}')

  async def __cname_doh_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq]
  ) -> None:
    logger.debug(f'Run doh cname resolve ...')
    logger.debug(f'{domain=} {dns_server=}')
    async with self.__semaphore:
      try:
        doh_query: QueryMessage = make_query(qname=domain.name, rdtype=CNAME)
        doh_query_binary: bytes = doh_query.to_wire()
        doh_query_base64: str = urlsafe_b64encode(doh_query_binary).decode('utf-8').rstrip('=')
        params: Dict[str, str] = {
          'dns': doh_query_base64
        }
        headers: Dict[str, str] = {
          'Accept': 'application/dns-message'
        }
        response: Response = await self.__http_client.get(url=dns_server.server, params=params, headers=headers)
        if response.status_code == 200:
          result_list: List[RRset] = [rrset for rrset in from_wire(response.content).answer]
          if len(result_list) > 0:
            for result in result_list:
              if result.rdtype == CNAME:
                for value in result:
                  cname_domains.append(DomainsPostElementReq(
                    domain=value.to_text().strip().strip('.'),
                    list_id=domain.list_id
                  ))
        else:
          logger.warning(f"__cname_doh_resolver for {domain=} : {response.status_code} - {response.content.decode('utf-8')}")
      except (ConnectError, ConnectTimeout, ReadError, RemoteProtocolError) as err:
        logger.debug(f'[{err.__class__.__name__}] : __cname_doh_resolver debug err : {err}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __cname_doh_resolver unknown err : {err}')

  async def __default_resolver(self: Self, domain: DomainResult, dns_server: DnsServerDto, lookup_type: RdataType) -> None:
    logger.debug(f'Run default dns resolve ...')
    logger.debug(f'{domain=} {dns_server=} {lookup_type=}')
    async with self.__semaphore:
      try:
        resolver: Resolver = Resolver(configure=False)
        resolver.nameservers = [dns_server.server]
        answer: Answer = await resolver.resolve(qname=domain.name, rdtype=lookup_type)
        result: List[Rdata] = [rdata for rdata in answer]
        if len(result) > 0:
          domain.append_lookup(result)
      except NoAnswer:
        logger.debug(f'NoAnswer for {domain=}')
      except DNSException as err:
        logger.debug(f'[{err.__class__.__name__}] : __default_resolver : {err}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __default_resolver : {err}')

  async def __cname_default_resolver(
    self: Self,
    domain: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq]
  ) -> None:
    logger.debug(f'Run default cname resolve ...')
    logger.debug(f'{domain=} {dns_server=}')
    async with self.__semaphore:
      try:
        resolver: Resolver = Resolver(configure=False)
        resolver.nameservers = [dns_server.server]
        answer: Answer = await resolver.resolve(qname=domain.name, rdtype=CNAME)
        result_list: List[Rdata] = [rdata for rdata in answer]
        if len(result_list) > 0:
          for result in result_list:
            if result.rdtype == CNAME:
              cname_domains.append(DomainsPostElementReq(
                domain=result.to_text().strip().strip('.'),
                list_id=domain.list_id
              ))
      except NoAnswer:
        logger.debug(f'NoAnswer for {domain=}')
      except DNSException as err:
        logger.debug(f'[{err.__class__.__name__}] : __cname_default_resolver : {err}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __cname_default_resolver : {err}')

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
    await gather(*tasks)
    return DnsServerResolveResultDto(
      server=dns_server.server,
      server_type='classic',
      ips_v4=domain.result.A,
      ips_v6=domain.result.AAAA,
      cnames=[
        cname.domain
        for cname in cname_domains
      ]
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
    await gather(*tasks)
    return DnsServerResolveResultDto(
      server=doh_server.server,
      server_type='doh',
      ips_v4=domain.result.A,
      ips_v6=domain.result.AAAA,
      cnames=[
        cname.domain
        for cname in cname_domains
      ]
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
        domain.result.A + domain.result.AAAA
      ))
      current_ips_by_network_address: Dict[str, List[IpRecordDto]] = {}
      desired_ips_by_network_address: Dict[str, IpRecordDto] = {}
      new_ips: List[IpRecordDto] = []
      remove_ips: List[IpRecordDto] = []

      for record in current_ips:
        network_address = get_ip_network_address(record.ip_address)
        if network_address not in current_ips_by_network_address:
          current_ips_by_network_address[network_address] = []
        current_ips_by_network_address[network_address].append(record)

      for resolved_ip in resolved_ips:
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
          remove_ips.append(current_ip)

        if not is_current_value_present:
          new_ips.append(desired_ip)

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
      await jobs_cache.set(job_mode, True)
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
      await jobs_cache.set(job_mode, False)
      await jobs_cache.set(Jobs.DOMAINS_RESOLVE, False)

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
        await db.put_add_domains_to_queue(domains=cname_domains)
      #
      await self.__dns_main_tasker(
        domain=domain,
        default_dns_servers=default_dns,
        doh_dns_servers=doh_dns
      )
    except Exception as err:
      logger.error(f'Resolving domain ID={domain_id} failed: [{err.__class__.__name__}]: {err}', exc_info=True)
