from threading import Event
from asyncio import (
  sleep,
  wait_for,
  create_task,
  gather,
  Queue,
  QueueFull,
  TimeoutError,
  CancelledError,
  Semaphore
)
from dns.resolver import Answer, NoAnswer
from dns.asyncresolver import Resolver
from dns.exception import DNSException
from dns.rdata import Rdata
from dns.rdatatype import RdataType, A, AAAA, CNAME
from dns.message import QueryMessage, make_query, from_wire
from dns.rrset import RRset
from itertools import product
from base64 import urlsafe_b64encode
from httpx import AsyncClient, Response
from types import CoroutineType
from typing import Self, List, Tuple, Dict

from logger.logger import logger
from config.config import settings
from cache.cache import jobs_cache, Jobs
from database.db import db
from client.http_base_client import HttpClient
from utils.utils import get_ip_version

from models.http.domains_req import DomainsPostElementReq

from models.dto.domains_dto import DomainResult
from models.dto.dns_server_dto import DnsServerDto
from models.dto.ip_record_dto import IpRecordDto

class DomainsResolver:

  __stop_domains_resolve_event: Event = Event()
  __queue_sleep_timeout: float = settings.queue_sleep_timeout
  __queue_get_timeout: float = settings.queue_get_timeout
  __task_exception_error_timeout: float = 10.0

  __lookup_types: Tuple[RdataType, RdataType] = (A, AAAA)
  __semaphore: Semaphore = Semaphore(settings.domain_resolve_semaphore_limit)

  __http_client: AsyncClient = HttpClient().client

  domains_resolve_queue: Queue = Queue(maxsize=settings.queue_max_size)

  def __init__(self: Self) -> None:
    logger.info(f'{self.__class__.__name__} init')

  # Get domains from Queue
  async def __task_process_domains_resolve_from_queue(self: Self) -> None:
    logger.info('STARTING A FLOW - Resolve domains')
    while not self.__stop_domains_resolve_event.is_set():
      try:
        # queue is empty - skip
        if self.domains_resolve_queue.empty():
          await sleep(self.__queue_sleep_timeout)
          continue
        domains: List[DomainResult] = await wait_for(
          self.domains_resolve_queue.get(),
          timeout=self.__queue_get_timeout
        )
        # get dns servers
        dns_servers: Tuple[List[DnsServerDto], List[DnsServerDto]] = await db.get_dns_servers_for_resolve() # first default, second doh
        # cname
        cname_domains: List[DomainsPostElementReq] = await self.__dns_cname_tasker(domains=domains, default_dns_servers=dns_servers[0], doh_dns_servers=dns_servers[1])
        if len(cname_domains) > 0:
          logger.debug(f'{cname_domains=}')
          await db.put_add_domains_to_queue(domains=cname_domains)
        # resolve
        await self.__dns_main_tasker(domains=domains, default_dns_servers=dns_servers[0], doh_dns_servers=dns_servers[1])
      except TimeoutError:
        await sleep(self.__queue_sleep_timeout)
        continue
      except CancelledError:
        logger.info('A request was received to stop the flow - Resolve domains')
        break
      except Exception as err:
        logger.error(f'Unexpected error in flow - Resolve domains : {err}', exc_info=True)
        await sleep(self.__task_exception_error_timeout)
        continue
    logger.warning('STOP FLOW - Resolve domains')

  async def __dns_main_tasker(self: Self, domains: List[DomainResult], default_dns_servers: List[DnsServerDto], doh_dns_servers: List[DnsServerDto]) -> None:
    logger.debug(f'START resolve domains ...')
    logger.debug(f'START {domains=}')
    try:
      tasks: List[CoroutineType] = []
      # Default DNS
      if len(default_dns_servers) > 0:
        for domain_result, dns_server, lookup_type in product(domains, default_dns_servers, self.__lookup_types):
          task: CoroutineType = self.__default_resolver(domain_result=domain_result, dns_server=dns_server, lookup_type=lookup_type)
          tasks.append(task)
      # DoH DNS
      if len(doh_dns_servers) > 0:
        for domain_result, dns_server, lookup_type in product(domains, doh_dns_servers, self.__lookup_types):
          task: CoroutineType = self.__doh_resolver(domain_result=domain_result, dns_server=dns_server, lookup_type=lookup_type)
          tasks.append(task)
      # Run parallel tasks
      await gather(*tasks)
      # Ips processing for domains
      for domain_result in domains:
        # get current ips
        if domain_result.id != None:
          current_ips: List[IpRecordDto] = await db.get_all_ips_for_domain(domain_id=domain_result.id)
        # add new ips, remove not resolved ips but current exists
        await self.__ips_processing(domain_result=domain_result, current_ips=current_ips)
      # INSERT IPS (send to Queue)
      # DELETE IPS (send to Queue)
      # UPDATE DOMAINS (send to Queue)
      await db.put_domains_after_resolve(domains=domains)
      # logger.debug(f'FINAL {domains=}')
    except Exception as err:
      logger.error(f'[{err.__class__.__name__}]: __dns_main_tasker - {err}', exc_info=True)

  async def __dns_cname_tasker(self: Self, domains: List[DomainResult], default_dns_servers: List[DnsServerDto], doh_dns_servers: List[DnsServerDto]) -> List[DomainsPostElementReq]:
    logger.debug(f'CNAME resolve for domains ...')
    logger.debug(f'CNAME for {domains=}')
    cname_domains: List[DomainsPostElementReq] = []
    try:
      tasks: List[CoroutineType] = []
      # Default DNS
      if len(default_dns_servers) > 0:
        for domain_result, dns_server in product(domains, default_dns_servers):
          task: CoroutineType = self.__cname_default_resolver(domain_result=domain_result, dns_server=dns_server, cname_domains=cname_domains)
          tasks.append(task)
      # DoH DNS
      if len(doh_dns_servers) > 0:
        for domain_result, dns_server in product(domains, doh_dns_servers):
          task: CoroutineType = self.__cname_doh_resolver(domain_result=domain_result, dns_server=dns_server, cname_domains=cname_domains)
          tasks.append(task)
      # Run parallel tasks
      await gather(*tasks)
      return cname_domains
    except Exception as err:
      logger.error(f'[{err.__class__.__name__}]: __dns_cname_tasker - {err}', exc_info=True)
      return cname_domains

  async def __doh_resolver(self: Self, domain_result: DomainResult, dns_server: DnsServerDto, lookup_type: RdataType) -> None:
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
    logger.debug(f'{domain_result=} {dns_server=} {lookup_type=}')
    async with self.__semaphore:
      try:
        doh_query: QueryMessage = make_query(qname=domain_result.name, rdtype=lookup_type)
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
            domain_result.append_doh_lookup(result)
        else:
          logger.warning(f'__dns_doh_resolver for {domain_result=} : {response.status_code} - {response.content.decode('utf-8')}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __dns_doh_resolver : {err}')

  async def __cname_doh_resolver(
    self: Self,
    domain_result: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq]
  ) -> None:
    logger.debug(f'Run doh cname resolve ...')
    logger.debug(f'{domain_result=} {dns_server=}')
    async with self.__semaphore:
      try:
        doh_query: QueryMessage = make_query(qname=domain_result.name, rdtype=CNAME)
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
                    list_id=domain_result.list_id
                  ))
        else:
          logger.warning(f'__dns_doh_resolver for {domain_result=} : {response.status_code} - {response.content.decode('utf-8')}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __dns_doh_resolver : {err}')

  async def __default_resolver(self: Self, domain_result: DomainResult, dns_server: DnsServerDto, lookup_type: RdataType) -> None:
    logger.debug(f'Run default dns resolve ...')
    logger.debug(f'{domain_result=} {dns_server=} {lookup_type=}')
    async with self.__semaphore:
      try:
        resolver: Resolver = Resolver(configure=False)
        resolver.nameservers = [dns_server.server]
        answer: Answer = await resolver.resolve(qname=domain_result.name, rdtype=lookup_type)
        result: List[Rdata] = [rdata for rdata in answer]
        if len(result) > 0:
          domain_result.append_lookup(result)
      except NoAnswer:
        logger.debug(f'NoAnswer for {domain_result=}')
      except DNSException as err:
        logger.warning(f'[{err.__class__.__name__}] : __dns_default_resolver : {err}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __dns_default_resolver : {err}')

  async def __cname_default_resolver(
    self: Self,
    domain_result: DomainResult,
    dns_server: DnsServerDto,
    cname_domains: List[DomainsPostElementReq]
  ) -> None:
    logger.debug(f'Run default cname resolve ...')
    logger.debug(f'{domain_result=} {dns_server=}')
    async with self.__semaphore:
      try:
        resolver: Resolver = Resolver(configure=False)
        resolver.nameservers = [dns_server.server]
        answer: Answer = await resolver.resolve(qname=domain_result.name, rdtype=CNAME)
        result_list: List[Rdata] = [rdata for rdata in answer]
        if len(result_list) > 0:
          for result in result_list:
            if result.rdtype == CNAME:
              cname_domains.append(DomainsPostElementReq(
                domain=result.to_text().strip().strip('.'),
                list_id=domain_result.list_id
              ))
      except NoAnswer:
        logger.debug(f'NoAnswer for {domain_result=}')
      except DNSException as err:
        logger.warning(f'[{err.__class__.__name__}] : __dns_default_resolver : {err}')
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __dns_default_resolver : {err}')

  async def __ips_processing(self: Self, domain_result: DomainResult, current_ips: List[IpRecordDto]) -> None:
    logger.debug(f'IP prepare for {domain_result.name}')
    logger.debug(f'{domain_result=}, {current_ips=}')
    try:
      current_ips_list: List[str] = [record.ip_address for record in current_ips]
      resolved_ips: List[str] = []
      new_ips: list[IpRecordDto] = []
      remove_ips: list[IpRecordDto] = []
      for ipv4 in domain_result.result.A:
        resolved_ips.append(ipv4)
      for ipv6 in domain_result.result.AAAA:
        resolved_ips.append(ipv6)
      # 1. Add new to DB
      new_ips = [
        IpRecordDto(ip_address=ip, addr_type=get_ip_version(ip))
        for ip in resolved_ips
        if ip not in current_ips_list
      ]
      # 2. Remove from DB
      remove_ips = [record for record in current_ips if record.ip_address not in resolved_ips]
      if len(new_ips) > 0:
        domain_result.append_ips_to_insert(ips=new_ips)
      if len(remove_ips) > 0:
        domain_result.append_ips_to_delete(ips=remove_ips)
    except Exception as err:
      raise err

  async def setup(self: Self) -> None:
    '''
    Start task for Queue
    '''
    try:
      self.__stop_domains_resolve_event.clear()
      create_task(
        coro=self.__task_process_domains_resolve_from_queue(),
        name='task_domains_resolve_queue'
      )
      #
      logger.debug(f'Setup {self.__class__.__name__} - OK')
    except Exception as err:
      raise err

  # Job

  # Put domains to Queue
  async def domains_resolve(self: Self) -> None:
    logger.info(f'Domains resolve - START')
    try:
      await jobs_cache.set(key=Jobs.DOMAINS_RESOLVE, value=True)
      domains: List[DomainResult] = await db.get_domains_for_resolve()
      # put to resolve queue
      while self.domains_resolve_queue.full():
        await sleep(self.__queue_sleep_timeout)
        continue
      logger.debug(f'Put {domains=} to resolve Queue')
      self.domains_resolve_queue.put_nowait(item=domains)
    except QueueFull:
      logger.error(f'Queue is full. Put domain {domains=} to resolve')
    except Exception as err:
      logger.error(f'Try Domains resolve failed : {err}', exc_info=True)
    finally:
      await jobs_cache.set(key=Jobs.DOMAINS_RESOLVE, value=False)
