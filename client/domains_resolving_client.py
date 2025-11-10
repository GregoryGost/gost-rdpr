from threading import Event
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
from dns.rdatatype import RdataType, A, AAAA, CNAME
from dns.message import QueryMessage, make_query, from_wire
from dns.rrset import RRset
from itertools import product
from base64 import urlsafe_b64encode
from httpx import AsyncClient, Response, ConnectTimeout, ReadError, RemoteProtocolError, ConnectError
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
        domain: DomainResult = await wait_for(
          self.domains_resolve_queue.get(),
          timeout=self.__queue_get_timeout
        )
        logger.debug(f'START resolving domain element {domain=}')
        # get dns servers
        dns_servers: Tuple[List[DnsServerDto], List[DnsServerDto]] = await db.get_dns_servers_for_resolve() # first default, second doh
        # cname
        domain_cname: List[DomainsPostElementReq] = await self.__dns_cname_tasker(domain=domain, default_dns_servers=dns_servers[0], doh_dns_servers=dns_servers[1])
        if len(domain_cname) > 0:
          logger.debug(f'{domain_cname=}')
          await db.put_add_domains_to_queue(domains=domain_cname)
        # resolve
        await self.__dns_main_tasker(domain=domain, default_dns_servers=dns_servers[0], doh_dns_servers=dns_servers[1])
        logger.debug(f'END resolving domain element {domain=}')
        self.domains_resolve_queue.task_done()
      except TimeoutError:
        await sleep(self.__queue_sleep_timeout)
        self.domains_resolve_queue.task_done()
        continue
      except Exception as err:
        logger.error(f'Unexpected error in flow - Resolve domains : {err}', exc_info=True)
        await sleep(self.__task_exception_error_timeout)
        self.domains_resolve_queue.task_done()
        continue
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
          logger.warning(f'__doh_resolver for {domain=} : {response.status_code} - {response.content.decode('utf-8')}')
      except (ConnectTimeout, ReadError, RemoteProtocolError, ConnectError) as err:
        logger.warning(f'[{err.__class__.__name__}] : __doh_resolver warning err : {err}')
        pass
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
          logger.warning(f'__cname_doh_resolver for {domain=} : {response.status_code} - {response.content.decode('utf-8')}')
      except (ConnectTimeout, ReadError, RemoteProtocolError) as err:
        logger.warning(f'[{err.__class__.__name__}] : __cname_doh_resolver debug err : {err}')
        pass
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
        logger.warning(f'[{err.__class__.__name__}] : __default_resolver : {err}')
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
        logger.warning(f'[{err.__class__.__name__}] : __cname_default_resolver : {err}')
        pass
      except Exception as err:
        logger.error(f'[{err.__class__.__name__}] : __cname_default_resolver : {err}')

  async def __ips_processing(self: Self, domain: DomainResult, current_ips: List[IpRecordDto]) -> None:
    logger.debug(f'IP prepare for {domain.name}')
    logger.debug(f'{domain=}, {current_ips=}')
    try:
      current_ips_list: List[str] = [record.ip_address for record in current_ips]
      resolved_ips: List[str] = []
      new_ips: list[IpRecordDto] = []
      remove_ips: list[IpRecordDto] = []
      for ipv4 in domain.result.A:
        resolved_ips.append(ipv4)
      for ipv6 in domain.result.AAAA:
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
        domain.append_ips_to_insert(ips=new_ips)
      if len(remove_ips) > 0:
        domain.append_ips_to_delete(ips=remove_ips)
    except Exception as err:
      raise err

  # async def setup(self: Self) -> None:
  #   '''
  #   Start task for Queue
  #   '''
  #   try:
  #     self.__stop_domains_resolve_event.clear()
  #     create_task(
  #       coro=self.__task_process_domains_resolve_from_queue(),
  #       name='task_domains_resolve_queue'
  #     )
  #     #
  #     logger.debug(f'Setup {self.__class__.__name__} - OK')
  #   except Exception as err:
  #     raise err

  # Job

  # Put domains to Queue
  async def domains_resolve(self: Self) -> None:
    logger.info(f'Domains resolve - START')
    try:
      await jobs_cache.set(Jobs.DOMAINS_RESOLVE, True)
      #
      logger.debug(f'Start task ...')
      self.__stop_domains_resolve_event.clear()
      create_task(
        coro=self.__task_process_domains_resolve_from_queue(),
        name='__task_process_domains_resolve_from_queue'
      )
      #
      domains: List[DomainResult] = await db.get_domains_for_resolve()
      logger.debug(f'Put {len(domains)} to resolve Queue')
      for domain in domains:
        await self.domains_resolve_queue.put(item=domain)
      # STOP domains resolve
      await self.domains_resolve_queue.join()
      self.__stop_domains_resolve_event.set()
      logger.info(f'Domains resolve - DONE')
    except Exception as err:
      logger.error(f'Try Domains resolve failed [{err.__class__.__name__}] : {err}', exc_info=True)
    finally:
      await jobs_cache.set(Jobs.DOMAINS_RESOLVE, False)
