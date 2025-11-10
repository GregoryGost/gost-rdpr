from asyncio import sleep, wait_for, create_task, Queue
from threading import Event

from httpx import Response, AsyncClient, BasicAuth, Timeout
from httpx._types import HeaderTypes
from typing import Self, List, Dict, Set

from .http_base_client import HttpClient
from logger.logger import logger
from config.config import settings
from database.db import db
from cache.cache import jobs_cache, Jobs

from models.dto.ip_record_dto import IpRecordDto
from models.dto.ros_config_dto import RosConfigDto, RosAction
from models.http.ros_rest_api_resp import (
  RosFirewallIpResp,
  RosRoutingIpResp,
  RosIpRouteDefaultGatewayResp,
  RosRoutingTableResp
)

class RosClient:
  '''
  HTTP REST API support starting with RouterOS v7.9  
  DOC: https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API
  '''

  ros_update_sleep_timeout: float = 0.1
  update_ros_queue: Queue = Queue(maxsize=settings.queue_max_size)

  __stop_update_ros_event: Event = Event()
  __queue_sleep_timeout: float = settings.queue_sleep_timeout
  __queue_get_timeout: float = settings.queue_get_timeout
  __task_exception_error_timeout: float = 10.0
  __client: AsyncClient = HttpClient().client
  __headers: HeaderTypes = {
    'Accept': '*/*',
    'Content-Type': 'application/json',
    'User-Agent': f'{settings.app_title} [{settings.app_version}]'
  }
  __timeout: Timeout = Timeout(
    timeout=settings.req_timeout_default,
    connect=settings.req_timeout_connect,
    read=settings.ros_rest_api_read_timeout
  )

  def __init__(self: Self) -> None:
    self.__client.timeout = self.__timeout
    logger.debug(f'{self.__class__.__name__} init ...')

  async def __task_process_update_ros_from_queue(self: Self) -> None:
    logger.info('STARTING A FLOW - Update ROS configs')
    while not self.__stop_update_ros_event.is_set():
      try:
        # queue is empty - skip
        if self.update_ros_queue.empty():
          await sleep(self.__queue_sleep_timeout)
          continue
        config: RosConfigDto = await wait_for(
          self.update_ros_queue.get(),
          timeout=self.__queue_get_timeout
        )
        logger.debug(f'START update ros config {config=}')
        # check connection
        await self.__check(config=config)
        # get all addresses from Database
        stored_ip_address: List[IpRecordDto] = await db.get_all_ips_for_update(addr_type=config.addr_type)
        stored_addresses_set: Set[str] = {ip.ip_address for ip in stored_ip_address}
        logger.debug(f'IP address count for ros update: {len(stored_ip_address)}')
        # get default gateway
        default_gateway: RosIpRouteDefaultGatewayResp = await self.__get_default_gateway(config=config)
        # get rdpr routing table
        routing_table: RosRoutingTableResp | None = await self.__get_routing_table(config=config)
        #
        # FIREWALL ADDRESS LIST
        # get all ips from firewall list
        all_ips_from_firewall_list: List[RosFirewallIpResp] = await self.__get_all_ips_from_firewall_list(config=config)
        all_ips_from_firewall_set: Set[str] = {ip.address for ip in all_ips_from_firewall_list}
        # duplicate protection in firewall list
        duplicate_firewall_ips, unique_firewall_ips = RosFirewallIpResp.separate_duplicates(addresses=all_ips_from_firewall_list)
        # prepared firewall
        firewall_address_delete: List[RosFirewallIpResp] = [
          address
          for address in unique_firewall_ips
          if address.address not in stored_addresses_set
        ]
        firewall_address_delete.extend(duplicate_firewall_ips)
        logger.info(f'Update RoS config [{config.host}] : firewall-address-list DELETE count={len(firewall_address_delete)}')
        firewall_address_add: List[IpRecordDto] = [
          address
          for address in stored_ip_address
          if address.ip_address not in all_ips_from_firewall_set
        ]
        logger.info(f'Update RoS config [{config.host}] : firewall-address-list ADD count={len(firewall_address_add)}')
        #
        # ROUTING
        all_ips_from_routing: List[RosRoutingIpResp] = await self.__get_all_ips_from_routing(config=config)
        all_ips_from_routing_set: Set[str] = {ip.address for ip in all_ips_from_routing}
        routing_address_wrong_gateway_update: List[RosRoutingIpResp] = [
          address
          for address in all_ips_from_routing
          if address.gateway != default_gateway.gateway
        ]
        logger.info(f'Update RoS config [{config.host}] : ip-routing wrong gateway UPDATE count={len(routing_address_wrong_gateway_update)}')
        # duplicate protection in route
        duplicate_routing_ips, unique_routing_ips = RosRoutingIpResp.separate_duplicates(addresses=all_ips_from_routing)
        routing_address_delete: List[RosRoutingIpResp] = [
          address
          for address in unique_routing_ips
          if address.address not in stored_addresses_set
        ]
        routing_address_delete.extend(duplicate_routing_ips)
        logger.info(f'Update RoS config [{config.host}] : ip-routing DELETE count={len(routing_address_delete)}')
        routing_address_add: List[IpRecordDto] = [
          address
          for address in stored_ip_address
          if address.ip_address not in all_ips_from_routing_set
        ]
        logger.info(f'Update RoS config [{config.host}] : ip-routing ADD count={len(routing_address_add)}')
        #
        # ROUTING TABLE
        if routing_table == None:
          await self.__add_routing_table(config=config)
        # CHANGE WRONG GATEWAY
        if len(routing_address_wrong_gateway_update) > 0:
          await self.__update_wrong_route_gateway(
            config=config,
            default_gateway=default_gateway,
            address_list=routing_address_wrong_gateway_update
          )
        # DELETE FROM FIREWALL AND ROUTING
        if len(firewall_address_delete) > 0:
          await self.__delete_from_ros(config=config, action=RosAction.FIREWALL_DELETE, address_list=firewall_address_delete)
        if len(routing_address_delete) > 0:
          await self.__delete_from_ros(config=config, action=RosAction.ROUTING_DELETE, address_list=routing_address_delete)
        # ADD NEW TO FIREWALL AND ROUTING
        if len(firewall_address_add) > 0:
          await self.__add_to_ros(config=config, action=RosAction.FIREWALL_ADD, address_list=firewall_address_add)
        if len(routing_address_add) > 0:
          await self.__add_to_ros(config=config, action=RosAction.ROUTING_ADD, address_list=routing_address_add, default_gateway=default_gateway)
        #
        logger.debug(f'END update ros config element {config=}')
        self.update_ros_queue.task_done()
      except TimeoutError:
        await sleep(self.__queue_sleep_timeout)
        self.update_ros_queue.task_done()
        continue
      except Exception as err:
        logger.error(f'Unexpected error in flow - Update ROS configs : {err}', exc_info=True)
        await sleep(self.__task_exception_error_timeout)
        self.update_ros_queue.task_done()
        continue
    logger.info('STOP FLOW - Update ROS configs')

  async def __check(self: Self, config: RosConfigDto) -> None:
    logger.debug(f'Try check RouterOS {config.host=} ...')
    try:
      url: str = f'http://{config.host}/rest/system/resource'
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      system_resource_response: Response = await self.__client.head(url=url, auth=auth)
      system_resource_response.raise_for_status()
      logger.debug(f'RoS check {config.host=} is OK')
    except Exception as err:
      raise err

  async def __get_default_gateway(self: Self, config: RosConfigDto) -> RosIpRouteDefaultGatewayResp:
    logger.debug(f'Get default gateway in {config.host=} ...')
    try:
      url: str = f'http://{config.host}/rest/ip/route/print'
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      data: Dict[str, List[str]] = {
        '.proplist': ['gateway', 'routing-table', 'immediate-gw'],
        '.query': ['dst-address=0.0.0.0/0', 'active=true']
      }
      ip_route_response: Response = await self.__client.post(url=url, auth=auth, json=data, headers=self.__headers)
      ip_route_response.raise_for_status()
      '''
      [
        {
          "gateway": "1.1.1.1",
          "immediate-gw": "1.1.1.1%WAN-Eth1",
          "routing-table": "main"
        }
      ]
      '''
      result_list: List[RosIpRouteDefaultGatewayResp] = [RosIpRouteDefaultGatewayResp(**item) for item in ip_route_response.json()]
      if len(result_list) < 1:
        raise Exception(f'Not found active default gateway on {config.host=} for active route and dst-address=0.0.0.0/0')
      if len(result_list) > 1:
        raise Exception(f'Found many default gateway on {config.host=} for active route and dst-address=0.0.0.0/0. {result_list=}')
      result: RosIpRouteDefaultGatewayResp = result_list[0]
      logger.debug(f'Default gateway in {config.host=} : {result.gateway=}, {result.routing_table=}, {result.immediate_gw=}')
      return result
    except Exception as err:
      raise err

  async def __get_routing_table(self: Self, config: RosConfigDto) -> RosRoutingTableResp | None:
    logger.debug(f'Get routing table in {config.host=} ...')
    try:
      url: str = f'http://{config.host}/rest/routing/table/print'
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      data: Dict[str, List[str]] = {
        '.proplist': ['.id', 'name'],
        '.query': [f'name={config.bgp_list_name}', 'disabled=false']
      }
      routing_table_response: Response = await self.__client.post(url=url, auth=auth, json=data, headers=self.__headers)
      routing_table_response.raise_for_status()
      '''
      [
        {
          ".id": "*200",
          "name": "bgp-networks"
        }
      ]
      '''
      result_list: List[RosRoutingTableResp] = [RosRoutingTableResp(**item) for item in routing_table_response.json()]
      if len(result_list) < 1: return None
      if len(result_list) > 1:
        raise Exception(f'Found many routing tables on {config.host=} for active table and name={config.bgp_list_name}. {result_list=}')
      result: RosRoutingTableResp = result_list[0]
      logger.debug(f'Routing table in {config.host=} : {result.id=}, {result.name=}')
      return result
    except Exception as err:
      raise err

  async def __add_routing_table(self: Self, config: RosConfigDto) -> None:
    logger.debug(f'Set rdpr routing table to {config.host=}')
    try:
      url: str = f'http://{config.host}/rest/routing/table'
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      data: Dict[str, str | bool] = {
        'name': config.bgp_list_name,
        'disabled': False,
        'fib': 'yes',
        'comment': f'Routing table for bgp list {config.bgp_list_name}'
      }
      routing_table_add_response: Response = await self.__client.put(url=url, auth=auth, json=data, headers=self.__headers)
      routing_table_add_response.raise_for_status()
    except Exception as err:
      raise err

  # ROS CPU intensive usage operation
  async def __get_all_ips_from_firewall_list(self: Self, config: RosConfigDto) -> List[RosFirewallIpResp]:
    '''ROS CPU intensive usage operation'''
    logger.debug(f'Get all ips address from firewall list from {config.host=} ...')
    result: List[RosFirewallIpResp] = []
    try:
      url: str = f'http://{config.host}/rest/ip/firewall/address-list/print'
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      data: Dict[str, List[str]] = {
        '.proplist': ['.id', 'address'],
        '.query': [f'list={config.bgp_list_name}', 'disabled=false']
      }
      routing_table_response: Response = await self.__client.post(url=url, auth=auth, json=data, headers=self.__headers)
      routing_table_response.raise_for_status()
      '''
      [
        {
          ".id": "*A",
          "address": "172.67.182.196"
        },
        {
          ".id": "*B",
          "address": "104.21.32.39"
        },
        {
          ".id": "*15",
          "address": "193.46.255.26"
        }
      ]
      '''
      result = [RosFirewallIpResp(**item) for item in routing_table_response.json()]
      logger.debug(f'All ips from firewall list {config.host=}, {config.bgp_list_name=} : count={len(result)}')
      return result
    except Exception as err:
      raise err

  # ROS CPU intensive usage operation
  async def __get_all_ips_from_routing(self: Self, config: RosConfigDto) -> List[RosRoutingIpResp]:
    '''ROS CPU intensive usage operation'''
    logger.debug(f'Get all ips address from firewall list from {config.host=} ...')
    result: List[RosRoutingIpResp] = []
    try:
      url: str = f'http://{config.host}/rest/ip/route/print'
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      data: Dict[str, List[str]] = {
        '.proplist': ['.id', 'dst-address', 'gateway'],
        '.query': [f'routing-table={config.bgp_list_name}', 'disabled=false']
      }
      ip_route_response: Response = await self.__client.post(url=url, auth=auth, json=data, headers=self.__headers)
      ip_route_response.raise_for_status()
      '''
      [
        {
          ".id": "*80022B07",
          "dst-address": "0.0.0.0/32",
          "gateway": "81.200.155.1"
        },
        {
          ".id": "*8000693E",
          "dst-address": "1.7.196.211/32",
          "gateway": "81.200.155.1"
        },
        {
          ".id": "*8000C376",
          "dst-address": "1.9.57.77/32",
          "gateway": "81.200.155.1"
        }
      ]
      '''
      [
        result.append(RosRoutingIpResp(**item))
        for item in ip_route_response.json()
      ]
      logger.debug(f'All ips from routing {config.host=}, {config.bgp_list_name=} : count={len(result)}')
      return result
    except Exception as err:
      raise err

  async def __update_wrong_route_gateway(
    self: Self,
    config: RosConfigDto,
    default_gateway: RosIpRouteDefaultGatewayResp,
    address_list: List[RosRoutingIpResp]
  ) -> None:
    logger.debug(f'Update wrong gateway for IP addresses in {config.host=} ...')
    try:
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      for address in address_list:
        url: str = f'http://{config.host}/rest/ip/route/{address.id}'
        data = {
          'gateway': default_gateway.gateway
        }
        try:
          ip_route_response: Response = await self.__client.patch(url=url, auth=auth, json=data, headers=self.__headers)
          ip_route_response.raise_for_status()
        except Exception as err:
          logger.error(f'Update wrong gateway failed for IP [{address.id}]{address.address}: {err}')
          continue
        finally:
          await sleep(self.ros_update_sleep_timeout)
    except Exception as err:
      raise err

  async def __delete_from_ros(self: Self, config: RosConfigDto, action: RosAction, address_list: List[RosFirewallIpResp] | List[RosRoutingIpResp]) -> None:
    logger.debug(f'Delete from {action=} in {config.host=} ...')
    base_url: str | None = None
    try:
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      if action == RosAction.FIREWALL_DELETE:
        base_url = f'http://{config.host}/rest/ip/firewall/address-list'
      if action == RosAction.ROUTING_DELETE:
        base_url = f'http://{config.host}/rest/ip/route'
      if base_url == None: raise Exception(f'Target url not exists. Action value: {action=}')
      for address in address_list:
        try:
          url: str = f'{base_url}/{address.id}'
          response: Response = await self.__client.delete(url=url, auth=auth, headers=self.__headers)
          response.raise_for_status()
        except Exception as err:
          logger.error(f'Delete failed for {action=} {address=}: {err}')
          continue
        finally:
          await sleep(self.ros_update_sleep_timeout)
    except Exception as err:
      raise err

  async def __add_to_ros(
    self: Self,
    config: RosConfigDto,
    action: RosAction,
    address_list: List[IpRecordDto],
    default_gateway: RosIpRouteDefaultGatewayResp | None = None
  ) -> None:
    logger.debug(f'Add to {action=} in {config.host=} ...')
    base_url: str | None = None
    try:
      auth: BasicAuth = BasicAuth(username=config.user, password=config.passwd)
      if action == RosAction.FIREWALL_ADD:
        base_url = f'http://{config.host}/rest/ip/firewall/address-list'
      if action == RosAction.ROUTING_ADD:
        base_url = f'http://{config.host}/rest/ip/route'
      if base_url == None: raise Exception(f'Target url not exists. Action value: {action=}')
      for address in address_list:
        try:
          if action == RosAction.FIREWALL_ADD:
            data: Dict[str, str | bool] = {
              'address': address.ip_address,
              'disabled': False,
              'list': config.bgp_list_name,
              'comment': address.comment
            }
            response: Response = await self.__client.put(url=base_url, auth=auth, json=data, headers=self.__headers)
            response.raise_for_status()
          if action == RosAction.ROUTING_ADD:
            data: Dict[str, str | bool] = {
              'routing-table': config.bgp_list_name,
              'dst-address': address.ip_address,
              'disabled': False,
              'comment': address.comment
            }
            if default_gateway != None:
              data['gateway'] = default_gateway.gateway
            response: Response = await self.__client.put(url=base_url, auth=auth, json=data, headers=self.__headers)
            response.raise_for_status()
        except Exception as err:
          logger.error(f'Delete failed for {action=} {address=}: {err}')
          continue
        finally:
          await sleep(self.ros_update_sleep_timeout)
    except Exception as err:
      raise err

  async def update(self: Self, addr_type: int | None = None) -> None:
    logger.info(f'Run update ROS configs {addr_type=}')
    try:
      # start JOB
      await jobs_cache.set(Jobs.ROS_UPDATE, True)
      # get all RoS configs from DB
      configs: List[RosConfigDto] = await db.get_all_configs_for_ros_update()
      if len(configs) > 0:
        #
        logger.debug(f'Start task ...')
        self.__stop_update_ros_event.clear()
        create_task(
          coro=self.__task_process_update_ros_from_queue(),
          name='__task_process_update_ros_from_queue'
        )
        for config in configs:
          if addr_type != None: config.addr_type = addr_type
          await self.update_ros_queue.put(item=config)
        await self.update_ros_queue.join()
        self.__stop_update_ros_event.set()
        logger.info(f'Update ROS configs DONE')
    except Exception as err:
      logger.error(f'Update ROS configs failed: [{err.__class__.__name__}] : {err}', exc_info=True)
    finally:
      await jobs_cache.set(Jobs.ROS_UPDATE, False)
