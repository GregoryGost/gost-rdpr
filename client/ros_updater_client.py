from logging import getLogger
from librouteros import async_connect
from librouteros.api import AsyncApi, AyncPath
from librouteros.login import async_plain
from librouteros.query import Key, AsyncQuery
from asyncio import sleep
from enum import IntEnum
from typing import Self, List

from logger.logger import logger, Logger
from config.config import settings
from database.db import db
from utils.utils import get_ip_without_prefix

from models.dto.ip_record_dto import IpRecordDto, RosIpRecordDto
from models.dto.ros_config_dto import RosConfigDto

class RosAction(IntEnum):
  FIREWALL  = 1
  ROUTING   = 2

class RosClient:
  '''
  REPO: https://github.com/luqasz/librouteros  
  DOC: https://librouteros.readthedocs.io/en/3.4.1/
  '''

  ros_update_sleep_timeout: float = 0.1

  def __init__(self: Self) -> None:
    getLogger('librouteros').setLevel(Logger.LOGGER_LEVEL[settings.ros_log_level])
    logger.debug(f'{self.__class__.__name__} init ...')

  async def __connect(self: Self, config: RosConfigDto) -> AsyncApi:
    logger.debug(f'Try connect to ROS: {config=} ...')
    try:
      return await async_connect(
        host=config.host,
        username=config.user,
        password=config.passwd,
        login_method=async_plain,
        timeout=settings.ros_connect_timeout
      )
    except Exception as err:
      raise err

  async def __check(self: Self, api: AsyncApi, config: RosConfigDto) -> None:
    logger.debug(f'Try check RouterOS {config.host=} ...')
    try:
      resource: AyncPath = api.path('system', 'resource')
      query: AsyncQuery = resource.select(Key('version'), Key('uptime'))
      async for item in query:
        version: str = item['version']
        uptime: str = item['uptime']
      logger.debug(f'RoS check {config.host=} is OK: {version=}, {uptime=}')
    except Exception as err:
      raise err

  async def __get_default_gateway(self: Self, api: AsyncApi, config: RosConfigDto) -> str:
    logger.debug(f'Get default gateway in {config.host=} ...')
    try:
      dst_address_key: Key = Key('dst-address')
      active_key: Key = Key('active')
      ip_route_path: AyncPath = api.path('ip', 'route')
      ip_route_query: AsyncQuery = ip_route_path.select().where(
        dst_address_key == '0.0.0.0/0', # type: ignore
        active_key == True # type: ignore
      )
      async for item in ip_route_query:
        default_gateway: str = item['gateway']
        routing_table: str = item['routing-table']
        immediate_gw: str = item['immediate-gw']
        if default_gateway == None:
          raise Exception(f'Not found active default gateway on {config.host=} for active route and dst-address=0.0.0.0/0')
      logger.debug(f'Default gateway in {config.host=} : {default_gateway=}, {routing_table=}, {immediate_gw=}')
      return default_gateway
    except Exception as err:
      raise err

  async def __get_routing_table(self: Self, api: AsyncApi, config: RosConfigDto) -> str | None:
    logger.debug(f'Get routing table in {config.host=} ...')
    try:
      disabled_key: Key = Key('disabled')
      table_name_key: Key = Key('name')
      routing_table_path: AyncPath = api.path('routing', 'table')
      routing_table_query: AsyncQuery = routing_table_path.select().where(
        disabled_key == False, # type: ignore
        table_name_key == config.bgp_list_name # type: ignore
      )
      async for item in routing_table_query:
        routing_table_id: str = item['.id']
        routing_table_name: str = item['name']
        routing_table_comment: str = item['comment']
      if routing_table_id == None: return None
      logger.debug(f'Routing table in {config.host=} : {routing_table_id=}, {routing_table_name=}, {routing_table_comment=}')
      return routing_table_id
    except Exception as err:
      raise err

  async def __add_routing_table(self: Self, api: AsyncApi, config: RosConfigDto) -> None:
    logger.debug(f'Set rdpr routing table to {config.host=}')
    try:
      routing_table_path: AyncPath = api.path('routing', 'table')
      await routing_table_path.add(**{
        'name': config.bgp_list_name,
        'disabled': False,
        'fib': 'yes',
        'comment': f'Routing table for bgp list {config.bgp_list_name}'
      })
    except Exception as err:
      raise err

  async def __get_all_ips_from_firewall_list(self: Self, api: AsyncApi, config: RosConfigDto) -> List[RosIpRecordDto]:
    logger.debug(f'Get all ips address from firewall list from {config.host=} ...')
    result: List[RosIpRecordDto] = []
    try:
      disabled_key: Key = Key('disabled')
      firewall_list_key: Key = Key('list')
      ip_firewall_address_list_path: AyncPath = api.path('ip', 'firewall', 'address-list')
      ip_firewall_address_list_query: AsyncQuery = ip_firewall_address_list_path.select().where(
        disabled_key == False, # type: ignore
        firewall_list_key == config.bgp_list_name # type: ignore
      )
      # {'.id': '*83', 'list': 'rdpr-bgp-networks', 'address': '34.0.241.162', 'creation-time': '2025-01-17 13:18:21', 
      # 'dynamic': False, 'disabled': False, 'comment': 'warsaw10147.discord.gg'}
      async for item in ip_firewall_address_list_query:
        result.append(RosIpRecordDto(id=item['.id'], address=item['address']))
      logger.debug(f'All ips from firewall list {config.host=}, {config.bgp_list_name=} : count={len(result)}')
      return result
    except Exception as err:
      raise err

  async def __get_all_ips_from_routing(self: Self, api: AsyncApi, config: RosConfigDto) -> List[RosIpRecordDto]:
    logger.debug(f'Get all ips address from firewall list from {config.host=} ...')
    result: List[RosIpRecordDto] = []
    try:
      disabled_key: Key = Key('disabled')
      routing_table_key: Key = Key('routing-table')
      ip_route_path: AyncPath = api.path('ip', 'route')
      ip_route_query: AsyncQuery = ip_route_path.select().where(
        disabled_key == False, # type: ignore
        routing_table_key == config.bgp_list_name # type: ignore
      )
      # {'.id': '*800062E8', 'dst-address': '1.7.196.211/32', 'routing-table': 'rdpr-bgp-networks', 
      # 'gateway': '192.168.88.1', 'immediate-gw': '192.168.88.1%WAN-Eth1', 'distance': 1, 'scope': 30, 
      # 'target-scope': 10, 'dynamic': False, 'inactive': False, 'active': True, 'static': True, 'disabled': False, 
      # 'comment': 'ae5.pr04.del1.tfbnw.net'}
      async for item in ip_route_query:
        # need remove /32 prefix for dst-address
        result.append(RosIpRecordDto(
          id=item['.id'],
          address=get_ip_without_prefix(ip_address=item['dst-address']),
          gateway=item['gateway']
        ))
      logger.debug(f'All ips from routing {config.host=}, {config.bgp_list_name=} : count={len(result)}')
      return result
    except Exception as err:
      raise err

  async def __update_wrong_gateway(self: Self, api: AsyncApi, config: RosConfigDto, default_gateway: str, address_list: List[RosIpRecordDto]) -> None:
    logger.debug(f'Update wrong gateway in {config.host=} ...')
    try:
      ip_route_path: AyncPath = api.path('ip', 'route')
      for address in address_list:
        await ip_route_path.update(**{
          '.id' : address.id,
          'gateway': default_gateway
        })
        await sleep(self.ros_update_sleep_timeout)
    except Exception as err:
      raise err

  async def __delete_from_ros(self: Self, api: AsyncApi, config: RosConfigDto, action: RosAction, address_list: List[RosIpRecordDto]) -> None:
    logger.debug(f'Delete from {action=} in {config.host=} ...')
    path: AyncPath | None = None
    try:
      if action == RosAction.FIREWALL:
        path = api.path('ip', 'firewall', 'address-list')
      if action == RosAction.ROUTING:
        path = api.path('ip', 'route')
      if path == None: raise Exception(f'Path not found. Value: {action=}')
      for address in address_list:
        await path.remove(address.id)
        await sleep(self.ros_update_sleep_timeout)
    except Exception as err:
      raise err

  async def __add_to_ros(
    self: Self,
    api: AsyncApi,
    config: RosConfigDto,
    action: RosAction,
    address_list: List[IpRecordDto],
    default_gateway: str | None = None
  ) -> None:
    logger.debug(f'Add to {action=} in {config.host=} ...')
    path: AyncPath | None = None
    try:
      if action == RosAction.FIREWALL:
        path = api.path('ip', 'firewall', 'address-list')
      if action == RosAction.ROUTING:
        path = api.path('ip', 'route')
      if path == None: raise Exception(f'Path not found. Value: {action=}')
      for address in address_list:
        if action == RosAction.FIREWALL:
          await path.add(**{
            'address': address.ip_address,
            'disabled': False,
            'list': config.bgp_list_name,
            'comment': address.comment
          })
        if action == RosAction.ROUTING:
          await path.add(**{
            'routing-table': config.bgp_list_name,
            'dst-address': address.ip_address,
            'disabled': False,
            'comment': address.comment,
            'gateway': default_gateway
          })
        await sleep(self.ros_update_sleep_timeout)
    except Exception as err:
      raise err

  async def update(self: Self, addr_type: int | None = None) -> None:
    logger.debug(f'Run update ROS configs {addr_type=}')
    try:
      # get all RoS configs from DB
      configs: List[RosConfigDto] = await db.get_all_configs_for_ros_update()
      if len(configs) > 0:
        stored_ip_address: List[IpRecordDto] = await db.get_all_ips_for_update(addr_type=addr_type)
        logger.debug(f'IP address count for update: {len(stored_ip_address)}')
        for config in configs:
          try:
            # connect to RoS
            api: AsyncApi = await self.__connect(config=config)
            # check connection
            await self.__check(api=api, config=config)
            # get default gateway
            default_gateway: str = await self.__get_default_gateway(api=api, config=config)
            # get rdpr routing table
            routing_table: str | None = await self.__get_routing_table(api=api, config=config)
            # add rdpr routing table if not exists
            if routing_table == None:
              await self.__add_routing_table(api=api, config=config)
            # get all ips from firewall list
            all_ips_from_firewall_list: List[RosIpRecordDto] = await self.__get_all_ips_from_firewall_list(api=api, config=config)
            #
            # FW LIST
            firewall_address_delete: List[RosIpRecordDto] = [
              address
              for address in all_ips_from_firewall_list
              if address.address not in IpRecordDto.only_address(addr_list=stored_ip_address)
            ]
            logger.info(f'Update RoS config [{config.host}] : firewall-address-list DELETE count={len(firewall_address_delete)}')
            firewall_address_add: List[IpRecordDto] = [
              address
              for address in stored_ip_address
              if address.ip_address not in RosIpRecordDto.only_address(addr_list=all_ips_from_firewall_list)
            ]
            logger.info(f'Update RoS config [{config.host}] : firewall-address-list ADD count={len(firewall_address_add)}')
            #
            # ROUTING
            all_ips_from_routing: List[RosIpRecordDto] = await self.__get_all_ips_from_routing(api=api, config=config)
            routing_address_wrong_gateway_update: List[RosIpRecordDto] = [
              address
              for address in all_ips_from_routing
              if address.gateway != default_gateway
            ]
            logger.info(f'Update RoS config [{config.host}] : ip-routing wrong gateway UPDATE count={len(routing_address_wrong_gateway_update)}')
            routing_address_delete: List[RosIpRecordDto] = [
              address
              for address in all_ips_from_routing
              if address.address not in IpRecordDto.only_address(addr_list=stored_ip_address)
            ]
            logger.info(f'Update RoS config [{config.host}] : ip-routing DELETE count={len(routing_address_delete)}')
            routing_address_add: List[IpRecordDto] = [
              address
              for address in stored_ip_address
              if address.ip_address not in RosIpRecordDto.only_address(addr_list=all_ips_from_routing)
            ]
            logger.info(f'Update RoS config [{config.host}] : ip-routing ADD count={len(routing_address_add)}')
            #
            # CHANGE WRONG GATEWAY
            if len(routing_address_wrong_gateway_update) > 0:
              await self.__update_wrong_gateway(
                api=api,
                config=config,
                default_gateway=default_gateway,
                address_list=routing_address_wrong_gateway_update
              )
            # DELETE FROM FIREWALL AND ROUTING
            if len(firewall_address_delete) > 0:
              await self.__delete_from_ros(api=api, config=config, action=RosAction.FIREWALL, address_list=firewall_address_delete)
            if len(routing_address_delete) > 0:
              await self.__delete_from_ros(api=api, config=config, action=RosAction.ROUTING, address_list=routing_address_delete)
            # ADD NEW TO FIREWALL AND ROUTING
            if len(firewall_address_add) > 0:
              await self.__add_to_ros(api=api, config=config, action=RosAction.FIREWALL, address_list=firewall_address_add)
            if len(routing_address_add) > 0:
              await self.__add_to_ros(api=api, config=config, action=RosAction.ROUTING, address_list=routing_address_add, default_gateway=default_gateway)
            logger.info(f'Update RoS config [{config.host}] successfully done')
          except Exception as err:
            # __connect failed may be
            logger.error(f'Update RoS config [{config.host}] failed: [{err.__class__.__name__}] : {err}')
            continue
          finally:
            await api.close()
    except Exception as err:
      logger.error(f'Update ROS configs unknown error: [{err.__class__.__name__}] : {err}', exc_info=True)
