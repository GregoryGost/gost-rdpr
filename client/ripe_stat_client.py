from ipaddress import ip_address
from typing import Any, Dict, Self

from httpx import AsyncClient, Response

from cache.cache import ripe_stat_cache
from client.http_base_client import HttpClient
from config.config import settings
from logger.logger import logger
from models.dto.ripe_stat_dto import RipeStatAddressPrefixDto


class RipeStatClientError(Exception):
  pass


class RipeStatClient:

  __client: AsyncClient = HttpClient.get_client('ripe_stat')

  def __init__(self: Self) -> None:
    self.__base_url: str = settings.ripe_stat_base_url.rstrip('/')

  async def get_prefix(self: Self, address: str) -> RipeStatAddressPrefixDto:
    normalized_address: str = str(ip_address(address))
    cache_key: str = f'prefix:{normalized_address}'

    cached_result = await self.__get_cached_prefix(
      address=normalized_address,
      cache_key=cache_key
    )
    if cached_result is not None:
      return cached_result

    async with ripe_stat_cache.lock(
      key=f'lock:{cache_key}',
      expire=settings.ripe_stat_cache_lock_ttl_sec
    ):
      cached_result = await self.__get_cached_prefix(
        address=normalized_address,
        cache_key=cache_key
      )
      if cached_result is not None:
        return cached_result

      result = await self.__get_prefix_from_ripe_stat(
        address=normalized_address
      )
      cache_ttl = (
        settings.ripe_stat_prefix_cache_ttl_sec
        if result.prefix is not None
        else settings.ripe_stat_empty_prefix_cache_ttl_sec
      )
      await ripe_stat_cache.set(
        key=cache_key,
        value=result.prefix or '',
        expire=cache_ttl
      )
      return result

  async def __get_prefix_from_ripe_stat(
    self: Self,
    address: str
  ) -> RipeStatAddressPrefixDto:
    response: Response = await self.__client.get(
      url=f'{self.__base_url}/data/network-info/data.json',
      params={'resource': address},
      headers={'Accept': 'application/json'}
    )

    payload: Dict[str, Any] = self.__get_payload(response=response)

    if not response.is_success or payload.get('status') != 'ok':
      message: str = str(payload.get('message', response.reason_phrase))
      raise RipeStatClientError(
        f'RIPEstat network-info error for {address}: '
        f'{message} (HTTP {response.status_code})'
      )

    data: Any = payload.get('data')

    if not isinstance(data, dict):
      raise RipeStatClientError(
        f'RIPEstat network-info returned invalid data for {address}'
      )

    prefix: Any = data.get('prefix')

    if prefix is not None and not isinstance(prefix, str):
      raise RipeStatClientError(
        f'RIPEstat network-info returned invalid prefix for {address}'
      )

    return RipeStatAddressPrefixDto(address=address, prefix=prefix)

  @staticmethod
  async def __get_cached_prefix(
    address: str,
    cache_key: str
  ) -> RipeStatAddressPrefixDto | None:
    if not await ripe_stat_cache.exists(cache_key):
      return None

    cached_prefix = await ripe_stat_cache.get(cache_key)

    if not isinstance(cached_prefix, str):
      logger.warning(
        f'Invalid RIPEstat cache value for {address}; refresh from RIPEstat'
      )
      return None

    logger.debug(f'RIPEstat cache hit for {address}')
    return RipeStatAddressPrefixDto(
      address=address,
      prefix=cached_prefix or None
    )

  @staticmethod
  def __get_payload(response: Response) -> Dict[str, Any]:
    try:
      payload: Any = response.json()
    except ValueError as err:
      raise RipeStatClientError(
        f'RIPEstat returned invalid JSON (HTTP {response.status_code})'
      ) from err

    if not isinstance(payload, dict):
      raise RipeStatClientError(
        f'RIPEstat returned JSON instead of object (HTTP {response.status_code})'
      )

    return payload
