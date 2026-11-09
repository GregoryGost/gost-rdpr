from asyncio import CancelledError, Task, current_task, timeout
from asyncio import Timeout as OperationTimeout
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from ipaddress import ip_address
from time import perf_counter
from typing import Any, Self

from httpx import AsyncClient, HTTPError, Response, Timeout

from cache.cache import ripe_stat_cache
from client.http_base_client import HttpClient
from config.config import settings
from logger.logger import logger
from metrics.metrics import observe_duration, ripe_duration
from models.dto.ripe_stat_dto import RipeStatAddressPrefixDto

_lookup_budget: ContextVar[tuple[Task[Any] | None, OperationTimeout] | None] = ContextVar(
  'ripe_lookup_budget', default=None
)


class RipeStatClientError(Exception):
  pass


class RipeStatClient:
  __client: AsyncClient = HttpClient.get_client(
    'ripe_stat',
    timeout=Timeout(
      connect=settings.ripe_stat_timeout_connect,
      read=settings.ripe_stat_timeout_read,
      write=settings.ripe_stat_timeout_write,
      pool=settings.ripe_stat_timeout_pool,
    ),
    connection_retries=settings.ripe_stat_connection_retries,
    retry_total_timeout=settings.ripe_stat_retry_total_timeout,
  )

  def __init__(self: Self) -> None:
    self.__base_url: str = settings.ripe_stat_base_url.rstrip('/')

  @staticmethod
  @asynccontextmanager
  async def lookup_budget() -> AsyncGenerator[None]:
    """Share one task-local deadline across admission, cache, and network waits."""
    active = _lookup_budget.get()
    owner = current_task()
    if active is not None and active[0] is owner:
      yield
      return
    deadline = timeout(settings.ripe_stat_operation_timeout)
    token = _lookup_budget.set((owner, deadline))
    try:
      async with deadline:
        yield
    except TimeoutError as err:
      raise RipeStatClientError('RIPEstat lookup operation timed out') from err
    finally:
      _lookup_budget.reset(token)

  @staticmethod
  def __cancelled_outcome() -> str:
    active = _lookup_budget.get()
    return 'failure' if active is not None and active[0] is current_task() and active[1].expired() else 'cancelled'

  async def get_prefix(self: Self, address: str) -> RipeStatAddressPrefixDto:
    started = perf_counter()
    source = 'cache'
    outcome = 'failure'
    try:
      async with self.lookup_budget():
        normalized_address: str = str(ip_address(address))
        cache_key: str = f'prefix:{normalized_address}'
        cached_result = await self.__get_cached_prefix(
          address=normalized_address, cache_key=cache_key, phase='cache_lookup'
        )
        if cached_result is not None:
          outcome = 'prefix' if cached_result.prefix is not None else 'empty'
          return cached_result
        source = 'cache_after_lock'
        lock_started = perf_counter()
        lock_acquired = False
        try:
          async with ripe_stat_cache.lock(key=f'lock:{cache_key}', expire=settings.ripe_stat_cache_lock_ttl_sec):
            lock_acquired = True
            observe_duration(ripe_duration, lock_started, phase='lock_wait', source='lock', outcome='acquired')
            cached_result = await self.__get_cached_prefix(
              address=normalized_address, cache_key=cache_key, phase='cache_recheck'
            )
            if cached_result is not None:
              outcome = 'prefix' if cached_result.prefix is not None else 'empty'
              return cached_result
            source = 'network'
            result = await self.__get_prefix_from_ripe_stat(address=normalized_address)
            cache_ttl = (
              settings.ripe_stat_prefix_cache_ttl_sec
              if result.prefix is not None
              else settings.ripe_stat_empty_prefix_cache_ttl_sec
            )
            await ripe_stat_cache.set(key=cache_key, value=result.prefix or '', expire=cache_ttl)
            outcome = 'prefix' if result.prefix is not None else 'empty'
            return result
        except CancelledError:
          if not lock_acquired:
            observe_duration(
              ripe_duration,
              lock_started,
              phase='lock_wait',
              source='lock',
              outcome=self.__cancelled_outcome(),
            )
          raise
        except Exception:
          if not lock_acquired:
            observe_duration(ripe_duration, lock_started, phase='lock_wait', source='lock', outcome='failure')
          raise
    except HTTPError as err:
      raise RipeStatClientError('RIPEstat lookup transport failed') from err
    except CancelledError:
      outcome = self.__cancelled_outcome()
      raise
    finally:
      observe_duration(ripe_duration, started, phase='lookup', source=source, outcome=outcome)

  async def __get_prefix_from_ripe_stat(self: Self, address: str) -> RipeStatAddressPrefixDto:
    started = perf_counter()
    outcome = 'failure'
    try:
      result = await self.__request_prefix(address)
      outcome = 'prefix' if result.prefix is not None else 'empty'
      return result
    except CancelledError:
      outcome = self.__cancelled_outcome()
      raise
    finally:
      observe_duration(ripe_duration, started, phase='network', source='network', outcome=outcome)

  async def __request_prefix(self, address: str) -> RipeStatAddressPrefixDto:
    response: Response = await self.__client.get(
      url=f'{self.__base_url}/data/network-info/data.json',
      params={'resource': address},
      headers={'Accept': 'application/json'},
    )

    payload: dict[str, Any] = self.__get_payload(response=response)

    if not response.is_success or payload.get('status') != 'ok':
      message: str = str(payload.get('message', response.reason_phrase))
      raise RipeStatClientError(f'RIPEstat network-info error for {address}: {message} (HTTP {response.status_code})')

    data: Any = payload.get('data')

    if not isinstance(data, dict):
      raise RipeStatClientError(f'RIPEstat network-info returned invalid data for {address}')

    prefix: Any = data.get('prefix')

    if prefix is not None and not isinstance(prefix, str):
      raise RipeStatClientError(f'RIPEstat network-info returned invalid prefix for {address}')

    return RipeStatAddressPrefixDto(address=address, prefix=prefix)

  @staticmethod
  async def __get_cached_prefix(
    address: str, cache_key: str, phase: str = 'cache_lookup'
  ) -> RipeStatAddressPrefixDto | None:
    started = perf_counter()
    outcome = 'failure'
    try:
      result = await RipeStatClient.__read_cached_prefix(address, cache_key)
      outcome = 'hit' if result is not None else 'miss'
      return result
    except CancelledError:
      outcome = RipeStatClient.__cancelled_outcome()
      raise
    finally:
      observe_duration(ripe_duration, started, phase=phase, source='cache', outcome=outcome)

  @staticmethod
  async def __read_cached_prefix(address: str, cache_key: str) -> RipeStatAddressPrefixDto | None:
    cached_prefix = await ripe_stat_cache.get(cache_key)

    if cached_prefix is None:
      return None

    if not isinstance(cached_prefix, str):
      logger.warning(f'Invalid RIPEstat cache value for {address}; refresh from RIPEstat')
      return None

    logger.debug(f'RIPEstat cache hit for {address}')
    return RipeStatAddressPrefixDto(address=address, prefix=cached_prefix or None)

  @staticmethod
  def __get_payload(response: Response) -> dict[str, Any]:
    try:
      payload: Any = response.json()
    except ValueError as err:
      raise RipeStatClientError(f'RIPEstat returned invalid JSON (HTTP {response.status_code})') from err

    if not isinstance(payload, dict):
      raise RipeStatClientError(f'RIPEstat returned JSON instead of object (HTTP {response.status_code})')

    return payload
