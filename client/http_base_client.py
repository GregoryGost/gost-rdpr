import logging
from httpx import AsyncClient, Timeout, AsyncHTTPTransport, Limits
from httpx._types import HeaderTypes
from typing import Self

from logger.logger import Logger
from config.config import settings
from metrics.httpx_metrics import HttpxMetrics

class HttpClient:

  headers: HeaderTypes = {
    'Accept': '*/*',
    'User-Agent': f'{settings.app_title} [{settings.app_version}]'
  }
  __metrics: HttpxMetrics = HttpxMetrics()
  __clients: dict[str, AsyncClient] = {}

  def __init__(self: Self) -> None:
    logging.getLogger('httpx').setLevel(Logger.LOGGER_LEVEL[settings.httpx_log_level])

  @classmethod
  def get_client(cls: type[Self], name: str = 'default', timeout: Timeout | None = None) -> AsyncClient:
    if name in cls.__clients:
      return cls.__clients[name]
    # Common
    limits: Limits = Limits(
      max_connections=settings.req_max_connections,
      max_keepalive_connections=settings.req_max_keepalive_connections
    )
    default_timeout: Timeout = Timeout(
      timeout=settings.req_timeout_default,
      connect=settings.req_timeout_connect,
      read=settings.req_timeout_read
    )
    transport: AsyncHTTPTransport = AsyncHTTPTransport(
      retries=settings.req_connection_retries,
      verify=settings.req_ssl_verify
    )
    client: AsyncClient = AsyncClient(
      headers=cls.headers,
      limits=limits,
      transport=transport,
      timeout=timeout or default_timeout
    )
    client.event_hooks['response'] = [cls.__metrics.async_metric_hook]
    cls.__clients[name] = client
    return client

  @classmethod
  async def close(cls: type[Self]) -> None:
    for client in cls.__clients.values():
      await client.aclose()
    cls.__clients.clear()
