import logging
from typing import ClassVar, Self

from httpx import AsyncClient, AsyncHTTPTransport, Limits, Timeout
from httpx._types import HeaderTypes

from config.config import settings
from logger.logger import Logger
from metrics.httpx_metrics import HttpxMetrics, ObservedAsyncTransport


class HttpClient:
  headers: ClassVar[HeaderTypes] = {'Accept': '*/*', 'User-Agent': f'{settings.app_title} [{settings.app_version}]'}
  __metrics: ClassVar[HttpxMetrics] = HttpxMetrics()
  __clients: ClassVar[dict[str, AsyncClient]] = {}

  @classmethod
  def get_client(cls: type[Self], name: str = 'default', timeout: Timeout | None = None) -> AsyncClient:
    if name in cls.__clients:
      return cls.__clients[name]
    logging.getLogger('httpx').setLevel(Logger.LOGGER_LEVEL[settings.httpx_log_level])
    # Common
    limits: Limits = Limits(
      max_connections=settings.req_max_connections, max_keepalive_connections=settings.req_max_keepalive_connections
    )
    default_timeout: Timeout = Timeout(
      timeout=settings.req_timeout_default, connect=settings.req_timeout_connect, read=settings.req_timeout_read
    )
    transport: AsyncHTTPTransport = AsyncHTTPTransport(
      retries=settings.req_connection_retries, verify=settings.req_ssl_verify
    )
    client: AsyncClient = AsyncClient(
      headers=cls.headers,
      limits=limits,
      transport=ObservedAsyncTransport(transport, integration=name, metrics=cls.__metrics),
      timeout=timeout or default_timeout,
    )
    cls.__clients[name] = client
    return client

  @classmethod
  async def close(cls: type[Self]) -> None:
    for client in cls.__clients.values():
      await client.aclose()
    cls.__clients.clear()
