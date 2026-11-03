import logging
from dataclasses import dataclass
from typing import ClassVar, Self

from httpx import (
  AsyncClient,
  AsyncHTTPTransport,
  ConnectError,
  ConnectTimeout,
  Headers,
  Limits,
  ReadError,
  ReadTimeout,
  RemoteProtocolError,
  Timeout,
  WriteError,
  WriteTimeout,
)
from httpx._types import HeaderTypes
from httpx_retries import Retry, RetryTransport

from config.config import settings
from logger.logger import Logger
from metrics.httpx_metrics import HttpxMetrics, ObservedAsyncTransport


@dataclass(frozen=True)
class _ClientProfile:
  timeout: tuple[float | None, float | None, float | None, float | None]
  max_connections: int
  max_keepalive_connections: int
  ssl_verify: bool
  retry_methods: frozenset[str]
  retries: int
  backoff_factor: float
  backoff_jitter: float
  max_backoff_wait: float
  total_sleep: float
  headers: tuple[tuple[str, str], ...]
  transport_trust_env: bool = True
  client_trust_env: bool = False


class HttpClient:
  """Own reusable named clients with immutable effective transport policies."""

  headers: ClassVar[HeaderTypes] = {'Accept': '*/*', 'User-Agent': f'{settings.app_title} [{settings.app_version}]'}
  __metrics: ClassVar[HttpxMetrics] = HttpxMetrics()
  __clients: ClassVar[dict[str, AsyncClient]] = {}
  __profiles: ClassVar[dict[str, _ClientProfile]] = {}

  @classmethod
  def get_client(
    cls: type[Self],
    name: str = 'default',
    timeout: Timeout | None = None,
    *,
    retry_methods: frozenset[str] = frozenset({'GET', 'HEAD'}),
  ) -> AsyncClient:
    """Reuse an identical named policy, rejecting conflicts and automatic PUT retries."""
    methods = frozenset(method.upper() for method in retry_methods)
    if not methods or not methods <= {'GET', 'HEAD', 'POST', 'PATCH', 'DELETE'}:
      raise ValueError('Retry methods must be a nonempty subset of GET, HEAD, POST, PATCH and DELETE')
    effective_timeout = (
      Timeout(timeout)
      if timeout is not None
      else Timeout(
        connect=settings.req_timeout_connect,
        read=settings.req_timeout_read,
        write=settings.req_timeout_write if settings.req_timeout_write is not None else settings.req_timeout_default,
        pool=settings.req_timeout_pool if settings.req_timeout_pool is not None else settings.req_timeout_default,
      )
    )
    headers = Headers(cls.headers)
    profile = _ClientProfile(
      timeout=(effective_timeout.connect, effective_timeout.read, effective_timeout.write, effective_timeout.pool),
      max_connections=settings.req_max_connections,
      max_keepalive_connections=settings.req_max_keepalive_connections,
      ssl_verify=settings.req_ssl_verify,
      retry_methods=methods,
      retries=settings.req_connection_retries,
      backoff_factor=settings.req_retry_backoff_factor,
      backoff_jitter=settings.req_retry_backoff_jitter,
      max_backoff_wait=settings.req_retry_max_backoff_wait,
      total_sleep=settings.req_retry_total_timeout,
      headers=tuple(sorted(headers.multi_items())),
    )
    if name in cls.__clients:
      if cls.__profiles[name] != profile:
        raise ValueError(f'HTTP client {name!r} already exists with a different configuration')
      return cls.__clients[name]
    logging.getLogger('httpx').setLevel(Logger.LOGGER_LEVEL[settings.httpx_log_level])
    transport = AsyncHTTPTransport(
      limits=Limits(
        max_connections=profile.max_connections,
        max_keepalive_connections=profile.max_keepalive_connections,
      ),
      retries=0,
      verify=profile.ssl_verify,
      trust_env=profile.transport_trust_env,
    )
    retry = Retry(
      total=profile.retries,
      allowed_methods=profile.retry_methods,
      status_forcelist={429, 502, 503, 504},
      retry_on_exceptions=(
        ConnectError,
        ConnectTimeout,
        ReadError,
        ReadTimeout,
        WriteError,
        WriteTimeout,
        RemoteProtocolError,
      ),
      backoff_factor=profile.backoff_factor,
      backoff_jitter=profile.backoff_jitter,
      max_backoff_wait=profile.max_backoff_wait,
      total_timeout=profile.total_sleep,
      respect_retry_after_header=True,
    )
    client: AsyncClient = AsyncClient(
      headers=headers,
      transport=ObservedAsyncTransport(
        RetryTransport(transport=transport, retry=retry), integration=name, metrics=cls.__metrics
      ),
      timeout=effective_timeout,
      trust_env=profile.client_trust_env,
    )
    cls.__clients[name] = client
    cls.__profiles[name] = profile
    return client

  @classmethod
  async def close(cls: type[Self]) -> None:
    """Close all owned transport stacks and forget their named policies."""
    for client in cls.__clients.values():
      await client.aclose()
    cls.__clients.clear()
    cls.__profiles.clear()
