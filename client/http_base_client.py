"""Build reusable HTTP clients with integration-owned retry and protocol policies."""

import logging
from asyncio import CancelledError
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import dataclass
from typing import ClassVar, Self

from httpx import (
  AsyncBaseTransport,
  AsyncClient,
  AsyncHTTPTransport,
  ConnectError,
  ConnectTimeout,
  Headers,
  Limits,
  ReadError,
  ReadTimeout,
  RemoteProtocolError,
  Request,
  Response,
  Timeout,
  WriteError,
  WriteTimeout,
)
from httpx._types import HeaderTypes
from httpx_retries import Retry, RetryTransport

from config.config import settings
from logger.logger import Logger
from metrics.httpx_metrics import HttpxMetrics, ObservedAsyncTransport

# These failures may consume a retry; pool pressure and local protocol mistakes must propagate.
_RETRYABLE_TRANSPORT_ERRORS = (
  ConnectError,
  ConnectTimeout,
  ReadError,
  ReadTimeout,
  WriteError,
  WriteTimeout,
  RemoteProtocolError,
)


@dataclass(frozen=True)
class _ClientProfile:
  """Keep the effective policy used to reject conflicting reuse of a client name."""

  # timeout contains connect, read, write and pool limits in seconds, respectively.
  timeout: tuple[float | None, float | None, float | None, float | None]
  # max_connections caps open connections in each owned pool.
  max_connections: int
  # max_keepalive_connections caps idle connections retained by each pool.
  max_keepalive_connections: int
  # ssl_verify controls certificate validation for all pools in this profile.
  ssl_verify: bool
  # retry_methods identifies operations the integration permits RetryTransport to replay.
  retry_methods: frozenset[str]
  # retries counts additional attempts, shared by HTTP status retries and protocol fallback.
  retries: int
  # backoff_factor scales RetryTransport's exponential retry delay in seconds.
  backoff_factor: float
  # backoff_jitter is the fractional randomization applied to retry delays.
  backoff_jitter: float
  # max_backoff_wait caps a single retry delay in seconds.
  max_backoff_wait: float
  # total_sleep caps cumulative retry sleep, rather than request execution time.
  total_sleep: float
  # headers is the normalized default-header snapshot compared on named-client reuse.
  headers: tuple[tuple[str, str], ...]
  # prefer_http2 opts into ALPN negotiation and request-local HTTP/1.1 fallback.
  prefer_http2: bool = False
  # transport_trust_env preserves the existing transport certificate environment policy.
  transport_trust_env: bool = True
  # client_trust_env keeps environment proxy discovery disabled at the client boundary.
  client_trust_env: bool = False


class _Http2AttemptTransport(AsyncBaseTransport):
  """Route retry attempts through two pools without owning a second retry loop."""

  def __init__(
    self,
    primary: AsyncBaseTransport,
    fallback: AsyncBaseTransport,
    http1_only: ContextVar[bool],
  ) -> None:
    """Retain primary ALPN and fallback H1 pools with the caller's per-request flag."""
    # _primary negotiates HTTP/2 or HTTP/1.1 and remains preferred for each new request.
    self._primary = primary
    # _fallback is an independent pool that never negotiates HTTP/2.
    self._fallback = fallback
    # _http1_only selects H1 only within the surrounding request's retry operation.
    self._http1_only = http1_only

  async def handle_async_request(self, request: Request) -> Response:
    """Send one request attempt and expose successful H2 body failures to retries.

    request is replayed only by the outer RetryTransport. An eligible primary
    failure selects H1 for any remaining attempts. HTTP status failures and
    negotiated H1 responses keep their existing body and retry behavior.
    Cancellation and nonretryable errors propagate after partial-body cleanup.
    """
    if self._http1_only.get():
      return await self._fallback.handle_async_request(request)
    try:
      # response is the primary attempt; only an HTTP/2 DoH success is buffered here.
      response = await self._primary.handle_async_request(request)
      if response.status_code == 200 and response.http_version == 'HTTP/2':
        try:
          await response.aread()
        except Exception, CancelledError:
          # Keep the read failure if cleanup also fails, but never hide a new cancellation.
          with suppress(Exception):
            await response.aclose()
          raise
      return response
    except _RETRYABLE_TRANSPORT_ERRORS:
      self._http1_only.set(True)
      raise

  async def aclose(self) -> None:
    """Attempt to close both owned pools even if closing the primary raises."""
    try:
      await self._primary.aclose()
    finally:
      await self._fallback.aclose()


class _Http2PreferredTransport(AsyncBaseTransport):
  """Scope protocol fallback to one RetryTransport invocation and its shared budget."""

  def __init__(self, primary: AsyncBaseTransport, fallback: AsyncBaseTransport, retry: Retry) -> None:
    """Wrap primary/fallback pools with retry policy retry and task-local routing."""
    # _http1_only is reset for every handle call, including concurrent or reused requests.
    self._http1_only: ContextVar[bool] = ContextVar('http1_only', default=False)
    # _transport is the sole retry owner and closes both pools through its routing transport.
    self._transport = RetryTransport(transport=_Http2AttemptTransport(primary, fallback, self._http1_only), retry=retry)

  async def handle_async_request(self, request: Request) -> Response:
    """Run request with fresh fallback state, restoring the caller's context on every exit."""
    # token restores any enclosing call's state without changing another task's routing.
    token = self._http1_only.set(False)
    try:
      return await self._transport.handle_async_request(request)
    finally:
      self._http1_only.reset(token)

  async def aclose(self) -> None:
    """Close the retry stack, which releases the ALPN and H1-only pools."""
    await self._transport.aclose()


class HttpClient:
  """Own reusable named clients with immutable effective transport policies."""

  # headers supplies the shared defaults included in each immutable client profile.
  headers: ClassVar[HeaderTypes] = {'Accept': '*/*', 'User-Agent': f'{settings.app_title} [{settings.app_version}]'}
  # __metrics observes logical exchanges outside the retry and protocol layers.
  __metrics: ClassVar[HttpxMetrics] = HttpxMetrics()
  # __clients retains clients until explicit application shutdown closes their transports.
  __clients: ClassVar[dict[str, AsyncClient]] = {}
  # __profiles records each name's effective policy to reject conflicting reuse.
  __profiles: ClassVar[dict[str, _ClientProfile]] = {}

  @classmethod
  def get_client(
    cls: type[Self],
    name: str = 'default',
    timeout: Timeout | None = None,
    *,
    retry_methods: frozenset[str] = frozenset({'GET', 'HEAD'}),
    connection_retries: int | None = None,
    retry_total_timeout: float | None = None,
    prefer_http2: bool = False,
  ) -> AsyncClient:
    """Reuse name only with an identical policy, rejecting automatic PUT retries.

    timeout supplies the four HTTPX attempt timeouts; omitted values come from
    settings. retry_methods permits replays, connection_retries overrides the
    additional-attempt count, and retry_total_timeout overrides cumulative sleep
    seconds. prefer_http2 enables ALPN and H1 fallback within that same budget;
    it is intended for buffered DoH requests. cls retains and closes the client.
    """
    # methods normalizes the permitted retry methods; method is each supplied spelling.
    methods = frozenset(method.upper() for method in retry_methods)
    if not methods or not methods <= {'GET', 'HEAD', 'POST', 'PATCH', 'DELETE'}:
      raise ValueError('Retry methods must be a nonempty subset of GET, HEAD, POST, PATCH and DELETE')
    # effective_timeout is the complete four-phase policy stored with this client name.
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
    # headers snapshots current defaults so later named-client requests can detect conflicts.
    headers = Headers(cls.headers)
    # profile contains all effective settings used to construct and compare this client.
    profile = _ClientProfile(
      timeout=(effective_timeout.connect, effective_timeout.read, effective_timeout.write, effective_timeout.pool),
      max_connections=settings.req_max_connections,
      max_keepalive_connections=settings.req_max_keepalive_connections,
      ssl_verify=settings.req_ssl_verify,
      retry_methods=methods,
      retries=settings.req_connection_retries if connection_retries is None else connection_retries,
      backoff_factor=settings.req_retry_backoff_factor,
      backoff_jitter=settings.req_retry_backoff_jitter,
      max_backoff_wait=settings.req_retry_max_backoff_wait,
      total_sleep=settings.req_retry_total_timeout if retry_total_timeout is None else retry_total_timeout,
      headers=tuple(sorted(headers.multi_items())),
      prefer_http2=prefer_http2,
    )
    if name in cls.__clients:
      if cls.__profiles[name] != profile:
        raise ValueError(f'HTTP client {name!r} already exists with a different configuration')
      return cls.__clients[name]
    logging.getLogger('httpx').setLevel(Logger.LOGGER_LEVEL[settings.httpx_log_level])
    # limits applies the same resource policy to both pools when fallback is enabled.
    limits = Limits(
      max_connections=profile.max_connections,
      max_keepalive_connections=profile.max_keepalive_connections,
    )
    # transport is the primary pool; HTTPX native retries stay disabled for one retry owner.
    transport = AsyncHTTPTransport(
      limits=limits,
      retries=0,
      verify=profile.ssl_verify,
      trust_env=profile.transport_trust_env,
      http1=True,
      http2=profile.prefer_http2,
    )
    # retry owns the combined attempt and sleep budgets for status and transport failures.
    retry = Retry(
      total=profile.retries,
      allowed_methods=profile.retry_methods,
      status_forcelist={429, 502, 503, 504},
      retry_on_exceptions=_RETRYABLE_TRANSPORT_ERRORS,
      backoff_factor=profile.backoff_factor,
      backoff_jitter=profile.backoff_jitter,
      max_backoff_wait=profile.max_backoff_wait,
      total_timeout=profile.total_sleep,
      respect_retry_after_header=True,
    )
    # retry_transport adds protocol routing only for explicitly opted-in integrations.
    retry_transport: AsyncBaseTransport
    if profile.prefer_http2:
      retry_transport = _Http2PreferredTransport(
        transport,
        AsyncHTTPTransport(
          limits=limits,
          retries=0,
          verify=profile.ssl_verify,
          trust_env=profile.transport_trust_env,
          http1=True,
          http2=False,
        ),
        retry,
      )
    else:
      retry_transport = RetryTransport(transport=transport, retry=retry)
    # client is the reusable integration boundary; observation surrounds all attempts.
    client: AsyncClient = AsyncClient(
      headers=headers,
      transport=ObservedAsyncTransport(retry_transport, integration=name, metrics=cls.__metrics),
      timeout=effective_timeout,
      trust_env=profile.client_trust_env,
    )
    cls.__clients[name] = client
    cls.__profiles[name] = profile
    return client

  @classmethod
  async def close(cls: type[Self]) -> None:
    """Close all owned transport stacks and forget their named policies in cls."""
    # client is each factory-owned integration client being shut down.
    for client in cls.__clients.values():
      await client.aclose()
    cls.__clients.clear()
    cls.__profiles.clear()
