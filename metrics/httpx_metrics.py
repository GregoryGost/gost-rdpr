"""Observe HTTP exchanges without consuming or interpreting response bodies."""

from asyncio import CancelledError
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from time import perf_counter
from types import TracebackType
from typing import Any

from httpx import (
  AsyncBaseTransport,
  AsyncByteStream,
  NetworkError,
  ProtocolError,
  Request,
  Response,
  TimeoutException,
)
from prometheus_client import Counter, Gauge, Histogram

from config.config import settings

_INTEGRATIONS = frozenset({'default', 'file_loader', 'domains_resolver', 'ripe_stat', 'ros'})
_METHODS = frozenset({'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'})


def _notify(callback: Callable[..., Any], *args: Any) -> None:
  # Instrumentation is synchronous and must never change business I/O outcomes.
  with suppress(Exception, CancelledError):
    callback(*args)


def _error_category(error: BaseException) -> str:
  if isinstance(error, CancelledError):
    return 'cancelled'
  if isinstance(error, TimeoutException | TimeoutError):
    return 'timeout'
  if isinstance(error, NetworkError):
    return 'network_error'
  if isinstance(error, ProtocolError):
    return 'protocol_error'
  return 'error'


class HttpxMetrics:
  """Publish bounded HTTP metrics through synchronous observer methods."""

  app_name: str = settings.app_title_metrics

  requests = Counter(
    'httpx_requests_total',
    'HTTP exchanges started, including exchanges without a response',
    ['app_name'],
  )
  requests_processing_time = Histogram(
    'httpx_requests_duration_seconds',
    'HTTP exchange lifecycle through first terminal, including consumer pauses',
    ['app_name'],
  )
  responses = Counter(
    'httpx_responses_total',
    'HTTP exchanges with received response headers',
    ['status_code', 'app_name'],
  )
  exceptions = Counter(
    'httpx_exceptions_total',
    'HTTP terminal errors or HTTP error statuses, with redacted request targets',
    ['method', 'host', 'path', 'status_code', 'error', 'app_name'],
  )
  headers_time = Histogram(
    'httpx_request_headers_duration_seconds',
    'Transport entry to response headers or transport error, including native retries',
    ['integration', 'outcome', 'app_name'],
  )
  exchanges_started = Counter(
    'httpx_exchanges_started_total',
    'HTTP exchanges started by integration',
    ['integration', 'app_name'],
  )
  exchanges_terminal = Counter(
    'httpx_exchanges_terminal_total',
    'First HTTP exchange terminals by phase and outcome',
    ['integration', 'phase', 'outcome', 'app_name'],
  )
  exchanges_in_flight = Gauge(
    'httpx_exchanges_in_flight',
    'HTTP exchanges without an observed terminal, including unconsumed streams',
    ['integration', 'app_name'],
  )
  exchange_time = Histogram(
    'httpx_exchange_duration_seconds',
    'HTTP lifecycle by integration and terminal, including consumer pauses',
    ['integration', 'phase', 'outcome', 'app_name'],
  )
  cleanup_errors = Counter(
    'httpx_stream_cleanup_errors_total',
    'Stream close errors after an already observed exchange terminal',
    ['integration', 'error', 'app_name'],
  )

  def started(self, integration: str) -> None:
    """Record one transport entry."""
    self.requests.labels(app_name=self.app_name).inc()
    self.exchanges_started.labels(integration=integration, app_name=self.app_name).inc()
    self.exchanges_in_flight.labels(integration=integration, app_name=self.app_name).inc()

  def headers(self, integration: str, duration: float, status_code: int, error: str | None) -> None:
    """Observe headers latency, including failed attempts without headers."""
    self.headers_time.labels(integration=integration, outcome=error or 'response', app_name=self.app_name).observe(
      duration
    )
    if status_code:
      self.responses.labels(status_code=status_code, app_name=self.app_name).inc()

  def finished(
    self,
    integration: str,
    duration: float,
    method: str,
    status_code: int,
    phase: str,
    outcome: str,
  ) -> None:
    """Record the first terminal independently of the received HTTP status."""
    self.exchanges_in_flight.labels(integration=integration, app_name=self.app_name).dec()
    self.requests_processing_time.labels(app_name=self.app_name).observe(duration)
    self.exchanges_terminal.labels(integration=integration, phase=phase, outcome=outcome, app_name=self.app_name).inc()
    self.exchange_time.labels(integration=integration, phase=phase, outcome=outcome, app_name=self.app_name).observe(
      duration
    )
    error = outcome if outcome not in {'eof', 'closed'} else 'http_status' if status_code >= 400 else None
    if error is not None:
      self.exceptions.labels(
        method=method,
        host='redacted',
        path='redacted',
        status_code=status_code,
        error=error,
        app_name=self.app_name,
      ).inc()

  def cleanup_failed(self, integration: str, error: str) -> None:
    """Record cleanup separately after the lifecycle has already ended."""
    self.cleanup_errors.labels(integration=integration, error=error, app_name=self.app_name).inc()


class _Exchange:
  def __init__(self, metrics: HttpxMetrics, integration: str, request: Request) -> None:
    self.metrics = metrics
    self.integration = integration
    self.method = request.method if request.method in _METHODS else 'OTHER'
    self.started_at = perf_counter()
    self.status_code = 0
    self.terminal = False
    _notify(self.metrics.started, self.integration)

  def headers(self, status_code: int = 0, error: str | None = None) -> None:
    self.status_code = status_code
    _notify(self.metrics.headers, self.integration, perf_counter() - self.started_at, status_code, error)

  def finish(self, phase: str, outcome: str) -> None:
    if self.terminal:
      return
    self.terminal = True
    _notify(
      self.metrics.finished,
      self.integration,
      perf_counter() - self.started_at,
      self.method,
      self.status_code,
      phase,
      outcome,
    )


class _ObservedAsyncStream(AsyncByteStream):
  def __init__(self, stream: AsyncByteStream, exchange: _Exchange) -> None:
    self._stream = stream
    self._exchange = exchange

  async def __aiter__(self) -> AsyncIterator[bytes]:
    try:
      async for chunk in self._stream:
        yield chunk
    except (Exception, CancelledError) as error:
      self._exchange.finish('body', _error_category(error))
      raise
    else:
      self._exchange.finish('body', 'eof')

  async def aclose(self) -> None:
    try:
      await self._stream.aclose()
    except (Exception, CancelledError) as error:
      category = _error_category(error)
      if self._exchange.terminal:
        _notify(self._exchange.metrics.cleanup_failed, self._exchange.integration, category)
      else:
        self._exchange.finish('close', category)
      raise
    else:
      self._exchange.finish('close', 'closed')


class ObservedAsyncTransport(AsyncBaseTransport):
  """Delegate existing transport I/O and observe response streams without reading them."""

  def __init__(
    self,
    transport: AsyncBaseTransport,
    *,
    integration: str = 'default',
    metrics: HttpxMetrics | None = None,
  ) -> None:
    self._transport = transport
    self._integration = integration if integration in _INTEGRATIONS else 'other'
    self._metrics = metrics if metrics is not None else HttpxMetrics()

  async def handle_async_request(self, request: Request) -> Response:
    """Observe one exchange; redirects and auth exchanges enter separately."""
    exchange = _Exchange(self._metrics, self._integration, request)
    try:
      response = await self._transport.handle_async_request(request)
    except (Exception, CancelledError) as error:
      category = _error_category(error)
      exchange.headers(error=category)
      exchange.finish('headers', category)
      raise
    exchange.headers(status_code=response.status_code)
    # Mock/custom transports can return a response whose body was already consumed.
    if response.is_stream_consumed:
      exchange.finish('body', 'eof')
    elif response.is_closed:
      exchange.finish('close', 'closed')
    if isinstance(response.stream, AsyncByteStream):
      response.stream = _ObservedAsyncStream(response.stream, exchange)
    return response

  async def aclose(self) -> None:
    """Keep ownership of transport cleanup with the existing transport."""
    await self._transport.aclose()

  async def __aenter__(self) -> ObservedAsyncTransport:
    await self._transport.__aenter__()
    return self

  async def __aexit__(
    self,
    exc_type: type[BaseException] | None = None,
    exc_value: BaseException | None = None,
    traceback: TracebackType | None = None,
  ) -> None:
    await self._transport.__aexit__(exc_type, exc_value, traceback)
