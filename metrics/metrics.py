from asyncio import CancelledError
from collections.abc import Iterable
from contextlib import suppress
from os import getpid
from time import perf_counter
from typing import ClassVar, Self
from uuid import uuid4

from fastapi.routing import iter_route_contexts
from prometheus_client import Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR
from starlette.types import ASGIApp

from config.config import settings
from models.dto.queue_dto import Observation

dns_duration = Histogram(
  'resolution_dns_duration_seconds',
  'DNS query and semantic validation duration',
  ['server_id', 'transport', 'record_type', 'outcome', 'reason'],
)
dns_semaphore_wait = Histogram(
  'resolution_dns_semaphore_wait_seconds',
  'DNS semaphore admission wait',
  ['server_id', 'transport', 'record_type', 'outcome', 'reason'],
)
ripe_duration = Histogram(
  'resolution_ripe_duration_seconds',
  'RIPEstat nested phase duration',
  ['phase', 'source', 'outcome'],
)
queue_duration = Histogram(
  'resolution_queue_duration_seconds',
  'Queue admission and residence duration',
  ['queue', 'phase', 'outcome'],
)
writer_duration = Histogram(
  'resolution_writer_duration_seconds',
  'Writer nested phase duration',
  ['phase', 'outcome'],
)
run_events = Counter(
  'resolution_run_events_total',
  'Domain processing, admission and persistence observations',
  ['mode', 'event'],
)
run_elapsed = Histogram(
  'resolution_run_elapsed_seconds',
  'Run elapsed time at the processing boundary',
  ['mode', 'outcome'],
)
run_snapshot = Gauge(
  'resolution_run_snapshot',
  'Latest started run snapshot; rates with validity zero are NaN',
  ['mode', 'field'],
)

_DNS_REASONS = frozenset(
  {
    'missing_response',
    'invalid_envelope',
    'unexpected_question',
    'unsuccessful_rcode',
    'cname_cycle',
    'ambiguous_cname',
    'cname_address_conflict',
    'cname_chain_too_long',
    'unsupported_lookup_type',
    'nxdomain_with_addresses',
    'unrelated_negative_answer',
    'referral',
    'unconfirmed_absence',
    'malformed_response',
    'http_status',
    'unexpected_media_type',
  }
)


def observe_duration(collector: Histogram, started: float, **labels: str) -> None:
  """Observe a nested duration without affecting the operation being measured."""
  with suppress(Exception, CancelledError):
    collector.labels(**labels).observe(max(0.0, perf_counter() - started))


def dns_labels(
  server_id: int | None, transport: str, record_type: str, outcome: str, reason: str | None = None
) -> dict[str, str]:
  """Use configured row identity and bounded semantic categories, never endpoints."""
  mapped_reason = reason or 'none'
  if reason and reason != 'none' and reason not in _DNS_REASONS:
    if reason in {'Timeout', 'LifetimeTimeout', 'ReadTimeout', 'ConnectTimeout', 'PoolTimeout', 'WriteTimeout'}:
      mapped_reason = 'timeout'
    elif reason in {'ConnectError', 'ReadError', 'WriteError', 'NetworkError', 'NoNameservers'}:
      mapped_reason = 'network_error'
    else:
      mapped_reason = 'other'
  return dict(
    server_id=str(server_id) if server_id is not None else 'unconfigured',
    transport=transport,
    record_type=record_type,
    outcome=outcome,
    reason=mapped_reason,
  )


class ResolutionRun:
  """Compact process-local statistics owned by one originating operation."""

  _latest: ClassVar[dict[str, ResolutionRun]] = {}
  _count_fields = (
    'selected',
    'attempted',
    'covered',
    'active',
    'success',
    'partial',
    'failure',
    'cancelled_processing',
    'admission_in_progress',
    'admitted',
    'not_admitted',
    'not_required',
    'pending',
    'confirmed',
    'known_not_committed',
    'unknown',
  )

  def __init__(self, mode: str) -> None:
    self.mode = mode if mode in {'new', 'stale', 'stored'} else 'stored'
    self.run_id = uuid4().hex
    self.started_at = perf_counter()
    self.processing_end: float | None = None
    self.last_receipt_at = self.started_at
    self.processing_complete = False
    self.interrupted = False
    self.counts: dict[str, int] = dict.fromkeys(self._count_fields, 0)
    self._latest[self.mode] = self
    self.publish()

  def select(self, count: int) -> None:
    self.counts['selected'] = count
    self.publish()

  def cover(self) -> None:
    """Record logical pass coverage separately from physical processing."""
    self.counts['covered'] += 1
    self.event('covered')
    self.publish()

  def observe(self) -> DomainObservation:
    return DomainObservation(self)

  def event(self, event: str) -> None:
    with suppress(Exception, CancelledError):
      run_events.labels(mode=self.mode, event=event).inc()

  def finish(self, normal: bool) -> None:
    self.processing_end = perf_counter()
    self.processing_complete = normal
    self.interrupted = not normal
    observe_duration(run_elapsed, self.started_at, mode=self.mode, outcome='complete' if normal else 'interrupted')
    self.publish(log=True)

  def snapshot(self) -> dict[str, int | float | bool]:
    end = self.processing_end
    elapsed = (end if end is not None else perf_counter()) - self.started_at
    processing_valid = bool(
      self.processing_complete
      and not self.interrupted
      and elapsed > 0
      and not self.counts['active']
      and self.counts['attempted'] == self.counts['selected']
    )
    persistence_elapsed = max(end or self.started_at, self.last_receipt_at) - self.started_at
    saved_valid = bool(
      processing_valid
      and not self.counts['admission_in_progress']
      and not self.counts['pending']
      and not self.counts['unknown']
      and persistence_elapsed > 0
    )
    return {
      **self.counts,
      'not_started': self.counts['selected'] - max(self.counts['attempted'], self.counts['covered']),
      'logical_coverage_complete': self.processing_complete and self.counts['covered'] == self.counts['selected'],
      'processing_complete': self.processing_complete,
      'interrupted': self.interrupted,
      'processing_elapsed': elapsed,
      'processing_rate_valid': processing_valid,
      'processing_rate': self.counts['attempted'] / elapsed if processing_valid else float('nan'),
      'persistence_elapsed': persistence_elapsed,
      'saved_rate_valid': saved_valid,
      'saved_rate': self.counts['confirmed'] / persistence_elapsed if saved_valid else float('nan'),
    }

  def publish(self, *, log: bool = False) -> None:
    with suppress(Exception, CancelledError):
      snapshot = self.snapshot()
      if self._latest.get(self.mode) is self:
        for field, value in snapshot.items():
          run_snapshot.labels(mode=self.mode, field=field).set(value)
      if log:
        from logger.logger import logger

        logger.info('Resolution processing run_id=%s mode=%s summary=%s', self.run_id, self.mode, snapshot)


class DomainObservation:
  """Idempotent source-domain observations; no SQL rows or domain names are retained."""

  def __init__(self, run: ResolutionRun) -> None:
    self.run = run
    self.started = False
    self.outcome: str | None = None
    self.finished = False
    self.admission = 'not_required'
    self.receipt: str | None = None
    self.final = False

  def notify(self, event: str, at: float) -> None:
    counts = self.run.counts
    changed = False
    if event == 'processing_started' and not self.started:
      self.started = True
      counts['attempted'] += 1
      counts['active'] += 1
      changed = True
    elif event in {'success', 'partial', 'failure', 'cancelled_processing'} and self.outcome is None:
      self.outcome = event
      counts['active'] -= int(self.started)
      counts[event] += 1
      changed = True
    elif event == 'processing_finished' and not self.finished:
      self.finished = True
      if self.admission == 'not_required':
        counts['not_required'] += 1
      changed = True
    elif event == 'admission_started' and self.admission == 'not_required':
      self.admission = 'in_progress'
      counts['admission_in_progress'] += 1
      changed = True
    elif event in {'admitted', 'not_admitted'} and self.admission == 'in_progress':
      self.admission = event
      counts['admission_in_progress'] -= 1
      counts[event] += 1
      if event == 'admitted':
        self.receipt = 'pending'
        counts['pending'] += 1
      changed = True
    elif (
      event in {'confirmed', 'known_not_committed', 'unknown', 'final_unknown'}
      and self.receipt is not None
      and not self.final
    ):
      state = 'unknown' if event == 'final_unknown' else event
      if self.receipt != state:
        counts[self.receipt] -= 1
        counts[state] += 1
        self.receipt = state
        changed = True
      self.final = event in {'confirmed', 'known_not_committed', 'final_unknown'}
      if self.final:
        self.run.last_receipt_at = max(self.run.last_receipt_at, at)
      changed = changed or self.final
    if changed:
      self.run.event(event)
      self.run.publish()


def persistence_summaries(observations: Iterable[Observation]) -> dict[str, dict]:
  """Copy safe primitive summaries without retaining callbacks or payloads."""
  summaries = {}
  with suppress(Exception, CancelledError):
    for observation in observations:
      if isinstance(observation, DomainObservation):
        run = observation.run
        summaries[run.run_id] = dict(run_id=run.run_id, mode=run.mode, summary=run.snapshot())
  return summaries


def log_persistence_summaries(summaries: dict[str, dict]) -> None:
  """Publish outside transactions; logging must never mask a writer result."""
  with suppress(Exception, CancelledError):
    from logger.logger import logger

    for snapshot in summaries.values():
      logger.info('Resolution persistence summary=%s', snapshot)


class PrometheusMiddleware(BaseHTTPMiddleware):
  app_info: Gauge = Gauge(
    name='fastapi_app_info',
    documentation='FastAPI application information',
    labelnames=['app_name', 'app_version', 'pid'],
  )
  """INFO"""

  requests_in_progress: Gauge = Gauge(
    name='fastapi_requests_in_progress',
    documentation='Gauge of requests by method and path currently being processed',
    labelnames=['method', 'path', 'app_name'],
  )
  requests: Counter = Counter(
    name='fastapi_requests_total',
    documentation='Total count of requests by method and path',
    labelnames=['method', 'path', 'app_name'],
  )
  requests_processing_time: Histogram = Histogram(
    name='fastapi_requests_duration_seconds',
    documentation='Histogram of requests processing time by path (in seconds)',
    labelnames=['method', 'path', 'app_name'],
  )
  """REQUESTS"""

  responses: Counter = Counter(
    name='fastapi_responses_total',
    documentation='Total count of responses by method, path and status codes',
    labelnames=['method', 'path', 'status_code', 'app_name'],
  )
  """RESPONSES"""

  exceptions: Counter = Counter(
    name='fastapi_exceptions_total',
    documentation='Total count of exceptions raised by path and exception type',
    labelnames=['method', 'path', 'exception_type', 'app_name'],
  )
  """EXCEPTIONS"""

  def __init__(self: Self, app: ASGIApp) -> None:
    super().__init__(app)

    self.app_info.labels(app_name=settings.app_title_metrics, app_version=settings.app_version, pid=getpid()).inc()

  @staticmethod
  def get_path(request: Request) -> tuple[str, bool]:
    for route in iter_route_contexts(request.app.routes):
      match, _ = route.matches(request.scope)
      if match == Match.FULL:
        return route.path or request.url.path, True
    return request.url.path, False

  async def dispatch(self: Self, request: Request, call_next: RequestResponseEndpoint) -> Response:
    method: str = request.method
    path, is_handled_path = self.get_path(request)

    if not is_handled_path:
      return await call_next(request)

    self.requests_in_progress.labels(method=method, path=path, app_name=settings.app_title_metrics).inc()
    self.requests.labels(method=method, path=path, app_name=settings.app_title_metrics).inc()

    before_time: float = perf_counter()
    status_code: int = HTTP_500_INTERNAL_SERVER_ERROR

    try:
      response: Response = await call_next(request)
    except BaseException as err:
      status_code = HTTP_500_INTERNAL_SERVER_ERROR
      self.exceptions.labels(
        method=method, path=path, exception_type=type(err).__name__, app_name=settings.app_title_metrics
      ).inc()
      raise err from None
    else:
      status_code = response.status_code
      after_time: float = perf_counter()
      self.requests_processing_time.labels(method=method, path=path, app_name=settings.app_title_metrics).observe(
        amount=after_time - before_time
      )
    finally:
      self.responses.labels(
        method=method, path=path, status_code=status_code, app_name=settings.app_title_metrics
      ).inc()
      self.requests_in_progress.labels(method=method, path=path, app_name=settings.app_title_metrics).dec()

    return response
