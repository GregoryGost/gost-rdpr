from asyncio import CancelledError
from collections.abc import Generator, Iterable
from contextlib import contextmanager, suppress
from os import getpid
from time import perf_counter
from typing import ClassVar, Literal, Self
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
writer_batch_size = Histogram(
  'resolution_writer_batch_size',
  'Prepared writer attempt size; addresses include repeated input entries and retries count again',
  ['kind'],
  buckets=(0, 1, 10, 50, 100, 500, 1000, 5000, 10000, 50000),
)
writer_sql_dispatches = Counter(
  'resolution_writer_sql_dispatches_total',
  'Attempted application DBAPI dispatches on the write engine, not successful SQLite VM statements',
  ['method'],
)
writer_sql_parameter_sets = Counter(
  'resolution_writer_sql_parameter_sets_total',
  'Submitted DBAPI parameter sets; execute counts one set including an empty or omitted set',
  ['method'],
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


@contextmanager
def observe_writer_phase(phase: Literal['reconcile', 'finish']) -> Generator[None]:
  """Time a whole writer phase while preserving exceptions and cancellation."""
  started = perf_counter()
  outcome = 'failure'
  try:
    yield
    outcome = 'complete'
  except CancelledError:
    outcome = 'cancelled'
    raise
  finally:
    with suppress(Exception, CancelledError):
      observe_duration(writer_duration, started, phase=phase, outcome=outcome)


def observe_writer_batch_size(commands: int, intents: int, addresses: int) -> None:
  """Record input sizes per prepared attempt, independently of commit receipts."""
  with suppress(Exception, CancelledError):
    for kind, size in (('commands', commands), ('intents', intents), ('addresses', addresses)):
      writer_batch_size.labels(kind=kind).observe(size)


def observe_writer_sql_dispatch(
  method: Literal['execute', 'executemany', 'execute_no_params'], parameter_sets: int
) -> None:
  """Count attempted dispatch, including failures, without retaining SQL or values.

  Native commits, rollbacks, triggers and raw connection-setup PRAGMAs are outside
  this boundary. Multi-VALUES execute submits one parameter set. Each dispatch
  adds one callback and two counter updates; that overhead remains in timings.
  """
  with suppress(Exception, CancelledError):
    writer_sql_dispatches.labels(method=method).inc()
    writer_sql_parameter_sets.labels(method=method).inc(parameter_sets)


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
  """Keep physical-origin metrics and separate logical-pass completion logs.

  Synchronous event-loop callbacks update this state without waiting for storage.
  Membership completion never changes physical-attempt or write-receipt counters.
  """

  # _latest identifies the run allowed to update each mode's existing gauge series.
  _latest: ClassVar[dict[str, ResolutionRun]] = {}
  # _count_fields preserves the public metric fields and their original meanings.
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
    """Start an origin run for the supplied mode, normalizing unsupported modes to stored."""
    # mode is the bounded metric/log category; run_id correlates this run's safe aggregate logs.
    self.mode = mode if mode in {'new', 'stale', 'stored'} else 'stored'
    self.run_id = uuid4().hex
    # started_at and processing_end delimit processing; last_receipt_at extends persistence timing.
    self.started_at = perf_counter()
    self.processing_end: float | None = None
    self.last_receipt_at = self.started_at
    # processing_complete and interrupted preserve the existing processing-boundary outcome.
    self.processing_complete = False
    self.interrupted = False
    # counts holds physical processing/admission/receipt facts exposed through Prometheus.
    self.counts: dict[str, int] = dict.fromkeys(self._count_fields, 0)
    # _selection_known distinguishes a real empty selection from a pass cancelled before selection.
    self._selection_known = False
    # _completed_members counts finished selected members, including reused physical operations.
    self._completed_members = 0
    # _track_membership lets the coordinator observe shared members; standalone runs use physical finish events.
    self._track_membership = False
    # _progress_limit freezes the configured message budget for this run.
    self._progress_limit = settings.resolve_domains_log_every
    # _progress_step is the next evenly spaced fraction; _last_progress suppresses rounded duplicates.
    self._progress_step = 1
    self._last_progress = 0
    # _unfinished_processing counts origin observations that have not finished processing/admission.
    self._unfinished_processing = 0
    # _unsettled_receipts includes provisional unknowns until a final receipt event arrives.
    self._unsettled_receipts = 0
    # _processing_logged and _persistence_logged bound each final log attempt, even if logging raises.
    self._processing_logged = False
    self._persistence_logged = False
    self._latest[self.mode] = self
    self.publish()

  def select(self, count: int, *, track_membership: bool = False) -> None:
    """Record count selected members and log their initial total once for NEW/STALE.

    track_membership lets a coordinator supply logical completion explicitly,
    including reused operations; standalone runs derive it from origin observers.
    """
    self.counts['selected'] = count
    self._track_membership = track_membership
    if not self._selection_known:
      self._selection_known = True
      with suppress(Exception, CancelledError):
        from logger.logger import logger

        if self.mode in {'new', 'stale'}:
          if count:
            logger.info('Resolution selected run_id=%s mode=%s total=%s', self.run_id, self.mode, count)
          else:
            logger.info('Нет доменов для обработки')
    self.publish()

  def cover(self) -> None:
    """Record logical pass coverage separately from physical processing."""
    self.counts['covered'] += 1
    self.event('covered')
    self.publish()

  def observe(self) -> DomainObservation:
    """Create an optional observer for one physical operation originating in this run."""
    return DomainObservation(self)

  def event(self, event: str) -> None:
    """Increment the existing event counter for event without affecting business work."""
    with suppress(Exception, CancelledError):
      run_events.labels(mode=self.mode, event=event).inc()

  def finish(self, normal: bool) -> None:
    """Record the existing processing boundary; normal selects completion, otherwise interruption.

    Final logs can follow this boundary when reused membership or receipt callbacks
    are still outstanding. No processing worker waits for those callbacks.
    """
    self.processing_end = perf_counter()
    self.processing_complete = normal
    self.interrupted = not normal
    observe_duration(run_elapsed, self.started_at, mode=self.mode, outcome='complete' if normal else 'interrupted')
    self.publish(log=True)

  def complete_member(self) -> None:
    """Observe one finished selected member without changing coverage or attempt metrics.

    The coordinator calls this once per membership after its physical operation
    terminates. Unstarted cancelled operations never reach this observation.
    Rounded fractions are deduplicated and exclude the final completion count.
    """
    with suppress(Exception, CancelledError):
      self._completed_members += 1
      if self.mode in {'new', 'stale'} and not self._processing_logged:
        # total is the fixed membership size; budget caps distinct nonfinal checkpoints even for huge settings.
        total = self.counts['selected']
        budget = min(self._progress_limit, max(0, total - 1))
        # denominator spaces the feasible checkpoints between the separate initial and final messages.
        denominator = budget + 1
        while self._progress_step <= budget:
          # threshold rounds this fraction upward to the next whole completed member.
          threshold = (self._progress_step * total + denominator - 1) // denominator
          if threshold > self._completed_members:
            break
          self._progress_step += 1
          if threshold <= self._last_progress or threshold >= total:
            continue
          self._last_progress = threshold
          from logger.logger import logger

          logger.info(
            'Resolution progress run_id=%s mode=%s completed=%s total=%s remaining=%s',
            self.run_id,
            self.mode,
            self._completed_members,
            total,
            total - self._completed_members,
          )
    self.publish()

  def snapshot(self) -> dict[str, int | float | bool]:
    """Copy the original metric snapshot, keeping rates invalid until their established boundaries."""
    # end is the recorded processing endpoint; elapsed remains live until that endpoint exists.
    end = self.processing_end
    elapsed = (end if end is not None else perf_counter()) - self.started_at
    # processing_valid preserves the original physical-attempt completeness requirement.
    processing_valid = bool(
      self.processing_complete
      and not self.interrupted
      and elapsed > 0
      and not self.counts['active']
      and self.counts['attempted'] == self.counts['selected']
    )
    # persistence_elapsed includes final receipt timing; saved_valid preserves existing rate eligibility.
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
    """Publish safe aggregate metrics and eligible final logs; log is a compatibility flag.

    finish still supplies log=True, but the recorded processing endpoint now
    controls eligibility. Later observation publications also retry eligibility,
    so receipt-before-finish and receipt-after-finish work
    without background tasks or retained writer payloads.
    """
    with suppress(Exception, CancelledError):
      # snapshot contains only primitive counters and timings, never domains or payloads.
      snapshot = self.snapshot()
      if self._latest.get(self.mode) is self:
        # field names one existing gauge dimension; value is its numeric/bool observation.
        for field, value in snapshot.items():
          run_snapshot.labels(mode=self.mode, field=field).set(value)
    # Logging has its own guard so a failed metric collector cannot suppress final summaries.
    self._log_final_summaries()

  def _log_final_summaries(self) -> None:
    """Attempt each final INFO once after its observations settle, excluding real empty passes.

    Persistence describes only commands originating here. Reused members contribute
    to completed_membership, never to admitted/confirmed counts. Provisional unknown
    receipts keep persistence open until a final outcome callback arrives.
    """
    if self.processing_end is None:
      return
    if self.mode in {'new', 'stale'} and self._selection_known and not self.counts['selected']:
      return
    if not self._processing_logged:
      if self.mode in {'new', 'stale'} and self.processing_complete:
        if self._completed_members < self.counts['selected']:
          return
      self._processing_logged = True
      with suppress(Exception, CancelledError):
        from logger.logger import logger

        logger.info(
          'Resolution processing run_id=%s mode=%s summary=%s',
          self.run_id,
          self.mode,
          dict(
            self.snapshot(),
            completed_membership=self._completed_members,
            remaining_membership=self.counts['selected'] - self._completed_members,
          ),
        )
    if self._persistence_logged or self._unfinished_processing or self._unsettled_receipts:
      return
    if self.counts['admission_in_progress']:
      return
    self._persistence_logged = True
    with suppress(Exception, CancelledError):
      from logger.logger import logger

      logger.info(
        'Resolution persistence run_id=%s mode=%s summary=%s',
        self.run_id,
        self.mode,
        dict(
          self.snapshot(),
          completed_membership=self._completed_members,
          remaining_membership=self.counts['selected'] - self._completed_members,
        ),
      )


class DomainObservation:
  """Idempotent source-domain observations; no SQL rows or domain names are retained."""

  def __init__(self, run: ResolutionRun) -> None:
    """Attach one physical operation to run until processing and its own receipt settle."""
    # run receives this operation's origin counters, even when other passes reuse its work.
    self.run = run
    # started records actual DNS entry; outcome accepts only the first terminal processing result.
    self.started = False
    self.outcome: str | None = None
    # finished closes this observer's processing/admission lifetime once.
    self.finished = False
    # admission tracks the optional command's enqueue state; receipt tracks its persistence evidence.
    self.admission = 'not_required'
    self.receipt: str | None = None
    # final rejects receipt updates after confirmed, known-not-committed or final-unknown evidence.
    self.final = False
    self.run._unfinished_processing += 1

  def notify(self, event: str, at: float) -> None:
    """Apply an idempotent lifecycle event at monotonic time at, then publish aggregate observations.

    Unknown evidence may later become known; final_unknown closes only the log's
    outstanding-receipt count and retains the public unknown metric category.
    """
    # counts aliases the originating run's counters; changed controls idempotent event publication.
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
      self.run._unfinished_processing -= 1
      if self.admission == 'not_required':
        counts['not_required'] += 1
      changed = True
      if not self.run._track_membership:
        self.run.complete_member()
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
        self.run._unsettled_receipts += 1
      changed = True
    elif (
      event in {'confirmed', 'known_not_committed', 'unknown', 'final_unknown'}
      and self.receipt is not None
      and not self.final
    ):
      # state folds terminal unknown evidence into the unchanged public unknown counter.
      state = 'unknown' if event == 'final_unknown' else event
      if self.receipt != state:
        counts[self.receipt] -= 1
        counts[state] += 1
        self.receipt = state
        changed = True
      self.final = event in {'confirmed', 'known_not_committed', 'final_unknown'}
      if self.final:
        self.run._unsettled_receipts -= 1
        self.run.last_receipt_at = max(self.run.last_receipt_at, at)
      changed = changed or self.final
    if changed:
      self.run.event(event)
      self.run.publish()


def persistence_summaries(observations: Iterable[Observation]) -> dict[str, dict]:
  """Copy safe primitive summaries without retaining callbacks or payloads."""
  # summaries deduplicates origin runs represented by the supplied batch observations.
  summaries = {}
  with suppress(Exception, CancelledError):
    # observation is an optional batch observer; only known run observers expose safe summaries.
    for observation in observations:
      if isinstance(observation, DomainObservation):
        # run is the physical origin, which may differ from passes reusing the work.
        run = observation.run
        summaries[run.run_id] = dict(run_id=run.run_id, mode=run.mode, summary=run.snapshot())
  return summaries


def log_persistence_summaries(summaries: dict[str, dict]) -> None:
  """Publish per-batch DEBUG snapshots outside transactions without masking writer results."""
  with suppress(Exception, CancelledError):
    from logger.logger import logger

    # snapshot is one copied origin-run aggregate represented in this batch.
    for snapshot in summaries.values():
      logger.debug('Resolution persistence summary=%s', snapshot)


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
