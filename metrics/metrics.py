from os import getpid
from time import perf_counter
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR
from prometheus_client import Gauge, Counter, Histogram

from starlette.types import ASGIApp
from typing import Self, Tuple

from config.config import settings

class PrometheusMiddleware(BaseHTTPMiddleware):

  app_info: Gauge = Gauge(
    name='fastapi_app_info',
    documentation='FastAPI application information',
    labelnames=['app_name', 'app_version', 'pid']
  )
  '''INFO'''

  requests_in_progress: Gauge = Gauge(
    name='fastapi_requests_in_progress',
    documentation='Gauge of requests by method and path currently being processed',
    labelnames=['method', 'path', 'app_name']
  )
  requests: Counter = Counter(
    name='fastapi_requests_total',
    documentation='Total count of requests by method and path',
    labelnames=['method', 'path', 'app_name']
  )
  requests_processing_time: Histogram = Histogram(
    name='fastapi_requests_duration_seconds',
    documentation='Histogram of requests processing time by path (in seconds)',
    labelnames=['method', 'path', 'app_name']
  )
  '''REQUESTS'''

  responses: Counter = Counter(
    name='fastapi_responses_total',
    documentation='Total count of responses by method, path and status codes',
    labelnames=['method', 'path', 'status_code', 'app_name']
  )
  '''RESPONSES'''

  exceptions: Counter = Counter(
    name='fastapi_exceptions_total',
    documentation='Total count of exceptions raised by path and exception type',
    labelnames=['method', 'path', 'exception_type', 'app_name']
  )
  '''EXCEPTIONS'''

  def __init__(self: Self, app: ASGIApp) -> None:
    super().__init__(app)

    self.app_info.labels(
      app_name=settings.app_title_metrics,
      app_version=settings.app_version,
      pid=getpid()
    ).inc()

  @staticmethod
  def get_path(request: Request) -> Tuple[str, bool]:
    for route in request.app.routes:
      match, child_scope = route.matches(request.scope)
      if match == Match.FULL:
        return route.path, True
    return request.url.path, False
  
  async def dispatch(self: Self, request: Request, call_next: RequestResponseEndpoint) -> Response:
    method: str = request.method
    path, is_handled_path = self.get_path(request)

    if not is_handled_path:
      return await call_next(request)
    
    self.requests_in_progress.labels(method=method, path=path, app_name=settings.app_title_metrics).inc()
    self.requests.labels(method=method, path=path, app_name=settings.app_title_metrics).inc()

    before_time: float = perf_counter()

    try:
      response: Response = await call_next(request)
    except BaseException as err:
      status_code: int = HTTP_500_INTERNAL_SERVER_ERROR
      self.exceptions.labels(
        method=method,
        path=path,
        exception_type=type(err).__name__,
        app_name=settings.app_title_metrics
      ).inc()
      raise err from None
    else:
      status_code: int = response.status_code
      after_time: float = perf_counter()
      '''
      trace пока не используем т.к. это новая фича prometheus:
      https://prometheus.github.io/client_python/instrumenting/exemplars/
      https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md#exemplars
      https://prometheus.io/docs/prometheus/latest/feature_flags/#exemplars-storage
      для версии prometheus версии 3.5 нужен флаг: --enable-feature=exemplar-storage
      '''
      # span: Span = trace.get_current_span()
      # trace_id: str = trace.format_trace_id(span.get_span_context().trace_id)
      self.requests_processing_time.labels(
        method=method,
        path=path,
        app_name=settings.app_title_metrics
      ).observe(
        amount=after_time - before_time
        # exemplar={'TraceID': trace_id}
      )
    finally:
      self.responses.labels(
        method=method,
        path=path,
        status_code=status_code,
        app_name=settings.app_title_metrics
      ).inc()
      self.requests_in_progress.labels(
        method=method,
        path=path,
        app_name=settings.app_title_metrics
      ).dec()

    return response
