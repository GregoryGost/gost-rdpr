from typing import Self
from httpx import Request, Response
from prometheus_client import Counter, Histogram
from time import perf_counter
from json import loads

from config.config import settings

class HttpxMetrics:
  '''
  Tracking calls to external systems from the application

  Uses httpx hooks
  https://www.python-httpx.org/advanced/event-hooks/

  request — called after the request is fully prepared, but before it is sent to the network
  response — called after the response is received from the network, but before it is returned to the caller
  '''

  app_name: str = settings.app_title_metrics

  requests: Counter = Counter(
    name='httpx_requests_total',
    documentation='Total count of requests by method and path',
    labelnames=['app_name']
  )
  requests_processing_time: Histogram = Histogram(
    name='httpx_requests_duration_seconds',
    documentation='Histogram of requests processing time by path (in seconds)',
    labelnames=['app_name']
  )
  '''REQUESTS'''

  responses: Counter = Counter(
    name='httpx_responses_total',
    documentation='Total count of responses by method, path and status codes',
    labelnames=['status_code', 'app_name']
  )
  '''RESPONSES'''

  exceptions: Counter = Counter(
    name='httpx_exceptions_total',
    documentation='Total count of exceptions raised by path and exception type',
    labelnames=['method', 'host', 'path', 'status_code', 'error', 'detail', 'app_name']
  )
  '''EXCEPTIONS'''

  def __init__(self: Self):
    pass

  async def async_metric_hook(self: Self, response: Response):
    request: Request = response.request
    method: str = request.method
    host: str = request.url.host
    path: str = request.url.path
    before_time: float = float(request.headers.get(key='X-Request-Perf-Counter', default=0.0))
    status_code: int = response.status_code
    after_time: float = perf_counter()

    self.requests.labels(app_name=self.app_name).inc()
    self.requests_processing_time.labels(app_name=self.app_name).observe(
      amount=after_time - before_time
    )

    self.responses.labels(status_code=status_code, app_name=self.app_name).inc()

    if status_code >= 400:
      '''
      For normal exceptions:
      {"error":"expired_token","error_description":"The access token provided has expired"}
      '''
      body: bytes = await response.aread()
      decode_body: str = body.decode(encoding='utf-8')
        
      if 'error' in decode_body:
        error: str = loads(body)['error']
        detail: str = loads(body)['error_description']
      elif 'code' in decode_body:
        error: str = loads(body)['status']
        detail: str = loads(body)['message']
      else:
        error: str = 'SeeInLog'
        detail: str = ''

      self.exceptions.labels(
        method=method,
        host=host,
        path=path,
        status_code=status_code,
        error=error,
        detail=detail,
        app_name=self.app_name
      ).inc()
