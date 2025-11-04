from httpx import AsyncClient, Timeout, AsyncHTTPTransport, Limits
from httpx._types import HeaderTypes

from config.config import settings
from metrics.httpx_metrics import HttpxMetrics

class HttpClient:

  headers: HeaderTypes = {
    'Accept': '*/*',
    'User-Agent': f'{settings.app_title} [{settings.app_version}]'
  }
  metrics: HttpxMetrics = HttpxMetrics()

  def __init__(self) -> None:
    # Common
    self.limits: Limits = Limits(
      max_connections=settings.req_max_connections,
      max_keepalive_connections=settings.req_max_keepalive_connections
    )
    self.timeout: Timeout = Timeout(
      timeout=settings.req_timeout_default,
      connect=settings.req_timeout_connect,
      read=settings.req_timeout_read
    )
    # Async
    self.transport: AsyncHTTPTransport = AsyncHTTPTransport(
      retries=settings.req_connection_retries,
      verify=settings.req_ssl_verify
    )
    self.client: AsyncClient = AsyncClient(
      headers=self.headers,
      limits=self.limits,
      transport=self.transport,
      timeout=self.timeout
    )
    self.client.event_hooks['response'] = [self.metrics.async_metric_hook]
