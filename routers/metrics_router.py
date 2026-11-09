from typing import Self

from fastapi import APIRouter, status
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY
from prometheus_client.openmetrics.exposition import generate_latest

from logger.logger import logger
from models.http.base import ErrorResp

from .base_router import BaseRouter


class MetricsRouter(BaseRouter):
  """
  /metrics [GET] - prometheus metrics
  """

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(tags=[self.tags.metrics_tag.name])
    logger.info('MetricsRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='/metrics',
      name='Metrics',
      description='Prometheus metrics',
      response_class=PlainTextResponse,
      responses={status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}},
    )
    async def metrics() -> Response:
      logger.debug('Call API route: GET /metrics')
      try:
        return PlainTextResponse(
          content=generate_latest(REGISTRY),
          headers={'Content-Type': CONTENT_TYPE_LATEST},
          status_code=status.HTTP_200_OK,
        )
      except Exception as err:  # noqa: BLE001 - The shared API boundary logs and translates every exception.
        return self.errorResp(err)

    return router
