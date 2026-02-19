from fastapi import APIRouter, status, Query
from time import monotonic
from fastapi.responses import JSONResponse

from typing import Annotated, Self

from logger.logger import logger
from database.db import db

from .base_router import BaseRouter

# base
from models.http.base import ErrorResp
# response models
from models.http.statistics_resp import StatsResp, StatsGrowthResp
# request models
from models.http.statistics_req import StatsGrowthQuery

class StatisticsRouter(BaseRouter):

  # ALL [GET]
  # 1. /stats
  # 2. /stats/growth  - Statistics: Line chart (periods)

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.statistics_tag.name],
      prefix='/stats'
    )
    logger.info(f'{self.__class__.__name__} init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all statistics total data',
      description='Displays all all statistics total data',
      response_model=StatsResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_stats() -> JSONResponse:
      logger.debug(f'Call API route: GET /stats')
      try:
        resp: StatsResp = await db.stats()
        return JSONResponse(resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)
    
    @router.get(
      path='/growth',
      name='Get Growth Time Series',
      description='Time series of record creation grouped by date/week/month.',
      response_model=StatsGrowthResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_stats_growth(query: Annotated[StatsGrowthQuery, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /stats/growth')
      try:
        before_time: float = monotonic()
        resp: StatsGrowthResp = await db.stats_growth(
          before_time=before_time,
          entity=query.entity,
          granularity=query.granularity,
          start_date=query.start_date,
          end_date=query.end_date,
          ip_subtype=query.ip_subtype,
          date_field=query.date_filter_field
        )
        return JSONResponse(resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
