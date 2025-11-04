from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from datetime import datetime
from time import time
from typing import Self

from logger.logger import logger
from config.config import settings
from database.db import db

from .base_router import BaseRouter

from models.http.home_resp import WelcomeResp, HealthResp

class HomeRouter(BaseRouter):

  start_time: float = time()

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.home_tag.name]
    )
    logger.info('HomeRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    # Welcome
    ############################################

    @router.get(
      path='/',
      name='Welcome',
      description='Base welcome answer',
      response_model=WelcomeResp
    )
    async def welcome() -> JSONResponse:
      logger.debug(f'Call API route: GET /')
      resp: WelcomeResp = WelcomeResp(version=settings.app_version, docs='/docs')
      return JSONResponse(resp.to_dict(), status.HTTP_200_OK)
    
    # Health
    ############################################

    @router.get(
      path='/health',
      name='Health check',
      description='API OK checker',
      response_model=HealthResp
    )
    async def health() -> JSONResponse:
      logger.debug(f'Call API route: GET /health')
      now = datetime.now()
      ts = datetime.timestamp(now) // 1
      uptime = (time() - self.start_time) // 1
      resp: HealthResp = HealthResp(
        ts=ts,
        uptime=uptime,
        db_pool=db.pool_status
      )
      return JSONResponse(resp.to_dict(), status.HTTP_200_OK)
    
    return router
