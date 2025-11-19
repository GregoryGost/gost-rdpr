from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from datetime import datetime
from time import time
from typing import Self

from logger.logger import logger
from config.config import settings
from database.db import db

from .base_router import BaseRouter

from models.http.home_resp import WelcomeResp, HealthResp, ConfigResp, ConfigStatic, ConfigDynamic

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
    
    # Current config
    ############################################

    @router.get(
      path='/config',
      name='Current config',
      description='Current config. All settings parameters',
      response_model=ConfigResp
    )
    async def get_config() -> JSONResponse:
      logger.debug(f'Call API route: GET /config')
      resp: ConfigResp = ConfigResp(
        static=ConfigStatic(
          root_path=settings.root_path,
          root_log_level=settings.root_log_level,
          app_title=settings.app_title,
          app_summary=settings.app_summary,
          app_description=settings.app_description,
          app_debug=settings.app_debug,
          app_version=settings.app_version,
          app_host=settings.app_host,
          app_port=settings.app_port,
          app_log_level=settings.app_log_level,
          queue_max_size=settings.queue_max_size,
          queue_get_timeout=settings.queue_get_timeout,
          queue_sleep_timeout=settings.queue_sleep_timeout,
          db_log_level=settings.db_log_level,
          db_timeout=settings.db_timeout,
          # db_pool_size=settings.db_pool_size,
          # db_pool_size_overflow=settings.db_pool_size_overflow,
          # db_pool_recycle_sec=settings.db_pool_recycle_sec,
          db_base_dir=settings.db_base_dir,
          db_file_name=settings.db_file_name,
          db_table_prefix=settings.db_table_prefix,
          db_save_batch_size=settings.db_save_batch_size,
          db_save_batch_timeout=settings.db_save_batch_timeout,
          attempts_limit=settings.attempts_limit,
          req_connection_retries=settings.req_connection_retries,
          req_timeout_default=settings.req_timeout_default,
          req_timeout_connect=settings.req_timeout_connect,
          req_timeout_read=settings.req_timeout_read,
          req_max_connections=settings.req_max_connections,
          req_max_keepalive_connections=settings.req_max_keepalive_connections,
          req_ssl_verify=settings.req_ssl_verify,
          req_default_limit=settings.req_default_limit,
          domains_filtered_min_len=settings.domains_filtered_min_len,
          domains_update_interval=settings.domains_update_interval,
          # domains_one_job_resolve_limit=settings.domains_one_job_resolve_limit,
          domain_resolve_semaphore_limit=settings.domain_resolve_semaphore_limit,
          domains_black_list=settings.domains_black_list,
          lists_update_interval_sec=settings.lists_update_interval_sec,
          ip_not_allowed=settings.ip_not_allowed,
          ros_rest_api_read_timeout=settings.ros_rest_api_read_timeout
        ),
        dynamic=ConfigDynamic(
          ip_not_allowed_list=settings.ip_not_allowed_list,
          app_title_metrics=settings.app_title_metrics,
          db_path=settings.db_path,
          db_connection=settings.db_connection
        )
      )
      return JSONResponse(resp.to_dict(), status.HTTP_200_OK)
    
    return router
