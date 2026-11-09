from asyncio import CancelledError
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from re import sub
from typing import Any, ClassVar, Self
from urllib.parse import unquote

from fastapi import FastAPI, Request, status
from fastapi.datastructures import QueryParams
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from uvicorn import Config, Server

from client.domains_resolving_client import _await_owned, saving_coordinator
from client.http_base_client import HttpClient
from config.config import settings
from database.db import db
from jobs.job_registry import job_registry
from logger.logger import logger
from metrics.metrics import PrometheusMiddleware
from models.http.base import ErrorResp
from routers.commands_router import CommandsRouter
from routers.dns_servers_router import DnsServersRouter
from routers.domains_lists_router import DomainsListsRouter
from routers.domains_router import DomainsRouter
from routers.home_router import HomeRouter
from routers.ips_lists_router import IpsListsRouter
from routers.ips_router import IpsRouter
from routers.metrics_router import MetricsRouter
from routers.ros_configs_router import RosConfigsRouter
from routers.statistics_router import StatisticsRouter

from .tags_metadata import TagsMetadata


class AppServer:
  tags: TagsMetadata = TagsMetadata()
  tags_metadata: ClassVar[list[dict[str, str]]] = [
    {'name': tags.home_tag.name, 'description': tags.home_tag.description}
  ]

  origins: ClassVar[list[str]] = [
    f'http://{settings.app_host}',
    f'http://{settings.app_host}:{settings.app_port}',
    f'https://{settings.app_host}',
    f'https://{settings.app_host}:{settings.app_port}',
  ]

  def __init__(self: Self) -> None:
    self.app: FastAPI = FastAPI(
      title=settings.app_title,
      summary=settings.app_summary,
      description=settings.app_description,
      debug=settings.app_debug,
      version=settings.app_version,
      docs_url='/docs',
      openapi_url='/docs/openapi.json',
      openapi_tags=self.tags_metadata,
      lifespan=self.__lifespan,
    )
    logger.debug('AppServer init completed')

  @asynccontextmanager
  async def __lifespan(self: Self, app: FastAPI) -> AsyncGenerator[None, Any]:
    try:
      await job_registry.reset()
      await db.setup()
      await saving_coordinator.start()
      yield
    finally:
      await _await_owned(self.__close_resources(), cancel_on_cancel=False)

  @staticmethod
  async def __close_resources() -> None:
    failure: BaseException | None = None
    for cleanup in (saving_coordinator.stop, db.close, saving_coordinator.finish_close, HttpClient.close):
      try:
        await cleanup()
      except (Exception, CancelledError) as err:
        if failure is None:
          failure = err
        else:
          logger.error('Additional application cleanup failed', exc_info=RuntimeError('Application cleanup failed'))
    if failure is not None:
      raise failure

  async def run(self: Self):
    logger.debug('AppServer run ...')

    # Init Web API
    app: FastAPI = self.app

    app.add_middleware(
      CORSMiddleware, allow_origins=self.origins, allow_credentials=True, allow_methods=['*'], allow_headers=['*']
    )
    app.add_middleware(PrometheusMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exception: RequestValidationError) -> JSONResponse:
      try:
        body: bytes = await request.body()
        args: QueryParams = request.query_params
        bodyStr: str = body.decode('utf-8')
        bodyStr = sub(r'\s+', ' ', bodyStr).strip()
        logger.error(
          f'RequestValidationError={exception!s} :\n URL={unquote(str(request.url))} :\n '
          f'bodyStr={bodyStr} :\n args={args}'
        )
        return JSONResponse(
          content=jsonable_encoder(exception.errors()), status_code=status.HTTP_422_UNPROCESSABLE_CONTENT
        )
      except Exception as err:
        logger.error('Request validation response failed', exc_info=True)
        return JSONResponse(
          content=ErrorResp(error=f'{err}').model_dump(exclude_none=True),
          status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    app.include_router(MetricsRouter().get_router())
    app.include_router(HomeRouter().get_router())
    app.include_router(DnsServersRouter().get_router())
    app.include_router(DomainsListsRouter().get_router())
    app.include_router(DomainsRouter().get_router())
    app.include_router(IpsListsRouter().get_router())
    app.include_router(IpsRouter().get_router())
    app.include_router(RosConfigsRouter().get_router())
    app.include_router(CommandsRouter().get_router())
    app.include_router(StatisticsRouter().get_router())

    # Configurable and running
    config: Config = Config(
      app, host=settings.app_host, port=settings.app_port, log_level=settings.app_log_level, server_header=False
    )
    server: Server = Server(config)
    await server.serve()
