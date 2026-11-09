from typing import Annotated, Self

from fastapi import APIRouter, BackgroundTasks, Query, status
from fastapi.responses import JSONResponse

from client.domains_resolving_client import DomainsResolver, saving_coordinator
from client.ros_updater_client import RosClient
from database.db import db
from jobs.job_registry import Jobs, job_registry
from logger.logger import logger

# base
from models.http.base import ErrorResp, OkResp

# request models
from models.http.commands_req import ListsLoadCommandQueryReq, RosUpdateCommandQueryReq

from .base_router import BaseRouter


class CommandsRouter(BaseRouter):
  domains_resolver: DomainsResolver = DomainsResolver()
  __ros_client: RosClient = RosClient()

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(tags=[self.tags.commands_tag.name], prefix='/commands')
    logger.info(f'{self.__class__.__name__} init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.post(
      path='/lists/load',
      name='Download domains and ips lists',
      description='Start background task for download domains and ips lists if hash files changed',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      },
    )
    async def lists_load_command(
      query: Annotated[ListsLoadCommandQueryReq, Query()], background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug('Call API route: POST /commands/lists/load')
      try:
        if await job_registry.try_start(Jobs.LISTS_LOAD):
          try:
            background_tasks.add_task(db.lists_load, query.forced)
          except Exception:
            await job_registry.finish(Jobs.LISTS_LOAD)
            raise
        else:
          return JSONResponse(OkResp(result=f'Job {Jobs.LISTS_LOAD} is Run').to_dict(), status.HTTP_200_OK)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        logger.error('List loading request failed', exc_info=True)
        return self.errorResp(err)

    # /domains/resolve
    @router.post(
      path='/domains/resolve/new',
      name='Resolve new domains',
      description='Start background task for resolve only new domains. It can be done more often',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      },
    )
    async def domains_resolve_new_command() -> JSONResponse:
      logger.debug('Call API route: POST /commands/domains/resolve/new')
      try:
        await saving_coordinator.submit_scan(Jobs.DOMAINS_RESOLVE_NEW, resolver=self.domains_resolver)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        logger.error('New-domain resolution request failed', exc_info=True)
        return self.errorResp(err)

    @router.post(
      path='/domains/resolve/stale',
      name='Resolve stale domains',
      description=(
        'Start background task for resolve stale domains. '
        'This should be done rarely because there are many such domains'
      ),
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      },
    )
    async def domains_resolve_stale_command() -> JSONResponse:
      logger.debug('Call API route: POST /commands/domains/resolve/stale')
      try:
        if not await saving_coordinator.submit_scan(Jobs.DOMAINS_RESOLVE_STALE, resolver=self.domains_resolver):
          return JSONResponse(
            OkResp(result=f'Job [{Jobs.DOMAINS_RESOLVE}] is now active').to_dict(), status.HTTP_200_OK
          )
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        logger.error('Stale-domain resolution request failed', exc_info=True)
        return self.errorResp(err)

    # /ros/update
    @router.post(
      path='/ros/update',
      name='Update firewall and routing at RouterOS devices',
      description='Update firewall address-list and routing records at all RouterOS devices(configs)',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResp},
      },
    )
    async def ros_update_command(
      query: Annotated[RosUpdateCommandQueryReq, Query()], background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug('Call API route: POST /commands/ros/update')
      try:
        if query.type != 4:
          return JSONResponse(
            ErrorResp(
              error=f'INVALID QUERY TYPE. {query=}',
              resolution=(
                'RouterOS Firewall address-list. IP-IP ranges are supported only for IPv4 addresses. '
                'More info: https://help.mikrotik.com/docs/spaces/ROS/pages/130220135/'
                'Address-lists#Addresslists-Properties Use type=4 parameter only !!!'
              ),
            ).to_dict(),
            status.HTTP_400_BAD_REQUEST,
          )
        if await job_registry.try_start(Jobs.ROS_UPDATE):
          try:
            background_tasks.add_task(self.__ros_client.update, query.type)
          except Exception:
            await job_registry.finish(Jobs.ROS_UPDATE)
            raise
        else:
          return JSONResponse(OkResp(result=f'Job [{Jobs.ROS_UPDATE}] is now active').to_dict(), status.HTTP_200_OK)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        logger.error('RouterOS update request failed', exc_info=True)
        return self.errorResp(err)

    return router
