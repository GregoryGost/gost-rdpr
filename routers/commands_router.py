from fastapi import APIRouter, status, BackgroundTasks, Query
from fastapi.responses import JSONResponse

from typing import Annotated, Self

from logger.logger import logger
from database.db import db
from cache.cache import jobs_cache, Jobs
from client.domains_resolving_client import DomainsResolver
from client.ros_updater_client import RosClient

from .base_router import BaseRouter

# base
from models.http.base import ErrorResp, OkResp
# request models
from models.http.commands_req import ListsLoadCommandQueryReq, RosUpdateCommandQueryReq

class CommandsRouter(BaseRouter):

  domains_resolver: DomainsResolver = DomainsResolver()
  __ros_client: RosClient = RosClient()

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.commands_tag.name],
      prefix='/commands'
    )
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
        status.HTTP_423_LOCKED: {'model': OkResp}
      }
    )
    async def lists_load_command(
      query: Annotated[ListsLoadCommandQueryReq, Query()],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: POST /commands/lists/load')
      try:
        job_status: bool | None = await jobs_cache.get(Jobs.LISTS_LOAD)
        if (job_status != None and job_status == False) or query.forced == True:
          background_tasks.add_task(db.lists_load, query.forced)
        else:
          return JSONResponse(
            OkResp(result=f'Job {Jobs.LISTS_LOAD} is Run').to_dict(),
            status.HTTP_423_LOCKED
          )
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    # /domains/resolve
    @router.post(
      path='/domains/resolve',
      name='Resolve domains',
      description='Start background task for resolve all domains',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_423_LOCKED: {'model': OkResp}
      }
    )
    async def domains_resolve_command(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: POST /commands/domains/resolve')
      try:
        job_status: bool | None = await jobs_cache.get(Jobs.DOMAINS_RESOLVE)
        if job_status != None and job_status == False:
          background_tasks.add_task(self.domains_resolver.domains_resolve)
        else:
          return JSONResponse(
            OkResp(result=f'Job {Jobs.DOMAINS_RESOLVE} is Run').to_dict(),
            status.HTTP_423_LOCKED
          )
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    # /ros/update
    @router.post(
      path='/ros/update',
      name='Update firewall and routing at RouterOS devices',
      description='Update firewall address-list and routing records at all RouterOS devices(configs)',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_423_LOCKED: {'model': OkResp}
      }
    )
    async def ros_update_command(query: Annotated[RosUpdateCommandQueryReq, Query()], background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: POST /commands/ros/update')
      try:
        job_status: bool | None = await jobs_cache.get(Jobs.ROS_UPDATE)
        if job_status != None and job_status == False:
          background_tasks.add_task(self.__ros_client.update, query.type)
        else:
          return JSONResponse(
            OkResp(result=f'Job {Jobs.ROS_UPDATE} is Run').to_dict(),
            status.HTTP_423_LOCKED
          )
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
