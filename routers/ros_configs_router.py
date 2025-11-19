from fastapi import APIRouter, status, BackgroundTasks, Query, Path, Body
from fastapi.responses import JSONResponse
from time import monotonic
from typing import Annotated, Self, List, Dict

from logger.logger import logger
from database.db import db

from .base_router import BaseRouter

# base
from models.http.base import ErrorResp, NotFoundResp, NoDataResp, OkResp
# request models
from models.http.ros_configs_req import RosConfigsQueryReq, RosConfigsSearchQueryReq, RosConfigsPostElementReq
# response models
from models.http.ros_configs_resp import RosConfigPayloadResp, RosConfigElementResp

class RosConfigsRouter(BaseRouter):

  __ros_configs_post_body_examples: List[List[Dict[str, str]]] = [
    [
      {
        "host": "192.168.200.1",
        "user": "test",
        "user_password": "1234",
        "bgp_list_name": "bgp-networks",
        "description": "Test CHR Host"
      }
    ]
  ]

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.ros_configs_tag.name],
      prefix='/ros'
    )
    logger.info('RosConfigsRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all Router OS configs',
      description='Displays all Router OS configs records. No connect tests',
      response_model=RosConfigPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_all_ros_configs(query: Annotated[RosConfigsQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ros')
      try:
        before_time: float = monotonic()
        return_data: RosConfigPayloadResp = await db.get_all_ros_configs(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/search',
      name='Find Router OS configs by text',
      description='Find a Router OS configs by text. Using fields "host" or "user" or "bgp_list_name"',
      response_model=RosConfigPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def search_ros_configs(query: Annotated[RosConfigsSearchQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ros/search')
      try:
        before_time: float = monotonic()
        return_data: RosConfigPayloadResp = await db.get_all_ros_configs(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date,
          search_text=query.text
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/{id}',
      name='Get Router OS configs by id',
      description='Get a Router OS configs by id',
      response_model=RosConfigElementResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
      }
    )
    async def get_ros_config_on_id(id: Annotated[int, Path(ge=1, title='Router OS configs record ID')]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ros/{id}')
      try:
        ros_config_resp: RosConfigElementResp | None = await db.get_ros_config_on_id(id)
        if ros_config_resp is None:
          not_found_resp: NotFoundResp = NotFoundResp(resolution=f"RoS config with ID={id} not found in local db")
          return JSONResponse(not_found_resp.to_dict(), status.HTTP_404_NOT_FOUND)
        return JSONResponse(ros_config_resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='',
      name='Add Router OS configs',
      description='Adds new RouterOS configurations. IP address rollout will be applied to each configuration',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
      }
    )
    async def ros_configs_add(
      data: Annotated[List[RosConfigsPostElementReq], Body(examples=self.__ros_configs_post_body_examples)],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: POST /ros')
      try:
        if (len(data) < 1):
          return JSONResponse(NoDataResp().to_dict(), status.HTTP_400_BAD_REQUEST)
        background_tasks.add_task(db.put_add_ros_configs_to_queue, data)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='/{id}',
      name='Delete one RouterOS config',
      description='Delete once RouterOS config record',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def ros_config_delete(
      id: Annotated[int, Path(ge=1, title='Router OS configs record ID')],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /ros/{id}')
      try:
        background_tasks.add_task(db.put_delete_ros_configs_to_queue, id)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    # delete all
    @router.delete(
      path='',
      name='Delete all RouterOS configs',
      description='Delete all RouterOS configs records',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def ros_configs_delete_all(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /ros')
      try:
        background_tasks.add_task(db.put_delete_ros_configs_to_queue)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
