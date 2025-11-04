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
from models.http.ips_lists_req import IpsListsQueryReq, IpsListsSearchQueryReq, IpsListsPostElementReq
# response models
from models.http.ips_lists_resp import IpsListsPayloadResp, IpsListElementResp

class IpsListsRouter(BaseRouter):

  __ips_lists_post_body_examples: List[List[Dict[str, str]]] = [
    [
      {
        'name': 'ips-list',
        'url': 'https://somedomain.som/path/path/path/some-ips-list'
      },
      {
        'name': 'ips-list-2',
        'url': 'https://somedomain.som/path/path/path/some-ips-list-2.txt',
        'description': 'Description for some ips address list'
      }
    ]
  ]

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.ips_lists_tag.name],
      prefix='/ips/lists'
    )
    logger.info('IpsListsRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all IP address lists',
      description='Displays all IP address lists records',
      response_model=IpsListsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_all_ips_lists(query: Annotated[IpsListsQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ips/lists')
      try:
        before_time: float = monotonic()
        return_data: IpsListsPayloadResp = await db.get_all_ips_lists(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date,
          attempts=query.attempts
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/search',
      name='Find Ips lists by text',
      description='Find a Ips lists by text. Using fields "name" or "url"',
      response_model=IpsListsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def search_ips_lists(query: Annotated[IpsListsSearchQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ips/lists')
      try:
        before_time: float = monotonic()
        return_data: IpsListsPayloadResp = await db.get_all_ips_lists(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date,
          search_text=query.text,
          attempts=query.attempts
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/{id}',
      name='Get one IP address list',
      description='Displays one IP address list record on ID',
      response_model=IpsListElementResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
      }
    )
    async def get_ips_list_on_id(id: Annotated[int, Path(gt=0, title='Ips list record ID')]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ips/lists/{id}')
      try:
        ips_lists_resp: IpsListElementResp | None = await db.get_ips_list_on_id(id)
        if ips_lists_resp is None:
          not_found_resp: NotFoundResp = NotFoundResp(resolution=f"Ips list ID '{id}' not found in local db")
          return JSONResponse(not_found_resp.to_dict(), status.HTTP_404_NOT_FOUND)
        return JSONResponse(ips_lists_resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='',
      name='Add new IP address lists',
      description='Add new IP address lists URL for download',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
      }
    )
    async def ips_lists_add(
      data: Annotated[List[IpsListsPostElementReq], Body(examples=self.__ips_lists_post_body_examples)],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: POST /ips/lists')
      try:
        if (len(data) < 1):
          return JSONResponse(NoDataResp().to_dict(), status.HTTP_400_BAD_REQUEST)
        background_tasks.add_task(db.put_add_ips_lists_to_queue, data)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='/{id}',
      name='Delete one IP address list',
      description='Delete one IP address list record',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def ips_list_delete(
      id: Annotated[int, Path(gt=0, title='Ips list record ID')],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /ips/lists/{id}')
      try:
        background_tasks.add_task(db.put_delete_ips_list_to_queue, id)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='',
      name='Delete all IP address lists records',
      description='Delete all IP address lists records',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def ips_lists_delete_all(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /ips/lists')
      try:
        background_tasks.add_task(db.put_delete_ips_list_to_queue)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
