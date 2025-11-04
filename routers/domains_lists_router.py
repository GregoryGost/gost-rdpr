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
from models.http.domains_lists_req import DomainsListsQueryReq, DomainsListsSearchQueryReq, DomainsListsPostElementReq
# response models
from models.http.domains_lists_resp import DomainsListsPayloadResp, DomainsListElementResp

class DomainsListsRouter(BaseRouter):

  __domains_lists_post_body_examples: List[List[Dict[str, str]]] = [
    [
      {
        'name': 'voice-domains-list',
        'url': 'https://somedomain.som/path/path/path/voice.txt'
      },
      {
        'name': 'voice-domains-list-2',
        'url': 'https://somedomain.som/path/path/path/voice-2.txt',
        'description': 'Description for some voice domains list'
      }
    ]
  ]

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.domains_lists_tag.name],
      prefix='/domains/lists'
    )
    logger.info('DomainsListsRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all Domains lists',
      description='Displays all Domains lists records',
      response_model=DomainsListsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_all_domains_lists(query: Annotated[DomainsListsQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /domains/lists')
      try:
        before_time: float = monotonic()
        return_data: DomainsListsPayloadResp = await db.get_all_domains_lists(
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
      name='Find Domains lists by text',
      description='Find a Domains lists by text. Using fields "name" or "url"',
      response_model=DomainsListsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def search_domains_lists(query: Annotated[DomainsListsSearchQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /domains/lists/search')
      try:
        before_time: float = monotonic()
        return_data: DomainsListsPayloadResp = await db.get_all_domains_lists(
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
      name='Get one Domains list',
      description='Displays one Domains list record info',
      response_model=DomainsListElementResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
      }
    )
    async def get_domains_list_on_id(id: Annotated[int, Path(gt=0, title='Domains list record ID')]) -> JSONResponse:
      logger.debug(f'Call API route: GET /domains/lists/{id}')
      try:
        domains_lists_resp: DomainsListElementResp | None = await db.get_domains_list_on_id(id)
        if domains_lists_resp is None:
          not_found_resp: NotFoundResp = NotFoundResp(resolution=f"Domains list ID '{id}' not found in local db")
          return JSONResponse(not_found_resp.to_dict(), status.HTTP_404_NOT_FOUND)
        return JSONResponse(domains_lists_resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='',
      name='Add new domains lists',
      description='Add new domains lists URL for download and parse for next',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
      }
    )
    async def domains_lists_add(
      data: Annotated[List[DomainsListsPostElementReq], Body(examples=self.__domains_lists_post_body_examples)],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: POST /domains/lists')
      try:
        if (len(data) < 1):
          return JSONResponse(NoDataResp().to_dict(), status.HTTP_400_BAD_REQUEST)
        background_tasks.add_task(db.put_add_domains_lists_to_queue, data)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='/{id}',
      name='Delete one Domains list',
      description='Delete one Domains list record',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def domains_list_delete(
      id: Annotated[int, Path(gt=0, title='Domains list record ID')],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /domains/lists/{id}')
      try:
        background_tasks.add_task(db.put_delete_domains_list_to_queue, id)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='',
      name='Delete all Domains lists records',
      description='Delete all Domains lists records',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def domains_lists_delete_all(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /domains/lists')
      try:
        background_tasks.add_task(db.put_delete_domains_list_to_queue)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
