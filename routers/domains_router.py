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
from models.http.domains_req import DomainsQueryReq, DomainsSearchQueryReq, DomainsPostElementReq
# response models
from models.http.domains_resp import DomainsPayloadResp, DomainElementResp

class DomainsRouter(BaseRouter):

  __domains_post_body_examples: List[List[Dict[str, str]]] = [
    [
      {
        'domain': 'google.com',
      },
      {
        'domain': 'rotterdam1192.discord.gg',
        'ros_comment': 'discord domain'
      }
    ]
  ]

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.domains_tag.name],
      prefix='/domains'
    )
    logger.info('DomainsRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all Domains records',
      description='Displays all available Domains records',
      response_model=DomainsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_all_domains(query: Annotated[DomainsQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /domains')
      try:
        before_time: float = monotonic()
        return_data: DomainsPayloadResp = await db.get_all_domains(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          resolved=query.resolved,
          start_date=query.start_date,
          end_date=query.end_date
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/search',
      name='Find Domains by text',
      description='Find a Domains by text. Using fields "name" or "url"',
      response_model=DomainsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def search_domains(query: Annotated[DomainsSearchQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /domains/search')
      try:
        before_time: float = monotonic()
        return_data: DomainsPayloadResp = await db.get_all_domains(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          resolved=query.resolved,
          start_date=query.start_date,
          end_date=query.end_date,
          search_text=query.text
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/{id}',
      name='Get one Domain',
      description='Displays one Domain record info',
      response_model=DomainElementResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
      }
    )
    async def get_domain_on_id(id: Annotated[int, Path(ge=0, title='Domain record ID')]) -> JSONResponse:
      logger.debug(f'Call API route: GET /domains/{id}')
      try:
        domain_resp: DomainElementResp | None = await db.get_domain_on_id(id)
        if domain_resp is None:
          not_found_resp: NotFoundResp = NotFoundResp(resolution=f"Domain with ID '{id}' not found in local db")
          return JSONResponse(not_found_resp.to_dict(), status.HTTP_404_NOT_FOUND)
        return JSONResponse(domain_resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='',
      name='Add new domains',
      description='Background add new domains',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
      }
    )
    async def domains_add(
      data: Annotated[List[DomainsPostElementReq], Body(examples=self.__domains_post_body_examples)],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: POST /domains')
      try:
        if (len(data) < 1):
          return JSONResponse(NoDataResp().to_dict(), status.HTTP_400_BAD_REQUEST)
        background_tasks.add_task(db.put_add_domains_to_queue, data)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='/{id}',
      name='Delete one Domain record',
      description='Background delete one Domain record',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def domain_delete(
      id: Annotated[int, Path(ge=-1, title='Domain record ID')],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /domains/{id}')
      try:
        background_tasks.add_task(db.put_delete_domains_to_queue, id)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    # delete all
    @router.delete(
      path='',
      name='Clear All Domains records (WARNING!!!)',
      description='Clear All Domains records. But not default record id=-1',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def domains_delete_all(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /domains')
      try:
        background_tasks.add_task(db.put_delete_domains_to_queue)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
