from fastapi import APIRouter, status, BackgroundTasks, Query, Path, Body
from fastapi.responses import JSONResponse
from time import monotonic
from typing import Annotated, Self, List, Dict

from logger.logger import logger
from database.db import db
from client.domains_resolving_client import DomainsResolver

from .base_router import BaseRouter

#
from models.dto.domains_dto import CheckDomainResultDto, DomainResult
# base
from models.http.base import ErrorResp, NotFoundResp, NoDataResp, OkResp
# request models
from models.http.domains_req import DomainsQueryReq, DomainsSearchQueryReq, DomainsPostElementReq, DomainResolveReq
# response models
from models.http.domains_resp import DomainsPayloadResp, DomainElementResp, DomainResolveResp, DnsServerResolveResultResp

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

  __domains_resolver: DomainsResolver = DomainsResolver()

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

    # single domain test resolver
    @router.post(
      path='/resolve/check',
      name='Resolve domain once',
      description='Resolve a domain using configured DNS servers without saving the result to the database',
      response_model=DomainResolveResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def resolve_domain_once(data: Annotated[DomainResolveReq, Body()]) -> JSONResponse:
      logger.debug('Call API route: POST /domains/resolve/check')
      try:
        result: CheckDomainResultDto = await self.__domains_resolver.resolve_once(domain_name=data.domain)
        return_data: DomainResolveResp = DomainResolveResp(
          domain=result.domain,
          results=[
            DnsServerResolveResultResp(
              server=item.server,
              server_type=item.server_type,
              ips_v4=item.ips_v4,
              ips_v6=item.ips_v6,
              cnames=item.cnames
            )
            for item in result.results
          ]
        )
        return JSONResponse(content=return_data.to_dict(), status_code=status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)
      
    # resolve and save single domain
    @router.post(
      path='/{id}/resolve',
      response_model=OkResp,
      status_code=status.HTTP_202_ACCEPTED,
      responses={
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def resolve_domain_now(id: Annotated[int, Path(gt=0)], background_tasks: BackgroundTasks) -> JSONResponse:
      background_tasks.add_task(
        self.__domains_resolver.resolve_stored_domain,
        id
      )
      return JSONResponse(
        OkResp(result='Domain resolving accepted').to_dict(),
        status.HTTP_202_ACCEPTED
      )

    return router
