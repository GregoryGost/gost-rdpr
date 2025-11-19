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
from models.http.dns_servers_req import DnsQueryReq, DnsSearchQueryReq, DnsPostElementReq
# response models
from models.http.dns_servers_resp import DnsPayloadResp, DnsElementResp

class DnsServersRouter(BaseRouter):
  '''
  /dns      [GET]     - Get all DNS servers records  
  /dns/{id} [GET]     - Get once DNS server record by id  
  /dns      [POST]    - Add new DNS servers  
  /dns      [DELETE]  - Clear All DNS servers records (WARNING!!!)  
  /dns/{id} [DELETE]  - Delete once DNS server record by id
  '''

  __dns_post_body_examples: List[List[Dict[str, str]]] = [
    [
      {
        'server': '9.9.9.9',
      },
      {
        'server': '1.1.1.1',
        'description': 'Simple IPv4 DNS server'
      },
      {
        'doh_server': 'https://dns.adguard-dns.com/dns-query',
        'description': 'DNS over HTTPS server URL'
      }
    ]
  ]

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.dns_servers_tag.name],
      prefix='/dns'
    )
    logger.info('DnsServersRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all DNS servers records',
      description='Displays all available DNS server records. Also displays the default DNS server with ID -1',
      response_model=DnsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_all_dns_servers(query: Annotated[DnsQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /dns')
      try:
        before_time: float = monotonic()
        return_data: DnsPayloadResp = await db.get_all_dns_servers(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date,
          default=query.default
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/search',
      name='Find DNS server by text',
      description='Find a DNS server by text. Using fields "server" or "doh_server"',
      response_model=DnsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def search_dns_servers(query: Annotated[DnsSearchQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /dns/search')
      try:
        before_time: float = monotonic()
        return_data: DnsPayloadResp = await db.get_all_dns_servers(
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
      name='Get one DNS server record',
      description='Display parameters at one DNS server record',
      response_model=DnsElementResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
      }
    )
    async def get_dns_server_on_id(id: Annotated[int, Path(ge=-1, title='DNS record ID')]) -> JSONResponse:
      logger.debug(f'Call API route: GET /dns/{id}')
      try:
        dns_server_resp: DnsElementResp | None = await db.get_dns_server_on_id(id)
        if dns_server_resp is None:
          not_found_resp: NotFoundResp = NotFoundResp(resolution=f"DNS server ID '{id}' not found in local db")
          return JSONResponse(not_found_resp.to_dict(), status.HTTP_404_NOT_FOUND)
        return JSONResponse(dns_server_resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='',
      name='Add new DNS servers',
      description='Allows you to add the required DNS servers through an array with parameters',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
      }
    )
    async def dns_servers_add(
      data: Annotated[List[DnsPostElementReq], Body(examples=self.__dns_post_body_examples)],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: POST /dns')
      try:
        if (len(data) < 1):
          return JSONResponse(NoDataResp().to_dict(), status.HTTP_400_BAD_REQUEST)
        background_tasks.add_task(db.put_add_dns_servers_to_queue, data)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='/{id}',
      name='Delete one DNS server record',
      description='Delete one DNS server record',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def dns_server_delete(
      id: Annotated[int, Path(gt=-1, title='DNS record ID')],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /dns/{id}')
      try:
        background_tasks.add_task(db.put_delete_dns_servers_to_queue, id)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='',
      name='Clear All DNS servers records (WARNING!!!)',
      description='Clear All DNS servers records. But not default record id=-1',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def dns_servers_delete_all(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /dns')
      try:
        background_tasks.add_task(db.put_delete_dns_servers_to_queue)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
