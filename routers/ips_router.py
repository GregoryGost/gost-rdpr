from fastapi import APIRouter, status, BackgroundTasks, Query, Path, Body
from fastapi.responses import JSONResponse
from httpx import HTTPError
from time import monotonic
from typing import Annotated, Self, List, Dict

from logger.logger import logger
from database.db import db
from cache.cache import ripe_stat_cache
from client.ripe_stat_client import RipeStatClient, RipeStatClientError
from utils.utils import get_ip_network_address, get_ip_version

from .base_router import BaseRouter

# base
from models.http.base import ErrorResp, NotFoundResp, NoDataResp, OkResp
# request models
from models.http.ips_req import IpsQueryReq, IpsSearchQueryReq, IpsPostElementReq
from models.http.ripe_stat_req import RipeStatPrefixCheckReq
# response models
from models.http.ips_resp import (
  IpsPayloadResp,
  IpsElementResp
)
from models.http.ripe_stat_resp import RipeStatPrefixCheckResp

class IpsRouter(BaseRouter):

  __ips_post_body_examples: List[List[Dict[str, str | int]]] = [
    [
      {
        'addr': '1.1.1.1',
      },
      {
        'addr': '9.9.9.9',
        'domain_id': 1
      },
      {
        'addr': '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'ros_comment': 'discord ip address'
      },
      {
        'addr': '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'domain_id': 3,
        'ros_comment': 'meta ip address'
      },
      {
        'addr': '8.8.8.8',
        'list_id': 15,
        'ros_comment': 'add address to list'
      },
      {
        'addr': '172.10.4.4',
        'use_default_gw': True,
        'ros_comment': 'Exclude IP /32 from the larger mask /16/24 so it doesnt go through the VPN'
      }
    ]
  ]

  __ripe_stat_client: RipeStatClient = RipeStatClient()

  def __init__(self: Self) -> None:
    self.router: APIRouter = APIRouter(
      tags=[self.tags.ips_tag.name],
      prefix='/ips'
    )
    logger.info('IpsRouter init')

  def get_router(self: Self) -> APIRouter:
    router: APIRouter = self.router

    @router.get(
      path='',
      name='Get all IP address records',
      description='Displays all available IP address records',
      response_model=IpsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def get_all_ips(query: Annotated[IpsQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ips')
      try:
        before_time: float = monotonic()
        return_data: IpsPayloadResp = await db.get_all_ips(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date,
          addr_type=query.type,
          use_default_gw=query.default_gw
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='/cleanup/not-allowed',
      name='Queue cleanup of IP addresses blocked by IP_NOT_ALLOWED',
      description=(
        'Starts background cleanup of IP address records matching '
        'IP_NOT_ALLOWED; deletion is queued without direct database writes'
      ),
      response_model=OkResp,
      status_code=status.HTTP_202_ACCEPTED,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def cleanup_not_allowed_ips(
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug('Call API route: POST /ips/cleanup/not-allowed')
      try:
        background_tasks.add_task(db.cleanup_not_allowed_ip_records)
        return JSONResponse(
          content=OkResp().to_dict(),
          status_code=status.HTTP_202_ACCEPTED
        )
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='/ripe/cache/clear',
      name='Clear RIPEstat prefix cache',
      description=(
        'Clears only the in-memory RIPEstat prefix cache without changing '
        'database records'
      ),
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def clear_ripe_stat_cache() -> JSONResponse:
      logger.debug('Call API route: POST /ips/ripe/cache/clear')
      try:
        await ripe_stat_cache.clear()
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/search',
      name='Find Ips address by text',
      description='Find a Ips address by text. Using fields "addr"',
      response_model=IpsPayloadResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def search_ips(query: Annotated[IpsSearchQueryReq, Query()]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ips/search')
      try:
        before_time: float = monotonic()
        return_data: IpsPayloadResp = await db.get_all_ips(
          before_time=before_time,
          limit=query.limit,
          offset=query.offset,
          start_date=query.start_date,
          end_date=query.end_date,
          search_text=query.text,
          addr_type=query.type,
          use_default_gw=query.default_gw
        )
        return JSONResponse(return_data.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='/ripe/check',
      name='Check IPv4 prefix in RIPEstat',
      description='Check an IPv4 address in RIPEstat without saving a record to the database',
      response_model=RipeStatPrefixCheckResp,
      responses={
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {'model': ErrorResp},
        status.HTTP_502_BAD_GATEWAY: {'model': ErrorResp},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def check_ip_prefix_in_ripe_stat(
      data: Annotated[RipeStatPrefixCheckReq, Body()]
    ) -> JSONResponse:
      logger.debug('Call API route: POST /ips/ripe/check')
      try:
        address: str | None = data.address

        if data.id is not None:
          ip_record: IpsElementResp | None = await db.get_ip_record_on_id(
            data.id
          )

          if ip_record is None:
            not_found_resp = NotFoundResp(
              resolution=f"IP address with ID '{data.id}' not found in local db"
            )
            return JSONResponse(
              content=not_found_resp.to_dict(),
              status_code=status.HTTP_404_NOT_FOUND
            )

          address = get_ip_network_address(ip_record.addr)

          if get_ip_version(address) != 4:
            error = ErrorResp(
              error='Only IPv4 addresses are supported by this check'
            )
            return JSONResponse(
              content=error.to_dict(),
              status_code=status.HTTP_422_UNPROCESSABLE_CONTENT
            )

          logger.debug(
            f'IP address found on ID={data.id} for RIPEstat prefix check: '
            f'{address}'
          )

        if address is None:
          raise ValueError('IP address is not defined')

        ripe_result = await self.__ripe_stat_client.get_prefix(address=address)
        return_data = RipeStatPrefixCheckResp(
          address=ripe_result.address,
          prefix=ripe_result.prefix
        )
        return JSONResponse(
          content=return_data.to_dict(),
          status_code=status.HTTP_200_OK
        )
      except (RipeStatClientError, HTTPError) as err:
        logger.error(
          f'RIPEstat prefix check failed for {address}: '
          f'[{err.__class__.__name__}] {err}'
        )
        error = ErrorResp(
          error='RIPEstat prefix check failed',
          resolution=str(err)
        )
        return JSONResponse(
          content=error.to_dict(),
          status_code=status.HTTP_502_BAD_GATEWAY
        )
      except Exception as err:
        return self.errorResp(err)

    @router.get(
      path='/{id}',
      name='Get one IP address record on ID',
      description='Displays one IP address record on ID',
      response_model=IpsElementResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
      }
    )
    async def get_ip_record_on_id(id: Annotated[int, Path(gt=0, title='IP address record ID')]) -> JSONResponse:
      logger.debug(f'Call API route: GET /ips/{id}')
      try:
        ip_addr_resp: IpsElementResp | None = await db.get_ip_record_on_id(id)
        if ip_addr_resp is None:
          not_found_resp: NotFoundResp = NotFoundResp(resolution=f"IP address with ID '{id}' not found in local db")
          return JSONResponse(not_found_resp.to_dict(), status.HTTP_404_NOT_FOUND)
        return JSONResponse(ip_addr_resp.to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.post(
      path='',
       name='Add new IP address records',
      description='Add new IP address records. New IPs link to default domain at ID = 0',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
        status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
      }
    )
    async def add_new_ips(
      data: Annotated[List[IpsPostElementReq], Body(examples=self.__ips_post_body_examples)],
      background_tasks: BackgroundTasks
    ):
      logger.debug(f'Call API route: POST /ips')
      try:
        if (len(data) < 1):
          return JSONResponse(NoDataResp().to_dict(), status.HTTP_400_BAD_REQUEST)
        background_tasks.add_task(db.put_add_ips_to_queue, data)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    @router.delete(
      path='/{id_or_ip}',
      name='Delete one IP address record (ip or id over query param)',
      description='Delete one IP address record on ID or IP',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def delete_ip_record(
      id_or_ip: Annotated[int | str, Path(title='ID or IP address')],
      background_tasks: BackgroundTasks
    ) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /ips/{id_or_ip}')
      try:
        background_tasks.add_task(db.put_delete_ips_to_queue, id_or_ip)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    # @router.delete() all
    @router.delete(
      path='',
      name='Clear All IP address records (WARNING!!!)',
      description='Clear All IP address records',
      response_model=OkResp,
      responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
      }
    )
    async def ips_delete_all(background_tasks: BackgroundTasks) -> JSONResponse:
      logger.debug(f'Call API route: DELETE /ips')
      try:
        background_tasks.add_task(db.put_delete_ips_to_queue)
        return JSONResponse(OkResp().to_dict(), status.HTTP_200_OK)
      except Exception as err:
        return self.errorResp(err)

    return router
