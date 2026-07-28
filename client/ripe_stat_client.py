from ipaddress import ip_address
from typing import Any, Dict, Self

from httpx import AsyncClient, Response

from client.http_base_client import HttpClient
from config.config import settings
from models.dto.ripe_stat_dto import RipeStatAddressPrefixDto


class RipeStatClientError(Exception):
  pass


class RipeStatClient:

  __client: AsyncClient = HttpClient.get_client('ripe_stat')

  def __init__(self: Self) -> None:
    self.__base_url: str = settings.ripe_stat_base_url.rstrip('/')

  async def get_prefix(self: Self, address: str) -> RipeStatAddressPrefixDto:
    normalized_address: str = str(ip_address(address))

    response: Response = await self.__client.get(
      url=f'{self.__base_url}/data/network-info/data.json',
      params={'resource': normalized_address},
      headers={'Accept': 'application/json'}
    )

    payload: Dict[str, Any] = self.__get_payload(response=response)

    if not response.is_success or payload.get('status') != 'ok':
      message: str = str(payload.get('message', response.reason_phrase))
      raise RipeStatClientError(
        f'RIPEstat network-info error for {normalized_address}: '
        f'{message} (HTTP {response.status_code})'
      )

    data: Any = payload.get('data')

    if not isinstance(data, dict):
      raise RipeStatClientError(
        f'RIPEstat network-info returned invalid data for {normalized_address}'
      )

    prefix: Any = data.get('prefix')

    if prefix is not None and not isinstance(prefix, str):
      raise RipeStatClientError(
        f'RIPEstat network-info returned invalid prefix for {normalized_address}'
      )

    return RipeStatAddressPrefixDto(
      address=normalized_address,
      prefix=prefix
    )

  @staticmethod
  def __get_payload(response: Response) -> Dict[str, Any]:
    try:
      payload: Any = response.json()
    except ValueError as err:
      raise RipeStatClientError(
        f'RIPEstat returned invalid JSON (HTTP {response.status_code})'
      ) from err

    if not isinstance(payload, dict):
      raise RipeStatClientError(
        f'RIPEstat returned JSON instead of object (HTTP {response.status_code})'
      )

    return payload
