from httpx import Response, AsyncClient
from hashlib import sha256
from re import compile
from typing import Pattern, Self, List, Tuple, Set

from .http_base_client import HttpClient

from logger.logger import logger

from models.dto.domains_lists_dto import DomainsListDto
from models.dto.ips_lists_dto import IpsListDto

class FileLoaderClient:

  __ips_pattern: Pattern[str] = compile(r'(\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/([0-9]|[1-2][0-9]|3[0-2]))?\b)|(\b(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){1,5}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,2}|::([0-9a-fA-F]{1,4}:){1,3}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,2}|::([0-9a-fA-F]{1,4}:){1,2}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){1,1}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}:[0-9a-fA-F]{1,4}|::[0-9a-fA-F]{1,4}|::(:[0-9a-fA-F]{1,4}){1,7})(/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?\b)')
  __domains_pattern: Pattern[str] = compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}(?:[a-zA-Z]{2,6}|xn--[a-z0-9]+)')
  __client: AsyncClient = HttpClient.get_client('file_loader')

  def __init__(self: Self):
    logger.debug(f'{self.__class__.__name__} init ...')

  async def get_domains_from_lists(self: Self, lists: List[DomainsListDto]) -> None:
    logger.debug(f'Try download domains lists: {lists=} ...')
    try:
      for file in lists:
        found_elements: Set[str] = set()
        hasher = sha256()
        try:
          # checking if a file exists without downloading its contents
          head_response: Response = await self.__client.head(url=file.url)
          if not head_response.is_success:
            # If the file does not exist, update attempts: + 1
            file.attempts = file.attempts + 1
            continue
          #
          async with self.__client.stream(method='GET', url=file.url) as response:
            response.raise_for_status()
            #
            async for line in response.aiter_lines():
              line_bytes: bytes = line.encode('utf-8', errors='ignore')
              hasher.update(line_bytes)
              hasher.update(b'\n')
              #
              found_domains: list[str] = self.__domains_pattern.findall(line)
              found_elements.update(found_domains)
          hash: str = hasher.hexdigest().upper()
          if hash == file.hash:
            continue
          if len(found_elements) == 0:
            file.found_elements = None
            continue
          file.hash = hash
          file.found_elements = found_elements
          logger.debug(f'Domains count in file "{file.name}" found_elements count={len(found_elements)} found_elements {hash=}')
        except Exception as err:
          logger.error(f'Download domains lists file "{file.name}" error: [{err.__class__.__name__}] {err}')
          continue
      logger.debug(f'Result domains lists: {lists=}')
    except Exception as err:
      logger.error(f'Download domains lists error: [{err.__class__.__name__}] {err}')
      raise err
    
  async def get_ips_from_lists(self: Self, lists: List[IpsListDto]) -> None:
    logger.debug(f'Try download ips lists: {lists=} ...')
    try:
      for file in lists:
        found_elements: Set[str] = set()
        hasher = sha256()
        try:
          # checking if a file exists without downloading its contents
          head_response: Response = await self.__client.head(url=file.url)
          if not head_response.is_success:
            # If the file does not exist, update attempts: + 1
            file.attempts = file.attempts + 1
            continue
          async with self.__client.stream(method='GET', url=file.url) as response:
            response.raise_for_status()
            #
            async for line in response.aiter_lines():
              line_bytes: bytes = line.encode('utf-8', errors='ignore')
              hasher.update(line_bytes)
              hasher.update(b'\n')
              #
              found_ips: List[Tuple[str, str]] = [(element[0], element[6]) for element in self.__ips_pattern.findall(line)]
              found_elements.update([entry[0] for entry in found_ips if entry[0] != None and entry[0] != '']) #ipv4
              found_elements.update([entry[1] for entry in found_ips if entry[1] != None and entry[1] != '']) #ipv6
          hash: str = hasher.hexdigest().upper()
          if hash == file.hash:
            continue
          if len(found_elements) == 0:
            file.found_elements = None
            continue
          file.hash = hash
          file.found_elements = found_elements
          logger.debug(f'Ips address count in file "{file.name}" found_elements count={len(found_elements)} found_elements {hash=}')
        except Exception as err:
          logger.error(f'Download ips lists file "{file.name}" error: [{err.__class__.__name__}] {err}')
          continue
      logger.debug(f'Result ips lists: {lists=}')
    except Exception as err:
      logger.error(f'Download ips lists error: [{err.__class__.__name__}] {err}')
      raise err
