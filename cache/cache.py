from cashews import cache
from cashews.backends.interface import Backend
from enum import StrEnum
from typing import Any, Self

from logger.logger import logger

class Jobs(StrEnum):
  LISTS_LOAD      = 'lists_load'
  DOMAINS_RESOLVE = 'domains_resolve'
  ROS_UPDATE      = 'ros_update'

class Cache():
  '''
  Async cache framework with simple API to build fast and reliable applications.  
  Doc: https://github.com/Krukov/cashews
  '''

  def __init__(self, prefix: str, size: int | None = None) -> None:
    if size != None:
      mem = f'mem://?size={size}'
    else:
      mem = 'mem://'
    self.cache: Backend = cache.setup(mem, prefix=prefix)
    logger.debug(f'{self.__class__.__name__} init')

  async def update(self, key: str, value: Any, expire: float | None = None) -> None:
    '''
    Update data in cache or add it if it does not exist.
    VALUE: need to be DICTIONARY or SERIALIZEABLE string
    '''
    exists: bool = await self.cache.exists(key)
    if exists:
      await self.cache.delete(key=key)
      await self.cache.set(key=key, value=value, expire=expire)
    else:
      await self.cache.set(key=key, value=value, expire=expire)

  async def get(self: Self, key: str) -> Any | None:
    return await self.cache.get(key)
  
  async def exists(self: Self, key: str) -> bool:
    return await self.cache.exists(key=key)
  
  async def clear(self: Self) -> None:
    await self.cache.clear()

  async def set(self: Self, key: str, value: Any, expire: float | None = None) -> None:
    await self.update(key=key, value=value, expire=expire)

try:
  jobs_cache: Cache = Cache('jobs_cache')
except Exception as err:
  raise err
