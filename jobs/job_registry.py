from asyncio import Lock
from enum import StrEnum
from typing import Self

from logger.logger import logger


class Jobs(StrEnum):
  LISTS_LOAD = 'lists_load'
  DOMAINS_RESOLVE = 'domains_resolve'
  DOMAINS_RESOLVE_NEW = 'domains_resolve_new'
  DOMAINS_RESOLVE_STALE = 'domains_resolve_stale'
  ROS_UPDATE = 'ros_update'


class JobRegistry:
  '''
  Stores active background jobs in the current application process.
  '''

  def __init__(self: Self) -> None:
    self.__active_jobs: set[Jobs] = set()
    self.__lock: Lock = Lock()

  async def try_start(self: Self, job: Jobs) -> bool:
    '''
    Atomically reserves a job. Returns False when the job is already active.
    '''
    async with self.__lock:
      if job in self.__active_jobs:
        return False
      self.__active_jobs.add(job)
      logger.debug(f'Job {job} started')
      return True

  async def finish(self: Self, job: Jobs) -> None:
    '''
    Marks a job as inactive. It is safe to call more than once.
    '''
    async with self.__lock:
      self.__active_jobs.discard(job)
      logger.debug(f'Job {job} finished')

  async def is_active(self: Self, job: Jobs) -> bool:
    async with self.__lock:
      return job in self.__active_jobs

  async def reset(self: Self) -> None:
    '''
    Clears all in-memory statuses before application startup.
    '''
    async with self.__lock:
      self.__active_jobs.clear()
      logger.debug(f'{self.__class__.__name__} reset')


job_registry: JobRegistry = JobRegistry()
