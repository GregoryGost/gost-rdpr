from asyncio import CancelledError, Lock, Task, create_task, gather
from collections.abc import Awaitable, Callable
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
  """
  Stores active background jobs in the current application process.
  """

  def __init__(self: Self) -> None:
    self.__active_jobs: set[Jobs] = set()
    self.__lock: Lock = Lock()

  async def try_start(self: Self, job: Jobs) -> bool:
    """
    Atomically reserves a job. Returns False when the job is already active.
    """
    async with self.__lock:
      if job in self.__active_jobs:
        return False
      self.__active_jobs.add(job)
      logger.debug(f'Job {job} started')
      return True

  async def finish(self: Self, job: Jobs) -> None:
    """
    Marks a job as inactive. It is safe to call more than once.
    """
    async with self.__lock:
      self.__active_jobs.discard(job)
      logger.debug(f'Job {job} finished')

  async def is_active(self: Self, job: Jobs) -> bool:
    async with self.__lock:
      return job in self.__active_jobs

  async def reset(self: Self) -> None:
    """
    Clears all in-memory statuses before application startup.
    """
    async with self.__lock:
      self.__active_jobs.clear()
      logger.debug(f'{self.__class__.__name__} reset')


job_registry: JobRegistry = JobRegistry()


class UpdateJobs:
  """Run full stale resolution and RouterOS updates one at a time within the application."""

  def __init__(self) -> None:
    """Keep both slots on the application event loop so admission needs no I/O or lock."""
    # _accepting is enabled by the lifespan after storage and domain workers are ready.
    self._accepting = False
    # _active holds the running kind and its task through workload cleanup.
    self._active: tuple[Jobs, Task[None]] | None = None
    # _pending holds at most one start callback for the other kind.
    self._pending: tuple[Jobs, Callable[[], Awaitable[None]]] | None = None

  def start(self) -> None:
    """Accept update requests after the application has started their dependencies."""
    self._accepting = True

  def is_stopping(self) -> bool:
    """Report whether shutdown has sealed admission and suppressed deferred dispatch."""
    return not self._accepting

  def submit(self, job: Jobs, run: Callable[[], Awaitable[None]]) -> bool:
    """Register a stale or RouterOS callback without waiting for it to run.

    Return False for a kind already running or pending. A pending callback
    starts only after the active callback and its cleanup return.
    """
    if job not in (Jobs.DOMAINS_RESOLVE_STALE, Jobs.ROS_UPDATE):
      raise ValueError(f'Cannot schedule update job {job}')
    if not self._accepting:
      raise RuntimeError('Update jobs are not accepting requests')
    if self._active is None:
      self._start_job(job, run)
    elif job == self._active[0] or self._pending is not None:
      return False
    else:
      self._pending = (job, run)
      logger.info('Update job %s is waiting for %s', job, self._active[0])
    return True

  def _start_job(self, job: Jobs, run: Callable[[], Awaitable[None]]) -> None:
    """Give the selected job the slot before its callback starts on the event loop."""
    # task owns the callback and all work the callback must settle before it returns.
    task = create_task(self._run_job(job, run), name=f'update:{job}', eager_start=False)
    self._active = (job, task)
    task.add_done_callback(self._job_finished)

  @staticmethod
  async def _run_job(job: Jobs, run: Callable[[], Awaitable[None]]) -> None:
    """Run the admitted callback and log its terminal outcome without request data."""
    logger.info('Update job %s started', job)
    try:
      await run()
    except CancelledError:
      logger.info('Update job %s cancelled', job)
      raise
    # error is the callback failure. The log exposes its class without integration data.
    except Exception as error:  # noqa: BLE001 - The background boundary must permit the next job after failure.
      logger.error('Update job %s failed [%s]', job, type(error).__name__)
    else:
      logger.info('Update job %s finished', job)

  def _job_finished(self, task: Task[None]) -> None:
    """Retire the completed task and hand its slot to pending work while accepting."""
    if self._active is None or self._active[1] is not task:
      return
    self._active = None
    if self._accepting and self._pending is not None:
      # pending is the next job and callback. Clear it before starting that job.
      pending = self._pending
      self._pending = None
      self._start_job(*pending)

  async def stop(self) -> None:
    """Close admission, discard deferred callbacks and await the owned task on shutdown."""
    self._accepting = False
    self._pending = None
    if self._active is not None:
      # task is the only callback allowed to use dependencies during this shutdown step.
      task = self._active[1]
      task.cancel()
      await gather(task, return_exceptions=True)


# update_jobs is the lifespan owner shared by the two update command routes.
update_jobs = UpdateJobs()
