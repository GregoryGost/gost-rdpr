from logging import StreamHandler, LogRecord
from prometheus_client import Counter
from typing import Self

from config.config import settings

class ConsoleHandler(StreamHandler):

  app_name: str = settings.app_title_metrics

  logger_counter: Counter = Counter(
    name='logger_total',
    documentation='Total count of logging',
    labelnames=['levelname', 'levelno', 'app_name']
  )
  '''LOGGER'''

  def emit(self: Self, record: LogRecord):
    try:
      self.logger_counter.labels(levelname=record.levelname, levelno=record.levelno, app_name=self.app_name).inc()
      msg: str = self.format(record)
      stream = self.stream
      # issue 35046: merged two stream.writes into one.
      stream.write(msg + self.terminator)
      self.flush()
    except RecursionError:  # See issue 36272
      raise
    except Exception:
      self.handleError(record)
