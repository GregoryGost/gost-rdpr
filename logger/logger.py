import logging
from logging import RootLogger, Formatter, StreamHandler

from config.config import settings

from metrics.logger_metrics import ConsoleHandler

class Logger:

  LOGGER_LEVEL: dict[str, int] = {
    'debug': logging.DEBUG,
    'error': logging.ERROR,
    'warn': logging.WARN,
    'info': logging.INFO
  }

  def __init__(self):
    self.format: Formatter = Formatter(
      fmt='[%(asctime)s.%(msecs)03d] [%(thread)s] %(levelname)s : %(message)s',
      datefmt='%Y-%m-%d %H:%M:%S'
    )
    self.stream_handler: StreamHandler = ConsoleHandler()
    self.logger: RootLogger = logging.root
    self.setup_logger()
    self.debug('Logger init - OK')

  def setup_logger(self) -> None:
    #
    self.logger.setLevel(self.LOGGER_LEVEL[settings.root_log_level])
    #
    self.stream_handler.setFormatter(self.format)
    self.stream_handler.setLevel(self.LOGGER_LEVEL[settings.root_log_level])
    self.logger.addHandler(self.stream_handler)

  def debug(self, msg, *args, **kwargs) -> None:
    self.logger.debug(msg, *args, **kwargs)

  def info(self, msg, *args, **kwargs) -> None:
    self.logger.info(msg, *args, **kwargs)

  def warning(self, msg, *args, **kwargs) -> None:
    self.logger.warning(msg, *args, **kwargs)

  def error(self, msg, *args, **kwargs) -> None:
    self.logger.error(msg, *args, **kwargs)

try:
  logger = Logger()
except Exception as err:
  raise err
