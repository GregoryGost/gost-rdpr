#!/usr/bin/env python3

import asyncio

from logger.logger import logger
from server.server import AppServer

########################################################################################################################
# APP RUN
########################################################################################################################

if __name__ == '__main__':
  logger.info('Application run')
  asyncio.run(AppServer().run())
