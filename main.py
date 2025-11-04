#!/usr/bin/python3
# -- coding: utf-8 --

import asyncio
from server.server import AppServer
from logger.logger import logger

########################################################################################################################
# APP RUN
########################################################################################################################

if __name__ == '__main__':
  logger.info(f'Application run')
  asyncio.run(AppServer().run())
