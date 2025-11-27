#!/usr/bin/python3
# -- coding: utf-8 --

from uvicorn import run
from fastapi import FastAPI
from server.server import AppServer
from logger.logger import logger
from config.config import settings

########################################################################################################################
# APP RUN
########################################################################################################################

app: FastAPI = AppServer().build()

if __name__ == '__main__':
  logger.info(f'Application start ...')
  run(app=app, log_level=settings.app_log_level, server_header=False)
