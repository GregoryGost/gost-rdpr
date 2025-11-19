from fastapi import status
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from typing import Self
from httpx import HTTPStatusError

from logger.logger import logger

from server.tags_metadata import TagsMetadata

from models.http.base import ErrorResp

class BaseRouter:

  tags: TagsMetadata = TagsMetadata()
  
  def __init__(self: Self):
    pass

  @classmethod
  def errorResp(cls: type[Self], err: Exception) -> JSONResponse:
    if isinstance(err, HTTPStatusError):
      response_status_code: int = err.response.status_code
      response_content: str = err.response.content.decode('utf-8')
      error: ErrorResp = ErrorResp(error=f'{response_content}')
      logger.error(f'Fast API httpx error: [{err.__class__.__name__}] : STATUS_CODE[{response_status_code}] {response_content}')
      return JSONResponse(content=error.model_dump(mode='json', exclude_none=True), status_code=response_status_code)
    elif isinstance(err, HTTPException):
      error: ErrorResp = ErrorResp(error=f'{err.detail}')
      logger.error(f'Fast API http error: [{err.__class__.__name__}] : STATUS_CODE[{err.status_code}] {err.detail}')
      return JSONResponse(content=error.model_dump(mode='json', exclude_none=True), status_code=err.status_code)
    logger.error(f'Fast API not category error: [{err.__class__.__name__}] : {err}', exc_info=True)
    error: ErrorResp = ErrorResp(error=f'{err}')
    return JSONResponse(content=error.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
