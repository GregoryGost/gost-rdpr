from pydantic import Field
from typing import Annotated

from .base import Base

class WelcomeResp(Base):
  version: Annotated[str, Field(title='API Version')]
  message: Annotated[str, Field(title='Welcome message')] = 'Welcome to API'
  docs: Annotated[str, Field(title='link to docs')]

class HealthResp(Base):
  status: Annotated[str, Field(title='Application status')] = 'OK'
  ts: Annotated[float, Field(title='Response now timestamp')]
  uptime: Annotated[float, Field(title='Application uptime')]
  db_pool: Annotated[str, Field(title='Database pool status')]
