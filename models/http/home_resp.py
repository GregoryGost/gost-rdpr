from pydantic import Field
from typing import Annotated, List

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

class ConfigStatic(Base):
  root_path: str
  root_log_level: str
  # FastAPI HTTP (APP) section
  app_title: str
  app_summary: str
  app_description: str
  app_debug: bool
  app_version: str
  app_host: str
  app_port: int
  app_log_level: str
  # Queue section
  queue_max_size: int
  queue_get_timeout: float
  queue_sleep_timeout: float
  # DB section
  db_log_level: str
  db_timeout: float
  # db_pool_size: int
  # db_pool_size_overflow: int
  # db_pool_recycle_sec: int
  db_base_dir: str
  db_file_name: str
  db_table_prefix: str
  db_save_batch_size: int
  db_save_batch_timeout: float
  attempts_limit: int
  # HTTP client Requests section
  req_connection_retries: int
  req_timeout_default: float
  req_timeout_connect: float
  req_timeout_read: float
  req_max_connections: int
  req_max_keepalive_connections: int
  req_ssl_verify: bool
  # Requests, Response models section
  req_default_limit: int
  # Domains section
  domains_filtered_min_len: int
  domains_update_interval: int
  # domains_one_job_resolve_limit: int
  domain_resolve_semaphore_limit: int
  domains_black_list: str
  # Lists section
  lists_update_interval_sec: int
  # IP address section
  ip_not_allowed: str
  # ROUTEROS section
  ros_rest_api_read_timeout: float

class ConfigDynamic(Base):
  ip_not_allowed_list: List[str]
  app_title_metrics: str
  db_path: str
  db_connection: str

class ConfigResp(Base):
  static: ConfigStatic
  dynamic: ConfigDynamic
