from os import getcwd
from os.path import normpath, join
from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
from typing import Self, List, Pattern
from re import sub, escape, compile, IGNORECASE

class Settings(BaseSettings):
  model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8')
  # Main section
  root_path: str = Field(default_factory=lambda: normpath(getcwd()))
  root_log_level: str = Field(default='error')
  # FastAPI HTTP (APP) section
  app_title: str = Field(default='GOST-RDPR (Resolve Domains Per Records)')
  app_summary: str = Field(
    default='A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses'
  )
  app_description: str = Field(
    default='''The utility provides parsing of domain names into IP addresses, processing of domain lists and their 
    subsequent parsing, processing of individual IP addresses and summarized IP groups. Updates firewall address list 
    and routing table'''
  )
  app_debug: bool = Field(default=False)
  app_version: str = Field(default='2.0.9')
  app_host: str = Field(default='0.0.0.0')
  app_port: int = Field(default=4000)
  app_log_level: str = Field(default='error')
  app_workers: int = Field(default=0)
  # Queue section
  queue_max_size: int = Field(default=1000)
  queue_get_timeout: float = Field(default=0.1)
  queue_sleep_timeout: float = Field(default=0.01)
  # DB section
  db_log_level: str = Field(default='error')
  db_timeout: float = Field(default=30.0) # default in lib sqlite3 = 5.0
  db_dir: str | None = Field(default=None)
  db_file_name: str = Field(default='rdpr-db.sqlite')
  db_table_prefix: str = Field(default='rdpr_')
  db_save_batch_size: int = Field(default=1000) # for while task save to db
  db_save_batch_timeout: float = Field(default=5.0) # 5 sec // recomend time.monotonic()
  attempts_limit: int = Field(default=5) # files download attempts limit
  # HTTP client Requests section
  req_connection_retries: int = Field(default=3)
  req_timeout_default: float = Field(default=20.0)
  req_timeout_connect: float = Field(default=20.0)
  req_timeout_read: float = Field(default=30.0)
  req_max_connections: int = Field(default=5)
  req_max_keepalive_connections: int = Field(default=30)
  req_ssl_verify: bool = Field(default=True)
  # Requests, Response models section
  req_default_limit: int = Field(default=100)
  # Domains section
  domains_filtered_min_len: int = Field(default=3)
  domains_update_interval: int = Field(default=172800) # default 2 days
  domain_resolve_semaphore_limit: int = Field(default=60)
  domains_black_list: str = Field(default='')
  # Lists section
  lists_update_interval_sec: int = Field(default=604800) # default 7 days
  # IP address section
  ip_not_allowed: str = Field(default='127.0.0.1, 0.0.0.0, 0.0.0.0/0, ::, ::/0')
  # ROUTEROS section
  ros_rest_api_read_timeout: float = Field(default=59.0) # ROS REST API server timeout = 60s

  @computed_field
  @property
  def ip_not_allowed_list(self: Self) -> List[str]:
    return self.ip_not_allowed.split(',')

  @computed_field
  @property
  def domains_not_allowed_pattern(self: Self) -> Pattern[str] | None:
    if len(self.domains_black_list) < 1: return None
    domains: List[str] = self.domains_black_list.split(',')
    escaped_domains: List[str] = [escape(domain) for domain in domains]
    pattern: str = r'\b(?:' + '|'.join(escaped_domains) + r')\b'
    return compile(pattern=pattern, flags=IGNORECASE)

  @computed_field
  @property
  def app_title_metrics(self: Self) -> str:
    app_title_slug: str = sub(r'[^a-z0-9]+', '-', self.app_title.lower()).strip('-')
    return app_title_slug
  
  @computed_field
  @property
  def db_path_dir(self: Self) -> str:
    if self.db_dir != None and self.db_dir != '':
      return self.db_dir
    return join(self.root_path, 'db')

  @computed_field
  @property
  def db_file_path(self: Self) -> str:
    return join(self.db_path_dir, self.db_file_name)

  @computed_field
  @property
  def db_connection(self: Self) -> str:
    # :/// - relative path
    # ://// - absolute path
    return f'sqlite+aiosqlite:///{self.db_file_path}'

try:
  load_dotenv()
  settings = Settings()
except Exception as err:
  raise err
