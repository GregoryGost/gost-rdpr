from os import getcwd
from os.path import normpath, join
from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from toml import load
from dotenv import load_dotenv
from typing import Self, List, Pattern, Dict, Any
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
  app_host: str = Field(default='0.0.0.0')
  app_port: int = Field(default=4000)
  app_log_level: str = Field(default='error')
  # Queue section
  queue_max_size: int = Field(default=1000)
  queue_get_timeout: float = Field(default=0.1)
  queue_sleep_timeout: float = Field(default=0.01)
  resolve_domains_log_every: int = Field(default=10)
  # DB section
  db_log_level: str = Field(default='error')
  db_timeout: float = Field(default=30.0) # default in lib sqlite3 = 5.0
  db_base_dir: str = Field(default='db')
  db_file_name: str = Field(default='rdpr-db.sqlite')
  db_table_prefix: str = Field(default='rdpr_')
  db_save_batch_size: int = Field(default=1000) # for while task save to db
  db_save_batch_timeout: float = Field(default=5.0) # 5 sec // recomend time.monotonic()
  db_pool_size: int = Field(default=5)
  db_pool_recycle: int = Field(default=1500)
  db_pool_timeout: int = Field(default=30)
  db_pool_size_overflow: int = Field(default=0) # max 3+2=5
  db_tune_journal_mode: str = Field(default='WAL') # Write-Ahead Logging - better concurrent access
  db_tune_wal_autocheckpoint: int = Field(default=1000) # Initiate a checkpoint approximately every 1000 WAL pages (choose experimentally: if WAL grows too quickly, decrease it; if checkpoints interfere, increase it)
  db_tune_synchronous: str = Field(default='NORMAL') # NORMAL - A good balance of performance and reliability for most VDS applications. `FULL`` provides maximum reliability, but is more expensive in terms of I/O.
  db_tune_busy_timeout: int = Field(default=2000) # This is the timeout (in milliseconds) during which SQLite will retry acquiring a lock instead of immediately failing with a "database is locked" error. Defaults in SQLite to 0 (no wait).
  db_tune_temp_store: str = Field(default='FILE')
  db_tune_mmap_size: int = Field(default=0)
  db_tune_cache_size: int = Field(default=-2048)
  # HTTP client Requests section
  attempts_limit: int = Field(default=5) # Files download attempts limit
  httpx_log_level: str = Field(default='error')
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
  domains_resolve_new_batch_size: int = Field(default=500)
  domains_resolve_stale_batch_size: int = Field(default=2000)
  domains_resolve_semaphore_limit: int = Field(default=20)
  domains_black_list: str = Field(default='')
  # Lists section
  lists_update_interval_sec: int = Field(default=604800) # default 7 days
  # IP address section
  ip_not_allowed: str = Field(default='127.0.0.1, 0.0.0.0, 0.0.0.0/0, ::, ::/0')
  # ROUTEROS section
  ros_rest_api_read_timeout: float = Field(default=59.0) # ROS REST API server read timeout = 60s
  ros_rest_api_default_timeout: float = Field(default=59.0) # ROS REST API server base default timeout = 60s
  # RIPE
  ripe_stat_base_url: str = Field(default='https://stat.ripe.net')
  ripe_stat_requests_semaphore_limit: int = Field(default=5)

  @computed_field
  @property
  def app_version(self: Self) -> str:
    version: str = 'unknown'
    pyproject_toml_file = Path(join(self.root_path, 'pyproject.toml'))
    if pyproject_toml_file.exists() and pyproject_toml_file.is_file():
      data: Dict[str, Any] = load(pyproject_toml_file)
      if 'project' in data and 'version' in data['project']:
        version = data['project']['version']
    return version

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
  def db_path(self: Self) -> str:
    return join(self.db_base_dir, self.db_file_name)

  @computed_field
  @property
  def db_connection(self: Self) -> str:
    return f'sqlite+aiosqlite:///{self.db_path}'

try:
  load_dotenv()
  settings = Settings()
except Exception as err:
  raise err
