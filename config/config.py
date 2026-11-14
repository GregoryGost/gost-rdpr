from ipaddress import IPv4Network, IPv6Network, ip_network
from os import getcwd
from os.path import join, normpath
from pathlib import Path
from re import IGNORECASE, Pattern, compile, escape, sub
from typing import Any, Self

from dotenv import load_dotenv
from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from toml import load


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
    default="""The utility provides parsing of domain names into IP addresses, processing of domain lists and their
    subsequent parsing, processing of individual IP addresses and summarized IP groups. Updates firewall address list
    and routing table"""
  )
  app_debug: bool = Field(default=False)
  app_host: str = Field(default='0.0.0.0')  # noqa: S104 - The container API must bind its published interfaces.
  app_port: int = Field(default=4000)
  app_log_level: str = Field(default='error')
  # Queue section
  queue_max_size: int = Field(default=10000, gt=0)
  queue_get_timeout: float = Field(default=0.1)
  queue_sleep_timeout: float = Field(default=0.01)
  # Maximum intermediate completion messages per nonempty NEW/STALE pass; initial and final logs are separate.
  resolve_domains_log_every: int = Field(default=10, ge=3)
  # DB section
  db_log_level: str = Field(default='error')
  db_timeout: float = Field(default=30.0)  # default in lib sqlite3 = 5.0
  db_base_dir: str = Field(default='db')
  db_file_name: str = Field(default='rdpr-db.sqlite')
  db_table_prefix: str = Field(default='rdpr_')
  db_save_batch_size: int = Field(default=1000)  # for while task save to db
  db_save_batch_timeout: float = Field(default=0.1)  # Flush partial batches after this many idle seconds.
  db_shutdown_timeout: float = Field(default=20.0, gt=0)
  db_pool_size: int = Field(default=5)
  db_pool_recycle: int = Field(default=1500)
  db_pool_timeout: int = Field(default=30)
  db_pool_size_overflow: int = Field(default=0)  # max 3+2=5
  db_tune_journal_mode: str = Field(default='WAL')  # Write-Ahead Logging - better concurrent access
  # Checkpoint approximately every 1000 WAL pages; tune for WAL growth and checkpoint latency.
  db_tune_wal_autocheckpoint: int = Field(default=1000)
  # NORMAL balances performance and reliability; FULL provides stronger durability with more I/O.
  db_tune_synchronous: str = Field(default='NORMAL')
  # Milliseconds to retry acquiring a lock before reporting a locked database; SQLite defaults to zero.
  db_tune_busy_timeout: int = Field(default=2000)
  db_tune_temp_store: str = Field(default='FILE')
  db_tune_mmap_size: int = Field(default=0)
  db_tune_cache_size: int = Field(default=-2048)
  # HTTP client Requests section
  attempts_limit: int = Field(default=5)  # Files download attempts limit
  httpx_log_level: str = Field(default='error')
  # HTTP client Requests section
  req_connection_retries: int = Field(default=3, ge=0)
  req_retry_backoff_factor: float = Field(default=0.25, ge=0, allow_inf_nan=False)
  req_retry_backoff_jitter: float = Field(default=1.0, ge=0, le=1, allow_inf_nan=False)
  req_retry_max_backoff_wait: float = Field(default=2.0, gt=0, allow_inf_nan=False)
  req_retry_total_timeout: float = Field(default=5.0, gt=0, allow_inf_nan=False)
  req_timeout_default: float = Field(default=20.0, gt=0, allow_inf_nan=False)
  req_timeout_connect: float = Field(default=20.0, gt=0, allow_inf_nan=False)
  req_timeout_read: float = Field(default=30.0, gt=0, allow_inf_nan=False)
  req_timeout_write: float | None = Field(default=None, gt=0, allow_inf_nan=False)
  req_timeout_pool: float | None = Field(default=None, gt=0, allow_inf_nan=False)
  req_max_connections: int = Field(default=32, gt=0)
  req_max_keepalive_connections: int = Field(default=32, ge=0)
  req_ssl_verify: bool = Field(default=True)
  # DNS and DoH operation budgets include resource admission and response reads.
  dns_timeout: float = Field(default=2.0, gt=0, allow_inf_nan=False)
  dns_lifetime: float = Field(default=5.0, gt=0, allow_inf_nan=False)
  dns_operation_timeout: float = Field(default=10.0, gt=0, allow_inf_nan=False)
  doh_timeout_connect: float = Field(default=3.0, gt=0, allow_inf_nan=False)
  doh_timeout_read: float = Field(default=5.0, gt=0, allow_inf_nan=False)
  doh_timeout_write: float = Field(default=3.0, gt=0, allow_inf_nan=False)
  doh_timeout_pool: float = Field(default=2.0, gt=0, allow_inf_nan=False)
  doh_connection_retries: int = Field(default=1, ge=0)
  doh_retry_total_timeout: float = Field(default=1.0, gt=0, allow_inf_nan=False)
  doh_operation_timeout: float = Field(default=10.0, gt=0, allow_inf_nan=False)
  # Requests, Response models section
  req_default_limit: int = Field(default=100)
  # Domains section
  domains_filtered_min_len: int = Field(default=3)
  domains_update_interval: int = Field(default=172800)  # default 2 days
  domains_resolve_new_batch_size: int = Field(default=500)
  domains_resolve_stale_batch_size: int = Field(default=2000)
  domains_resolve_worker_limit: int = Field(default=32, gt=0)
  domains_resolve_semaphore_limit: int = Field(default=64, gt=0)
  domains_black_list: str = Field(default='')
  # Lists section
  lists_update_interval_sec: int = Field(default=604800)  # default 7 days
  # IP address section
  ip_not_allowed: str = Field(
    default=(
      '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, '
      '169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, '
      '192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, '
      '198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, '
      '240.0.0.0/4, ::/128, ::1/128, fc00::/7, fe80::/10, '
      'ff00::/8, 2001:db8::/32'
    )
  )
  # ROUTEROS section
  ros_rest_api_read_timeout: float = Field(
    default=59.0, gt=0, allow_inf_nan=False
  )  # ROS REST API server read timeout = 60s
  ros_rest_api_default_timeout: float = Field(
    default=59.0, gt=0, allow_inf_nan=False
  )  # ROS REST API server base default timeout = 60s
  ros_rest_api_write_timeout: float | None = Field(default=None, gt=0, allow_inf_nan=False)
  ros_rest_api_pool_timeout: float | None = Field(default=None, gt=0, allow_inf_nan=False)
  # RIPE
  ripe_stat_base_url: str = Field(default='https://stat.ripe.net')
  ripe_stat_requests_semaphore_limit: int = Field(default=16, gt=0)
  ripe_stat_timeout_connect: float = Field(default=3.0, gt=0, allow_inf_nan=False)
  ripe_stat_timeout_read: float = Field(default=5.0, gt=0, allow_inf_nan=False)
  ripe_stat_timeout_write: float = Field(default=3.0, gt=0, allow_inf_nan=False)
  ripe_stat_timeout_pool: float = Field(default=2.0, gt=0, allow_inf_nan=False)
  ripe_stat_connection_retries: int = Field(default=1, ge=0)
  ripe_stat_retry_total_timeout: float = Field(default=1.0, gt=0, allow_inf_nan=False)
  ripe_stat_operation_timeout: float = Field(default=10.0, gt=0, allow_inf_nan=False)
  ripe_stat_cache_size: int = Field(default=10000)
  ripe_stat_prefix_cache_ttl_sec: int = Field(default=28800)
  ripe_stat_empty_prefix_cache_ttl_sec: int = Field(default=3600)
  ripe_stat_cache_lock_ttl_sec: int = Field(default=120)

  @computed_field
  @property
  def app_version(self: Self) -> str:
    version: str = 'unknown'
    pyproject_toml_file = Path(join(self.root_path, 'pyproject.toml'))
    if pyproject_toml_file.exists() and pyproject_toml_file.is_file():
      data: dict[str, Any] = load(pyproject_toml_file)
      if 'project' in data and 'version' in data['project']:
        version = data['project']['version']
    return version

  @computed_field
  @property
  def ip_not_allowed_list(self: Self) -> list[str]:
    return [value.strip() for value in self.ip_not_allowed.split(',') if value.strip()]

  @property
  def ip_not_allowed_networks(self: Self) -> list[IPv4Network | IPv6Network]:
    return [ip_network(value, strict=False) for value in self.ip_not_allowed_list]

  @computed_field
  @property
  def domains_not_allowed_pattern(self: Self) -> Pattern[str] | None:
    if len(self.domains_black_list) < 1:
      return None
    domains: list[str] = self.domains_black_list.split(',')
    escaped_domains: list[str] = [escape(domain) for domain in domains]
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
