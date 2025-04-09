import os
import time
import base64
import logging
import requests
import urllib3
import re
import asyncio
import uvicorn
import sqlite3 as db
import traceback
from datetime import datetime
from dns.resolver import Resolver
from dns.exception import DNSException
from dns.message import QueryMessage, make_query, from_wire
from dns.rrset import RRset
from dns.rdatatype import RdataType, A, AAAA, CNAME
from dns.rdata import Rdata
from librouteros import connect as rosConnect
from librouteros.login import plain
from librouteros.api import Api, ReplyDict
from librouteros.query import Key
from itertools import chain
from typing import Any, Annotated
from fastapi import FastAPI, BackgroundTasks, status, Query, Path, Body, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from prometheus_fastapi_instrumentator import Instrumentator
from contextlib import asynccontextmanager
from threading import Thread, current_thread
from queue import Queue, Empty
from multiprocessing.pool import ThreadPool
from itertools import product
from urllib.parse import unquote

########################################################################################################################
# IMPORT HELPER FUNCTIONS
########################################################################################################################

from utils import getDefCpus, getTimestamp, getIpVersion, getHash, getIpWithoutPrefix

########################################################################################################################
# MODELS AND TYPES
########################################################################################################################

from models import ErrorResp, NoDataResp, NotFoundResp, OkStatusResp, HealthResp, LimitOffsetQuery
from models import DnsQuery, DnsPostElement, DnsPayloadResp, DnsElementResp, DnsPostElementResp
from models import DomainsQuery, DomainElementResp, DomainsPayloadResp, DomainsPostElement, DomainsPostElementResp, DomainDeleteResp
from models import IpsQuery, IpsPayloadResp, IpsElementResp, IpsPostElementResp, IpsDeleteQuery, IpsDeleteResp
from models import RosConfigPayloadResp, RosConfigElementResp, RosConfigConnElementResp, RosConnectResult, RosConfigsPostElement, RosConfigsPostElementResp
from models import DomainsListsPayloadResp, DomainsListsElementResp, DomainsListsPostElement, DomainsListsPostElementResp
from models import JobsLimitOffsetQuery, JobsPayloadResp, JobsElementResp
from models import CommandStatusResp, RoSCommandQuery, DomainListsCommandQuery
from models import IpAddrListsPayloadResp, IpAddrListsElementResp, IpAddrListsPostElementResp, IpAddrListsPostElement, IpAddrListsCommandQuery

from rdtypes import DomainResult

########################################################################################################################
# LOCAL VARIABLES
########################################################################################################################

DEF_PORT = 4000
DEF_HOST = '0.0.0.0'
DEF_LOG_LEVEL = 'error' # error
DEF_DOMAINS_UPDATE_INTERVAL = 172800 # 2 days
DEF_RESOLVE_DOMAINS_BATCH_SIZE = 50
DEF_DB_FLUSH_BATCH_SIZE = 1000
DEF_THREADS_COUNT = getDefCpus() # getDefCpus()
DEF_QUEUE_SIZE = 100
DEF_RESOLVE_EMPTY_ITER = 100
DEF_DB_EMPTY_ITER = DEF_RESOLVE_EMPTY_ITER + 50

SQLITE_FILE = 'rdpr-db.sqlite'
SQLITE_BASE_DIR = 'db'
SQLITE_DB = os.path.join(SQLITE_BASE_DIR, SQLITE_FILE)
ROS_CONFIG_TABLE_NAME = 'ros_configs'
DNS_SERVERS_TABLE_NAME = 'dns_servers'
DOMAINS_TABLE_NAME = 'domains'
DOMAINS_LISTS_TABLE_NAME = 'domains_lists'
IP_RECORDS_TABLE_NAME = 'ip_records'
IPS_LISTS_TABLE_NAME = 'ip_lists'
JOB_TABLE_NAME = 'jobs'
#
JOBNAME_RESOLVE_DOMAINS = 'resolveDomains'
JOBNAME_IP_ADDR_LISTS_LOAD = 'ipAddrListsLoad'
JOBNAME_DOMAINS_LISTS_LOAD = 'domainsListsLoad'
JOBNAME_ROUTEROS_UPDATE = 'routerOsUpdate'
#
REQ_TIMEOUT = (20, 30)
DB_TIMEOUT = 30.0 # default in lib sqlite3 = 5.0
ROS_TIMEOUT = 30
SSL_CHECK_ENABLE = True
HEADERS = {
  'Accept': '*/*',
  'User-Agent': 'GOST-RDPR (python)'
}
IP_NOT_ALLOWED = ['127.0.0.1', '0.0.0.0', '0.0.0.0/0', '::', '::/0']
DOMAIN_PATTERN = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}(?:[a-zA-Z]{2,6}|xn--[a-z0-9]+)')
IP_ALL_PATTERN = re.compile(r'(\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/([0-9]|[1-2][0-9]|3[0-2]))?\b)|(\b(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){1,5}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,2}|::([0-9a-fA-F]{1,4}:){1,3}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,2}|::([0-9a-fA-F]{1,4}:){1,2}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){1,1}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}:[0-9a-fA-F]{1,4}|::[0-9a-fA-F]{1,4}|::(:[0-9a-fA-F]{1,4}){1,7})(/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?\b)')
#
DNS_SERVERS_TAG = 'DNS Servers'
DOMAINS_TAG = 'Domains'
IPS_TAG = 'IP address'
ROS_CONFIGS_TAG = 'RoS Configs'
DOMAINS_LISTS_TAG = 'Domains Lists'
IPS_LISTS_TAG = 'IP Address Lists'
COMMANDS_TAG = 'Commands'
JOBS_TAG = 'Jobs'
#
LOGGER_LEVEL = {
  'trace': logging.DEBUG,
  'debug': logging.DEBUG,
  'error': logging.ERROR,
  'warn': logging.WARN,
  'info': logging.INFO
}

########################################################################################################################
# ENVIRONMENTS
########################################################################################################################

IS_PRODUCTION = False if os.environ.get('IS_PRODUCTION') != None and os.environ.get('IS_PRODUCTION') == 'False' else True
HOST = str(os.environ.get('HOST')) if os.environ.get('HOST') != None and os.environ.get('HOST') != '' else DEF_HOST
PORT = int(os.environ['PORT']) if os.environ.get('PORT') != None and os.environ.get('PORT') != '' else DEF_PORT
LOG_LEVEL = str(os.environ.get('LOG_LEVEL')) if os.environ.get('LOG_LEVEL') != None and os.environ.get('LOG_LEVEL') != '' else DEF_LOG_LEVEL
DOMAINS_UPDATE_INTERVAL = int(os.environ['DOMAINS_UPDATE_INTERVAL']) if os.environ.get('DOMAINS_UPDATE_INTERVAL') != None and os.environ.get('DOMAINS_UPDATE_INTERVAL') != '' else DEF_DOMAINS_UPDATE_INTERVAL
DB_FLUSH_BATCH_SIZE = int(os.environ['DB_FLUSH_BATCH_SIZE']) if os.environ.get('DB_FLUSH_BATCH_SIZE') != None and os.environ.get('DB_FLUSH_BATCH_SIZE') != '' else DEF_DB_FLUSH_BATCH_SIZE
THREADS_COUNT = int(os.environ['THREADS_COUNT']) if os.environ.get('THREADS_COUNT') != None and os.environ.get('THREADS_COUNT') != '' else DEF_THREADS_COUNT
QUEUE_SIZE = int(os.environ['QUEUE_SIZE']) if os.environ.get('QUEUE_SIZE') != None and os.environ.get('QUEUE_SIZE') != '' else DEF_QUEUE_SIZE
RESOLVE_DOMAINS_BATCH_SIZE = int(os.environ['RESOLVE_DOMAINS_BATCH_SIZE']) if os.environ.get('RESOLVE_DOMAINS_BATCH_SIZE') != None and os.environ.get('RESOLVE_DOMAINS_BATCH_SIZE') != '' else DEF_RESOLVE_DOMAINS_BATCH_SIZE
DB_EMPTY_ITER = int(os.environ['DB_EMPTY_ITER']) if os.environ.get('DB_EMPTY_ITER') != None and os.environ.get('DB_EMPTY_ITER') != '' else DEF_DB_EMPTY_ITER
RESOLVE_EMPTY_ITER = int(os.environ['RESOLVE_EMPTY_ITER']) if os.environ.get('RESOLVE_EMPTY_ITER') != None and os.environ.get('RESOLVE_EMPTY_ITER') != '' else DEF_RESOLVE_EMPTY_ITER

DEBUG = True if IS_PRODUCTION == False else False

########################################################################################################################
# BASE INIT
########################################################################################################################

if SSL_CHECK_ENABLE == False:
  urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

tagsMetadata = [
  {
    'name': 'Home',
    'description': 'Base method healthcheck'
  },
  {
    'name': DNS_SERVERS_TAG,
    'description': 'Methods for DNS servers. DNS servers will be used to resolve domain names. All available DNS servers are applied per domain'
  },
  {
    'name': DOMAINS_LISTS_TAG,
    'description': 'Methods for managing domain lists. Links to domain lists from which domains will be obtained directly and then their IP addresses'
  },
  {
    'name': DOMAINS_TAG,
    'description': 'Methods for domain names that are then resolved to IP addresses as A(IPv4), AAAA(IPv6), NS, CNAME records'
  },
  {
    'name': IPS_LISTS_TAG,
    'description': 'Methods for managing IP address lists. Links to IP address lists from which the IP addresses themselves will be obtained directly. They can be either just IP addresses or addresses with summarization'
  },
  {
    'name': IPS_TAG,
    'description': 'Methods for managing IP addresses. IP addresses added manually are bound to the base domain with index -1'
  },
  {
    'name': ROS_CONFIGS_TAG,
    'description': 'Methods for managing Router configurations, to which all received IP addresses will be assigned'
  },
  {
    'name': COMMANDS_TAG,
    'description': 'Commands to perform periodic background tasks (downloading lists, resolving domains, etc.)'
  },
  {
    'name': JOBS_TAG,
    'description': 'Information on background tasks'
  }
]

logging.basicConfig(
  level=logging.ERROR,
  format='[%(asctime)s.%(msecs)03d] %(levelname)s : %(message)s',
  datefmt='%Y-%m-%d %H:%M:%S'
)
logging.getLogger('requests').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(LOGGER_LEVEL[LOG_LEVEL])

startTime = time.time()
cpus = os.cpu_count()

# Startup Lifespan (event)
@asynccontextmanager
async def lifespan_handle(app: FastAPI):
  instrumentator.expose(app, endpoint='/monitoring', include_in_schema=False)
  yield

app = FastAPI(
  title='GOST RDPR (Resolve Domain Parser)',
  summary='A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses',
  description='The utility provides parsing of domain names into IP addresses, processing of domain lists and their subsequent parsing, processing of individual IP addresses and summarized IP groups. Updates firewall address list and routing table',
  debug=DEBUG,
  version='1.0.0',
  docs_url='/docs',
  openapi_url='/docs/openapi.json',
  openapi_tags=tagsMetadata,
  lifespan=lifespan_handle
)
instrumentator = Instrumentator().instrument(app)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(req: Request, exc: RequestValidationError) -> JSONResponse:
  body = await req.body()
  bodyStr = body.decode('utf-8')
  bodyStr = re.sub(r'\s+', ' ', bodyStr).strip()
  logger.error(f'RequestValidationError={str(exc)} : URL={unquote(req.url.__str__())} : Request={bodyStr}')
  return JSONResponse(content=jsonable_encoder(exc.errors()), status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

########################################################################################################################
# APP HELPER FUNCTIONS
########################################################################################################################

# Check ip Allow
def checkIpAllow(ip: str):
  if ip in IP_NOT_ALLOWED:
    return False
  else:
    return True

# ERROR function for @app methods
def errorResp(err: Exception) -> JSONResponse:
  logger.error(f'[{err.__class__.__name__}] : {err}')
  error: ErrorResp = ErrorResp(error=f'{err}')
  return JSONResponse(content=error.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

########################################################################################################################
# FUNCTIONS
########################################################################################################################

# Check SQLite DB exists
def dbCheck():
  fullDbPath = os.path.join(os.path.dirname(__file__), SQLITE_DB)
  logger.debug(f'Run dbCheck [{fullDbPath}]')
  try:
    os.makedirs(SQLITE_BASE_DIR, exist_ok=True)
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute('SELECT sqlite_version();')
    version = cursor.fetchone()[0]
    logger.info(f'SQLite version: {version}')
    connection.close()
    logger.debug(f'dbCheck OK')
  except Exception as err:
    raise err

# Create databases and tables
def dbInit():
  logger.debug(f'Run dbInit')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    # Activated Foreign Keys
    cursor.execute(f'PRAGMA foreign_keys=on;')
    ## ROS_CONFIG_TABLE_NAME
    #cursor.execute(f"DROP TABLE IF EXISTS '{ROS_CONFIG_TABLE_NAME}';")
    cursor.execute(f"""
      CREATE TABLE IF NOT EXISTS '{ROS_CONFIG_TABLE_NAME}' (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        pass TEXT NOT NULL,
        bgp_list_name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT host_uq UNIQUE (host),
        CONSTRAINT host_chk CHECK (host != '')
        CONSTRAINT user_chk CHECK (user != '')
        CONSTRAINT bgp_list_name_chk CHECK (bgp_list_name != '')
      );
    """)
    ## DNS_SERVERS_TABLE_NAME
    # cursor.execute(f"DROP TABLE IF EXISTS '{DNS_SERVERS_TABLE_NAME}';")
    cursor.execute(f"""
      CREATE TABLE IF NOT EXISTS '{DNS_SERVERS_TABLE_NAME}' (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server TEXT,
        doh_server TEXT,
        description TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT server_uq UNIQUE (server),
        CONSTRAINT server_chk CHECK (server != ''),
        CONSTRAINT doh_server_uq UNIQUE (doh_server),
        CONSTRAINT doh_server_chk CHECK (doh_server != '')
      );
    """)
    cursor.execute(f"INSERT OR IGNORE INTO '{DNS_SERVERS_TABLE_NAME}' (id, server, description) VALUES (?,?,?);",
      (-1, '1.1.1.1', 'Cloudflare DNS - Default'))
    ## DOMAINS_LISTS_TABLE_NAME
    # cursor.execute(f"DROP TABLE IF EXISTS '{DOMAINS_LISTS_TABLE_NAME}';")
    cursor.execute(f"""
      CREATE TABLE IF NOT EXISTS '{DOMAINS_LISTS_TABLE_NAME}' (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        description TEXT,
        hash TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP,
        CONSTRAINT name_uq UNIQUE (name),
        CONSTRAINT name_chk CHECK (name != '')
        CONSTRAINT url_chk CHECK (url != '')
      );
    """)
    cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_domain_list_name ON {DOMAINS_LISTS_TABLE_NAME} (name)')
    ## IPS_LISTS_TABLE_NAME
    # cursor.execute(f"DROP TABLE IF EXISTS '{IPS_LISTS_TABLE_NAME}';")
    cursor.execute(f"""
      CREATE TABLE IF NOT EXISTS '{IPS_LISTS_TABLE_NAME}' (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        description TEXT,
        hash TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP,
        CONSTRAINT name_uq UNIQUE (name),
        CONSTRAINT name_chk CHECK (name != '')
        CONSTRAINT url_chk CHECK (url != '')
      );
    """)
    cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_ip_list_name ON {IPS_LISTS_TABLE_NAME} (name)')
    ## DOMAINS_TABLE_NAME
    # cursor.execute(f"DROP TABLE IF EXISTS '{DOMAINS_TABLE_NAME}';")
    cursor.execute(f"""
      CREATE TABLE IF NOT EXISTS '{DOMAINS_TABLE_NAME}' (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_list_id INTEGER,
        resolved INTEGER NOT NULL DEFAULT 0,
        name TEXT NOT NULL,
        ros_comment TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP,
        CONSTRAINT name_uq UNIQUE (name),
        CONSTRAINT name_chk CHECK (name != '')
        FOREIGN KEY (domain_list_id) REFERENCES {DOMAINS_LISTS_TABLE_NAME} (id) ON DELETE CASCADE
      );
    """)
    cursor.execute(f"INSERT OR IGNORE INTO '{DOMAINS_TABLE_NAME}' (id, resolved, name, ros_comment) VALUES (?,?,?,?);", (-1, True, 'default', 'Default Domain'))
    ## IP_RECORDS_TABLE_NAME
    # cursor.execute(f"DROP TABLE IF EXISTS '{IP_RECORDS_TABLE_NAME}';")
    ipRecordsCreateSql = f"""
      CREATE TABLE IF NOT EXISTS '{IP_RECORDS_TABLE_NAME}' (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_list_id INTEGER,
        domain_id INTEGER NOT NULL,
        addr_type INTEGER NOT NULL,
        ip_address TEXT NOT NULL,
        ros_comment TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT ip_addr_uq UNIQUE (ip_address),
        CONSTRAINT ip_addr_chk CHECK (ip_address != ''),
        FOREIGN KEY (domain_id) REFERENCES '{DOMAINS_TABLE_NAME}' (id) ON DELETE CASCADE,
        FOREIGN KEY (ip_list_id) REFERENCES '{IPS_LISTS_TABLE_NAME}' (id) ON DELETE CASCADE
      );
    """
    cursor.execute(ipRecordsCreateSql)
    cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_ip_address ON {IP_RECORDS_TABLE_NAME} (ip_address)')
    # From OLD to NEW
    # Add IPS_LISTS_TABLE_NAME foreign
    cursor.execute(f"PRAGMA table_info({IP_RECORDS_TABLE_NAME});")
    ipRecordsTableElements: list[tuple[int, str, str, int, str | None, int]] = cursor.fetchall() # cid, name, type, not_null, dflt_value, pk
    elements: list[tuple[int, str, str, int, str | None, int]] = [entry for entry in ipRecordsTableElements if entry[1] == 'ip_list_id']
    if len(elements) < 1:
      cursor.execute(f"""
        CREATE TEMPORARY TABLE 'temp_{IP_RECORDS_TABLE_NAME}' AS SELECT * FROM '{IP_RECORDS_TABLE_NAME}';
      """)
      cursor.execute(f"DROP TABLE IF EXISTS '{IP_RECORDS_TABLE_NAME}';")
      cursor.execute(ipRecordsCreateSql)
      cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_ip_address ON {IP_RECORDS_TABLE_NAME} (ip_address)')
      cursor.execute(f"""
        INSERT INTO '{IP_RECORDS_TABLE_NAME}' SELECT id, NULL, domain_id, addr_type, ip_address, ros_comment, created_at FROM 'temp_{IP_RECORDS_TABLE_NAME}';
      """)
    ## JOB_TABLE_NAME
    cursor.execute(f"""
      CREATE TABLE IF NOT EXISTS '{JOB_TABLE_NAME}' (
        job_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        end_at TIMESTAMP,
        CONSTRAINT name_chk CHECK (name != '')
      );
    """)
    cursor.execute(f"""
      DELETE FROM '{JOB_TABLE_NAME}'
      WHERE end_at IS NULL;
    """)
    # Save all commands
    connection.commit()
    connection.close()
    logger.debug(f'dbInit OK')
  except Exception as err:
    raise err

# Resolve Domain
# Use all DNS servers (from DB or default if DB is empty)
def dnsResolvePool(domains_data: list[DomainResult]) -> list[DomainResult]:
  result: list[DomainResult] = []
  dnsServers: list[str] = []
  dnsDohServers: list[str] = []
  lookupTypes: tuple[RdataType, RdataType] = (A, AAAA)
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT server, doh_server FROM '{DNS_SERVERS_TABLE_NAME}' WHERE id > 0;")
    dnsAll = cursor.fetchall()
    if (len(dnsAll) < 1):
      cursor.execute(f"SELECT server, doh_server FROM '{DNS_SERVERS_TABLE_NAME}' WHERE id < 0;")
      dnsAll = cursor.fetchall()
    connection.close()
    for dns in dnsAll:
      if dns[0] != None:
        dnsServers.append(dns[0])
      if dns[1] != None:
        dnsDohServers.append(dns[1])
    if len(dnsServers) > 0:
      pool = ThreadPool(processes=min(len(domains_data) * len(dnsServers) * len(lookupTypes), 60))
      for domainResult in pool.imap(dnsWorker, product(domains_data, dnsServers, lookupTypes), chunksize=1):
        result.append(domainResult)
      pool.close()
    if len(dnsDohServers) > 0:
      pool = ThreadPool(processes=min(len(domains_data) * len(dnsDohServers) * len(lookupTypes), 60))
      for domainResult in pool.imap(dnsDohWorker, product(domains_data, dnsDohServers, lookupTypes), chunksize=1):
        result.append(domainResult)
      pool.close()
    return result
  except Exception as err:
    logger.error(f'[{err.__class__.__name__}]: dnsResolve - {err}')
    return result

# Resolve CNAMES
def dnsResolveCnamePool(domains_data: set[str]) -> list[str]:
  result: list[str] = []
  dnsServers: list[str] = []
  dnsDohServers: list[str] = []
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT server, doh_server FROM '{DNS_SERVERS_TABLE_NAME}' WHERE id > 0;")
    dnsAll = cursor.fetchall()
    if (len(dnsAll) < 1):
      cursor.execute(f"SELECT server, doh_server FROM '{DNS_SERVERS_TABLE_NAME}' WHERE id < 0;")
      dnsAll = cursor.fetchall()
    connection.close()
    for dns in dnsAll:
      if dns[0] != None:
        dnsServers.append(dns[0])
      if dns[1] != None:
        dnsDohServers.append(dns[1])
    if len(dnsServers) > 0:
      pool = ThreadPool(processes=min(len(domains_data) * len(dnsServers), 60))
      for cnameDomains in pool.imap(dnsWorkerCname, product(domains_data, dnsServers), chunksize=1):
        result.extend(cnameDomains)
      pool.close()
    if len(dnsDohServers) > 0:
      pool = ThreadPool(processes=min(len(domains_data) * len(dnsDohServers), 60))
      for cnameDomains in pool.imap(dnsDohWorkerCname, product(domains_data, dnsDohServers), chunksize=1):
        result.extend(cnameDomains)
      pool.close()
    return result
  except Exception as err:
    logger.error(f'[{err.__class__.__name__}] : dnsResolveCnamePool - {err}')
    return result

# Simple DNS server function for threadpool
def dnsWorker(arg: tuple[DomainResult, str, RdataType]) -> DomainResult:
  domainResult, dnsServer, lookupType = arg
  domain = domainResult.name.strip()
  try:
    resolver = Resolver(configure=False)
    resolver.nameservers = [dnsServer]
    resultList: list[Rdata] = [rdata for rdata in resolver.resolve(qname=domain, rdtype=lookupType)]
    if len(resultList) > 0:
      domainResult.append_lookup(resultList)
    return domainResult
  except DNSException as err:
    logger.warning(f'[{err.__class__.__name__}] : dnsWorker : {err}')
    return domainResult

def dnsWorkerCname(arg: tuple[str, str]) -> list[str]:
  cnameResult: list[str] = []
  domain, dnsServer = arg
  domain = domain.strip()
  try:
    resolver = Resolver(configure=False)
    resolver.nameservers = [dnsServer]
    resultList: list[Rdata] = [rdata for rdata in resolver.resolve(qname=domain, rdtype=CNAME)]
    if len(resultList) > 0:
      for result in resultList:
        if result.rdtype == CNAME:
          cnameResult.append(result.to_text().strip().strip('.'))
    return cnameResult
  except DNSException as err:
    logger.warning(f'[{err.__class__.__name__}] : dnsWorkerCname : {err}')
    return cnameResult

# DNS over HTTPS server function for threadpool (RFC 8484)
# tested on:
# https://dns.adguard-dns.com/dns-query
# https://cloudflare-dns.com/dns-query
# https://dns.google/dns-query
# https://dns.quad9.net:5053/dns-query
# https://dns.nextdns.io/dns-query
def dnsDohWorker(arg: tuple[DomainResult, str, RdataType]) -> DomainResult:
  domainResult, dnsDohServer, lookupType = arg
  domain = domainResult.name.strip()
  try:
    dohQuery: QueryMessage = make_query(qname=domain, rdtype=lookupType)
    dohQueryBinary = dohQuery.to_wire()
    dohQueryBase64 = base64.urlsafe_b64encode(dohQueryBinary).decode('utf-8').rstrip('=')
    params = {
      'dns': dohQueryBase64
    }
    headers = {
      'Accept': 'application/dns-message'
    }
    response = requests.get(dnsDohServer, params=params, headers=headers, verify=SSL_CHECK_ENABLE, timeout=REQ_TIMEOUT)
    if response.status_code == 200:
      responseBinary = response.content
      resultList: list[RRset] = [rrset for rrset in from_wire(responseBinary).answer]
      if len(resultList) > 0:
        domainResult.append_doh_lookup(resultList)
    else:
      logger.warning(f'dnsDohWorker : {response.status_code} - {response.text}')
    return domainResult
  except Exception as err:
    logger.warning(f'[{err.__class__.__name__}] : dnsDohWorker : {err}')
    return domainResult

def dnsDohWorkerCname(arg: tuple[str, str]) -> list[str]:
  cnameResult: list[str] = []
  domain, dnsDohServer = arg
  domain = domain.strip()
  try:
    dohQuery: QueryMessage = make_query(qname=domain, rdtype=CNAME)
    dohQueryBinary = dohQuery.to_wire()
    dohQueryBase64 = base64.urlsafe_b64encode(dohQueryBinary).decode('utf-8').rstrip('=')
    params = {
      'dns': dohQueryBase64
    }
    headers = {
      'Accept': 'application/dns-message'
    }
    response = requests.get(dnsDohServer, params=params, headers=headers, verify=SSL_CHECK_ENABLE, timeout=REQ_TIMEOUT)
    if response.status_code == 200:
      responseBinary = response.content
      resultList: list[RRset] = [rrset for rrset in from_wire(responseBinary).answer]
      if len(resultList) > 0:
        for result in resultList:
          if result.rdtype == CNAME:
            for value in result:
              cnameResult.append(value.to_text().strip().strip('.'))
    else:
      logger.warning(f'dnsDohWorkerCname : {response.status_code} - {response.text}')
    return cnameResult
  except Exception as err:
    logger.warning(f'[{err.__class__.__name__}] : dnsDohWorkerCname : {err}')
    return cnameResult

# Processing IP address
# Get:
# 1. Detect new IPs for ADD to ROS
# 2. Detect deleted IPs for REMOVE from ROS
# 3. Exclude no changes IPs
def ipsProcessing(domain_result: DomainResult, current_ips: list[str]):
  resolvedIpsList = []
  newIps = []
  removeIps = []
  try:
    for ipv4 in domain_result.result.A:
      resolvedIpsList.append(ipv4)
    for ipv6 in domain_result.result.AAAA:
      resolvedIpsList.append(ipv6)
    # 1. Add new to DB
    for ip in resolvedIpsList:
      if ip not in current_ips:
        newIps.append(ip)
    for ip in current_ips:
      if ip not in resolvedIpsList:
        removeIps.append(ip)
    if (len(newIps) > 0):
      for ip in newIps:
        ipVersion = getIpVersion(ip)
        if ipVersion not in [4, 6]:
          continue
        if checkIpAllow(ip) == False:
          continue
        domain_result.insert.ips_insert.append((domain_result.id, ipVersion, ip))
    if (len(removeIps) > 0):
      for ip in removeIps:
        domain_result.insert.ips_delete.append((domain_result.id, ip))
  except Exception as err:
    raise err

# Get connect RouterOs API interface
def connectRos(ros_host: str, ros_user: str, ros_user_pass: str) -> Api:
  try:
    rosApi = rosConnect(
      host=ros_host,
      username=ros_user,
      password=ros_user_pass,
      login_method=plain,
      timeout=ROS_TIMEOUT
    )
    return rosApi
  except Exception as err:
    raise err

# Check RouterOs instance
def rosCheck():
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT host, user, pass FROM '{ROS_CONFIG_TABLE_NAME}' LIMIT 1;")
    rosRow = cursor.fetchone()
    if rosRow == None:
      raise Exception(f'ROS warning config: Config is Empty. Please save first config')
    #
    connection.close()
    api = connectRos(rosRow[0], rosRow[1], rosRow[2])
    query = tuple(api.path('system/resource').select(Key('version'), Key('uptime')))
    version = query[0]['version']
    uptime = query[0]['uptime']
    api.close()
  except Exception as err:
    raise err

# Update domain data into Router OS
def rosUpdate(host: str, user: str, user_pass: str, bgp_list_name: str, ip_address_all: set[tuple[str, str, str, str]]):
  logger.info(f'Run rosUpdate for host={host}, user={user}, bgp_list_name={bgp_list_name}, ip_address_all_len={len(ip_address_all)}')
  api: Api | None = None
  try:
    api = connectRos(host, user, user_pass)
    dbIpAddressOnly = {entry[0] for entry in ip_address_all}
    # 1. Get Default Gateway
    roDstAddressKey = Key('dst-address')
    roActiveKey = Key('active')
    gatewayQuery = list(api.path('ip/route').select().where(
        roDstAddressKey == '0.0.0.0/0', # type: ignore
        roActiveKey == True # type: ignore
      ))
    defaultGateway = gatewayQuery[0]['gateway']
    logger.info(f'rosUpdate[{host}] : default gateway={defaultGateway}')
    if defaultGateway == None or len(gatewayQuery) < 1:
      raise Exception(f'Not found active default gateway on {host} for dst-address=0.0.0.0/0')
    #
    # 2. Get rdpr routing table
    roTableDisabledKey = Key('disabled')
    roTableNameKey = Key('name')
    routingTableQuery = list(api.path('routing/table').select().where(
        roTableDisabledKey == False, # type: ignore
        roTableNameKey == bgp_list_name # type: ignore
      ))
    logger.info(f'rosUpdate[{host}] : routing table : {routingTableQuery}')
    if routingTableQuery == None or len(routingTableQuery) < 1:
      routingTablePath = api.path('routing/table')
      routingTablePath.add(**{
        'name': bgp_list_name,
        'disabled': False,
        'fib': 'yes',
        'comment': f'Routing table for bgp list {bgp_list_name}'
      })
    #
    # 3. Firewall List
    fwIpAddressAll: list[tuple[str, str]] = rosGetFirewallAddrListAllIps(api, bgp_list_name)
    logger.info(f'rosUpdate[{host}] : firewall-address-list={bgp_list_name} count={len(fwIpAddressAll)}')
    #
    fwIpAddressRemove: list[tuple[str, str]] = [entry for entry in fwIpAddressAll if entry[1] not in dbIpAddressOnly]
    logger.info(f'rosUpdate[{host}] : firewall-address-list remove count={len(fwIpAddressRemove)}')
    #
    fwIpAddressOnly: set[str] = {entry[1] for entry in fwIpAddressAll}
    fwIpAddressAdd: list[tuple[str, str, str, str]] = [entry for entry in ip_address_all if entry[0] not in fwIpAddressOnly]
    logger.info(f'rosUpdate[{host}] : firewall-address-list add count={len(fwIpAddressAdd)}')
    #
    # 4. Routing
    roIpAddressAll: list[tuple[str, str, str]] = rosGetRoutesAllIps(api, bgp_list_name) # list[tuple(.id, ip-addr, gateway)]
    logger.info(f'rosUpdate[{host}] : route address routing-table={bgp_list_name} count={len(roIpAddressAll)}')
    #
    roWrongIpAddressRemove: list[tuple[str, str, str]] = [entry for entry in roIpAddressAll if entry[2] != defaultGateway]
    logger.info(f'rosUpdate[{host}] : wrong gateway route address remove count={len(roWrongIpAddressRemove)}')
    #
    roIpAddressRemove: list[tuple[str, str, str]] = [entry for entry in roIpAddressAll if entry[1] not in dbIpAddressOnly]
    logger.info(f'rosUpdate[{host}] : route address remove count={len(roIpAddressRemove)}')
    #
    roIpAddressOnly: set[str] = {entry[1] for entry in roIpAddressAll}
    roIpAddressAdd: list[tuple[str, str, str, str]] = [entry for entry in ip_address_all if entry[0] not in roIpAddressOnly]
    logger.info(f'rosUpdate[{host}] : route address add count={len(roIpAddressAdd)}')
    #
    # 5. Change gateway if gateway IP change
    if len(roWrongIpAddressRemove) > 0:
      rosRoGatewayChange(api, defaultGateway, roWrongIpAddressRemove)
    #
    # 6. Remove Firewall and Routing
    if len(fwIpAddressRemove) > 0:
      rosFwRemove(api, fwIpAddressRemove)
    if len(roIpAddressRemove) > 0:
      rosRoRemove(api, roIpAddressRemove)
    #
    # 7. Add new to Firewall and Routing
    if len(fwIpAddressAdd) > 0:
      rosFwAdd(api, bgp_list_name, fwIpAddressAdd)
    if len(roIpAddressAdd) > 0:
      rosRoAdd(api, bgp_list_name, defaultGateway, roIpAddressAdd)
    #
    api.close()
  except Exception as err:
    logger.error(f'[{err.__class__.__name__}] : rosUpdate : {err}')
    if LOG_LEVEL == 'trace': logger.error(traceback.format_exc())
    if api: api.close()
    raise err

# Get all IP address from firewall-address-list
def rosGetFirewallAddrListAllIps(api: Api, bgp_list_name: str) -> list[tuple[str, str]]:
  result: list[tuple[str, str]] = []
  disabledKey: Key = Key('disabled')
  fwListKey: Key = Key('list')
  try:
    fwIpAddrQuery: list[ReplyDict] = list(api.path('ip/firewall/address-list').select().where(
      disabledKey == False, # type: ignore
      fwListKey == bgp_list_name # type: ignore
    ))
    # {'.id': '*83', 'list': 'rdpr-bgp-networks', 'address': '34.0.241.162', 'creation-time': '2025-01-17 13:18:21', 
    # 'dynamic': False, 'disabled': False, 'comment': 'warsaw10147.discord.gg'}
    if len(fwIpAddrQuery) > 1:
      result = [(fwAddrListELement['.id'], fwAddrListELement['address']) for fwAddrListELement in fwIpAddrQuery]
    return result
  except Exception:
    return result

# Get all IP adress from routes
def rosGetRoutesAllIps(api: Api, bgp_list_name: str) -> list[tuple[str, str, str]]:
  result: list[tuple[str, str, str]] = []
  disabledKey: Key = Key('disabled')
  routingTableKey: Key = Key('routing-table')
  try:
    roIpAddrQuery: list[ReplyDict] = list(api.path('ip/route').select().where(
      disabledKey == False, # type: ignore
      routingTableKey == bgp_list_name # type: ignore
    ))
    # {'.id': '*800062E8', 'dst-address': '1.7.196.211/32', 'routing-table': 'rdpr-bgp-networks', 
    # 'gateway': '192.168.88.1', 'immediate-gw': '192.168.88.1%WAN-Eth1', 'distance': 1, 'scope': 30, 
    # 'target-scope': 10, 'dynamic': False, 'inactive': False, 'active': True, 'static': True, 'disabled': False, 
    # 'comment': 'ae5.pr04.del1.tfbnw.net'}
    if len(roIpAddrQuery) > 1:
      result = [(roElement['.id'], getIpWithoutPrefix(roElement['dst-address']), roElement['gateway']) for roElement in roIpAddrQuery]
    return result
  except Exception:
    return result

# Remove IP record from firewall address list
def rosFwRemove(api: Api, fw_ip_address_list: list[tuple[str, str]]):
  try:
    for ipRecord in fw_ip_address_list:
      fwAddrListPath = api.path('ip/firewall/address-list')
      fwAddrListPath.remove(ipRecord[0])
      time.sleep(0.1)
  except Exception as err:
    raise err

# Add new IP address to firewall address list
# fw_ip_address element: (ip, ip_ros_comment, domain, domain_ros_comment)
def rosFwAdd(api: Api, bgp_list_name: str, fw_ip_address_list: list[tuple[str, str, str, str]]):
  try:
    for ipRecord in fw_ip_address_list:
      ipAddrComment = '' # ip_ros_comment -> domain_ros_comment -> domain
      if ipRecord[1] != None and ipRecord[1] != '':
        ipAddrComment = ipRecord[1]
      elif ipRecord[1] == None and (ipRecord[3] != None and ipRecord[3] != ''):
        ipAddrComment = ipRecord[3]
      elif ipRecord[1] == None and (ipRecord[3] == None or ipRecord[3] == ''):
        ipAddrComment = ipRecord[2]
      fwAddrListPath = api.path('ip/firewall/address-list')
      fwAddrListPath.add(**{
        'address': ipRecord[0],
        'disabled': False,
        'list': bgp_list_name,
        'comment': ipAddrComment
      })
      time.sleep(0.1)
  except Exception as err:
    raise err

# Remove IP record from rounting
def rosRoRemove(api: Api, ro_ip_address_list: list[tuple[str, str, str]]):
  try:
    for ipRecord in ro_ip_address_list:
      ipRoutePath = api.path('ip/route')
      ipRoutePath.remove(ipRecord[0])
      time.sleep(0.1)
  except Exception as err:
    raise err

# Add new IP address to routing
# ro_ip_address element: (ip, ip_ros_comment, domain, domain_ros_comment)
def rosRoAdd(api: Api, bgp_list_name: str, default_gateway: str, ro_ip_address_list: list[tuple[str, str, str, str]]):
  try:
    for ipRecord in ro_ip_address_list:
      ipAddrComment = '' # ip_ros_comment -> domain_ros_comment -> domain
      if ipRecord[1] != None and ipRecord[1] != '':
        ipAddrComment = ipRecord[1]
      elif ipRecord[1] == None and (ipRecord[3] != None and ipRecord[3] != ''):
        ipAddrComment = ipRecord[3]
      elif ipRecord[1] == None and (ipRecord[3] == None or ipRecord[3] == ''):
        ipAddrComment = ipRecord[2]
      ipRoutePath = api.path('ip/route')
      ipRoutePath.add(**{
        'routing-table': bgp_list_name,
        'dst-address': ipRecord[0],
        'disabled': False,
        'comment': ipAddrComment,
        'gateway': default_gateway
      })
      time.sleep(0.1)
  except Exception as err:
    raise err
  
# Change default gateway if gateway change
def rosRoGatewayChange(api: Api, default_gateway: str, ro_wrong_ip_address_list: list[tuple[str, str, str]]):
  try:
    ipRoutePath = api.path('ip/route')
    for ipRecord in ro_wrong_ip_address_list:
      ipRoutePath.update(**{
        '.id' : ipRecord[0],
        'gateway': default_gateway
      })
      time.sleep(0.1)
  except Exception as err:
    raise err

# Download domains list
def downloadDomainsList(domains_list_id: int, name: str, url: str, hash: str | None, forced: bool) -> str | None:
  logger.debug(f'RUN - downloadDomainsList for domains_list_id={domains_list_id}, name={name}, url={url}, hash={hash}')
  connection = None
  domainsInsert: list[tuple[int, str]] = []
  try:
    # download file
    fileResponse = requests.get(url=url, verify=SSL_CHECK_ENABLE, headers=HEADERS, timeout=REQ_TIMEOUT, allow_redirects=True, stream=True)
    if not fileResponse.ok:
      raise Exception(f'Error code [{fileResponse.status_code}] while trying to upload a file on URL "{url}"')
    # decode content
    fileData = fileResponse.content.decode('utf-8')
    fileHash = getHash(fileData)
    if hash != None and fileHash == hash and forced == False:
      logger.info(f'Domains list [{domains_list_id}][{name}] hash is not modify. Skip it ...')
      return None
    # get all domains from context
    fileDomains: set[str] = set()
    # fileDomains = set(DOMAIN_PATTERN.findall(fileData))
    for line in fileResponse.iter_lines():
      if line:
        decodedLine = line.decode('utf-8')
        foundDomains: list[str] = DOMAIN_PATTERN.findall(decodedLine)
        fileDomains.update(foundDomains)
    logger.debug(f'domains count in file "{name}" = {len(fileDomains)}')
    if len(fileDomains) > 0:
      cnameDomains: list[str] = dnsResolveCnamePool(fileDomains)
      fileDomains.update(cnameDomains)
      logger.debug(f'domains count after CNAME resolve "{name}" = {len(fileDomains)}')
      domainsInsert = [(domains_list_id, domain.strip()) for domain in fileDomains]
      try:
        connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
        cursor = connection.cursor()
        cursor.execute(f"SELECT id, name FROM '{DOMAINS_TABLE_NAME}' WHERE domain_list_id = ?", (domains_list_id, ))
        currentDomains: list[tuple[int, str]] = cursor.fetchall()
        logger.debug(f'current domains size "{name}" = {len(currentDomains)}')
        if len(currentDomains) > 0:
          domainsInsertOnly: set[str] = {entry[1] for entry in domainsInsert}
          domainsIdsDelete: list[tuple[int]] = [(entry[0], ) for entry in currentDomains if entry[1] not in domainsInsertOnly]
          logger.debug(f'remove domains count "{name}" = {len(domainsIdsDelete)}')
          if len(domainsIdsDelete) > 0:
            cursor.executemany(f"DELETE FROM '{DOMAINS_TABLE_NAME}' WHERE id = ?;", domainsIdsDelete)
        cursor.executemany(f"INSERT OR IGNORE INTO '{DOMAINS_TABLE_NAME}' (domain_list_id, name) VALUES (?,?);", domainsInsert)
        cursor.execute(f"UPDATE '{DOMAINS_LISTS_TABLE_NAME}' SET hash = '{fileHash}', updated_at = CURRENT_TIMESTAMP WHERE id = {domains_list_id};")
        connection.commit()
        cursor.close()
        connection.close()
        return fileHash
      except db.Error as err:
        if connection: connection.rollback()
        logger.error(f'downloadDomainsList db.Error [{name}] - {err}')
      finally:
        if connection: connection.close()
    return None
  except Exception as err:
    raise err

# Download IP address list
def downloadIpAddrList(ip_addr_list_id: int, name: str, url: str, hash: str | None, forced: bool) -> str | None:
  logger.debug(f'RUN - downloadIpAddrList for ip_addr_list_id={ip_addr_list_id}, name={name}, url={url}, hash={hash}')
  connection = None
  ipsAddrInsert: list[tuple[int, str, int]] = []
  try:
    # download file
    fileResponse = requests.get(url=url, verify=SSL_CHECK_ENABLE, headers=HEADERS, timeout=REQ_TIMEOUT, allow_redirects=True, stream=True)
    if not fileResponse.ok:
      raise Exception(f'Error code [{fileResponse.status_code}] while trying to upload a file on URL "{url}"')
    # decode content
    fileData = fileResponse.content.decode('utf-8')
    fileHash = getHash(fileData)
    if hash != None and fileHash == hash and forced == False:
      logger.info(f'IP address list [{ip_addr_list_id}][{name}] hash is not modify. Skip it ...')
      return None
    # get all domains from context
    fileIpsAddr: set[str] = set()
    for line in fileResponse.iter_lines():
      if line:
        decodedLine = line.decode('utf-8')
        foundIps: list[tuple[str, str]] = [(element[0], element[6]) for element in IP_ALL_PATTERN.findall(decodedLine)]
        fileIpsAddr.update([entry[0] for entry in foundIps if entry[0] != None and entry[0] != '']) #ipv4
        fileIpsAddr.update([entry[1] for entry in foundIps if entry[1] != None and entry[1] != '']) #ipv6
    logger.debug(f'ips address count in file "{name}" = {len(fileIpsAddr)}')
    if len(fileIpsAddr) > 0:
      for ip in fileIpsAddr:
        ip = ip.strip()
        ipVersion = getIpVersion(ip)
        if ipVersion != False:
          ipsAddrInsert.append((ip_addr_list_id, ip, ipVersion))
      try:
        connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
        cursor = connection.cursor()
        cursor.execute(f"SELECT id, ip_address FROM '{IP_RECORDS_TABLE_NAME}' WHERE ip_list_id = ?", (ip_addr_list_id, ))
        currentIpsAddr: list[tuple[int, str]] = cursor.fetchall()
        logger.debug(f'current IP address size "{name}" = {len(currentIpsAddr)}')
        if len(currentIpsAddr) > 0:
          ipsAddrInsertOnly: set[str] = {entry[1] for entry in ipsAddrInsert}
          ipsAddrDelete: list[tuple[int]] = [(entry[0], ) for entry in currentIpsAddr if entry[1] not in ipsAddrInsertOnly]
          logger.debug(f'remove IP address count "{name}" = {len(ipsAddrDelete)}')
          if len(ipsAddrDelete) > 0:
            cursor.executemany(f"DELETE FROM '{IP_RECORDS_TABLE_NAME}' WHERE id = ?;", ipsAddrDelete)
        cursor.executemany(f"INSERT OR IGNORE INTO '{IP_RECORDS_TABLE_NAME}' (ip_list_id, ip_address, addr_type, domain_id) VALUES (?,?,?,-1);", ipsAddrInsert)
        cursor.execute(f"UPDATE '{IPS_LISTS_TABLE_NAME}' SET hash = '{fileHash}', updated_at = CURRENT_TIMESTAMP WHERE id = {ip_addr_list_id};")
        connection.commit()
        cursor.close()
        connection.close()
        return fileHash
      except db.Error as err:
        if connection: connection.rollback()
        logger.error(f'downloadIpAddrList db.Error [{name}] - {err}')
      finally:
        if connection: connection.close()
    return None
  except Exception as err:
    raise err

# Background Task func for download domains lists
# Select only what has not been processed for N time
def backgroundTask_DomainsListsLoad(forced: bool):
  logger.info(f'backgroundTask_DomainsListsLoad - START')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
        SELECT id, name, url, hash
        FROM '{DOMAINS_LISTS_TABLE_NAME}'
      ;""")
    domainsListsAll = cursor.fetchall()
    logger.info(f'domains lists count for load - {len(domainsListsAll)}')
    cursor.execute(f"INSERT INTO '{JOB_TABLE_NAME}' (name) VALUES ('{JOBNAME_DOMAINS_LISTS_LOAD}');")
    connection.commit()
    for domainsList in domainsListsAll:
      id = domainsList[0]
      name = domainsList[1]
      url = domainsList[2]
      hash = domainsList[3]
      try:
        downloadDomainsList(id, name, url, hash, forced)
      except Exception as err:
        logger.error(f"[{err.__class__.__name__}] : Failed to process the list '{name}' of domains. Error => {err}")
        continue
    cursor.execute(f"UPDATE '{JOB_TABLE_NAME}' SET end_at = CURRENT_TIMESTAMP WHERE name = '{JOBNAME_DOMAINS_LISTS_LOAD}' AND end_at IS NULL;")
    connection.commit()
    cursor.close()
    connection.close()
    logger.info(f'backgroundTask_DomainsListsLoad - DONE')
  except Exception as err:
    if LOG_LEVEL == 'trace': logger.error(traceback.format_exc())
    logger.error(f'[{err.__class__.__name__}] : backgroundTask_DomainsListsLoad :: {err}')

# Background Task func for download IP address lists
# Select only what has not been processed for N time
def backgroundTask_IpAddrListsLoad(forced: bool):
  logger.info(f'backgroundTask_IpAddrListsLoad - START')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
        SELECT id, name, url, hash
        FROM '{IPS_LISTS_TABLE_NAME}'
      ;""")
    ipsAddrListsAll = cursor.fetchall()
    logger.info(f'ip address lists count for load - {len(ipsAddrListsAll)}')
    cursor.execute(f"INSERT INTO '{JOB_TABLE_NAME}' (name) VALUES ('{JOBNAME_IP_ADDR_LISTS_LOAD}');")
    connection.commit()
    for ipAddrList in ipsAddrListsAll:
      id = ipAddrList[0]
      name = ipAddrList[1]
      url = ipAddrList[2]
      hash = ipAddrList[3]
      try:
        downloadIpAddrList(id, name, url, hash, forced)
      except Exception as err:
        logger.error(f"[{err.__class__.__name__}] : Failed to process the list '{name}' of IP addresses. Error => {err}")
        continue
    cursor.execute(f"UPDATE '{JOB_TABLE_NAME}' SET end_at = CURRENT_TIMESTAMP WHERE name = '{JOBNAME_IP_ADDR_LISTS_LOAD}' AND end_at IS NULL;")
    connection.commit()
    cursor.close()
    connection.close()
    logger.info(f'backgroundTask_IpAddrListsLoad - DONE')
  except Exception as err:
    if LOG_LEVEL == 'trace': logger.error(traceback.format_exc())
    logger.error(f'[{err.__class__.__name__}] : backgroundTask_IpAddrListsLoad :: {err}')

# Many Threaded Queue reader for processing domains
# batch_offset - protection against simultaneous writing to the database of several streams
def consumer_ResolveDomains(domains_queue: Queue, db_queue: Queue):
  tName = current_thread().name
  logger.info(f'{tName} : consumer_ResolveDomains - RUN')
  connection = None
  emptyIterations = 0
  domains: list[DomainResult] = []
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    logger.debug(f'{tName} : consumer_ResolveDomains : db.connect - OK')
  except Exception as err:
    logger.error(f'{tName} : [{err.__class__.__name__}] : consumer_ResolveDomains : DB connection error : {err}')
    raise err
  if connection != None:
    logger.info(f'{tName} : consumer_ResolveDomains : Run while ...')
    while True:
      logger.debug(f'{tName} : consumer_ResolveDomains : queue-size={domains_queue.qsize()} emptyIterations={emptyIterations}')
      try:
        domain: tuple[int, str] = domains_queue.get(timeout=0.1)
        emptyIterations = 0
        domainResult: DomainResult = DomainResult(id=domain[0], name=domain[1])
        domains.append(domainResult)
        #
        if len(domains) >= RESOLVE_DOMAINS_BATCH_SIZE:
          domainsResult: list[DomainResult] = dnsResolvePool(domains)
          for domainResult in domainsResult:
            while db_queue.full():
              time.sleep(0.001)
            currentIps: list[str] = []
            cursor = connection.cursor()
            cursor.execute(f"SELECT ip_address FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id = ?;", (domainResult.id, ))
            ips = cursor.fetchall()
            cursor.close()
            for ip in ips:
              currentIps.append(ip[0])
            ipsProcessing(domainResult, currentIps)
            db_queue.put(domainResult)
          domains.clear()
        domains_queue.task_done()
      except Empty:
        emptyIterations += 1
        if emptyIterations >= RESOLVE_EMPTY_ITER:
          if len(domains) > 0:
            domainsResult: list[DomainResult] = dnsResolvePool(domains)
            domainsCount = len(domainsResult)
            for domainResult in domainsResult:
              while db_queue.full():
                time.sleep(0.1)
              currentIps: list[str] = []
              cursor = connection.cursor()
              cursor.execute(f"SELECT ip_address FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id = ?;", (domainResult.id, ))
              ips = cursor.fetchall()
              cursor.close()
              for ip in ips:
                currentIps.append(ip[0])
              ipsProcessing(domainResult, currentIps)
              db_queue.put(domainResult)
            domains.clear()
            logger.info(f'{tName} : consumer_ResolveDomains : Exit while domains={domainsCount} (Empty)!')
            continue
          logger.info(f'{tName} : consumer_ResolveDomains : Exit while (Empty)!')
          break
        else:
          time.sleep(0.1) # 0.1 * 100 = 10 sec
        continue
      except Exception as err:
        logger.error(f'{tName} : [{err.__class__.__name__}] : consumer_ResolveDomains : while error : {err}')
        continue
  else:
    logger.error(f'{tName} : consumer_ResolveDomains : DB connection is Empty')

# Single Thread saver to DB domains data
def consumer_SaveDomainsData(db_queue: Queue):
  tName = current_thread().name
  logger.info(f'{tName} : consumer_SaveDomainsData - RUN')
  connection = None
  ipsInsertSqlData = []
  ipsDeleteSqlData = []
  emptyIterations = 0
  domainsBatch = []
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    logger.debug(f'{tName} : consumer_SaveDomainsData : db.connect - OK')
  except Exception as err:
    logger.error(f'{tName} : [{err.__class__.__name__}] : consumer_SaveDomainsData : DB connection error : {err}')
    raise err
  if connection != None:
    logger.info(f'{tName} : consumer_SaveDomainsData : Run while ...')
    while True:
      logger.debug(f'{tName} : consumer_SaveDomainsData : db-queue-size={db_queue.qsize()} emptyIterations={emptyIterations}')
      try:
        domainResult: DomainResult = db_queue.get(timeout=0.1)
        emptyIterations = 0
        ipsInsertSqlData = list(chain(ipsInsertSqlData, domainResult.insert.ips_insert))
        ipsDeleteSqlData = list(chain(ipsDeleteSqlData, domainResult.insert.ips_delete))
        domainsBatch.append((domainResult.id, ))
        logger.debug(f'{tName} : consumer_SaveDomainsData : domainsBatch count={len(domainsBatch)}')
        if len(domainsBatch) >= DEF_DB_FLUSH_BATCH_SIZE:
          logger.info(f'{tName} : consumer_SaveDomainsData : Dumping ips({len(ipsInsertSqlData)}), for domains={len(domainsBatch)} to storage')
          cursor = connection.cursor()
          cursor.executemany(f"INSERT OR IGNORE INTO '{IP_RECORDS_TABLE_NAME}' (domain_id, addr_type, ip_address) VALUES (?,?,?);", ipsInsertSqlData)
          cursor.executemany(f"DELETE FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id = ? AND ip_address = ?;", ipsDeleteSqlData)
          cursor.executemany(f"UPDATE '{DOMAINS_TABLE_NAME}' SET resolved = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND id != -1;", domainsBatch)
          connection.commit()
          cursor.close()
          logger.debug(f'{tName} : consumer_SaveDomainsData : Dumping count={len(domainsBatch)} to storage - OK')
          ipsInsertSqlData.clear()
          ipsDeleteSqlData.clear()
          domainsBatch.clear()
        db_queue.task_done()
      except Empty:
        emptyIterations += 1
        if emptyIterations >= DB_EMPTY_ITER:
          if len(domainsBatch) > 0:
            logger.info(f'{tName} : consumer_SaveDomainsData : LAST Dumping ips({len(ipsInsertSqlData)}), for domains={len(domainsBatch)} to storage')
            cursor = connection.cursor()
            cursor.executemany(f"INSERT OR IGNORE INTO '{IP_RECORDS_TABLE_NAME}' (domain_id, addr_type, ip_address) VALUES (?,?,?);", ipsInsertSqlData)
            cursor.executemany(f"DELETE FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id = ? AND ip_address = ?;", ipsDeleteSqlData)
            cursor.executemany(f"UPDATE '{DOMAINS_TABLE_NAME}' SET resolved = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND id != -1;", domainsBatch)
            connection.commit()
            cursor.close()
            if connection: connection.close()
            logger.debug(f'{tName} : consumer_SaveDomainsData : LAST Dumping count={len(domainsBatch)} to storage - OK')
            ipsInsertSqlData.clear()
            ipsDeleteSqlData.clear()
            domainsBatch.clear()
            continue
          logger.info(f'{tName} : consumer_SaveDomainsData : Exit while (Empty)!')
          break
        else:
          time.sleep(0.1) # 0.1 * 100 = 10 sec
        continue
      except Exception as err:
        logger.error(f'{tName} : [{err.__class__.__name__}] : consumer_SaveDomainsData : while error : {err}')
        continue
  else:
    logger.error(f'{tName} : consumer_SaveDomainsData : DB connection is Empty')

# Background Task func for resolve domains names
# Select only what has not been processed for N time and ID > 0
def backgroundTask_resolveDomains(domains_queue: Queue):
  logger.info(f'backgroundTask_resolveDomains - RUN')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT id, name
      FROM '{DOMAINS_TABLE_NAME}'
      WHERE id > 0 AND (updated_at IS NULL OR (unixepoch(CURRENT_TIMESTAMP) - unixepoch(updated_at)) >= {DOMAINS_UPDATE_INTERVAL});
    """)
    domains: list[tuple[int, str]] = cursor.fetchall()
    #
    if len(domains) > 0:
      logger.info(f'backgroundTask_resolveDomains : domains count for resolve={len(domains)} Start job ...')
      cursor.execute(f"INSERT INTO '{JOB_TABLE_NAME}' (name) VALUES ('{JOBNAME_RESOLVE_DOMAINS}');")
      connection.commit()
      for domain in domains:
        while domains_queue.full():
          time.sleep(0.1)
        logger.debug(f'backgroundTask_resolveDomains : insert domain[{domain[1]}] to queue. queue-size={domains_queue.qsize()}')
        domains_queue.put(domain)
      cursor.execute(f"UPDATE '{JOB_TABLE_NAME}' SET end_at = CURRENT_TIMESTAMP WHERE name = '{JOBNAME_RESOLVE_DOMAINS}' AND end_at IS NULL;")
      connection.commit()
    else:
      logger.info(f'backgroundTask_resolveDomains : no domains for job. skip it ...')
    connection.close()
    logger.info(f'backgroundTask_resolveDomains - DONE')
  except Exception as err:
    if LOG_LEVEL == 'trace': logger.error(traceback.format_exc())
    logger.error(f'[{err.__class__.__name__}] : backgroundTask_resolveDomains : {err}')

# Background Task func for update RouterOS device
def backgroundTask_routerOsUpdate(addr_type: int | None):
  logger.info(f'backgroundTask_routerOsUpdate - RUN')
  whereSql = ''
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT host, user, pass, bgp_list_name FROM '{ROS_CONFIG_TABLE_NAME}';")
    rosConfigs: list[tuple[str, str, str, str]] = cursor.fetchall()
    if len(rosConfigs) > 0:
      logger.info(f'backgroundTask_routerOsUpdate : routeros configs count={len(rosConfigs)} Start job ...')
      cursor.execute(f"INSERT INTO '{JOB_TABLE_NAME}' (name) VALUES ('{JOBNAME_ROUTEROS_UPDATE}');")
      connection.commit()
      if addr_type != None:
        whereSql = f' WHERE ir.addr_type = {addr_type}'
      cursor.execute(f"""
        SELECT ir.ip_address, ir.ros_comment, d.name, d.ros_comment 
        FROM '{IP_RECORDS_TABLE_NAME}' AS ir
        LEFT JOIN '{DOMAINS_TABLE_NAME}' AS d ON ir.domain_id = d.id
        {whereSql};
      """)
      dbIpAddressAll = cursor.fetchall()
      ipAddressSetAll: set[tuple[str, str, str, str]] = {(ip, ip_ros_comment, domain, domain_ros_comment) for ip, ip_ros_comment, domain, domain_ros_comment in dbIpAddressAll}
      logger.debug(f'backgroundTask_routerOsUpdate : IP address count in DB={len(ipAddressSetAll)}')
      for config in rosConfigs:
        host: str = config[0]
        user: str = config[1]
        userPass: str = config[2]
        bgpListName: str = config[3]
        try:
          logger.info(f'backgroundTask_routerOsUpdate : rosUpdate[{host}] : DB IP addresses count list={len(dbIpAddressAll)} set={len(ipAddressSetAll)}')
          rosUpdate(host, user, userPass, bgpListName, ipAddressSetAll)
        except Exception as err:
          continue
      cursor.execute(f"UPDATE '{JOB_TABLE_NAME}' SET end_at = CURRENT_TIMESTAMP WHERE name = '{JOBNAME_ROUTEROS_UPDATE}' AND end_at IS NULL;")
      connection.commit()
    connection.close()
    logger.info(f'backgroundTask_routerOsUpdate - DONE')
  except Exception as err:
    if LOG_LEVEL == 'trace': logger.error(traceback.format_exc())
    logger.error(f'[{err.__class__.__name__}] : backgroundTask_routerOsUpdate : {err}')

# MAIN FUNC
async def main():
  logger.info(f'Run main')
  try:
    dbCheck()
    dbInit()
    config = uvicorn.Config('main:app', host=HOST, port=PORT, log_level=LOG_LEVEL, server_header=False)
    server = uvicorn.Server(config)
    logger.info(f'Try run App. cpus={cpus}[{getDefCpus()}] prod={IS_PRODUCTION}, host={HOST}, port={PORT}, log_level={LOG_LEVEL}, debug={DEBUG}')
    await server.serve()
  except Exception as err:
    if LOG_LEVEL == 'trace': logger.error(traceback.format_exc())
    logger.error(f'[{err.__class__.__name__}] : main : {err}')

########################################################################################################################
# REST API
########################################################################################################################

#
# MAIN
#

# API OK checker
@app.get(
    tags=['Home'],
    path='/',
    name='Health check',
    description='API OK checker',
    response_model=HealthResp
  )
async def get_home():
  logger.debug(f'Call API route: GET /')
  now = datetime.now()
  ts = datetime.timestamp(now) // 1
  uptime = (time.time() - startTime) // 1
  resp: HealthResp = HealthResp(ts=ts, uptime=uptime)
  return JSONResponse(resp.model_dump(mode='json', exclude_none=True), status.HTTP_200_OK)

#
# DNS
#

dnsPostBodyExamples = [
  [
    {
      'server': '9.9.9.9',
    },
    {
      'server': '1.1.1.1',
      'description': 'Simple IPv4 DNS server'
    },
    {
      'doh_server': 'https://dns.adguard-dns.com/dns-query',
      'description': 'DNS over HTTPS server URL'
    }
  ]
]

# Get all DNS records
@app.get(
    tags=[DNS_SERVERS_TAG],
    path='/dns',
    name='Get all DNS servers records',
    description='Displays all available DNS server records. Also displays the default DNS server with ID -1',
    response_model=DnsPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_all_dns(query: Annotated[DnsQuery, Query()]):
  logger.debug(f'Call API route: GET /dns')
  whereSql = ''
  try:
    returnData: DnsPayloadResp = DnsPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    if query.default == False:
      whereSql = f'WHERE id > 0'
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(id) FROM '{DNS_SERVERS_TABLE_NAME}' {whereSql};")
    dnsSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT id, server, doh_server, description, created_at
      FROM '{DNS_SERVERS_TABLE_NAME}'
      {whereSql}
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    dnsAll = cursor.fetchall()
    connection.close()
    for dns in dnsAll:
      returnData.payload.append(DnsElementResp(
        id=dns[0],
        server=dns[1],
        doh_server=dns[2],
        description=dns[3],
        created_at=getTimestamp(dns[4])
      ))
    returnData.count = len(returnData.payload)
    returnData.total = dnsSize
    return JSONResponse(returnData.model_dump(mode='json'), status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Get DNS info on ID
@app.get(
    tags=[DNS_SERVERS_TAG],
    path='/dns/{id}',
    name='Get once DNS server record',
    description='Display parameters at once DNS server record',
    response_model=DnsElementResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
    }
  )
async def get_dns_on_id(id: Annotated[int, Path(gt=0, title='DNS record ID')]):
  logger.debug(f'Call API route: GET /dns/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT id, server, doh_server, description, created_at
      FROM '{DNS_SERVERS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    dns = cursor.fetchone()
    connection.close()
    if dns == None:
      dnsNotFound: NotFoundResp = NotFoundResp(reason=f"ID '{id}' not found")
      return JSONResponse(content=dnsNotFound.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_404_NOT_FOUND)
    dnsElement: DnsElementResp = DnsElementResp(
      id=int(id),
      server=dns[1],
      doh_server=dns[2],
      description=dns[3],
      created_at=getTimestamp(dns[4])
    )
    return JSONResponse(content=dnsElement.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Add new DNS servers
@app.post(
    tags=[DNS_SERVERS_TAG],
    path='/dns',
    name='Add new DNS servers',
    description='Allows you to add the required DNS servers through an array with parameters',
    status_code=status.HTTP_200_OK,
    response_model=list[DnsPostElementResp],
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
    }
  )
async def dns_add(data: Annotated[list[DnsPostElement], Body(examples=dnsPostBodyExamples)]):
  logger.debug(f'Call API route: POST /dns')
  try:
    if (len(data) < 1):
      return JSONResponse(NoDataResp().model_dump(mode='json', exclude_none=True), status.HTTP_400_BAD_REQUEST)
    returnData: list[dict[str, Any]] = list()
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    for dnsItem in data:
      server = dnsItem.server
      dohServer = dnsItem.doh_server
      description = dnsItem.description
      try:
        cursor.execute(f"INSERT INTO '{DNS_SERVERS_TABLE_NAME}' (server, doh_server, description) VALUES (?,?,?);",
          (server, dohServer, description))
        dnsId = cursor.lastrowid
        if (dnsId == None or dnsId < 1):
          raise Exception(f'Error get dnsId for "{server}". Result: {dnsId}')
        if server != None:
          returnData.append(DnsPostElementResp(name=server, id=dnsId).model_dump(mode='json', exclude_none=True))
        if dohServer != None:
          returnData.append(DnsPostElementResp(name=dohServer, id=dnsId).model_dump(mode='json', exclude_none=True))
      except Exception as err:
        if server != None:
          returnData.append(DnsPostElementResp(name=server, error=str(err)).model_dump(mode='json', exclude_none=True))
        if dohServer != None:
          returnData.append(DnsPostElementResp(name=dohServer, error=str(err)).model_dump(mode='json', exclude_none=True))
    connection.commit()
    connection.close()
    return JSONResponse(content=returnData, status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All DNS servers
# WARN. DANGER ZONE !!!
@app.delete(
    tags=[DNS_SERVERS_TAG],
    path='/internal/dns/all',
    name='Clear All DNS servers records (WARNING!!!)',
    description='Clear All DNS servers records. But not default record id=-1',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def dns_remove_all():
  logger.debug(f'Call API route: DELETE /internal/dns/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    # not delete default dns
    cursor.execute(f"DELETE FROM '{DNS_SERVERS_TABLE_NAME}' WHERE id > 0;")
    countResult = cursor.execute('SELECT changes();')
    countDelete = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    return JSONResponse(OkStatusResp(count=countDelete).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete once DNS server
@app.delete(
    tags=[DNS_SERVERS_TAG],
    path='/dns/{id}',
    name='Delete once DNS server record',
    description='Delete once DNS server record',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def dns_remove(id: Annotated[int, Path(gt=0, title='DNS record ID')]):
  logger.debug(f'Call API route: DELETE /dns/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      DELETE FROM '{DNS_SERVERS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countDelete = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    return JSONResponse(OkStatusResp(count=countDelete).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# DOMAINS LISTS
#

domainsListsPostBodyExamples = [
  [
    {
      'name': 'voice-domains-list',
      'url': 'https://somedomain.som/path/path/path/voice.txt'
    },
    {
      'name': 'voice-domains-list-2',
      'url': 'https://somedomain.som/path/path/path/voice-2.txt',
      'description': 'Description for some voice domains list'
    }
  ]
]

# Get all domains lists
@app.get(
    tags=[DOMAINS_LISTS_TAG],
    path='/domains/lists',
    name='Get all Domains lists',
    description='Displays all Domains lists records',
    response_model=DomainsListsPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_all_domains_lists(query: Annotated[LimitOffsetQuery, Query()]):
  logger.debug(f'Call API route: GET /domains/lists')
  try:
    returnData: DomainsListsPayloadResp = DomainsListsPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(id) FROM '{DOMAINS_LISTS_TABLE_NAME}';")
    domainsListsSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT id, name, url, description, hash, created_at, updated_at
      FROM '{DOMAINS_LISTS_TABLE_NAME}'
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    domainsListsAll = cursor.fetchall()
    for domainsList in domainsListsAll:
      returnData.payload.append(DomainsListsElementResp(
        id=domainsList[0],
        name=domainsList[1],
        url=domainsList[2],
        description=domainsList[3],
        hash=domainsList[4],
        created_at=getTimestamp(domainsList[5]),
        updated_at=getTimestamp(domainsList[6]) if domainsList[6] != None else None
      ))
    returnData.count = len(returnData.payload)
    returnData.total = domainsListsSize
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Get Domains list info on ID
@app.get(
    tags=[DOMAINS_LISTS_TAG],
    path='/domains/lists/{id}',
    name='Get once Domains list',
    description='Displays once Domains list record info',
    response_model=DomainsListsElementResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
    }
  )
async def get_domains_list_on_id(id: Annotated[int, Path(gt=0, title='Domains list record ID')]):
  logger.debug(f'Call API route: GET /domains/lists/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT id, name, url, description, hash, created_at, updated_at
      FROM '{DOMAINS_LISTS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    domainsList = cursor.fetchone()
    connection.close()
    if domainsList == None:
      domainsListNotFound: NotFoundResp = NotFoundResp(reason=f"ID '{id}' not found")
      return JSONResponse(content=domainsListNotFound.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_404_NOT_FOUND)
    domainsListElement: DomainsListsElementResp = DomainsListsElementResp(
      id=domainsList[0],
      name=domainsList[1],
      url=domainsList[2],
      description=domainsList[3],
      hash=domainsList[4],
      created_at=getTimestamp(domainsList[5]),
      updated_at=getTimestamp(domainsList[6]) if domainsList[6] != None else None
    )
    return JSONResponse(content=domainsListElement.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Add new domains lists
@app.post(
    tags=[DOMAINS_LISTS_TAG],
    path='/domains/lists',
    name='Add new domains lists',
    description='Add new domains lists URL for download and parse for next',
    status_code=status.HTTP_200_OK,
    response_model=list[DomainsListsPostElementResp],
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
    }
  )
async def domains_lists_add(data: Annotated[list[DomainsListsPostElement], Body(examples=domainsListsPostBodyExamples)]):
  logger.debug(f'Call API route: POST /domains/lists')
  try:
    if (len(data) < 1):
      return JSONResponse(NoDataResp().model_dump(mode='json', exclude_none=True), status.HTTP_400_BAD_REQUEST)
    returnData: list[dict[str, Any]] = list()
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    for domainsListItem in data:
      try:
        cursor.execute(f"INSERT INTO '{DOMAINS_LISTS_TABLE_NAME}' (name, url, description) VALUES (?,?,?);",
          (domainsListItem.name, domainsListItem.url, domainsListItem.description))
        domainsListId = cursor.lastrowid
        if (domainsListId == None or domainsListId < 1):
          raise Exception(f"Error get domainsListId for '{domainsListItem.name}'. Result: {domainsListId}")
        returnData.append(DomainsListsPostElementResp(name=domainsListItem.name, id=domainsListId).model_dump(mode='json', exclude_none=True))
      except Exception as err:
        returnData.append(DomainsListsPostElementResp(name=domainsListItem.name, error=str(err)).model_dump(mode='json', exclude_none=True))
    connection.commit()
    connection.close()
    return JSONResponse(content=returnData, status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All Domains lists
# WARN. DANGER ZONE !!!
@app.delete(
    tags=[DOMAINS_LISTS_TAG],
    path='/internal/domains/lists/all',
    name='Delete all Domains lists records',
    description='Delete all Domains lists records',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def domains_lists_remove_all():
  logger.debug(f'Call API route: DELETE /internal/domains/lists/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    # not delete default dns
    cursor.execute(f"DELETE FROM '{DOMAINS_LISTS_TABLE_NAME}';")
    countResult = cursor.execute('SELECT changes();')
    count = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: IpsDeleteResp = IpsDeleteResp(count=count)
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete once Domains list
@app.delete(
    tags=[DOMAINS_LISTS_TAG],
    path='/domains/lists/{id}',
    name='Delete once Domains list',
    description='Delete once Domains list record',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def domains_list_remove(id: Annotated[int, Path(gt=0, title='Domains list record ID')]):
  logger.debug(f'Call API route: DELETE /domains/lists/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      DELETE FROM '{DOMAINS_LISTS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countDelete = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    return JSONResponse(OkStatusResp(count=countDelete).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# DOMAINS
#

domainsPostBodyExamples = [
  [
    {
      'domain': 'google.com',
    },
    {
      'domain': 'rotterdam1192.discord.gg',
      'ros_comment': 'discord domain'
    }
  ]
]

# Get all Domain infos
@app.get(
    tags=[DOMAINS_TAG],
    path='/domains',
    name='Get all Domains records',
    description='Displays all available Domains records',
    response_model=DomainsPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_all_domains(query: Annotated[DomainsQuery, Query()]):
  logger.debug(f'Call API route: GET /domains')
  resolvedSql = ''
  try:
    returnData: DomainsPayloadResp = DomainsPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    if (query.resolved != None):
      resolvedSql = f'WHERE resolved = {query.resolved}'
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(id) FROM '{DOMAINS_TABLE_NAME}' {resolvedSql};")
    domainsSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT id, resolved, name, ros_comment, created_at, updated_at, domain_list_id
      FROM '{DOMAINS_TABLE_NAME}' 
      {resolvedSql}
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    domains = cursor.fetchall()
    for domain in domains:
      cursor.execute(f"SELECT ip_address, addr_type, ros_comment FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id = ?;", (domain[0], ))
      ipAddrRaw = cursor.fetchall()
      ipAddrV4: list[str] = list()
      ipAddrV6: list[str] = list()
      for ip in ipAddrRaw:
        if (ip[1] == 4):
          ipAddrV4.append(ip[0])
        if (ip[1] == 6):
          ipAddrV6.append(ip[0])
      returnData.payload.append(DomainElementResp(
        id=domain[0],
        domains_list_id=domain[6],
        resolved=True if domain[1] == 1 else False,
        name=domain[2],
        ros_comment=domain[3],
        created_at=getTimestamp(domain[4]),
        updated_at=getTimestamp(domain[5]) if domain[5] != None else None,
        ips_v4=ipAddrV4 if len(ipAddrV4) > 0 else None,
        ips_v6=ipAddrV6 if len(ipAddrV6) > 0 else None
      ))
    returnData.count = len(returnData.payload)
    returnData.total = domainsSize
    connection.close()
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Get domain info on ID
@app.get(
    tags=[DOMAINS_TAG],
    path='/domains/{id}',
    name='Get domain record info on ID',
    description='Display parameters at once Domain name record',
    response_model=DomainElementResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
    }
  )
async def get_domain_on_id(id: Annotated[int, Path(gt=0, title='Domain record ID')]):
  logger.debug(f'Call API route: GET /domains/{id}')
  ipAddrV4: list[str] = list()
  ipAddrV6: list[str] = list()
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT resolved, name, ros_comment, created_at, updated_at, domain_list_id
      FROM '{DOMAINS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    domain = cursor.fetchone()
    if domain == None:
      domainNotFound: NotFoundResp = NotFoundResp(reason=f"ID '{id}' not found")
      return JSONResponse(content=domainNotFound.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_404_NOT_FOUND)
    cursor.execute(f"SELECT ip_address, addr_type, ros_comment FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id = ?;",
                   (id, ))
    ipAddrRaw = cursor.fetchall()
    for ip in ipAddrRaw:
      if (ip[1] == 4):
        ipAddrV4.append(ip[0])
      if (ip[1] == 6):
        ipAddrV6.append(ip[0])
    connection.close()
    returnData: DomainElementResp = DomainElementResp(
      id=id,
      domains_list_id=domain[5],
      resolved=True if domain[0] == 1 else False,
      name=domain[1],
      ros_comment=domain[2],
      created_at=getTimestamp(domain[3]),
      updated_at=getTimestamp(domain[4]) if domain[4] != None else None,
      ips_v4=ipAddrV4 if len(ipAddrV4) > 0 else None,
      ips_v6=ipAddrV6 if len(ipAddrV6) > 0 else None
    )
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Add new domains
@app.post(
    tags=[DOMAINS_TAG],
    path='/domains',
    name='Add new Domains',
    description='Allows you to add the required domain names through an array with parameters',
    status_code=status.HTTP_200_OK,
    response_model=list[DomainsPostElementResp],
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
    }
  )
async def domains_add(data: Annotated[list[DomainsPostElement], Body(examples=domainsPostBodyExamples)]):
  logger.debug(f'Call API route: POST /domains')
  try:
    if (len(data) < 1):
      return JSONResponse(NoDataResp().model_dump(mode='json', exclude_none=True), status.HTTP_400_BAD_REQUEST)
    returnData: list[dict[str, Any]] = list()
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    for domainItem in data:
      domain = domainItem.domain
      rosComment = domainItem.ros_comment
      try:
        cursor.execute(f"INSERT INTO '{DOMAINS_TABLE_NAME}' (name, ros_comment) VALUES (?,?);", (domain, rosComment))
        domainId = cursor.lastrowid
        if (domainId == None or domainId < 1):
          raise Exception(f'Error get domainId for "{domain}". Result: {domainId}')
        returnData.append(DomainsPostElementResp(domain=domain, id=domainId).model_dump(mode='json', exclude_none=True))
      except Exception as err:
        returnData.append(DomainsPostElementResp(domain=domain, error=str(err)).model_dump(mode='json', exclude_none=True))
    connection.commit()
    connection.close()
    return JSONResponse(content=returnData, status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All Domains
# WARN. DANGER ZONE !!!
# Additional clear ALL IP addr, NS servers, CNAMEs
@app.delete(
    tags=[DOMAINS_TAG],
    path='/internal/domains/all',
    name='Clear All Domains records (WARNING!!!)',
    description='Clear All Domains records. But not default record id=-1',
    response_model=DomainDeleteResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def domains_remove_all():
  logger.debug(f'Call API route: DELETE /internal/domains/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    # not delete default domain
    cursor.execute(f"DELETE FROM '{DOMAINS_TABLE_NAME}' WHERE id > 0;")
    countResult = cursor.execute('SELECT changes();')
    countDomains = countResult.fetchone()[0]
    cursor.execute(f"DELETE FROM '{IP_RECORDS_TABLE_NAME}' WHERE domain_id > 0;")
    countResult = cursor.execute('SELECT changes();')
    countIps = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: DomainDeleteResp = DomainDeleteResp(
      count_domain=countDomains,
      count_ip_address=countIps
    )
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete domain on ID
@app.delete(
    tags=[DOMAINS_TAG],
    path='/domains/{id}',
    name='Delete once Domain name record',
    description='Delete once Domain name record',
    response_model=DomainDeleteResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def domain_remove(id: Annotated[int, Path(gt=0, title='Domain record ID')]):
  logger.debug(f'Call API route: DELETE /domains/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      DELETE FROM '{DOMAINS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countDomains = countResult.fetchone()[0]
    cursor.execute(f"""
      DELETE FROM '{IP_RECORDS_TABLE_NAME}'
      WHERE domain_id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countIps = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: DomainDeleteResp = DomainDeleteResp(
      count_domain=countDomains,
      count_ip_address=countIps
    )
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# IP ADDRESSES LISTS
#

ipsListsPostBodyExamples = [
  [
    {
      'name': 'ips-list',
      'url': 'https://somedomain.som/path/path/path/some-ips-list'
    },
    {
      'name': 'ips-list-2',
      'url': 'https://somedomain.som/path/path/path/some-ips-list-2.txt',
      'description': 'Description for some ips address list'
    }
  ]
]

# Get all IP address lists
@app.get(
    tags=[IPS_LISTS_TAG],
    path='/ips/lists',
    name='Get all IP address lists',
    description='Displays all IP address lists records',
    response_model=IpAddrListsPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_all_ips_addr_lists(query: Annotated[LimitOffsetQuery, Query()]):
  logger.debug(f'Call API route: GET /ips/lists')
  try:
    returnData: IpAddrListsPayloadResp = IpAddrListsPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(id) FROM '{IPS_LISTS_TABLE_NAME}';")
    ipsListsSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT id, name, url, description, hash, created_at, updated_at
      FROM '{IPS_LISTS_TABLE_NAME}'
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    ipsListsAll = cursor.fetchall()
    for ipsList in ipsListsAll:
      returnData.payload.append(IpAddrListsElementResp(
        id=ipsList[0],
        name=ipsList[1],
        url=ipsList[2],
        description=ipsList[3],
        hash=ipsList[4],
        created_at=getTimestamp(ipsList[5]),
        updated_at=getTimestamp(ipsList[6]) if ipsList[6] != None else None
      ))
    returnData.count = len(returnData.payload)
    returnData.total = ipsListsSize
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Get IP address list info on ID
@app.get(
    tags=[IPS_LISTS_TAG],
    path='/ips/lists/{id}',
    name='Get once IP address list',
    description='Displays once IP address list record on ID',
    response_model=IpAddrListsElementResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
    }
  )
async def get_ip_addr_list_on_id(id: Annotated[int, Path(gt=0, title='IP address list record ID')]):
  logger.debug(f'Call API route: GET /ips/lists/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT id, name, url, description, hash, created_at, updated_at
      FROM '{IPS_LISTS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    ipsAddrList = cursor.fetchone()
    connection.close()
    if ipsAddrList == None:
      ipsAddrListNotFound: NotFoundResp = NotFoundResp(reason=f"ID '{id}' not found")
      return JSONResponse(content=ipsAddrListNotFound.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_404_NOT_FOUND)
    ipsAddrListElement: IpAddrListsElementResp = IpAddrListsElementResp(
      id=ipsAddrList[0],
      name=ipsAddrList[1],
      url=ipsAddrList[2],
      description=ipsAddrList[3],
      hash=ipsAddrList[4],
      created_at=getTimestamp(ipsAddrList[5]),
      updated_at=getTimestamp(ipsAddrList[6]) if ipsAddrList[6] != None else None
    )
    return JSONResponse(content=ipsAddrListElement.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Add new IP address lists
@app.post(
    tags=[IPS_LISTS_TAG],
    path='/ips/lists',
    name='Add new IP address lists',
    description='Add new IP address lists URL for download',
    status_code=status.HTTP_200_OK,
    response_model=list[IpAddrListsPostElementResp],
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
    }
  )
async def ips_addr_lists_add(data: Annotated[list[IpAddrListsPostElement], Body(examples=domainsListsPostBodyExamples)]):
  logger.debug(f'Call API route: POST /ips/lists')
  try:
    if (len(data) < 1):
      return JSONResponse(NoDataResp().model_dump(mode='json', exclude_none=True), status.HTTP_400_BAD_REQUEST)
    returnData: list[dict[str, Any]] = list()
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    for ipsAddrListItem in data:
      try:
        cursor.execute(f"INSERT INTO '{IPS_LISTS_TABLE_NAME}' (name, url, description) VALUES (?,?,?);",
          (ipsAddrListItem.name, ipsAddrListItem.url, ipsAddrListItem.description))
        ipsAddrListId = cursor.lastrowid
        if (ipsAddrListId == None or ipsAddrListId < 1):
          raise Exception(f"Error get domainsListId for '{ipsAddrListItem.name}'. Result: {ipsAddrListId}")
        returnData.append(IpAddrListsPostElementResp(name=ipsAddrListItem.name, id=ipsAddrListId).model_dump(mode='json', exclude_none=True))
      except Exception as err:
        returnData.append(IpAddrListsPostElementResp(name=ipsAddrListItem.name, error=str(err)).model_dump(mode='json', exclude_none=True))
    connection.commit()
    connection.close()
    return JSONResponse(content=returnData, status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All IP address lists
# WARN. DANGER ZONE !!!
@app.delete(
    tags=[IPS_LISTS_TAG],
    path='/internal/ips/lists/all',
    name='Delete all IP address lists records',
    description='Delete all IP address lists records',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ips_addr_lists_remove_all():
  logger.debug(f'Call API route: DELETE /internal/ips/lists/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    # not delete default dns
    cursor.execute(f"DELETE FROM '{IPS_LISTS_TABLE_NAME}';")
    countResult = cursor.execute('SELECT changes();')
    count = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: IpsDeleteResp = IpsDeleteResp(count=count)
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete once IP address list
@app.delete(
    tags=[IPS_LISTS_TAG],
    path='/ips/lists/{id}',
    name='Delete once IP address list',
    description='Delete once IP address list record',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ip_addr_list_remove(id: Annotated[int, Path(gt=0, title='IP address list record ID')]):
  logger.debug(f'Call API route: DELETE /ips/lists/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      DELETE FROM '{IPS_LISTS_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countDelete = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    return JSONResponse(OkStatusResp(count=countDelete).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# IP ADDRESSES
#

# Get all IPs infos
@app.get(
    tags=[IPS_TAG],
    path='/ips',
    name='Get all IP address records',
    description='Displays all available IP address records',
    response_model=IpsPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_all_ips(query: Annotated[IpsQuery, Query()]):
  logger.debug(f'Call API route: GET /ips')
  whereSql = ''
  try:
    returnData: IpsPayloadResp = IpsPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    if query.type != None and query.start_date == None and query.end_date == None:
      whereSql = f"WHERE ir.addr_type = {query.type}"
    elif query.type == None and query.start_date != None and query.end_date != None:
      whereSql = f"WHERE unixepoch(ir.created_at) >= unixepoch('{query.start_date}') AND unixepoch(ir.created_at) < unixepoch('{query.end_date}')"
    elif query.type != None and query.start_date != None and query.end_date != None:
      whereSql = f"WHERE ir.addr_type = {query.type} AND unixepoch(ir.created_at) >= unixepoch('{query.start_date}') AND unixepoch(ir.created_at) < unixepoch('{query.end_date}')"
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(id) FROM '{IP_RECORDS_TABLE_NAME}' AS ir {whereSql};")
    ipsSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT
        d.name,
        d.ros_comment,
        ir.addr_type,
        ir.ip_address,
        ir.ros_comment,
        ir.created_at,
        ir.id,
        ir.ip_list_id,
        ipl.name,
        ir.domain_id
      FROM '{IP_RECORDS_TABLE_NAME}' AS ir
      LEFT JOIN '{DOMAINS_TABLE_NAME}' AS d ON d.id = ir.domain_id
      LEFT JOIN '{IPS_LISTS_TABLE_NAME}' AS ipl ON ipl.id = ir.ip_list_id
      {whereSql}
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    ips = cursor.fetchall()
    for ip in ips:
      if (ip[4] != None):
        rosComment = ip[4]
      elif (ip[1] != None):
        rosComment = ip[1]
      else:
        rosComment = ''
      returnData.payload.append(IpsElementResp(
        id=ip[6],
        domain=ip[0],
        domain_id=ip[9],
        ros_comment=rosComment,
        type=ip[2],
        addr=ip[3],
        created_at=getTimestamp(ip[5]),
        ip_list_id=ip[7],
        ip_list_name=ip[8]
      ))
    returnData.count = len(returnData.payload)
    returnData.total = ipsSize
    connection.close()
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Get IP address info on ID
@app.get(
    tags=[IPS_TAG],
    path='/ips/{id}',
    name='Get IP addres record on ID',
    description='Displays all available IP address records',
    response_model=IpsElementResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
    }
  )
async def get_ip_addr(id: Annotated[int, Path(gt=0, title='IP address record ID')]):
  logger.debug(f'Call API route: GET /ips/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT
        d.name,
        ir.addr_type,
        ir.ip_address,
        ir.ros_comment,
        ir.created_at,
        ir.ip_list_id,
        ipl.name,
        ir.domain_id 
      FROM '{IP_RECORDS_TABLE_NAME}' AS ir
      LEFT JOIN '{DOMAINS_TABLE_NAME}' AS d ON d.id = ir.domain_id
      LEFT JOIN '{IPS_LISTS_TABLE_NAME}' AS ipl ON ipl.id = ir.ip_list_id
      WHERE ir.id = ?;""", (id, ))
    ip = cursor.fetchone()
    if ip == None:
      ipNotFound: NotFoundResp = NotFoundResp(reason=f"ID '{id}' not found")
      return JSONResponse(content=ipNotFound.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_404_NOT_FOUND)
    connection.close()
    returnData: IpsElementResp = IpsElementResp(
      id=id,
      domain=ip[0],
      domain_id=ip[7],
      ros_comment=ip[3],
      type=ip[1],
      addr=ip[2],
      created_at=getTimestamp(ip[4]),
      ip_list_id=ip[5],
      ip_list_name=ip[6]
    )
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Add new IP or IP/subnet without Domain
@app.post(
    tags=[IPS_TAG],
    path='/ips',
    name='Add new IP address records',
    description='Adds new IP address records. New IPs link to default domain at ID = -1',
    status_code=status.HTTP_200_OK,
    response_model=list[IpsPostElementResp],
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
    }
  )
async def ips_add(data: Annotated[list[str], Body(examples=[['1.1.1.1', '9.9.9.9']])]):
  logger.debug(f'Call API route: POST /ips/add')
  try:
    if (len(data) < 1):
      return JSONResponse(NoDataResp().model_dump(mode='json', exclude_none=True), status.HTTP_400_BAD_REQUEST)
    returnData: list[dict[str, Any]] = list()
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    for ip in data:
      try:
        ipVersion = getIpVersion(ip)
        if ipVersion not in [4, 6]:
          raise Exception(f"IP '{ip}' incorrect")
        cursor.execute(f"INSERT INTO '{IP_RECORDS_TABLE_NAME}' (domain_id, addr_type, ip_address) VALUES (?,?,?);", (-1, ipVersion, ip))
        insertIpId = cursor.lastrowid
        if (insertIpId == None or insertIpId < 1):
          raise Exception(f'Error get insertIpId for "{ip}". Result: {insertIpId}')
        returnData.append(IpsPostElementResp(ip=ip, id=insertIpId).model_dump(mode='json', exclude_none=True))
      except Exception as err:
        returnData.append(IpsPostElementResp(ip=ip, error=str(err)).model_dump(mode='json', exclude_none=True))
    connection.commit()
    connection.close()
    return JSONResponse(content=returnData, status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All IP addresses
# WARN. DANGER ZONE !!!
@app.delete(
    tags=[IPS_TAG],
    path='/internal/ips/all',
    name='Delete all IP address records',
    description='Delete all IP address records',
    response_model=IpsDeleteResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ips_remove_all():
  logger.debug(f'Call API route: DELETE /internal/ips/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    # not delete default dns
    cursor.execute(f"DELETE FROM '{IP_RECORDS_TABLE_NAME}';")
    countResult = cursor.execute('SELECT changes();')
    count = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: IpsDeleteResp = IpsDeleteResp(count=count)
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete IP addr on ID or Address
@app.delete(
    tags=[IPS_TAG],
    path='/ips',
    name='Delete once IP address record (ip or id over query param)',
    description='Delete once IP address record on ID or IP',
    response_model=IpsDeleteResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ip_remove_on_id_or_addr(query: Annotated[IpsDeleteQuery, Query()]):
  logger.debug(f'Call API route: DELETE /ips for ip={query.ip}, id={query.id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    if query.id != None:
      cursor.execute(f"""
        DELETE FROM '{IP_RECORDS_TABLE_NAME}'
        WHERE id = ?;
      """, (query.id, ))
    if query.ip != None:
      cursor.execute(f"""
        DELETE FROM '{IP_RECORDS_TABLE_NAME}'
        WHERE ip_address = ?;
      """, (query.ip, ))
    countResult = cursor.execute('SELECT changes();')
    count = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: IpsDeleteResp = IpsDeleteResp(count=count)
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# ROS CONFIGS
#

rosConfigsPostBodyExamples = [
  [
    {
      "host": "192.168.200.1",
      "user": "test",
      "user_password": "1234",
      "bgp_list_name": "bgp-networks",
      "description": "Test CHR Host"
    }
  ]
]

# Get All ros configs (no connect, list in DB only)
@app.get(
    tags=[ROS_CONFIGS_TAG],
    path='/ros/configs',
    name='Get all Router OS configs',
    description='Displays all Router OS configs records. No connect tests',
    response_model=RosConfigPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_all_ros_configs(query: Annotated[LimitOffsetQuery, Query()]):
  logger.debug(f'Call API route: GET /ros/configs')
  try:
    returnData: RosConfigPayloadResp = RosConfigPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(id) FROM '{ROS_CONFIG_TABLE_NAME}'")
    rosConfigsSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT id, host, user, pass, bgp_list_name, description, created_at
      FROM '{ROS_CONFIG_TABLE_NAME}'
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    rosConfigs = cursor.fetchall()
    connection.close()
    for config in rosConfigs:
      returnData.payload.append(RosConfigElementResp(
        id=config[0],
        host=config[1],
        user=config[2],
        password=config[3],
        bgp_list_name=config[4],
        description=config[5],
        created_at=getTimestamp(config[6])
      ))
    returnData.count = len(returnData.payload)
    returnData.total = rosConfigsSize
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Get info for RoS config and Test connect to host
@app.get(
    tags=[ROS_CONFIGS_TAG],
    path='/ros/configs/{id}',
    name='info for RoS config',
    description='Get info for RoS config and Test connect to host',
    response_model=RosConfigConnElementResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_404_NOT_FOUND: {'model': NotFoundResp}
    }
  )
async def ros_get_and_check_config(id: Annotated[int, Path(gt=0, title='ROS config record ID')]):
  logger.debug(f'Call API route: GET /ros/configs/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      SELECT id, host, user, pass, bgp_list_name, description, created_at
      FROM '{ROS_CONFIG_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    rosConfig = cursor.fetchone()
    connection.close()
    if rosConfig == None:
      notFoundResult: NotFoundResp = NotFoundResp(reason=f"ID '{id}' not found")
      return JSONResponse(content=notFoundResult.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_404_NOT_FOUND)
    try:
      api = connectRos(rosConfig[1], rosConfig[2], rosConfig[3])
      query = tuple(api.path('system/resource').select(Key('version'), Key('uptime')))
      rosVersion = query[0]['version']
      rosUptime = query[0]['uptime']
      api.close()
      rosConnectResult: RosConnectResult = RosConnectResult(version=rosVersion, uptime=rosUptime)
    except Exception as err:
      rosConnectResult: RosConnectResult = RosConnectResult(connect_error=str(err))
    returnData: RosConfigConnElementResp = RosConfigConnElementResp(
      id=rosConfig[0],
      host=rosConfig[1],
      user=rosConfig[2],
      password=rosConfig[3],
      bgp_list_name=rosConfig[4],
      description=rosConfig[5],
      created_at=getTimestamp(rosConfig[6]),
      connect_result=rosConnectResult
    )
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Add new RouterOS host config
@app.post(
    tags=[ROS_CONFIGS_TAG],
    path='/ros/configs',
    name='Add Router OS configs',
    description='Adds new RouterOS configurations. IP address rollout will be applied to each configuration',
    response_model=list[RosConfigsPostElementResp],
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp},
      status.HTTP_400_BAD_REQUEST: {'model': NoDataResp}
    }
  )
async def ros_config_add(data: Annotated[list[RosConfigsPostElement], Body(examples=rosConfigsPostBodyExamples)]):
  logger.debug(f'Call API route: POST /ros/configs')
  try:
    if (len(data) < 1):
      return JSONResponse(NoDataResp().model_dump(mode='json', exclude_none=True), status.HTTP_400_BAD_REQUEST)
    returnData: list[dict[str, Any]] = list()
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    for rosConfig in data:
      try:
        cursor.execute(f"INSERT INTO '{ROS_CONFIG_TABLE_NAME}' (host, user, pass, bgp_list_name, description) VALUES (?,?,?,?,?);",
                        (rosConfig.host, rosConfig.user, rosConfig.user_password, rosConfig.bgp_list_name, rosConfig.description))
        rosId = cursor.lastrowid
        if (rosId == None or rosId < 1):
          raise Exception(f"Error get rosId for '{rosConfig.host}'. Result: {rosId}")
        returnData.append(RosConfigsPostElementResp(host=rosConfig.host, id=rosId).model_dump(mode='json', exclude_none=True))
      except Exception as err:
        returnData.append(RosConfigsPostElementResp(host=rosConfig.host, error=str(err)).model_dump(mode='json', exclude_none=True))
    connection.commit()
    connection.close()
    return JSONResponse(content=returnData, status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All RouterOS configs
# WARN. DANGER ZONE !!!
@app.delete(
    tags=[ROS_CONFIGS_TAG],
    path='/internal/ros/configs/all',
    name='Delete all RouterOS configs',
    description='Delete all RouterOS configs records',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ros_configs_remove_all():
  logger.debug(f'Call API route: DELETE /internal/ros/configs/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"DELETE FROM '{ROS_CONFIG_TABLE_NAME}';")
    countResult = cursor.execute('SELECT changes();')
    count = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: OkStatusResp = OkStatusResp(count=count)
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete Ros config
@app.delete(
    tags=[ROS_CONFIGS_TAG],
    path='/ros/configs/{id}',
    name='Delete once RouterOS config',
    description='Delete once RouterOS config record',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ros_config_remove(id: Annotated[int, Path(gt=0, title='ROS config record ID')]):
  logger.debug(f'Call API route: DELETE /ros/configs/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      DELETE FROM '{ROS_CONFIG_TABLE_NAME}'
      WHERE id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countDelete = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    return JSONResponse(OkStatusResp(count=countDelete).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# COMMANDS
#

# START resolve ALL domains
# TODO add force param
@app.post(
    tags=[COMMANDS_TAG],
    path='/commands/domains/resolve',
    name='Resolve domains',
    description='Start background task for resolve all domains',
    response_model=CommandStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def resolve_domains(background_tasks: BackgroundTasks):
  logger.debug(f'Call API route: POST /commands/domains/resolve')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(job_id) FROM '{JOB_TABLE_NAME}' WHERE name = '{JOBNAME_RESOLVE_DOMAINS}' AND end_at IS NULL;")
    jobCount = cursor.fetchone()[0]
    connection.close()
    if jobCount == 0:
      domainsQueue = Queue(maxsize=DEF_QUEUE_SIZE)
      dbQueue = Queue(maxsize=DEF_QUEUE_SIZE)
      threads = []
      for i in range(THREADS_COUNT):
        tName = f'thread-{i+1}'
        threads.append(tName)
        t: Thread = Thread(name=tName, target=consumer_ResolveDomains, args=(domainsQueue,dbQueue), daemon=True)
        t.start()
      t: Thread = Thread(name=f'thread-db', target=consumer_SaveDomainsData, args=(dbQueue,), daemon=True)
      t.start()
      background_tasks.add_task(backgroundTask_resolveDomains, domainsQueue)
      return JSONResponse(CommandStatusResp(
          status=f"Run background task 'resolve_domains' and job '{JOBNAME_RESOLVE_DOMAINS}'",
          threads=threads,
          threads_count = len(threads)
        ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
    else:
      return JSONResponse(CommandStatusResp(
          status=f"Job '{JOBNAME_RESOLVE_DOMAINS}' is maybe Run now",
          jobs=jobCount
        ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# START update firewall and routing into All Router OS
@app.post(
    tags=[COMMANDS_TAG],
    path='/commands/ros/update',
    name='Update firewall and routing at RouterOS devices',
    description='Update firewall address-list and routing records at all RouterOS devices(configs)',
    response_model=CommandStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def routeros_update(query: Annotated[RoSCommandQuery, Query()], background_tasks: BackgroundTasks):
  logger.debug(f'Call API route: POST /commands/ros/update')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(job_id) FROM '{JOB_TABLE_NAME}' WHERE name = '{JOBNAME_ROUTEROS_UPDATE}' AND end_at IS NULL;")
    jobCount = cursor.fetchone()[0]
    connection.close()
    if jobCount == 0:
      background_tasks.add_task(backgroundTask_routerOsUpdate, query.type)
      return JSONResponse(CommandStatusResp(
          status=f"Run background task 'routeros_update' and job '{JOBNAME_ROUTEROS_UPDATE}'"
        ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
    else:
      return JSONResponse(CommandStatusResp(
          status=f"Job '{JOBNAME_ROUTEROS_UPDATE}' is maybe Run now",
          jobs=jobCount
        ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Download domains lists
# Insert found domains in DB
@app.post(
    tags=[COMMANDS_TAG],
    path='/commands/domains/lists/load',
    name='Download domains lists',
    description='Start background task for download domains lists if hash files changed',
    response_model=CommandStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def domains_lists_load(query: Annotated[DomainListsCommandQuery, Query()], background_tasks: BackgroundTasks):
  logger.debug(f'Call API route: POST /commands/domains/lists/load')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(job_id) FROM '{JOB_TABLE_NAME}' WHERE name = '{JOBNAME_DOMAINS_LISTS_LOAD}' AND end_at IS NULL;")
    jobCount = cursor.fetchone()[0]
    connection.close()
    if jobCount == 0 or query.forced == True:
      background_tasks.add_task(backgroundTask_DomainsListsLoad, query.forced)
      return JSONResponse(CommandStatusResp(
        status=f"Run background task 'domains_lists_load' and job '{JOBNAME_DOMAINS_LISTS_LOAD}'"
      ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
    else:
      return JSONResponse(CommandStatusResp(
        status=f"Job '{JOBNAME_DOMAINS_LISTS_LOAD}' is maybe Run now",
        jobs=jobCount
      ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Download IP address lists
# Insert found IPs in DB
@app.post(
    tags=[COMMANDS_TAG],
    path='/commands/ips/lists/load',
    name='Download IP address lists',
    description='Start background task for download IP address lists if hash files changed',
    response_model=CommandStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def ips_addr_lists_load(query: Annotated[IpAddrListsCommandQuery, Query()], background_tasks: BackgroundTasks):
  logger.debug(f'Call API route: POST /commands/ips/lists/load')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(job_id) FROM '{JOB_TABLE_NAME}' WHERE name = '{JOBNAME_IP_ADDR_LISTS_LOAD}' AND end_at IS NULL;")
    jobCount = cursor.fetchone()[0]
    connection.close()
    if jobCount == 0 or query.forced == True:
      background_tasks.add_task(backgroundTask_IpAddrListsLoad, query.forced)
      return JSONResponse(CommandStatusResp(
        status=f"Run background task 'ips_addr_lists_load' and job '{JOBNAME_IP_ADDR_LISTS_LOAD}'"
      ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
    else:
      return JSONResponse(CommandStatusResp(
        status=f"Job '{JOBNAME_IP_ADDR_LISTS_LOAD}' is maybe Run now",
        jobs=jobCount
      ).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

#
# JOBS
#

# Get jobs
@app.get(
    tags=[JOBS_TAG],
    path='/jobs',
    name='Get all background jobs',
    description='Get all background jobs records',
    response_model=JobsPayloadResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def get_jobs(query: Annotated[JobsLimitOffsetQuery, Query()]):
  logger.debug(f'Call API route: GET /jobs')
  startedSql = ''
  try:
    returnData: JobsPayloadResp = JobsPayloadResp(
      limit=query.limit,
      offset=query.offset
    )
    if (query.in_progress != None):
      startedSql = f'WHERE end_at IS {'NULL' if query.in_progress == True else 'NOT NULL'}'
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(job_id) FROM '{JOB_TABLE_NAME}' {startedSql};")
    jobsTotalSize = cursor.fetchone()[0]
    cursor.execute(f"""
      SELECT job_id, name, started_at, end_at
      FROM '{JOB_TABLE_NAME}'
      {startedSql}
      LIMIT ? OFFSET ?;
    """, (query.limit, query.offset))
    jobs = cursor.fetchall()
    connection.close()
    for job in jobs:
      returnData.payload.append(JobsElementResp(
        job_id=job[0],
        name=job[1],
        started_at=getTimestamp(job[2]),
        end_at=getTimestamp(job[3]) if job[3] != None else None
      ))
    returnData.count = len(returnData.payload)
    returnData.total = jobsTotalSize
    return JSONResponse(content=returnData.model_dump(mode='json'), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Delete Job on ID
# TODO Stop linked threads if job removed
@app.delete(
    tags=[JOBS_TAG],
    path='/jobs/{id}',
    name='Delete background job',
    description='Delete background job records on ID',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def job_remove(id: Annotated[int, Path(gt=0, title='JOB ID')]):
  logger.debug(f'Call API route: DELETE /jobs/{id}')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"""
      DELETE FROM '{JOB_TABLE_NAME}'
      WHERE job_id = ?;
    """, (id, ))
    countResult = cursor.execute('SELECT changes();')
    countDelete = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    return JSONResponse(OkStatusResp(count=countDelete).model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

# Clear All Jobs
# TODO Stop all linked threads
# WARN. DANGER ZONE !!!
@app.delete(
    tags=[JOBS_TAG],
    path='/internal/jobs/all',
    name='Delete all Jobs',
    description='Delete all Jobs records',
    response_model=OkStatusResp,
    responses={
      status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResp}
    }
  )
async def jobs_remove_all():
  logger.debug(f'Call API route: DELETE /internal/jobs/all')
  try:
    connection = db.connect(database=SQLITE_DB, timeout=DB_TIMEOUT)
    cursor = connection.cursor()
    cursor.execute(f"DELETE FROM '{JOB_TABLE_NAME}';")
    countResult = cursor.execute('SELECT changes();')
    count = countResult.fetchone()[0]
    connection.commit()
    connection.close()
    returnData: OkStatusResp = OkStatusResp(count=count)
    return JSONResponse(content=returnData.model_dump(mode='json', exclude_none=True), status_code=status.HTTP_200_OK)
  except Exception as err:
    return errorResp(err)

########################################################################################################################
# APP RUN
########################################################################################################################

if __name__ == '__main__':
  print(f'main.py run')
  asyncio.run(main())
