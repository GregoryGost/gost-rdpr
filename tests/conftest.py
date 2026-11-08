"""Fixtures for isolated unit/integration tests and real service E2E processes."""

import asyncio
import ctypes
import importlib
import inspect
import json
import logging
import os
import shutil
import socket
import sys
from base64 import urlsafe_b64decode
from collections import Counter
from contextlib import closing, contextmanager
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import dotenv
import httpx
import pytest
from pydantic_settings.sources import DotEnvSettingsSource

_coverage_migration_directories = set()


def observe_child_tasks():
  """Install transparent task accounting without replacing application behavior."""
  original = asyncio.BaseEventLoop.create_task
  evidence = {'peak_active_tasks': 0, 'created_by_coroutine': {}}

  def create_task(self, coro, *args, **kwargs):
    task = original(self, coro, *args, **kwargs)
    name = getattr(coro, '__qualname__', type(coro).__name__)
    counts = evidence['created_by_coroutine']
    counts[name] = counts.get(name, 0) + 1
    evidence['peak_active_tasks'] = max(evidence['peak_active_tasks'], len(asyncio.all_tasks(self)))
    return task

  asyncio.BaseEventLoop.create_task = create_task
  return evidence


def normalize_migration_coverage(data, root, directories):
  """Merge identical migration copies and exclude test-owned migration fault code."""
  from coverage import CoverageData

  root = Path(root).resolve()
  directories = {Path(directory).resolve() for directory in directories}
  paths = {}
  for filename in data.measured_files():
    source = Path(filename).resolve()
    if source.is_relative_to(root) or source.parent not in directories:
      paths[filename] = filename
      continue
    original = root / 'migrations' / source.name
    if (
      original.is_file()
      and source.is_file()
      and sha256(original.read_bytes()).digest() == sha256(source.read_bytes()).digest()
    ):
      paths[filename] = str(original)
  if paths == {filename: filename for filename in data.measured_files()}:
    return

  has_arcs = data.has_arcs()
  read = data.arcs if data.has_arcs() else data.lines
  # Preserve even unexecuted files, branch entry/exit arcs, and exact context names.
  contexts = {}
  for context in data.measured_contexts():
    data.set_query_context(context)
    measurements = contexts[context] = {}
    for filename, target in paths.items():
      values = read(filename)
      if values:
        measurements.setdefault(target, set()).update(values)
  data.set_query_contexts(None)
  tracers = {target: data.file_tracer(filename) for filename, target in paths.items()}
  data.erase()
  # A fresh data object also writes the branch/line metadata after the old file is erased.
  replacement = CoverageData(basename=data.data_filename())
  add = replacement.add_arcs if has_arcs else replacement.add_lines
  add({})
  replacement.touch_files(set(paths.values()))
  replacement.add_file_tracers(tracers)
  for context, measurements in contexts.items():
    replacement.set_context(context)
    add(measurements)
  replacement.write()
  replacement.close()
  data.read()


@pytest.hookimpl(wrapper=True, trylast=True)
def pytest_runtestloop(session):
  """Normalize parent data after fixture teardown, before pytest-cov combines children."""
  result = yield
  from coverage import Coverage

  coverage = Coverage.current()
  if coverage is not None:
    coverage.stop()
    normalize_migration_coverage(
      coverage.get_data(), Path(__file__).resolve().parents[1], _coverage_migration_directories
    )
  return result


@pytest.fixture
async def app(tmp_path, monkeypatch):
  """Prevent secret-file reads and production I/O before importing globals."""
  real_http_send = httpx.AsyncHTTPTransport.handle_async_request
  _coverage_migration_directories.add(tmp_path / 'migrations')
  monkeypatch.setattr(dotenv, 'load_dotenv', lambda *args, **kwargs: False)
  monkeypatch.setattr(DotEnvSettingsSource, '_read_env_files', lambda self: {})
  monkeypatch.setenv('DB_BASE_DIR', str(tmp_path))
  monkeypatch.setenv('DB_FILE_NAME', 'import-only.sqlite')
  monkeypatch.setenv('DB_TABLE_PREFIX', 'rdpr_')
  monkeypatch.setenv('DOMAINS_UPDATE_INTERVAL', '172800')
  monkeypatch.setenv('IP_NOT_ALLOWED', '127.0.0.0/8')
  monkeypatch.setenv('ROOT_LOG_LEVEL', 'error')
  monkeypatch.chdir(tmp_path)

  async def reject_http(*args, **kwargs):
    raise AssertionError('Unexpected real HTTP transport')

  async def reject_dns(*args, **kwargs):
    raise AssertionError('Unexpected real DNS transport')

  monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', reject_http)
  monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', reject_dns)
  root_logger = logging.getLogger()
  previous_handlers = list(root_logger.handlers)
  previous_level = root_logger.level
  config = importlib.import_module('config.config')
  monkeypatch.setattr(config.settings, 'db_base_dir', str(tmp_path))
  monkeypatch.setattr(config.settings, 'db_file_name', 'isolated.sqlite')
  monkeypatch.setattr(config.settings, 'domains_update_interval', 172800)
  monkeypatch.setattr(config.settings, 'ip_not_allowed', '127.0.0.0/8')
  database = importlib.import_module('database.db')
  resolver = importlib.import_module('client.domains_resolving_client')
  monkeypatch.setattr(resolver, 'saving_coordinator', resolver.SavingCoordinator())
  for name in ('server.server', 'routers.commands_router', 'routers.domains_router'):
    if name in sys.modules:
      monkeypatch.setattr(sys.modules[name], 'saving_coordinator', resolver.saving_coordinator)
  dto = importlib.import_module('models.dto.domains_dto')
  server_dto = importlib.import_module('models.dto.dns_server_dto')
  ip_dto = importlib.import_module('models.dto.ip_record_dto')
  ripe = importlib.import_module('client.ripe_stat_client')
  cache = importlib.import_module('cache.cache').ripe_stat_cache
  await cache.clear()
  clients = []

  def make_http(handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    clients.append(client)
    return client

  value = SimpleNamespace(
    database=database,
    resolver=resolver,
    dto=dto,
    settings=config.settings,
    Server=server_dto.DnsServerDto,
    Ip=ip_dto.IpRecordDto,
    ripe=ripe,
    make_http=make_http,
    real_http_send=real_http_send,
  )
  try:
    yield value
  finally:
    await resolver.saving_coordinator.stop()
    try:
      await resolver.saving_coordinator.finish_close()
    except database.DatabaseWriteError:
      # Persistence fault tests already assert the retained failure; bookkeeping still retires in finally.
      pass
    for client in clients:
      await client.aclose()
    await cache.clear()
    await cache.cache.close()
    await resolver.HttpClient.close()
    await database.db._DataBase__read_engine.dispose()
    await database.db._DataBase__write_engine.dispose()
    for handler in root_logger.handlers[:]:
      if handler not in previous_handlers:
        root_logger.removeHandler(handler)
        handler.close()
    root_logger.setLevel(previous_level)


@pytest.fixture
def resolver(app):
  instance = app.resolver.DomainsResolver()
  instance._DomainsResolver__semaphore = asyncio.Semaphore(4)
  instance._DomainsResolver__ripe_stat_semaphore = asyncio.Semaphore(1)
  return instance


@pytest.fixture
def repository(app, monkeypatch):
  queue_dto = importlib.import_module('models.dto.queue_dto')

  async def confirmed(domain):
    if domain.write_receipt is None:
      domain.write_receipt = queue_dto.WriteReceipt()
    domain.write_receipt.mark_admitted()
    domain.write_receipt.set_outcome(queue_dto.WriteOutcome.CONFIRMED)

  boundary = SimpleNamespace(
    get_all_ips_for_domain=AsyncMock(return_value=[]),
    put_domain_after_resolve=AsyncMock(side_effect=confirmed),
    put_add_domains_to_queue=AsyncMock(),
    get_dns_servers_for_resolve=AsyncMock(return_value=([], [])),
    writer_failure=None,
    writer_wakeups=set(),
    wait_closed_cleanup=AsyncMock(),
  )

  async def current_candidate(id, *, new=None):
    del new
    getter = getattr(boundary, 'get_domain_on_id', None)
    if getter is None:
      return None
    record = await getter(id=id)
    return (
      None
      if record is None
      else app.dto.DomainCandidate(id=record.id, name=record.name, list_id=record.domains_list_id)
    )

  boundary.get_domain_candidate_for_resolve = AsyncMock(side_effect=current_candidate)
  boundary.register_writer_failure_wakeup = boundary.writer_wakeups.add
  boundary.unregister_writer_failure_wakeup = boundary.writer_wakeups.discard
  monkeypatch.setattr(app.resolver, 'db', boundary)
  return boundary


@pytest.fixture
def dns_message():
  def build(kind='positive', query=None, addresses=('8.8.8.8',)):
    query = query or dns.message.make_query('www.example.test.', 'A')
    message = dns.message.make_response(query)
    owner = query.question[0].name.to_text()

    def add(section, name, rdtype, *values, rdclass='IN'):
      section.append(dns.rrset.from_text(name, 60, rdclass, rdtype, *values))

    if kind in {'positive', 'positive-unrelated', 'nxdomain-positive'}:
      add(message.answer, owner, 'A', *addresses)
    if kind == 'positive-unrelated':
      add(message.answer, 'stranger.invalid.', 'A', '9.9.9.9')
      add(message.additional, owner, 'A', '1.1.1.1')
      add(message.answer, 'stranger.invalid.', 'CNAME', 'bad.invalid.')
    if kind.startswith('alias') or kind == 'cname-only':
      add(message.answer, owner, 'CNAME', 'edge.example.test.')
    if kind == 'alias-positive':
      add(message.answer, 'edge.example.test.', 'A', *addresses)
    if kind == 'alias-chain-positive':
      add(message.answer, 'edge.example.test.', 'CNAME', 'terminal.example.test.')
      add(message.answer, 'terminal.example.test.', 'A', *addresses)
      add(message.answer, owner, 'CNAME', 'edge.example.test.')
      add(message.answer, 'unreachable.example.test.', 'CNAME', 'untrusted.example.test.')
    if kind in {'nxdomain', 'alias-nxdomain', 'nxdomain-positive', 'nxdomain-ns'}:
      message.set_rcode(dns.rcode.NXDOMAIN)
    if kind in {'nodata', 'alias-nodata', 'unrelated-negative', 'foreign-soa', 'wrong-soa-class'}:
      soa_owner = 'other.invalid.' if kind == 'foreign-soa' else 'example.test.'
      add(
        message.authority,
        soa_owner,
        'SOA',
        'ns.example.test. hostmaster.example.test. 1 60 60 60 60',
        rdclass='CH' if kind == 'wrong-soa-class' else 'IN',
      )
    if kind == 'unrelated-negative':
      add(message.answer, 'stranger.invalid.', 'A', '9.9.9.9')
    if kind in {'referral', 'nxdomain-ns'}:
      add(message.authority, 'example.test.', 'NS', 'ns.example.test.')
    if kind == 'servfail':
      message.set_rcode(dns.rcode.SERVFAIL)
    if kind == 'refused':
      message.set_rcode(dns.rcode.REFUSED)
    if kind == 'wrong-name':
      message.question = dns.message.make_query('other.invalid.', 'A').question
    if kind == 'wrong-type':
      message.question = dns.message.make_query(owner, 'AAAA').question
    if kind == 'wrong-class':
      message.question = dns.message.make_query(owner, 'A', rdclass='CH').question
    if kind == 'multiple-questions':
      message.question += dns.message.make_query('other.invalid.', 'A').question
    if kind == 'no-question':
      message.question = []
    if kind == 'not-response':
      message.flags &= ~dns.flags.QR
    if kind == 'truncated':
      message.flags |= dns.flags.TC
    if kind == 'wrong-opcode':
      message.set_opcode(dns.opcode.UPDATE)
    if kind == 'alias-cycle':
      add(message.answer, 'edge.example.test.', 'CNAME', owner)
    if kind == 'alias-address-collision':
      add(message.answer, owner, 'A', '8.8.4.4')
    if kind in {'alias-conflict', 'alias-duplicate'}:
      target = 'other.example.test.' if kind == 'alias-conflict' else 'edge.example.test.'
      add(message.answer, owner, 'CNAME', target)
      add(message.answer, 'edge.example.test.', 'A', *addresses)
    if kind == 'aaaa-only':
      add(message.answer, owner, 'AAAA', '2001:4860:4860::8888')
    if kind in {'chain-limit', 'chain-below-limit'}:
      length = dns.message.MAX_CHAIN - (kind == 'chain-below-limit')
      current = owner
      for index in range(length):
        target = f'edge{index}.example.test.'
        add(message.answer, current, 'CNAME', target)
        current = target
      add(message.answer, current, 'A', *addresses)
    return message

  return build


@pytest.fixture
def network(app, resolver, dns_message, monkeypatch):
  """Replace DNS/HTTP I/O, leaving the production classifier untouched."""
  requests = []

  def install(kinds, transport='classic', status=200, media='application/dns-message', mutate_wire=None):
    async def classic(boundary, qname, rdtype, **kwargs):
      requests.append((boundary.nameservers[0], rdtype))
      kind = kinds.get((boundary.nameservers[0], rdtype), kinds.get(boundary.nameservers[0]))
      if isinstance(kind, Exception):
        raise kind
      query = dns.message.make_query(qname, rdtype)
      message = dns_message(kind, query=query)
      wire = message.to_wire()
      message = dns.message.from_wire(wire)
      # Resolver.resolve owns transport validation; expose its response envelope.
      if kind in {'nodata', 'alias-nodata', 'empty', 'referral'}:
        raise dns.resolver.NoAnswer(response=message)
      if kind in {'nxdomain', 'alias-nxdomain'}:
        raise dns.resolver.NXDOMAIN(qnames=[query.question[0].name], responses={query.question[0].name: message})
      return SimpleNamespace(response=message)

    def doh(request):
      encoded = request.url.params['dns']
      query = dns.message.from_wire(urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
      requests.append((str(request.url.copy_with(query=None)), query.question[0].rdtype))
      endpoint = str(request.url.copy_with(query=None))
      kind = kinds.get((endpoint, query.question[0].rdtype), kinds.get(endpoint))
      if isinstance(kind, Exception):
        raise kind
      assert request.method == 'GET'
      assert request.headers['accept'] == 'application/dns-message'
      message = dns_message(kind, query=query)
      wire = message.to_wire()
      if mutate_wire is not None:
        wire = mutate_wire(wire)
      return httpx.Response(status, headers={'Content-Type': media}, content=wire)

    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', classic)
    resolver._DomainsResolver__http_client = app.make_http(doh)
    return requests

  return install


def load_cpu_kernel():
  """Configure pointer-sized Windows APIs without inspecting any other process."""
  if sys.platform != 'win32' or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise RuntimeError('Controlled CPU profiles require 64-bit Windows')
  from ctypes import wintypes

  kernel = ctypes.WinDLL('kernel32', use_last_error=True)
  kernel.GetCurrentProcess.restype = wintypes.HANDLE
  kernel.GetProcessAffinityMask.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_size_t)] * 2
  kernel.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
  kernel.GetLogicalProcessorInformationEx.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
  return kernel


def load_cpu_mask():
  kernel = load_cpu_kernel()
  process, system = ctypes.c_size_t(), ctypes.c_size_t()
  if not kernel.GetProcessAffinityMask(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(system)):
    raise ctypes.WinError(ctypes.get_last_error())
  if not process.value:
    raise RuntimeError('A single processor-group affinity is required')
  return process.value


def load_set_cpu_mask(mask):
  kernel = load_cpu_kernel()
  if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), mask):
    raise ctypes.WinError(ctypes.get_last_error())
  effective = load_cpu_mask()
  if effective != mask:
    raise RuntimeError(f'CPU affinity mismatch: requested {mask:#x}, effective {effective:#x}')
  return effective


def load_cpu_topology():
  """Read native core classes; higher EfficiencyClass means greater performance."""
  from ctypes import wintypes

  kernel = load_cpu_kernel()
  length = wintypes.DWORD()
  if kernel.GetLogicalProcessorInformationEx(0, None, ctypes.byref(length)) or ctypes.get_last_error() != 122:
    raise RuntimeError('Cannot size native CPU topology')
  buffer = ctypes.create_string_buffer(length.value)
  if not kernel.GetLogicalProcessorInformationEx(0, buffer, ctypes.byref(length)):
    raise ctypes.WinError(ctypes.get_last_error())
  raw = buffer.raw[: length.value]
  cores = []
  offset = 0
  while offset < len(raw):
    relationship = int.from_bytes(raw[offset : offset + 4], 'little')
    size = int.from_bytes(raw[offset + 4 : offset + 8], 'little')
    if relationship != 0 or size < 48 or offset + size > len(raw):
      raise RuntimeError('Invalid native processor-core topology')
    group_count = int.from_bytes(raw[offset + 30 : offset + 32], 'little')
    group = int.from_bytes(raw[offset + 40 : offset + 42], 'little')
    if group_count != 1 or group != 0:
      raise RuntimeError('Controlled CPU profiles support only one processor group')
    cores.append(
      {'efficiency_class': raw[offset + 9], 'mask': int.from_bytes(raw[offset + 32 : offset + 40], 'little')}
    )
    offset += size
  return cores


def load_cpu_profile_mask(profile, topology, allowed):
  if profile not in {'performance', 'efficiency'}:
    raise ValueError(f'Unknown controlled CPU profile: {profile}')
  classes = {core['efficiency_class'] for core in topology}
  if len(classes) < 2:
    raise RuntimeError('Requested CPU class is unavailable: heterogeneous core classes are required')
  selected = max(classes) if profile == 'performance' else min(classes)
  mask = 0
  for core in topology:
    if core['efficiency_class'] == selected:
      mask |= core['mask'] & allowed
  if not mask:
    raise RuntimeError(f'Requested CPU profile {profile} has no allowed logical processors')
  return mask


class ServiceProcess:
  """Run the real entrypoint with disposable settings and graceful shutdown."""

  db_path: Path
  providers: SimpleNamespace
  dns_host: str
  doh_url: str
  provider_url: str
  load_mode: bool

  def __init__(self, root, directory, environment):
    self.root = root
    self.directory = directory
    self.environment = environment
    self.process = None
    self.log_path = directory / 'application.log'
    self.log = None
    self.startup_attempts = []
    self.cpu_evidence = None

  @contextmanager
  def cpu_profile(self, profile):
    """Scope CPU changes to this pytest process and its test-owned application children."""
    if profile not in {'unrestricted', 'performance', 'efficiency'}:
      raise ValueError(f'Unknown CPU profile: {profile}')
    if self.process is not None:
      raise RuntimeError('Select a CPU profile before application startup')
    original = None
    evidence = {'profile': profile, 'runner_pid': os.getpid(), 'affinity_changed': False, 'requested_mask': None}
    self.cpu_evidence = evidence
    previous = self.environment.get('TEST_CPU_PROFILE')
    try:
      if profile != 'unrestricted':
        original = load_cpu_mask()
        topology = load_cpu_topology()
        requested = load_cpu_profile_mask(profile, topology, original)
        evidence.update(topology=topology, original_mask=original, requested_mask=requested)
        evidence['selected_logical_cpus'] = [
          index for index in range(requested.bit_length()) if requested & (1 << index)
        ]
        evidence['selected_efficiency_class'] = (
          max(core['efficiency_class'] for core in topology)
          if profile == 'performance'
          else min(core['efficiency_class'] for core in topology)
        )
        evidence['effective_mask'] = load_set_cpu_mask(requested)
        evidence['affinity_changed'] = True
      elif sys.platform == 'win32':
        evidence.update(original_mask=load_cpu_mask(), topology=load_cpu_topology())
        evidence['requested_mask'] = None
        evidence['effective_mask'] = evidence['original_mask']
      self.environment['TEST_CPU_PROFILE'] = json.dumps(evidence)
      yield evidence
    finally:
      primary = sys.exception()
      try:
        if original is not None:
          evidence['restored_mask'] = load_set_cpu_mask(original)
      except (OSError, RuntimeError) as error:
        evidence['restore_error'] = repr(error)
        if primary is None:
          raise
        primary.add_note(f'CPU affinity restoration failed: {error!r}')
      finally:
        if previous is None:
          self.environment.pop('TEST_CPU_PROFILE', None)
        else:
          self.environment['TEST_CPU_PROFILE'] = previous

  def select_source(self, root):
    """Bind entrypoint, imports and startup migrations to one generated source snapshot."""
    if self.process is not None:
      raise RuntimeError('Cannot replace source while the application is running')
    root = Path(root).resolve()
    artifact_root = Path(__file__).resolve().parents[1] / '.pytest_cache'
    if not root.is_relative_to(artifact_root.resolve()) or not (root / 'main.py').is_file():
      raise ValueError('Comparison source must be a generated snapshot inside .pytest_cache')
    migration_source = root / 'migrations'
    if not migration_source.is_dir() or not (root / 'config/config.py').is_file():
      raise ValueError('Comparison source is missing configuration or migrations')
    target = self.directory / 'migrations'
    for path in target.glob('*.py'):
      path.unlink()
    for path in migration_source.glob('*.py'):
      shutil.copy2(path, target / path.name)
    self.root = root
    self.environment['PYTHONPATH'] = str(root)
    self.environment['TEST_SOURCE_EVIDENCE'] = str(self.directory / 'executed-source.json')

  def diagnostics(self):
    return self.log_path.read_text(encoding='utf-8', errors='replace') if self.log_path.exists() else ''

  def resource_snapshot(self, application_pid):
    """Read the actual child's CPU time and resident memory from its operating system."""
    assert self.process is not None
    assert self.process.returncode is None
    pid = application_pid
    if sys.platform == 'win32':
      from ctypes import wintypes

      class MemoryCounters(ctypes.Structure):
        _fields_ = [
          ('cb', wintypes.DWORD),
          ('PageFaultCount', wintypes.DWORD),
          ('PeakWorkingSetSize', ctypes.c_size_t),
          ('WorkingSetSize', ctypes.c_size_t),
          ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
          ('QuotaPagedPoolUsage', ctypes.c_size_t),
          ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
          ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
          ('PagefileUsage', ctypes.c_size_t),
          ('PeakPagefileUsage', ctypes.c_size_t),
        ]

      kernel = ctypes.WinDLL('kernel32', use_last_error=True)
      psapi = ctypes.WinDLL('psapi', use_last_error=True)
      kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
      kernel.OpenProcess.restype = wintypes.HANDLE
      kernel.CloseHandle.argtypes = [wintypes.HANDLE]
      kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
      psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
      handle = kernel.OpenProcess(0x1000 | 0x0010, False, pid)
      if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
      try:
        times = [wintypes.FILETIME() for _ in range(4)]
        memory = MemoryCounters()
        memory.cb = ctypes.sizeof(memory)
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
          raise ctypes.WinError(ctypes.get_last_error())
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), ctypes.sizeof(memory)):
          raise ctypes.WinError(ctypes.get_last_error())
        cpu = sum((value.dwHighDateTime << 32) + value.dwLowDateTime for value in times[2:]) / 10_000_000
        return {
          'pid': pid,
          'cpu_seconds': cpu,
          'rss_bytes': memory.WorkingSetSize,
          'peak_rss_bytes': memory.PeakWorkingSetSize,
          'source': 'Windows process APIs',
        }
      finally:
        kernel.CloseHandle(handle)
    if sys.platform.startswith('linux'):
      process_dir = Path('/proc') / str(pid)
      fields = (process_dir / 'stat').read_text(encoding='ascii').rsplit(')', 1)[1].split()
      status = dict(line.split(':', 1) for line in (process_dir / 'status').read_text(encoding='ascii').splitlines())
      cpu = (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
      rss = int(status['VmRSS'].split()[0]) * 1024
      peak_rss = int(status['VmHWM'].split()[0]) * 1024
      return {
        'pid': pid,
        'cpu_seconds': cpu,
        'rss_bytes': rss,
        'peak_rss_bytes': peak_rss,
        'source': 'Linux procfs process counters',
      }
    raise RuntimeError(f'Child resource sampling is not implemented for {sys.platform}')

  async def health_ready(self):
    """Bound a real health request and own its socket across cancellation."""
    loop = asyncio.get_running_loop()
    port = int(self.environment['APP_PORT'])
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as connection:
      connection.setblocking(False)
      async with asyncio.timeout(0.5):
        await loop.sock_connect(connection, ('127.0.0.1', port))
        await loop.sock_sendall(
          connection,
          f'GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n'.encode('ascii'),
        )
        response = bytearray()
        while chunk := await loop.sock_recv(connection, 4096 - len(response) + 1):
          response.extend(chunk)
          if len(response) > 4096:
            return False
        headers, separator, _ = response.partition(b'\r\n\r\n')
        if not separator:
          return False
        status = bytes(headers).split(b'\r\n', 1)[0].split(b' ', 2)
        return len(status) >= 2 and status[0] in {b'HTTP/1.0', b'HTTP/1.1'} and status[1] == b'200'

  async def start(self):
    if self.process is not None:
      raise RuntimeError('Application is already running')
    if getattr(self, 'load_mode', False) and self.environment.get('TEST_TASK_MEASUREMENTS'):
      raise ValueError('Load runs must use public metrics without task interception')
    # Test-owned setup runs before main.py; stdin requests a graceful SIGINT shutdown.
    bootstrap = (
      'import _thread, asyncio, ctypes, json, os, runpy, sys, threading\n'
      'from pathlib import Path\n'
      'from hashlib import sha256\n'
      + inspect.getsource(load_cpu_kernel)
      + '\n'
      + inspect.getsource(load_cpu_mask)
      + '\n'
      + inspect.getsource(load_set_cpu_mask)
      + '\n'
      'if os.environ.get("TEST_CPU_PROFILE"):\n'
      '  cpu = json.loads(os.environ["TEST_CPU_PROFILE"])\n'
      '  cpu["application_pid"] = os.getpid()\n'
      '  if cpu["requested_mask"] is not None:\n'
      '    cpu["application_effective_mask"] = load_set_cpu_mask(cpu["requested_mask"])\n'
      '  elif sys.platform == "win32":\n'
      '    cpu["application_effective_mask"] = load_cpu_mask()\n'
      '  Path("cpu-affinity.json").write_text(json.dumps(cpu), encoding="utf-8")\n'
      + inspect.getsource(normalize_migration_coverage)
      + '\n'
      + inspect.getsource(observe_child_tasks)
      + '\n'
      'task_evidence = observe_child_tasks() if os.environ.get("TEST_TASK_MEASUREMENTS") else None\n'
      'def stop():\n'
      '  os.read(sys.stdin.fileno(), 1)\n'
      '  _thread.interrupt_main()\n'
      'threading.Thread(target=stop, daemon=True).start()\n'
      'coverage = None\n'
      'if os.environ.get("COVERAGE_PROCESS_START"):\n'
      '  import coverage as coverage_module\n'
      '  coverage = coverage_module.Coverage(config_file=os.environ["COVERAGE_PROCESS_START"], data_suffix=True)\n'
      '  coverage.start()\n'
      'try:\n'
      '  runpy.run_path(sys.argv[1], run_name="__main__")\n'
      'except KeyboardInterrupt:\n'
      '  pass\n'
      'finally:\n'
      '  if os.environ.get("TEST_SOURCE_EVIDENCE"):\n'
      '    evidence = {"main": str(Path(sys.argv[1]).resolve()), "pythonpath": os.environ.get("PYTHONPATH"), '
      '"modules": {name: str(Path(module.__file__).resolve()) for name, module in tuple(sys.modules.items()) '
      'if name in ("config.config", "database.db", "metrics.metrics", "server.server") and '
      'getattr(module, "__file__", None)}, "migrations": {path.name: sha256(path.read_bytes()).hexdigest() '
      'for path in sorted((Path.cwd() / "migrations").glob("*.py"))}}\n'
      '    Path(os.environ["TEST_SOURCE_EVIDENCE"]).write_text(json.dumps(evidence), encoding="utf-8")\n'
      '  if task_evidence is not None:\n'
      '    Path(os.environ["TEST_TASK_MEASUREMENTS"]).write_text(json.dumps(task_evidence), encoding="utf-8")\n'
      '  if coverage is not None:\n'
      '    coverage.stop()\n'
      '    normalize_migration_coverage(coverage.get_data(), Path(sys.argv[1]).parent, [Path.cwd() / "migrations"])\n'
      '    coverage.save()\n'
    )
    attempt = {'status': 'starting'}
    self.startup_attempts.append(attempt)
    started = perf_counter()
    self.log = self.log_path.open('ab', buffering=0)
    try:
      if self.environment.get('TEST_CPU_PROFILE'):
        (self.directory / 'cpu-affinity.json').unlink(missing_ok=True)
      self.process = await asyncio.create_subprocess_exec(
        sys.executable,
        '-B',
        '-c',
        bootstrap,
        str(self.root / 'main.py'),
        cwd=self.directory,
        env=self.environment,
        stdin=asyncio.subprocess.PIPE,
        stdout=self.log,
        stderr=asyncio.subprocess.STDOUT,
      )
      async with asyncio.timeout(15):
        while True:
          if self.process.returncode is not None:
            raise AssertionError(f'Application exited before readiness:\n{self.diagnostics()}')
          try:
            if await self.health_ready():
              attempt.update(status='ready', readiness_seconds=perf_counter() - started)
              if self.environment.get('TEST_CPU_PROFILE'):
                attempt['cpu'] = json.loads((self.directory / 'cpu-affinity.json').read_text(encoding='utf-8'))
              break
          except OSError, TimeoutError:
            pass
          await asyncio.sleep(0.02)
    except BaseException as error:
      attempt.update(status='failed', elapsed_seconds=perf_counter() - started, error=repr(error))
      try:
        await self.stop(allow_failure=True)
      except BaseException as cleanup_error:  # noqa: BLE001 -- Preserve the primary error at this harness boundary.
        attempt['cleanup_error'] = repr(cleanup_error)
        error.add_note(f'Startup cleanup also failed: {cleanup_error!r}')
      raise

  @property
  def url(self):
    return f'http://127.0.0.1:{self.environment["APP_PORT"]}'

  async def stop(self, *, allow_failure=False):
    """Retain bounded process cleanup even when the calling test is cancelled."""
    cleanup = asyncio.create_task(self._stop(allow_failure=allow_failure))
    cancelled = False
    while not cleanup.done():
      try:
        await asyncio.shield(cleanup)
      except asyncio.CancelledError:
        cancelled = True
    cleanup.result()
    if cancelled:
      raise asyncio.CancelledError

  async def _stop(self, *, allow_failure=False):
    process, self.process = self.process, None
    try:
      if process is None:
        return
      if process.returncode is None:
        try:
          assert process.stdin is not None
          process.stdin.write(b'\n')
          await process.stdin.drain()
        except BrokenPipeError, ConnectionResetError:
          pass
        try:
          shutdown_timeout = max(15, float(self.environment.get('DB_SHUTDOWN_TIMEOUT', 20)) + 10)
          await asyncio.wait_for(process.wait(), timeout=shutdown_timeout)
        except TimeoutError:
          process.kill()
          await asyncio.wait_for(process.wait(), timeout=5)
          raise AssertionError(f'Application did not shut down gracefully:\n{self.diagnostics()}') from None
      if not allow_failure:
        assert process.returncode == 0, self.diagnostics()
    finally:
      try:
        if process is not None and process.stdin is not None:
          process.stdin.close()
          await process.stdin.wait_closed()
      finally:
        if self.log is not None:
          self.log.close()
          self.log = None


class ProviderState(SimpleNamespace):
  """Configure deterministic wire responses and retain bounded load evidence.

  Schedule keys are (transport, name_or_ip, rdtype_or_None, cycle), names have no
  trailing dot, and attempts start at one. A schedule is a nonempty sequence of
  step dictionaries; its final step repeats. The optional response_factory uses
  (transport, name_or_ip, rdtype_or_None, attempt, cycle) and supplies unscheduled
  steps. Each step may set kind, addresses, aliases, ttl, delay, status,
  retry_after, prefix, media, body, or close. DNS kinds retain dns_message values;
  malformed, disconnect and drop model protocol/transport failures. RIPE kinds
  positive, empty, error and malformed select JSON responses. begin_cycle resets
  attempts only after all exchanges finish; aggregate counters remain cumulative.
  """

  def sample(self, collection: list[Any], value: Any) -> None:
    if self.sample_limit is None or len(collection) < self.sample_limit:
      collection.append(value)

  def record_error(self, error: BaseException) -> None:
    self.counters[('provider', 'handler', 'error')] += 1
    if len(self.errors) < 32:
      self.errors.append(repr(error))

  def assert_idle(self) -> None:
    if self.dns_active or self.ripe_active:
      raise RuntimeError('Provider exchanges are still active')

  def begin_cycle(self, cycle: int) -> None:
    self.assert_idle()
    self.cycle = cycle
    self.attempts.clear()

  def reset_evidence(self) -> None:
    self.assert_idle()
    for values in (self.requests, self.http_requests, self.response_ttls, self.errors):
      values.clear()
    self.counters.clear()
    self.dns_peak_active = self.ripe_peak_active = 0

  def step(self, transport: str, name: str, rdtype: int | None) -> dict[str, Any]:
    name = name.rstrip('.').lower()
    key = (transport, name, rdtype, self.cycle)
    if key not in self.attempts and len(self.attempts) >= self.attempt_key_limit:
      raise ValueError('Provider attempt-key limit exceeded; retire a completed cycle')
    attempt = self.attempts[key] = self.attempts.get(key, 0) + 1
    schedule = self.schedule.get(key)
    if schedule is not None:
      if not schedule:
        raise ValueError('Response schedules must contain at least one step')
      step = dict(schedule[min(attempt - 1, len(schedule) - 1)])
    elif self.response_factory is not None:
      step = dict(self.response_factory(transport, name, rdtype, attempt, self.cycle))
    else:
      step = {}
    kind = step.get('kind', 'default')
    # Callback values are not metric labels: keep cardinality independent of data.
    outcome = kind if kind in self.outcomes else 'other'
    self.counters[(transport, str(rdtype), outcome)] += 1
    self.counters[(transport, 'attempt', 'first' if attempt == 1 else 'retry')] += 1
    return step

  def evidence(self) -> dict[str, Any]:
    return {
      'cycle': self.cycle,
      'counters': [
        {'transport': key[0], 'record': key[1], 'outcome': key[2], 'count': count}
        for key, count in sorted(self.counters.items())
      ],
      'attempt_keys': len(self.attempts),
      'sample_limit': self.sample_limit,
      'request_samples': list(self.requests),
      'http_samples': list(self.http_requests),
      'dns_active': self.dns_active,
      'ripe_active': self.ripe_active,
      'dns_peak_active': self.dns_peak_active,
      'ripe_peak_active': self.ripe_peak_active,
      'errors': list(self.errors),
    }


@pytest.fixture
async def e2e_service(tmp_path, dns_message, request):
  """Keep application logic real and replace only external wire protocols."""
  from coverage import Coverage

  root = Path(__file__).resolve().parents[1]
  _coverage_migration_directories.add(tmp_path / 'migrations')
  shutil.copytree(root / 'migrations', tmp_path / 'migrations', ignore=shutil.ignore_patterns('__pycache__'))
  db_path = tmp_path / 'service.sqlite'

  options = getattr(request, 'param', True)
  configuration = options if isinstance(options, dict) else {}
  load_mode = bool(configuration.get('load', False))
  sample_limit = configuration.get('request_sample_limit', 128) if load_mode else None
  if sample_limit is not None and (not isinstance(sample_limit, int) or sample_limit < 0):
    raise ValueError('request_sample_limit must be a nonnegative integer')
  providers = ProviderState(
    cycle=0,
    schedule={},
    response_factory=None,
    attempts={},
    attempt_key_limit=1_000_000,
    counters=Counter(),
    sample_limit=sample_limit,
    keepalive=bool(load_mode),
    outcomes=frozenset(
      {
        'default',
        'positive',
        'empty',
        'nodata',
        'nxdomain',
        'servfail',
        'refused',
        'malformed',
        'disconnect',
        'drop',
        'error',
        'alias-positive',
        'alias-chain-positive',
      }
    ),
    classic='positive',
    doh='positive',
    cname_kinds={},
    requests=[],
    response_ttls=[],
    http_requests=[],
    http_statuses={},
    errors=[],
    classic_addresses=('8.8.8.8',),
    doh_addresses=('8.8.4.4',),
    addresses_by_domain={},
    delay=0.0,
    unavailable=False,
    hold_dns=False,
    hold_dns_names=set(),
    dns_entered_by_name={},
    dns_release_by_name={},
    drop_classic=False,
    dns_entered=asyncio.Event(),
    dns_release=asyncio.Event(),
    hold_ripe=False,
    ripe_entered=asyncio.Event(),
    ripe_release=asyncio.Event(),
    ripe_delay=0.0,
    ripe_active=0,
    ripe_peak_active=0,
    dns_active=0,
    dns_peak_active=0,
  )

  def response_wire(query, transport, step):
    providers.sample(providers.requests, (transport, query.question[0].name.to_text(), query.question[0].rdtype))
    kind = step.get('kind') or (
      getattr(providers, transport)
      if query.question[0].rdtype == dns.rdatatype.A
      else providers.cname_kinds.get(transport, 'nodata')
    )
    addresses = step.get(
      'addresses',
      providers.addresses_by_domain.get(
        (transport, query.question[0].name.to_text()), getattr(providers, f'{transport}_addresses')
      ),
    )
    if kind == 'malformed':
      return b'not-a-dns-message'
    message = dns_message(kind, query=query, addresses=addresses)
    aliases = step.get('aliases')
    if aliases is not None:
      message.answer.clear()
      owner = query.question[0].name.to_text()
      for alias in aliases:
        target = alias.rstrip('.') + '.'
        message.answer.append(dns.rrset.from_text(owner, 60, 'IN', 'CNAME', target))
        owner = target
      if (
        addresses
        and query.question[0].rdtype == dns.rdatatype.A
        and kind in {'positive', 'alias-positive', 'alias-chain-positive'}
      ):
        message.answer.append(dns.rrset.from_text(owner, 60, 'IN', 'A', *addresses))
    if load_mode and kind in {'nodata', 'nxdomain', 'empty'}:
      # An authoritative negative must cover arbitrary synthetic names, not only example.test.
      message.authority.clear()
      zone = query.question[0].name.parent().to_text()
      message.authority.append(dns.rrset.from_text(zone, 60, 'IN', 'SOA', f'ns.{zone} hostmaster.{zone} 1 60 60 60 60'))
    for record in (*message.answer, *message.authority):
      record.ttl = int(step.get('ttl', 60))
    providers.sample(providers.response_ttls, sorted({record.ttl for record in (*message.answer, *message.authority)}))
    return message.to_wire()

  handlers = set()

  def spawn_handler(coroutine):
    task = asyncio.create_task(coroutine)
    handlers.add(task)

    def finish(completed):
      handlers.discard(completed)
      if not completed.cancelled() and (error := completed.exception()) is not None:
        providers.record_error(error)

    task.add_done_callback(finish)
    return task

  class DnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
      self.transport = transport

    def datagram_received(self, data, addr):
      if len(handlers) >= 4096:
        providers.counters[('classic', 'transport', 'overload')] += 1
        return
      spawn_handler(self.respond(data, addr))

    async def respond(self, data, addr):
      providers.dns_active += 1
      providers.dns_peak_active = max(providers.dns_peak_active, providers.dns_active)
      try:
        query = dns.message.from_wire(data)
        step = providers.step('classic', query.question[0].name.to_text(), query.question[0].rdtype)
        wire = response_wire(query, 'classic', step)
        if providers.drop_classic or step.get('kind') in {'drop', 'disconnect'}:
          return
        if delay := step.get('delay', providers.delay):
          await asyncio.sleep(delay)
        self.transport.sendto(wire, addr)
      except (dns.exception.DNSException, ValueError, IndexError, OSError) as error:
        providers.record_error(error)
      finally:
        providers.dns_active -= 1

    def error_received(self, exc):
      providers.record_error(exc)

  connections = set()

  async def serve_http(reader, writer):
    connections.add(writer)
    providers.counters[('http', 'transport', 'connections')] += 1
    try:
      while True:
        # Idle pooled connections own no exchange and may expire quietly.
        try:
          async with asyncio.timeout(30 if providers.keepalive else 5):
            line = await reader.readline()
        except TimeoutError:
          return
        if not line:
          return
        async with asyncio.timeout(60 if load_mode else 5):
          method, target, _ = line.decode('ascii').split()
          headers = {}
          header_size = 0
          while line := await reader.readline():
            header_size += len(line)
            if header_size > 16384:
              raise ValueError('Provider request headers exceed limit')
            if line == b'\r\n':
              break
            key, value = line.decode('ascii').split(':', 1)
            headers[key.lower()] = value.strip()
          if method != 'GET' or int(headers.get('content-length', '0')) or 'transfer-encoding' in headers:
            raise ValueError('Provider supports bodyless GET requests only')
          url = urlsplit(target)
          params = parse_qs(url.query)
          query = None
          providers.sample(providers.http_requests, (method, url.path))
          if url.path == '/dns-query':
            transport = 'doh'
            assert headers.get('accept') == 'application/dns-message'
            encoded = params['dns'][0]
            query = dns.message.from_wire(urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            name, rdtype = query.question[0].name.to_text(), query.question[0].rdtype
          elif url.path == '/data/network-info/data.json':
            transport = 'ripe'
            name, rdtype = params['resource'][0], None
          else:
            raise AssertionError(f'Unexpected provider request: {method} {url.path}')
          step = providers.step(transport, name, rdtype)
          if transport == 'doh':
            providers.dns_active += 1
            providers.dns_peak_active = max(providers.dns_peak_active, providers.dns_active)
          else:
            providers.ripe_active += 1
            providers.ripe_peak_active = max(providers.ripe_peak_active, providers.ripe_active)
            providers.sample(providers.requests, ('ripe', name, None))
            providers.ripe_entered.set()
          try:
            if delay := step.get('delay', providers.delay + (providers.ripe_delay if transport == 'ripe' else 0)):
              await asyncio.sleep(delay)
            if providers.unavailable or step.get('kind') == 'disconnect':
              return
            if step.get('kind') == 'drop':
              await reader.read(1)
              return
            pending_statuses = providers.http_statuses.get(url.path, [])
            legacy_status = pending_statuses.pop(0) if pending_statuses and 'status' not in step else None
            status = int(step.get('status', legacy_status if legacy_status is not None else 200))
            if not 100 <= status <= 599:
              raise ValueError('Provider HTTP status must be in 100..599')
            if legacy_status is not None:
              body, media = b'', 'application/octet-stream'
            elif transport == 'doh':
              assert query is not None
              body = response_wire(query, 'doh', step)
              name = name.rstrip('.')
              if name in providers.hold_dns_names:
                providers.dns_entered_by_name.setdefault(name, asyncio.Event()).set()
                await providers.dns_release_by_name.setdefault(name, asyncio.Event()).wait()
              if providers.hold_dns:
                providers.dns_entered.set()
                await providers.dns_release.wait()
              media = 'application/dns-message'
            else:
              if providers.hold_ripe:
                await providers.ripe_release.wait()
              kind = step.get('kind', 'empty')
              if kind == 'malformed':
                body = b'{invalid-json'
              elif kind == 'error':
                body = json.dumps({'status': 'error', 'message': 'Synthetic provider failure'}).encode()
              else:
                body = json.dumps({'status': 'ok', 'data': {'prefix': step.get('prefix')}}).encode()
              media = 'application/json'
            body = step.get('body', body)
            close = step.get('close', not providers.keepalive) or headers.get('connection', '').lower() == 'close'
            response_headers = (
              f'HTTP/1.1 {status} Synthetic Provider Response\r\n'
              f'Content-Type: {step.get("media", media)}\r\nContent-Length: {len(body)}\r\n'
              f'Connection: {"close" if close else "keep-alive"}\r\n'
            )
            if 'retry_after' in step:
              response_headers += f'Retry-After: {step["retry_after"]}\r\n'
            writer.write((response_headers + '\r\n').encode('ascii') + body)
            await writer.drain()
            providers.counters[(transport, 'status', str(status))] += 1
            if close:
              return
          finally:
            if transport == 'doh':
              providers.dns_active -= 1
            else:
              providers.ripe_active -= 1
    except ConnectionError, asyncio.IncompleteReadError:
      # Clients may cancel or time out intentionally during degraded-provider cases.
      providers.counters[('http', 'transport', 'client_closed')] += 1
    except (AssertionError, KeyError, ValueError, IndexError, dns.exception.DNSException, TimeoutError) as error:
      providers.record_error(error)
    finally:
      writer.close()
      try:
        await writer.wait_closed()
      except ConnectionError:
        pass
      finally:
        connections.discard(writer)

  loop = asyncio.get_running_loop()
  # Classic DNS has no configurable port. A separate loopback address owns port 53.
  dns_host = f'127.{uuid4().int % 254 + 1}.{uuid4().int % 254 + 1}.{uuid4().int % 254 + 1}'
  dns_transport, _ = await loop.create_datagram_endpoint(DnsProtocol, local_addr=(dns_host, 53))
  http_server = None
  service = None
  try:
    http_server = await asyncio.start_server(
      lambda reader, writer: spawn_handler(serve_http(reader, writer)), '127.0.0.1', 0
    )
    provider_url = f'http://127.0.0.1:{http_server.sockets[0].getsockname()[1]}'
    # Reserve an ephemeral address before handing it to the real HTTP server.
    port_reservation = await asyncio.start_server(lambda reader, writer: writer.close(), '127.0.0.1', 0)
    port = port_reservation.sockets[0].getsockname()[1]
    port_reservation.close()
    await port_reservation.wait_closed()
    environment = {key: os.environ[key] for key in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if key in os.environ}
    environment.update(
      {
        'PYTHONPATH': str(root),
        'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHON_DOTENV_DISABLED': '1',
        'APP_HOST': '127.0.0.1',
        'APP_PORT': str(port),
        'APP_LOG_LEVEL': 'error',
        'ROOT_LOG_LEVEL': 'error',
        'DB_BASE_DIR': str(tmp_path),
        'DB_FILE_NAME': db_path.name,
        'DB_TABLE_PREFIX': 'rdpr_',
        'RIPE_STAT_BASE_URL': provider_url,
      }
    )
    if not load_mode:
      environment.update(
        {
          'DB_SAVE_BATCH_TIMEOUT': '0.05',
          'DB_SHUTDOWN_TIMEOUT': '5',
          'REQ_CONNECTION_RETRIES': '0',
          'DOH_CONNECTION_RETRIES': '0',
          'RIPE_STAT_CONNECTION_RETRIES': '0',
          'DOH_TIMEOUT_CONNECT': '2',
          'DOH_TIMEOUT_READ': '2',
          'DOH_TIMEOUT_WRITE': '2',
          'DOH_TIMEOUT_POOL': '2',
          'RIPE_STAT_TIMEOUT_CONNECT': '2',
          'RIPE_STAT_TIMEOUT_READ': '2',
          'RIPE_STAT_TIMEOUT_WRITE': '2',
          'RIPE_STAT_TIMEOUT_POOL': '2',
          'REQ_TIMEOUT_DEFAULT': '2',
          'REQ_TIMEOUT_CONNECT': '2',
          'REQ_TIMEOUT_READ': '2',
        }
      )
    coverage = Coverage.current()
    if not load_mode and coverage is not None:
      environment['COVERAGE_PROCESS_START'] = str(root / 'pyproject.toml')
      coverage_file = coverage.get_option('run:data_file')
      assert isinstance(coverage_file, str)
      environment['COVERAGE_FILE'] = str(Path(coverage_file).resolve())
    elif not load_mode and os.environ.get('COVERAGE_PROCESS_START'):
      environment['COVERAGE_PROCESS_START'] = os.environ['COVERAGE_PROCESS_START']
      if os.environ.get('COVERAGE_FILE'):
        environment['COVERAGE_FILE'] = os.environ['COVERAGE_FILE']
    service = ServiceProcess(root, tmp_path, environment)
    service.load_mode = bool(load_mode)
    service.db_path = db_path
    service.providers = providers
    service.dns_host = dns_host
    service.doh_url = f'{provider_url}/dns-query'
    service.provider_url = provider_url
    if options.get('start', True) if isinstance(options, dict) else options:
      await service.start()
    yield service
  finally:
    providers.dns_release.set()
    for release in providers.dns_release_by_name.values():
      release.set()
    providers.ripe_release.set()
    try:
      if service is not None:
        await service.stop()
    finally:
      dns_transport.close()
      if http_server is not None:
        http_server.close()
      for writer in tuple(connections):
        writer.close()
      for task in tuple(handlers):
        task.cancel()
      if handlers:
        async with asyncio.timeout(5):
          await asyncio.gather(*tuple(handlers), return_exceptions=True)
      if http_server is not None:
        async with asyncio.timeout(5):
          await http_server.wait_closed()
      assert providers.errors == []
