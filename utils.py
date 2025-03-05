import os
from ipaddress import ip_network
import hashlib
from datetime import datetime

# get cpu logical count
def getDefCpus() -> int:
  try:
    cpus = os.cpu_count()
    if cpus != None and cpus > 3:
      return int(cpus - 1)
    return 1
  except:
    return 1

# Get HASH SHA2(256) for string or bytes
def getHash(content: bytes | str):
  if isinstance(content, str):
    contentBytes = content.encode('utf-8')
  else:
    contentBytes = content
  sha256Hasher = hashlib.sha256()
  sha256Hasher.update(contentBytes)
  return sha256Hasher.hexdigest().upper()

# Get float timestamp (1737057102.0)
def getTimestamp(date: str) -> float:
  return datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timestamp()

# Get formated IP addr or IP/subnet
def getIpWithPrefix(ip: str):
  # print(f'Run getIpWithPrefix helper for ip: {ip}')
  try:
    ipPefix = ip_network(ip).prefixlen
    if ipPefix != 32:
      return ip
    else:
      return f'{ip}/{ipPefix}'
  except Exception as err:
    raise err

# Get IP address without subnet for /32 addresses
def getIpWithoutPrefix(ip_pref: str) -> str:
  try:
    ipPefix = ip_network(ip_pref).prefixlen
    if ipPefix != 32:
      return ip_pref
    ip = ip_network(ip_pref, strict=False).network_address
    return str(ip)
  except Exception as err:
    raise err

# Check IP or IP/subnet type
def getIpVersion(ip: str):
  # print(f'Run getIpVersion helper for ip: {ip}')
  try:
    ip.strip()
    return ip_network(ip).version
  except ValueError:
    # if not ip addr format
    return False
  except Exception as err:
    raise err

# Check IP or IP/subnet type (without raise Error)
def checkIpVersion(ip: str) -> bool:
  try:
    type = ip_network(ip).version
    if type == 4 or type == 6:
      return True
    else:
      return False
  except Exception as err:
    return False

#
# NO USE
#

# Batched array object
# for x in batch(data, 3):
#   print(x)
def batch(iterable, n=1):
  l = len(iterable)
  for ndx in range(0, l, n):
    yield iterable[ndx:min(ndx + n, l)]
