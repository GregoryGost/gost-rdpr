from ipaddress import ip_network
from pathlib import Path
from hashlib import sha256
from typing import Literal

from config.config import settings

# Check IP or IP/subnet type
def get_ip_version(ip: str) -> Literal[4, 6]:
  # print(f'Run get_ip_version helper for ip: {ip}')
  try:
    return ip_network(ip).version
  except Exception as err:
    raise err

def check_ip_allow(ip: str) -> bool:
  '''
  Allow = True  
  Block = False
  '''
  if ip in settings.ip_not_allowed_list:
    return False
  return True

def get_ip_without_prefix(ip_address: str) -> str:
  try:
    ipPefix = ip_network(ip_address).prefixlen
    if ipPefix != 32:
      return ip_address
    ip = ip_network(ip_address, strict=False).network_address
    return str(ip)
  except Exception as err:
    raise err

def calculate_checksum(file_path: Path) -> str:
  '''Calculate checksum for file'''
  with open(file_path, 'r', encoding='utf-8') as f:
    content: str = f.read()
  return sha256(content.encode('utf-8')).hexdigest()
