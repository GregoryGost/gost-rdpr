from dataclasses import dataclass, field

@dataclass
class TagElement:
  name: str
  description: str

@dataclass
class TagsMetadata:
  metrics_tag: TagElement = field(default_factory=lambda: TagElement(
    name='Metrics',
    description='Method for metrics'
  ))
  home_tag: TagElement = field(default_factory=lambda: TagElement(
    name='Home',
    description='Welcome method and healthcheck'
  ))
  dns_servers_tag: TagElement = field(default_factory=lambda: TagElement(
    name='DNS Servers',
    description='Methods for DNS servers. DNS servers will be used to resolve domain names. All available DNS servers are applied per domain'
  ))
  domains_lists_tag: TagElement = field(default_factory=lambda: TagElement(
    name='Domains Lists',
    description='Methods for managing domain lists. Links to domain lists from which domains will be obtained directly and then their IP addresses'
  ))
  domains_tag: TagElement = field(default_factory=lambda: TagElement(
    name='Domains',
    description='Methods for domain names that are then resolved to IP addresses as A(IPv4), AAAA(IPv6), NS, CNAME records'
  ))
  ips_lists_tag: TagElement = field(default_factory=lambda: TagElement(
    name='IP Address Lists',
    description='Methods for managing IP address lists. Links to IP address lists from which the IP addresses themselves will be obtained directly. They can be either just IP addresses or addresses with summarization'
  ))
  ips_tag: TagElement = field(default_factory=lambda: TagElement(
    name='IP address',
    description='Methods for managing IP addresses. IP addresses added manually are bound to the base domain with index 0'
  ))
  ros_configs_tag: TagElement = field(default_factory=lambda: TagElement(
    name='RoS Configs',
    description='Methods for managing Router configurations, to which all received IP addresses will be assigned'
  ))
  commands_tag: TagElement = field(default_factory=lambda: TagElement(
    name='Commands',
    description='Commands to perform periodic background tasks (downloading lists, resolving domains, etc.)'
  ))
  # jobs_tag
