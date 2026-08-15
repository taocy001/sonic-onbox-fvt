"""Port abstraction.

A test port needs two identifiers:
  name  SONiC canonical name / Linux netdev name, e.g. Ethernet0 (scapy uses it to send/receive)
  bcm   Vendor-X logical port number (bcmcmd uses it for loopback/counter operations)
"""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Port:
    name: str                       # EthernetX, netdev / DB key
    bcm: Optional[str] = None       # bcm logical port number (a number or something like 'ce0')
    alias: Optional[str] = None     # display alias, for logging only
    admin_up: bool = False

    def __str__(self):
        return self.name
