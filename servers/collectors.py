"""Management-plane UDP collectors: syslog / SNMP trap. Bind a local port and record whatever the DUT client sends."""
from framework import log

from .base import ThreadServer

_log = log.get("mgmtsrv")


class SyslogServer(ThreadServer):
    """Remote syslog receiver (UDP 514). Records the received message text."""

    def __init__(self, bind_ip="0.0.0.0", port=514):
        super().__init__(bind_ip, port)
        self.messages = []

    def on_datagram(self, data, addr):
        msg = data.decode(errors="replace")
        self.messages.append(msg)
        return None

    def has(self, substr):
        return any(substr in m for m in self.messages)


class SnmpTrapServer(ThreadServer):
    """SNMP trap receiver (UDP 162). Only records arrival (no deep PDU parsing)."""

    def __init__(self, bind_ip="0.0.0.0", port=162):
        super().__init__(bind_ip, port)
        self.traps = []

    def on_datagram(self, data, addr):
        self.traps.append((data, addr))
        return None
