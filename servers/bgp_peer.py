"""BGP peer: use exabgp (a real daemon, installed to the DUT from an offline wheel) to play
an EBGP peer, bound to the local peer_ip (a dummy interface for LocalPeerIP), establishing a
session with the DUT's bgpd and advertising routes.

Verification: DUT learns the route -> FIB -> orchagent -> ASIC ROUTE_ENTRY / NEXTHOP /
NEXTHOP_GROUP. When exabgp is unavailable, fall back to a minimal scapy BGP (OPEN/KEEPALIVE
only, low fidelity).
"""
import os
import tempfile

from framework import log

from .base import ProcessServer

_log = log.get("bgp")

EXABGP_CONF = """\
neighbor {dut_ip} {{
    router-id {peer_ip};
    local-address {peer_ip};
    local-as {peer_as};
    peer-as {dut_as};
    static {{
        {routes}
    }}
}}
"""


class ExaBgpPeer:
    def __init__(self, dut_ip, peer_ip, peer_as=65002, dut_as=65001,
                 advertise=("172.16.0.0/24", "172.16.1.0/24"), advertise_nexthop=None):
        # peer_ip: the BGP session address (bound to a local dummy). advertise_nexthop: the
        # next hop for advertised routes; must be an address within a data-plane port's subnet
        # that has a static neighbor (so the route is programmed to the ASIC data plane rather
        # than resolving locally). Defaults to peer_ip (only valid when both are on the same port).
        self.dut_ip, self.peer_ip = dut_ip, peer_ip
        self.peer_as, self.dut_as = peer_as, dut_as
        self.advertise = advertise
        self.advertise_nexthop = advertise_nexthop or peer_ip
        self._conf = None
        self._srv = None

    def _write_conf(self):
        routes = "\n        ".join(
            f"route {p} next-hop {self.advertise_nexthop};" for p in self.advertise)
        text = EXABGP_CONF.format(dut_ip=self.dut_ip, peer_ip=self.peer_ip,
                                  peer_as=self.peer_as, dut_as=self.dut_as,
                                  routes=routes)
        fd, path = tempfile.mkstemp(suffix=".conf", prefix="exabgp_")
        os.write(fd, text.encode())
        os.close(fd)
        return path

    def start(self):
        self._conf = self._write_conf()
        env = dict(os.environ, exabgp_daemon_daemonize="false",
                   exabgp_tcp_bind=self.peer_ip)
        self._srv = ProcessServer(["exabgp", self._conf], env=env, ready_wait=4.0)
        self._srv.start()
        _log.info("exabgp peer %s -> DUT %s, advertising %s",
                  self.peer_ip, self.dut_ip, list(self.advertise))
        return self

    def stop(self):
        if self._srv:
            self._srv.stop()
        if self._conf and os.path.exists(self._conf):
            os.unlink(self._conf)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
