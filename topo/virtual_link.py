"""Virtual L3 link: front-panel port with L3 IP + static neighbor + MAC loopback, simulating a peer on the DUT itself.

The programmed chip objects can be verified: ROUTER_INTERFACE (IP configured),
NEIGHBOR_ENTRY + NEXTHOP (static neighbor). Data-plane frames pass through the chip via
loopback; the peer is played by scapy in responders/ or a local daemon in servers/.

Conventions:
  dut_ip   DUT-side interface IP (e.g. 10.99.1.1)
  peer_ip  peer IP (same subnet, e.g. 10.99.1.2)
  peer_mac peer MAC (the static neighbor points at it; the scapy peer replies with the same MAC)
"""
from framework import log

_log = log.get("vlink")

DEFAULT_PEER_MAC = "00:de:ad:be:ef:a2"


class VirtualLink:
    def __init__(self, cli, dut, loopback, port, dut_ip, peer_ip,
                 prefix=24, peer_mac=DEFAULT_PEER_MAC, vlan=1000):
        self.cli, self.dut, self.lb = cli, dut, loopback
        self.port = port
        self.dut_ip, self.peer_ip = dut_ip, peer_ip
        self.prefix, self.peer_mac, self.vlan = prefix, peer_mac, vlan
        self._undo = []

    @property
    def cidr(self):
        return f"{self.dut_ip}/{self.prefix}"

    def setup(self):
        p = self.port.name
        # 1) Remove from default VLAN (the port needs to do L3)
        rc, _ = self.cli.config_raw(f"vlan member del {self.vlan} {p}")
        if rc == 0:
            self._undo.append(f"vlan member add -u {self.vlan} {p}")
        # 2) Configure L3 IP -> ROUTER_INTERFACE + connected route
        self.cli.config(f"interface ip add {p} {self.cidr}")
        self._undo.append(f"interface ip remove {p} {self.cidr}")
        self.cli.intf_startup(p)
        # 3) MAC loopback: data-plane frames can loop back through the chip
        self.lb.enable(self.port)
        # 4) Static neighbor -> NEIGHBOR_ENTRY + NEXTHOP (lets the DUT resolve the peer and program the chip)
        self.cli.sh.run(
            f"ip neigh replace {self.peer_ip} lladdr {self.peer_mac} dev {p}",
            check=False)
        _log.info("VirtualLink up: %s dut=%s peer=%s/%s mac=%s",
                  p, self.dut_ip, self.peer_ip, self.prefix, self.peer_mac)
        return self

    def teardown(self):
        self.cli.sh.run(f"ip neigh del {self.peer_ip} dev {self.port.name}",
                        check=False)
        self.lb.disable(self.port)
        for cmd in reversed(self._undo):
            self.cli.config_raw(cmd)
        self._undo.clear()
        # OS-agnostic fallback: fully restore the port to the L2 baseline. On SONiC/switchport
        # OS, `interface ip remove` only deletes the IP and leaves a bare INTERFACE|<port>
        # routed port, and does not auto-return to the default VLAN (and setup's
        # `vlan member del 1000` fails on Vlan1-berthed devices -> the undo's vlan re-add was
        # never even registered) -- the port thus stays stuck at L3, polluting any subsequent L2
        # case that needs it in the default VLAN (pollution sentinel observed: Ethernet0 stays
        # routed long after test_bgp). reset_port_to_l2 clears the bare INTERFACE key + returns to
        # the default VLAN, the same authoritative primitive as the l3up/l3net fixture teardown.
        from framework import hygiene
        dv = 1 if self.cli.is_switchport_os() else self.vlan
        try:
            hygiene.reset_port_to_l2(self.cli, self.lb, self.dut, self.port, dv)
        except Exception:  # noqa: BLE001  fallback cleanup failure should not crash the case teardown
            pass

    def __enter__(self):
        return self.setup()

    def __exit__(self, *exc):
        self.teardown()
        return False


class LocalPeerIP:
    """Bind peer_ip to a dummy interface on the DUT itself, so a control-plane daemon (exabgp)
    peers with the DUT's control plane via the kernel's local stack, while the route's nexthop
    still points at the data-plane port (programmed to the chip via the static neighbor)."""

    def __init__(self, cli, peer_ip, prefix=32, dev="dummypeer"):
        from framework import worker as _W
        # Parallel lane separation: dummy interface name per worker suffix (w1 / original name in single-process)
        self.cli, self.peer_ip, self.prefix, self.dev = cli, peer_ip, prefix, dev + _W.suffix()

    def setup(self):
        sh = self.cli.sh
        sh.run(f"ip link add {self.dev} type dummy", check=False)
        sh.run(f"ip link set {self.dev} up", check=False)
        sh.run(f"ip addr add {self.peer_ip}/{self.prefix} dev {self.dev}", check=False)
        return self

    def teardown(self):
        self.cli.sh.run(f"ip link del {self.dev}", check=False)

    def __enter__(self):
        return self.setup()

    def __exit__(self, *exc):
        self.teardown()
        return False
