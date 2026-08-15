"""VRF hairpin topology: turn a single box into multiple independent routers interconnected via chip-internal loopback.

The L3 counterpart of the L2 asymmetric-VLAN hairpin (topo/hairpin.py) -- replacing different ingress VLANs with
different VRFs: bind the ingress port to Vrf-A and the egress port to Vrf-B, and you get two routers with
**mutually isolated routing tables** on a single device.

  - Control-plane isolation: each VRF has an independent RIB/FIB (`ip route ... vrf <v>`).
  - Data-plane isolation: each VRF has an independent SAI virtual_router (RIFs attach to their own VR).
  - Loop breaking: the egress port's re-injected frame has DMAC=neighbor MAC != router MAC and is dropped at the
    L3 port (same as the l3probe paradigm); layered on top is the structural loop break of "the returning frame
    lands in a VRF with no matching route and terminates naturally", so there is no storm.

Use: any L3 data-plane case that can only be expressed with "more than one router / mutually isolated routing
tables" -- cross-VRF route leaking (forward direction), prefix-selective leaking, independent forwarding of the
same prefix, per-VRF default routes, etc.

Orchestration takes legal paths (config CLI + ip route/neigh), all reversible; counting reuses the gold paradigm
of framework.counters.ChipCounters -- clear -> send traffic -> poll-accumulate + confirmation read (under the
changed-since-clear view the before/after difference method breaks down, see the l3probe notes).
"""
import time

from framework.counters import ChipCounters


class VrfHairpin:
    """Multi-VRF hairpin orchestrator on a single device. Setup methods are reversible; `cleanup()` unwinds in reverse order."""

    def __init__(self, cli, dut, lb, topo, asicdb=None):
        self.cli, self.dut, self.lb, self.topo, self.asicdb = cli, dut, lb, topo, asicdb
        self.bsh = lb.bsh
        self.rmac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")
        self._vrfs = []       # created VRF names (cleaned up in reverse)
        self._bound = []      # (port, vrf, cidr)
        self._routes = []     # (vrf, dst_net, nh, port_name)

    # ---- VRF / port binding ----
    def add_vrf(self, name):
        rc, r = self.cli.config_raw(f"vrf add {name}")
        assert rc == 0, f"config vrf add {name} failed: {r.err or r.out}"
        self._vrfs.append(name)
        return self

    def bind(self, vrf, port, cidr, tries=20):
        """Move port out of the default VLAN -> bind vrf -> configure IP -> startup -> enable loopback. Returns (ok, why).

        Ordering is critical (the paradigm already validated on hardware in test_vrf_chip): first wait for the VLAN
        member to be truly removed, to avoid a "both in a VLAN and having an IP" mixed state where the loopback
        floods the re-injected frame into a loop within the VLAN. Binding the VRF must happen before configuring the IP.
        """
        dv = self.topo.default_vlan
        self.cli.config_raw(f"vlan member del {dv} {port.name}")
        for _ in range(tries):
            if not self.cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{port.name}"):
                break
            time.sleep(0.3)
        rc, r = self.cli.config_raw(f"interface vrf bind {port.name} {vrf}")
        if rc != 0:
            return False, f"vrf bind: {r.err or r.out}"
        bound = False
        for _ in range(15):
            if self.cli.db_hgetall("CONFIG_DB", f"INTERFACE|{port.name}").get("vrf_name") == vrf:
                bound = True
                break
            time.sleep(0.3)
        if not bound:
            return False, "interface vrf_name not set in CONFIG_DB"
        rc, r = self.cli.config_raw(f"interface ip add {port.name} {cidr}")
        if rc != 0:
            return False, f"ip add: {r.err or r.out}"
        self.cli.intf_startup(port.name)
        self.lb.enable(port)
        self._bound.append((port, vrf, cidr))
        return True, ""

    # ---- routes ----
    def route(self, vrf, dst_net, nh, port_name, nh_mac):
        """Add dst_net via nh within vrf (port_name is already enslaved to that vrf)."""
        self.cli.neigh_set(nh, nh_mac, port_name)
        self.cli.sh.run(f"ip route replace {dst_net} via {nh} vrf {vrf}", check=False)
        self._routes.append((vrf, dst_net, nh, port_name))

    def leak(self, dst_net, from_vrf, nh, egress_port, nh_mac):
        """Cross-VRF route leaking: install a route for dst_net in from_vrf whose next-hop/egress interface lands on
        the egress_port of **another VRF** (`ip route ... via <nh> dev <egress_port> vrf <from_vrf>`).

        If the device supports VRF leaking, this route is programmed to the ASIC and from_vrf's traffic is forwarded
        out egress_port accordingly; if not, it is not programmed -> no data-plane forwarding (the case FAILs to
        expose it). egress_port must already be enslaved to the destination VRF.
        """
        self.cli.neigh_set(nh, nh_mac, egress_port.name)
        self.cli.sh.run(
            f"ip route replace {dst_net} via {nh} dev {egress_port.name} vrf {from_vrf}",
            check=False)
        self._routes.append((from_vrf, dst_net, nh, egress_port.name))

    def wait_route(self, vrf, dst_net, tries=20):
        pfx = dst_net.split("/")[0]
        for _ in range(tries):
            if pfx in self.cli.sh.run(f"ip route show {dst_net} vrf {vrf}", check=False).out:
                return True
            time.sleep(0.5)
        return False

    # ---- data-plane probing ----
    def _pkt(self, dst_ip, src_ip, ttl=64):
        from scapy.all import Ether, IP, UDP
        return (Ether(dst=self.rmac, src=self.topo.mac("src")) /
                IP(src=src_ip, dst=dst_ip, ttl=ttl) / UDP())

    def forward_tx(self, in_port, dst_ip, src_ip, egress_port, n=30, timeout=3.0):
        """Inject packets for dst_ip into in_port and return egress_port's accumulated chip TX (>=~n means truly forwarded to that egress).

        Forward gold paradigm: clear -> send traffic -> poll-accumulate to >= n*0.9 or timeout, then +0.4s for one
        confirmation read added in (guards against under-counting from slow DMA settling, while also catching a slow
        self-replicating storm that overshoots the upper bound).
        """
        from scapy.all import sendp
        ChipCounters.clear(self.bsh)
        sendp(self._pkt(dst_ip, src_ip), iface=in_port.name, count=n, verbose=False)
        total, deadline = 0, time.time() + timeout
        while total < n * 0.9 and time.time() < deadline:
            time.sleep(0.4)
            total += ChipCounters.read(self.bsh, self.dut.bcm_of(egress_port)).tx_pkt
        time.sleep(0.4)
        total += ChipCounters.read(self.bsh, self.dut.bcm_of(egress_port)).tx_pkt
        return total

    def no_forward_tx(self, in_port, dst_ip, src_ip, egress_port, n=30, settle=2.0):
        """Negative observation ("should not arrive"): after injecting, wait >= 2 counter refresh periods and
        **accumulate** reads of egress_port TX, to prevent a leaked frame arriving later than 1s from being missed
        by a single early read (false PASS)."""
        from scapy.all import sendp
        ChipCounters.clear(self.bsh)
        sendp(self._pkt(dst_ip, src_ip), iface=in_port.name, count=n, verbose=False)
        total, end = 0, time.time() + settle
        while time.time() < end:
            time.sleep(0.5)
            total += ChipCounters.read(self.bsh, self.dut.bcm_of(egress_port)).tx_pkt
        return total

    # ---- cleanup (reverse order, idempotent) ----
    def cleanup(self):
        for vrf, dst, nh, port_name in reversed(self._routes):
            self.cli.sh.run(f"ip route del {dst} vrf {vrf}", check=False)
            self.cli.neigh_del(nh, port_name)
        self._routes.clear()
        for port, vrf, cidr in reversed(self._bound):
            try:
                self.lb.disable(port)
            except Exception:  # noqa: BLE001
                pass
            self.cli.config_raw(f"interface ip remove {port.name} {cidr}")
            self.cli.config_raw(f"interface vrf unbind {port.name}")
            self.cli.config_raw(f"vlan member add -u {self.topo.default_vlan} {port.name}")
        self._bound.clear()
        for vrf in reversed(self._vrfs):
            self.cli.config_raw(f"vrf del {vrf}")
        self._vrfs.clear()
