"""L3 forwarding real-traffic probe (storm-safe) -- reuses the anti-storm pattern already validated on hardware in test_l3_forward_traffic.py.

Mechanism: both L3 ports p_in/p_out are configured with an IP + MAC loopback enabled; inject a packet
on p_in with "dst=remote subnet, outer DMAC=router MAC" -> DUT routes it to p_out (DMAC rewritten to
neighbor / SMAC to router / TTL-1) -> p_out chip TX +N; the frame looped back on p_out is dropped at
the L3 port because DMAC=neighbor MAC != router MAC -> no storm. Reuse for data-plane
route/neighbor/MTU test cases to avoid repeated boilerplate.
"""
import time

from framework.counters import ChipCounters

NH_MAC = "00:11:22:33:44:aa"   # remote next-hop neighbor MAC (arbitrary test value, verifies the DMAC-rewrite target)


def router_mac(cli):
    """DUT router MAC (DEVICE_METADATA.mac), the SMAC of the forwarded frame."""
    return cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")


def reset_l3(cli, _lb, dut, ports, routes=()):
    """Reset the L3 ports in use: disable loopback, delete test routes, disable leftover egress mirror (prevents software loop), clear chip counters. Call both before and after."""
    for p in ports:
        try:
            _lb.disable(p)
        except Exception:  # noqa: BLE001
            pass
    for net in routes:
        cli.sh.run(f"ip {'-6 ' if ':' in net else ''}route del {net}", check=False)
    for p in ports:
        _lb.bsh.cmd(f"mirror port {dut.bcm_of(p)} mode=off")
    _lb.bsh.cmd("clear c")


def wait_route(cli, dst_net, tries=20):
    """Wait for the route to be programmed into the kernel (FRR/zebra). Must be ready before injecting, otherwise unknown dst -> flood -> storm hitting the loopback port."""
    pre = "-6 " if ":" in dst_net else ""
    for _ in range(tries):
        if dst_net.split("/")[0] in cli.sh.run(f"ip {pre}route show {dst_net}", check=False).out:
            return True
        time.sleep(0.5)
    return False


def tx_delta(_lb, dut, p_out, pkt, iface, n=30, settle=1.0):
    """Inject pkt (already built, DMAC=router MAC) n times to iface, return the total p_out chip TX.

    Counting discipline (multi-expert review fix): on both devices `show c` has "delta since last
    show" semantics, so before/after subtraction is a known bad pattern -- the base read consumes
    the display and includes background noise from the previous window, and the delta can go
    negative/undercount (7 call sites in route/arp/ndp once undercounted to TX=1 this way). The
    correct approach = clear -> send traffic -> poll and accumulate + confirming read."""
    from scapy.all import sendp
    bsh = _lb.bsh
    ChipCounters.clear(bsh)                     # in parallel mode, auto-narrows to this worker's port range
    sendp(pkt, iface=iface, count=n, verbose=False)
    total = 0
    deadline = time.time() + max(settle, 1.0) + 2.0
    while total < n * 0.9 and time.time() < deadline:
        time.sleep(0.4)
        total += ChipCounters.read(bsh, dut.bcm_of(p_out)).tx_pkt
    # Confirming read: normal traffic has settled (+0); a slow self-replicating storm keeps growing, letting the caller's upper-bound assertion honestly expose it
    time.sleep(0.4)
    total += ChipCounters.read(bsh, dut.bcm_of(p_out)).tx_pkt
    return total


class TwoPortL3:
    """setup/teardown context for a two-L3-port forwarding scenario: configure p_in/p_out IP+loopback+static neighbor, yield a handle.

    Usage:
        with TwoPortL3(cli, dut, _lb, topo, l3up) as s:
            # s.p_in / s.p_out / s.nh / s.rmac are ready; the caller configures routes via SONiC CLI then sends traffic
            ...
    On exit, delete the neighbor + reset (disable loopback / delete routes / disable mirror / clear
    counters), preventing cross-test storms.
    """

    def __init__(self, cli, dut, _lb, topo, l3up, v6=False):
        self.cli, self.dut, self._lb, self.topo, self.l3up, self.v6 = cli, dut, _lb, topo, l3up, v6
        self.ports = (topo.l3_port(0), topo.l3_port(1))

    def __enter__(self):
        sub_in = self.topo.subnet("v6b" if self.v6 else "c")
        sub_out = self.topo.subnet("v6a" if self.v6 else "d")
        reset_l3(self.cli, self._lb, self.dut, self.ports)
        self.p_in = self.l3up(self.topo.l3_port(0).name, f"{sub_in['dut']}/{sub_in['prefix']}")
        self.p_out = self.l3up(self.topo.l3_port(1).name, f"{sub_out['dut']}/{sub_out['prefix']}")
        self.nh = sub_out["peer"]
        self.sub_in, self.sub_out = sub_in, sub_out
        n6 = "-6 " if self.v6 else ""
        self.cli.sh.run(f"ip {n6}neigh replace {self.nh} lladdr {NH_MAC} dev {self.p_out.name}", check=False)
        self.rmac = router_mac(self.cli)
        return self

    def __exit__(self, *exc):
        n6 = "-6 " if self.v6 else ""
        self.cli.sh.run(f"ip {n6}neigh del {self.nh} dev {self.p_out.name}", check=False)
        reset_l3(self.cli, self._lb, self.dut, self.ports)
        return False

    def make_pkt(self, dst_ip, ttl=64, dscp=None, sport=0):
        """Build the injection frame: outer DMAC=router MAC (triggers routing), dst=dst_ip."""
        from scapy.all import Ether, IP, IPv6, UDP
        eth = Ether(dst=self.rmac, src=self.topo.mac("src"))
        if self.v6:
            l3 = IPv6(src=self.sub_in["peer"], dst=dst_ip, hlim=ttl)
        else:
            tos = (dscp << 2) if dscp is not None else 0
            l3 = IP(src=self.sub_in["peer"], dst=dst_ip, ttl=ttl, tos=tos)
        return eth / l3 / UDP(sport=sport or 1234, dport=80)

    def forward_tx(self, dst_ip, ttl=64, n=30):
        """Inject a packet to dst_ip, return the p_out chip TX delta (>=~n means real forwarding to that egress)."""
        return tx_delta(self._lb, self.dut, self.p_out, self.make_pkt(dst_ip, ttl=ttl),
                        self.p_in.name, n=n)
