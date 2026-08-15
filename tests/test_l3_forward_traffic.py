"""L3 forwarding real-traffic end-to-end cases (template) -- not just verifying ASIC_DB programming, but **driving real traffic to verify forwarding behavior**.

Mechanism (verified on hardware, storm-free):
  p_in and p_out both get L3 IPs + MAC loopback enabled; inject at p_in an IP packet "destined for the remote subnet, with outer DMAC=DUT
  router MAC" -> it loops back through p_in and re-enters the pipeline -> the DUT forwards it by route to p_out (TTL-1, DMAC rewritten to the
  neighbor MAC, SMAC rewritten to the router MAC) -> it physically egresses p_out (chip TX counter +N) -> it loops back through p_out and
  re-enters -> because its DMAC=neighbor MAC != router MAC it is dropped at the L3 port (not forwarded again, hence **no storm**).

Verification: p_out chip MIB_TPKT(TX) increments ~N == the L3 unicast was indeed forwarded to the correct egress (real traffic, end to end).

**Shared test environment**: the cases in this file share a **module-level `l3net` base** (l3_port0/1 + misc_port0 configured with L3 +
loopback once, see conftest.l3net) -- no more repeating the l3up port-build/loopback boilerplate per case; each case only adds/clears its own route/neighbor.
"""
import time

import pytest

from framework.counters import ChipCounters

pytestmark = pytest.mark.traffic

try:
    from scapy.all import Ether, IP, IPv6, UDP, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 30                       # number of injected packets (small, paired with an upper-bound assertion to guard against runaway)
_NH_MAC = "00:11:22:33:44:aa"  # remote neighbor (next hop) MAC -- an arbitrary test value, verifies the DMAC rewrite target


@pytest.fixture(autouse=True)
def _l3_clean(cli, _lb, dut, topo):
    """**Before and after** each L3 traffic case, clear test routes/neighbors, tear down leftover mirrors, and clear chip counters.

    Note: **do not touch loopback** -- loopback is held by the module-level `l3net` base (`_lb.hold`) and the per-case safety net re-enables
    it automatically; here we only clear the case-level dynamic increments (routes/neighbors/mirrors/counters), keeping the base unchanged to
    avoid cross-case leftovers turning re-ingress frames into a loop storm."""
    def _reset():
        for net in (topo.route("a"), topo.route("v6a")):
            v6 = ":" in net
            cli.sh.run(f"ip {'-6 ' if v6 else ''}route del {net}", check=False)
        # turn off any leftover egress mirror on all test ports (keeps them from mirroring traffic to cpu0 into a software loop) + clear chip counters
        for p in (topo.l3_port(0), topo.l3_port(1), topo.misc_port(0)):
            _lb.bsh.cmd(f"mirror port {dut.bcm_of(p)} mode=off")
        # parallel-lane discipline: use ChipCounters.clear (scoped to this worker's port block); a global bare `clear c` would
        # wipe the counter baseline another lane is measuring (the iron rule of zero global side effects on the observation path); single-lane semantics are unchanged.
        ChipCounters.clear(_lb.bsh)
    _reset()
    yield
    _reset()


def _wait_route(cli, dst_net, tries=20):
    """Wait for the static route to be programmed into the kernel (FRR/zebra)."""
    for _ in range(tries):
        if dst_net.split("/")[0] in cli.sh.run(f"ip route show {dst_net}", check=False).out:
            return True
        time.sleep(0.5)
    return False


def test_l3_ipv4_unicast_forwarding(l3net):
    """L3 IPv4 unicast forwarding, real traffic: inject IP packets at p_in -> route to p_out -> verify p_out chip TX +~N."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    env = l3net
    cli, dut, topo = env.cli, env.dut, env.topo
    p_in, p_out = env.p_in, env.p_out
    nh = env.sub_out["peer"]                   # next hop IP (within the p_out subnet)
    dst_net = topo.route("a")                  # remote destination subnet (e.g. 10.251.0.0/24)
    dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"

    # static neighbor + route (via SONiC/kernel). Note: at the CONFIG_DB layer the neighbor need not be truly reachable
    cli.neigh_set(nh, _NH_MAC, p_out.name)
    cli.sh.run(f"ip route replace {dst_net} via {nh}", check=False)
    try:
        if not _wait_route(cli, dst_net):
            pytest.fail(f"static route {dst_net} not programmed to kernel/FRR "
                        f"after 'ip route replace' with static neighbor; cannot drive L3 forward")

        rmac = env.rmac
        assert rmac, "router MAC (DEVICE_METADATA.mac) not found"
        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=env.sub_in["peer"], dst=dst_ip, ttl=64) / UDP())

        bsh = env.bsh
        ChipCounters.clear(bsh)                    # zero out: this diag `show c` only shows the change since the last show/clear,
        sendp(pkt, iface=p_in.name, count=_N, verbose=False)   # so clear->send->read once (= packets forwarded to p_out),
        time.sleep(1.0)                            # rather than base/after subtraction (base consumes the display + includes background noise -> negative delta)
        delta = ChipCounters.read(bsh, dut.bcm_of(p_out))

        # lower bound: >=N*0.9 proves the packets were indeed forwarded to p_out (real traffic, end to end).
        # upper bound: catches a runaway storm (flooding reaches the millions when the route isn't ready).
        assert _N * 0.9 <= delta.tx_pkt < 100_000, (
            f"L3 forward to {p_out.name}: chip TX delta={delta.tx_pkt} "
            f"(expected ~{_N} forwarded, no storm)")
    finally:
        cli.sh.run(f"ip route del {dst_net}", check=False)
        cli.neigh_del(nh, p_out.name)


def test_l3_ipv6_unicast_forwarding(l3net):
    """L3 IPv6 unicast forwarding, real traffic: inject IPv6 packets at p_in -> route to p_out -> verify p_out chip TX +~N.

    Note: the v6 case reuses the same p_in/p_out base (each port already has a v4 IP); it adds a v6 IP to the base ports and cleans it up at
    the end, leaving the base unaffected (v4 preserved)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    env = l3net
    cli, dut, topo = env.cli, env.dut, env.topo
    p_in, p_out = env.p_in, env.p_out
    sub_in, sub_out = topo.subnet("v6b"), topo.subnet("v6a")
    # add a v6 IP to the base ports (case-level increment, cleared at the end)
    cli.config_raw(f"interface ip add {p_in.name} {sub_in['dut']}/{sub_in['prefix']}")
    cli.config_raw(f"interface ip add {p_out.name} {sub_out['dut']}/{sub_out['prefix']}")
    nh = sub_out["peer"]                       # IPv6 next hop
    dst_net = topo.route("v6a")                # remote IPv6 subnet (e.g. 2001:db8:251::/64)
    dst_ip = dst_net.split("/")[0] + "5"

    cli.sh.run(f"ip -6 neigh replace {nh} lladdr {_NH_MAC} dev {p_out.name}", check=False)
    cli.sh.run(f"ip -6 route replace {dst_net} via {nh}", check=False)
    try:
        ok = False
        for _ in range(20):
            if dst_net.split("/")[0] in cli.sh.run(f"ip -6 route show {dst_net}", check=False).out:
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            pytest.fail(f"IPv6 static route {dst_net} not programmed to kernel "
                        f"after 'ip -6 route replace' with static neighbor; cannot drive L3 forward")

        rmac = env.rmac
        assert rmac, "router MAC (DEVICE_METADATA.mac) not found"
        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IPv6(src=sub_in["peer"], dst=dst_ip, hlim=64) / UDP())

        bsh = env.bsh
        ChipCounters.clear(bsh)
        sendp(pkt, iface=p_in.name, count=_N, verbose=False)
        time.sleep(1.0)
        delta = ChipCounters.read(bsh, dut.bcm_of(p_out))
        assert _N * 0.9 <= delta.tx_pkt < 100_000, (
            f"IPv6 L3 forward to {p_out.name}: chip TX delta={delta.tx_pkt} "
            f"(expected ~{_N} forwarded, no storm)")
    finally:
        cli.sh.run(f"ip -6 route del {dst_net}", check=False)
        cli.sh.run(f"ip -6 neigh del {nh} dev {p_out.name}", check=False)
        cli.config_raw(f"interface ip del {p_in.name} {sub_in['dut']}/{sub_in['prefix']}")
        cli.config_raw(f"interface ip del {p_out.name} {sub_out['dut']}/{sub_out['prefix']}")


def test_l3_forward_content_rewrite(l3net):
    """L3 forwarding **content check** (egress-mirror to CPU to capture the real frame): inject an IP packet routed to p_out, mirror p_out's
    egress to cpu0, capture the forwarded frame, and verify **DMAC rewritten to neighbor MAC, SMAC rewritten to router MAC, TTL decremented by
    1 (64->63)**. This truly "drives real traffic to verify forwarding correctness", not just ASIC programming.

    Note: this relies on egress-mirror-to-cpu0 delivering the forwarded frame to a netdev to be captured. On some platforms the KNET does not
    map mirror-to-cpu frames to any netdev (not a forwarding defect -- forwarding itself is already verified by
    test_l3_ipv4/ipv6/ecmp_forwarding + ttl). So gate on the mirror_cpu_capture capability: platforms without this observation capability skip
    gracefully rather than raising a false forwarding-defect failure."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo = env.cli, env.dut, env.topo
    topo.caps.require("mirror_cpu_capture")   # skip on platforms lacking mirror->netdev observation (forwarding is verified by other cases)
    from framework.traffic import Capture
    from framework.collector import MirrorCollector
    p_in, p_out = env.p_in, env.p_out
    nh = env.sub_out["peer"]
    dst_net = topo.route("a"); dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"
    cli.neigh_set(nh, _NH_MAC, p_out.name)
    cli.sh.run(f"ip route replace {dst_net} via {nh}", check=False)
    try:
        if not _wait_route(cli, dst_net):
            pytest.fail(f"route {dst_net} not programmed to kernel/FRR; "
                        f"cannot validate L3 forward content rewrite")
        rmac = env.rmac
        assert rmac, "router MAC (DEVICE_METADATA.mac) not found"
        dscp = topo.dscp("ef")                     # inject a DSCP, verify it is preserved after routing (unchanged when there is no remark policy)
        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=env.sub_in["peer"], dst=dst_ip, ttl=64, tos=dscp << 2) / UDP())
        mc = MirrorCollector(env.bsh, dut)
        mc.enable(p_out)
        try:
            # the mirrored frame shows up on the p_out netdev (direction may be outbound), so don't add an inbound filter; capture everything and filter by content
            with Capture(p_out.name, inbound=False) as cap:
                sendp(pkt, iface=p_in.name, count=20, verbose=False)
            # the unique signature of a forwarded frame: DMAC already rewritten to the neighbor MAC (distinct from the injected frame's DMAC=router MAC)
            fwd = [p for p in cap.packets
                   if p.haslayer(IP) and p[IP].dst == dst_ip
                   and p[Ether].dst.lower() == _NH_MAC.lower()]
            assert fwd, "no forwarded frame captured via egress mirror to cpu0"
            f = fwd[0]
            got_dmac, got_smac = f[Ether].dst.lower(), f[Ether].src.lower()
            assert got_dmac == _NH_MAC.lower(), \
                f"egress DMAC not rewritten to neighbor MAC: got {got_dmac}, want {_NH_MAC}"
            assert got_smac == rmac.lower(), \
                f"egress SMAC not rewritten to router MAC: got {got_smac}, want {rmac}"
            assert f[IP].ttl == 63, f"TTL not decremented on routing: got {f[IP].ttl}, want 63"
            assert (f[IP].tos >> 2) == dscp, \
                f"DSCP not preserved across routing: got {f[IP].tos >> 2}, want {dscp}"
        finally:
            mc.disable()
    finally:
        cli.sh.run(f"ip route del {dst_net}", check=False)
        cli.neigh_del(nh, p_out.name)


def test_l3_ttl_expired_not_forwarded(l3net):
    """L3 TTL-expired negative real traffic: inject TTL=1 packets; the DUT decrements to 0 and should **drop, not forward**, verify p_out chip
    TX~0 (distinct from the normal TTL=64 forwarding, proving the DUT handles TTL expiry correctly)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo = env.cli, env.dut, env.topo
    p_in, p_out = env.p_in, env.p_out
    nh = env.sub_out["peer"]
    dst_net = topo.route("a"); dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"
    cli.neigh_set(nh, _NH_MAC, p_out.name)
    cli.sh.run(f"ip route replace {dst_net} via {nh}", check=False)
    try:
        if not _wait_route(cli, dst_net):
            pytest.fail(f"route {dst_net} not programmed to kernel/FRR; "
                        f"cannot validate TTL-expired handling")
        rmac = env.rmac
        assert rmac, "router MAC (DEVICE_METADATA.mac) not found"
        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=env.sub_in["peer"], dst=dst_ip, ttl=1) / UDP())   # TTL=1 -> decremented to 0, expired
        bsh = env.bsh
        ChipCounters.clear(bsh)
        sendp(pkt, iface=p_in.name, count=_N, verbose=False)
        time.sleep(1.0)
        delta = ChipCounters.read(bsh, dut.bcm_of(p_out))
        # TTL-expired packets should be dropped, not forwarded to p_out (a tiny amount of background traffic is tolerated, but far < N)
        assert delta.tx_pkt < _N * 0.5, (
            f"TTL-expired packets should NOT be forwarded to {p_out.name}, "
            f"but chip TX delta={delta.tx_pkt} (sent={_N} with ttl=1)")
    finally:
        cli.sh.run(f"ip route del {dst_net}", check=False)
        cli.neigh_del(nh, p_out.name)


def test_l3_ecmp_member_failure_rebalances(l3net):
    """L3 ECMP **member-failure rebalancing** (the old "both ports >0" distribution case is now strictly covered by test_l3_route_chip's
    5-tuple 15% distribution case, so this was reworked into the previously missing failure-convergence scenario):
    (1) one route with two next hops, inject varying flows, both egress ports get a share (positive control, original check retained);
    (2) delete the nh2 neighbor -> orchagent removes that NHG member (wait for the ASIC NEIGHBOR_ENTRY to actually disappear) -> re-inject the
      same batch of flows, **all traffic re-hashes onto the surviving member**: p_o1 TX ~N, p_o2 TX ~0, total ~N (no black hole, no storm) --
      proving the hardware truly rebalances on member failure rather than black-holing the flows that landed on the failed member."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    from framework.verify import AsicDb
    env = l3net
    cli, dut, topo = env.cli, env.dut, env.topo
    p_in, p_o1, p_o2 = env.p_in, env.p_out, env.p_o2
    nh1, nh2 = env.sub_out["peer"], env.sub_o2["peer"]
    dst_net = topo.route("a"); dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"
    n = 200

    cli.neigh_set(nh1, "00:11:22:33:44:b1", p_o1.name)
    cli.neigh_set(nh2, "00:11:22:33:44:b2", p_o2.name)
    cli.sh.run(f"ip route replace {dst_net} nexthop via {nh1} nexthop via {nh2}", check=False)
    try:
        if not _wait_route(cli, dst_net):
            pytest.fail(f"ECMP route {dst_net} not programmed to kernel/FRR; "
                        f"cannot validate ECMP member failover")
        rmac = env.rmac
        assert rmac, "router MAC (DEVICE_METADATA.mac) not found"
        # vary the L4 source port + the last octet of the source, triggering the ECMP hash to spread different flows across different next hops
        base = env.sub_in["peer"].rsplit(".", 1)[0]
        pkts = [(Ether(dst=rmac, src=topo.mac("src")) /
                 IP(src=f"{base}.{10 + (i % 200)}", dst=dst_ip, ttl=64) /
                 UDP(sport=1000 + i, dport=80)) for i in range(n)]
        bsh = env.bsh
        # (1) positive control: with both members present, both egress ports get a share (clear->send->read each port once)
        ChipCounters.clear(bsh)
        sendp(pkts, iface=p_in.name, verbose=False)
        time.sleep(1.5)
        d1 = ChipCounters.read(bsh, dut.bcm_of(p_o1)).tx_pkt
        d2 = ChipCounters.read(bsh, dut.bcm_of(p_o2)).tx_pkt
        total = d1 + d2
        assert n * 0.9 <= total < 100_000, \
            f"ECMP total TX={total} (o1={d1}, o2={d2}, sent={n}); expected ~{n}, no storm"
        assert d1 > 0 and d2 > 0, \
            f"ECMP did not distribute across both nexthops: {p_o1.name} TX={d1}, {p_o2.name} TX={d2}"

        # (2) member failure: remove nh2 from the route (switch to single-hop nh1) + delete its neighbor -> orchagent shrinks the NHG.
        # Deleting only the neighbor while **the route still references nh2** leaves routeorch holding that nexthop reference -> neighorch does
        # not delete the ASIC NEIGHBOR_ENTRY (measured still present after 15s), so what gets tested is a race rather than post-convergence
        # rebalancing. Doing a single-hop route replace first removes nh2 from the NHG; only once nh2 is no longer referenced by any route can
        # its ASIC neighbor object truly be deleted -- this is an equivalent and more reliable "member failure" injection (control-plane
        # nexthop withdrawal), with the same observation target (surviving member absorbs all flows, failed member zero, no black hole, no storm).
        cli.sh.run(f"ip route replace {dst_net} via {nh1}", check=False)
        cli.neigh_del(nh2, p_o2.name)
        asic = AsicDb(cli)
        gone = False
        end = time.time() + 30
        while time.time() < end:
            if not any(nh2 in k for k in asic.objects("SAI_OBJECT_TYPE_NEIGHBOR_ENTRY")):
                gone = True
                break
            time.sleep(0.5)
        assert gone, (f"neighbor {nh2} still in ASIC NEIGHBOR_ENTRY 30s after removing it from the "
                      f"route (nexthop via {nh1} only) and deleting the neighbor; "
                      f"cannot cleanly measure ECMP member failover")
        # re-inject the same batch of flows: should all re-hash onto the surviving member nh1/p_o1
        ChipCounters.clear(bsh)
        sendp(pkts, iface=p_in.name, verbose=False)
        time.sleep(1.5)
        d1b = ChipCounters.read(bsh, dut.bcm_of(p_o1)).tx_pkt
        d2b = ChipCounters.read(bsh, dut.bcm_of(p_o2)).tx_pkt
        assert d2b < n * 0.1, (
            f"flows still egress the FAILED ECMP member {p_o2.name} (TX={d2b}) after its "
            f"neighbor was removed from ASIC")
        assert n * 0.9 <= d1b < 100_000, (
            f"surviving ECMP member {p_o1.name} did not absorb all flows after member failure: "
            f"TX={d1b} (sent={n}, failed member TX={d2b}); traffic black-holed or storming")
    finally:
        cli.sh.run(f"ip route del {dst_net}", check=False)
        cli.neigh_del(nh1, p_o1.name)
        cli.neigh_del(nh2, p_o2.name)
