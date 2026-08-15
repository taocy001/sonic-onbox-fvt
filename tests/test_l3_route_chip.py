"""L3 routing **path-selection** chip-behavior test suite -- verifies LPM longest-prefix
match, host-route (/32) preference, default route, and connected-route behavior on the
**hardware forwarding plane**, not merely the presence of objects in ASIC_DB.

Complementary to test_l3_forward_traffic.py: that file verifies "unicast can forward / TTL
expiry / content rewrite / ECMP existence"; this file focuses on the **routing decision**:
when multiple prefixes simultaneously cover one destination address, does the chip pick the
correct next-hop egress port by longest prefix (proving the selection by pointing different
prefixes at different physical egresses and observing which port the traffic leaves from).

Mechanism (reuses the on-hardware-verified L3 pattern, storm-free):
  p_in / p_out1 / p_out2 each get an L3 IP + MAC loopback enabled; inject into p_in an IP
  packet with "outer DMAC = DUT router MAC, dest IP hitting the prefix under test" -> it
  re-enters via p_in loopback -> DUT selects a route and forwards to some egress port
  (TTL-1, DMAC rewritten to that egress's neighbor MAC) -> it physically leaves that egress
  (chip TX +N) -> re-enters via that port's loopback -> dropped at the L3 port because
  DMAC != router MAC (not forwarded again, hence no storm).
  Point two prefixes covering the same address at p_out1 / p_out2 respectively, and observe
  **which port's TX increments** to know which route the chip selected.

Each test asserts both:
  1) the corresponding SAI_OBJECT_TYPE_ROUTE_ENTRY appears in ASIC_DB (programming path);
  2) data plane: the correct egress port's chip TX ~= N, the wrong egress port's TX ~= 0
     (hardware selection conclusion);
  connected/rewrite tests additionally use an egress mirror to capture real frames and
  verify DMAC rewrite + TTL-1.

All values come from topo; ports use the L3 domain (c,d) + misc domain (g), three ports,
to avoid port conflicts with other tests.
Print/assert/skip and comments/docstrings in English.
"""
import time

import pytest

from framework.collector import MirrorCollector
from framework.counters import ChipCounters
from framework.traffic import Capture
from framework.verify import AsicDb

pytestmark = pytest.mark.l3

try:
    from scapy.all import Ether, IP, IPv6, UDP, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 40                         # injected packet count (small + upper-bound assert guards against runaway storm)
_NH1_MAC = "00:11:22:33:55:a1"  # egress-1 neighbor (next-hop) MAC -- DMAC rewrite target when egress-1 is selected
_NH2_MAC = "00:11:22:33:55:a2"  # egress-2 neighbor MAC -- verifies egress-2 selection
_TX_HI = 100_000                # TX upper bound: catches route-not-ready -> flood -> storm


@pytest.fixture(autouse=True)
def _route_clean(cli, _lb, dut, topo):
    """Before/after each test, clear the test routes/neighbors this file programs, disable
    leftover mirrors, and clear chip counters.
    Note: **does not touch loopback** -- loopback is held by the module-level `l3net` base
    (`_lb.hold`); each test only clears the route/neighbor/mirror/counter delta, keeping the
    base unchanged, to avoid cross-test residue (undeleted routes / stale neighbors / mixed
    state) that would make re-entering frames loop into a storm."""
    nets = ["10.251.0.0/16", "10.251.7.0/24", "10.251.7.9/32",
            "10.251.8.0/24", "10.99.123.0/24", "128.0.0.0/1", topo.route("a"), topo.route("b")]

    # Test routes for the v6 selection cases (big=topo.route("v6a"), small=its longer inner
    # prefix); clean these up defensively too
    nets6 = [topo.route("v6a"), f"{topo.route('v6a').split('/')[0]}/120"]

    def _reset():
        for net in nets:
            cli.sh.run(f"ip route del {net}", check=False)
        for net in nets6:
            cli.sh.run(f"ip -6 route del {net}", check=False)
        for p in (topo.l3_port(0), topo.l3_port(1), topo.misc_port(0)):
            cli.sh.run(f"ip neigh flush dev {p.name}", check=False)
            cli.sh.run(f"ip -6 neigh flush dev {p.name}", check=False)
            _lb.bsh.cmd(f"mirror port {dut.bcm_of(p)} mode=off")
        # Parallel-lane discipline: use ChipCounters.clear (scoped to this worker's port
        # block); a global bare `clear c` would wipe the counter baseline another lane is
        # measuring (iron rule: observation lane has zero global side effects); single-lane
        # semantics unchanged.
        ChipCounters.clear(_lb.bsh)

    _reset()
    yield
    _reset()


def _router_mac(cli):
    return cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")


def _wait_route(cli, dst_net, tries=20):
    """Wait for the static route to be programmed into the kernel (FRR/zebra); returns
    whether it is ready.
    The default route 0.0.0.0/0 renders in the kernel as `default via ...` (does not contain
    the substring 0.0.0.0), so for the /0 prefix switch to matching the `default` keyword to
    avoid a substring match that would always fail."""
    base = dst_net.split("/")[0]
    is_default = dst_net in ("0.0.0.0/0", "::/0")
    for _ in range(tries):
        out = cli.sh.run(f"ip route show {dst_net}", check=False).out
        if (is_default and "default" in out) or (not is_default and base in out):
            return True
        time.sleep(0.5)
    return False


def _tx(bsh, dut, port):
    return ChipCounters.read(bsh, dut.bcm_of(port)).tx_pkt


_SRC_MAC = "00:de:ad:be:ef:01"   # injected source MAC (outer SMAC; rewritten to router MAC after forwarding)


def _drive(p_in, src_ip, dst_ip, rmac, count=_N, ttl=64):
    """Inject into p_in an IP packet with "outer DMAC = router MAC, dest hitting the prefix
    under test" to trigger hardware path-selected forwarding."""
    pkt = (Ether(dst=rmac, src=_SRC_MAC) /
           IP(src=src_ip, dst=dst_ip, ttl=ttl) / UDP(sport=33000, dport=80))
    sendp(pkt, iface=p_in.name, count=count, verbose=False)


# ============================ path-selection tests ============================

def test_host_route_preferred_over_lpm(l3net):
    """Host route (/32) preferred over the LPM route covering it: the same destination
    address is covered by both a /24 and a /32; the /24 points to egress-1, the /32 to
    egress-2; a packet hitting that address should **take the /32 (egress-2)** -- chip
    longest-prefix match.

    Verifies: ASIC_DB has both ROUTE_ENTRYs; data plane egress-2 TX ~= N while egress-1
    TX ~= 0."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    env = l3net
    cli, dut, topo, bsh = env.cli, env.dut, env.topo, env.bsh
    p_in, p1, p2 = env.p_in, env.p_out, env.p_o2        # /24 egress=p1, /32 egress=p2
    s_in, s1, s2 = env.sub_in, env.sub_out, env.sub_o2
    nh1, nh2 = s1["peer"], s2["peer"]
    lpm_net = "10.251.7.0/24"
    host_net = "10.251.7.9/32"
    dst_ip = "10.251.7.9"          # hits both /24 and /32; longest prefix = /32 -> egress-2

    rmac = env.rmac
    if not rmac:
        pytest.fail("DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found on DUT")
    cli.neigh_set(nh1, _NH1_MAC, p1.name)
    cli.neigh_set(nh2, _NH2_MAC, p2.name)
    cli.sh.run(f"ip route replace {lpm_net} via {nh1}", check=False)
    cli.sh.run(f"ip route replace {host_net} via {nh2}", check=False)

    if not (_wait_route(cli, lpm_net) and _wait_route(cli, host_net)):
        pytest.fail("DEVICE DEFECT: LPM/host static routes not entering kernel/FRR (routing not programmed)")

    # ASIC_DB programming path: both prefixes should appear as ROUTE_ENTRY
    asic = AsicDb(cli)
    assert asic.has_route("10.251.7.9/32"), "host route /32 not programmed to ASIC_DB"
    assert asic.has_route("10.251.7.0/24"), "LPM route /24 not programmed to ASIC_DB"

    # This diag `show c` is a changed-since-clear view: clear -> send -> read once per port
    # (per-port independent).
    ChipCounters.clear(bsh)
    _drive(p_in, s_in["peer"], dst_ip, rmac)
    time.sleep(1.0)
    d1, d2 = _tx(bsh, dut, p1), _tx(bsh, dut, p2)

    assert d2 >= _N * 0.9, (
        f"host route /32 not selected: expected ~{_N} on {p2.name}, got TX delta={d2}")
    assert d1 < _N * 0.5, (
        f"traffic leaked to LPM /24 egress {p1.name} (TX delta={d1}); host /32 should win")
    assert d2 < _TX_HI, f"storm on {p2.name}: TX delta={d2}"


def test_lpm_longest_prefix_selection(l3net):
    """Longest-prefix match: a /16 overlaps a more-specific /24, pointing to egress-1 /
    egress-2 respectively; a packet hitting the /24 range should take the /24 (egress-2),
    a packet hitting only the /16 (not in the /24) should take the /16 (egress-1). Two
    injections prove the chip selects by longest prefix."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo, bsh = env.cli, env.dut, env.topo, env.bsh
    p_in, p1, p2 = env.p_in, env.p_out, env.p_o2        # /16 egress=p1, /24 egress=p2
    s_in, s1, s2 = env.sub_in, env.sub_out, env.sub_o2
    nh1, nh2 = s1["peer"], s2["peer"]
    big_net = "10.251.0.0/16"
    small_net = "10.251.7.0/24"
    ip_in_small = "10.251.7.50"     # hits /24 -> egress-2
    ip_only_big = "10.251.9.50"     # hits /16 but not in /24 -> egress-1

    rmac = env.rmac
    if not rmac:
        pytest.fail("DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found on DUT")
    cli.neigh_set(nh1, _NH1_MAC, p1.name)
    cli.neigh_set(nh2, _NH2_MAC, p2.name)
    cli.sh.run(f"ip route replace {big_net} via {nh1}", check=False)
    cli.sh.run(f"ip route replace {small_net} via {nh2}", check=False)

    if not (_wait_route(cli, big_net) and _wait_route(cli, small_net)):
        pytest.fail("DEVICE DEFECT: /16 and /24 static routes not entering kernel/FRR (routing not programmed)")

    asic = AsicDb(cli)
    assert asic.has_route("10.251.0.0/16"), "/16 route not programmed to ASIC_DB"
    assert asic.has_route("10.251.7.0/24"), "/24 route not programmed to ASIC_DB"

    # Each injection window independently: clear -> send -> read once per port
    # (changed-since-clear view).
    # (a) hits /24 -> should take egress-2
    ChipCounters.clear(bsh)
    _drive(p_in, s_in["peer"], ip_in_small, rmac)
    time.sleep(1.0)
    d1, d2 = _tx(bsh, dut, p1), _tx(bsh, dut, p2)
    assert d2 >= _N * 0.9 and d1 < _N * 0.5, (
        f"dst in /24 should egress {p2.name}: got out1={d1}, out2={d2}")

    # (b) hits only /16 -> should take egress-1
    ChipCounters.clear(bsh)
    _drive(p_in, s_in["peer"], ip_only_big, rmac)
    time.sleep(1.0)
    d1, d2 = _tx(bsh, dut, p1), _tx(bsh, dut, p2)
    assert d1 >= _N * 0.9 and d2 < _N * 0.5, (
        f"dst only in /16 should egress {p1.name}: got out1={d1}, out2={d2}")
    assert d1 < _TX_HI, f"storm on {p1.name}: TX delta={d1}"


def _derive_v6_subnet(sub, bump=2):
    """Derive a new subnet from an existing v6 subnet (the profile has only v6a/v6b, and the
    three-port v6 scenario needs one more): third hextet +bump. Derived from topo values (not
    hardcoded), and naturally disjoint from the worker offset (remap_ip6 = third hextet
    +0x100 per worker) -- still isolated across workers after derivation."""
    head = sub["dut"].split("::")[0]           # e.g. "2001:db8:83"
    parts = head.split(":")
    parts[-1] = format(int(parts[-1], 16) + bump, "x")
    base = ":".join(parts)
    return {"dut": f"{base}::1", "peer": f"{base}::2", "prefix": sub["prefix"]}


def _route6_replace_wait(cli, net, via, tries=20):
    """Program a v6 static route + wait for it to be programmed into the kernel. Before DAD
    completes after address configuration, `ip -6 route replace` is rejected because the
    nexthop is unreachable -- resend in a loop until the route is visible (equivalent to
    waiting for DAD + connected route to be ready)."""
    for _ in range(tries):
        cli.sh.run(f"ip -6 route replace {net} via {via}", check=False)
        if net.split("/")[0] in cli.sh.run(f"ip -6 route show {net}", check=False).out:
            return True
        time.sleep(0.5)
    return False


def _drive6(p_in, src_ip, dst_ip, rmac, count=_N):
    """Inject into p_in an IPv6 packet with "outer DMAC = router MAC, dest hitting the v6
    prefix under test" to trigger hardware path-selected forwarding."""
    pkt = (Ether(dst=rmac, src=_SRC_MAC) /
           IPv6(src=src_ip, dst=dst_ip, hlim=64) / UDP(sport=33000, dport=80))
    sendp(pkt, iface=p_in.name, count=count, verbose=False)


def test_lpm_longest_prefix_selection_v6(l3net):
    """IPv6 longest-prefix match (v6 twin of test_lpm_longest_prefix_selection): v6 LPM uses
    a separate ASIC table/key width that the v4 selection conclusion cannot cover. The /64
    points to egress-1, the longer inner /120 to egress-2; an IPv6 packet hitting the /120
    range should take egress-2, one hitting only the /64 (not in the /120) should take
    egress-1.

    Per v6-test convention, the base ports temporarily get v6 IPs added (p_in=v6b,
    egress-1=v6a, egress-2=derived from v6a), cleaned up at the end."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo, bsh = env.cli, env.dut, env.topo, env.bsh
    p_in, p1, p2 = env.p_in, env.p_out, env.p_o2        # /64 egress=p1, /120 egress=p2
    sub_in, sub1 = topo.subnet("v6b"), topo.subnet("v6a")
    sub2 = _derive_v6_subnet(topo.subnet("v6a"))
    nh1, nh2 = sub1["peer"], sub2["peer"]
    big_net = topo.route("v6a")                          # e.g. 2001:db8:251::/64
    base6 = big_net.split("/")[0]                        # "2001:db8:251::"
    small_net = f"{base6}/120"                           # longer prefix inside /64 (low 256 addresses)
    ip_in_small = f"{base6}9"                            # hits both /64 and /120 -> egress-2
    ip_only_big = f"{base6}1:9"                          # hits /64 but outside /120 -> egress-1

    rmac = env.rmac
    if not rmac:
        pytest.fail("DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found on DUT")
    # Add v6 IPs to the base ports (test-level delta, cleaned up in finally, does not affect base v4)
    cli.config_raw(f"interface ip add {p_in.name} {sub_in['dut']}/{sub_in['prefix']}")
    cli.config_raw(f"interface ip add {p1.name} {sub1['dut']}/{sub1['prefix']}")
    cli.config_raw(f"interface ip add {p2.name} {sub2['dut']}/{sub2['prefix']}")
    cli.sh.run(f"ip -6 neigh replace {nh1} lladdr {_NH1_MAC} dev {p1.name}", check=False)
    cli.sh.run(f"ip -6 neigh replace {nh2} lladdr {_NH2_MAC} dev {p2.name}", check=False)
    try:
        if not (_route6_replace_wait(cli, big_net, nh1)
                and _route6_replace_wait(cli, small_net, nh2)):
            pytest.fail("DEVICE DEFECT: IPv6 /64 and /120 static routes not entering kernel/FRR "
                        "(v6 routing not programmed)")

        asic = AsicDb(cli)
        assert asic.has_route(big_net), f"IPv6 {big_net} route not programmed to ASIC_DB"
        assert asic.has_route(small_net), f"IPv6 {small_net} route not programmed to ASIC_DB"

        # (a) hits /120 -> should take egress-2 (each injection window: clear -> send -> read once per port)
        ChipCounters.clear(bsh)
        _drive6(p_in, sub_in["peer"], ip_in_small, rmac)
        time.sleep(1.0)
        d1, d2 = _tx(bsh, dut, p1), _tx(bsh, dut, p2)
        assert d2 >= _N * 0.9 and d1 < _N * 0.5, (
            f"IPv6 dst in /120 should egress {p2.name} (longest prefix): got out1={d1}, out2={d2}")
        assert d2 < _TX_HI, f"storm on {p2.name}: TX delta={d2}"

        # (b) hits only /64 -> should take egress-1
        ChipCounters.clear(bsh)
        _drive6(p_in, sub_in["peer"], ip_only_big, rmac)
        time.sleep(1.0)
        d1, d2 = _tx(bsh, dut, p1), _tx(bsh, dut, p2)
        assert d1 >= _N * 0.9 and d2 < _N * 0.5, (
            f"IPv6 dst only in /64 should egress {p1.name}: got out1={d1}, out2={d2}")
        assert d1 < _TX_HI, f"storm on {p1.name}: TX delta={d1}"
    finally:
        cli.sh.run(f"ip -6 route del {big_net}", check=False)
        cli.sh.run(f"ip -6 route del {small_net}", check=False)
        cli.sh.run(f"ip -6 neigh del {nh1} dev {p1.name}", check=False)
        cli.sh.run(f"ip -6 neigh del {nh2} dev {p2.name}", check=False)
        cli.config_raw(f"interface ip del {p_in.name} {sub_in['dut']}/{sub_in['prefix']}")
        cli.config_raw(f"interface ip del {p1.name} {sub1['dut']}/{sub1['prefix']}")
        cli.config_raw(f"interface ip del {p2.name} {sub2['dut']}/{sub2['prefix']}")


def test_default_route_catchall(l3net):
    """Default-route catch-all: for a destination address not covered by any specific
    prefix, the injected packet should take the "default route" egress.
    Verifies: ASIC_DB has the catch-all ROUTE_ENTRY; data plane that egress's TX ~= N.

    Safety-critical: **never use literal 0.0.0.0/0** -- this DUT's mgmt (eth0) default route
    is in the main table, and the build host (SSH peer) is on a different subnet with return
    traffic going through that default route; `ip route replace 0.0.0.0/0` would override the
    mgmt default route and break SSH. Instead use the **upper-half default** 128.0.0.0/1
    (covers 128.0.0.0-255.255.255.255): for the public test destination 198.51.100.7 (>128)
    it is the only catch-all prefix, yet it does not cover 10.x (mgmt gateway / build host) --
    mgmt return traffic still uses the original 0.0.0.0/0 and SSH is unaffected. Semantically
    this is "catch-all forwarding when no more-specific prefix covers the destination", i.e.
    default-route behavior."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo, bsh = env.cli, env.dut, env.topo, env.bsh
    p_in, p1 = env.p_in, env.p_out
    s_in, s1 = env.sub_in, env.sub_out
    nh1 = s1["peer"]
    default_net = "128.0.0.0/1"                    # upper-half default (catch-all), does not override mgmt's 0.0.0.0/0
    # Pick an address not covered by any other prefix in this suite (all 10.x) and inside
    # 128.0.0.0/1 (public range) so it can only hit this catch-all prefix
    dst_ip = "198.51.100.7"

    rmac = env.rmac
    if not rmac:
        pytest.fail("DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found on DUT")
    cli.neigh_set(nh1, _NH1_MAC, p1.name)
    cli.sh.run(f"ip route replace {default_net} via {nh1}", check=False)
    try:
        if not _wait_route(cli, default_net):
            pytest.fail("DEVICE DEFECT: catch-all route 128.0.0.0/1 not entering kernel/FRR (routing not programmed)")

        asic = AsicDb(cli)
        assert asic.has_route(default_net), "catch-all (upper-half default) route not programmed to ASIC_DB"

        ChipCounters.clear(bsh)                    # changed-since-clear view: clear -> send -> read once
        _drive(p_in, s_in["peer"], dst_ip, rmac)
        time.sleep(1.0)
        d1 = _tx(bsh, dut, p1)
        assert _N * 0.9 <= d1 < _TX_HI, (
            f"default route did not forward catch-all dst to {p1.name}: "
            f"TX delta={d1} (expected ~{_N}, no storm)")
    finally:
        cli.sh.run(f"ip route del {default_net}", check=False)


def test_connected_route_forward_and_rewrite(l3net):
    """Connected-route forward + L3 rewrite: the dest IP falls in an egress port's
    **connected subnet** (no static route needed) with the neighbor resolved; a packet
    hitting some host in that subnet should forward directly out that connected port. Use an
    egress mirror to capture the real frame and verify DMAC rewritten to the neighbor MAC,
    SMAC rewritten to router MAC, TTL 64->63. Verifies the chip forwards + rewrites correctly
    for connected prefixes."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo, bsh = env.cli, env.dut, env.topo, env.bsh
    # Relies on egress-mirror-to-cpu0 to capture forwarded frames; on some platforms KNET
    # does not deliver mirror frames to the netdev (not a forwarding defect), gated to skip
    topo.caps.require("mirror_cpu_capture")
    p_in, p_out = env.p_in, env.p_out
    s_in, s_out = env.sub_in, env.sub_out
    # Another host in the connected subnet (not dut/peer itself), as the forwarding
    # destination; the neighbor points to it
    host_ip = s_out["peer"].rsplit(".", 1)[0] + ".66"

    rmac = env.rmac
    if not rmac:
        pytest.fail("DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found on DUT")
    # No static route programmed -- the connected subnet is already in the routing table
    # (connected route). Only resolve the destination host's neighbor.
    cli.neigh_set(host_ip, _NH1_MAC, p_out.name)
    time.sleep(0.5)

    # ASIC_DB should have the ROUTE_ENTRY for this connected subnet (subnet/connected route)
    asic = AsicDb(cli)
    connected_pfx = f"{s_out['dut'].rsplit('.', 1)[0]}.0/{s_out['prefix']}"
    assert asic.has_route(connected_pfx), (
        f"connected route {connected_pfx} not programmed to ASIC_DB")

    pkt = (Ether(dst=rmac, src=topo.mac("src")) /
           IP(src=s_in["peer"], dst=host_ip, ttl=64) / UDP(sport=33000, dport=80))
    mc = MirrorCollector(bsh, dut)
    mc.enable(p_out)
    try:
        with Capture(p_out.name, inbound=False) as cap:
            sendp(pkt, iface=p_in.name, count=20, verbose=False)
        fwd = [p for p in cap.packets
               if p.haslayer(IP) and p[IP].dst == host_ip
               and p[Ether].dst.lower() == _NH1_MAC.lower()]
        assert fwd, (
            f"no forwarded frame captured on connected route to {host_ip} "
            f"via egress mirror on {p_out.name}")
        f = fwd[0]
        assert f[Ether].dst.lower() == _NH1_MAC.lower(), (
            f"DMAC not rewritten to neighbor: got {f[Ether].dst}, want {_NH1_MAC}")
        assert f[Ether].src.lower() == rmac.lower(), (
            f"SMAC not rewritten to router MAC: got {f[Ether].src}, want {rmac}")
        assert f[IP].ttl == 63, f"TTL not decremented on connected-route forward: got {f[IP].ttl}"
    finally:
        mc.disable()
        cli.neigh_del(host_ip, p_out.name)


def test_ecmp_hash_distributes_5tuple(l3net):
    """ECMP 5-tuple hash distribution: one route with two next-hops (on two egress ports),
    inject multiple flows **varying the whole 5-tuple** (varying SIP/DIP last octet + L4
    source/dest ports), verify both egress ports get traffic and the distribution is not
    extremely skewed (each carries >15% of the total). Stronger than "both ports >0": proves
    the chip's ECMP hash truly spreads by 5-tuple rather than sending all flows to a single
    member."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = l3net
    cli, dut, topo, bsh = env.cli, env.dut, env.topo, env.bsh
    p_in, p1, p2 = env.p_in, env.p_out, env.p_o2
    s_in, s1, s2 = env.sub_in, env.sub_out, env.sub_o2
    nh1, nh2 = s1["peer"], s2["peer"]
    ecmp_net = topo.route("a")               # remote destination network
    n = 256

    rmac = env.rmac
    if not rmac:
        pytest.fail("DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found on DUT")
    cli.neigh_set(nh1, _NH1_MAC, p1.name)
    cli.neigh_set(nh2, _NH2_MAC, p2.name)
    cli.sh.run(f"ip route replace {ecmp_net} nexthop via {nh1} nexthop via {nh2}", check=False)
    try:
        if not _wait_route(cli, ecmp_net):
            pytest.fail(f"DEVICE DEFECT: ECMP route {ecmp_net} not entering kernel/FRR (routing not programmed)")

        asic = AsicDb(cli)
        assert asic.has_route(ecmp_net), f"ECMP route {ecmp_net} not in ASIC_DB"

        sbase = s_in["peer"].rsplit(".", 1)[0]
        dbase = ecmp_net.split("/")[0].rsplit(".", 1)[0]
        # Vary the whole 5-tuple: SIP last octet, DIP last octet, L4 sport, L4 dport all vary,
        # maximizing hash entropy
        pkts = [(Ether(dst=rmac, src=topo.mac("src")) /
                 IP(src=f"{sbase}.{10 + (i % 200)}", dst=f"{dbase}.{20 + (i % 200)}", ttl=64) /
                 UDP(sport=2000 + i, dport=3000 + (i * 7) % 5000)) for i in range(n)]

        # changed-since-clear view: clear -> send -> read once per port (per-port independent)
        ChipCounters.clear(bsh)
        sendp(pkts, iface=p_in.name, verbose=False)
        time.sleep(1.5)
        d1, d2 = _tx(bsh, dut, p1), _tx(bsh, dut, p2)
        total = d1 + d2

        assert n * 0.9 <= total < _TX_HI, (
            f"ECMP total TX={total} (o1={d1}, o2={d2}, sent={n}); expected ~{n}, no storm")
        # Distribution not extremely skewed: each member carries at least 15% of the total
        # (256 flows, 2 members, ideally ~50% each, generous tolerance)
        assert d1 >= total * 0.15 and d2 >= total * 0.15, (
            f"ECMP hash skewed/not distributing across nexthops: "
            f"{p1.name} TX={d1}, {p2.name} TX={d2} (total={total}); "
            f"each member should carry >=15% of 5-tuple-varied flows")
    finally:
        cli.sh.run(f"ip route del {ecmp_net}", check=False)
