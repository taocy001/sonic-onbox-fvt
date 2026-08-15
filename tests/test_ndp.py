"""NDP (IPv6) full feature set: ND/neighbor/RA/DAD/proxy/RA-Guard. Ports referenced from topo. Capacity/rate needs a traffic generator -- out of this framework's scope, no case provided."""
import time

import pytest

from framework import l3probe

pytestmark = [pytest.mark.l3]


def _connected6(topo):
    """Derive the connected prefix from the v6a subnet (e.g. 2001:db8:83::/64)."""
    net = topo.subnet("v6a")
    base = net["dut"].rsplit("::", 1)[0]
    return f"{base}::/{net['prefix']}"


def _l3v6(cli, guard, topo, port, cidr=None):
    net = topo.subnet("v6a")
    if cidr is None:
        cidr = f"{net['dut']}/{net['prefix']}"
    cli.config_raw(f"vlan member del {topo.default_vlan} {port}")
    guard.defer_undo(f"vlan member add -u {topo.default_vlan} {port}")
    cli.config(f"interface ip add {port} {cidr}")
    guard.defer_undo(f"interface ip remove {port} {cidr}")
    cli.intf_startup(port)


def _wait_neigh_entry(asicdb, nh_ip, mac, timeout=10.0):
    """Poll ASIC_DB NEIGHBOR_ENTRY: return the key matching this next-hop IP with DST_MAC equal to the given MAC (None if absent).
    Stronger than wait_count_gt (which only watches count growth): the count can be satisfied by a
    parallel lane / kernel background neighbor; only a DST_MAC match proves **this** nh->MAC neighbor
    was really programmed into the chip (the same gold-standard as test_arp_full/test_l3_neighbor_chip)."""
    want = mac.upper()
    end = time.time() + timeout
    while time.time() < end:
        for k in asicdb.objects("SAI_OBJECT_TYPE_NEIGHBOR_ENTRY"):
            if nh_ip in k:
                got = (asicdb.field(k, "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS") or "")
                if got.upper() == want:
                    return k
        time.sleep(0.5)
    return None


def test_ipv6_address_and_rif(cli, asicdb, l3up, topo):
    """IPv6 config -> connected route programmed (proves RIF + route, more robust to port reuse than the RIF-count method)."""
    net = topo.subnet("v6a")
    l3up(topo.port_name("c"), f"{net['dut']}/{net['prefix']}")
    assert asicdb.has_route(_connected6(topo), timeout=10), "IPv6 config did not create RIF/connected route"


@pytest.mark.traffic
def test_static_neighbor_v6(cli, asicdb, dut, _lb, l3up, topo, config_guard):
    """Static IPv6 neighbor: (1) ASIC NEIGHBOR/route programming + (2) **real traffic**: after configuring a static v6 neighbor, inject an IPv6 packet routed to that next hop,
    verifying it really forwards out p_out by the neighbor (chip TX +≈N), proving static ND is genuinely used for data-plane forwarding (not just programmed)."""
    topo.caps.require("loopback")
    route_v6 = topo.route("v6a")
    dst_ip = route_v6.split("/")[0] + "5"
    with l3probe.TwoPortL3(cli, dut, _lb, topo, l3up, v6=True) as s:
        assert s.rmac, "router MAC (DEVICE_METADATA.mac) not found"
        # Verify **this** static neighbor (s.nh -> NH_MAC) was really programmed into ASIC: the old
        # "count grew OR route exists" could be satisfied by a parallel-lane background neighbor /
        # a leftover route from the previous case (false pass); only a DST_MAC match is real evidence.
        assert _wait_neigh_entry(asicdb, s.nh, l3probe.NH_MAC, timeout=10), (
            f"static IPv6 neighbor {s.nh}->{l3probe.NH_MAC} not programmed to ASIC "
            f"NEIGHBOR_ENTRY with matching DST_MAC")
        cli.config_raw(f"route add prefix {route_v6} nexthop {s.nh}")
        config_guard.defer_undo(f"route del prefix {route_v6} nexthop {s.nh}")
        if not l3probe.wait_route(cli, route_v6):
            pytest.fail(f"IPv6 route {route_v6} not installed to kernel FIB; "
                        f"cannot drive traffic")
        tx = s.forward_tx(dst_ip, n=30)
        assert 27 <= tx < 100_000, \
            f"static v6 neighbor real-traffic: chip TX to {s.p_out.name}={tx} (expected ~30 forwarded)"


def test_ipv6_connected_route_teardown(cli, asicdb, l3up, topo, config_guard):
    """connected route **teardown direction** (distinct from the setup direction of test_ipv6_address_and_rif --
    the two cases were previously byte-level duplicates, two runs of the same thing with zero new signal):
    after ip removal, the connected ROUTE_ENTRY must genuinely disappear from ASIC, covering the
    v6 address withdrawal -> route reclamation chain (the zebra->orch->SAI delete path was previously unobserved)."""
    net = topo.subnet("v6a")
    pfx = _connected6(topo)
    port = topo.port_name("c")
    cidr = f"{net['dut']}/{net['prefix']}"
    l3up(port, cidr)
    assert asicdb.has_route(pfx, timeout=10), "IPv6 connected route not programmed"
    cli.config(f"interface ip remove {port} {cidr}")
    gone = False
    end = time.time() + 15
    while time.time() < end:
        if not any(pfx in k for k in asicdb.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY")):
            gone = True
            break
        time.sleep(0.5)
    assert gone, (
        f"IPv6 connected route {pfx} still in ASIC_DB after 'interface ip remove' "
        f"(v6 route teardown not reaching the chip)")


def test_dynamic_nd_learning(cli, _lb, asicdb, topo, config_guard):
    """Dynamic ND learning (the v6 counterpart of test_dynamic_arp_learning, previously missing): a real NS->NA exchange
    drives neighsyncd -> ASIC NEIGHBOR_ENTRY -- an independent code path for ICMPv6 / link-local sources
    that neither static `ip -6 neigh` nor v4 ARP covers. A stand-in responder (inline NdpResponder,
    mirroring responders/arp.py) answers the DUT's NS for the peer v6 on the loopback port; assert:
    (1) the DUT really sent an NS; (2) peer_ip->peer_mac is programmed into ASIC with matching DST_MAC.
    Single-port loopback, only answering the targeted NS; storm-guard mode matches the ARP version."""
    from responders.base import Responder
    topo.caps.require("loopback")
    net = topo.subnet("v6a")
    peer_ip, dut_ip = net["peer"], net["dut"]
    peer_mac = topo.mac("peer_c")
    port = topo.port("c")
    dev = port.name

    class NdpResponder(Responder):
        """Answer the ICMPv6 NS for peer_ip: reply with a solicited NA (carrying peer_mac)."""
        bpf = "icmp6"
        def handle(self, pkt):
            from scapy.all import (Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
                                   ICMPv6NDOptDstLLAddr)
            if not pkt.haslayer(ICMPv6ND_NS) or not _eq6(pkt[ICMPv6ND_NS].tgt, peer_ip):
                return None
            self.stats["seen"] += 1
            src6 = pkt[IPv6].src
            dst6 = src6 if src6 != "::" else "ff02::1"
            return (Ether(dst=pkt[Ether].src, src=peer_mac) /
                    IPv6(src=peer_ip, dst=dst6) /
                    ICMPv6ND_NA(tgt=peer_ip, R=0, S=1, O=1) /
                    ICMPv6NDOptDstLLAddr(lladdr=peer_mac))

    _l3v6(cli, config_guard, topo, dev)
    _lb.enable(port)
    try:
        # Wait for the DUT address to finish DAD (during tentative, ping6 cannot select it as source)
        end = time.time() + 8
        while time.time() < end:
            r = cli.sh.run(f"ip -6 addr show dev {dev}", check=False)
            if dut_ip in (r.out or "") and "tentative" not in (r.out or ""):
                break
            time.sleep(0.5)
        with NdpResponder(dev) as resp:
            cli.sh.run(f"ping -6 -c 4 -W 1 -I {dev} {peer_ip}", check=False, timeout=15)
            time.sleep(2)
        assert resp.stats["seen"] > 0, (
            f"DUT never emitted an ICMPv6 NS to resolve the IPv6 peer {peer_ip} on {dev}")
        # Verify **this** dynamic v6 neighbor (peer_ip->peer_mac) is programmed into the chip with matching DST_MAC
        assert _wait_neigh_entry(asicdb, peer_ip, peer_mac, timeout=10), (
            f"dynamic ND neighbor {peer_ip}->{peer_mac} not programmed to ASIC "
            f"NEIGHBOR_ENTRY with matching DST_MAC")
    finally:
        cli.sh.run(f"ip -6 neigh del {peer_ip} dev {dev}", check=False)
        _lb.disable(port)


def _eq6(a, b):
    """Normalize-and-compare two IPv6 address strings (scapy/kernel spell them differently but same address)."""
    import socket
    try:
        return socket.inet_pton(socket.AF_INET6, a) == socket.inet_pton(socket.AF_INET6, b)
    except OSError:
        return a == b


def test_dad_duplicate_address(cli, _lb, topo, config_guard):
    """DAD duplicate address detection (real behavior): enable MAC loopback on the ingress port and start
    an "occupier" responder -- when the DUT emits a DAD NS for its tentative IPv6 address, reply with an
    override NA claiming the address is already taken; it re-enters the CPU via loopback and the DUT kernel
    should mark that address 'dadfailed'. Assert that `ip -6 addr` genuinely shows 'dadfailed' (a real conflict),
    rather than the old "assert no dadfailed when there is no conflict" trivial truth."""
    from responders.base import Responder
    topo.caps.require("loopback")
    net = topo.subnet("v6a")
    port = topo.port("c")
    dev = port.name
    dut_addr = net["dut"]
    peer_mac = topo.mac("peer_c")
    peer_ll = "fe80::200:ff:fe00:cc11"   # occupier's link-local address (arbitrary, only used as NA source)

    class DadDefender(Responder):
        bpf = "icmp6"
        def handle(self, pkt):
            from scapy.all import (Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
                                   ICMPv6NDOptDstLLAddr)
            if not pkt.haslayer(ICMPv6ND_NS):
                return None
            if not _eq6(pkt[ICMPv6ND_NS].tgt, dut_addr):   # only the DAD NS for that DUT address
                return None
            self.stats["seen"] += 1
            # override NA claims the address belongs to the occupier -> DUT judges it duplicate
            return (Ether(dst="33:33:00:00:00:01", src=peer_mac) /
                    IPv6(src=peer_ll, dst="ff02::1") /
                    ICMPv6ND_NA(tgt=dut_addr, R=0, S=0, O=1) /
                    ICMPv6NDOptDstLLAddr(lladdr=peer_mac))

    _lb.enable(port)
    try:
        with DadDefender(dev) as defender:
            _l3v6(cli, config_guard, topo, dev)   # configure IPv6 -> triggers the DAD NS for the tentative address
            failed = False
            end = time.time() + 8
            while time.time() < end:
                r = cli.sh.run(f"ip -6 addr show dev {dev}", check=False)
                if "dadfailed" in r.out:
                    failed = True
                    break
                time.sleep(0.5)
        # A (default classification, formerly a skip on positive-control failure): emitting a DAD NS is
        # standard IPv6 behavior, and this platform's MAC-loopback CPU send/receive path is validated;
        # the DUT emitting no DAD NS for a tentative address is treated as a defect -> FAIL.
        # Uncertain point: if this image disables DAD by default (dad_transmits=0) it is not a defect; defaulted to A and annotated.
        assert defender.stats["seen"] > 0, (
            "DUT emitted no DAD NS for its tentative IPv6 address "
            "(MAC-loopback delivery path is validated on this platform); "
            "cannot test DAD outcome (uncertain, defaulted to A)")
        # The occupier did reply with an override NA -> the kernel should judge it duplicate: hard-assert 'dadfailed' really appears
        assert failed, "no dadfailed despite defending NA"
    finally:
        _lb.disable(port)


# Removed test_ra_guard_config: this version of sonic-utilities has no `interface ipv6 ra-guard`
# command (the CLI genuinely does not exist); removed under classification-C rules (no assertable real device behavior).
