"""Trap / CoPP: protocol packets punted to CPU.

Verification uses Pattern A (single-port loopback + inbound capture). Confirmed on device:
LLDP injected on a loopback port gets trapped to CPU and can be captured with an `inbound`
filter (which excludes netdev TX echo).
"""
import time

import pytest

pytestmark = [pytest.mark.trap, pytest.mark.traffic, pytest.mark.pattern_a]


@pytest.mark.parametrize("ctx", ["l2", "l3"])
def test_lldp_trap_to_cpu(traffic, topo, request, ctx):
    """LLDP multicast frames should be punted to CPU, captured inbound on the ingress port netdev.

    Context: LLDP is a link-local slow protocol; its trap entry has no L3_IIF class
    restriction, so it must be punted for both an L2 port and an L3 context (unlike protocol
    traps arp/nd/dhcp that punt only on L3) -- hence both contexts are verified."""
    from scapy.all import Ether, Raw

    if ctx == "l3":
        request.getfixturevalue("copp_l3_ctx")
    p = traffic.ports[0]  # loopback already enabled
    magic = b"TRAP-LLDP-PROBE"
    lldp = (Ether(dst="01:80:c2:00:00:0e", src=topo.mac("src"), type=0x88cc) /
            Raw(b"\x02\x07\x04" + magic + b"\x00" * 16))
    with traffic.capture(p, bpf="ether dst 01:80:c2:00:00:0e", inbound=True) as cap:
        traffic.send(p, lldp, count=10)
        time.sleep(0.6)
    hits = cap.match(lambda x: magic in bytes(x))
    assert len(hits) >= 5, f"LLDP({ctx}) not punted to CPU (captured inbound {len(hits)}/10)"


def test_arp_request_trap(traffic, cli, topo, copp_l3_ctx):
    """Broadcast ARP requests should be punted to CPU (for ARP learning/response).

    Injection context semantics: ARP is a protocol-class trap, punted only for inbound
    packets on an L3 interface -- injected via copp_l3_ctx (SVI VLAN); not punting on a pure
    L2 port is correct behavior.

    Precise attribution: attribute by the injected frame's hwsrc+psrc, excluding background
    ARP from parallel lanes / kernel noise; a low-rate 10 frames is well below CIR, so with
    healthy punt there should be almost no loss, and the lower bound is raised to 8/10
    (leaving 2 frames for sniffer start/stop races).
    """
    from scapy.all import Ether, ARP

    p = traffic.ports[0]
    net = topo.subnet("a")
    smac = topo.mac("src")
    arp = Ether(dst=topo.mac("bcast"), src=smac) / \
        ARP(op=1, psrc=net["peer"], pdst=net["dut"], hwsrc=smac)
    with traffic.capture(p, bpf="arp", inbound=True) as cap:
        traffic.send(p, arp, count=10)
        time.sleep(0.6)
    # precise attribution: count only frames this test injected (hwsrc+psrc dual key), excluding background ARP crosstalk
    hits = cap.match(lambda x: x.haslayer("ARP")
                     and x["ARP"].hwsrc == smac and x["ARP"].psrc == net["peer"])
    assert len(hits) >= 8, \
        f"ARP punt lossy/dead: captured {len(hits)}/10 injected ARP inbound on {p.name}"
    # upper bound (same as test_copp_full/test_copp_dataplane_chip): broadcast ARP injected on
    # a loopback port; loopback-replicated copies share hwsrc+psrc and also count into hits, so
    # an overcount = self-loop amplification, which must be caught rather than silently satisfying the lower bound.
    assert len(hits) <= 10, \
        f"ARP punt over-count {len(hits)} (>10): loopback replication/storm inflating captures"
