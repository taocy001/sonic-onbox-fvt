"""Pattern C content check: use a hairpin topology to capture forwarded frames **after p_out egress
processing** and verify concrete fields (DSCP, TTL, L4/payload), not just counters.

Capture path: CPU->p_in(VLAN A)->FDB forwards to p_out egress (egress processing)->loops back into VLAN B->l2
punts to CPU->captured inbound on the p_out netdev. Fields/VLAN/IP all come from topo, not hard-coded.

Verifiable: DSCP, TTL, L4 ports, payload and other fields **not affected by the CPU-punt**.
Not verifiable: the **outer VLAN tag** -- the punt path stamps the punted frame with VLAN B's tag, masking
p_out's VLAN A egress tagging (content-checking VLAN tag push/pop needs a separate SPAN/mirror-to-CPU capture,
not the hairpin-punt).
"""
import time

import pytest

pytestmark = [pytest.mark.traffic, pytest.mark.smoke]
MAGIC = b"PCCONTENT"


def _forward_and_capture(cli, dut, lb, topo, send_pkt, count=20):
    """Hairpin-forward send_pkt (p_in->p_out); return the list of (post-forwarding) frames captured on the p_out netdev."""
    from scapy.all import sendp

    from framework.traffic import Capture
    from topo.hairpin import Hairpin

    dmac = topo.hp_probe_dst
    p_in, p_out = topo.port("e"), topo.port("f")
    hp = Hairpin(cli, dut, lb, p_in, p_out,
                 topo.hp_vlan_a, topo.hp_vlan_b, svi_ip=topo.hp_svi)
    hp.setup()
    hp.fdb_to_out(dmac)        # VLAN A: probe->p_out forwarding
    hp.punt_b_to_cpu(dmac)     # VLAN B: probe->CPU punt (capture point)
    try:
        time.sleep(2)
        hp.arm()
        with Capture(p_out.name, inbound=True) as cap:
            sendp(send_pkt, iface=p_in.name, count=count, verbose=0)
            time.sleep(0.6)
        return [p for p in cap.packets if MAGIC in bytes(p)]
    finally:
        hp.teardown()


@pytest.fixture
def fwd_capture(cli, dut, _lb, topo):
    """Return a callable: send_pkt -> list of captured forwarded frames."""

    def _run(send_pkt, count=20):
        return _forward_and_capture(cli, dut, _lb, topo, send_pkt, count)
    return _run


def test_forward_preserves_content(fwd_capture, topo):
    """L2 forwarding content invariants (single hairpin, one frame carrying all fields, **every** matching frame
    checked frame-by-frame): DSCP=ef, TTL=64 (L2 forwarding does not decrement), given IP src/dst, given UDP
    ports, payload -- all unchanged after forwarding.

    Merged from the original 4 preserves_* cases: each ran a full hairpin setup/teardown (VLAN create/delete +
    member move + dual-port loopback, several to a dozen-plus seconds each), yet one probe frame can carry all
    fields at once, and each original case only checked the first frame (`hits[0]`) and merely asserted non-empty
    over 20 sends. This case covers the same invariants, cuts machine time 4x, and strengthens the assertions:
    a capture-count lower bound of count*0.3 (the punt path has a policer, so take a loose lower bound; the
    original only asserted non-empty) plus a full field check per frame."""
    from scapy.all import Ether, IP, UDP, Raw
    dscp = topo.dscp("ef")
    net = topo.subnet("a")
    count = 20
    pkt = (Ether(dst=topo.hp_probe_dst, src=topo.mac("src")) /
           IP(src=net["dut"], dst=net["peer"], ttl=64, tos=dscp << 2) /
           UDP(sport=4321, dport=8765) / Raw(MAGIC + b"payload123"))
    hits = fwd_capture(pkt, count=count)
    assert len(hits) >= count * 0.3, (
        f"too few forwarded frames captured: {len(hits)}/{count} "
        f"(lower bound {int(count * 0.3)} already tolerates the CPU-punt policer)")
    for i, h in enumerate(hits):
        ip = h["IP"]
        assert (ip.tos >> 2) == dscp, \
            f"frame#{i}: DSCP changed after L2 forwarding: expected {dscp} got {ip.tos >> 2}"
        assert ip.ttl == 64, \
            f"frame#{i}: L2 forwarding must not change TTL, got {ip.ttl}"
        assert ip.src == net["dut"] and ip.dst == net["peer"], \
            f"frame#{i}: IP addresses changed after forwarding: {ip.src}->{ip.dst}"
        udp = h["UDP"]
        assert udp.sport == 4321 and udp.dport == 8765, \
            f"frame#{i}: L4 ports changed: {udp.sport}->{udp.dport}"
        assert b"payload123" in bytes(h), f"frame#{i}: payload lost/changed"
