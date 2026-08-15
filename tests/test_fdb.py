"""L2 FDB functionality: static entry programming + known unicast forwarded per FDB.

Verification model Pattern B (dual-port loopback + chip counters).
Topology: the ingress port and egress port (traffic.ports[0]/[1], assigned by topo) are both in the default VLAN1000.
Static FDB: dmac -> egress port. Send dmac unicast on the ingress port -> forwarded out the egress port, egress chip TX += N.

Storm prevention (see framework/loopback.py isolate_pvid): any frame forwarded to a looped port, after egress loops back
and re-enters, gets **re-directed** to this port -> a self-loop storm (same-port filtering does not break it) -- the storm itself
can satisfy a pure lower-bound assertion, so before measuring the egress port must switch to an isolated PVID to break the loop,
and the assertion must carry both a lower bound (real forwarding) and an upper bound (guard against a storm false pass).

Note: the pure ASIC_DB programming verification case (formerly test_static_fdb_in_asicdb) was removed -- all its value is covered by
test_mac.py::test_static_mac_crud (same assertions + disappears on delete + dataplane) and
test_fdb_chip.py::test_static_fdb_chip_and_dataplane (ASIC_DB + chip l2 + traffic).
"""
import time

import pytest

pytestmark = [pytest.mark.l2, pytest.mark.traffic, pytest.mark.pattern_b]


def _wait_asicdb_mac(asicdb, mac, tries=20):
    """Poll ASIC_DB until **that MAC's** FDB_ENTRY appears (colon-stripped/with-colon, case-insensitive).

    Do not use asicdb.has(any FDB_ENTRY) -- any background-learned/leftover entry satisfies it, a known source of false passes."""
    needle = mac.replace(":", "").upper()
    for _ in range(tries):
        for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY"):
            ku = k.upper()
            if needle in ku or mac.upper() in ku:
                return True
        time.sleep(0.4)
    return False


def test_static_fdb_forwarding(cli, traffic, asicdb, config_guard, topo, _lb, l2_fwd_vlan):
    from scapy.all import Ether, IP, UDP, Raw

    vlan = l2_fwd_vlan   # use a real VLAN when the berth does not forward (the swssconfig->ASIC path is available)
    dmac, smac = topo.mac("dst"), topo.mac("src")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    n = 100

    # arrange: static FDB dmac -> p_out (CONFIG_DB, programmed by fdborch)
    cli.fdb_static_add(vlan, dmac, p_out.name)
    try:
        # must wait for **that dmac's** entry to appear (any FDB_ENTRY would be satisfied by background learning/leftovers -> false pass)
        assert _wait_asicdb_mac(asicdb, dmac), \
            f"static FDB {dmac} not programmed to ASIC_DB"

        # Loop the egress port (so chip TX count is measurable), then switch to an isolated PVID to break the "directed to the looped port"
        # self-loop: the re-entering frame lands in the isolated VLAN, finds no destination, and terminates; p_out's egress membership
        # in the original VLAN and the FDB entry are unaffected by the PVID, so directed forwarding proceeds as usual and TX is still measurable.
        traffic.loop(p_out)
        time.sleep(1)
        _lb.isolate_pvid(p_out, 3990)

        pkt = (Ether(dst=dmac, src=smac) / IP(dst="10.0.0.1") /
               UDP() / Raw(b"L2FDB" + b"x" * 40))
        # Send traffic after zeroing, read ingress/egress once each (that port's RX/TX count since clear); do not subtract base/after --
        # this diag `show c` only shows change since the last show/clear, and base would consume the display + include background noise -> possible negative delta (clear -> read once)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=n)
        time.sleep(1)
        d_in = traffic.chip_counters(p_in)
        d_out = traffic.chip_counters(p_out)

        # Ingress receives ~N from loopback re-entry; egress forwards out ~N. Both bounds asserted: the lower bound proves real forwarding,
        # the upper bound guards against a storm (a self-loop storm pushes both counts to the millions, and with only a lower bound a storm would actually "pass more easily").
        assert n * 0.9 <= d_in.rx_pkt < 10_000, \
            f"ingress looped RX out of range (RX+{d_in.rx_pkt}, expected ~{n}; storm if huge)"
        assert n * 0.9 <= d_out.tx_pkt < 10_000, \
            (f"not forwarded per FDB to {p_out.name} "
             f"(TX+{d_out.tx_pkt}, expected ~{n}; storm if huge)")
    finally:
        _lb.restore_pvid(p_out)
        traffic.unloop(p_out)
        cli.fdb_static_del(vlan, dmac)
