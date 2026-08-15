"""Chip entry coverage (part 3): traffic/protocol-driven dynamic entry programming.

- Dynamic FDB: send a frame with a source MAC -> switch learns it -> ASIC dynamic FDB_ENTRY.
- Dynamic neighbor: ArpResponder emulates the peer answering ARP -> DUT learns the neighbor -> ASIC NEIGHBOR_ENTRY.

Assertion principle: only accept the entry and content for the **specific** MAC/IP. A "total count grew"
check would be satisfied by any background learning (IPv6 ND noise, leftovers from parallel workers, MACs
from other tests) — it is a known source of false passes and is never used.
"""
import time

import pytest

pytestmark = [pytest.mark.chip, pytest.mark.traffic]


def test_dynamic_fdb_learning(cli, traffic, asicdb, topo, l2_fwd_vlan):
    """Source MAC learning (**real-traffic driven**): after sending real frames, the ASIC shows a dynamic
    FDB entry for **this smac**, proving the NOS programs the data-plane-learned address into the chip.
    The **forward-by-FDB** behavior once the address is learned is verified with real traffic in
    test_fdb.py::test_static_fdb_forwarding and test_mac.py::test_mac_move.

    The learning stimulus frame's dst is steered via static FDB to ports[1] (same pattern as smoke_check) —
    no longer flooding an unknown unicast across the 160-port production VLAN. The assertion only accepts
    the key for this smac: the original "total grew (grew) or this MAC appears" grew arm would be satisfied
    by any background dynamic learning -> it could pass even if smac was never learned."""
    from scapy.all import Ether, IP, UDP, Raw

    p = traffic.ports[0]          # already looped back, default VLAN member
    p_out = traffic.ports[1]      # directed sink port (learning frame is forwarded out, not looped back)
    vlan = l2_fwd_vlan
    smac = "00:de:ad:be:ef:4b"    # source MAC unique to this test (does not share topo.mac("learn") with
                                  # test_fdb_chip, to avoid its historical learning left in ASIC_DB
                                  # satisfying the assertion -> false pass)
    learn_dst = "00:aa:bb:cc:dd:7b"
    cli.sh.run("sonic-clear fdb all", check=False)      # clean start: leftovers must not pre-satisfy the assertion
    cli.fdb_static_add(vlan, learn_dst, p_out.name)     # directed sink (wait=True waits for ASIC programming)
    try:
        pkt = Ether(dst=learn_dst, src=smac) / IP() / UDP() / Raw(b"x" * 40)
        traffic.send(p, pkt, count=30)
        # poll for the FDB_ENTRY of **this smac** (key may be colon-stripped or colon-form, case-insensitive)
        needle = smac.replace(":", "").upper()
        found = False
        for _ in range(12):
            if any(needle in k.upper() or smac.upper() in k.upper()
                   for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY")):
                found = True
                break
            time.sleep(0.5)
        assert found, f"source MAC {smac} not dynamically learned into ASIC FDB"
    finally:
        cli.fdb_static_del(vlan, learn_dst)


def test_dynamic_arp_neighbor(cli, dut, _lb, asicdb, config_guard, topo):
    """ArpResponder emulates the peer -> DUT ping triggers ARP -> dynamic neighbor NEIGHBOR_ENTRY learned.

    Verifies **specific entry + content**: peer_ip appears in a NEIGHBOR_ENTRY key (matched with quotes to
    avoid prefix collisions, e.g. 10.0.0.1 colliding with 10.0.0.10), and its DST_MAC == the peer_mac forged
    by ArpResponder — proving what is programmed into the ASIC is exactly the resolution result we forged.
    The original "total > base" would be satisfied by any concurrently learned neighbor (false pass), and
    peer_mac was never validated."""
    from responders.arp import ArpResponder

    port = dut.pick_test_ports(1)[0]
    net = topo.subnet("a")
    peer_ip, peer_mac = net["peer"], topo.mac("peer_a")
    dut_ip = f"{net['dut']}/{net['prefix']}"
    dvlan = topo.default_vlan
    cli.config_raw(f"vlan member del {dvlan} {port.name}")
    config_guard.defer_undo(f"vlan member add -u {dvlan} {port.name}")
    cli.config(f"interface ip add {port.name} {dut_ip}")
    config_guard.defer_undo(f"interface ip remove {port.name} {dut_ip}")
    cli.intf_startup(port.name)
    _lb.enable(port)
    try:
        with ArpResponder(port.name, peer_ip, peer_mac) as resp:
            cli.sh.run(f"ping -c 4 -W 1 -I {port.name} {peer_ip}", check=False, timeout=10)
            time.sleep(2)
        # positive control: the Responder must actually receive the DUT's ARP request (link/loopback issues surface here)
        assert resp.stats["seen"] > 0, \
            "ArpResponder did not receive DUT ARP request (link/loopback issue)"
        # specific entry: poll until this peer_ip appears in a NEIGHBOR_ENTRY key
        entry = None
        deadline = time.time() + 8
        while entry is None and time.time() < deadline:
            entry = next((k for k in asicdb.objects("SAI_OBJECT_TYPE_NEIGHBOR_ENTRY")
                          if f'"{peer_ip}"' in k), None)
            if entry is None:
                time.sleep(0.4)
        assert entry, f"dynamic neighbor {peer_ip} not programmed to ASIC NEIGHBOR_ENTRY"
        # content: the resolved MAC must equal the forged reply's peer_mac (attribute programming is async in orch, short poll)
        got = None
        for _ in range(10):
            got = asicdb.field(entry, "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS")
            if got:
                break
            time.sleep(0.4)
        assert got and got.upper() == peer_mac.upper(), \
            f"neighbor {peer_ip} programmed DST_MAC mismatch (got {got!r}, want {peer_mac})"
    finally:
        _lb.disable(port)
