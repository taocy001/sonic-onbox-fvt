"""Chip table coverage (part 2): SAI objects newly programmed after config/traffic/protocol triggers, verifying the **orchagent->SAI programming chain** actually takes effect (the corresponding object appears in ASIC_DB).

**This file is scoped to "programming-layer verification" — proving the NOS actually
programs config into chip objects**, not data-plane forwarding verification. The
**data-plane forwarding/drop behavior** of these objects is verified with real traffic
in dedicated tests (not repeated here, to avoid being misread as a forwarding test):
  - FDB forwarding      -> test_fdb.py::test_static_fdb_forwarding / test_mac.py::test_mac_move (real traffic verifies forwarding to the port)
  - neighbor/nexthop/route -> test_route_full.py / test_arp_full.py::test_static_arp / test_l3_forward_traffic.py (injected packets verify forwarding)
  - ECMP distribution   -> test_l3_forward_traffic.py::test_l3_ecmp_forwarding_distributes (verifies both egress ports receive traffic)
  - RIF/connected       -> test_l3_forward_traffic.py (route forwarding depends on the RIF)

The suite covers dynamic/feature table entries: RIF, NEIGHBOR, NEXTHOP,
NEXTHOP_GROUP (ECMP), ROUTE, FDB, LAG (member-level identity assertions are in
test_lag_chip/test_lacp). Each test also asserts the **delete path** (after del the
object actually leaves ASIC_DB) — an orch teardown-chain leak (the pattern behind the
hairpin desync incident) was previously invisible.

**L3 tests (RIF/route/neighbor/nexthop/ecmp) share a module-level `l3net` base**
(conftest.l3net: l3_port(0)/(1) + misc_port(0) configured once with L3 IPs + loopback
held, exposing env.p_in/p_out/sub_in/sub_out/rmac); each test only adds/clears its own
route/neighbor delta and the base is unchanged across tests — no longer does each test
repeat l3up port bring-up + config interface ip (each SONiC config goes through YANG
validation, which is slow). FDB/LAG use different ports / do not build L3, kept as-is.
"""
import time

import pytest

pytestmark = [pytest.mark.chip]


def _wait(pred, timeout=8.0, interval=0.4):
    """Poll until the predicate is true (waiting for orch's async program/teardown). Returns whether it was achieved."""
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    return False


def _neigh_keys(asicdb, ip):
    """NEIGHBOR_ENTRY keys containing the given IP (the key embeds JSON, where the IP appears as a quoted string)."""
    return [k for k in asicdb.objects("SAI_OBJECT_TYPE_NEIGHBOR_ENTRY") if f'"{ip}"' in k]


def _route_keys(asicdb, prefix):
    return [k for k in asicdb.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY") if prefix in k]


def test_router_interface_created(l3net, asicdb):
    """Verify the **connected route** is programmed after configuring an IP (proving the RIF was created). Shares the l3net base: base setup already configures p_in as L3 (IP + loopback held), so this directly verifies its connected route is in the ASIC == the RIF is programmed (if not programmed, the connected route would not be issued)."""
    import ipaddress
    net = l3net.sub_in
    conn = str(ipaddress.ip_network(f"{net['dut']}/{net['prefix']}", strict=False))
    assert asicdb.has_route(conn, timeout=8), \
        f"L3 base did not generate RIF/connected route {conn} in ASIC"


def test_neighbor_and_nexthop_created(l3net, asicdb):
    env = l3net
    cli, topo = env.cli, env.topo
    p1 = env.p_in.name
    peer = env.sub_in["peer"]
    cli.neigh_set(peer, topo.mac('peer_a'), p1)
    cli.config_raw(f"route add prefix {topo.route('a')} nexthop {peer}")
    try:
        # Identity-level assertion (not a global count increase): the NEIGHBOR_ENTRY key
        # embeds this test's peer IP and the NEXT_HOP attribute points at that IP — parallel
        # lanes / background ND noise cannot falsely satisfy it, and it checks the programmed
        # content (correct IP).
        assert _wait(lambda: _neigh_keys(asicdb, peer)), \
            f"NEIGHBOR_ENTRY for {peer} not generated"
        assert _wait(lambda: asicdb.find("SAI_OBJECT_TYPE_NEXT_HOP",
                                         SAI_NEXT_HOP_ATTR_IP=peer)), \
            f"NEXT_HOP with IP {peer} not generated"
    finally:
        # Clear the test-level delta, keeping the shared base unchanged (for reuse by later tests)
        cli.config_raw(f"route del prefix {topo.route('a')} nexthop {peer}")
        cli.neigh_del(peer, p1)
    # Delete-path assertion: after teardown the object must actually leave ASIC_DB (residue = orch desync leak, the root cause of the historical hairpin incident)
    assert _wait(lambda: not _neigh_keys(asicdb, peer)), \
        f"DEVICE ISSUE: NEIGHBOR_ENTRY for {peer} not removed after neigh del (stale ASIC entry)"
    assert _wait(lambda: not asicdb.find("SAI_OBJECT_TYPE_NEXT_HOP", SAI_NEXT_HOP_ATTR_IP=peer)), \
        f"DEVICE ISSUE: NEXT_HOP for {peer} not removed after route/neigh del (stale ASIC entry)"


def test_route_entry_created(l3net, asicdb):
    env = l3net
    cli, topo = env.cli, env.topo
    p1 = env.p_in.name
    na = env.sub_in
    peer = na["peer"]
    cli.neigh_set(peer, topo.mac('peer_a'), p1)
    connected = f"{na['dut'].rsplit('.', 1)[0]}.0/{na['prefix']}"
    try:
        assert asicdb.has_route(connected, timeout=10), "connected route did not program ROUTE_ENTRY"
        cli.config_raw(f"route add prefix {topo.route('b')} nexthop {peer}")
        assert asicdb.has_route(topo.route("b"), timeout=10), "static route did not program ROUTE_ENTRY"
    finally:
        cli.config_raw(f"route del prefix {topo.route('b')} nexthop {peer}")
        cli.neigh_del(peer, p1)
    # Delete-path assertion: after route del the ROUTE_ENTRY must leave ASIC_DB (guards against an orch teardown-chain leak)
    assert _wait(lambda: not _route_keys(asicdb, topo.route("b"))), \
        f"DEVICE ISSUE: ROUTE_ENTRY {topo.route('b')} not removed after route del (stale ASIC entry)"


def test_ecmp_nexthop_group_created(l3net, asicdb):
    """Dual-nexthop static route -> NEXTHOP_GROUP + member. Shares l3net's two L3 ports p_in/p_out."""
    env = l3net
    cli, topo = env.cli, env.topo
    p1, p2 = env.p_in.name, env.p_out.name
    na, nb = env.sub_in, env.sub_out
    cli.neigh_set(na['peer'], topo.mac('peer_a'), p1)
    cli.neigh_set(nb['peer'], topo.mac('peer_b'), p2)
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP:*")
    base_m = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER:*")
    cli.config_raw(f"route add prefix {topo.route('c')} nexthop {na['peer']}")
    cli.config_raw(f"route add prefix {topo.route('c')} nexthop {nb['peer']}")
    try:
        assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP:*", base,
                                    timeout=12), "ECMP did not generate NEXT_HOP_GROUP"
        # Creating the group is not enough: a group with 0/1 members (an orch fan-out programming defect) would still pass the group count — there must be >=2 new members
        assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER:*",
                                    base_m + 1, timeout=12), \
            "ECMP NEXT_HOP_GROUP has <2 new members (fan-out not programmed)"
    finally:
        cli.config_raw(f"route del prefix {topo.route('c')} nexthop {na['peer']}")
        cli.config_raw(f"route del prefix {topo.route('c')} nexthop {nb['peer']}")
        cli.neigh_del(na['peer'], p1)
        cli.neigh_del(nb['peer'], p2)
    # Delete-path assertion: after teardown the group/member counts fall back to baseline (guards against a NEXT_HOP_GROUP object leak)
    assert _wait(lambda: asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP:*") <= base,
                 timeout=12), \
        "DEVICE ISSUE: NEXT_HOP_GROUP not removed after route del (stale ASIC object)"


def test_fdb_entry_created(cli, asicdb, _lb, topo, config_guard):
    p3 = topo.port("e")
    # On l2_home_forwarding=false platforms the default VLAN is a berth and members are not
    # programmed to the ASIC, so a static FDB is not programmed on it (in a real VLAN
    # fdb_static_add creates the FDB_ENTRY normally). So build a real test VLAN + convert to an L2 member.
    vlan = topo.vlan("l2fwd") if not topo.caps.has("l2_home_forwarding") else topo.default_vlan
    if vlan != topo.default_vlan:
        cli.ensure_port_l2(p3)
        cli.config_raw(f"vlan add {vlan}")
        config_guard.defer_undo(f"vlan del {vlan}")
        cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {vlan} {p3.name}")
        config_guard.defer_undo(f"vlan member del {vlan} {p3.name}")
    _lb.enable(p3)   # the port must be up for the static FDB to be programmed to the ASIC
    mac = topo.mac("dst")
    cli.fdb_static_add(vlan, mac, p3.name)
    try:
        found = False
        for _ in range(20):
            if any(mac.upper() in k.upper()
                   for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY")):
                found = True
                break
            time.sleep(0.5)
        assert found, "static FDB did not program FDB_ENTRY"
    finally:
        cli.fdb_static_del(vlan, mac)
        _lb.disable(p3)
    # Delete-path assertion: after fdb del this MAC's FDB_ENTRY must leave ASIC_DB
    assert _wait(lambda: not any(mac.upper() in k.upper()
                                 for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY")),
                 timeout=10), \
        f"DEVICE ISSUE: static FDB_ENTRY {mac} not removed after fdb del (stale ASIC entry)"


def test_lag_objects_created(cli, asicdb, config_guard):
    """LAG programming lifecycle: create/program + **delete/reclaim** (the strong create
    assertion is covered by test_lag_chip; this fills the LAG delete path missing from the
    suite — after portchannel del, SAI_OBJECT_TYPE_LAG must fall back)."""
    base_lag = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_LAG:*")
    cli.config_raw("portchannel add PortChannel61")
    config_guard.defer_undo("portchannel del PortChannel61")   # idempotent safety net
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_LAG:*", base_lag,
                                timeout=10), "LAG not generated"
    # Delete-path assertion: after del the LAG count falls back to baseline (guards against an orch delete-chain leak)
    cli.config_raw("portchannel del PortChannel61")
    assert _wait(lambda: asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_LAG:*") <= base_lag,
                 timeout=12), \
        "DEVICE ISSUE: LAG not removed after portchannel del (stale ASIC object)"
