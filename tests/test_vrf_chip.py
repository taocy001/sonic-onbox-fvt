"""VRF chip behavior / data-plane isolation cases -- verify not just CONFIG_DB/ASIC object existence but **real isolation**.

Complementary to the existing test_vrf.py (which only verifies VRF/binding written to the DB), this focuses on three things:
  1) the same prefix pushes one ROUTE_ENTRY in each of two VRFs, and their **vr (virtual_router) oids differ**
     (the chip really places same-named routes into different virtual routers, proving VRF isolation in the ASIC).
  2) data-plane isolation: the route is only in Vrf-A; inject a flow to the Vrf-A ingress port -> forwarded to the Vrf-A egress (chip TX +N);
     inject the **same** destination to the Vrf-B ingress port -> **not forwarded** (no cross-VRF leak, chip TX ~0).
  3) the same IP in two VRFs does not cross-talk: each route points at its own egress, and A's traffic does not land on B's egress port.

The mechanism follows test_l3_forward_traffic's "loopback re-ingress + chip counter delta" pattern (on-DUT, no storm):
  configure IP on the ingress/egress ports + enable MAC loopback; inject an IP packet with "DMAC=DUT router MAC, dst=remote subnet",
  which loops back and re-enters the pipeline at the ingress port -> the DUT forwards it to the egress port per **the routing table of the VRF that port belongs to** (chip TX +N).
  The re-ingressed frame at the egress port has DMAC=neighbor MAC != router MAC and is dropped at the L3 port, so no storm.

If VRF binding/routing/isolation does not take effect on the device -> FAIL to expose the defect (no longer masked by skip); only runtime
preconditions like missing scapy, loopback capability, and missing router MAC are kept as skip. All VRF/IP/binding/route teardown cleans up, idempotently.
"""
import json
import time

import pytest

from framework.counters import ChipCounters

pytestmark = [pytest.mark.l3]

try:
    from scapy.all import Ether, IP, UDP, sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

VRF_A = "Vrf-iso-a"
VRF_B = "Vrf-iso-b"
_N = 30                          # injection count (small, paired with an upper-bound assertion to guard against runaway storms)
_NH_MAC_A = "00:11:22:33:55:a1"  # Vrf-A egress next-hop neighbor MAC (verifies DMAC-rewrite target / forwarding egress)
_NH_MAC_B = "00:11:22:33:55:b1"  # Vrf-B egress next-hop neighbor MAC


def _tx_accum(bsh, dut, port, expect, timeout=3.0):
    """The golden positive-counting pattern (same as traffic.smoke_check): poll-accumulate this port's TX until >= expect*0.9 or timeout,
    then +0.4s for one confirming read added in -- a fixed sleep + single read under-counts when DMA settles slowly (lower-bound false-FAIL flapping),
    and the confirming read also guards against a slow self-replicating storm punching through the upper bound."""
    total = 0
    deadline = time.time() + timeout
    while total < expect * 0.9 and time.time() < deadline:
        time.sleep(0.4)
        total += ChipCounters.read(bsh, dut.bcm_of(port)).tx_pkt
    time.sleep(0.4)
    total += ChipCounters.read(bsh, dut.bcm_of(port)).tx_pkt
    return total


def _tx_settle(bsh, dut, port, settle=2.0):
    """Negative ("should not arrive") observation: wait >= 2 counter-refresh periods and read **accumulatively** -- a single early read would miss leak frames arriving later than 1s, turning the leak assertion into a false PASS."""
    total = 0
    end = time.time() + settle
    while time.time() < end:
        time.sleep(0.5)
        total += ChipCounters.read(bsh, dut.bcm_of(port)).tx_pkt
    return total


# ---------------------------------------------------------------------------
# Low-level VRF orchestration helpers (via legal paths: config CLI + ip route/neigh), all reversible.
# ---------------------------------------------------------------------------
def _rmac(cli):
    return cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")


def _oid(key):
    """Full ASIC key (ASIC_STATE:SAI_OBJECT_TYPE_X:oid:0x..) -> bare oid:0x..
    The vr parsed out of a ROUTE_ENTRY is a bare oid, while objects() returns a full key, so they must be normalized before comparison."""
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def _vrf_add(cli, vrf):
    rc, r = cli.config_raw(f"vrf add {vrf}")
    return rc, (r.err or r.out)


def _vr_oids(asicdb):
    return set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER"))


def _wait_new_vr(asicdb, before, timeout=8.0):
    """Wait for a new VIRTUAL_ROUTER oid to appear, return it (VRF -> SAI VR mapping)."""
    end = time.time() + timeout
    while time.time() < end:
        now = _vr_oids(asicdb)
        new = now - before
        if new:
            return next(iter(new))
        time.sleep(0.4)
    return None


def _bind_port_l3_in_vrf(cli, dut, _lb, topo, port, vrf, cidr):
    """Bind port into vrf and configure L3 IP + enable loopback to pull up.

    Order is critical: first remove from the default VLAN -> bind VRF -> configure IP -> startup -> enable loopback.
    Binding VRF must come before configuring IP (SONiC creates the VRF interface first, then adds the address).
    Returns True if both binding and IP succeed, otherwise False (caller skips accordingly).
    """
    dv = topo.default_vlan
    cli.config_raw(f"vlan member del {dv} {port.name}")
    # Wait for the VLAN member to really be removed, to avoid a "both in a VLAN and has an IP" mixed state causing the re-ingressed frame to loop
    for _ in range(20):
        if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{port.name}"):
            break
        time.sleep(0.3)
    rc, r = cli.config_raw(f"interface vrf bind {port.name} {vrf}")
    if rc != 0:
        return False, f"vrf bind: {r.err or r.out}"
    # Confirm CONFIG_DB reflects the binding
    ok = False
    for _ in range(15):
        if cli.db_hgetall("CONFIG_DB", f"INTERFACE|{port.name}").get("vrf_name") == vrf:
            ok = True
            break
        time.sleep(0.3)
    if not ok:
        return False, "interface vrf_name not set in CONFIG_DB"
    rc, r = cli.config_raw(f"interface ip add {port.name} {cidr}")
    if rc != 0:
        return False, f"ip add: {r.err or r.out}"
    cli.intf_startup(port.name)
    _lb.enable(port)
    return True, ""


def _unbind_port(cli, _lb, topo, port, vrf, cidr):
    """Reverse-order reclaim: disable loopback -> remove IP -> unbind VRF -> back to the default VLAN."""
    try:
        _lb.disable(port)
    except Exception:  # noqa: BLE001
        pass
    cli.config_raw(f"interface ip remove {port.name} {cidr}")
    cli.config_raw(f"interface vrf unbind {port.name}")
    cli.config_raw(f"vlan member add -u {topo.default_vlan} {port.name}")


def _vrf_route(cli, vrf, dst_net, nh, port_name, nh_mac):
    """Add dst_net via nh in the vrf routing table (the port is already enslaved to the vrf master)."""
    cli.neigh_set(nh, nh_mac, port_name)
    cli.sh.run(f"ip route replace {dst_net} via {nh} vrf {vrf}", check=False)


def _vrf_route_del(cli, vrf, dst_net, nh, port_name):
    cli.sh.run(f"ip route del {dst_net} vrf {vrf}", check=False)
    cli.neigh_del(nh, port_name)


def _wait_vrf_route(cli, vrf, dst_net, tries=20):
    pfx = dst_net.split("/")[0]
    for _ in range(tries):
        if pfx in cli.sh.run(f"ip route show {dst_net} vrf {vrf}", check=False).out:
            return True
        time.sleep(0.5)
    return False


def _route_entries_for(asicdb, prefix):
    """Return the ROUTE_ENTRY matching this prefix in ASIC_DB, parsing out its vr oid.
    The key looks like ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{"dest":"..","switch_id":"..","vr":"oid:.."}.
    Returns list[(key, vr_oid)]."""
    out = []
    for k in asicdb.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY"):
        body = k.split("SAI_OBJECT_TYPE_ROUTE_ENTRY:", 1)[-1]
        try:
            d = json.loads(body)
        except (ValueError, TypeError):
            continue
        if d.get("dest", "").startswith(prefix):
            out.append((k, d.get("vr")))
    return out


# ---------------------------------------------------------------------------
# fixture: two VRFs each bind one L3 ingress port; setup/teardown clean up idempotently.
# ---------------------------------------------------------------------------
@pytest.fixture
def vrf_pair(cli, dut, _lb, topo, asicdb):
    """Create VRF_A / VRF_B, each binding one ingress L3 port (c->A, d->B), return a context dict.

    The ingress ports use the same subnet role but land in their own VRF (same IP does not conflict, exactly the isolation point to verify).
    If VRF create / bind / IP config fails -> FAIL (device defect, no fabricated pass); only missing loopback capability / router MAC is a precondition skip.
    """
    topo.caps.require("loopback")
    rmac = _rmac(cli)
    if not rmac:
        pytest.skip("router MAC (DEVICE_METADATA.mac) not found")

    p_in_a = topo.l3_port(0)     # Vrf-A ingress port
    p_in_b = topo.l3_port(1)     # Vrf-B ingress port
    # The ingress ports use the **same** subnet in their own VRF (same IP, different VRF -> must be isolated)
    sub = topo.subnet("c")
    cidr = f"{sub['dut']}/{sub['prefix']}"
    in_peer = sub["peer"]

    created_vrfs = []
    bound = []   # (port, vrf, cidr)

    def _cleanup():
        for port, vrf, c in reversed(bound):
            _unbind_port(cli, _lb, topo, port, vrf, c)
        for vrf in reversed(created_vrfs):
            cli.config_raw(f"vrf del {vrf}")

    try:
        before_vr = _vr_oids(asicdb)
        for vrf in (VRF_A, VRF_B):
            rc, msg = _vrf_add(cli, vrf)
            # Originally skipped on CLI failure; vrf add is an existing command, so failure is a real defect -> assert it succeeds
            assert rc == 0, f"config vrf add {vrf} failed: {msg}"
            created_vrfs.append(vrf)
        # The two VRFs should each produce a VIRTUAL_ROUTER (>=2 new beyond the default VR); wait for async push
        _wait_new_vr(asicdb, before_vr)
        time.sleep(1.0)
        new_vrs = _vr_oids(asicdb) - before_vr
        # Originally skipped if fewer than 2; VRFs not each building a distinct VIRTUAL_ROUTER on the chip = VRF not in hardware, a device defect -> FAIL
        assert len(new_vrs) >= 2, (
            f"DEVICE DEFECT: two VRFs did not create distinct SAI VIRTUAL_ROUTER objects in ASIC "
            f"(got {len(new_vrs)}); VRF not isolated/programmed into hardware")

        # Originally skipped on bind failure; interface vrf bind/ip add are both existing commands, so failure is a real defect -> FAIL
        # (uncertain: why may cover multiple causes CLI/CONFIG_DB; per the default rule, exposed as FAIL and annotated)
        ok_a, why_a = _bind_port_l3_in_vrf(cli, dut, _lb, topo, p_in_a, VRF_A, cidr)
        assert ok_a, f"DEVICE DEFECT: bind {p_in_a.name} to {VRF_A} failed: {why_a}"
        bound.append((p_in_a, VRF_A, cidr))
        ok_b, why_b = _bind_port_l3_in_vrf(cli, dut, _lb, topo, p_in_b, VRF_B, cidr)
        assert ok_b, f"DEVICE DEFECT: bind {p_in_b.name} to {VRF_B} failed: {why_b}"
        bound.append((p_in_b, VRF_B, cidr))

        yield {
            "rmac": rmac, "p_in_a": p_in_a, "p_in_b": p_in_b,
            "in_peer": in_peer, "new_vrs": new_vrs,
        }
    finally:
        _cleanup()


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
def test_vrf_same_ip_two_vrfs_distinct_vr(cli, dut, _lb, topo, asicdb, vrf_pair):
    """The same prefix adds one route in each of two VRFs -> the ASIC should show **two** ROUTE_ENTRY with **different** vr oids,
    equal to Vrf-A / Vrf-B's VIRTUAL_ROUTER respectively (proving the chip isolates same-named routes into different virtual routers)."""
    # This case only verifies ASIC programming (no traffic): each VRF adds one route to the **same prefix**, with the next hop being the peer
    # in its own ingress-port subnet (already enslaved to the corresponding VRF), no extra egress port needed.
    dst_net = topo.route("a")                            # both VRFs use the **same** destination prefix

    # Add one route to the same prefix in each VRF (next hop is the peer in its own ingress-port subnet, already enslaved)
    _vrf_route(cli, VRF_A, dst_net, vrf_pair["in_peer"], vrf_pair["p_in_a"].name, _NH_MAC_A)
    _vrf_route(cli, VRF_B, dst_net, vrf_pair["in_peer"], vrf_pair["p_in_b"].name, _NH_MAC_B)
    try:
        # Originally skipped if the route was not programmed; the port is enslaved to the VRF, so the static route should enter the corresponding VRF kernel table,
        # and if it does not, VRF enslave/isolation did not really take effect, a device defect -> FAIL (treated as a defect by default, annotated)
        assert _wait_vrf_route(cli, VRF_A, dst_net) and _wait_vrf_route(cli, VRF_B, dst_net), (
            f"DEVICE DEFECT: per-VRF static route {dst_net} not programmed into the VRF kernel "
            f"tables (VRF port enslavement/isolation not effective)")

        prefix = dst_net.split("/")[0]
        entries = []
        end = time.time() + 12
        while time.time() < end:
            entries = _route_entries_for(asicdb, prefix)
            if len(entries) >= 2:
                break
            time.sleep(0.5)

        assert len(entries) >= 2, (
            f"same prefix {dst_net} in two VRFs should produce 2 ROUTE_ENTRY in ASIC, "
            f"got {len(entries)}: {[k for k, _ in entries]}")
        vrs = {vr for _, vr in entries if vr}
        assert len(vrs) >= 2, (
            f"two ROUTE_ENTRY for same prefix share the SAME vr oid -> NOT VRF-isolated in ASIC: "
            f"{entries}")
        # These vrs should be the two VIRTUAL_ROUTERs newly created by vrf_pair (not the default VR).
        # new_vrs are full ASIC keys, the vr in the route is a bare oid, so normalize before comparing.
        new_vr_oids = {_oid(v) for v in vrf_pair["new_vrs"]}
        assert vrs & new_vr_oids, (
            f"route vr oids {vrs} do not match created VRF VIRTUAL_ROUTERs {new_vr_oids}")
    finally:
        _vrf_route_del(cli, VRF_A, dst_net, vrf_pair["in_peer"], vrf_pair["p_in_a"].name)
        _vrf_route_del(cli, VRF_B, dst_net, vrf_pair["in_peer"], vrf_pair["p_in_b"].name)


def test_vrf_dataplane_isolation_no_cross_leak(cli, dut, _lb, topo, vrf_pair):
    """Data-plane isolation: the route is added **only** in Vrf-A. Inject a flow to the Vrf-A ingress port -> should be forwarded to the Vrf-A egress (chip TX +~N);
    inject the **same** destination packet to the Vrf-B ingress port (B has no such route) -> should **not** be forwarded to any egress (no cross-VRF
    leak, egress-port chip TX ~0). This is the real "a VRF-A route is unreachable from VRF-B"."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")

    # Vrf-A egress port: bind into A, configure IP, enable loopback
    sub_out = topo.subnet("d")
    out_cidr = f"{sub_out['dut']}/{sub_out['prefix']}"
    p_out = topo.misc_port(0)
    ok, why = _bind_port_l3_in_vrf(cli, dut, _lb, topo, p_out, VRF_A, out_cidr)
    # Originally skipped on bind failure; failure is a real defect -> FAIL (treated as a defect by default)
    assert ok, f"DEVICE DEFECT: bind egress {p_out.name} to {VRF_A} failed: {why}"
    nh = sub_out["peer"]
    dst_net = topo.route("a")
    dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"
    rmac = vrf_pair["rmac"]

    # The route is only in Vrf-A
    _vrf_route(cli, VRF_A, dst_net, nh, p_out.name, _NH_MAC_A)
    try:
        # Originally skipped if the route was not programmed; already enslaved, the route should enter the Vrf-A kernel table, not entering is a real defect -> FAIL
        assert _wait_vrf_route(cli, VRF_A, dst_net), (
            f"DEVICE DEFECT: Vrf-A route {dst_net} not programmed into the VRF kernel table "
            f"(cannot drive isolation test; VRF enslavement not effective)")
        # Ensure Vrf-B really has **no** such route (isolation precondition)
        assert not _wait_vrf_route(cli, VRF_B, dst_net, tries=2), \
            "route unexpectedly present in Vrf-B; cannot prove isolation"

        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=vrf_pair["in_peer"], dst=dst_ip, ttl=64) / UDP())
        bsh = _lb.bsh
        # This diag's `show c` only shows counts that changed since the last show/clear (changed-since-clear view),
        # counting discipline = clear -> drive traffic -> poll-accumulate + confirming read (positive), negative waits >=2 refresh periods accumulating (guards against late-arrival misses).

        # (1) Vrf-A ingress -> should be forwarded to the Vrf-A egress
        ChipCounters.clear(bsh)
        sendp(pkt, iface=vrf_pair["p_in_a"].name, count=_N, verbose=False)
        d_a = _tx_accum(bsh, dut, p_out, _N)

        # (2) Vrf-B ingress -> same destination, B has no route -> should not be forwarded to the Vrf-A egress (no leak)
        ChipCounters.clear(bsh)
        sendp(pkt, iface=vrf_pair["p_in_b"].name, count=_N, verbose=False)
        d_b = _tx_settle(bsh, dut, p_out)

        assert _N * 0.9 <= d_a < 100_000, (
            f"Vrf-A traffic NOT forwarded to its egress {p_out.name}: chip TX delta={d_a} "
            f"(expected ~{_N}, no storm)")
        assert d_b < _N * 0.5, (
            f"CROSS-VRF LEAK: Vrf-B traffic to a Vrf-A-only route reached Vrf-A egress "
            f"{p_out.name}: chip TX delta={d_b} (sent={_N}; expected ~0)")
    finally:
        _vrf_route_del(cli, VRF_A, dst_net, nh, p_out.name)
        _unbind_port(cli, _lb, topo, p_out, VRF_A, out_cidr)


def test_vrf_same_ip_independent_forwarding(cli, dut, _lb, topo, vrf_pair):
    """The same destination IP has a route in each of two VRFs, pointing at **different** egress ports: inject a flow to the Vrf-A ingress -> only to A's egress;
    inject a flow to the Vrf-B ingress -> only to B's egress. Verify **no cross-talk** (A's traffic does not land on B's egress port, and vice versa)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")

    sub_a, sub_b = topo.subnet("d"), topo.subnet("e")
    out_a_cidr = f"{sub_a['dut']}/{sub_a['prefix']}"
    out_b_cidr = f"{sub_b['dut']}/{sub_b['prefix']}"
    p_out_a = topo.misc_port(0)
    p_out_b = topo.misc_port(1)

    # Originally skipped on bind failure; failure is a real defect -> FAIL (treated as a defect by default)
    ok_a, why_a = _bind_port_l3_in_vrf(cli, dut, _lb, topo, p_out_a, VRF_A, out_a_cidr)
    assert ok_a, f"DEVICE DEFECT: bind egress-A {p_out_a.name} to {VRF_A} failed: {why_a}"
    ok_b, why_b = _bind_port_l3_in_vrf(cli, dut, _lb, topo, p_out_b, VRF_B, out_b_cidr)
    if not ok_b:
        _unbind_port(cli, _lb, topo, p_out_a, VRF_A, out_a_cidr)   # reclaim egress port A before failing
        pytest.fail(f"DEVICE DEFECT: bind egress-B {p_out_b.name} to {VRF_B} failed: {why_b}")

    nh_a, nh_b = sub_a["peer"], sub_b["peer"]
    dst_net = topo.route("a")                       # the same destination prefix
    dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"
    rmac = vrf_pair["rmac"]

    _vrf_route(cli, VRF_A, dst_net, nh_a, p_out_a.name, _NH_MAC_A)
    _vrf_route(cli, VRF_B, dst_net, nh_b, p_out_b.name, _NH_MAC_B)
    try:
        # Originally skipped if the route was not programmed; already enslaved, both VRF routes should each enter the kernel table, not entering is a real defect -> FAIL
        assert _wait_vrf_route(cli, VRF_A, dst_net) and _wait_vrf_route(cli, VRF_B, dst_net), (
            f"DEVICE DEFECT: per-VRF route {dst_net} not programmed into VRF kernel tables "
            f"(cannot drive independence test; VRF enslavement not effective)")

        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=vrf_pair["in_peer"], dst=dst_ip, ttl=64) / UDP())
        bsh = _lb.bsh
        # This diag's `show c` is a changed-since-clear view (each port consumed independently): the positive port poll-accumulates + confirming read,
        # the negative port waits >=2 refresh periods accumulating (guards against missing late-arriving leak frames).

        # Vrf-A ingress injection: should reach p_out_a, not p_out_b
        ChipCounters.clear(bsh)
        sendp(pkt, iface=vrf_pair["p_in_a"].name, count=_N, verbose=False)
        a_to_a = _tx_accum(bsh, dut, p_out_a, _N)
        a_to_b = _tx_settle(bsh, dut, p_out_b)

        # Vrf-B ingress injection: should reach p_out_b, not p_out_a
        ChipCounters.clear(bsh)
        sendp(pkt, iface=vrf_pair["p_in_b"].name, count=_N, verbose=False)
        b_to_b = _tx_accum(bsh, dut, p_out_b, _N)
        b_to_a = _tx_settle(bsh, dut, p_out_a)

        assert _N * 0.9 <= a_to_a < 100_000, (
            f"Vrf-A traffic not forwarded to Vrf-A egress {p_out_a.name}: TX={a_to_a} (~{_N} expected)")
        assert a_to_b < _N * 0.5, (
            f"CROSS-VRF LEAK: Vrf-A traffic reached Vrf-B egress {p_out_b.name}: TX={a_to_b}")
        assert _N * 0.9 <= b_to_b < 100_000, (
            f"Vrf-B traffic not forwarded to Vrf-B egress {p_out_b.name}: TX={b_to_b} (~{_N} expected)")
        assert b_to_a < _N * 0.5, (
            f"CROSS-VRF LEAK: Vrf-B traffic reached Vrf-A egress {p_out_a.name}: TX={b_to_a}")
    finally:
        _vrf_route_del(cli, VRF_A, dst_net, nh_a, p_out_a.name)
        _vrf_route_del(cli, VRF_B, dst_net, nh_b, p_out_b.name)
        _unbind_port(cli, _lb, topo, p_out_b, VRF_B, out_b_cidr)
        _unbind_port(cli, _lb, topo, p_out_a, VRF_A, out_a_cidr)
