"""Basic routing full feature set: v4/v6 static/default/floating/Null0/distance. Ports reference topo.

Data-plane routing cases (static/default/blackhole) verify forward/drop behavior with **real traffic**
(not just ASIC has_route programming), reusing framework.l3probe's storm-safe L3 probe (p_in inject ->
route to p_out -> measure chip TX).
"""
import time

import pytest

from framework import l3probe

pytestmark = [pytest.mark.l3, pytest.mark.traffic]


def test_ipv4_static_route(cli, asicdb, dut, _lb, l3up, topo, config_guard):
    """IPv4 static route: configure the route via SONiC CLI -> (1) ASIC has_route (programmed) + (2) **real traffic**: inject
    packets routed to p_out, verifying p_out chip TX +~N (really forwarded out that egress, not just checking the DB)."""
    topo.caps.require("loopback")
    route_a = topo.route("a")
    dst_ip = route_a.split("/")[0].rsplit(".", 1)[0] + ".5"
    with l3probe.TwoPortL3(cli, dut, _lb, topo, l3up) as s:
        assert s.rmac, "router MAC (DEVICE_METADATA.mac) not found"
        # Configure the static route via SONiC CLI, next hop = p_out subnet peer (resolved to p_out via a static neighbor)
        cli.config_raw(f"route add prefix {route_a} nexthop {s.nh}")
        config_guard.defer_undo(f"route del prefix {route_a} nexthop {s.nh}")
        assert asicdb.has_route(route_a, timeout=10), "IPv4 static route not programmed to ASIC"
        if not l3probe.wait_route(cli, route_a):
            pytest.fail(f"static route {route_a} programmed to ASIC but NOT installed "
                        f"to kernel FIB; cannot drive traffic")
        tx = s.forward_tx(dst_ip, n=30)
        assert 27 <= tx < 100_000, \
            f"static route real-traffic: chip TX to {s.p_out.name}={tx} (expected ~30 forwarded, no storm)"


def test_default_route(cli, asicdb, dut, _lb, l3up, topo, config_guard):
    """Default route: configure 0.0.0.0/0 -> inject a packet whose "destination is in no connected subnet", verifying it is
    really forwarded via the default route to p_out with chip TX +~N (real traffic, not just has_route)."""
    topo.caps.require("loopback")
    route_default = topo.route("default4")
    dst_ip = "198.51.100.7"   # in no connected subnet, can only go via the default route
    with l3probe.TwoPortL3(cli, dut, _lb, topo, l3up) as s:
        assert s.rmac, "router MAC (DEVICE_METADATA.mac) not found"
        rc, r = cli.config_raw(f"route add prefix {route_default} nexthop {s.nh}")
        config_guard.defer_undo(f"route del prefix {route_default} nexthop {s.nh}")
        # C: same 'route add prefix ... nexthop ...' syntax as test_ipv4_static_route (proven valid),
        # so the default-route config command must succeed; a rejected command is exposed as a failure, no longer masked by skip.
        assert rc == 0, f"default route config command rejected: {r.err or r.out}"
        # Kernel precondition: must wait until the default's next hop is **this test's nh**.
        # The old criterion `"default" in ip route show default` was trivially satisfied by the mgmt-port kernel default route
        # (via eth0, distance 0) -- in zebra it suppresses this test's static default route (static distance 1 loses to kernel 0),
        # zebra pushes 0/0 with next hop eth0, and fpmsyncd **drops it by design** ("The NextHop interface is
        # either eth0 or docker0") -> 0/0 never reaches APPL_DB/ASIC. Here the device behaves completely correctly,
        # the scenario is untestable on a device without mgmt VRF, so honestly skip.
        import time as _t
        kernel_def = ""
        for _ in range(20):
            kernel_def = cli.sh.run("ip route show default", check=False).out or ""
            if s.nh in kernel_def:
                break
            _t.sleep(0.5)
        if s.nh not in kernel_def:
            if "eth0" in kernel_def:
                pytest.skip("mgmt default route (via eth0, kernel distance 0) shadows the test "
                            "static default; fpmsyncd drops eth0-nexthop routes by design -- "
                            "scenario untestable without mgmt VRF")
            pytest.fail("static default route accepted but not installed to "
                        f"kernel FIB (current default: {kernel_def.strip()!r})")
        # Strengthened ASIC precondition: 0/0 entry **existing** is not enough (SONiC creates a DROP fallback entry at startup, so existence is trivially true) --
        # forwarding intent (non-DROP + non-empty next hop) must be verified before it can be attributed to the chip.
        assert asicdb.route_is_forwarding(route_default, timeout=8), (
            "default route present in ASIC_DB but still DROP/null-nexthop intent "
            "(orchagent never programmed the forward action; check fpmsyncd/routeorch)")
        tx = s.forward_tx(dst_ip, n=30)
        # A (default classification, originally an honest skip for "mgmt default route preemption"): this probe uses MAC loopback
        # to re-inject the frame into the chip ingress, and forwarding is decided by the chip FIB (asicdb.has_route already verified);
        # the mgmt default route via eth0 is not in the switch chip, so hardware forwarding is unaffected by it, hence TX should be ~N.
        # ASIC+kernel programming verified yet TX<27 is a known hardware-forwarding defect of "valid RIF+neighbor but TX=0" -> FAIL.
        # Uncertain item: defaulted to A and annotated.
        assert tx >= 27, (
            f"default route programmed to ASIC+kernel but real traffic NOT forwarded "
            f"to {s.p_out.name} (chip TX={tx}, expected ~30); L3 forward TX=0 with valid FIB "
            f"(uncertain, defaulted to A)")
        assert tx < 100_000, \
            f"default route real-traffic: chip TX to {s.p_out.name}={tx} (storm guard)"


def test_null0_blackhole_route(cli, dut, _lb, l3up, topo, config_guard):
    """Null0 blackhole route: verify dropping with **real traffic**. Under the same p_out egress, compare: (1) a normal route's
    destination is really forwarded (TX~N), (2) the blackhole subnet's destination is dropped (TX~0) -- proving it is the
    blackhole dropping packets, not the environment failing to forward."""
    topo.caps.require("loopback")
    route_fwd = topo.route("a")        # normal-forwarding control
    route_bh = topo.route("b")         # blackhole subnet
    dst_fwd = route_fwd.split("/")[0].rsplit(".", 1)[0] + ".5"
    dst_bh = route_bh.split("/")[0].rsplit(".", 1)[0] + ".5"
    with l3probe.TwoPortL3(cli, dut, _lb, topo, l3up) as s:
        assert s.rmac, "router MAC (DEVICE_METADATA.mac) not found"
        cli.config_raw(f"route add prefix {route_fwd} nexthop {s.nh}")
        config_guard.defer_undo(f"route del prefix {route_fwd} nexthop {s.nh}")
        # Blackhole route: the reworked OS uses the product `config route add prefix ... blackhole` (present in its parameter table),
        # the community image uses vtysh Null0.
        if cli.is_switchport_os():
            cli.config_raw(f"route add prefix {route_bh} blackhole")
        else:
            cli.vtysh(f"configure terminal\nip route {route_bh} Null0", config=False)
        try:
            if not (l3probe.wait_route(cli, route_fwd) and l3probe.wait_route(cli, route_bh)):
                pytest.fail("forward/blackhole routes not installed to kernel FIB; "
                            "cannot drive traffic")
            # The two measurement windows are independent: tx_delta internally does clear -> drive traffic -> accumulate read, no manual clear c needed
            tx_fwd = s.forward_tx(dst_fwd, n=30)
            tx_bh = s.forward_tx(dst_bh, n=30)
            # Normal subnet is really forwarded; blackhole subnet is dropped (TX far below normal)
            assert 27 <= tx_fwd < 100_000, f"control (normal route) TX={tx_fwd}, expected ~30 forwarded"
            assert tx_bh < 30 * 0.5, \
                f"blackhole route should DROP traffic to {route_bh}, but chip TX to {s.p_out.name}={tx_bh}"
        finally:
            if cli.is_switchport_os():
                cli.config_raw(f"route del prefix {route_bh} blackhole")
            else:
                cli.vtysh(f"configure terminal\nno ip route {route_bh} Null0", config=False)


def _wait_asic_route_gone(asicdb, pfx, timeout=15.0):
    """Poll whether the ROUTE_ENTRY containing this prefix has disappeared from ASIC_DB (route deletion really lands on the chip)."""
    end = time.time() + timeout
    while time.time() < end:
        if not any(pfx in k for k in asicdb.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY")):
            return True
        time.sleep(0.5)
    return False


def test_route_withdraw_stops_forwarding(cli, asicdb, dut, _lb, l3up, topo, config_guard):
    """Route deletion really withdraws hardware forwarding (the whole suite previously only tested the add direction, del was only
    in finally without observation): (1) route add -> real traffic TX~N (positive control); (2) route del -> ROUTE_ENTRY really
    disappears from the ASIC; (3) re-inject the same flow -> TX~0 (chip no longer forwards). Covers the
    zebra->fpmsyncd->orchagent->SAI deletion path end-to-end -- if deletion leaves residue (a stale hardware route) it would
    forward forever, and no case could see it before."""
    topo.caps.require("loopback")
    route_a = topo.route("a")
    dst_ip = route_a.split("/")[0].rsplit(".", 1)[0] + ".5"
    with l3probe.TwoPortL3(cli, dut, _lb, topo, l3up) as s:
        assert s.rmac, "router MAC (DEVICE_METADATA.mac) not found"
        rc, r = cli.config_raw(f"route add prefix {route_a} nexthop {s.nh}")
        config_guard.defer_undo(f"route del prefix {route_a} nexthop {s.nh}")   # fallback (repeated del is idempotent)
        assert rc == 0, f"route add CLI failed: {r.err or r.out}"
        assert asicdb.has_route(route_a, timeout=10), "static route not programmed to ASIC"
        if not l3probe.wait_route(cli, route_a):
            pytest.fail(f"static route {route_a} not installed to kernel FIB; "
                        f"cannot drive traffic")
        # (1) Positive control: really forwards while the route is present (if it does not work, "stops forwarding after deletion" is meaningless)
        tx1 = s.forward_tx(dst_ip, n=30)
        assert 27 <= tx1 < 100_000, (
            f"positive control: route present but chip TX to {s.p_out.name}={tx1} "
            f"(expected ~30 forwarded, no storm)")
        # (2) Delete the route: ASIC ROUTE_ENTRY must really disappear (chip-side evidence of the deletion path)
        rc, r = cli.config_raw(f"route del prefix {route_a} nexthop {s.nh}")
        assert rc == 0, f"route del CLI failed: {r.err or r.out}"
        assert _wait_asic_route_gone(asicdb, route_a), (
            f"route {route_a} still in ASIC_DB after 'route del' "
            f"(stale hardware route would forward forever)")
        # (3) Re-inject the same flow: after withdrawal the chip must not forward to p_out anymore (a tiny amount of background is allowed, but far < N)
        tx2 = s.forward_tx(dst_ip, n=30)
        assert tx2 < 30 * 0.5, (
            f"withdrawn route still forwarding in hardware: chip TX to {s.p_out.name}={tx2} "
            f"after route del (sent=30)")


def _appl_nexthops(cli, pfx):
    """Read the nexthop set of APPL_DB ROUTE_TABLE:<pfx> (fpmsyncd only writes the **FIB-selected** route into APPL_DB,
    so this is "the next hop of the route that entered the FIB" -- closer to the hardware forwarding plane than the FRR RIB)."""
    h = cli.db_hgetall("APPL_DB", f"ROUTE_TABLE:{pfx}")
    return set(x for x in (h.get("nexthop", "") or "").split(",") if x)


def _wait_appl_nexthop(cli, pfx, want_nh, timeout=12.0):
    """Poll-wait until the nexthop set of APPL_DB ROUTE_TABLE:<pfx> contains want_nh (waiting for the zebra->fpmsyncd async refresh)."""
    end = time.time() + timeout
    nhs = set()
    while time.time() < end:
        nhs = _appl_nexthops(cli, pfx)
        if want_nh in nhs:
            return nhs
        time.sleep(0.5)
    return nhs


def _static_route(cli, op, pfx, nh, dist):
    """Device adaptation for static-route config: the reworked OS uses the product `config route add/del prefix ... nexthop ...
    distance N` (vtysh does not carry config on that product, config is written to CONFIG_DB STATIC_ROUTE);
    the community image uses vtysh `ip route`. Assertion semantics unchanged (APPL_DB FIB selection + ASIC programming)."""
    if cli.is_switchport_os():
        cli.config_raw(f"route {op} prefix {pfx} nexthop {nh} distance {dist}")
    else:
        neg = "" if op == "add" else "no "
        cli.vtysh(f"configure terminal\n{neg}ip route {pfx} {nh} {dist}", config=False)


def _rib_has_both(cli, pfx, nh_p, nh_f):
    """Control-plane evidence that both static routes are configured: the reworked OS uses `show ip route-config` (config view);
    the community image uses the distance lines of the FRR RIB."""
    if cli.is_switchport_os():
        # Config-plane ground truth = CONFIG_DB STATIC_ROUTE|<pfx> (nexthop/distance comma-joined, e.g.
        # "10,200"/"nh1,nh2"); show ip route-config needs IPADDRESS+VRF args, and the info is equivalent, so read the DB directly.
        h = cli.db_hgetall("CONFIG_DB", f"STATIC_ROUTE|{pfx}") or {}
        nhs, dists = h.get("nexthop", ""), h.get("distance", "")
        ok = nh_p in nhs and nh_f in nhs and "10" in dists.split(",") and "200" in dists.split(",")
        return ok, f"STATIC_ROUTE|{pfx}={h}"
    rib = cli.run(f"show ip route {pfx}").out or ""
    return ("distance 10" in rib and "distance 200" in rib), rib


def _route_nexthop_matches(asicdb, pfx, nh_ip, timeout=12.0):
    """Poll-verify that the ASIC ROUTE_ENTRY for this prefix has SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID pointing at
    "the NEXT_HOP object with SAI_NEXT_HOP_ATTR_IP == nh_ip" (or a NEXT_HOP_GROUP containing that NEXT_HOP member).
    Stronger than has_route's key existence: it proves the **next hop itself** the chip selected, not just "that prefix has an object"."""
    end = time.time() + timeout
    while time.time() < end:
        nh_oids = {k.split("SAI_OBJECT_TYPE_NEXT_HOP:", 1)[1]
                   for k in asicdb.find("SAI_OBJECT_TYPE_NEXT_HOP", SAI_NEXT_HOP_ATTR_IP=nh_ip)}
        if nh_oids:
            # The platform may wrap a single next hop into a NEXT_HOP_GROUP: its group oid also counts as pointing at that next hop
            grp_oids = set()
            for m in asicdb.objects("SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"):
                attrs = asicdb.cli.db_hgetall("ASIC_DB", m)
                if attrs.get("SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID") in nh_oids:
                    grp_oids.add(attrs.get("SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID"))
            want = nh_oids | grp_oids
            for rk in asicdb.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY"):
                if pfx in rk and asicdb.field(rk, "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID") in want:
                    return True
        time.sleep(0.5)
    return False


def test_floating_static_route_distance(cli, asicdb, dut, _lb, l3up, topo, config_guard):
    """Floating static route: distance really affects **FIB selection + hardware forwarding** (not just appearing in FRR RIB/APPL_DB).

    Configure two static routes for the same prefix: primary (low distance) via nh1, floating (high distance) via nh2, with the two
    next hops landing in the subnets of two directly-connected L3 ports (both resolvable, both configured with a static neighbor MAC). Assert:
      - while primary is up, only primary enters the FIB: APPL_DB ROUTE_TABLE nexthop == primary (floating is **not** in it),
        both are in the control plane (RIB/route-config); the ASIC ROUTE_ENTRY's NEXT_HOP_ID resolves to primary's
        NEXT_HOP object; **real traffic**: injected packets should egress from primary egress p_p (chip TX ~N);
      - after deleting primary (primary down), floating takes over: APPL_DB nexthop switches to floating + ASIC
        NEXT_HOP_ID resolves to floating's NEXT_HOP object; **real traffic**: the same flow now egresses from p_f (TX ~N) --
        distance-driven failover really takes effect on the hardware forwarding plane, not just a DB key switch.
    (APPL_DB nexthop switches between primary/floating by distance.)
    Contamination guard: each phase injects from the **opposite port** as ingress (injection itself makes the injection port TX+N, so egress cannot be measured on the injection port)."""
    topo.caps.require("loopback")
    sub_p, sub_f = topo.subnet("c"), topo.subnet("d")   # directly-connected subnets of the primary / floating next hops
    nh_p, nh_f = sub_p["peer"], sub_f["peer"]
    p_p, p_f = topo.l3_port(0), topo.l3_port(1)
    pfx = topo.route("c")

    # Bring both L3 ports up (l3up enables MAC loopback to pull oper-up) + directly-connected subnets, so the connected nexthops of both static routes are resolvable
    l3up(p_p.name, f"{sub_p['dut']}/{sub_p['prefix']}")
    l3up(p_f.name, f"{sub_f['dut']}/{sub_f['prefix']}")
    cli.neigh_set(nh_p, topo.mac('peer_c'), p_p.name)
    cli.neigh_set(nh_f, topo.mac('peer_b'), p_f.name)

    # C (originally an isolation skip): the test prefix topo.route("c") should not already exist in the APPL_DB FIB on a clean device;
    # if it does, there is residue / injection by another process, exposed as a failure rather than masked by skip.
    assert not _appl_nexthops(cli, pfx), (
        f"test prefix {pfx} already in APPL_DB FIB before test (stale/leaked state); "
        f"cannot isolate distance-based selection")

    # primary distance 10 via nh_p; floating distance 200 via nh_f (high distance = backup)
    _static_route(cli, "add", pfx, nh_p, 10)
    _static_route(cli, "add", pfx, nh_f, 200)
    try:
        # (1) primary is in the FIB: APPL_DB nexthop == primary, floating is not
        nhs = _wait_appl_nexthop(cli, pfx, nh_p)
        # A: the primary next hop lands in an up directly-connected L3 port subnet with a static neighbor configured (resolvable), so the primary static route
        # must enter the APPL_DB FIB; not entering means the route was not programmed into the FIB/hardware -> defect.
        assert nhs, (f"static route {pfx} (primary via {nh_p}) not installed to APPL_DB FIB "
                     f"despite resolvable connected nexthop; route not entering hardware FIB")
        assert nh_p in nhs, f"primary (lower distance) nexthop {nh_p} not selected into FIB: {nhs}"
        assert nh_f not in nhs, (
            f"floating (higher distance) nexthop {nh_f} should NOT be in FIB while primary is up: {nhs}")
        # Both should be in the FRR RIB (control plane), proving floating is a real backup rather than unconfigured
        ok, rib = _rib_has_both(cli, pfx, nh_p, nh_f)
        assert ok, (
            f"both primary (distance 10) and floating (distance 200) should be present in the "
            f"routing control plane (RIB/route-config):\n{rib}")
        # The ASIC-selected next hop must be primary (object-level: ROUTE_ENTRY.NEXT_HOP_ID -> NEXT_HOP.IP==nh_p)
        assert _route_nexthop_matches(asicdb, pfx, nh_p), (
            f"ASIC ROUTE_ENTRY for {pfx} does not resolve to primary nexthop {nh_p} "
            f"(NEXT_HOP_ID mismatch: chip may still hold a stale/other nexthop)")
        # Real traffic: inject from p_f (the opposite port as ingress), should be forwarded out of primary egress p_p
        from scapy.all import Ether, IP, UDP
        rmac = l3probe.router_mac(cli)
        assert rmac, "router MAC (DEVICE_METADATA.mac) not found"
        dst_ip = pfx.split("/")[0].rsplit(".", 1)[0] + ".5"
        pkt1 = (Ether(dst=rmac, src=topo.mac("src")) /
                IP(src=sub_f["peer"], dst=dst_ip, ttl=64) / UDP(sport=1234, dport=80))
        tx_p = l3probe.tx_delta(_lb, dut, p_p, pkt1, p_f.name, n=30)
        assert 27 <= tx_p < 100_000, (
            f"primary route (distance 10) not carrying real traffic: chip TX to "
            f"{p_p.name}={tx_p} (expected ~30 forwarded, no storm)")

        # (2) primary down: delete primary -> floating should be installed into the FIB and take over hardware forwarding
        _static_route(cli, "del", pfx, nh_p, 10)
        nhs2 = _wait_appl_nexthop(cli, pfx, nh_f)
        assert nh_f in nhs2, (
            f"after primary withdrawn, floating nexthop {nh_f} did not take over the FIB "
            f"(distance did not drive failover): APPL_DB nexthops={nhs2}")
        assert nh_p not in nhs2, f"withdrawn primary {nh_p} still in FIB after removal: {nhs2}"
        # The ASIC-selected next hop must switch to floating (object-level, stronger than has_route's key existence)
        assert _route_nexthop_matches(asicdb, pfx, nh_f), (
            f"floating route {pfx} in FIB but ASIC ROUTE_ENTRY does not resolve to floating "
            f"nexthop {nh_f} (chip may still point at the withdrawn primary)")
        # Real traffic: the same-destination flow now egresses from floating egress p_f (failover really takes effect in hardware)
        pkt2 = (Ether(dst=rmac, src=topo.mac("src")) /
                IP(src=sub_p["peer"], dst=dst_ip, ttl=64) / UDP(sport=1234, dport=80))
        tx_f = l3probe.tx_delta(_lb, dut, p_f, pkt2, p_p.name, n=30)
        assert 27 <= tx_f < 100_000, (
            f"distance failover not effective in hardware: after primary withdrawal chip TX to "
            f"floating egress {p_f.name}={tx_f} (expected ~30 forwarded, no storm)")
    finally:
        _static_route(cli, "del", pfx, nh_p, 10)
        _static_route(cli, "del", pfx, nh_f, 200)
        cli.neigh_del(nh_p, p_p.name)
        cli.neigh_del(nh_f, p_f.name)
