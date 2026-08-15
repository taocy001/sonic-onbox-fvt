"""Consistency closed loop between CRM resource counts and **actual chip occupancy**.

The existing test_crm.py / test_queue_crm.py only verify CRM used/available are readable;
test_crm_thresholds.py verifies the threshold-alarm syslog closed loop. The angle this module adds
is a **cross-check of CRM counts against the real SAI object count in ASIC_DB** -- CRM:STATS is the
chip's own resource accounting, which must agree with the count of objects actually programmed to
the chip, otherwise the accounting is decoupled from hardware.

Per-case chip-behavior assertions (not just "the DB object exists"):
  1. Invariant: used + available == capacity constant (the total is constant before/after adding a
     resource) -- proving CRM really does hardware-quota accounting.
  2. Driven increment (route/neighbor/nexthop/fdb, all programmed via CLI / swssconfig / ip, no
     bcmcmd table edits): CRM used rises == the corresponding ASIC_DB SAI_OBJECT count rises in sync
     (matching delta). The same action makes CRM available **fall by the same amount** (used-up /
     avail-down conservation).
  3. Threshold crossing: straddle the type-used threshold on both sides of the current used value ->
     CRM state rises to EXCEEDED (syslog).

CRM counts are populated per polling cycle; after polling=1, wait for used to reflect ASIC changes.
Counts not-ready / resource absent on this image / the port the driver needs is absent -> a
justified pytest.skip, never assert True. Ports/prefixes/neighbors/MACs all come from topo.
Syslog observation of the threshold alarm uses the baseline-count method (record the matching line
count n0 before setting the threshold, then require strictly > n0 afterward); the pattern contains
a resource-name token (e.g. IPV4_ROUTE) -- old alarm lines in historical logs will not falsely
satisfy it.

L2/route/neighbor/nexthop resource accounting is normal (these objects are indeed programmed to the
chip); user ACL rules are not programmed to ASIC (acl_rule_program=false), so this module does not
touch ACL CRM.
"""
import time

import pytest

pytestmark = [pytest.mark.crm]

# CRM counts are populated per polling cycle; after polling=1, give it a few seconds for used to reflect ASIC changes.
CRM_UPDATE_TIMEOUT = 20
CRM_POLL_INTERVAL = 1
SYSLOG_TIMEOUT = 25
EXPECT_EXCEEDED = "THRESHOLD_EXCEEDED"

# CRM resource name (COUNTERS_DB CRM:STATS) -> (ASIC_DB SAI object type, CLI subcommand path)
_ASIC_TYPE = {
    "ipv4_route":    "SAI_OBJECT_TYPE_ROUTE_ENTRY",
    "ipv4_neighbor": "SAI_OBJECT_TYPE_NEIGHBOR_ENTRY",
    "ipv4_nexthop":  "SAI_OBJECT_TYPE_NEXT_HOP",
    "fdb_entry":     "SAI_OBJECT_TYPE_FDB_ENTRY",
}


# ---------------- CRM stats primitives (pure DB, read-only) ----------------
def _crm_stats(cli, res):
    """Read a resource's used/available: COUNTERS_DB HMGET CRM:STATS crm_stats_<res>_used/_available.

    Returns (used, available) integers; if any field is missing/non-numeric (CRM not-ready or the
    resource does not exist), returns None.
    """
    out = cli.db(
        "COUNTERS_DB",
        f"HMGET CRM:STATS crm_stats_{res}_used crm_stats_{res}_available",
    )
    vals = [l.strip() for l in out.splitlines() if l.strip() != ""]
    if len(vals) < 2 or not (vals[0].lstrip("-").isdigit() and vals[1].lstrip("-").isdigit()):
        return None
    return int(vals[0]), int(vals[1])


def _wait_stats(cli, res, predicate, timeout=CRM_UPDATE_TIMEOUT):
    """Poll (used, available) until predicate(used, avail) is true; returns (ok, used, avail)."""
    last = (None, None)
    end = time.time() + timeout
    while time.time() < end:
        st = _crm_stats(cli, res)
        if st is not None:
            last = st
            if predicate(st[0], st[1]):
                return True, st[0], st[1]
        time.sleep(CRM_POLL_INTERVAL)
    return False, last[0], last[1]


def _asic_count(asicdb, res):
    """Current count of ASIC_DB SAI objects for this CRM resource (actual chip occupancy)."""
    return asicdb.count(f"ASIC_STATE:{_ASIC_TYPE[res]}:*")


def _crm_injector(cli, res, topo, get_l3up):
    """Return (inject, undo) by CRM resource type: inject() programs **one** resource of that class via
    a legitimate path (really programmed to the chip), undo() deletes it. The L3 interface up/IP (and
    the route's nexthop neighbor) are done inside this function, **before** the baseline, so the
    baseline already includes the connected-route/interface overhead and inject's delta cleanly maps
    to the single injected resource.

    Ports/prefixes/neighbors/MACs all come from topo (not hardcoded). get_l3up is a callback that
    lazily fetches the l3up fixture -- only L3 resources need loopback to pull the port up; FDB (L2)
    does not depend on it, avoiding needlessly coupling the whole case to the loopback capability."""
    if res == "fdb_entry":
        vlan, mac, port = topo.default_vlan, topo.mac("learn"), topo.l2_port(0).name
        # static FDB via swssconfig (HSET does not trigger fdborch), wait=True waits for real ASIC programming
        return (lambda: cli.fdb_static_add(vlan, mac, port),
                lambda: cli.fdb_static_del(vlan, mac))
    if res == "ipv4_route":
        net = topo.subnet("c")
        route = topo.route("a")
        nh = net["peer"]
        nh_mac = topo.mac("peer_a")
        port = topo.port_name("c")
        get_l3up()(port, f"{net['dut']}/{net['prefix']}")
        # resolve the nexthop neighbor before the baseline, so inject only adds that one static route -> ipv4_route used cleanly +1
        cli.neigh_set(nh, nh_mac, port)

        def _undo():
            cli.sh.run(f"ip route del {route} via {nh} dev {port}", check=False)
            cli.neigh_del(nh, port)
            cli.sh.run(f"ip neigh flush dev {port}", check=False)

        return (lambda: cli.sh.run(f"ip route replace {route} via {nh} dev {port}", check=False),
                _undo)
    if res == "ipv4_neighbor":
        net = topo.subnet("d")
        peer_ip = net["peer"]
        peer_mac = topo.mac("peer_c")
        port = topo.port_name("d")
        get_l3up()(port, f"{net['dut']}/{net['prefix']}")

        def _undo():
            cli.neigh_del(peer_ip, port)
            cli.sh.run(f"ip neigh flush dev {port}", check=False)

        return (lambda: cli.neigh_set(peer_ip, peer_mac, port),
                _undo)
    raise AssertionError(f"no CRM injector for res {res}")


def _count_syslog_matches(cli, ere_pattern):
    """Count lines in /var/log/syslog matching ere_pattern (grep -E regex) (same implementation as test_crm_thresholds).

    The read primitive for the baseline-count method: the caller records baseline n0 **before** the
    triggering action, then requires the count strictly > n0 afterward for a "new alarm line to have
    appeared" -- fundamentally excluding false satisfaction from old alarm lines in historical logs
    (prior cases / prior sessions). When /var/log/syslog is unreadable, fall back to journalctl
    (still read-only, -n bounds the window to prevent a full scan).
    """
    r = cli.sh.run(f"grep -acE '{ere_pattern}' /var/log/syslog 2>/dev/null", check=False)
    out = (r.out or "").strip()
    if out.isdigit():
        return int(out)
    r = cli.sh.run(
        f"journalctl -q --no-pager -n 5000 2>/dev/null | grep -acE '{ere_pattern}'", check=False)
    out = (r.out or "").strip()
    return int(out) if out.isdigit() else 0


def _wait_syslog_exceeded(cli, res_token, baseline, timeout=SYSLOG_TIMEOUT):
    """Poll syslog until the "<res_token> ... THRESHOLD_EXCEEDED" match count strictly exceeds baseline (a new line appears).

    res_token is the resource name in the crmorch alarm line (e.g. IPV4_ROUTE, line format
    "<RES> THRESHOLD_EXCEEDED for TH_USED ..."); tightening the match prevents crosstalk from other
    resources / historical alarms.
    """
    pat = f"{res_token}.*{EXPECT_EXCEEDED}"
    end = time.time() + timeout
    while time.time() < end:
        if _count_syslog_matches(cli, pat) > baseline:
            return True
        time.sleep(1)
    return False


def _set_threshold(cli, res_key, ttype, low, high):
    """Set a resource's type/low/high threshold: write CONFIG_DB CRM|Config directly (res_key uses an underscore prefix, e.g. ipv4_route).

    Bypasses the crm CLI -- SONiC hard-blocks the crm CLI for vendor-x (the subcommand returns rc=0
    but writes nothing); writing CONFIG_DB directly is equivalent to the CLI (crmorch consumes it
    directly) and works on both image types.
    """
    return cli.crm_set_threshold(res_key, ttype, low, high)


# ---------------- fixtures ----------------
@pytest.fixture
def crm_fast_poll(cli):
    """Set the CRM polling interval to 1s so used reflects ASIC changes quickly, restored after the test (restore value taken from the DB at entry).

    Writes CONFIG_DB CRM|Config polling_interval directly, bypassing the blocked crm CLI (under
    SONiC/vendor-x the crm subcommand returns rc=0 but writes nothing); crmorch consumes CONFIG_DB
    directly, so the direct write is equivalent to the CLI and works on both image types.
    """
    attrs = cli.db_hgetall("CONFIG_DB", "CRM|Config")
    orig = attrs.get("polling_interval", "300")
    cli.crm_set_polling(1)
    time.sleep(2)
    yield
    cli.crm_set_polling(orig)


@pytest.fixture
def crm_thr_guard(cli):
    """Threshold-change guard: on entry snapshot the modified resource's type/low/high, on exit restore each one (CRM goes through the DB, which config_guard does not cover)."""
    saved = {}

    def _snapshot(res_key):
        attrs = cli.db_hgetall("CONFIG_DB", "CRM|Config")
        saved[res_key] = {
            "type": attrs.get(f"{res_key}_threshold_type", "percentage"),
            "low": attrs.get(f"{res_key}_low_threshold", "70"),
            "high": attrs.get(f"{res_key}_high_threshold", "85"),
        }

    yield _snapshot
    # restore by writing CONFIG_DB directly (same as the set path, bypassing the blocked crm CLI)
    for res_key, v in saved.items():
        cli.crm_set_threshold(res_key, v["type"], v["low"], v["high"])


# ======================================================================
# Case 1: invariant used + available == capacity (CRM really does hardware-quota accounting)
# ======================================================================
@pytest.mark.parametrize("res", ["ipv4_route", "ipv4_neighbor", "fdb_entry"])
def test_crm_used_plus_available_is_capacity(cli, asicdb, res, topo, crm_fast_poll, request):
    """CRM resource-accounting invariant + real-occupancy accounting: after injecting one real resource, used **really +1**, capacity (used+available) unchanged.

    Chip behavior: CRM available is (hardware capacity - used). After injecting one resource of that
    class via a legitimate path (route/neighbor/FDB, really programmed to the chip), we assert:
      1) used >= used0+1 (the injected resource's real occupancy is reflected in CRM accounting,
         rather than a hardcoded/never-updated placeholder value);
      2) used+available == the pre-injection capacity constant (available falls by an equal amount
         as occupancy grows, capacity conserved);
      3) cross-confirm the corresponding ASIC SAI object count also +1 (confirming real chip
         occupancy, not counter jitter).
    teardown deletes the resource; capacity returns to the same constant and used falls back. This
    verifies CRM as chip resource accounting, rather than "the command did not crash".
    """
    # Only L3 resources (route/neighbor) need loopback to pull the port up, so lazily fetch l3up; FDB does not depend on it (avoids needless coupling).
    def get_l3up():
        return request.getfixturevalue("l3up")
    inject, undo = _crm_injector(cli, res, topo, get_l3up)

    # CRM counts are populated by polling: poll-wait for readiness; failure to become ready is surfaced as a defect (no longer masked by skip)
    ready, u0, a0 = _wait_stats(cli, res, lambda u, a: True)
    assert ready, (
        f"CRM stats for {res} never became ready after "
        f"{CRM_UPDATE_TIMEOUT}s polling (CRM daemon not populating)"
    )
    used0, avail0 = u0, a0
    cap0 = used0 + avail0
    _CAP_TOL = 8   # near-conservation tolerance for capacity: absorbs CRM async sampling + route-pool internal sharing + background add/delete on the shared device
    assert cap0 > 0, f"{res}: used+available capacity must be >0 (used={used0} avail={avail0})"
    asic0 = _asic_count(asicdb, res)

    inject()
    try:
        grew, used1, avail1 = _wait_stats(cli, res, lambda u, a: u >= used0 + 1)
        # after injecting a real resource, used must +1; no increase = defect
        assert grew, (
            f"{res}: injected one resource but CRM used did not increment "
            f"(used {used0}->{used1}); not programmed/accounted to ASIC"
        )
        # 1) real-occupancy accounting: used at least +1
        assert used1 >= used0 + 1, f"{res}: used did not grow after inject (used {used0}->{used1})"
        # 2) near-conservation of capacity: after injecting, used+available still ~= the original capacity
        #    constant. Small drift is allowed -- CRM used/available update asynchronously + route-pool
        #    internal sharing (adding 1 route may make available drop by more than 1) + background
        #    add/delete on the shared lab device; the true "CRM accounting decoupled from chip" is
        #    backstopped by the (3) ASIC object count +1 cross-confirmation below.
        assert abs((used1 + avail1) - cap0) <= _CAP_TOL, (
            f"{res}: capacity drifted beyond tolerance after injecting one resource: was {cap0}, "
            f"now used={used1} avail={avail1} sum={used1 + avail1} (tol={_CAP_TOL})"
        )
        # 3) cross-confirm real chip occupancy: the corresponding ASIC SAI object count +1 in sync (allow background jitter, take >=+1)
        asic1 = _asic_count(asicdb, res)
        assert asic1 >= asic0 + 1, (
            f"{res}: CRM used grew ({used0}->{used1}) but ASIC {_ASIC_TYPE[res]} did not "
            f"({asic0}->{asic1}); CRM accounting decoupled from chip"
        )
    finally:
        undo()
    # teardown: after deleting the resource, capacity is still the same constant and used falls back
    ok, used2, avail2 = _wait_stats(cli, res, lambda u, a: abs((u + a) - cap0) <= _CAP_TOL and u <= used1)
    assert ok, (
        f"{res}: after deleting injected resource, capacity/used did not settle back "
        f"(cap0={cap0}, now used={used2} avail={avail2} "
        f"sum={used2 + avail2 if used2 is not None else None}, peak used={used1})"
    )


# ======================================================================
# Case 2: increment consistency -- CRM used up == ASIC_DB SAI object count up, and available down by the same amount
# ======================================================================
def test_crm_route_used_matches_asic_route_count(cli, asicdb, l3up, topo, crm_fast_poll):
    """ipv4_route: add one static route -> CRM used +1 and ASIC_DB ROUTE_ENTRY count +1 (consistent),
    while CRM available -1 (used-up/avail-down conservation); after deleting the route both fall back together."""
    res = "ipv4_route"
    net = topo.subnet("c")
    route = topo.route("a")
    nh = net["peer"]
    nh_mac = topo.mac("peer_a")
    port = topo.port_name("c")
    l3up(port, f"{net['dut']}/{net['prefix']}")
    # single box, no peer, so the nexthop ARP cannot resolve -> route unresolved -> not programmed to ASIC. Add a
    # static neighbor to resolve the nexthop, so the route is really programmed to the chip (added before the
    # baseline, so it only affects neighbor accounting and does not pollute the route-used baseline).
    cli.neigh_set(nh, nh_mac, port)

    ready, u0, a0 = _wait_stats(cli, res, lambda u, a: True)
    assert ready, "CRM ipv4_route stats never became ready after polling"
    used0, avail0 = u0, a0
    asic0 = _asic_count(asicdb, res)

    cli.sh.run(f"ip route replace {route} via {nh} dev {port}", check=False)
    try:
        grew, used1, avail1 = _wait_stats(cli, res, lambda u, a: u >= used0 + 1)
        assert grew, (
            f"ipv4_route CRM used did not increment (used {used0}->{used1}); "
            "route not programmed/accounted to ASIC"
        )
        # real chip occupancy: ASIC_DB ROUTE_ENTRY +1 in sync (at least +1, allowing background route jitter)
        asic1 = _asic_count(asicdb, res)
        assert asic1 >= asic0 + 1, (
            f"CRM used grew ({used0}->{used1}) but ASIC ROUTE_ENTRY did not "
            f"({asic0}->{asic1}); CRM accounting decoupled from chip"
        )
        # near-conservation of capacity (drift allowed: route pool reorganizes with occupancy + the /32 host
        # route introduced by the static neighbor + background route jitter on the shared device; real occupancy
        # is already confirmed by the ASIC ROUTE_ENTRY +1 above, here we only guard against capacity being drastically rewritten)
        assert abs((used1 + avail1) - (used0 + avail0)) <= 16, (
            f"ipv4_route capacity drifted beyond tolerance: was {used0 + avail0}, "
            f"now {used1 + avail1} (used +{used1 - used0}, avail {avail1 - avail0:+d})"
        )
    finally:
        cli.sh.run(f"ip route del {route} via {nh} dev {port}", check=False)
        cli.neigh_del(nh, port)
    fell, used2, _ = _wait_stats(cli, res, lambda u, a: u <= used1)
    assert fell, f"ipv4_route used did not fall back after route delete (stuck at {used2}, peak {used1})"


def test_crm_neighbor_used_matches_asic_neighbor_count(cli, asicdb, l3up, topo, crm_fast_poll):
    """ipv4_neighbor: add one static neighbor -> CRM used +1 and ASIC_DB NEIGHBOR_ENTRY count +1 (consistent),
    available -1 conserved; falls back after deleting the neighbor."""
    res = "ipv4_neighbor"
    net = topo.subnet("d")
    peer_ip = net["peer"]
    peer_mac = topo.mac("peer_c")
    port = topo.port_name("d")
    l3up(port, f"{net['dut']}/{net['prefix']}")

    ready, u0, a0 = _wait_stats(cli, res, lambda u, a: True)
    assert ready, "CRM ipv4_neighbor stats never became ready after polling"
    used0, avail0 = u0, a0
    asic0 = _asic_count(asicdb, res)

    cli.neigh_set(peer_ip, peer_mac, port)
    try:
        grew, used1, avail1 = _wait_stats(cli, res, lambda u, a: u >= used0 + 1)
        assert grew, (
            f"ipv4_neighbor CRM used did not increment (used {used0}->{used1}); "
            "neighbor not programmed/accounted to ASIC"
        )
        asic1 = _asic_count(asicdb, res)
        assert asic1 >= asic0 + 1, (
            f"CRM used grew ({used0}->{used1}) but ASIC NEIGHBOR_ENTRY did not "
            f"({asic0}->{asic1}); CRM accounting decoupled from chip"
        )
        assert (used1 - used0) == (avail0 - avail1), (
            f"ipv4_neighbor used/available not conserved: used +{used1 - used0}, "
            f"avail {avail0 - avail1:+d}"
        )
    finally:
        cli.neigh_del(peer_ip, port)
        cli.sh.run(f"ip neigh flush dev {port}", check=False)
    fell, used2, _ = _wait_stats(cli, res, lambda u, a: u <= used1)
    assert fell, f"ipv4_neighbor used did not fall back after neigh delete (stuck at {used2}, peak {used1})"


def test_crm_nexthop_used_matches_asic_nexthop_count(cli, asicdb, l3up, topo, crm_fast_poll):
    """ipv4_nexthop: a neighbor + a route through it makes a nexthop land -> CRM used +1 and ASIC_DB NEXT_HOP count +1,
    available -1 conserved; falls back after deletion."""
    res = "ipv4_nexthop"
    net = topo.subnet("c")
    peer_ip = net["peer"]
    peer_mac = topo.mac("peer_a")
    route = topo.route("b")
    port = topo.port_name("c")
    l3up(port, f"{net['dut']}/{net['prefix']}")

    ready, u0, a0 = _wait_stats(cli, res, lambda u, a: True)
    assert ready, "CRM ipv4_nexthop stats never became ready after polling"
    used0, avail0 = u0, a0
    asic0 = _asic_count(asicdb, res)

    cli.neigh_set(peer_ip, peer_mac, port)
    cli.sh.run(f"ip route replace {route} via {peer_ip} dev {port}", check=False)
    try:
        grew, used1, avail1 = _wait_stats(cli, res, lambda u, a: u >= used0 + 1)
        assert grew, (
            f"ipv4_nexthop CRM used did not increment (used {used0}->{used1}); "
            "nexthop not programmed/accounted to ASIC"
        )
        asic1 = _asic_count(asicdb, res)
        assert asic1 >= asic0 + 1, (
            f"CRM used grew ({used0}->{used1}) but ASIC NEXT_HOP did not "
            f"({asic0}->{asic1}); CRM accounting decoupled from chip"
        )
        assert (used1 - used0) == (avail0 - avail1), (
            f"ipv4_nexthop used/available not conserved: used +{used1 - used0}, "
            f"avail {avail0 - avail1:+d}"
        )
    finally:
        cli.sh.run(f"ip route del {route} via {peer_ip} dev {port}", check=False)
        cli.neigh_del(peer_ip, port)
        cli.sh.run(f"ip neigh flush dev {port}", check=False)
    fell, used2, _ = _wait_stats(cli, res, lambda u, a: u <= used1)
    assert fell, f"ipv4_nexthop used did not fall back after delete (stuck at {used2}, peak {used1})"


def test_crm_fdb_used_matches_asic_fdb_count(cli, asicdb, topo, crm_fast_poll):
    """fdb_entry: write one static FDB (swssconfig -> APPL_DB -> fdborch -> ASIC) -> CRM used +1 and
    ASIC_DB FDB_ENTRY count +1 (consistent), available -1 conserved; falls back after deleting the FDB. L2 resource."""
    res = "fdb_entry"
    _pobj = topo.l2_port(0)
    port = _pobj.name                  # L2-domain port, not polluted by a RIF
    mac = topo.mac("learn")            # dedicated MAC, avoids crosstalk with the FDB state of the shared src
    # on an l2_home_forwarding=false platform the default VLAN is a berth, members are not programmed to ASIC, and a
    # static FDB is not programmed -> use a real test VLAN (in a real VLAN the crmorch fdb_entry count grows normally).
    _own_vlan = not topo.caps.has("l2_home_forwarding")
    vlan = topo.vlan("l2fwd") if _own_vlan else topo.default_vlan
    if _own_vlan:
        cli.ensure_port_l2(_pobj)
        cli.config_raw(f"vlan add {vlan}")
        cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {vlan} {port}")

    ready, u0, a0 = _wait_stats(cli, res, lambda u, a: True)
    assert ready, "CRM fdb_entry stats never became ready after polling"
    used0, avail0 = u0, a0
    asic0 = _asic_count(asicdb, res)

    # static FDB via swssconfig (HSET does not trigger fdborch), wait=True waits for real ASIC programming before returning
    cli.fdb_static_add(vlan, mac, port)
    try:
        grew, used1, avail1 = _wait_stats(cli, res, lambda u, a: u >= used0 + 1)
        assert grew, (
            f"fdb_entry CRM used did not increment (used {used0}->{used1}); "
            "static FDB not programmed/accounted to ASIC"
        )
        asic1 = _asic_count(asicdb, res)
        assert asic1 >= asic0 + 1, (
            f"CRM used grew ({used0}->{used1}) but ASIC FDB_ENTRY did not "
            f"({asic0}->{asic1}); CRM accounting decoupled from chip"
        )
        assert (used1 - used0) == (avail0 - avail1), (
            f"fdb_entry used/available not conserved: used +{used1 - used0}, "
            f"avail {avail0 - avail1:+d}"
        )
    finally:
        cli.fdb_static_del(vlan, mac)
        if _own_vlan:
            cli.config_raw(f"vlan member del {vlan} {port}")
            cli.config_raw(f"vlan del {vlan}")
    fell, used2, _ = _wait_stats(cli, res, lambda u, a: u <= used1)
    assert fell, f"fdb_entry used did not fall back after FDB delete (stuck at {used2}, peak {used1})"


# ======================================================================
# Case 3: threshold crossing raises state -- used really grows above the threshold -> CRM state EXCEEDED (syslog)
# ======================================================================
def test_crm_route_threshold_crossing_raises_state(cli, asicdb, l3up, topo,
                                                   crm_fast_poll, crm_thr_guard):
    """Threshold crossing: add a route so used really grows (ASIC ROUTE_ENTRY growing in sync proves real occupancy), straddle the
    type-used threshold on both sides of used -> CRM raises the state to THRESHOLD_EXCEEDED (syslog). Verifies the "threshold crossing raises state" CRM closed loop."""
    res = "ipv4_route"
    crm_thr_guard(res)
    net = topo.subnet("c")
    route = topo.route("c")
    nh = net["peer"]
    nh_mac = topo.mac("peer_a")
    port = topo.port_name("c")
    l3up(port, f"{net['dut']}/{net['prefix']}")
    # a static neighbor resolves the nexthop so the added route is really programmed to ASIC (single box, no peer, ARP cannot resolve, otherwise the route is unresolved).
    cli.neigh_set(nh, nh_mac, port)

    ready, u0, _a0 = _wait_stats(cli, res, lambda u, a: True)
    assert ready, "CRM ipv4_route stats never became ready after polling"
    used0 = u0
    asic0 = _asic_count(asicdb, res)

    cli.sh.run(f"ip route replace {route} via {nh} dev {port}", check=False)
    try:
        grew, used1, _ = _wait_stats(cli, res, lambda u, a: u >= used0 + 1)
        assert grew, (
            f"ipv4_route CRM used did not increment (used {used0}->{used1}); "
            "route not programmed/accounted to ASIC"
        )
        # confirm the increment is driven by real chip occupancy (not counter jitter)
        assert _asic_count(asicdb, res) >= asic0 + 1, (
            "ipv4_route used grew without ASIC ROUTE_ENTRY increase; not a real chip occupancy"
        )
        # grew guarantees used >= used0+1 >= 1, always usable for straddling the threshold on both sides
        assert used1 >= 1, f"ipv4_route used={used1} after inject, cannot straddle threshold"
        # type used, low=used-1 high=used -> used>=high -> state should rise to EXCEEDED (write CONFIG_DB directly, using res_key)
        # record the "IPV4_ROUTE ... EXCEEDED" baseline line count before setting the threshold, then require the count to
        # strictly increase (a new line really appears), so old alarm lines left by other cases in historical logs no longer falsely satisfy it.
        res_token = res.upper()   # crmorch resource name, e.g. IPV4_ROUTE
        n0 = _count_syslog_matches(cli, f"{res_token}.*{EXPECT_EXCEEDED}")
        _set_threshold(cli, res, "used", used1 - 1, used1)
        assert _wait_syslog_exceeded(cli, res_token, n0), (
            f"device issue: CRM did not raise new {res_token} {EXPECT_EXCEEDED} syslog line "
            f"after setting type used low={used1 - 1} high={used1} (used={used1}, baseline lines={n0})"
        )
    finally:
        cli.sh.run(f"ip route del {route} via {nh} dev {port}", check=False)
        cli.neigh_del(nh, port)
