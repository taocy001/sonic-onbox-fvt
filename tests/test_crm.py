"""CRM resource usage: batch-drive N real resources → CRM used actually grows ~N + ASIC_DB SAI objects grow ~N in sync.

The old test_crm.py only did "write threshold then read back from CONFIG_DB" (config-echo) and
"crm show doesn't crash" (no-Traceback), which is a false pass / db-only. This version checks
real behavior:

  1. Batch-program N IPv4 routes/neighbors/FDB entries via legitimate paths (`ip route` /
     `ip neigh` / swssconfig static FDB) → these objects are really programmed into the chip;
  2. Assert CRM used (COUNTERS_DB CRM:STATS) grows ~N, and the corresponding ASIC_DB SAI object
     count (ROUTE_ENTRY / NEIGHBOR_ENTRY / FDB_ENTRY) grows ~N in sync -- proving CRM really
     accounts for *actual chip usage* (not just that the command didn't crash);
  3. After deletion used falls back.

Complementary to test_crm_chip.py (single-entry +1 used==ASIC consistency) and
test_crm_thresholds.py (threshold-alert closure): this file verifies the dimension of "CRM used
grows *linearly* with N real ASIC objects" (L3 route/neighbor + L2 FDB).

CRM counters are populated per polling cycle; after polling=1, give it a few seconds for used to
reflect ASIC changes. Counters not-ready (just reloaded) / routes not programmed to ASIC → a
legitimate pytest.skip, never assert True. Ports/subnets/prefixes all come from topo.
"""
import time

import pytest

pytestmark = [pytest.mark.crm]

# Number of resources to batch-drive. A moderate value: large enough to make "linear growth"
# credible, yet not enough to overwhelm shared lab equipment.
_N = 8
# Upper bound (seconds) for resources to be programmed to ASIC + reflected by CRM polling.
_CRM_TIMEOUT = 30
_CRM_POLL = 1
# Lower-bound tolerance for the growth criterion: background route/neighbor jitter may leave a
# few entries without net growth, so take ~0.75N as the lower bound for "really grew in batch".
_GROW_FRAC = 0.75


# ---------------- CRM stats primitives (pure DB, read-only, borrowed from test_crm_chip) ----------------
def _crm_stats(cli, res):
    """Read a resource's used/available: COUNTERS_DB HMGET CRM:STATS crm_stats_<res>_used/_available.

    Returns (used, available) integers; returns None if either field is missing/non-numeric
    (CRM not-ready or the resource does not exist).
    """
    out = cli.db(
        "COUNTERS_DB",
        f"HMGET CRM:STATS crm_stats_{res}_used crm_stats_{res}_available",
    )
    vals = [l.strip() for l in out.splitlines() if l.strip() != ""]
    if len(vals) < 2 or not (vals[0].lstrip("-").isdigit() and vals[1].lstrip("-").isdigit()):
        return None
    return int(vals[0]), int(vals[1])


def _wait_used(cli, res, predicate, timeout=_CRM_TIMEOUT):
    """Poll used until predicate(used) is true; returns (ok, last_used, last_avail)."""
    last = (None, None)
    end = time.time() + timeout
    while time.time() < end:
        st = _crm_stats(cli, res)
        if st is not None:
            last = st
            if predicate(st[0]):
                return True, st[0], st[1]
        time.sleep(_CRM_POLL)
    return False, last[0], last[1]


def _asic_count(asicdb, sai_type):
    return asicdb.count(f"ASIC_STATE:{sai_type}:*")


def _gen_prefixes(base_route, n):
    """Derive n mutually-disjoint /24 test prefixes from the topo base prefix (synthesize test addresses only; the network base comes from topo).

    base_route like "10.251.0.0/24" → 10.251.{c+1+i}.0/24. topo does not directly provide a pool
    of N prefixes, so derive them consecutively from the base network -- necessary for the "batch"
    test, and the network still originates from topo (no hardcoded unrelated addresses).
    """
    net, plen = base_route.split("/")
    a, b, c, _d = net.split(".")
    return [f"{a}.{b}.{int(c) + 1 + i}.0/{plen}" for i in range(n)]


def _gen_neigh_ips(dut_ip, n):
    """Derive n neighbor IPs within the L3 port subnet (last octet starting at .20, avoiding dut/.1 and peer/.2)."""
    a, b, c, _d = dut_ip.split(".")
    return [f"{a}.{b}.{c}.{20 + i}" for i in range(n)]


@pytest.fixture
def crm_fast_poll(cli):
    """Set CRM polling interval to 1s so used quickly reflects ASIC changes; restore after the test (restore value taken from DB on entry).

    Write CONFIG_DB CRM|Config polling_interval directly, bypassing the crm CLI -- on some images
    the crm CLI subcommand returns rc=0 but writes nothing; the direct write is equivalent to the
    CLI (crmorch consumes CONFIG_DB directly) and works on both kinds of image.
    """
    attrs = cli.db_hgetall("CONFIG_DB", "CRM|Config")
    orig = attrs.get("polling_interval", "300")
    cli.crm_set_polling(1)
    time.sleep(2)
    yield
    cli.crm_set_polling(orig)


# ======================================================================
# Case 1: N routes → CRM ipv4_route used +~N and ASIC ROUTE_ENTRY +~N → delete falls back
# ======================================================================
def test_crm_ipv4_route_used_grows_with_n_routes(cli, asicdb, l3up, topo, crm_fast_poll):
    """Batch routes drive CRM ipv4_route used linear growth: install one resolved next hop on an
    L3 port, program N mutually-disjoint static routes through it → CRM ipv4_route used should
    grow >=~0.75N and ASIC_DB ROUTE_ENTRY grow >=~0.75N in sync (CRM accounts for real chip
    usage); after deleting all, used falls back."""
    res = "ipv4_route"
    sub = topo.subnet("c")
    port = topo.l3_port(0).name
    l3up(port, f"{sub['dut']}/{sub['prefix']}")
    nh = sub["peer"]
    nh_mac = topo.mac("peer_a")
    prefixes = _gen_prefixes(topo.route("a"), _N)

    ready, u0, _a0 = _wait_used(cli, res, lambda u: True)
    assert ready, "DEVICE DEFECT: CRM ipv4_route stats never became ready after polling"
    used0 = u0
    asic0 = _asic_count(asicdb, "SAI_OBJECT_TYPE_ROUTE_ENTRY")

    # Resolve the next-hop neighbor first so routes through it are deterministically programmed to ASIC.
    cli.neigh_set(nh, nh_mac, port)
    for pfx in prefixes:
        cli.sh.run(f"ip route replace {pfx} via {nh} dev {port}", check=False)
    try:
        grew, used1, _ = _wait_used(cli, res, lambda u: u >= used0 + int(_N * _GROW_FRAC))
        assert grew, (
            f"DEVICE DEFECT: ipv4_route CRM used did not grow by ~{_N} (used {used0}->{used1}); "
            "routes not programmed/accounted to ASIC on this image"
        )
        # Real chip usage: ASIC_DB ROUTE_ENTRY grows in batch in sync (>=~0.75N).
        asic1 = _asic_count(asicdb, "SAI_OBJECT_TYPE_ROUTE_ENTRY")
        assert asic1 - asic0 >= int(_N * _GROW_FRAC), (
            f"CRM used grew (+{used1 - used0}) but ASIC ROUTE_ENTRY only +{asic1 - asic0} "
            f"for {_N} routes; CRM accounting decoupled from chip"
        )
    finally:
        for pfx in prefixes:
            cli.sh.run(f"ip route del {pfx} via {nh} dev {port}", check=False)
        cli.neigh_del(nh, port)
    fell, used2, _ = _wait_used(cli, res, lambda u: u <= used1 - int(_N * _GROW_FRAC))
    assert fell, (
        f"ipv4_route used did not fall back after deleting {_N} routes "
        f"(stuck at {used2}, peak {used1})"
    )


# ======================================================================
# Case 2: N neighbors → CRM ipv4_neighbor used +~N and ASIC NEIGHBOR_ENTRY +~N → delete falls back
# ======================================================================
def test_crm_ipv4_neighbor_used_grows_with_n_neighbors(cli, asicdb, l3up, topo, crm_fast_poll):
    """Batch neighbors drive CRM ipv4_neighbor used linear growth: configure N static neighbors
    within the L3 port subnet → CRM ipv4_neighbor used grows >=~0.75N and ASIC_DB NEIGHBOR_ENTRY
    grows >=~0.75N in sync; after deletion, falls back."""
    res = "ipv4_neighbor"
    sub = topo.subnet("d")
    port = topo.l3_port(1).name
    l3up(port, f"{sub['dut']}/{sub['prefix']}")
    ips = _gen_neigh_ips(sub["dut"], _N)
    macs = [f"00:11:22:33:55:{i:02x}" for i in range(_N)]

    ready, u0, _a0 = _wait_used(cli, res, lambda u: True)
    assert ready, "DEVICE DEFECT: CRM ipv4_neighbor stats never became ready after polling"
    used0 = u0
    asic0 = _asic_count(asicdb, "SAI_OBJECT_TYPE_NEIGHBOR_ENTRY")

    for ip, mac in zip(ips, macs):
        cli.neigh_set(ip, mac, port)
    try:
        grew, used1, _ = _wait_used(cli, res, lambda u: u >= used0 + int(_N * _GROW_FRAC))
        assert grew, (
            f"DEVICE DEFECT: ipv4_neighbor CRM used did not grow by ~{_N} (used {used0}->{used1}); "
            "neighbors not programmed/accounted to ASIC on this image"
        )
        asic1 = _asic_count(asicdb, "SAI_OBJECT_TYPE_NEIGHBOR_ENTRY")
        assert asic1 - asic0 >= int(_N * _GROW_FRAC), (
            f"CRM used grew (+{used1 - used0}) but ASIC NEIGHBOR_ENTRY only +{asic1 - asic0} "
            f"for {_N} neighbors; CRM accounting decoupled from chip"
        )
    finally:
        for ip, mac in zip(ips, macs):
            cli.neigh_del(ip, port)
        cli.sh.run(f"ip neigh flush dev {port}", check=False)
    fell, used2, _ = _wait_used(cli, res, lambda u: u <= used1 - int(_N * _GROW_FRAC))
    assert fell, (
        f"ipv4_neighbor used did not fall back after deleting {_N} neighbors "
        f"(stuck at {used2}, peak {used1})"
    )


# ======================================================================
# Case 3: N static FDB entries → CRM fdb_entry used +~N and ASIC FDB_ENTRY +~N → delete falls back
# ======================================================================
def test_crm_fdb_used_grows_with_n_entries(cli, asicdb, topo, crm_fast_poll):
    """Batch static FDB drives CRM fdb_entry used linear growth: write N static FDB entries with
    distinct MACs to an L2 port of the default VLAN (swssconfig -> APPL_DB -> fdborch -> ASIC) →
    CRM fdb_entry used grows >=~0.75N and ASIC_DB FDB_ENTRY grows >=~0.75N in sync (the L2 table's
    batch-linear dimension; single-entry +1 is already covered by test_crm_chip); after deleting
    all, used falls back."""
    res = "fdb_entry"
    _pobj = topo.l2_port(0)
    port = _pobj.name                  # L2-domain port, not polluted by a RIF
    # On l2_home_forwarding=false platforms the default VLAN is a parking spot and its members
    # are not programmed to ASIC, so static FDB on it is not programmed (in a real VLAN
    # fdb_static_add creates FDB_ENTRY normally). So create a real test VLAN + convert to L2 member.
    _own_vlan = not topo.caps.has("l2_home_forwarding")
    vlan = topo.vlan("l2fwd") if _own_vlan else topo.default_vlan
    if _own_vlan:
        cli.ensure_port_l2(_pobj)
        cli.config_raw(f"vlan add {vlan}")
        cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {vlan} {port}")
    # Derive N distinct locally-administered unicast MACs (02: prefix), non-overlapping with the src/learn/neighbor MAC pools of other cases.
    macs = [f"02:aa:bb:cc:66:{i:02x}" for i in range(_N)]

    ready, u0, _a0 = _wait_used(cli, res, lambda u: True)
    assert ready, "DEVICE DEFECT: CRM fdb_entry stats never became ready after polling"
    used0 = u0
    asic0 = _asic_count(asicdb, "SAI_OBJECT_TYPE_FDB_ENTRY")

    # Static FDB goes through swssconfig (HSET does not trigger fdborch); program N distinct MACs one by one.
    for mac in macs:
        cli.fdb_static_add(vlan, mac, port)
    try:
        grew, used1, _ = _wait_used(cli, res, lambda u: u >= used0 + int(_N * _GROW_FRAC))
        assert grew, (
            f"DEVICE DEFECT: fdb_entry CRM used did not grow by ~{_N} (used {used0}->{used1}); "
            "static FDB entries not programmed/accounted to ASIC on this image"
        )
        # Real chip usage: ASIC_DB FDB_ENTRY grows in batch in sync (>=~0.75N).
        asic1 = _asic_count(asicdb, "SAI_OBJECT_TYPE_FDB_ENTRY")
        assert asic1 - asic0 >= int(_N * _GROW_FRAC), (
            f"CRM used grew (+{used1 - used0}) but ASIC FDB_ENTRY only +{asic1 - asic0} "
            f"for {_N} static FDB entries; CRM accounting decoupled from chip"
        )
    finally:
        for mac in macs:
            cli.fdb_static_del(vlan, mac)
        if _own_vlan:
            cli.config_raw(f"vlan member del {vlan} {port}")
            cli.config_raw(f"vlan del {vlan}")
    fell, used2, _ = _wait_used(cli, res, lambda u: u <= used1 - int(_N * _GROW_FRAC))
    assert fell, (
        f"fdb_entry used did not fall back after deleting {_N} static FDB entries "
        f"(stuck at {used2}, peak {used1})"
    )
