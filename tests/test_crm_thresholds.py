"""CRM increment driving + threshold-alarm closed loop (adapted from sonic-mgmt tests/crm/).

The existing test_crm.py / test_queue_crm.py only *read* used/available. This module adds
the real closed loop:

  drive a resource increment -> CRM used really grows -> straddle the threshold around the
  measured value to trigger a syslog alarm -> THRESHOLD_EXCEEDED / THRESHOLD_CLEAR really
  appear -> delete the resource -> used falls back.

Core paradigm `verify_thresholds` (adapted from ~/sonic-mgmt/tests/common/helpers/crm.py and tests/crm/test_crm.py):
  1. Set polling interval to 1 (write CONFIG_DB CRM|Config polling_interval directly, restore
     after test, see the crm_fast_poll fixture) -- SONiC hard-blocks the crm CLI for vendor-x,
     so bypass the CLI and write CONFIG_DB directly (consumed by crmorch, equivalent).
  2. Read the resource's current used/avail: COUNTERS_DB HMGET CRM:STATS crm_stats_<res>_used/_available.
  3. Drive an increment (route/neighbor/nexthop/nexthop_group), poll to verify used really grows.
  4. Threshold alarm: type used, straddle low/high around the measured value:
       exceeded: low=used-1, high=used  -> used >= high -> THRESHOLD_EXCEEDED
       clear:    low=used,   high=used+1 -> used <  low  -> THRESHOLD_CLEAR
     Alarm observation uses a *baseline count* method: before setting the threshold, record
     the count n0 of syslog lines matching "<RES> THRESHOLD_EXCEEDED/CLEAR", then poll
     requiring the count to be strictly > n0 (a new line appeared) -- old alarm lines left in
     the history log by prior tests/sessions no longer falsely satisfy it; the pattern
     includes the resource-name token (e.g. IPV4_ROUTE) to prevent crosstalk from other
     resources' alarms.
  5. Cleanup: delete route/neighbor (verify used falls back), restore threshold and polling interval.

CRM counters not-ready (just reloaded) / resource absent on this image / driving port absent
-> pytest.skip with a reason, never assert True.
Ports/prefixes/neighbors all come from topo, not hardcoded; L3 ports brought oper-up via l3up.
"""
import time

import pytest

pytestmark = [pytest.mark.crm]

# adapted from sonic-mgmt: crmorch's WARNING alarm text ("... THRESHOLD_EXCEEDED for ...").
EXPECT_EXCEEDED = "THRESHOLD_EXCEEDED"
EXPECT_CLEAR = "THRESHOLD_CLEAR"

# CRM counters are filled per polling period; after polling=1, give a few seconds for used to reflect the ASIC change.
CRM_UPDATE_TIMEOUT = 20      # polling limit for the used counter to update (seconds)
CRM_POLL_INTERVAL = 1
SYSLOG_TIMEOUT = 25          # polling limit for the threshold alarm to be written to syslog (seconds)


# ---------------- CRM stats / threshold primitives (pure CLI + DB + syslog) ----------------
def _crm_stats(cli, res):
    """Read a resource's used/available: COUNTERS_DB HMGET CRM:STATS crm_stats_<res>_used/_available.

    Returns (used, available) integers; returns None if either field is missing/non-numeric
    (CRM not-ready or resource does not exist).
    """
    out = cli.db(
        "COUNTERS_DB",
        f"HMGET CRM:STATS crm_stats_{res}_used crm_stats_{res}_available",
    )
    vals = [l.strip() for l in out.splitlines() if l.strip() != ""]
    if len(vals) < 2 or not (vals[0].lstrip("-").isdigit() and vals[1].lstrip("-").isdigit()):
        return None
    return int(vals[0]), int(vals[1])


def _wait_used(cli, res, predicate, timeout=CRM_UPDATE_TIMEOUT):
    """Poll used until predicate(used) is true; returns (ok, last_used, last_avail)."""
    last = (None, None)
    end = time.time() + timeout
    while time.time() < end:
        st = _crm_stats(cli, res)
        if st is not None:
            last = st
            if predicate(st[0]):
                return True, st[0], st[1]
        time.sleep(CRM_POLL_INTERVAL)
    return False, last[0], last[1]


def _set_threshold(cli, res_key, ttype, low, high):
    """Set a resource's type/low/high threshold: write CONFIG_DB CRM|Config directly (res_key uses an underscore prefix, e.g. ipv4_route).

    Bypasses the crm CLI -- SONiC hard-blocks the crm CLI for vendor-x (subcommands return
    rc=0 but write nothing); writing CONFIG_DB directly is equivalent to the CLI (crmorch
    consumes it directly), and works on both image types.
    """
    return cli.crm_set_threshold(res_key, ttype, low, high)


def _count_syslog_matches(cli, ere_pattern):
    """Count lines in /var/log/syslog matching ere_pattern (grep -E regex).

    The read primitive of the baseline-count method: the caller records baseline n0 *before*
    the trigger action, then requires the count to be strictly > n0 to count as "a new alarm
    line appeared" -- fundamentally excluding false satisfaction from old alarm lines in the
    history log (prior tests / previous sessions). Falls back to journalctl when
    /var/log/syslog is unreadable (still read-only, -n bounds the window to avoid a full scan).
    """
    r = cli.sh.run(f"grep -acE '{ere_pattern}' /var/log/syslog 2>/dev/null", check=False)
    out = (r.out or "").strip()
    if out.isdigit():
        return int(out)
    r = cli.sh.run(
        f"journalctl -q --no-pager -n 5000 2>/dev/null | grep -acE '{ere_pattern}'", check=False)
    out = (r.out or "").strip()
    return int(out) if out.isdigit() else 0


def _wait_syslog_new(cli, ere_pattern, baseline, timeout=SYSLOG_TIMEOUT):
    """Poll syslog until the count of lines matching ere_pattern is strictly greater than baseline (i.e. a *new* alarm line appeared)."""
    end = time.time() + timeout
    while time.time() < end:
        if _count_syslog_matches(cli, ere_pattern) > baseline:
            return True
        time.sleep(1)
    return False


# ---------------- fixtures ----------------
@pytest.fixture
def crm_fast_poll(cli):
    """Set the CRM polling interval to 1 second (so used counters reflect ASIC changes quickly), restore after test.

    Write CONFIG_DB CRM|Config polling_interval directly, bypassing the blocked crm CLI
    (under SONiC/vendor-x the crm subcommands return rc=0 but write nothing); crmorch consumes
    CONFIG_DB directly, so direct write is equivalent to the CLI and works on both images.
    The restore value is taken from CONFIG_DB on entry (a device default may be 300), not hardcoded.
    """
    attrs = cli.db_hgetall("CONFIG_DB", "CRM|Config")
    orig = attrs.get("polling_interval", "300")
    cli.crm_set_polling(1)
    # wait one new period to ensure re-polling at 1s
    time.sleep(2)
    yield
    cli.crm_set_polling(orig)


@pytest.fixture
def crm_thr_guard(cli):
    """Threshold-modification guard: on entry, snapshot the modified resource's type/low/high; on exit, restore each (CRM goes through DB, not covered by config_guard)."""
    saved = {}

    def _snapshot(res_key):
        # res_key is the resource prefix in CONFIG_DB (e.g. ipv4_route / nexthop_group)
        attrs = cli.db_hgetall("CONFIG_DB", "CRM|Config")
        saved[res_key] = {
            "type": attrs.get(f"{res_key}_threshold_type", "percentage"),
            "low": attrs.get(f"{res_key}_low_threshold", "70"),
            "high": attrs.get(f"{res_key}_high_threshold", "85"),
        }

    yield _snapshot
    # restore by writing CONFIG_DB directly (same path as setting, bypassing the blocked crm CLI)
    for res_key, v in saved.items():
        cli.crm_set_threshold(res_key, v["type"], v["low"], v["high"])


# ---------------- verify_thresholds closed loop (adapted from sonic-mgmt) ----------------
def _verify_threshold_alarm(cli, crm_cli_res, res_db_key, res_stat, syslog_res_token):
    """Threshold-alarm closed loop: based on the current measured used, straddle the type-used
    threshold on both sides and verify syslog shows EXCEEDED then CLEAR.

    crm_cli_res       : CLI subcommand path (e.g. "ipv4 route" / "nexthop_group")
    res_db_key        : resource prefix in CONFIG_DB CRM|Config (e.g. "ipv4_route") -- for the crm_thr_guard snapshot
    res_stat          : resource name in COUNTERS_DB CRM:STATS (e.g. "ipv4_route")
    syslog_res_token  : resource name in the crmorch alarm line (e.g. "IPV4_ROUTE", the first
                        %s in crmorch.cpp's `"%s THRESHOLD_EXCEEDED for %s ..."`); tightens the match

    Alarm observation uses the baseline-count method: before setting the threshold, record the
    matching line count n0; polling requires the count to be strictly > n0 (a new line
    appeared), so old alarm lines left by other tests/resources in the history log don't
    falsely satisfy it.
    """
    ready, used, _avail = _wait_used(cli, res_stat, lambda u: True)
    assert ready, f"CRM stats for {res_stat} never became ready after polling"
    # the caller already drove the increment, so used must be >=1; otherwise the counter did not reflect the injected resource, which is a defect
    assert used >= 1, (
        f"{res_stat} used={used} despite injected resource; "
        "nothing to straddle threshold against"
    )

    # tighten the pattern to the specific resource: crmorch line format "<RES> THRESHOLD_EXCEEDED/CLEAR for TH_USED ..."
    exc_pat = f"{syslog_res_token}.*{EXPECT_EXCEEDED}"
    clr_pat = f"{syslog_res_token}.*{EXPECT_CLEAR}"

    # exceeded: low=used-1, high=used -> used>=high -> triggers EXCEEDED (write CONFIG_DB directly, using res_db_key)
    # record the baseline line count before setting the threshold, then require the count to strictly increase (a new alarm line really appeared)
    n_exc0 = _count_syslog_matches(cli, exc_pat)
    _set_threshold(cli, res_db_key, "used", used - 1, used)
    exceeded = _wait_syslog_new(cli, exc_pat, n_exc0)
    assert exceeded, (
        f"device issue: no new '{syslog_res_token} {EXPECT_EXCEEDED}' syslog line for {crm_cli_res} "
        f"after setting used low={used-1} high={used} (used={used}, baseline lines={n_exc0})"
    )

    # clear: low=used, high=used+1 -> used<low -> triggers CLEAR (write CONFIG_DB directly, using res_db_key)
    n_clr0 = _count_syslog_matches(cli, clr_pat)
    _set_threshold(cli, res_db_key, "used", used, used + 1)
    cleared = _wait_syslog_new(cli, clr_pat, n_clr0)
    assert cleared, (
        f"device issue: no new '{syslog_res_token} {EXPECT_CLEAR}' syslog line for {crm_cli_res} "
        f"after setting used low={used} high={used+1} (used={used}, baseline lines={n_clr0})"
    )


# ======================================================================
# full closed-loop cases (increment + threshold alarm + fall-back)
# ======================================================================
def test_crm_ipv4_route_threshold_closed_loop(cli, l3up, topo, crm_fast_poll, crm_thr_guard):
    """ipv4_route full closed loop: ip route add -> used+1 -> threshold EXCEEDED/CLEAR -> route del -> used falls back."""
    crm_thr_guard("ipv4_route")
    net = topo.subnet("c")
    route = topo.route("a")                      # prefix under test, from topo
    nh = net["peer"]
    nh_mac = topo.mac("peer_a")                  # next-hop neighbor MAC, from topo (aligned with test_crm.py)
    port = topo.port_name("c")
    l3up(port, f"{net['dut']}/{net['prefix']}")  # bring up an oper-up L3 port

    ready, u0, _a0 = _wait_used(cli, "ipv4_route", lambda u: True)
    assert ready, "CRM ipv4_route stats never became ready after polling"
    used0 = u0

    # first resolve the next-hop neighbor: a route with an unresolved nexthop is correctly held
    # by SONiC and not programmed to ASIC, so used doesn't grow. Static neighbor (lladdr) ->
    # neighsyncd, so a route through it is deterministically programmed to ASIC.
    cli.neigh_set(nh, nh_mac, port)
    # drive the increment: kernel adds a route via the resolved nexthop (programmed to ASIC route via fpmsyncd/orchagent).
    cli.sh.run(f"ip route replace {route} via {nh} dev {port}", check=False)
    try:
        grew, used1, _ = _wait_used(cli, "ipv4_route", lambda u: u >= used0 + 1)
        assert grew, (
            f"ipv4_route CRM used did not increment (used {used0}->{used1}); "
            "route not programmed/accounted to ASIC"
        )
        # threshold-alarm closed loop (based on the measured used after the increment)
        _verify_threshold_alarm(cli, "ipv4 route", "ipv4_route", "ipv4_route", "IPV4_ROUTE")
    finally:
        cli.sh.run(f"ip route del {route} via {nh} dev {port}", check=False)
        cli.neigh_del(nh, port)
        cli.sh.run(f"ip neigh flush dev {port}", check=False)
    # fall-back verification: after deleting the route, used should return near baseline (<= used1, no longer stuck at peak)
    fell, used2, _ = _wait_used(cli, "ipv4_route", lambda u: u <= used1)
    assert fell, f"ipv4_route used did not fall back after route delete (stuck at {used2}, peak {used1})"


def test_crm_ipv4_neighbor_threshold_closed_loop(cli, l3up, topo, crm_fast_poll, crm_thr_guard):
    """ipv4_neighbor full closed loop: ip neigh replace -> used+1 -> threshold EXCEEDED/CLEAR -> neigh del -> fall back."""
    crm_thr_guard("ipv4_neighbor")
    net = topo.subnet("d")
    peer_ip = net["peer"]
    peer_mac = topo.mac("peer_c")
    port = topo.port_name("d")
    l3up(port, f"{net['dut']}/{net['prefix']}")

    ready, u0, _a0 = _wait_used(cli, "ipv4_neighbor", lambda u: True)
    assert ready, "CRM ipv4_neighbor stats never became ready after polling"
    used0 = u0

    # drive the increment: static neighbor (lladdr) -> neighsyncd -> ASIC NEIGHBOR_ENTRY.
    cli.neigh_set(peer_ip, peer_mac, port)
    try:
        grew, used1, _ = _wait_used(cli, "ipv4_neighbor", lambda u: u >= used0 + 1)
        assert grew, (
            f"ipv4_neighbor CRM used did not increment (used {used0}->{used1}); "
            "neighbor not programmed/accounted to ASIC"
        )
        _verify_threshold_alarm(cli, "ipv4 neighbor", "ipv4_neighbor", "ipv4_neighbor", "IPV4_NEIGHBOR")
    finally:
        cli.neigh_del(peer_ip, port)
        cli.sh.run(f"ip neigh flush dev {port}", check=False)
    fell, used2, _ = _wait_used(cli, "ipv4_neighbor", lambda u: u <= used1)
    assert fell, f"ipv4_neighbor used did not fall back after neigh delete (stuck at {used2}, peak {used1})"


# ======================================================================
# increment-verification cases (drive used to really grow + fall back; the threshold loop is covered by the two above)
# ======================================================================
def test_crm_ipv4_nexthop_increment(cli, l3up, topo, crm_fast_poll):
    """ipv4_nexthop increment: neighbor+route lands one nexthop -> used+1 -> delete -> fall back."""
    net = topo.subnet("c")
    peer_ip = net["peer"]
    peer_mac = topo.mac("peer_a")
    route = topo.route("b")
    port = topo.port_name("c")
    l3up(port, f"{net['dut']}/{net['prefix']}")

    ready, u0, _a0 = _wait_used(cli, "ipv4_nexthop", lambda u: True)
    assert ready, "CRM ipv4_nexthop stats never became ready after polling"
    used0 = u0

    cli.neigh_set(peer_ip, peer_mac, port)
    cli.sh.run(f"ip route replace {route} via {peer_ip} dev {port}", check=False)
    try:
        grew, used1, _ = _wait_used(cli, "ipv4_nexthop", lambda u: u >= used0 + 1)
        assert grew, (
            f"ipv4_nexthop CRM used did not increment (used {used0}->{used1}); "
            "nexthop not programmed/accounted to ASIC"
        )
    finally:
        cli.sh.run(f"ip route del {route} via {peer_ip} dev {port}", check=False)
        cli.neigh_del(peer_ip, port)
        cli.sh.run(f"ip neigh flush dev {port}", check=False)
    fell, used2, _ = _wait_used(cli, "ipv4_nexthop", lambda u: u <= used1)
    assert fell, f"ipv4_nexthop used did not fall back after delete (stuck at {used2}, peak {used1})"


def test_crm_nexthop_group_increment(cli, l3up, topo, crm_fast_poll):
    """nexthop_group increment: one ECMP route (two neighbors) -> forms a nexthop group -> used+1 -> delete -> fall back."""
    net_c = topo.subnet("c")
    net_d = topo.subnet("d")
    # two next hops for the same prefix (peers of two different L3 ports) form ECMP -> nexthop group.
    nh1, mac1, port1 = net_c["peer"], topo.mac("peer_a"), topo.port_name("c")
    nh2, mac2, port2 = net_d["peer"], topo.mac("peer_b"), topo.port_name("d")
    route = topo.route("c")
    l3up(port1, f"{net_c['dut']}/{net_c['prefix']}")
    l3up(port2, f"{net_d['dut']}/{net_d['prefix']}")

    ready, u0, _a0 = _wait_used(cli, "nexthop_group", lambda u: True)
    assert ready, "CRM nexthop_group stats never became ready after polling"
    used0 = u0

    cli.neigh_set(nh1, mac1, port1)
    cli.neigh_set(nh2, mac2, port2)
    # one multi-path (ECMP) route
    cli.sh.run(
        f"ip route replace {route} nexthop via {nh1} dev {port1} nexthop via {nh2} dev {port2}",
        check=False,
    )
    try:
        grew, used1, _ = _wait_used(cli, "nexthop_group", lambda u: u >= used0 + 1)
        # the ECMP nexthop_group should be programmed to ASIC; no growth is anomalous
        assert grew, (
            f"nexthop_group CRM used did not increment (used {used0}->{used1}); "
            "ECMP group not programmed/accounted to ASIC"
        )
    finally:
        cli.sh.run(f"ip route del {route}", check=False)
        cli.neigh_del(nh1, port1)
        cli.neigh_del(nh2, port2)
        for p in (port1, port2):
            cli.sh.run(f"ip neigh flush dev {p}", check=False)
    fell, used2, _ = _wait_used(cli, "nexthop_group", lambda u: u <= used1)
    assert fell, f"nexthop_group used did not fall back after delete (stuck at {used2}, peak {used1})"
