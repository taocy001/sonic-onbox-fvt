"""Full port traffic counter set: RX/TX_OK, ERR, DRP, broadcast/multicast/unicast classification, frame-length buckets, utilization.

show interfaces counters output + COUNTERS_DB SAI fields + chip counters growing with traffic.
"""
import time

import pytest

pytestmark = [pytest.mark.counters]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

# Injection volume and per-test dedicated DSTs (distinct MAC per test to avoid static FDB del/add races)
_N = 200
# Storm guard (consistent with test_counters_chip): lower bound catches under-counting, upper bound
# traps runaway self-looping storms -- an "increment is enough" assertion with no upper bound would
# PASS under a flooding storm too, i.e. a fake pass.
_STORM_GUARD = 3000
_FIELDS_DST = "00:aa:bb:cc:dd:53"
_CLEAR_DST = "00:aa:bb:cc:dd:54"
_SHOW_DST = "00:aa:bb:cc:dd:55"

SAI_FIELDS = [
    "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
    "SAI_PORT_STAT_IF_IN_ERRORS",
    "SAI_PORT_STAT_IF_IN_DISCARDS",
    "SAI_PORT_STAT_IF_OUT_DISCARDS",
    "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS",
    "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS",
    "SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS",
    "SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS",
]


def _chip_rx_accum(traffic, p, pkt, n, clear=True, deadline=8.0):
    """Chip RX delta measurement: polled accumulation + confirmation read (on both DUTs `show c`
    was measured to have "change since last show" semantics, so the old before/after diff
    under-counts / produces a bogus delta).
    With clear=True, first call traffic.clear_chip_counters() (= ChipCounters.clear; in parallel
    mode only clears this worker's port block); tests that also do SAI/show before-after in the same
    measurement window must pass clear=False -- a chip-level clear zeroes and wraps the SAI readback,
    destroying the SAI baseline (observed on 155/158), so instead do one read up front to drain the
    "since last show" backlog window."""
    if clear:
        traffic.clear_chip_counters()
    else:
        traffic.chip_counters(p)   # drain read: resets the observation window of the delta semantics
    traffic.send(p, pkt, count=n)
    total, end = 0, time.time() + deadline
    while total < n and time.time() < end:
        time.sleep(0.4)
        total += traffic.chip_counters(p).rx_pkt
    time.sleep(0.4)
    total += traffic.chip_counters(p).rx_pkt   # confirmation read: catches late DMA and slow storms
    return total


@pytest.mark.traffic
def test_show_interfaces_counters_columns(cli, traffic):
    """`show interfaces counters` column headers exist + real traffic reaches the chip (binary assertion, no xfail).

    On the already-looped ports[0], inject N known unicast frames (dst static FDB points to ports[1],
    deterministic unicast forwarding with no storm); the chip RX delta (clear -> accumulate + confirm,
    dual bounds) is hard evidence that real traffic reached the hardware.
    Division of labor: that the show values advance with traffic is verified by test_clear_counters
    (needs sonic-clear to rebuild the snapshot baseline, immune to chip-clear wraparound); the SAI
    COUNTERS_DB delta is verified by test_counters_db_sai_fields_exist and
    test_counters_chip.test_sai_port_counter_exact -- the original premise that "an oper-down loopback
    port is not sampled by the flex counter" has been disproven by measurement, so this test keeps only
    its two core jobs: column headers + chip evidence."""
    out = cli.run("show interfaces counters").out
    assert "Traceback" not in out, "show interfaces counters crashed"
    for col in ("RX_OK", "TX_OK", "RX_ERR", "RX_DRP"):
        assert col in out, f"counter column {col} missing"
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p = traffic.ports[0]
    cli.fdb_static_add(traffic.default_vlan, _SHOW_DST, traffic.ports[1].name)
    try:
        pkt = (Ether(dst=_SHOW_DST, src="00:de:ad:be:ef:55") /
               IP(dst="9.9.9.5") / UDP() / Raw(b"SHOW" + b"x" * 50))
        chip_rx = _chip_rx_accum(traffic, p, pkt, _N)
        # Hard evidence: real traffic re-enters this port via loopback, so chip RX must grow with it
        # and not run away (dual bounds guard against a storm fake-pass)
        assert _N * 0.9 <= chip_rx < _N + _STORM_GUARD, (
            f"chip RX delta out of bounds on {p.name}: +{chip_rx}, sent {_N} "
            f"(expected [{_N * 0.9:.0f}, {_N + _STORM_GUARD}))")
    finally:
        cli.fdb_static_del(traffic.default_vlan, _SHOW_DST)


@pytest.mark.traffic
def test_counters_db_sai_fields_exist(cli, traffic, topo):
    """COUNTERS_DB port counters: verify each SAI field exists + SAI IF_IN_UCAST_PKTS delta truly follows the injected volume.

    The original version only verified field existence + chip corroboration, on the premise that "an
    oper-down loopback port is not sampled by the flex counter" -- that premise has been disproven by
    the same test suite (test_counters_chip.test_sai_port_counter_exact's exact +N, and
    test_clear_counters's show RX_OK advancement), so this is upgraded to a behavioral assertion:
    inject N known unicast frames (dst static FDB points to ports[1], deterministic unicast forwarding
    with no storm), and the SAI IF_IN_UCAST_PKTS delta should land in [0.9N, N+guard). A SAI delta
    >=0.9N is itself strong evidence that "traffic reached the chip and was sampled by the flex
    counter"; the original chip RX corroboration is subsumed by it (and a chip clear in the same window
    would zero and wrap the SAI readback, destroying the baseline), so it is removed."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p = traffic.ports[0]
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {p.name}")
    if not oid:
        pytest.skip("no COUNTERS oid (flex counter not ready)")
    h0 = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    present = [f for f in SAI_FIELDS if f in h0]
    assert len(present) >= 5, f"too few port SAI counter fields: only {present}"
    ucast = "SAI_PORT_STAT_IF_IN_UCAST_PKTS"
    assert ucast in h0, f"{ucast} missing from COUNTERS:{oid} (port flex counter group broken)"

    cli.fdb_static_add(traffic.default_vlan, _FIELDS_DST, traffic.ports[1].name)
    try:
        # Take a fresh baseline before injecting (SAI raw values are cumulative, so before/after diff
        # is correct; do not chip-clear)
        base = int(cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}").get(ucast, 0))
        pkt = (Ether(dst=_FIELDS_DST, src="00:de:ad:be:ef:53") /
               IP(dst="9.9.9.9") / UDP() / Raw(b"PCNT" + b"x" * 50))
        traffic.send(p, pkt, count=_N)
        d = 0
        for _ in range(15):   # flex counter poll ~1s + sync delay
            time.sleep(1)
            d = int(cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}").get(ucast, 0)) - base
            if d >= _N * 0.9:
                break
        time.sleep(1)
        d = int(cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}").get(ucast, 0)) - base  # confirmation read
        assert _N * 0.9 <= d < _N + _STORM_GUARD, (
            f"SAI {ucast} delta out of bounds on {p.name}: +{d}, sent {_N} "
            f"(expected [{_N * 0.9:.0f}, {_N + _STORM_GUARD}); "
            "low=flex counter not sampling injected traffic, high=flood storm)")
    finally:
        cli.fdb_static_del(traffic.default_vlan, _FIELDS_DST)


@pytest.mark.traffic
def test_broadcast_counter_increments(cli, traffic, topo):
    """Broadcast frames grow the broadcast classification counter (SAI_PORT_STAT_IF_IN_BROADCAST_PKTS) -- not just total RX.

    The old assertion only checked d.rx_pkt (total RX), which unicast frames satisfy too -> it can't
    prove broadcast classification. Here we read COUNTERS_DB's dedicated IN_BROADCAST counter: inject N
    broadcast frames on the already-looped ports[0] (re-entering this port's ingress via MAC loopback),
    let the chip RX delta corroborate that traffic reached the hardware, then poll the IN_BROADCAST
    delta. On a looped port the flex counter was measured to sample accurately (the original
    "oper-down not sampled" premise has been disproven), so we assert the dedicated broadcast counter
    increments directly, no longer xfail; the only retained skip is an env guard for an unready
    COUNTERS oid / broadcast field."""
    pytest.importorskip("scapy.all")   # dry-run/build host without scapy -> skip rather than ERROR
    from scapy.all import Ether, IP, UDP, Raw
    p = traffic.ports[0]
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {p.name}")
    if not oid:
        pytest.skip("no COUNTERS oid (flex counter not ready)")
    field = "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS"
    ucast = "SAI_PORT_STAT_IF_IN_UCAST_PKTS"
    h0 = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    if field not in h0:
        pytest.skip(f"{field} not in COUNTERS:{oid} (broadcast counter group disabled)")
    base = int(h0.get(field, 0))
    # Cross-classification negative-control baseline: broadcast frames must never be counted as unicast
    # (a wrong-bucket counter can also fool an "increment is enough" check)
    u0 = int(h0.get(ucast, 0)) if ucast in h0 else None

    n = 100
    pkt = Ether(dst=topo.mac("bcast"), src=topo.mac("src")) / IP() / UDP() / Raw(b"x" * 40)
    # Chip corroboration uses drain read + accumulate + confirm (clear=False: SAI before/after runs in
    # the same window, and a chip clear would zero and wrap the SAI readback, destroying the base/u0
    # baseline)
    chip_rx = _chip_rx_accum(traffic, p, pkt, n, clear=False)
    # Hard evidence: broadcast frames re-enter this port via loopback, so chip RX must grow with it
    # (independent of the flex counter)
    assert chip_rx >= n * 0.9, (
        f"broadcast traffic did not reach chip on {p.name}: chip RX +{chip_rx}, sent {n}")
    delta = 0
    for _ in range(12):
        time.sleep(1)
        cur = int(cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}").get(field, 0))
        delta = cur - base
        if delta >= n * 0.9:
            break
    time.sleep(1)
    h1 = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")   # confirmation read: a slow storm breaching the upper bound -> honest failure
    delta = int(h1.get(field, 0)) - base
    # Dual bounds: broadcast is a classic storm seed, and an assertion with no upper bound PASSes even
    # under a storm (fake pass)
    assert n * 0.9 <= delta < n + _STORM_GUARD, (
        f"broadcast classification counter {field} delta {delta} out of bounds on {p.name} "
        f"(sent {n} broadcast frames, chip RX +{chip_rx}; expected [{n * 0.9:.0f}, {n + _STORM_GUARD}))")
    # Negative control: this batch of frames should not advance the unicast classification bucket
    # (tolerate <0.2N of background unicast noise)
    if u0 is not None:
        u_delta = int(h1.get(ucast, 0)) - u0
        assert u_delta < n * 0.2, (
            f"broadcast frames misclassified as unicast on {p.name}: {ucast} +{u_delta} "
            f"during {n}-frame broadcast burst (expected < {n * 0.2:.0f})")


def _show_rxtx(cli, port_name):
    """From `show interfaces counters`, take the larger of a port's RX_OK/TX_OK (stripping thousands commas); None if absent.

    Parse raw lines rather than parse_table: some images prepend a "Last cached time was ..." line
    that shifts the header alignment and breaks whole-table parsing (row present, values read as None,
    observed). Locate the RX_OK/TX_OK column indices by header, then take the matching token from the
    port's row."""
    out = cli.run("show interfaces counters").out or ""
    header, row = None, None
    for ln in out.splitlines():
        toks = ln.split()
        if not toks:
            continue
        if "RX_OK" in toks and "TX_OK" in toks:
            header = toks
        elif toks[0] == port_name:
            row = toks
    if not header or not row:
        return None
    vals = []
    for col in ("RX_OK", "TX_OK"):
        try:
            v = row[header.index(col)].replace(",", "")
        except (ValueError, IndexError):
            continue
        if v.lstrip("-").isdigit():
            vals.append(int(v))
    return max(vals) if vals else None


@pytest.mark.traffic
def test_clear_counters(cli, traffic):
    """`sonic-clear counters` resets the show-interfaces-counters display baseline (true reset semantics).

    Sequence: first sonic-clear rebuilds the display snapshot to the current values, then inject real
    traffic (chip RX delta proves traffic reached the hardware), poll show until the delta before>0,
    then after another sonic-clear the display should fall back (after<=before).
    That opening clear is not optional: the framework's chip-level `clear c` (from smoke/other tests)
    zeroes the hardware counters, so the SAI readback wraps to a smaller value; if the stale snapshot
    is kept (larger than the current cumulative value), the show diff is stuck at 0 (the root cause of
    COUNTERS_DB going +200 while show stays 0). After rebuilding the baseline this test is immune to
    the wraparound."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p = traffic.ports[0]
    # Diagnostic evidence chain: gather the COUNTERS_DB raw cumulative value (whether the flex counter
    # samples) and the show display value (snapshot-diff semantics) separately
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {p.name}")

    def _db_in_ucast():
        if not oid:
            return None
        v = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}").get("SAI_PORT_STAT_IF_IN_UCAST_PKTS")
        return int(v) if v and v.lstrip("-").isdigit() else None

    r0 = cli.run("sonic-clear counters")
    assert r0.rc == 0 or "Clear" in r0.out or r0.out == "", "sonic-clear counters (baseline) failed"
    db_base = _db_in_ucast()
    cli.fdb_static_add(traffic.default_vlan, _CLEAR_DST, traffic.ports[1].name)
    try:
        pkt = (Ether(dst=_CLEAR_DST, src="00:de:ad:be:ef:54") /
               IP(dst="9.9.9.4") / UDP() / Raw(b"CLR" + b"x" * 50))
        # clear=False: this test does show/COUNTERS_DB before/after throughout, and a chip clear would
        # zero and wrap the SAI readback, destroying the db_base/show snapshot baseline (exactly the
        # wraparound mechanism described in this test's opening comment)
        chip_rx = _chip_rx_accum(traffic, p, pkt, _N, clear=False)
        assert chip_rx >= _N * 0.9, (
            f"traffic did not reach chip on {p.name}: chip RX +{chip_rx}, sent {_N}")
    finally:
        cli.fdb_static_del(traffic.default_vlan, _CLEAR_DST)

    # Let the flex counter fold the traffic into the display (PORT_STAT poll period 3s + sync delay,
    # poll until nonzero)
    # _show_rxtx returns a single int (larger of RX/TX) or None
    before = None
    for _ in range(12):
        time.sleep(1.5)
        before = _show_rxtx(cli, p.name)
        if before is not None and before > 0:
            break
    db_now = _db_in_ucast()
    db_delta = (db_now - db_base) if (db_now is not None and db_base is not None) else None
    r = cli.run("sonic-clear counters")
    assert r.rc == 0 or "Clear" in r.out or r.out == "", "sonic-clear counters failed"
    assert before, (
        f"show interfaces counters reports {before} for {p.name} after {_N} frames; "
        f"COUNTERS_DB IN_UCAST delta={db_delta} (base={db_base}, now={db_now}) -- "
        "delta>0 means flex counter sampled but show/snapshot layer lost it; "
        "delta==0 means flex counter did not sample the loopback traffic")
    time.sleep(2)
    after = _show_rxtx(cli, p.name)
    assert after is not None, (
        f"show interfaces counters has no row for {p.name} after clear")
    # True-reset assertion: after clear the display value must collapse to near zero (only ~2s of
    # background traffic remains). The old assertion after<=before also holds on a silent link for an
    # image where "clear is a no-op" (after==before passes) -- a fake pass.
    reset_floor = max(before * 0.1, 10)
    assert after <= reset_floor, (
        f"sonic-clear counters did not reset {p.name}: before={before}, after={after} "
        f"(expected <= {reset_floor:.0f}; an equality-only check would fake-pass a no-op clear)")
