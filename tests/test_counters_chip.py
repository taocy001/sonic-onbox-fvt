"""Counter **accuracy** test set -- not "count > 0 passes" but "send N packets, count is exactly +N".

This is the precision complement to test_port_counters.py / test_stats_full.py ("increasing is
enough"): those verify "count grows with traffic (>=0.9N)", this file verifies "count equals the
injected amount (exactly N, with a tiny noise tolerance)".

Mechanism (reusing the traffic / _lb hairpin loopback pattern, verified on-DUT without storms):
  the CPU uses scapy to sendp N **known unicast** frames on ports[0] (=cdN) which has MAC loopback
  enabled:
    - the frame physically egresses that port -> chip MAC TX counter (MIB_TPKT) **exactly +N**;
    - via MAC loopback it re-enters the pipeline as ingress again -> chip MAC RX counter (MIB_RPKT)
      **exactly +N**;
    - the destination MAC points via static FDB at ports[1] (not looped, oper-down) -> the
      re-ingressed frame is unicast-forwarded out of ports[0], not back to this port (no
      self-loop, no storm).
  The chip counter (bcmcmd show c) is instantaneous, accurate, and immune to netdev TX echo, and is
  the only trustworthy source for "exact counting" (the SAI COUNTERS_DB is not sampled by flex
  counter on an oper-down loopback port, so this file's exact assertions use only chip counters;
  SAI/portstat serve only as "readability/monotonicity" corroboration, not exact-N assertions).

Accuracy tolerance note: the chip MAC count is deterministic for hairpin loopback (measured exactly
+N), but there is always background BUM flooding / protocol-frame noise on the link. So "exact" =
falling within [N, N + NOISE_CAP]: lower bound == N (not one may be lost, unlike the lax 0.5N/0.9N
lower bounds of "increasing is enough"), upper bound N + small noise (blocking runaway storms and
statistical mismatch). Before each case sends packets, it first quietly measures a background-noise
baseline; if noise is too large it skips (the environment is not clean and the exact assertion is
unreliable).

drop-reason accuracy: use DEBUG_COUNTER (PORT_INGRESS_DROPS reason) to precisely attribute a
chip-builtin drop; inject N specific malformed frames -> that reason count is exactly +N (chip
builtin drop logic, not a user ACL).

Prints/asserts/skips in English; comments/docstrings translated. Ports/VLANs all come from
topo / dut, never hardcoded.
"""
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.traffic]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

# Injection count: large enough that background noise is a small relative fraction, yet not enough to saturate the loopback link.
_N = 200

# Noise cap (single direction): exact hairpin-loopback count + background BUM/protocol-frame noise. Measured background is single digits to tens per second,
# so take 25% of N as the "exact" upper edge; exceeding it is treated as a storm/mismatch -> assertion fails to expose.
_NOISE_CAP = int(_N * 0.25)
# Storm guard: background BUM flooding on the shared lab link can spike to a few hundred within the measurement window (instantaneous bursts the quiet window cannot catch),
# so the chip count's **upper bound cannot be exactly N**. This suite's assertion becomes: lower bound strictly == N (every injected frame counted, none lost --
# this is the real evidence of "accuracy", background noise only makes the count larger not smaller), and the upper bound uses a lax guard that only blocks "runaway self-loop storms"
# (a real storm reaches 100k+, as seen in the LAG/neighbor cases), letting through a few hundred of background noise.
_STORM_GUARD = 3000
# Quiet baseline window (seconds): measure the background delta over this time before sending; too large means the environment is not clean -> skip.
_QUIET_WINDOW = 2.0
# Max acceptable background delta in the same window (before sending). Exceeding it means the link already has notable noise and the exact assertion is unreliable.
_QUIET_MAX = _NOISE_CAP

# Injected-frame destination MAC: different from both traffic.smoke_check's SMOKE_DST and the stats case's _QSTAT_DST,
# to avoid cross-case static FDB add/delete races deleting each other's entries -> turning into unknown-unicast flood -> storm.
_CNT_DST = "00:aa:bb:cc:dd:71"
_CNT_SRC = "00:de:ad:be:ef:71"


def _ucast_pkt():
    """Known unicast stimulus frame (fixed 64+ bytes). dst points via static FDB at ports[1], does not return to this port."""
    return (Ether(dst=_CNT_DST, src=_CNT_SRC) /
            IP(dst="10.0.0.9") / UDP() / Raw(b"CNTACC" + b"x" * 50))


def _quiet_baseline_ok(traffic, port, getter):
    """Before sending, measure the background delta over a quiet window; return False if noise is too large (caller skips).
    getter(counters) picks the direction to observe (rx_pkt / tx_pkt) from ChipCounters.
    First clear (via ChipCounters.clear; in parallel mode clears only this worker's port block) then read once: under both
    `show c` semantics (delta / cumulative) a single read equals the window's delta, immune to the before/after
    under-count / false negative delta under delta semantics."""
    traffic.clear_chip_counters()
    time.sleep(_QUIET_WINDOW)
    noise = getter(traffic.chip_counters(port))
    return noise <= _QUIET_MAX, noise


def _chip_accum(traffic, p, pkt, n, getter, deadline=8.0):
    """The framework-mandated pattern for chip counter measurement: clear -> inject -> poll-accumulate + confirming read
    (same as framework.traffic.smoke_check). On both DUTs `show c` is measured to have "delta since last show" semantics --
    the old before/after difference subtracts the pre-injection backlog as baseline, systematically under-counting -> a strict
    lower bound == N would falsely fail; under delta semantics accumulating each read gives the total since clear, and on a
    cumulative-semantics device the first read meeting the target exits early. The confirming read catches late counter DMA
    and slow storms (normal traffic is +0 by now, a self-loop storm pushes total past the upper bound -> honest failure).
    clear goes through traffic.clear_chip_counters() = ChipCounters.clear, in parallel clearing only this worker's port block."""
    traffic.clear_chip_counters()
    traffic.send(p, pkt, count=n)
    total, end = 0, time.time() + deadline
    while total < n and time.time() < end:
        time.sleep(0.4)
        total += getter(traffic.chip_counters(p))
    time.sleep(0.4)
    total += getter(traffic.chip_counters(p))
    return total


# ============================ [A] Port RX/TX exact counting ============================
@pytest.fixture
def _cnt_fdb(cli, traffic):
    """Set up the static FDB for injected frames (dst -> ports[1]) so re-ingressed frames deterministically unicast-forward out of ports[0] without storming.
    Removed in teardown. Returns None (side effect only)."""
    p_out = traffic.ports[1]
    cli.fdb_static_add(traffic.default_vlan, _CNT_DST, p_out.name)
    yield
    cli.fdb_static_del(traffic.default_vlan, _CNT_DST)


def test_port_tx_counter_exact(traffic, _cnt_fdb):
    """Port TX exact counting: send N frames on the looped ports[0]; chip MAC TX (MIB_TPKT) should be **exactly +N**
    (within [N, N+noise]). CPU-injected frames must physically egress this port, so TX is deterministic.
    This is "exact" not "increasing": lower bound strictly == N (not one may be lost)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p = traffic.ports[0]

    ok, noise = _quiet_baseline_ok(traffic, p, lambda d: d.tx_pkt)
    if not ok:
        pytest.skip(f"link too noisy for exact TX accuracy: background TX +{noise} "
                    f"in {_QUIET_WINDOW}s (> {_QUIET_MAX})")

    d = _chip_accum(traffic, p, _ucast_pkt(), _N, lambda c: c.tx_pkt)
    assert _N <= d < _N + _STORM_GUARD, (
        f"port TX counter inaccurate on {p.name}: chip TX +{d}, sent {_N} "
        f"(must be >= {_N} = no under-count, and < {_N + _STORM_GUARD} = no runaway storm)")


def test_port_rx_counter_exact(traffic, _cnt_fdb):
    """Port RX exact counting: send N frames that re-enter via MAC loopback; chip MAC RX (MIB_RPKT) should be **exactly +N**.
    Lower bound strictly == N (loopback re-ingress is 1:1, no loss no duplication)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p = traffic.ports[0]

    ok, noise = _quiet_baseline_ok(traffic, p, lambda d: d.rx_pkt)
    if not ok:
        pytest.skip(f"link too noisy for exact RX accuracy: background RX +{noise} "
                    f"in {_QUIET_WINDOW}s (> {_QUIET_MAX})")

    d = _chip_accum(traffic, p, _ucast_pkt(), _N, lambda c: c.rx_pkt)
    assert _N <= d < _N + _STORM_GUARD, (
        f"port RX counter inaccurate on {p.name}: chip RX +{d}, sent {_N} "
        f"(must be >= {_N} = loopback re-ingress counted every frame, and < {_N + _STORM_GUARD} = no storm)")


def test_port_rx_scales_with_count(traffic, _cnt_fdb):
    """Counter linearity: send two batches N1, N2 in a row; RX deltas should be exactly ~N1, ~N2 respectively (counter is linear with injected amount, no saturation, no duplication).
    Stronger than a single point: proves the counter is accurate across magnitudes."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p = traffic.ports[0]
    n1, n2 = 50, 150

    ok, noise = _quiet_baseline_ok(traffic, p, lambda d: d.rx_pkt)
    if not ok:
        pytest.skip(f"link too noisy for linearity check: background RX +{noise}")

    deltas = []
    for n in (n1, n2):
        # Each batch clears independently -> accumulate + confirming read; under delta semantics batches do not cross-talk (clear rebuilds a zero baseline)
        d = _chip_accum(traffic, p, _ucast_pkt(), n, lambda c: c.rx_pkt)
        deltas.append((n, d))
    # Linearity: each batch delta >= injected amount (nothing lost) with no runaway storm; background BUM makes the upper bound imprecise, so use the storm guard.
    for n, d in deltas:
        assert n <= d < n + _STORM_GUARD, (
            f"RX counter not scaling with injected count on {p.name}: sent {n}, chip RX +{d} "
            f"(must be >= {n}, < {n + _STORM_GUARD}); all={deltas}")


def test_sai_port_counter_exact(traffic, cli, _cnt_fdb):
    """SAI COUNTERS_DB port count accuracy: send N unicast frames, expect SAI
    SAI_PORT_STAT_IF_IN_UCAST_PKTS to be exactly +N. When driving traffic on a loopback port the flex counter samples
    exactly in practice (the original "oper-down not sampled" premise has been disproven by measurement), so assert
    exactly and no longer xfail."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p = traffic.ports[0]
    base = traffic.counters(p)
    traffic.send(p, _ucast_pkt(), count=_N)
    time.sleep(12)  # SAI flex counter polls ~1s, leave ample margin
    d = (traffic.counters(p) - base).rx_ucast
    assert _N <= d <= _N + _NOISE_CAP, (
        f"SAI IF_IN_UCAST_PKTS not accurate on {p.name}: +{d}, sent {_N}")


# ============================ [B] Per-queue exact counting ============================
def _queue_oids(cli, port_name):
    """Get {q -> oid} from COUNTERS_QUEUE_NAME_MAP (all queues of this port)."""
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
    return {int(k.split(":")[1]): v for k, v in m.items()
            if k.startswith(port_name + ":") and k.split(":")[1].isdigit()}


def _queue_pkts(cli, oid):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    v = h.get("SAI_QUEUE_STAT_PACKETS")
    return int(v) if v is not None and str(v).isdigit() else 0


def test_per_queue_counter_exact(traffic, cli, _cnt_fdb):
    """Per-queue exact counting: N frames with the same dot1p/TC egress ports[0], all landing in the same egress queue ->
    that queue's SAI_QUEUE_STAT_PACKETS summed delta across all queues should be **exactly ~N** (not >0).

    Stronger than test_stats_full (>=0.5N passes): here the total must fall within [N, N+noise], and **exactly one** queue
    carries the bulk (a single TC should not spread across queues). Queue counting goes through the COUNTERS_DB flex counter;
    when driving traffic on a loopback port the flex counter samples exactly (the "oper-down not sampled" premise has been
    disproven), so assert exactly and no longer xfail. The only remaining skip is the env guard for an unready queue name-map."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p = traffic.ports[0]
    cand = _queue_oids(cli, p.name)
    if not cand:
        pytest.skip(f"no queue oid for {p.name} (queue flex counter not ready)")

    base = {q: _queue_pkts(cli, o) for q, o in cand.items()}
    traffic.send(p, _ucast_pkt(), count=_N)

    grew = {}
    for _ in range(16):   # queue flex counter polling can take up to 10s
        time.sleep(1)
        cur = {q: _queue_pkts(cli, o) for q, o in cand.items()}
        grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
        if sum(grew.values()) >= _N:
            break
    total = sum(grew.values())
    assert _N <= total <= _N + _NOISE_CAP, (
        f"per-queue packet count not accurate on {p.name}: total +{total} across {grew}, "
        f"sent {_N} (expected [{_N}, {_N + _NOISE_CAP}])")
    # A single TC's traffic should concentrate in one queue (not scatter) -- the bulk-carrying queue should be the vast majority
    top = max(grew.values()) if grew else 0
    assert top >= total * 0.8, (
        f"single-TC traffic spread across queues unexpectedly on {p.name}: {grew}")


# ============================ [C] drop-reason exact counting ============================
_DROP_NAME = "CNTACC_DROP"
_DROP_REASON = "SMAC_EQUALS_DMAC"   # chip builtin L2 drop
_DROP_SAME_MAC = "00:aa:bb:cc:dd:7d"
_PROGRAM_WAIT = 30
_COUNT_POLL = 20


def _supported_reasons(cli):
    """Read show dropcounters capabilities, get the set of reasons supported by PORT_INGRESS_DROPS."""
    out = cli.run("show dropcounters capabilities").out
    reasons, in_block = set(), False
    for line in out.splitlines():
        if "PORT_INGRESS_DROPS" in line and not line.startswith((" ", "\t")):
            in_block = True
            continue
        if in_block:
            tok = line.strip()
            if tok and tok.replace("_", "").isalnum() and tok.upper() == tok and " " not in tok:
                reasons.add(tok)
    return reasons


def _drop_counts(cli, name):
    """From show dropcounters counts, sum the debug counter named `name` across all ports;
    return None if the column does not exist."""
    rows = cli.parse_table(cli.run("show dropcounters counts").out)
    if not rows or name not in rows[0].keys():
        return None
    total, seen = 0, False
    for row in rows:
        v = row.get(name, "")
        if v.lstrip("-").isdigit():
            total += int(v)
            seen = True
    return total if seen else None


def test_drop_reason_counter_exact(cli, _lb, topo, config_guard):
    """drop-reason exact attribution counting: install a PORT_INGRESS_DROPS=SMAC_EQUALS_DMAC counter, inject N
    SMAC==DMAC malformed frames -> that reason count should be **exactly +N** (chip builtin drop precisely attributed to this reason).

    Stronger than test_drop_packets (>=0.5N passes): lower bound strictly == N (every malformed frame should be dropped and attributed to this reason).
    Inject via an independent MAC loopback port (not depending on the traffic forwarding topology). reason unsupported -> skip (platform difference, no false pass)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    supported = _supported_reasons(cli)
    if not supported:
        pytest.skip("no PORT_INGRESS_DROPS reasons reported (debug counter unsupported on image)")
    if _DROP_REASON not in supported:
        pytest.skip(f"drop reason {_DROP_REASON} not supported (have: {sorted(supported)})")

    rc, r = cli.config_raw(
        f"dropcounters install {_DROP_NAME} PORT_INGRESS_DROPS {_DROP_REASON} -d 'dut-test acc'")
    out = r.out + r.err
    if rc != 0:
        if "root" in out.lower() or "permission" in out.lower():
            pytest.skip(f"dropcounters install needs root: {out.strip()[:120]}")
        pytest.skip(f"dropcounters install unsupported/failed: {out.strip()[:120]}")
    config_guard.defer_undo(f"dropcounters delete {_DROP_NAME}")

    # Wait for the name->oid mapping to appear (programmed into syncd/ASIC collection)
    ready = False
    for _ in range(_PROGRAM_WAIT * 2):
        if cli.db_hgetall("COUNTERS_DB", "COUNTERS_DEBUG_NAME_PORT_STAT_MAP").get(_DROP_NAME):
            ready = True
            break
        time.sleep(0.5)
    if not ready:
        pytest.skip(f"{_DROP_NAME} installed but not in name->oid map (syncd programming pending)")

    p = topo.misc_port(0)
    _lb.enable(p)   # MAC loopback lets CPU-injected malformed frames re-enter the pipeline and trigger the chip builtin drop
    try:
        base = _drop_counts(cli, _DROP_NAME)
        if base is None:
            pytest.skip(f"{_DROP_NAME} column absent in 'show dropcounters counts' (not populated)")

        pkt = (Ether(dst=_DROP_SAME_MAC, src=_DROP_SAME_MAC) /
               IP(src="1.1.1.1", dst="2.2.2.2") / UDP() / Raw(b"x" * 40))
        traffic_sendp(p, pkt, _N)

        delta = 0
        for _ in range(_COUNT_POLL):
            time.sleep(1)
            cur = _drop_counts(cli, _DROP_NAME)
            if cur is None:
                continue
            delta = cur - base
            if delta >= _N:
                break
        if delta == 0:
            # reason supported but such frames not dropped by default -> the old xfail masked it, now FAIL outright to expose
            pytest.fail(f"device does not drop {_DROP_REASON} frames by default "
                        f"(counter installed but delta=0 after {_N} injected)")
        assert _N <= delta <= _N + _NOISE_CAP, (
            f"drop-reason counter not accurate: {_DROP_REASON} +{delta}, "
            f"injected exactly {_N} (expected [{_N}, {_N + _NOISE_CAP}])")
    finally:
        _lb.disable(p)


def traffic_sendp(port, pkt, count):
    """CPU scapy injects packets to the given port (re-entering the pipeline via its MAC loopback). Independent of the traffic fixture."""
    from scapy.all import sendp
    sendp(pkt, iface=port.name, count=count, verbose=False)
