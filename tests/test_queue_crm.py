"""Queue/PG/buffer-pool watermark and drop-reason counters -- real-traffic driven, verifying true chip values increment.

The old version only did "show doesn't crash" (no-Traceback) and "CRM used>=0" (trivially-true),
which are fake passes. This version instead does:

  1. test_queue_counters_show -> inject real traffic via MAC loopback and assert that some egress
     queue on the injection port has its SAI_QUEUE_STAT_PACKETS (and watermark field if present)
     truly increment (the chip folded traffic into the queue counter);
  2. test_dropcounters_reason_delta -> install a PORT_INGRESS_DROPS drop counter, inject malformed
     frames that the chip's built-in logic drops, and assert that reason's count truly increments
     (drop attributed to the chip, borrowed from test_counters_chip).

Full CRM resource usage (old test_crm_show_all_resources / test_crm_resource_usage_readable) is
already covered by test_crm_chip.py (used consistent with ASIC object count) and test_crm.py (used
grows linearly with N real resources), so this file no longer duplicates it (delegated/removed) and
focuses on the two chip-value chains: queue/PG/buffer counters and drop-reason.

Queue/PG/buffer flex counters fill per the poll period (default ~10s); unready / this image lacking
the counter group -> a justified pytest.skip, never assert True. Ports/VLANs all come from the
topo / traffic fixtures.
Prints/assert/skip and comments/docstrings in English.
"""
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.traffic]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

# Injection volume. Large enough to visibly lift queue/watermark counters, but not enough to saturate
# the loopback link.
_N = 200
# Destination MAC for queue-egress traffic (distinct from other tests' SMOKE_DST/_QSTAT_DST to avoid
# static FDB del/add races).
_QC_DST = "00:aa:bb:cc:dd:51"
_QC_SRC = "00:de:ad:be:ef:51"


# ============================ [A] Queue/watermark counters increment with real traffic ============================
def _queue_oids(cli, port_name):
    """From COUNTERS_QUEUE_NAME_MAP take {q -> oid} (all queues of the given port)."""
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
    return {int(k.split(":")[1]): v for k, v in m.items()
            if k.startswith(port_name + ":") and k.split(":")[1].isdigit()}


def _stat(cli, oid, field):
    """Read one SAI field (int) of a COUNTERS oid; return None if missing/non-numeric."""
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    v = h.get(field)
    return int(v) if v is not None and str(v).isdigit() else None


def test_queue_counters_show(traffic, cli):
    """Queue counters increment with real traffic: inject N known unicast frames on the already-looped
    ports[0] -- a CPU-injected frame first egresses ports[0] (through its egress queue) then re-enters
    via MAC loopback, so some egress queue on ports[0] should see SAI_QUEUE_STAT_PACKETS increment >=~0.5N.

    This is the full "config -> traffic -> true chip value" chain, replacing the old "show command
    doesn't crash". Queue flex counter not ready -> skip.
    """
    if not _SCAPY:
        # LABEL D: build-host import guard (scapy is only missing on build/dry-run hosts, not a device defect); scapy is available on the DUT
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    cand = _queue_oids(cli, p_in.name)
    if not cand:
        # Verdict aligned with test_qos_remark_chip / test_qos_sched_chip: the same observation (empty
        # queue oid map) FAILs as a device defect in those two, so here we no longer skip to hide it --
        # an empty map means the queue flex-counter / dataplane path is broken.
        pytest.fail(f"DEVICE DEFECT: no queue oid for {p_in.name} in COUNTERS_QUEUE_NAME_MAP "
                    "(live DUT must expose queue flex counters; empty map = broken counter/dataplane path)")

    # dst static FDB points to ports[1], so after the frame re-enters ports[0] it unicast-forwards out
    # (no self-looping storm).
    cli.fdb_static_add(traffic.default_vlan, _QC_DST, p_out.name)
    try:
        base = {q: (_stat(cli, o, "SAI_QUEUE_STAT_PACKETS") or 0) for q, o in cand.items()}
        pkt = (Ether(dst=_QC_DST, src=_QC_SRC) /
               IP(dst="3.3.3.3") / UDP() / Raw(b"QCNT" + b"x" * 50))
        traffic.send(p_in, pkt, count=_N)

        grew = {}
        for _ in range(16):   # queue flex counter poll default ~10s, leave ample headroom
            time.sleep(1)
            cur = {q: (_stat(cli, o, "SAI_QUEUE_STAT_PACKETS") or 0) for q, o in cand.items()}
            grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
            if sum(grew.values()) >= _N * 0.5:
                break
        total = sum(grew.values())
        assert total >= _N * 0.5, (
            f"queue SAI_QUEUE_STAT_PACKETS did not increment on {p_in.name} "
            f"(sent={_N}, per-queue delta={grew}); queue counter not tracking real traffic")
    finally:
        cli.fdb_static_del(traffic.default_vlan, _QC_DST)


def test_pg_watermark_moves_on_traffic(traffic, cli):
    """PG watermark moves with real traffic: after injecting N frames, some PG on the injection port
    should see SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES rise (watermark records peak occupancy).

    A watermark is a peak level, so more injection makes a rise more likely; some images have the PG
    watermark counter group disabled -> skip.
    """
    if not _SCAPY:
        # LABEL D: build-host import guard (scapy is only missing on build/dry-run hosts, not a device defect); scapy is available on the DUT
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    field = "SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"
    pgmap = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PG_NAME_MAP")
    cand = {k: v for k, v in pgmap.items() if k.startswith(p_in.name + ":")}
    if not cand:
        # LABEL D: bench boundary -- loopback-port oper-down side effect yields no PG watermark flex-counter oid, not a device defect
        pytest.skip(f"no PG oid for {p_in.name} (PG watermark flex counter not ready)")
    # Confirm this counter group is actually sampling the field (otherwise the reads below get nothing).
    if not any(_stat(cli, oid, field) is not None for oid in cand.values()):
        # LABEL D: bench boundary -- this PG watermark counter group is not collecting (flex-counter group disabled), not a device defect
        pytest.skip(f"{field} not sampled in any PG of {p_in.name} (PG watermark group disabled)")

    cli.fdb_static_add(traffic.default_vlan, _QC_DST, p_out.name)
    try:
        # A watermark is a peak: clear the watermark before sending, ensuring the rise comes from this
        # injection.
        cli.run("sonic-clear priority-group watermark")
        time.sleep(2)
        base = {oid: (_stat(cli, oid, field) or 0) for oid in cand.values()}
        pkt = (Ether(dst=_QC_DST, src=_QC_SRC) /
               IP(dst="3.3.3.4") / UDP() / Raw(b"PGWM" + b"x" * 200))
        # Send several rounds to raise the instantaneous occupancy so the watermark catches the peak.
        for _ in range(3):
            traffic.send(p_in, pkt, count=_N)
            time.sleep(0.3)

        moved = 0
        for _ in range(16):   # watermark flex counter poll ~10s
            time.sleep(1)
            cur = {oid: (_stat(cli, oid, field) or 0) for oid in cand.values()}
            moved = max((cur[oid] - base[oid]) for oid in cand.values())
            if moved > 0:
                break
        # LABEL A (defaulted, uncertain): after 3*N frames the watermark peak must move; no movement
        # means the counter is not tracking real traffic (could also be a transient-measurement false
        # negative on the loopback bench, but per "uncertain defaults to A/fail" we expose it rather
        # than hide it via xfail)
        assert moved > 0, (
            f"DEVICE DEFECT: PG shared watermark did not move on {p_in.name} after "
            f"{3 * _N} frames (field={field}); PG watermark not tracking real traffic"
        )
    finally:
        cli.fdb_static_del(traffic.default_vlan, _QC_DST)


# ============================ [B] drop-reason counters increment with malformed frames ============================
_DROP_NAME = "QCRM_DROP"
_DROP_REASON = "SMAC_EQUALS_DMAC"   # chip built-in L2 drop
_DROP_SAME_MAC = "00:aa:bb:cc:dd:5d"
_PROGRAM_WAIT = 30
_COUNT_POLL = 20


def _supported_reasons(cli):
    """Read show dropcounters capabilities and take the set of reasons supported by PORT_INGRESS_DROPS."""
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
    """From show dropcounters counts, sum the debug counter named `name` across all ports; return None if the column is absent."""
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


def test_dropcounters_reason_delta(cli, _lb, topo, config_guard):
    """drop-reason counters increment with malformed frames: install a PORT_INGRESS_DROPS=SMAC_EQUALS_DMAC
    drop counter, inject N SMAC==DMAC malformed frames through a dedicated MAC loopback port -> that
    reason's count should increase >=~0.5N (the chip's built-in drop is truly attributed).

    Replaces the old "show dropcounters capabilities doesn't crash". Reason unsupported / install needs
    root / this image doesn't drop such frames by default -> a justified skip or honest xfail, never a
    fake pass. Borrowed from test_counters_chip.test_drop_reason_counter_exact.
    """
    if not _SCAPY:
        # LABEL D: build-host import guard (scapy is only missing on build/dry-run hosts, not a device defect); scapy is available on the DUT
        pytest.skip("scapy unavailable (dry-run/build host)")
    supported = _supported_reasons(cli)
    # Expect PORT_INGRESS_DROPS and SMAC_EQUALS_DMAC to be supported; their absence is a regression defect
    assert supported, (
        "DEVICE DEFECT: no PORT_INGRESS_DROPS reasons reported by "
        "`show dropcounters capabilities`"
    )
    assert _DROP_REASON in supported, (
        f"DEVICE DEFECT: drop reason {_DROP_REASON} not reported as supported "
        f"(have: {sorted(supported)})"
    )

    rc, r = cli.config_raw(
        f"dropcounters install {_DROP_NAME} PORT_INGRESS_DROPS {_DROP_REASON} -d 'dut-test qcrm'")
    out = r.out + r.err
    if rc != 0:
        if "root" in out.lower() or "permission" in out.lower():
            # LABEL D: environment/permission precondition (non-root), not a device defect -- does not trigger when run privileged on the DUT
            pytest.skip(f"dropcounters install needs root: {out.strip()[:120]}")
        # capability already confirmed supported, so a still-failing install is a defect
        assert rc == 0, (
            f"DEVICE DEFECT: dropcounters install failed though {_DROP_REASON} "
            f"is supported: {out.strip()[:120]}"
        )
    config_guard.defer_undo(f"dropcounters delete {_DROP_NAME}")

    # Wait for the name->oid mapping to appear (programmed into syncd/ASIC collection)
    ready = False
    for _ in range(_PROGRAM_WAIT * 2):
        if cli.db_hgetall("COUNTERS_DB", "COUNTERS_DEBUG_NAME_PORT_STAT_MAP").get(_DROP_NAME):
            ready = True
            break
        time.sleep(0.5)
    # An installed counter must be programmed into the name->oid mapping; still absent after polling _PROGRAM_WAIT seconds is a defect
    assert ready, (
        f"DEVICE DEFECT: {_DROP_NAME} installed but never appeared in "
        "COUNTERS_DEBUG_NAME_PORT_STAT_MAP (syncd programming failed)"
    )

    p = topo.misc_port(0)
    _lb.enable(p)   # MAC loopback re-injects CPU-sent malformed frames into the pipeline to trigger the chip's built-in drop
    try:
        base = _drop_counts(cli, _DROP_NAME)
        # A programmed counter must appear in `show dropcounters counts`; a missing column is a defect
        assert base is not None, (
            f"DEVICE DEFECT: {_DROP_NAME} column absent in "
            "`show dropcounters counts` (installed but not populated)"
        )

        pkt = (Ether(dst=_DROP_SAME_MAC, src=_DROP_SAME_MAC) /
               IP(src="1.1.1.1", dst="2.2.2.2") / UDP() / Raw(b"x" * 40))
        from scapy.all import sendp
        sendp(pkt, iface=p.name, count=_N, verbose=False)

        delta = 0
        for _ in range(_COUNT_POLL):
            time.sleep(1)
            cur = _drop_counts(cli, _DROP_NAME)
            if cur is None:
                continue
            delta = cur - base
            if delta >= _N * 0.5:
                break
        # LABEL A (defaulted, uncertain): SMAC_EQUALS_DMAC is a device-supported built-in L2 drop, so a
        # count of 0 after injecting N frames means the chip did not drop/attribute a supported reason
        # (expose it rather than hide via xfail; if it truly is "this drop is disabled by default" that
        # would be by-design, but per "uncertain defaults to A/fail" we treat it as a failure).
        assert delta >= _N * 0.5, (
            f"DEVICE DEFECT: drop-reason counter did not track injected drops: "
            f"{_DROP_REASON} +{delta}, injected {_N} (expected >= {_N * 0.5:.0f}); "
            "chip did not drop/attribute a supported reason"
        )
    finally:
        _lb.disable(p)
