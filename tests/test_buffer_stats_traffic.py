"""**Live-traffic testing** of PG (ingress priority group) and buffer pool statistics -- filling a spot in the
statistics dimension that has long had only weak "watermark ticks once" coverage.

Inventory: among the SAI statistics fields the whole suite has asserted on, the PG side has only one spot each
for `SHARED_WATERMARK_BYTES` and `XOFF_ROOM_WATERMARK_BYTES`, and the pool side only one for
`WATERMARK_BYTES`, all merely "it went up". This means:
  - PG **throughput** statistics (PACKETS/BYTES) have zero coverage -- nobody knows if they break;
  - PG **drop** statistics (DROPPED_PACKETS) have zero coverage -- yet ingress drop is exactly the first scene
    of the crime when lossless is misconfigured (see the attribution criteria in test_congestion_chip.py CG9);
  - the pool's **real-time occupancy** (CURR_OCCUPANCY_BYTES) has zero coverage -- only the peak was verified.

This file pins these down on a "send real traffic -> counters must move" basis. The congestion-related ones (PG
drop, xoff room, pool occupancy peak) live in test_congestion_chip.py CG10, which has a ready low-rate congestion rig.

Ports use the traffic fixture (ports[0] is already looped back): the frame egresses ports[0] physically and
returns to the pipeline, so **the PG counters are recorded on ports[0]**, the same mechanism as the existing PG watermark cases.
"""
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.qos, pytest.mark.traffic]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 400
_PAYLOAD = 200
_DST = "00:aa:bb:cc:dd:b5"
_SRC = "00:de:ad:be:ef:b5"

_PG_PKTS = "SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"
_PG_BYTES = "SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES"
_POOL_WM = "SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"
_POOL_OCC = "SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"


def _stat(cli, oid, field):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get(field)
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else None


def _pg_oids(cli, port):
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PG_NAME_MAP") or {}
    return {k: v for k, v in m.items() if k.startswith(port + ":")}


def _sum_delta(cli, oids, field, base):
    tot = 0
    for oid in oids:
        cur = _stat(cli, oid, field)
        if cur is not None and base.get(oid) is not None:
            tot += cur - base[oid]
    return tot


def test_bs1_pg_packet_and_byte_counters_advance(cli, traffic, l2_fwd_vlan):
    """BS1 PG **throughput** statistics increment with real traffic: after injecting N frames, the sum of
    `..._STAT_PACKETS` across all PGs of the ingress port advances by at least half of N, and `..._STAT_BYTES` advances in step.

    Why judge only the "sum" rather than pin a specific PG: which PG a frame lands in depends on the
    DSCP/PCP -> TC -> PG mapping, which varies with each image's default maps; this case verifies that "PG-layer
    counting is working", while the specific landing spot is the responsibility of test_qos_pfcmaps_chip / test_qos_remark_chip.

    Packets and bytes must be judged together: only the packet count moving while bytes stay still (or vice versa)
    is a classic flexcounter field mismapping that looking at a single field would not catch."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    cand = _pg_oids(cli, p_in.name)
    if not cand:
        pytest.skip(f"no PG oid for {p_in.name} in COUNTERS_PG_NAME_MAP "
                    f"(registration gap — see test_counter_infra.py CI1)")
    oids = list(cand.values())
    if all(_stat(cli, o, _PG_PKTS) is None for o in oids):
        pytest.skip(f"{_PG_PKTS} not sampled on any PG of {p_in.name}; the PG "
                    f"counter group does not collect throughput")
    base_p = {o: _stat(cli, o, _PG_PKTS) for o in oids}
    base_b = {o: _stat(cli, o, _PG_BYTES) for o in oids}
    cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
    try:
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="5.5.5.5") / UDP()
               / Raw(b"BS1" + b"x" * _PAYLOAD))
        traffic.send(p_in, pkt, count=_N)
        d_pkts = d_bytes = 0
        for _ in range(15):
            time.sleep(1)
            d_pkts = _sum_delta(cli, oids, _PG_PKTS, base_p)
            d_bytes = _sum_delta(cli, oids, _PG_BYTES, base_b)
            if d_pkts >= _N * 0.5:
                break
    finally:
        cli.fdb_static_del(l2_fwd_vlan, _DST)
    assert d_pkts >= _N * 0.5, (
        f"PG packet counters on {p_in.name} advanced by only {d_pkts} after injecting "
        f"{_N} frames (want >= {int(_N * 0.5)}); ingress priority-group throughput "
        f"statistics are not tracking real traffic (per-PG oids={list(cand)[:4]})")
    assert d_bytes > 0, (
        f"PG packet count advanced by {d_pkts} but PG byte count did not move at all "
        f"on {p_in.name}; packets and bytes come from the same counter group, so one "
        f"moving without the other is a field-mapping error in the flex counter, not "
        f"a traffic effect")
    # The bytes/packets ratio should fall in a reasonable range (~250B frames); being off by an order of magnitude means the fields are crossed
    avg = d_bytes / max(d_pkts, 1)
    assert 32 <= avg <= 16384, (
        f"PG bytes/packets ratio is {avg:.1f} (deltas: {d_pkts} pkts / {d_bytes} B) "
        f"for ~{_PAYLOAD + 42}B frames — implausible; the BYTES field is likely "
        f"mapped to a different counter")


def test_bs2_pool_counter_fields_exposed(cli):
    """BS2 buffer pool counter **field exposure** (read-only, no traffic): the registered buffer pool counter rows
    must carry occupancy-class fields, not just a bunch of stuck-at-zero miscellany.

    Why this does not verify "rises with traffic": the repo has long characterized that as a **rig limitation** --
    the loopback port is oper-down, there is no real egress congestion, the pool watermark simply does not move on
    this rig, and forcing an assertion would only produce device-independent false failures. The **behavioral**
    verification of pool counters lives in test_congestion_chip.py CG10 (which has a shaper low-rate congestion rig
    where the pool is really occupied).

    This case guards the other half: whether the fields are present. A known mismatch pattern affects it -- if
    orchagent's watermark counter set does not distinguish pool direction and aims `XOFF_ROOM_WATERMARK` (stat 20)
    at a non-ingress pool, SAI reports `Unsupported buffer pool stat`. syncd maintains only one "supported stat set"
    per pool, and once a stat is judged unsupported, **the other watermark counters in the same group get pulled
    down with it** -- manifesting as missing fields in the pool counter rows. So a missing field is not a minor
    thing; it is the downstream symptom of that mismatch."""
    pools = cli.db_hgetall("COUNTERS_DB", "COUNTERS_BUFFER_POOL_NAME_MAP") or {}
    if not pools:
        pytest.skip("COUNTERS_BUFFER_POOL_NAME_MAP empty (registration gap — "
                    "see test_counter_infra.py CI1)")
    bad = []
    for name, oid in pools.items():
        row = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
        if not row:
            bad.append(f"{name}(no COUNTERS row)")
            continue
        if not any(f in row for f in (_POOL_WM, _POOL_OCC)):
            have = [f for f in row if f.startswith("SAI_BUFFER_POOL_STAT_")]
            bad.append(f"{name}(no occupancy field; has {have[:4]})")
    assert not bad, (
        f"buffer pool counter rows are missing occupancy fields: {bad}. syncd keeps "
        f"ONE supported-stat set per pool, so a single rejected stat "
        f"(`Unsupported buffer pool stat`: XOFF_ROOM_WATERMARK aimed at "
        f"a non-ingress pool) takes the whole watermark group down with it. Without "
        f"these fields there is no runtime view of how much buffer is actually in "
        f"use — capacity planning can only be computed, never verified.")
