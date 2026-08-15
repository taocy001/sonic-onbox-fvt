"""Statistics inventory gap-fill: **live-traffic testing** of three counter classes -- frame-size/anomalous-frame distribution, derived rates, and protocol traps. An objective inventory of "which SAI_*_STAT_* fields the whole suite has ever asserted on" found that, beyond the basic queue/port counters, six counter classes have **zero coverage** (grep across the whole repo finds no reference):

    ETHER_STATS_* (frame-size distribution / anomalous frames), RATES:* (derived rates), trap counters (FLOW_CNT_TRAP),
    LAG counters, TUNNEL counters, PFCWD counters

This file fills the first three -- all verifiable with real traffic on the existing loopback rig. Current status of the latter three and why they are skipped:
  - LAG counters: require actually building a PortChannel and driving traffic through member ports, which belongs
    to test_lag_chip's scenarios; a counter dimension should be added there rather than standing up a separate
    aggregation-group orchestration here;
  - TUNNEL counters: this image does not include vxlan (declared in profiles caps), so there is nothing to verify;
  - PFCWD counters: only take a non-zero value once a PFC deadlock is created, which the loopback rig cannot
    produce -- this belongs to the traffic-generator domain.
All three are honestly registered as coverage gaps, rather than padded out with weak "the command didn't crash" cases.
"""
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.traffic]

try:
    from scapy.all import Ether, IP, UDP, ARP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 300
_DST = "00:aa:bb:cc:dd:e7"
_SRC = "00:de:ad:be:ef:e7"


def _pstat(cli, oid, field):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get(field)
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else None


def _port_oid(cli, name):
    return cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {name}")


# ============================ Frame-size distribution / anomalous frames ============================
_SIZE_BUCKETS = [
    ("SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS", 64),
    ("SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS", 100),
    ("SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS", 200),
    ("SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS", 400),
    ("SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS", 800),
]


def test_cc1_frame_size_buckets_count_the_right_bucket(cli, traffic, l2_fwd_vlan):
    """CC1 frame-size distribution counters count the **right bucket**: send frames of a given length, and only the matching length bucket should advance.

    Why this is worth verifying separately: this counter group is the first-hand evidence for diagnosing "what
    frames the peer is actually sending" (small-packet storms, fragments, anomalous lengths), and its most common
    failure is not "doesn't advance" but "advances in the wrong bucket" -- the bucket boundaries differ by a byte
    (whether FCS/preamble is included) across chips, and once wrong, every frame-length-based judgment is skewed.

    Criteria: inject N frames of the target length, the target bucket advances >= N/2, and it must be the bucket
    that advances the most. Other buckets are not required to stay constant (background BUM/protocol frames keep moving)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    oid = _port_oid(cli, p_in.name)
    if not oid:
        pytest.skip(f"no port oid for {p_in.name}")
    avail = [(f, sz) for f, sz in _SIZE_BUCKETS if _pstat(cli, oid, f) is not None]
    if len(avail) < 2:
        pytest.skip(f"port {p_in.name} exposes fewer than 2 ETHER_IN_PKTS_* size "
                    f"buckets (have {[f for f, _ in avail]}); frame-size distribution "
                    f"not sampled on this image")
    # Pick a middle bucket, avoiding 64B (lots of background protocol frames)
    target_field, target_size = avail[len(avail) // 2]
    pad = max(0, target_size - 14 - 20 - 8 - 4)      # eth+ip+udp+fcs
    base = {f: (_pstat(cli, oid, f) or 0) for f, _ in avail}
    cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
    try:
        pkt = Ether(dst=_DST, src=_SRC) / IP(dst="6.6.6.6") / UDP() / Raw(b"z" * pad)
        traffic.send(p_in, pkt, count=_N)
        grew = {}
        for _ in range(15):
            time.sleep(1)
            grew = {f: (_pstat(cli, oid, f) or 0) - base[f] for f, _ in avail}
            if grew.get(target_field, 0) >= _N * 0.5:
                break
    finally:
        cli.fdb_static_del(l2_fwd_vlan, _DST)
    got = grew.get(target_field, 0)
    assert got >= _N * 0.5, (
        f"sent {_N} frames of ~{target_size}B into {p_in.name} but the matching size "
        f"bucket {target_field} only advanced by {got} (all buckets: {grew}); frame "
        f"size distribution counters are not tracking real traffic")
    top = max(grew, key=grew.get)
    assert top == target_field, (
        f"frames of ~{target_size}B were counted mostly in {top} (+{grew[top]}) "
        f"instead of {target_field} (+{got}); the size-bucket boundaries are off "
        f"(FCS/preamble inclusion differs from what the counter names imply) — every "
        f"frame-length based diagnosis on this box would be misleading. all={grew}")


def test_cc2_oversize_frames_are_counted(cli, dut, traffic, config_guard,
                                         l2_fwd_vlan):
    """CC2 oversize frames must be counted in the anomalous-frame statistics (`ETHER_STATS_OVERSIZE_PKTS` or RX_ERR).

    "Statistics say oversize" and "actually dropped or not" need not agree; the statistics themselves must be
    accurate, otherwise you cannot even detect the divergence.

    This only verifies "oversize frames are counted", not "whether they are dropped" (drop behavior belongs to test_storm_mtu_chip)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    oid = _port_oid(cli, p_in.name)
    if not oid:
        pytest.skip(f"no port oid for {p_in.name}")
    fields = ["SAI_PORT_STAT_ETHER_STATS_OVERSIZE_PKTS",
              "SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS",
              "SAI_PORT_STAT_IF_IN_ERRORS"]
    avail = [f for f in fields if _pstat(cli, oid, f) is not None]
    if not avail:
        pytest.skip(f"port {p_in.name} exposes none of {fields}; oversize accounting "
                    f"not sampled on this image")
    mtu = int((cli.db_hgetall("CONFIG_DB", f"PORT|{p_in.name}") or {}).get("mtu", 9100))
    rc, r = cli.config_raw(f"interface mtu {p_in.name} 1500")
    if rc != 0:
        pytest.skip(f"cannot lower MTU on {p_in.name} to build an oversize frame: "
                    f"{((r.out or '') + (r.err or ''))[-140:]}")
    config_guard.defer_undo(f"interface mtu {p_in.name} {mtu}")
    time.sleep(2)
    base = {f: (_pstat(cli, oid, f) or 0) for f in avail}
    cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
    try:
        # A frame clearly over 1500; scapy sends directly to the netdev, the kernel does no MTU trimming (the frame re-enters the chip via loopback)
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="6.6.6.7") / UDP()
               / Raw(b"O" * 1800))
        traffic.send(p_in, pkt, count=_N // 3)
        grew = {}
        for _ in range(15):
            time.sleep(1)
            grew = {f: (_pstat(cli, oid, f) or 0) - base[f] for f in avail}
            if any(v > 0 for v in grew.values()):
                break
    finally:
        cli.fdb_static_del(l2_fwd_vlan, _DST)
    assert any(v > 0 for v in grew.values()), (
        f"injected {_N // 3} frames of ~1842B into {p_in.name} with MTU set to 1500, "
        f"and not one oversize/error counter moved (deltas={grew}). Over-MTU frames "
        f"are invisible in statistics on this box — a peer sending jumbo into a "
        f"1500B port would look perfectly healthy while its traffic disappears.")


# ============================ Derived rates ============================
def test_cc3_rate_table_populated_under_sustained_traffic(cli, traffic,
                                                          l2_fwd_vlan):
    """CC3 `RATES:PORT` derived rates must be non-zero under sustained traffic.

    A rate is not a chip counter; it is computed by orchagent periodically differencing the counters. It fails
    differently from a counter: the counter advances while the rate stays at 0 (the diff thread died / the period
    is misconfigured / the previous sample point was not saved). Operations dashboards, alarm thresholds, and
    `portstat`'s RX_BPS column all consume this table directly -- a stuck 0 means every "bandwidth utilization"
    monitor is fake, and nothing on the counter side reveals it."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    oid = _port_oid(cli, p_in.name)
    if not oid:
        pytest.skip(f"no port oid for {p_in.name}")
    rate_keys = cli.db_keys("COUNTERS_DB", "RATES:*") or []
    if not rate_keys:
        pytest.skip("no RATES:* table in COUNTERS_DB (rate derivation not enabled)")
    row = cli.db_hgetall("COUNTERS_DB", f"RATES:{oid}") or {}
    if not row:
        pytest.skip(f"no RATES row for {p_in.name} (oid={oid}); rate derivation does "
                    f"not cover this port")
    cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
    try:
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="6.6.6.8") / UDP()
               / Raw(b"R" * 900))
        seen = {}
        # A rate is only computable if traffic is "sustained": send several rounds, leaving time for the diff period between rounds
        for _ in range(8):
            traffic.send(p_in, pkt, count=_N)
            time.sleep(2)
            row = cli.db_hgetall("COUNTERS_DB", f"RATES:{oid}") or {}
            seen = {k: v for k, v in row.items()
                    if str(v).replace(".", "", 1).isdigit() and float(v) > 0}
            if seen:
                break
    finally:
        cli.fdb_static_del(l2_fwd_vlan, _DST)
    assert seen, (
        f"RATES:{oid} ({p_in.name}) stayed all-zero through 8 rounds of sustained "
        f"injection (row={row}). Byte/packet counters advance but the derived rate "
        f"never does — every bandwidth-utilisation view (portstat RX_BPS, dashboards, "
        f"rate-based alarms) reads zero on a busy port, and nothing in the raw "
        f"counters hints at it.")


# ============================ Protocol trap counters ============================
def test_cc4_trap_counters_advance_on_protocol_traffic(cli, traffic, l2_fwd_vlan):
    """CC4 protocol-punt counters (FLOW_CNT_TRAP) increment with real protocol packets.

    The CoPP batch of cases verifies "whether packets are punted to the CPU" and "whether the policer tier is
    right", but **how many** were punted is verified by no one. Trap counters are the only quantitative basis for
    judging that the control plane is under attack (which protocol is flooding, whether policing actually engaged);
    without them CoPP's runtime observability is zero.

    Inject ARP requests (every vendor's trap table has arp). If the image has not enabled FLOW_CNT_TRAP or that
    trap is not modeled, skip honestly with an explanation."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    g = cli.db_hgetall("CONFIG_DB", "FLEX_COUNTER_TABLE|FLOW_CNT_TRAP") or {}
    if (g.get("FLEX_COUNTER_STATUS") or "").lower() != "enable":
        pytest.skip(f"FLOW_CNT_TRAP counter group not enabled ({g}); trap counting "
                    f"is off on this image")
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_TRAP_NAME_MAP") or {}
    if not m:
        pytest.skip("COUNTERS_TRAP_NAME_MAP empty: the group is enabled but no trap "
                    "was ever registered (same registration-gap class as "
                    "test_counter_infra.py CI1)")
    p_in = traffic.ports[0]
    base = {t: (_pstat(cli, o, "SAI_HOSTIF_TRAP_STAT_PACKETS") or 0)
            for t, o in m.items()}
    pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=_SRC)
           / ARP(op=1, psrc="10.199.0.2", pdst="10.199.0.1"))
    traffic.send(p_in, pkt, count=_N // 2)
    grew = {}
    for _ in range(15):
        time.sleep(1)
        grew = {t: (_pstat(cli, o, "SAI_HOSTIF_TRAP_STAT_PACKETS") or 0) - base[t]
                for t, o in m.items()}
        if any(v > 0 for v in grew.values()):
            break
    moved = {t: v for t, v in grew.items() if v > 0}
    assert moved, (
        f"no trap counter advanced after injecting {_N // 2} ARP requests into "
        f"{p_in.name} (traps={list(m)[:8]}, deltas all zero). Control-plane punting "
        f"is unmeasurable: there is no way to tell which protocol is flooding the CPU "
        f"or whether CoPP policing is actually engaging.")
