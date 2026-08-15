"""Counter **infrastructure liveness** -- the pre-flight checkup for every statistics case. A possible failure mode:
    every group in FLEX_COUNTER_TABLE is enabled, the corresponding GROUP_TABLE in FLEX_COUNTER_DB is present too,
    `COUNTERS_PORT_NAME_MAP` has entries, but `COUNTERS_QUEUE_NAME_MAP` /
    `COUNTERS_PG_NAME_MAP` have 0 entries, the whole COUNTERS_DB is nearly empty,
    `show queue counters` prints an empty table, and `portstat` is all N/A.
That is: **statistics fail wholesale while the config plane is all green**, with no error at all.

In this state every statistics case skips or fails for its own reason, looking like a pile of scattered issues,
when it is really one root cause (flex counter registration never completed). So there must be a dedicated set of cases
watching the infrastructure itself, deciding once and for all whether "statistics work at all"; only then do the downstream statistics cases mean anything.

Three tiers of criteria, tightening layer by layer:
  CI1 registration: every enabled counter group must have NAME_MAP entries, with coverage proportional to the port count;
  CI2 collection: each oid in a NAME_MAP must actually have a COUNTERS:<oid> row carrying that class's SAI_*_STAT_* fields;
  CI3 advance: inject real traffic, port counters must move -- the first two tiers may have "rows and fields but always 0".
"""
import re
import time

import pytest

pytestmark = [pytest.mark.counters]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 300
_DST = "00:aa:bb:cc:dd:1f"
_SRC = "00:de:ad:be:ef:1f"

# group name -> (NAME_MAP, this class's counter-field prefix, expected entries per port; None=not scaled by port count)
_GROUPS = {
    "PORT":                  ("COUNTERS_PORT_NAME_MAP", "SAI_PORT_STAT_", 1),
    "QUEUE":                 ("COUNTERS_QUEUE_NAME_MAP", "SAI_QUEUE_STAT_", None),
    "QUEUE_WATERMARK":       ("COUNTERS_QUEUE_NAME_MAP", "SAI_QUEUE_STAT_", None),
    "PG_WATERMARK":          ("COUNTERS_PG_NAME_MAP",
                              "SAI_INGRESS_PRIORITY_GROUP_STAT_", None),
    "PG_DROP":               ("COUNTERS_PG_NAME_MAP",
                              "SAI_INGRESS_PRIORITY_GROUP_STAT_", None),
    "BUFFER_POOL_WATERMARK": ("COUNTERS_BUFFER_POOL_NAME_MAP",
                              "SAI_BUFFER_POOL_STAT_", None),
    "RIF":                   ("COUNTERS_RIF_NAME_MAP",
                              "SAI_ROUTER_INTERFACE_STAT_", None),
}


def _enabled_groups(cli):
    out = []
    for k in cli.db_keys("CONFIG_DB", "FLEX_COUNTER_TABLE|*") or []:
        g = k.split("|", 1)[1]
        h = cli.db_hgetall("CONFIG_DB", k) or {}
        if (h.get("FLEX_COUNTER_STATUS") or "").lower() == "enable":
            out.append(g)
    return out


def _eth_ports(cli):
    return [k.split("|", 1)[1] for k in cli.db_keys("CONFIG_DB", "PORT|Ethernet*") or []
            if re.match(r"Ethernet\d+$", k.split("|", 1)[1])]


def _stat(cli, oid, field):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get(field)
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else None


# ============================ CI1 registration ============================
def test_ci1_enabled_counter_groups_have_name_map(cli):
    """CI1 every enabled flex counter group must have a non-empty NAME_MAP.

    A group enabled with an empty NAME_MAP = that class of statistics is **entirely unreadable**: no oid means no entry point,
    and upstream `show queue counters` / telemetry / SNMP all get nothing. This is invisible on the config plane
    (both CONFIG_DB and FLEX_COUNTER_DB show everything as fine).

    The RIF group is special: with no L3 interfaces an empty NAME_MAP is normal, so only judge it when a RIF exists."""
    enabled = _enabled_groups(cli)
    if not enabled:
        pytest.skip("no flex counter group enabled in CONFIG_DB")
    has_rif = bool(cli.db_keys("CONFIG_DB", "INTERFACE|*") or
                   cli.db_keys("CONFIG_DB", "VLAN_INTERFACE|*"))
    empty, seen = [], 0
    for g in enabled:
        spec = _GROUPS.get(g)
        if not spec:
            continue                     # ACL/PFCWD/TRAP etc. have their own cases
        name_map, _prefix, _per = spec
        if g == "RIF" and not has_rif:
            continue
        seen += 1
        n = len(cli.db_hgetall("COUNTERS_DB", name_map) or {})
        if n == 0:
            empty.append(f"{g}({name_map})")
    if not seen:
        pytest.skip("none of the tracked counter groups is enabled")
    assert not empty, (
        f"{len(empty)}/{seen} enabled counter groups have an EMPTY name map: {empty}. "
        f"The group is enabled in CONFIG_DB and its FLEX_COUNTER_GROUP_TABLE exists, "
        f"but no object was ever registered — every consumer (show/telemetry/SNMP) "
        f"reads nothing. Root-cause the flex counter registration path, not the "
        f"individual statistics tests that fail downstream of it.")


def test_ci2_queue_and_pg_maps_cover_every_port(cli):
    """CI2 coverage: the queue/PG NAME_MAP must cover **every** Ethernet port, not just some of them.

    Partial coverage is more insidious than fully empty: a sampling check most likely hits a port that has counters, so "statistics look fine",
    while in the field a few ports' queue counters are always 0. The criterion is deliberately loose -- it only requires each port to have at least one `<port>:<n>`
    entry, not a full set of queues (queue count varies by SKU)."""
    ports = _eth_ports(cli)
    if not ports:
        pytest.skip("no Ethernet ports in CONFIG_DB")
    missing = {}
    for label, name_map in (("queue", "COUNTERS_QUEUE_NAME_MAP"),
                            ("PG", "COUNTERS_PG_NAME_MAP")):
        m = cli.db_hgetall("COUNTERS_DB", name_map) or {}
        if not m:
            continue                     # fully empty is judged by CI1, not re-reported here
        covered = {k.split(":")[0] for k in m if ":" in k}
        gap = sorted(set(ports) - covered)
        if gap:
            missing[label] = gap
    if not missing:
        maps = {lbl: len(cli.db_hgetall("COUNTERS_DB", nm) or {})
                for lbl, nm in (("queue", "COUNTERS_QUEUE_NAME_MAP"),
                                ("PG", "COUNTERS_PG_NAME_MAP"))}
        if not any(maps.values()):
            pytest.skip(f"queue/PG name maps both empty (CI1 covers that): {maps}")
    assert not missing, (
        "counter name maps do not cover every port: "
        + "; ".join(f"{lbl} missing {len(g)}/{len(ports)} ports e.g. {g[:6]}"
                    for lbl, g in missing.items())
        + ". Those ports have no readable queue/PG statistics at all, while their "
          "neighbours do — sampling-based checks will not notice.")


# ============================ CI2 collection ============================
def test_ci3_registered_oids_have_counter_rows(cli):
    """CI3 registered is not enough, it must actually be collected: each oid in a NAME_MAP must have a `COUNTERS:<oid>` row,
    and the row must carry that class's `SAI_*_STAT_*` fields.

    A NAME_MAP with no counter row = orchagent registered the object but flexcounter never sampled it,
    reading back as an empty dict -- upstream this shows as `show` printing an empty table or all N/A."""
    checked, bad = 0, []
    for g, (name_map, prefix, _per) in _GROUPS.items():
        m = cli.db_hgetall("COUNTERS_DB", name_map) or {}
        if not m:
            continue
        # sampling the first 5 oids per class is enough to tell "whether it is being collected"; no need for a full scan (slow at 256 ports)
        for key, oid in list(m.items())[:5]:
            checked += 1
            row = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
            if not row:
                bad.append(f"{g}:{key}(no COUNTERS row)")
            elif not any(f.startswith(prefix) for f in row):
                bad.append(f"{g}:{key}(row has no {prefix}* field)")
    if not checked:
        pytest.skip("no registered counter object to sample (see CI1)")
    assert not bad, (
        f"{len(bad)}/{checked} registered counter objects carry no sampled data: "
        f"{bad[:8]}. The object is in the name map but flexcounter never wrote a "
        f"row for it — consumers get an empty result rather than a zero.")


# ============================ CI3 advance (traffic measurement) ============================
@pytest.mark.traffic
def test_ci4_port_counters_advance_on_traffic(cli, traffic, l2_fwd_vlan):
    """CI4 **traffic measurement**: after injecting real traffic, the SAI port counters on the injection port must advance.

    The first three passing but this one failing = the counter rows exist with full fields but values are always 0 (collection thread died / sampling
    cycle not running / oid mapped to the wrong port). This is the final gate against "statistics look fine but are actually dead".

    Only the port layer is judged (the most basic class); the traffic cases for queue/PG/pool live in
    test_stats_full.py / test_buffer_stats_traffic.py / test_counters_chip.py."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {p_in.name}")
    if not oid:
        pytest.skip(f"no port oid for {p_in.name} (CI1 covers the registration gap)")
    fields = ["SAI_PORT_STAT_IF_IN_UCAST_PKTS", "SAI_PORT_STAT_IF_IN_OCTETS",
              "SAI_PORT_STAT_IF_OUT_UCAST_PKTS", "SAI_PORT_STAT_IF_OUT_OCTETS"]
    base = {f: _stat(cli, oid, f) for f in fields}
    absent = [f for f, v in base.items() if v is None]
    if len(absent) == len(fields):
        pytest.fail(
            f"DEVICE DEFECT: port {p_in.name} (oid={oid}) has none of the basic SAI "
            f"port counters in COUNTERS_DB ({fields}); the PORT flex counter group "
            f"is enabled but nothing is sampled")
    cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
    try:
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="4.4.4.4") / UDP()
               / Raw(b"CI4" + b"x" * 200))
        traffic.send(p_in, pkt, count=_N)
        grew = {}
        for _ in range(15):              # port counter polling is ~1s by default, leave plenty of margin
            time.sleep(1)
            grew = {f: (_stat(cli, oid, f) or 0) - (base[f] or 0)
                    for f in fields if base[f] is not None}
            if any(v > 0 for v in grew.values()):
                break
    finally:
        cli.fdb_static_del(l2_fwd_vlan, _DST)
    assert any(v > 0 for v in grew.values()), (
        f"no SAI port counter on {p_in.name} advanced after injecting {_N} frames "
        f"(deltas={grew}). The counter rows exist and carry the fields, but the "
        f"values are frozen — flexcounter is registered yet not sampling. Cross-check "
        f"with the chip MIB counters (`bcmcmd 'show c'`): if the chip counted the "
        f"frames and COUNTERS_DB did not, the break is in syncd's flex counter "
        f"polling, not in the data path.")
