"""Full config-plane vs chip-plane buffer/QoS reconciliation primitives.

Shared by `tests/test_scale_consistency_chip.py` (read-only reconciliation round) and
`tests/test_scenario_fullscale_roce.py` (self-check immediately after full-scale config) --
one set of criteria, so the two don't each carry a private copy that drifts apart.

Each audit_* returns `(missing, checked)`:
  missing -- reproducible list of object description strings that exist in the config
             plane but are absent (or mismatched) on the chip plane;
  checked -- number of objects that actually had a criterion to check (bindings with no
             chip-observable footprint are not counted, to avoid false greens).
The caller is responsible for the assertion and its wording.
"""
import re


def int0(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def expand_idx(idx_expr):
    """Index segment "3" / "0-2" -> [3] / [0,1,2]."""
    s = str(idx_expr).strip()
    if "-" in s:
        a, _, b = s.partition("-")
        if a.isdigit() and b.isdigit():
            return list(range(int(a), int(b) + 1))
        return []
    return [int(s)] if s.isdigit() else []


def profiles(cli):
    return {k.split("|", 1)[1]: (cli.db_hgetall("CONFIG_DB", k) or {})
            for k in cli.db_keys("CONFIG_DB", "BUFFER_PROFILE|*") or []}


def wred_profiles(cli):
    return {k.split("|", 1)[1]: (cli.db_hgetall("CONFIG_DB", k) or {})
            for k in cli.db_keys("CONFIG_DB", "WRED_PROFILE|*") or []}


def schedulers(cli):
    return {k.split("|", 1)[1]: (cli.db_hgetall("CONFIG_DB", k) or {})
            for k in cli.db_keys("CONFIG_DB", "SCHEDULER|*") or []}


def ref_name(v):
    """A CONFIG_DB reference value may be "[BUFFER_PROFILE|x]" or a bare name; strip to the bare name."""
    return (v or "").strip("[]").split("|")[-1]


def binding_rows(cli, table, field="profile"):
    """[(port, index, value)], index ranges expanded, EthernetN ports only."""
    rows = []
    for k in cli.db_keys("CONFIG_DB", f"{table}|*") or []:
        parts = k.split("|")
        if len(parts) < 3 or not re.match(r"Ethernet\d+$", parts[1]):
            continue
        val = ref_name((cli.db_hgetall("CONFIG_DB", k) or {}).get(field))
        if not val:
            continue
        for i in expand_idx(parts[2]):
            rows.append((parts[1], i, val))
    return rows


def pid_map(chip, cli, ports, timeout=5):
    """Port name -> chip PORT_ID. Unresolvable ones are listed separately, not misreported as "not programmed"."""
    ok, bad = {}, []
    for p in sorted(ports):
        try:
            ok[p] = chip.port_id(p, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            bad.append((p, str(e)[:60]))
    return ok, bad


def config_ports(cli):
    return {k.split("|", 1)[1]
            for k in cli.db_keys("CONFIG_DB", "PORT|Ethernet*") or []}


def _index(entries, pid_field, idx_field):
    """(PORT_ID, index) -> entry. Only for tables where the key is unique."""
    out = {}
    for e in entries:
        pid, idx = e.get(pid_field), e.get(idx_field)
        if pid is not None and idx is not None:
            out[(pid, idx)] = e
    return out


def _index_multi(entries, pid_field, idx_field):
    """(PORT_ID, index) -> [entry, ...], keeping ALL entries that share a key.

    TM_SCHEDULER_NODE must use this: its (PORT_ID, TM_SCHEDULER_NODE_ID) is not unique --
    the same queue has one entry at each level of the scheduling tree (L0/L1/L2_SCHED_NODE).
    A unique index would be overwritten by the last one, but the weight lives on only one
    of those levels, so every port gets falsely reported as a "weight=1 want 80" failure."""
    out = {}
    for e in entries:
        pid, idx = e.get(pid_field), e.get(idx_field)
        if pid is not None and idx is not None:
            out.setdefault((pid, idx), []).append(e)
    return out


# ============================ the five audits ============================
def audit_pg_headroom(cli, chip, pid):
    """Lossless PG binding -> TM_ING_THD_PORT_PRI_GRP.HEADROOM_LIMIT_CELLS."""
    profs = profiles(cli)
    ents = _index(chip.traverse("TM_ING_THD_PORT_PRI_GRP"), "PORT_ID", "TM_PRI_GRP_ID")
    missing, checked = [], 0
    for port, idx, prof in binding_rows(cli, "BUFFER_PG"):
        if port not in pid:
            continue
        xoff = int0((profs.get(prof) or {}).get("xoff"))
        if xoff <= 0:
            continue
        checked += 1
        ent = ents.get((pid[port], idx))
        got = int0((ent or {}).get("HEADROOM_LIMIT_CELLS"))
        want = chip.cells(xoff)
        if not ent or got == 0:
            missing.append(f"{port}/pg{idx}(not programmed)")
        elif abs(got - want) > 2:
            missing.append(f"{port}/pg{idx}({got}c want~{want}c)")
    return missing, checked


def audit_queue_thresholds(cli, chip, pid):
    """Egress queue buffer binding -> TM_THD_UC_Q static/min thresholds."""
    if not chip.has_table("TM_THD_UC_Q"):
        return [], 0
    profs = profiles(cli)
    ents = _index(chip.traverse("TM_THD_UC_Q"), "PORT_ID", "TM_UC_Q_ID")
    missing, checked = [], 0
    for port, idx, prof in binding_rows(cli, "BUFFER_QUEUE"):
        if port not in pid:
            continue
        p = profs.get(prof) or {}
        st, mn = int0(p.get("static_th")), int0(p.get("size"))
        if st <= 0 and mn <= 0:
            continue                      # pure-alpha type: no distinctive chip footprint
        checked += 1
        ent = ents.get((pid[port], idx))
        if not ent:
            missing.append(f"{port}/q{idx}(no entry)")
            continue
        if st > 0:
            got, want = int0(ent.get("SHARED_LIMIT_CELLS_STATIC")), chip.cells(st)
            if abs(got - want) > 2:
                missing.append(f"{port}/q{idx}(static {got}c want~{want}c)")
        else:
            got, want = int0(ent.get("MIN_GUARANTEE_CELLS")), chip.cells(mn)
            if abs(got - want) > 2:
                missing.append(f"{port}/q{idx}(min {got}c want~{want}c)")
    return missing, checked


def audit_queue_schedulers(cli, chip, pid):
    """Queue scheduler binding -> TM_SCHEDULER_NODE WEIGHT / SCHED_MODE.

    DWRR checks WEIGHT only: the chip SCHED_MODE has only SP/RR values, and both WRR and
    DRR show up as RR, so "seeing RR" does not mean weighting failed to take effect. A
    weight of 1 is indistinguishable from the default and is not counted as a criterion."""
    sched = schedulers(cli)
    ents = _index_multi(chip.traverse("TM_SCHEDULER_NODE"),
                        "PORT_ID", "TM_SCHEDULER_NODE_ID")
    missing, checked = [], 0
    for port, idx, name in binding_rows(cli, "QUEUE", field="scheduler"):
        if port not in pid:
            continue
        s = sched.get(name) or {}
        stype, weight = (s.get("type") or "").upper(), int0(s.get("weight"))
        if stype not in ("DWRR", "STRICT") or (stype == "DWRR" and weight <= 1):
            continue
        checked += 1
        rows = ents.get((pid[port], idx)) or []
        if not rows:
            missing.append(f"{port}/q{idx}(no node)")
            continue
        # Multiple scheduling-tree levels share one key and the parameter lands on only
        # one of them: a hit on any level counts as programmed.
        if stype == "STRICT":
            ok = any(str(e.get("SCHED_MODE")) == "SP" for e in rows)
            got = [str(e.get("SCHED_MODE")) for e in rows]
        else:
            ok = any(int0(e.get("WEIGHT")) == weight for e in rows)
            got = [e.get("WEIGHT") for e in rows]
        if not ok:
            want = "SP" if stype == "STRICT" else weight
            missing.append(f"{port}/q{idx}({got} want {want})")
    return missing, checked


def audit_wred(cli, chip, pid):
    """Queue wred_profile binding -> TM_WRED_UC_Q.ECN."""
    if not chip.has_table("TM_WRED_UC_Q"):
        return [], 0
    wp = wred_profiles(cli)
    ents = _index(chip.traverse("TM_WRED_UC_Q"), "PORT_ID", "TM_UC_Q_ID")
    missing, checked = [], 0
    for port, idx, name in binding_rows(cli, "QUEUE", field="wred_profile"):
        if port not in pid:
            continue
        checked += 1
        ent = ents.get((pid[port], idx))
        if not ent:
            missing.append(f"{port}/q{idx}(no entry)")
            continue
        if "ecn_none" not in (wp.get(name, {}).get("ecn", "") or "").lower() \
                and int0(ent.get("ECN")) != 1:
            missing.append(f"{port}/q{idx}(ECN={ent.get('ECN')})")
    return missing, checked


def audit_pfc(cli, chip, pid):
    """PORT_QOS_MAP.pfc_enable -> PC_PFC ENABLE_TX / ENABLE_RX."""
    if not chip.has_table("PC_PFC"):
        return [], 0
    ents = {e.get("PORT_ID"): e for e in chip.traverse("PC_PFC")
            if e.get("PORT_ID") is not None}
    missing, checked = [], 0
    for k in cli.db_keys("CONFIG_DB", "PORT_QOS_MAP|Ethernet*") or []:
        port = k.split("|", 1)[1]
        if port not in pid:
            continue
        if not ((cli.db_hgetall("CONFIG_DB", k) or {}).get("pfc_enable") or "").strip():
            continue
        checked += 1
        e = ents.get(pid[port])
        if not e:
            missing.append(f"{port}(no PC_PFC entry)")
        elif int0(e.get("ENABLE_TX")) != 1 or int0(e.get("ENABLE_RX")) != 1:
            missing.append(f"{port}(tx={e.get('ENABLE_TX')},rx={e.get('ENABLE_RX')})")
    return missing, checked


AUDITS = (
    ("lossless PG headroom", audit_pg_headroom),
    ("egress queue thresholds", audit_queue_thresholds),
    ("queue schedulers", audit_queue_schedulers),
    ("queue WRED/ECN", audit_wred),
    ("port PFC enable", audit_pfc),
)


def report(kind, missing, checked, show=8, extra=""):
    return (
        f"{len(missing)}/{checked} {kind} present in CONFIG_DB were NOT programmed "
        f"to the chip: {missing[:show]}"
        + (f" (+{len(missing) - show} more)" if len(missing) > show else "")
        + ". Config plane accepted every one of them — this is the silent "
          "bulk-config event-loss class. "
        + extra)
