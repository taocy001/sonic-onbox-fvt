"""Cross-image helper for QoS map creation/binding.

Background:
- **SONiC's QoS is a product-CLI configuration model** (config dscp-to-tc-map /
  tc-to-queue-map / port-qos-map / buffer profile / scheduler / wred-profile /
  port-queue / ecn / pfcwd), and the hwsku ships no community template
  (buffers.json.j2 etc.) -- `config qos reload` having nothing to render is
  **by that product's design**, not a defect. CLI map creation end-to-end:
  CLI -> CONFIG_DB (TC by **name** BE/AF1..CS7) -> ASIC SAI_QOS_MAP (numeric tc;
  `add` first seeds a 64-entry default table then applies the overrides).
- Community images lack this CLI: QoS relies on the hwsku template pushed by
  `config qos reload`; a missing template is a real defect (fail honestly).

TC name <-> number (dscp 0-7->tc0(BE), 8-15->tc1(AF1), ..., 56-63->tc7(CS7)).
"""
import time

from . import log

_log = log.get("qos")

TC_NAMES = ("BE", "AF1", "AF2", "AF3", "AF4", "EF", "CS6", "CS7")


def tc_num(v):
    """Normalize a TC value to a number: community images store a numeric string,
    SONiC stores a name. Returns None if unparsable."""
    s = str(v).strip()
    if s.lstrip("-").isdigit():
        return int(s)
    try:
        return TC_NAMES.index(s.upper())
    except ValueError:
        return None


def tc_name(n):
    return TC_NAMES[int(n)]


def asic_qos_map_pairs(payload, key_field, val_field):
    """Parse ASIC SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST -> {key:int val:int}.

    sairedis serialization: {"count":N,"list":[{"key":{...},"value":{...}},...]};
    TC_TO_QUEUE's queue field is queue_index in newer versions and qidx in older
    ones, both accepted.
    (Promoted from tests/test_qos_config.py to a shared implementation, reused by
    the pfc three-map / lossless cases.)"""
    import json as _json
    if not payload:
        return {}
    try:
        obj = _json.loads(payload)
    except (ValueError, TypeError):
        return {}
    if not isinstance(obj, dict):
        return {}
    pairs = {}
    for item in obj.get("list", []):
        k, v = item.get("key", {}), item.get("value", {})
        if not isinstance(k, dict) or not isinstance(v, dict):
            continue
        vf = val_field if val_field in v else (
            "qidx" if val_field == "queue_index" and "qidx" in v else val_field)
        if key_field in k and vf in v:
            try:
                pairs[int(k[key_field])] = int(v[vf])
            except (ValueError, TypeError):
                continue
    return pairs


def has_qos_cli(cli):
    """Whether this image has the product-level QoS map-creation CLI (SONiC; cached probe)."""
    if getattr(cli, "_qos_cli", None) is None:
        r = cli.sh.run("config dscp-to-tc-map add --help", check=False)
        cli._qos_cli = (r.rc == 0 and "--dscp" in (r.out or ""))
    return cli._qos_cli


def ensure_default_qos_maps(cli):
    """SONiC self-heal guard: if the product's read-only default QoS maps
    (TC_TO_QUEUE_MAP/DSCP_TO_TC_MAP) get cleared (typical cause = mistakenly running
    `config qos reload` on this image, which only clears and never builds),
    PORT_QOS_MAP's dangling reference makes whole-DB YANG validation fail, and the
    CLI cannot rebuild them ("Default QoS mapping is read-only") -- only a direct
    redis write fixes it. This restores them per product semantics (TC name
    BE..CS7->queue 0..7; DSCP all BE, 46->EF/48->CS6/56->CS7) and warns. No-op on
    non-QoS-CLI images."""
    if not has_qos_cli(cli):
        return
    refs = cli.db_keys("CONFIG_DB", "PORT_QOS_MAP|*")
    if not refs:
        return
    fixed = []
    if not cli.db_hgetall("CONFIG_DB", "TC_TO_QUEUE_MAP|default"):
        args = " ".join(f"{n} {i}" for i, n in enumerate(TC_NAMES))
        cli.sh.run(f"sonic-db-cli CONFIG_DB HSET 'TC_TO_QUEUE_MAP|default' {args}", check=False)
        fixed.append("TC_TO_QUEUE_MAP|default")
    if not cli.db_hgetall("CONFIG_DB", "DSCP_TO_TC_MAP|default"):
        pairs = []
        for d in range(64):
            tc = {46: "EF", 48: "CS6", 56: "CS7"}.get(d, "BE")
            pairs.append(f"{d} {tc}")
        cli.sh.run(f"sonic-db-cli CONFIG_DB HSET 'DSCP_TO_TC_MAP|default' {' '.join(pairs)}",
                   check=False)
        fixed.append("DSCP_TO_TC_MAP|default")
    if fixed:
        _log.warning("restored missing read-only default QoS maps %s (whole-DB YANG "
                     "validation was failing; likely a destructive `config qos reload` on this image)", fixed)


def _unbind_port_qos(cli, port_name):
    """Unbind a port's QoS. `port-qos-map del` only deletes policer/scheduler
    references (no-op on map bindings) -- so remove via GCU; if this port is the last
    entry in PORT_QOS_MAP, GCU refuses to "delete down to an empty table", so delete
    the whole table instead."""
    keys = cli.db_keys("CONFIG_DB", "PORT_QOS_MAP|*")
    if not keys:
        return
    path = "/PORT_QOS_MAP" if len(keys) <= 1 else f"/PORT_QOS_MAP/{port_name}"
    patch = f'[{{"op":"remove","path":"{path}"}}]'
    cli.sh.run(f"echo '{patch}' > /tmp/fvt_qos_unbind.json && "
               f"config apply-patch /tmp/fvt_qos_unbind.json", check=False, timeout=60)


def build_baseline(cli, port_name, prefix="FVTQOS"):
    """On **images that have the QoS CLI**, build a test baseline: DSCP->TC map +
    TC->queue map + binding to the port (trust_dscp). Returns an undo callable
    (reverse-order cleanup); returns None on images without the QoS CLI (caller
    decides).

    `dscp-to-tc-map add` first generates a complete 64-entry default table
    (0-7->BE, 8-15->AF1, ...), then applies the given overrides -- so a single
    creation yields a fully-populated map that can be compared pair-by-pair against
    the ASIC.
    """
    if not has_qos_cli(cli):
        return None
    d2t, t2q = f"{prefix}_D2T", f"{prefix}_T2Q"
    cli.config_raw(f"dscp-to-tc-map add {d2t} -d 46 -t EF")
    cli.config_raw(f"tc-to-queue-map add {t2q} -t EF -q 5")
    # Some images ship a PORT_QOS_MAP on **every port** (trust_8021p + default map),
    # in which case `add` is rejected ("has QoS configuration. Please use update")
    # yet **rc is still 0** -- so we must choose add/update by reading back CONFIG_DB
    # and settle it by trust_mode landing in the DB (rc is untrustworthy).
    orig_pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{port_name}") or {}
    sub = "update" if orig_pqm else "add"
    cli.config_raw(f"port-qos-map {sub} {port_name} -t trust_dscp -dscpt {d2t} -tq {t2q}")
    for _ in range(5):
        cur = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{port_name}") or {}
        if cur.get("trust_mode") == "trust_dscp":
            break
        time.sleep(1)
    else:
        _log.warning("build_baseline: trust_dscp did not land on %s (via %s); "
                     "classification-dependent traffic will misqueue", port_name, sub)
    time.sleep(3)   # wait for orchagent to program the ASIC

    def _undo():
        # For a port that shipped with a PORT_QOS_MAP: restore the original entry
        # rather than delete -- deleting would wipe out the factory QoS config too.
        # Only delete outright when there was no original entry.
        if orig_pqm:
            from .gcu import Gcu
            g = Gcu(cli)
            g.apply_patch([{"op": "replace", "path": g.path("PORT_QOS_MAP", port_name),
                            "value": orig_pqm}])
        else:
            _unbind_port_qos(cli, port_name)
        time.sleep(1)
        cli.config_raw(f"tc-to-queue-map del {t2q}")
        cli.config_raw(f"dscp-to-tc-map del {d2t}")
        time.sleep(1)

    return _undo


def build_sched_baseline(cli, port_name, prefix="FVTSCH"):
    """Build a scheduler (DWRR w=50) + WRED profile and bind them to the port's
    queue0. Gives SCHEDULER/WRED/queue-binding cases real objects to verify.
    Returns undo; returns None on images without the QoS CLI."""
    if not has_qos_cli(cli):
        return None
    sch, sp, wred = f"{prefix}_SCH", f"{prefix}_SP", f"{prefix}_WRED"
    cli.config_raw(f"scheduler add {sch} -t DWRR -w 50")
    cli.config_raw(f"scheduler add {sp} -t STRICT")   # -p declared unsupported by the device
    cli.config_raw(f"wred-profile add {wred} -en true -ecn ecn_all "
                   f"-gmin 100000 -gmax 200000 -ymin 100000 -ymax 200000 "
                   f"-rmin 100000 -rmax 200000")
    # A scheduler object is programmed to the ASIC only when referenced: DWRR bound to queue0, STRICT to queue1
    cli.config_raw(f"port-queue add {port_name} 0 -s {sch} -w {wred}")
    cli.config_raw(f"port-queue add {port_name} 1 -s {sp}")
    cli.config_raw(f"buffer profile add {prefix}_BUF --dynamic-th 3")   # ASIC BUFFER_PROFILE 0->1
    time.sleep(3)

    def _undo():
        cli.config_raw(f"port-queue del {port_name} 1")
        cli.config_raw(f"port-queue del {port_name} 0")
        time.sleep(1)
        cli.config_raw(f"buffer profile del {prefix}_BUF")
        cli.config_raw(f"wred-profile del {wred}")
        cli.config_raw(f"scheduler del {sp}")
        cli.config_raw(f"scheduler del {sch}")
        time.sleep(1)

    return _undo
