"""config->DB contract checks for QoS / buffer / PFCWD / ecnconfig (config + DB only, no traffic).

Adapted from sonic-mgmt: tests/qos/test_buffer.py, tests/qos/test_ecn_config.py,
tests/pfcwd/test_pfc_config.py. The emphasis is filling our missing "illegal config is rejected by the NOS" dimension --
verifying both legal acceptance (config really lands in CONFIG_DB) and illegal rejection (CLI non-zero rc or CONFIG_DB unchanged + no traceback).

Device state (minimal l2 preset):
  - By default CONFIG_DB has no QOS_MAP/BUFFER_*/WRED_PROFILE (the buffers.json.j2 template is missing);
  - Content-check cases (1/2/4-list) first run `config qos reload`; if still empty they have **a legitimate reason to skip**, never asserting True;
  - The PFCWD / ecnconfig CLIs exist, so the "illegal rejection" cases **can always run** (they do not depend on pre-existing legal config).

Ports use topo.misc_port(0) (the g/h misc domain). All changes are rolled back via config_guard. Messages in English, comments in English.
"""
import json
import time

import pytest

from framework import qos

pytestmark = [pytest.mark.qos, pytest.mark.cli]

# DSCP valid range 0-63; TC/queue usually 0-7 (8 TCs/queues); dot1p 0-7
_DSCP_MAX = 63
_TC_MAX = 7
_DOT1P_MAX = 7
_QUEUE_MAX = 15  # some platforms have more than 8 queues, so relax to a 16-queue upper bound


@pytest.fixture(scope="module")
def qos_reloaded(cli, topo):
    """Module-wide setup: get the QoS maps into CONFIG_DB/ASIC -- **according to the image's config model**:

    - Community image: `config qos reload` renders the hwsku templates; a missing template (buffers.json.j2) is a real defect,
      and content cases FAIL honestly when the ASIC is empty.
    - SONiC: QoS is a **product-CLI config model** (config dscp-to-tc-map/tc-to-queue-map/
      port-qos-map...), and the hwsku carries no templates (by design, not a defect). **Never run reload** -- on this
      image reload only clears without building, and the resulting dangling PORT_QOS_MAP references cause whole-DB YANG
      validation to fail (mechanism in the test_qos.py module docstring); when there is no map, build a test baseline via the
      product CLI (add seeds a 64-entry default table, complete enough to compare against the ASIC entry by entry), cleaned up at module end.
    """
    if not qos.has_qos_cli(cli):
        cli.sh.run("config qos reload", check=False, timeout=120)
        # qos reload pushes asynchronously; give it a little time to land in CONFIG_DB
        time.sleep(3)
    undos = []
    if qos.has_qos_cli(cli):
        if not cli.db_keys("CONFIG_DB", "DSCP_TO_TC_MAP|*"):
            u = qos.build_baseline(cli, topo.misc_port(0).name, prefix="FVTQC")
            if u:
                undos.append(u)
        if not cli.db_keys("CONFIG_DB", "WRED_PROFILE|*"):   # ecnconfig-class cases need WRED_PROFILE
            u = qos.build_sched_baseline(cli, topo.misc_port(0).name, prefix="FVTQCS")
            if u:
                undos.append(u)
    yield
    for u in reversed(undos):
        u()


# ============================ 1) DSCP/dot1p map tables: ASIC programming + CONFIG_DB content check ============================
# The "real behavior" evidence for this group lives in the ASIC: the config effect of the QoS classification maps is
# **observable in ASIC_DB's SAI_QOS_MAP**. So the main assertion becomes "the SAI_QOS_MAP of the corresponding type is really
# programmed into the chip", with the CONFIG_DB key/value-range check as a secondary sanity.
# When buffers.json.j2 is missing, `config qos reload` pushes nothing -> the ASIC has no such map -> honest xfail (visible, no false pass).
# End-to-end data-plane verification that "different DSCP/PCP land on different egress queues" is covered by test_qos_remark_chip.py (real traffic + egress queue counts).
_QOS_MAP_DEFECT = ("`config qos reload` programming incomplete "
                   "-> QoS classification map not programmed to ASIC")

_QOS_PORT_MAP_ATTRS = [
    "SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP",
    "SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP",
    "SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP",
    "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP",
    "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP",
]

# buffer/WRED objects may fail to reach the ASIC due to a missing buffers.json.j2 or incomplete `config qos reload` push --
# when the ASIC is actually empty, uniformly cite this reason to xfail (visible, not hidden, no false pass).
_BUFFER_DEFECT = ("`config qos reload` programming incomplete "
                  "-> buffer object not programmed to ASIC")
_POOL_TYPES = {"SAI_BUFFER_POOL_TYPE_INGRESS", "SAI_BUFFER_POOL_TYPE_EGRESS",
               "SAI_BUFFER_POOL_TYPE_BOTH"}
_THRESH_MODES = {"SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC",
                 "SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC",
                 "SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC",
                 "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC"}


def _oid(key):
    """ASIC_STATE:SAI_OBJECT_TYPE_X:oid:0x.. -> oid:0x.."""
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def _int(v):
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else None


def _map_entries(cli, table):
    """Read a QoS map table (e.g. DSCP_TO_TC_MAP), returning {map_name: {field: value}}. Empty -> {}."""
    keys = cli.db_keys("CONFIG_DB", f"{table}|*")
    out = {}
    for k in keys:
        name = k.split("|", 1)[1]
        out[name] = cli.db_hgetall("CONFIG_DB", k)
    return out


def _asic_qos_maps_by_type(asicdb):
    """Group ASIC QOS_MAP objects by SAI_QOS_MAP_ATTR_TYPE: {type_str: [key,...]}."""
    out = {}
    for k in asicdb.objects("SAI_OBJECT_TYPE_QOS_MAP"):
        t = asicdb.field(k, "SAI_QOS_MAP_ATTR_TYPE")
        out.setdefault(t, []).append(k)
    return out


def _asic_qos_map_pairs(payload, key_field, val_field):
    """Parse ASIC SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST, returning an integer map {key_field value: val_field value}.

    sairedis serializes sai_qos_map_list_t as JSON:
        {"count":N,"list":[{"key":{"dscp":0,"tc":0,...},"value":{"tc":1,...}}, ...]}
    where key/value are both sai_qos_map_params_t (containing tc/dot1p/dscp/prio/pg/queue_index/color/...).
    Depending on the map type, take key_field (e.g. dscp/dot1p/tc) and val_field (e.g. tc/queue_index). Parse failure/empty -> {}."""
    if not payload:
        return {}
    try:
        obj = json.loads(payload)
    except (ValueError, TypeError):
        return {}
    if not isinstance(obj, dict):
        return {}
    pairs = {}
    for item in obj.get("list", []):
        k = item.get("key", {})
        v = item.get("value", {})
        if not isinstance(k, dict) or not isinstance(v, dict):
            continue
        # The value field name differs across sairedis versions: TC_TO_QUEUE's queue serializes as queue_index in newer versions
        # and qidx in older ones -- accept both.
        vf = val_field if val_field in v else ("qidx" if val_field == "queue_index" and "qidx" in v else val_field)
        if key_field in k and vf in v:
            try:
                pairs[int(k[key_field])] = int(v[vf])
            except (ValueError, TypeError):
                continue
    return pairs


def _match_asic_map(asic_pairs_list, cfg_pairs):
    """Whether cfg_pairs (CONFIG_DB's {key:val}) is **exactly, pair by pair** contained in some ASIC map's {key:val}.

    Returns (ok, diff): ok=True means there exists some ASIC map whose every pair matches cfg_pairs exactly;
    otherwise returns the mismatching items {key:(cfg_val, asic_val)} on the closest ASIC map, for error localization."""
    best = None
    for ap in asic_pairs_list:
        diff = {k: (v, ap.get(k)) for k, v in cfg_pairs.items() if ap.get(k) != v}
        if not diff:
            return True, {}
        if best is None or len(diff) < len(best):
            best = diff
    return False, (best if best is not None else dict(cfg_pairs))


def test_dscp_to_tc_map_content(cli, asicdb, qos_reloaded):
    """DSCP->TC map programmed exactly into the chip: the map_to_value_list of the ASIC type=DSCP_TO_TC SAI_QOS_MAP must
    **reflect exactly, pair by pair** the DSCP->TC key/value pairs of CONFIG_DB DSCP_TO_TC_MAP (not just checking the 0-63/0-7 ranges).
    If this image did not push the map / the map_to_value_list is unparseable -> honest xfail."""
    by_type = _asic_qos_maps_by_type(asicdb)
    dscp_maps = by_type.get("SAI_QOS_MAP_TYPE_DSCP_TO_TC")
    if not dscp_maps:
        pytest.fail(_QOS_MAP_DEFECT + " [DSCP_TO_TC SAI_QOS_MAP absent in ASIC]")
    maps = _map_entries(cli, "DSCP_TO_TC_MAP")
    assert maps, "ASIC has DSCP_TO_TC SAI_QOS_MAP but CONFIG_DB DSCP_TO_TC_MAP empty (config<->chip mismatch)"
    # Parse each ASIC DSCP_TO_TC map's {dscp: tc}
    asic_pairs = [p for p in (
        _asic_qos_map_pairs(asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"), "dscp", "tc")
        for k in dscp_maps) if p]
    if not asic_pairs:
        pytest.fail(_QOS_MAP_DEFECT + " [DSCP_TO_TC SAI_QOS_MAP present but map_to_value_list empty/unparseable]")
    for name, m in maps.items():
        assert m, f"DSCP_TO_TC_MAP|{name} has no entries"
        cfg = {}
        for dscp, tc in m.items():
            # key/value range sanity (retained), then build the integer pairs for exact comparison
            assert dscp.isdigit() and 0 <= int(dscp) <= _DSCP_MAX, \
                f"illegal DSCP key {dscp!r} in {name} (must be 0-{_DSCP_MAX})"
            tcn = qos.tc_num(tc)   # community=numeric, SONiC=name (BE/AF1..CS7), compared after normalization
            assert tcn is not None and 0 <= tcn <= _TC_MAX, \
                f"illegal TC value {tc!r} for DSCP {dscp} in {name} (0-{_TC_MAX} or a TC name)"
            cfg[int(dscp)] = tcn
        # Main assertion: every DSCP->TC pair in CONFIG_DB must appear exactly in some ASIC map's map_to_value_list
        ok, diff = _match_asic_map(asic_pairs, cfg)
        assert ok, (
            f"CONFIG_DB DSCP_TO_TC_MAP|{name} not exactly reflected in any ASIC DSCP_TO_TC "
            f"SAI_QOS_MAP map_to_value_list; mismatching dscp->(cfg_tc,asic_tc): "
            f"{dict(list(diff.items())[:12])}")


def test_dot1p_to_tc_map_content(cli, asicdb, qos_reloaded):
    """dot1p->TC map programmed exactly into the chip: the map_to_value_list of the ASIC type=DOT1P_TO_TC SAI_QOS_MAP must
    **reflect exactly, pair by pair** the dot1p->TC key/value pairs of CONFIG_DB DOT1P_TO_TC_MAP (not just checking the ranges).
    If this image did not push the map / the map_to_value_list is unparseable -> honest xfail."""
    by_type = _asic_qos_maps_by_type(asicdb)
    dot1p_maps = by_type.get("SAI_QOS_MAP_TYPE_DOT1P_TO_TC")
    if not dot1p_maps:
        if qos.has_qos_cli(cli) and not cli.db_keys("CONFIG_DB", "DOT1P_TO_TC_MAP|*"):
            # The product-CLI config-model image has no entry point to create a DOT1P->TC map (no top-level dot1p-to-tc-map command)
            # -- with no channel to build one there is nothing to verify, so structural skip (not a defect).
            pytest.skip("this image QoS CLI has no command to create a DOT1P_TO_TC map; "
                        "nothing to verify (structural)")
        pytest.fail(_QOS_MAP_DEFECT + " [DOT1P_TO_TC SAI_QOS_MAP absent in ASIC]")
    maps = _map_entries(cli, "DOT1P_TO_TC_MAP")
    assert maps, "ASIC has DOT1P_TO_TC SAI_QOS_MAP but CONFIG_DB DOT1P_TO_TC_MAP empty (config<->chip mismatch)"
    asic_pairs = [p for p in (
        _asic_qos_map_pairs(asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"), "dot1p", "tc")
        for k in dot1p_maps) if p]
    if not asic_pairs:
        pytest.fail(_QOS_MAP_DEFECT + " [DOT1P_TO_TC SAI_QOS_MAP present but map_to_value_list empty/unparseable]")
    for name, m in maps.items():
        assert m, f"DOT1P_TO_TC_MAP|{name} has no entries"
        cfg = {}
        for dot1p, tc in m.items():
            assert dot1p.isdigit() and 0 <= int(dot1p) <= _DOT1P_MAX, \
                f"illegal dot1p key {dot1p!r} in {name} (must be 0-{_DOT1P_MAX})"
            tcn = qos.tc_num(tc)
            assert tcn is not None and 0 <= tcn <= _TC_MAX, f"illegal TC value {tc!r} in {name}"
            cfg[int(dot1p)] = tcn
        ok, diff = _match_asic_map(asic_pairs, cfg)
        assert ok, (
            f"CONFIG_DB DOT1P_TO_TC_MAP|{name} not exactly reflected in any ASIC DOT1P_TO_TC "
            f"SAI_QOS_MAP map_to_value_list; mismatching dot1p->(cfg_tc,asic_tc): "
            f"{dict(list(diff.items())[:12])}")


def test_tc_to_queue_map_content(cli, asicdb, qos_reloaded):
    """TC->queue map programmed exactly into the chip: the map_to_value_list of the ASIC type=TC_TO_QUEUE SAI_QOS_MAP must
    **reflect exactly, pair by pair** the TC->queue key/value pairs of CONFIG_DB TC_TO_QUEUE_MAP (not just checking the ranges).
    If this image did not push the map / the map_to_value_list is unparseable -> honest xfail."""
    by_type = _asic_qos_maps_by_type(asicdb)
    q_maps = by_type.get("SAI_QOS_MAP_TYPE_TC_TO_QUEUE")
    if not q_maps:
        pytest.fail(_QOS_MAP_DEFECT + " [TC_TO_QUEUE SAI_QOS_MAP absent in ASIC]")
    maps = _map_entries(cli, "TC_TO_QUEUE_MAP")
    assert maps, "ASIC has TC_TO_QUEUE SAI_QOS_MAP but CONFIG_DB TC_TO_QUEUE_MAP empty (config<->chip mismatch)"
    # For TC_TO_QUEUE, the value field name in the SAI serialization is queue_index
    asic_pairs = [p for p in (
        _asic_qos_map_pairs(asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"), "tc", "queue_index")
        for k in q_maps) if p]
    if not asic_pairs:
        pytest.fail(_QOS_MAP_DEFECT + " [TC_TO_QUEUE SAI_QOS_MAP present but map_to_value_list empty/unparseable]")
    for name, m in maps.items():
        assert m, f"TC_TO_QUEUE_MAP|{name} has no entries"
        cfg = {}
        for tc, q in m.items():
            tcn = qos.tc_num(tc)   # on SONiC the key is a TC name
            assert tcn is not None and 0 <= tcn <= _TC_MAX, \
                f"illegal TC key {tc!r} in {name} (0-{_TC_MAX} or a TC name)"
            assert q.isdigit() and 0 <= int(q) <= _QUEUE_MAX, \
                f"illegal queue value {q!r} for TC {tc} in {name} (must be 0-{_QUEUE_MAX})"
            cfg[tcn] = int(q)
        ok, diff = _match_asic_map(asic_pairs, cfg)
        assert ok, (
            f"CONFIG_DB TC_TO_QUEUE_MAP|{name} not exactly reflected in any ASIC TC_TO_QUEUE "
            f"SAI_QOS_MAP map_to_value_list; mismatching tc->(cfg_queue,asic_queue): "
            f"{dict(list(diff.items())[:12])}")


def test_port_qos_map_references_valid(cli, asicdb, qos_reloaded):
    """Port QoS binding really programmed into the chip: at least one ASIC PORT's SAI_PORT_ATTR_QOS_*_MAP points to a truly
    existing SAI_QOS_MAP object (config->chip: the port QoS binding lands in hardware, not just CONFIG_DB reference consistency), with no dangling references.

    No SAI_QOS_MAP at all (buffers.json.j2 missing) -> honest xfail."""
    qos_maps = {_oid(k) for k in asicdb.objects("SAI_OBJECT_TYPE_QOS_MAP")}
    if not qos_maps:
        pytest.fail(_QOS_MAP_DEFECT + " [no SAI_QOS_MAP -> no port QoS binding on chip]")
    bound, dangling = 0, []
    for p in asicdb.objects("SAI_OBJECT_TYPE_PORT"):
        for attr in _QOS_PORT_MAP_ATTRS:
            ref = asicdb.field(p, attr)
            if ref and ref != "oid:0x0":
                if ref in qos_maps:
                    bound += 1
                else:
                    dangling.append((_oid(p), attr, ref))
    assert not dangling, f"ASIC PORT bound to non-existent SAI_QOS_MAP (dangling): {dangling[:10]}"
    assert bound > 0, ("SAI_QOS_MAP objects exist but no ASIC PORT references any via "
                       "SAI_PORT_ATTR_QOS_*_MAP (port QoS binding not programmed to chip)")


# ============================ 2) buffer profile / pool / pg / queue content checks ============================

def _buffer_absent(cli, what):
    """Characterization when the ASIC lacks the buffer object: the product-CLI config-model image (SONiC) manages buffers via its
    own model (config buffer profile/port-queue) and does not build SAI pool objects by default -- template-style default-pool
    checks do not apply, so structural skip (dedicated cases for its own buffer CLI are a follow-up); a community image with a
    missing template = real defect, honest FAIL."""
    if qos.has_qos_cli(cli):
        pytest.skip(f"this image manages buffers via its own CLI model; no default SAI "
                    f"{what} objects to check against templates (structural; "
                    f"product-CLI buffer tests are a follow-up)")
    pytest.fail(_BUFFER_DEFECT + f" [{what} absent in ASIC]")

def test_buffer_pool_content(cli, asicdb, qos_reloaded):
    """Buffer pool really programmed into the chip: the main assertion cross-checks the ASIC SAI_OBJECT_TYPE_BUFFER_POOL's
    type/size/threshold_mode (chip evidence: type in {ingress,egress,both}, size>0, threshold_mode a valid enum), then checks
    consistency against the CONFIG_DB BUFFER_POOL type/mode/size. This image lacks buffers.json.j2 -> ASIC has no BUFFER_POOL -> honest xfail.

    (The original case only checked CONFIG_DB type/mode/size validity and skipped when CONFIG_DB was empty, an anti-pattern; now upgraded to a chip-level assertion.)"""
    pools = asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL")
    if not pools:
        _buffer_absent(cli, "BUFFER_POOL")
    # 1) ASIC-side attribute correctness (the buffer pool really lands in hardware, not just a CONFIG_DB write-back)
    bad, asic_types = [], set()
    for p in pools:
        typ = asicdb.field(p, "SAI_BUFFER_POOL_ATTR_TYPE")
        size = _int(asicdb.field(p, "SAI_BUFFER_POOL_ATTR_SIZE"))
        tm = asicdb.field(p, "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE")
        if typ not in _POOL_TYPES or size is None or size <= 0 or \
                (tm is not None and tm not in _THRESH_MODES):
            bad.append((_oid(p), typ, size, tm))
        else:
            asic_types.add(typ)
    assert not bad, f"ASIC BUFFER_POOL objects with invalid type/size/threshold_mode: {bad}"
    # 2) CONFIG_DB <-> ASIC consistency sanity: the ingress/egress pools configured in CONFIG_DB should each have a matching type on the chip
    _t2s = {"ingress": "SAI_BUFFER_POOL_TYPE_INGRESS", "egress": "SAI_BUFFER_POOL_TYPE_EGRESS"}
    for name, p in _map_entries(cli, "BUFFER_POOL").items():
        typ = p.get("type")
        assert typ in ("ingress", "egress"), f"BUFFER_POOL|{name} illegal type {typ!r}"
        assert p.get("mode") in ("static", "dynamic", None), \
            f"BUFFER_POOL|{name} illegal mode {p.get('mode')!r}"
        assert _t2s[typ] in asic_types or "SAI_BUFFER_POOL_TYPE_BOTH" in asic_types, \
            f"CONFIG_DB BUFFER_POOL|{name} type={typ} has no matching ASIC pool ({sorted(asic_types)})"


def test_buffer_profile_content_and_pool_ref(cli, asicdb, qos_reloaded):
    """Buffer profile really programmed into the chip: the main assertion checks the ASIC SAI_OBJECT_TYPE_BUFFER_PROFILE's
    SAI_BUFFER_PROFILE_ATTR_BUFFER_SIZE (non-negative) + SAI_BUFFER_PROFILE_ATTR_POOL_ID pointing to a truly existing
    SAI_OBJECT_TYPE_BUFFER_POOL (not a dangling oid:0x0). CONFIG_DB size/pool-ref checks are retained as sanity.
    This image lacks buffers.json.j2 -> ASIC has no BUFFER_PROFILE -> honest xfail.

    (The original case only checked CONFIG_DB size/pool-ref and skipped when CONFIG_DB was empty, an anti-pattern; now upgraded to a chip-level assertion.)"""
    profs = asicdb.objects("SAI_OBJECT_TYPE_BUFFER_PROFILE")
    if not profs:
        _buffer_absent(cli, "BUFFER_PROFILE")
    asic_pools = {_oid(p) for p in asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL")}
    if not asic_pools and qos.has_qos_cli(cli):
        # SONiC's own buffer model: profiles do not reference SAI pools (factory/CLI-built profiles have no POOL_ID,
        # and there are no default SAI_BUFFER_POOL objects) -- pool-ref semantics do not apply, so structural skip.
        pytest.skip("this image's buffer profiles do not reference SAI pools (own buffer "
                    "model, no SAI_BUFFER_POOL objects); pool-ref check not applicable")
    bad = []
    for pr in profs:
        pool = asicdb.field(pr, "SAI_BUFFER_PROFILE_ATTR_POOL_ID")
        # POOL_ID must point to a truly existing BUFFER_POOL, not dangling (profile->pool reference consistency lands in hardware)
        if not pool or pool == "oid:0x0" or (asic_pools and pool not in asic_pools):
            bad.append((_oid(pr), "pool_ref", pool))
            continue
        sz = _int(asicdb.field(pr, "SAI_BUFFER_PROFILE_ATTR_BUFFER_SIZE"))
        if sz is None or sz < 0:
            bad.append((_oid(pr), "buffer_size", sz))
        tm = asicdb.field(pr, "SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE")
        if tm is not None and tm not in _THRESH_MODES:
            bad.append((_oid(pr), "threshold_mode", tm))
    assert not bad, f"ASIC BUFFER_PROFILE objects with bad pool_ref/size/threshold_mode: {bad}"
    # CONFIG_DB sanity (original checks retained): size/xon/xoff non-negative + pool reference points to an existing BUFFER_POOL
    pool_names = set(_map_entries(cli, "BUFFER_POOL").keys())
    for name, pr in _map_entries(cli, "BUFFER_PROFILE").items():
        for fld in ("size", "xon", "xoff", "xon_offset"):
            v = pr.get(fld)
            if v is not None:
                assert v.lstrip("-").isdigit() and int(v) >= 0, \
                    f"BUFFER_PROFILE|{name}.{fld}={v!r} not a non-negative integer"
        pool = pr.get("pool")
        if pool is not None and pool_names:
            ref = pool.strip("[]").split("|")[-1]
            assert ref in pool_names, f"BUFFER_PROFILE|{name}.pool={pool!r} references missing BUFFER_POOL|{ref}"


def test_buffer_pg_and_queue_profile_ref(cli, asicdb, qos_reloaded):
    """PG/queue buffer binding really programmed into the chip: the main assertion checks that the ASIC INGRESS_PRIORITY_GROUP's
    SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE and QUEUE's SAI_QUEUE_ATTR_BUFFER_PROFILE_ID point to a truly existing
    SAI_OBJECT_TYPE_BUFFER_PROFILE (not dangling: PG/queue really have a buffer allocation landing in hardware).
    CONFIG_DB BUFFER_PG/BUFFER_QUEUE profile reference consistency is retained as sanity. No BUFFER_PROFILE -> honest xfail.

    (The original case only checked CONFIG_DB ref consistency and skipped when CONFIG_DB was empty, an anti-pattern; now upgraded to a chip-level binding assertion.)"""
    asic_profs = {_oid(p) for p in asicdb.objects("SAI_OBJECT_TYPE_BUFFER_PROFILE")}
    if not asic_profs:
        _buffer_absent(cli, "BUFFER_PROFILE (PG/queue binding)")
    if not asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL") and qos.has_qos_cli(cli):
        # As above: in the own-buffer model with no SAI pools, PG/queue buffer allocation is managed internally and does not
        # go through the SAI PG/QUEUE BUFFER_PROFILE attribute -- the binding check does not apply, so structural skip.
        pytest.skip("this image manages PG/queue buffers internally (no SAI pools); "
                    "PG/queue->profile SAI binding check not applicable")
    bound, dangling = 0, []
    for pg in asicdb.objects("SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP"):
        bp = asicdb.field(pg, "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE")
        if bp and bp != "oid:0x0":
            if bp in asic_profs:
                bound += 1
            else:
                dangling.append(("IPG", _oid(pg), bp))
    for q in asicdb.objects("SAI_OBJECT_TYPE_QUEUE"):
        bp = asicdb.field(q, "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID")
        if bp and bp != "oid:0x0":
            if bp in asic_profs:
                bound += 1
            else:
                dangling.append(("QUEUE", _oid(q), bp))
    assert not dangling, f"IPG/QUEUE bound to non-existent BUFFER_PROFILE (dangling): {dangling[:10]}"
    assert bound > 0, ("BUFFER_PROFILE objects exist but no INGRESS_PRIORITY_GROUP or QUEUE references "
                       "any via buffer profile attr (PG/queue buffer binding not programmed to chip)")
    # CONFIG_DB sanity (original checks retained): BUFFER_PG/BUFFER_QUEUE profile references point to an existing BUFFER_PROFILE
    prof_names = set(_map_entries(cli, "BUFFER_PROFILE").keys())
    if prof_names:
        for table in ("BUFFER_PG", "BUFFER_QUEUE"):
            for key, ent in _map_entries(cli, table).items():
                prof = ent.get("profile")
                if not prof:
                    continue
                ref = prof.strip("[]").split("|")[-1]
                assert ref in prof_names, \
                    f"{table}|{key}.profile={prof!r} references missing BUFFER_PROFILE|{ref}"


# ============================ 3) PFCWD config checks (adapted from test_pfc_config.py) ============================
def _pfcwd_supported(cli):
    """Whether the PFCWD CLI is available (`config pfcwd --help` contains the start subcommand)."""
    r = cli.run("config pfcwd --help")
    return r.rc == 0 and "start" in (r.out + r.err)


def _pfc_wd_key(cli, port):
    """Read CONFIG_DB PFC_WD|<port> (empty -> {})."""
    return cli.db_hgetall("CONFIG_DB", f"PFC_WD|{port}")


def _pfcwd_per_queue_flex_counters(cli):
    """The per-queue PFC_WD counter entries pfcwd creates in FLEX_COUNTER_DB for monitored queues (a non-echo signal).

    After pfcwd **actually starts**, pfcwdorch registers a PFC_WD flex counter in FLEX_COUNTER_DB for each lossless queue
    (FLEX_COUNTER_TABLE:PFC_WD:<queue_oid>), which is derived evidence that cannot be faked by writing back CONFIG_DB.
    Exclude FLEX_COUNTER_GROUP_TABLE:PFC_WD (only registers the group, not "monitoring started")."""
    keys = cli.db_keys("FLEX_COUNTER_DB", "FLEX_COUNTER_TABLE:PFC_WD:*")
    if not keys:
        # Tolerate separator/prefix differences in some versions, still excluding GROUP-level registration entries
        keys = [k for k in cli.db_keys("FLEX_COUNTER_DB", "*PFC_WD*")
                if "GROUP" not in k.upper()]
    return keys


def test_pfcwd_legal_start_accepted(cli, topo, config_guard):
    """Legal `config pfcwd start --action drop <port> <detect> --restoration-time <restore>` is accepted
    -> verify CONFIG_DB PFC_WD|<port> lands (action/detection_time/restoration_time fields correct).
    Rolled back via config_guard with `pfcwd stop <port>`."""
    # The image should carry the PFCWD CLI (see module docstring); missing is treated as a device defect FAIL.
    assert _pfcwd_supported(cli), "PFCWD CLI not available (config pfcwd start missing)"
    port = topo.misc_port(0).name
    # pfcwd requires enabling PFC priority on the port first. On this platform `config interface pfc priority <port> <pri> on`
    # takes only a **single** priority at a time (a `3,4` comma list is rejected by the CLI), so enable them one by one:
    # single-priority enable succeeds, and after enabling pfcwd start is accepted. Enabling PFC first is a legal prerequisite, not a device defect.
    pr, pe = cli.config_raw(f"interface pfc priority {port} 3 on")
    assert "Traceback" not in (pe.out + pe.err), \
        f"config interface pfc priority crashed: {(pe.out + pe.err)[:200]}"
    assert pr == 0 and "Cannot find interface" not in (pe.out + pe.err), (
        f"`config interface pfc priority {port} 3 on` rejected "
        f"(rc={pr}): {(pe.out + pe.err).strip()[:160]}")
    config_guard.defer_undo(f"interface pfc priority {port} 3 off")
    rc, r = cli.config_raw(f"pfcwd start --action drop {port} 400 --restoration-time 400")
    out = r.out + r.err
    assert "Traceback" not in out, f"config pfcwd start crashed with traceback: {out[:200]}"
    assert "PFC is not enabled" not in out, (
        f"pfcwd start still reports 'PFC is not enabled' after enabling PFC "
        f"priority on {port}; per-port PFC provisioning chain broken: {out.strip()[:160]}")
    # A legal pfcwd start must be accepted; rejection = missing lossless queue/buffer config, exposed as FAIL.
    assert rc == 0, (f"legal pfcwd start rejected (rc={rc}); likely missing lossless "
                     f"qos/buffer config: {out.strip()[:160]}")
    config_guard.defer_undo(
        "__toplevel__ pfcwd stop",
        verify=lambda: not cli.db_keys("CONFIG_DB", "PFC_WD|*"))   # no args = stop all pfcwd (this case only started it on this port, harmless)
    cfg = {}
    for _ in range(10):
        cfg = _pfc_wd_key(cli, port)
        if cfg:
            break
        time.sleep(0.3)
    # CLI accepted (rc=0) but did not write PFC_WD = config did not land, exposed as FAIL (root cause: missing lossless PFC/buffer config).
    assert cfg, (f"pfcwd start accepted but no PFC_WD|{port} entry created "
                 "(requires lossless PFC/buffer config absent on this minimal preset)")
    assert cfg.get("action") == "drop", f"PFC_WD|{port}.action={cfg.get('action')!r}, expected 'drop'"
    assert cfg.get("detection_time") == "400", f"PFC_WD|{port}.detection_time={cfg.get('detection_time')!r}"
    assert cfg.get("restoration_time") == "400", f"PFC_WD|{port}.restoration_time={cfg.get('restoration_time')!r}"
    # Non-echo evidence: landing in CONFIG_DB is just a write-back; whether the watchdog **actually started** is shown by the
    # per-queue PFC_WD flex counter pfcwdorch registers in FLEX_COUNTER_DB for monitored queues (cannot be faked by writing back CONFIG_DB).
    started = False
    for _ in range(20):
        if _pfcwd_per_queue_flex_counters(cli):
            started = True
            break
        time.sleep(0.5)
    assert started, (
        f"PFC_WD|{port} written to CONFIG_DB but no per-queue PFC_WD flex counter appeared in "
        f"FLEX_COUNTER_DB (watchdog config landed but did not actually start)")


@pytest.mark.parametrize(
    "desc,args",
    [
        # illegal action: outside click Choice[drop|forward|alert]
        ("invalid_action", "pfcwd start --action bogus {port} 400 --restoration-time 400"),
        # illegal detection_time: non-integer (click INT parse failure)
        ("nonint_detect", "pfcwd start --action drop {port} 40a0 --restoration-time 400"),
        # out-of-range detection_time: 0 (PFCWD detection time cannot be 0)
        ("zero_detect", "pfcwd start --action drop {port} 0 --restoration-time 400"),
        # illegal restoration_time: non-integer / out of range (rejected by click INTEGER RANGE)
        ("nonint_restore", "pfcwd start --action drop {port} 400 --restoration-time 40c0"),
        ("zero_restore", "pfcwd start --action drop {port} 400 --restoration-time 0"),
    ],
    ids=["invalid_action", "nonint_detect", "zero_detect", "nonint_restore", "zero_restore"],
)
def test_pfcwd_illegal_rejected(cli, topo, config_guard, desc, args):
    """Illegal PFCWD config must be rejected by the NOS: CLI non-zero rc or CONFIG_DB PFC_WD|<port> not written with bad values,
    and no Python traceback (adapted from test_pfc_config.py's invalid_action / low|high detect|restore cases)."""
    # The image should carry the PFCWD CLI (see module docstring); missing is a device defect FAIL.
    assert _pfcwd_supported(cli), "PFCWD CLI not available"
    port = topo.misc_port(0).name
    before = _pfc_wd_key(cli, port)
    rc, r = cli.config_raw(args.format(port=port))
    out = r.out + r.err
    # Fallback rollback: in case it is unexpectedly accepted, stop it
    config_guard.defer_undo(
        f"__toplevel__ pfcwd stop {port}",
        verify=lambda: not cli.db_hgetall("CONFIG_DB", f"PFC_WD|{port}"))
    # Must not crash (a traceback is a defect, not a "rejection")
    assert "Traceback" not in out, f"[{desc}] config pfcwd start crashed instead of clean reject: {out[:200]}"
    after = _pfc_wd_key(cli, port)
    if rc != 0:
        # Clean rejection: rc!=0. And CONFIG_DB must not be altered with bad values
        assert after == before, f"[{desc}] CLI rejected (rc={rc}) but CONFIG_DB PFC_WD|{port} changed: {before} -> {after}"
        return
    # rc==0: CONFIG_DB must not have this illegal config written (bad values must not land)
    assert after == before, (
        f"[{desc}] illegal pfcwd config accepted AND written to CONFIG_DB PFC_WD|{port}: "
        f"{before} -> {after} (NOS failed to reject)")


# ============================ 4) ecnconfig (adapted from test_ecn_config.py) ============================
def _ecnconfig_supported(cli):
    r = cli.run("ecnconfig --help")
    return r.rc == 0 and "WRED" in (r.out + r.err)


def _wred_profile(cli, name):
    return cli.db_hgetall("CONFIG_DB", f"WRED_PROFILE|{name}")


def test_ecnconfig_list_profiles(cli, asicdb, qos_reloaded):
    """WRED/ECN profile list really programmed into the chip: every WRED_PROFILE listed by `ecnconfig -l` must be reflected as a
    whole into ASIC SAI_OBJECT_TYPE_WRED objects (count >= number of CONFIG_DB profiles), and those WRED objects must carry at
    least a color threshold or ECN mark mode (not bare objects). Complementary to test_ecnconfig_legal_modify_updates_db (which
    verifies a single profile's value change reaching the ASIC) -- here we verify the different facet that "the profile list as a
    whole really reaches the chip". No SAI_OBJECT_TYPE_WRED -> honest xfail.

    (The original case only echo-checked that `ecnconfig -l` output contains the profile names, redundant with legal_modify; now upgraded to a chip-level list assertion.)"""
    # The image should carry the ecnconfig CLI (see module docstring); missing is a device defect FAIL.
    assert _ecnconfig_supported(cli), "ecnconfig not available"
    r = cli.run("ecnconfig -l")
    out = r.out + r.err
    assert "Traceback" not in out, f"ecnconfig -l crashed: {out[:200]}"
    profs = _map_entries(cli, "WRED_PROFILE")
    wreds = asicdb.objects("SAI_OBJECT_TYPE_WRED")
    if not profs and not wreds:
        _buffer_absent(cli, "WRED")
    # CONFIG_DB profile names should echo in ecnconfig -l (config-side sanity)
    for name in profs:
        assert name in r.out, f"ecnconfig -l did not list WRED_PROFILE {name}"
    # Main assertion: the CONFIG_DB WRED profiles must be really programmed into ASIC SAI_OBJECT_TYPE_WRED objects
    if not wreds:
        pytest.fail("WRED_PROFILE present in CONFIG_DB but no SAI_OBJECT_TYPE_WRED programmed "
                    "to ASIC (orch->ASIC WRED path absent)")
    typed = 0
    for w in wreds:
        attrs = asicdb.cli.db_hgetall("ASIC_DB", w)
        if any(attrs.get(f"SAI_WRED_ATTR_{c}_MAX_THRESHOLD") for c in ("GREEN", "YELLOW", "RED")) \
                or attrs.get("SAI_WRED_ATTR_ECN_MARK_MODE"):
            typed += 1
    assert typed > 0, ("ASIC has SAI_OBJECT_TYPE_WRED objects but none carry color thresholds / ECN "
                       "mark mode (bare objects -> WRED profile content not really programmed)")
    # Each CONFIG_DB WRED profile corresponds to at least one ASIC WRED object (the list as a whole lands in hardware)
    if profs:
        assert len(wreds) >= len(profs), \
            f"CONFIG_DB has {len(profs)} WRED_PROFILE but ASIC has only {len(wreds)} SAI_OBJECT_TYPE_WRED"


def _pick_wred_profile(cli):
    profs = _map_entries(cli, "WRED_PROFILE")
    return (next(iter(profs.items())) if profs else (None, None))


def test_ecnconfig_legal_modify_updates_db(cli, asicdb, qos_reloaded):
    """Legal `ecnconfig -p <profile> -gmin <v> -gmax <v>` changes WRED params -> CONFIG_DB WRED_PROFILE updates,
    **and orch pushes the new thresholds to the ASIC SAI_OBJECT_TYPE_WRED's GREEN_MIN/MAX_THRESHOLD** (config->chip closed loop;
    a broken orch->ASIC WRED path in the image is caught; cf. test_qos_sched_chip::test_scheduler_weight_change_reflects_asic).

    This image has no WRED_PROFILE -> skip; a CONFIG_DB profile exists but the ASIC has not programmed WRED -> xfail(strict=False)
    (known device defect, visible, no false pass). Record the original value before the change and restore it via ecnconfig."""
    # The image should carry the ecnconfig CLI (see module docstring); missing is a device defect FAIL.
    assert _ecnconfig_supported(cli), "ecnconfig not available"
    name, prof = _pick_wred_profile(cli)
    # No WRED_PROFILE = root cause is a missing buffers.json.j2 / qos profile not loaded, exposed as FAIL.
    assert name, "no WRED_PROFILE to modify (qos profile not loaded)"
    # green_min/green_max field names (may be *_min_threshold in different versions)
    gmin_fld = "green_min_threshold" if "green_min_threshold" in prof else next(
        (k for k in prof if "green" in k and "min" in k), None)
    gmax_fld = "green_max_threshold" if "green_max_threshold" in prof else next(
        (k for k in prof if "green" in k and "max" in k), None)
    # A WRED_PROFILE that exists but lacks green min/max threshold fields = malformed profile, exposed as FAIL.
    assert gmin_fld and gmax_fld, f"WRED_PROFILE|{name} has no green min/max threshold fields: {list(prof)}"
    old_min, old_max = prof[gmin_fld], prof[gmax_fld]
    # green min/max not numeric = malformed profile, exposed as FAIL (cannot derive new values from it).
    assert str(old_min).isdigit() and str(old_max).isdigit(), \
        f"WRED_PROFILE|{name} green min/max not numeric ({old_min!r}/{old_max!r}); cannot derive new values"
    # Pick a legal pair of new values with max>min (offset from the originals, ensuring gmin<gmax)
    new_min = str(int(old_min) + 1000)
    new_max = str(int(old_max) + 2000)
    # ecnconfig is not a config subcommand, so restore manually via ecnconfig (in finally), not registered with config_guard
    res = cli.run(f"ecnconfig -p {name} -gmin {new_min} -gmax {new_max}")
    out = res.out + res.err
    assert "Traceback" not in out, f"ecnconfig modify crashed: {out[:200]}"
    # A legal ecnconfig value change must be accepted; rejection = device defect, exposed as FAIL.
    assert res.rc == 0, f"legal ecnconfig modify rejected: {out.strip()[:160]}"
    try:
        updated = {}
        for _ in range(10):
            updated = _wred_profile(cli, name)
            if updated.get(gmin_fld) == new_min and updated.get(gmax_fld) == new_max:
                break
            time.sleep(0.3)
        assert updated.get(gmin_fld) == new_min, \
            f"WRED_PROFILE|{name}.{gmin_fld}={updated.get(gmin_fld)!r}, expected {new_min}"
        assert updated.get(gmax_fld) == new_max, \
            f"WRED_PROFILE|{name}.{gmax_fld}={updated.get(gmax_fld)!r}, expected {new_max}"
        # === Chip closed loop: the new WRED thresholds must reach ASIC SAI_OBJECT_TYPE_WRED via orch (not just a CONFIG_DB write-back) ===
        wreds = asicdb.objects("SAI_OBJECT_TYPE_WRED")
        if not wreds:
            # CONFIG_DB has a WRED profile but the ASIC has no WRED object at all = orch->ASIC WRED path not in effect,
            # a known device defect, exposed as FAIL.
            pytest.fail("WRED_PROFILE present in CONFIG_DB but no SAI_OBJECT_TYPE_WRED "
                        "programmed to ASIC (orch->ASIC WRED path absent)")
        asic_ok = False
        for _ in range(20):
            for w in asicdb.objects("SAI_OBJECT_TYPE_WRED"):
                attrs = asicdb.cli.db_hgetall("ASIC_DB", w)
                if (attrs.get("SAI_WRED_ATTR_GREEN_MIN_THRESHOLD") == new_min and
                        attrs.get("SAI_WRED_ATTR_GREEN_MAX_THRESHOLD") == new_max):
                    asic_ok = True
                    break
            if asic_ok:
                break
            time.sleep(0.5)
        assert asic_ok, (
            f"ecnconfig set {name} gmin/gmax {new_min}/{new_max} updated CONFIG_DB but no ASIC "
            f"SAI_OBJECT_TYPE_WRED shows SAI_WRED_ATTR_GREEN_MIN/MAX_THRESHOLD={new_min}/{new_max} "
            f"(orch->ASIC WRED threshold update broken)")
    finally:
        # Restore the original values (ecnconfig is not a config subcommand, so restore manually rather than via config_guard)
        cli.run(f"ecnconfig -p {name} -gmin {old_min} -gmax {old_max}")


def test_ecnconfig_illegal_value_rejected(cli, qos_reloaded):
    """Illegal WRED params (non-numeric threshold) must be rejected: ecnconfig non-zero rc or CONFIG_DB unchanged, and no traceback.
    This image has no WRED_PROFILE -> skip."""
    # The image should carry the ecnconfig CLI (see module docstring); missing is a device defect FAIL.
    assert _ecnconfig_supported(cli), "ecnconfig not available"
    name, prof = _pick_wred_profile(cli)
    # No WRED_PROFILE = root cause is a missing buffers.json.j2 / qos profile not loaded, exposed as FAIL.
    assert name, "no WRED_PROFILE to test against (qos profile not loaded)"
    before = _wred_profile(cli, name)
    # Non-numeric threshold -> ecnconfig should reject
    r = cli.run(f"ecnconfig -p {name} -gmin notanumber")
    out = r.out + r.err
    assert "Traceback" not in out, f"ecnconfig illegal value crashed instead of clean reject: {out[:200]}"
    after = _wred_profile(cli, name)
    if r.rc != 0:
        assert after == before, f"ecnconfig rejected (rc={r.rc}) but WRED_PROFILE|{name} changed: {before} -> {after}"
    else:
        assert after == before, \
            f"illegal WRED value accepted AND written to WRED_PROFILE|{name}: {before} -> {after}"


# ============================ 5) buffer illegal rejection (adapted from test_buffer.py's exceeding_headroom idea) ======
def test_buffer_profile_illegal_size_rejected(cli, qos_reloaded, config_guard):
    """Configuring an illegal size (non-numeric) on a BUFFER_PROFILE -> must be rejected by the NOS (CLI non-zero rc or CONFIG_DB
    not written with the bad value, and no traceback). Adapted from test_buffer.py's exceeding_headroom idea (out-of-bounds buffer should be rejected).

    This image has no `config buffer` subcommand / no existing BUFFER_PROFILE to mutate -> a legitimate reason to skip.
    Only assert when the "rejection" path can be cleanly triggered, never a false pass.
    """
    # Probe whether the `config buffer` CLI exists (some versions may lack a static buffer config command)
    helpr = cli.run("config buffer --help")
    # The image should carry the `config buffer profile` CLI; missing is exposed as FAIL (root cause: full buffer config not loaded).
    assert helpr.rc == 0 and "profile" in (helpr.out + helpr.err).lower(), \
        "no `config buffer profile` CLI (cannot exercise buffer-reject via CLI)"
    profs = _map_entries(cli, "BUFFER_PROFILE")
    # No existing BUFFER_PROFILE = root cause is a missing buffers.json.j2 / buffer config not loaded, exposed as FAIL.
    assert profs, "no existing BUFFER_PROFILE to mutate (buffer config not loaded)"
    name = next(iter(profs))
    before = _map_entries(cli, "BUFFER_PROFILE").get(name, {})
    # === Legal control (to eliminate a "hollow negative test"): if the `buffer profile set --size` syntax simply does not exist
    # on this image, an illegal value's rc!=0 is just a usage error and "after==before" is trivially true -- the test exercised no
    # validation logic. First use help to confirm the subcommand and --size option really exist; if they do and the profile has a
    # numeric size, do one legal write (writing back the original value, naturally requiring no restore) to prove the legal form is
    # really accepted, after which "illegal rejected" is meaningful.
    helps = cli.run("config buffer profile set --help")
    if helps.rc != 0 or "--size" not in (helps.out + helps.err):
        pytest.skip("`config buffer profile set --size` syntax not supported; "
                    "illegal-size rejection cannot be exercised meaningfully (structural)")
    if str(before.get("size", "")).isdigit():
        rc0, r0 = cli.config_raw(f"buffer profile set {name} --size {before['size']}")
        # The legal set (writing back the original value) must be accepted, otherwise the command is unusable for this profile and the negative conclusion is meaningless
        assert rc0 == 0, (
            f"legal `buffer profile set {name} --size {before['size']}` rejected "
            f"(rc={rc0}): {(r0.out + r0.err).strip()[:160]}; size validation path not exercisable")
    # Illegal size: a non-numeric string (the syntax was confirmed to exist by the legal control/help, so rc!=0 is genuinely a value-validation rejection).
    rc, r = cli.config_raw(f"buffer profile set {name} --size notanumber")
    out = r.out + r.err
    assert "Traceback" not in out, f"config buffer profile illegal size crashed: {out[:200]}"
    after = _map_entries(cli, "BUFFER_PROFILE").get(name, {})
    if rc != 0:
        assert after == before, f"CLI rejected (rc={rc}) but BUFFER_PROFILE|{name} changed: {before} -> {after}"
    else:
        # If unexpectedly accepted, register a rollback and assert the bad value did not land
        config_guard.defer_undo(f"buffer profile set {name} --size {before.get('size', '0')}")
        assert after.get("size") == before.get("size"), \
            f"illegal buffer size accepted AND written to BUFFER_PROFILE|{name}: {before} -> {after}"
