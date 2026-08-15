"""Chip-level attribute correctness of QoS scheduling/buffering (filling gaps left by test_qos*/test_stats_full).

Problem with existing QoS cases: most only check that "the ASIC object exists" or that
"CONFIG_DB content is valid" -- the very anti-pattern this suite is meant to fix.
This file focuses on whether ASIC_DB object attributes are correct (not just present), covering:
  - SCHEDULER       : scheduling_type valid (STRICT/DWRR/WRR) + weighted scheduler weight in range;
                      both strict and weighted present (typical SONiC SP+WRR profile);
  - QUEUE           : type/index valid + bound to a real existing SCHEDULER (scheduling tree formed, not dangling);
  - WRED            : at least one color enabled + max>min thresholds + drop probability 0-100 + valid ECN mark mode;
  - BUFFER_POOL     : type (ingress/egress) valid + size>0 + valid threshold_mode;
  - BUFFER_PROFILE  : pool_id points to a real existing BUFFER_POOL + valid buffer_size;
  - INGRESS_PG      : bound to a real existing BUFFER_PROFILE;
  - PFC per-priority: `config interface pfc priority <p> on` -> ASIC port PFC bitmap includes that priority (config->chip);
  - scheduler weight hot-change: change CONFIG_DB SCHEDULER weight -> ASIC SCHEDULER SCHEDULING_WEIGHT updated in sync;
  - dataplane       : loopback traffic -> egress queue SAI_QUEUE_STAT_PACKETS increments, and that queue
                      actually has a scheduler binding (tying "queue is scheduled" from config->chip->real forwarding count).

Device reality: no QoS/buffer by default, missing buffers.json.j2 template, `config qos reload`
programming is incomplete. So SCHEDULER/WRED/BUFFER_PROFILE cases first run
`config qos reload`; when still empty, xfail as a known device defect (visible, not masked, not a false pass).
QUEUE/IPG objects are created per port at ASIC init (independent of qos reload), so their attribute
checks can always run.

Ports use topo.misc_port() (g/h misc domain). Changes use config_guard / manual restore. Messages in English, comments in English.
"""
import time

import pytest

from framework import qos

pytestmark = [pytest.mark.qos]

# Missing buffers.json.j2 template makes qos reload programming incomplete -- known device defect; xfail cases reference this reason uniformly
_BUFFERS_DEFECT = ("missing buffers.json.j2 template, `config qos reload` "
                   "programming incomplete; object not programmed to ASIC")

_SCHED_TYPES = {
    "SAI_SCHEDULING_TYPE_STRICT",
    "SAI_SCHEDULING_TYPE_DWRR",
    "SAI_SCHEDULING_TYPE_WRR",
}
_WEIGHTED = {"SAI_SCHEDULING_TYPE_DWRR", "SAI_SCHEDULING_TYPE_WRR"}
_QUEUE_TYPES = {"SAI_QUEUE_TYPE_ALL", "SAI_QUEUE_TYPE_UNICAST", "SAI_QUEUE_TYPE_MULTICAST"}
_POOL_TYPES = {"SAI_BUFFER_POOL_TYPE_INGRESS", "SAI_BUFFER_POOL_TYPE_EGRESS",
               "SAI_BUFFER_POOL_TYPE_BOTH"}
_THRESH_MODES = {"SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC",
                 "SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC",
                 "SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC",
                 "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC"}

_QDST = "00:aa:bb:cc:dd:71"   # dst for dataplane queue counting (different MAC from other cases to avoid FDB cross-talk)


@pytest.fixture(scope="module")
def qos_loaded(cli, topo):
    """Module-wide setup: get QoS/scheduling objects into the ASIC, per the image's config model:

    - Community image: `config qos reload` renders the hwsku template; a missing template is a
      real defect, so FAIL honestly.
    - Product CLI-configured image (hwsku has no template by design). Never run reload --
      on this image reload only clears and does not build; PORT_QOS_MAP dangling references break
      the whole YANG database (mechanism described in test_qos.py module docstring); instead build
      the baseline directly via product CLI: maps+port binding (build_baseline) + scheduler/WRED+queue0
      binding (build_sched_baseline), cleaned up at module end.
    """
    if not qos.has_qos_cli(cli):
        cli.sh.run("config qos reload", check=False, timeout=120)
        end = time.time() + 25
        while time.time() < end:
            if cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:*"):
                break
            time.sleep(2)
    undos = []
    if qos.has_qos_cli(cli):
        if not cli.db_keys("CONFIG_DB", "DSCP_TO_TC_MAP|*"):   # ASIC has a default dot1p map, so check CONFIG_DB
            u = qos.build_baseline(cli, topo.misc_port(0).name, prefix="FVTSC")
            if u:
                undos.append(u)
        if not cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:*"):
            u = qos.build_sched_baseline(cli, topo.misc_port(0).name, prefix="FVTSCS")
            if u:
                undos.append(u)
    yield
    for u in reversed(undos):
        u()


def _oid(key):
    """ASIC_STATE:SAI_OBJECT_TYPE_X:oid:0x.. -> oid:0x.."""
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def _int(v):
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else None


# ============================ SCHEDULER ============================
def test_scheduler_attrs_valid(asicdb, qos_loaded):
    """Each ASIC SCHEDULER's scheduling_type must be a valid enum (STRICT/DWRR/WRR); weighted types
    (DWRR/WRR) must have SCHEDULING_WEIGHT in [1,100] (SAI mandates weight 1-100). Verifies attribute correctness, not just presence."""
    scheds = asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")
    if not scheds:
        pytest.fail(_BUFFERS_DEFECT + " [SCHEDULER]")
    # When this image's qos reload is incomplete, SCHEDULER objects exist but carry no SCHEDULING_TYPE (bare objects) --
    # this is a manifestation of the known buffers.json.j2 defect rather than an invalid attribute; xfail as a known defect (visible, no false pass).
    typed = [s for s in scheds if asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE")]
    if not typed:
        pytest.fail(_BUFFERS_DEFECT + " [SCHEDULER objects exist but none carry SCHEDULING_TYPE -> qos reload incomplete]")
    bad = []
    for s in typed:
        st = asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE")
        if st not in _SCHED_TYPES:
            bad.append((_oid(s), "type", st))
            continue
        if st in _WEIGHTED:
            w = _int(asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT"))
            if w is None or not (1 <= w <= 100):
                bad.append((_oid(s), "weight", w))
    assert not bad, f"SCHEDULER objects with invalid type/weight: {bad}"


def test_scheduler_has_strict_and_weighted(asicdb, qos_loaded):
    """A typical SONiC QoS profile programs both strict (SP) and weighted (WRR/DWRR) schedulers -- verifies
    scheduling-policy diversity really lands on the chip, rather than only one kind or all empty."""
    scheds = asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")
    if not scheds:
        pytest.fail(_BUFFERS_DEFECT + " [SCHEDULER]")
    types = {asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE") for s in scheds}
    types.discard(None)
    # All schedulers being bare objects (no SCHEDULING_TYPE) = known defect of incomplete qos reload; xfail rather than hard fail.
    if not types:
        pytest.fail(_BUFFERS_DEFECT + " [SCHEDULER objects carry no SCHEDULING_TYPE -> qos reload incomplete]")
    assert "SAI_SCHEDULING_TYPE_STRICT" in types, \
        f"no strict-priority scheduler programmed to ASIC (types={types})"
    assert types & _WEIGHTED, \
        f"no weighted (WRR/DWRR) scheduler programmed to ASIC (types={types})"


# ============================ QUEUE (created at init, independent of qos reload) ============================
def test_queue_attrs_valid(asicdb):
    """Each ASIC QUEUE has a valid type (UCAST/MCAST/ALL), index in [0,15], and PORT pointing to a real existing port object.
    Verifies queue-object attribute correctness (scheduling-tree leaf nodes formed), not just presence."""
    queues = asicdb.objects("SAI_OBJECT_TYPE_QUEUE")
    assert queues, "no SAI QUEUE objects in ASIC_DB (queues should be created at init per port)"
    port_oids = {_oid(p) for p in asicdb.objects("SAI_OBJECT_TYPE_PORT")}
    bad = []
    valid = 0
    for q in queues:
        qt = asicdb.field(q, "SAI_QUEUE_ATTR_TYPE")
        idx = _int(asicdb.field(q, "SAI_QUEUE_ATTR_INDEX"))
        port = asicdb.field(q, "SAI_QUEUE_ATTR_PORT")
        # Some QUEUE objects have no cached type/index in ASIC_DB (redis) (created internally by SAI; SONiC does not explicitly write these fields) --
        # this is a redis caching artifact rather than a chip defect; skip them and only validate values for queues that carry attributes.
        if qt is None and idx is None:
            continue
        # The queue index upper bound is a per-port concept: a front-panel port = 8 unicast (0-7) + some multicast -> [0,15].
        # CPU/internal queues (SAI_QUEUE_ATTR_PORT unbound) are used for CoPP, with far more queues than front-panel ports,
        # and a much larger valid index range (multicast index can reach 40+), so for queues with no port binding only validate
        # valid type + non-negative index, without applying the front-panel [0,15] upper bound (otherwise CPU queues are wrongly flagged).
        is_frontpanel = bool(port) and (not port_oids or port in port_oids)
        if port and port_oids and port not in port_oids:
            bad.append((_oid(q), "dangling-port", port))
        elif qt not in _QUEUE_TYPES or idx is None or idx < 0:
            bad.append((_oid(q), qt, idx))
        elif is_frontpanel and idx > 15:
            bad.append((_oid(q), "frontpanel-idx-oob", qt, idx))
        else:
            valid += 1
    assert not bad, f"QUEUE objects with invalid type/index/port: {bad[:10]} (total bad {len(bad)})"
    assert valid > 0, "no QUEUE object in ASIC_DB carries cached type/index attributes"


def test_frontpanel_multicast_queue_structure(asicdb):
    """Front-panel port multicast-queue modeling coverage: each front-panel port should have unicast queues (index 0..k-1) +
    multicast queues (indices immediately following unicast, contiguous). ASIC_DB QUEUE objects do not cache
    SAI_QUEUE_ATTR_PORT (cannot group by port), so use COUNTERS_QUEUE_NAME_MAP (`EthernetX:idx` -> queue oid) to build
    a port->queue mapping, then look up each queue's SAI_QUEUE_ATTR_TYPE in ASIC_DB to classify UC/MC. Verifies multicast
    queues both exist and are contiguous with unicast indices without misalignment (not dangling/not out-of-order),
    confirming front-panel HQoS leaf modeling is correct.
    (CPU/internal queues follow a different model, covered by test_queue_attrs_valid.)"""
    import re as _re
    from collections import defaultdict
    name_map = asicdb.cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
    if not name_map:
        pytest.skip("COUNTERS_QUEUE_NAME_MAP empty; cannot map front-panel port queues")
    by_port = defaultdict(dict)   # EthernetX -> {idx: oid}
    for name, oid in name_map.items():
        m = _re.match(r"(Ethernet\d+):(\d+)$", name)
        if m:
            by_port[m.group(1)][int(m.group(2))] = oid
    ports = [p for p, q in by_port.items() if len(q) >= 8]   # front-panel ports (>=8 queues)
    if not ports:
        pytest.skip("no front-panel port with >=8 queues in COUNTERS_QUEUE_NAME_MAP")
    bad, checked = [], 0
    for p in sorted(ports, key=lambda x: int(x[8:]))[:8]:    # sample at most 8 ports
        uc, mc = [], []
        for idx, oid in by_port[p].items():
            qt = asicdb.field(f"ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:{oid}", "SAI_QUEUE_ATTR_TYPE")
            if qt == "SAI_QUEUE_TYPE_UNICAST":
                uc.append(idx)
            elif qt == "SAI_QUEUE_TYPE_MULTICAST":
                mc.append(idx)
        if not mc:
            bad.append((p, "no-multicast-queue", sorted(by_port[p])))
            continue
        uc.sort(); mc.sort()
        n_uc = len(uc)
        if uc and uc != list(range(n_uc)):
            bad.append((p, "uc-not-0-based-contiguous", uc))
        elif mc[0] != n_uc or mc != list(range(mc[0], mc[0] + len(mc))):
            bad.append((p, "mc-not-contiguous-after-uc", uc, mc))
        else:
            checked += 1
    assert not bad, f"front-panel MC queue structure malformed: {bad[:5]}"
    assert checked > 0, "no front-panel port structurally validated for UC+MC queues"


def test_queue_bound_to_scheduler(asicdb, qos_loaded):
    """Queues bound to schedulers: at least some QUEUE objects' SCHEDULER_PROFILE_ID points to a real existing
    SCHEDULER object (the scheduling tree is truly formed, queues are actually "managed by some scheduling policy",
    not a dangling oid:0x0).

    SONiC typically binds SP/WRR schedulers to each port's queues. If no scheduler is programmed at all -> known buffers.json.j2 defect xfail.
    """
    sched_objs = asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")
    if not sched_objs:
        pytest.fail(_BUFFERS_DEFECT + " [SCHEDULER for queue binding]")
    # All schedulers being bare objects (no SCHEDULING_TYPE) means scheduling policy is not really configured (incomplete qos reload) --
    # in this case queues have no scheduler to bind to; xfail as a known defect rather than hard fail.
    if not any(asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE") for s in sched_objs):
        pytest.fail(_BUFFERS_DEFECT + " [no typed SCHEDULER -> queue scheduling not configured]")
    scheds = {_oid(s) for s in sched_objs}
    queues = asicdb.objects("SAI_OBJECT_TYPE_QUEUE")
    assert queues, "no SAI QUEUE objects in ASIC_DB"
    bound, dangling = 0, []
    for q in queues:
        sp = asicdb.field(q, "SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID")
        if sp and sp != "oid:0x0":
            if sp in scheds:
                bound += 1
            else:
                dangling.append((_oid(q), sp))
    # The binding point differs across implementations: community attaches the profile on the QUEUE attribute; SONiC attaches it on the SCHEDULER_GROUP
    # (SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID, a valid HQoS model).
    for g in asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER_GROUP"):
        sp = asicdb.field(g, "SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID")
        if sp and sp != "oid:0x0":
            if sp in scheds:
                bound += 1
            else:
                dangling.append((_oid(g), sp))
    assert not dangling, f"QUEUE/SCHED_GROUP bound to non-existent SCHEDULER (dangling): {dangling[:10]}"
    assert bound > 0, \
        f"no QUEUE nor SCHEDULER_GROUP bound to any SCHEDULER ({len(scheds)} schedulers exist unreferenced)"


# ============================ WRED ============================
def test_wred_profile_attrs_valid(asicdb, qos_loaded):
    """Each ASIC WRED: at least one color enabled; for that color max_threshold>min_threshold (>0);
    drop_probability in [0,100]; ECN_MARK_MODE is a valid enum. Verifies WRED curve parameters are correct, not just presence."""
    wreds = asicdb.objects("SAI_OBJECT_TYPE_WRED")
    if not wreds:
        pytest.fail(_BUFFERS_DEFECT + " [WRED]")
    bad = []
    for w in wreds:
        attrs = asicdb.cli.db_hgetall("ASIC_DB", w)
        colors_on = []
        for color in ("GREEN", "YELLOW", "RED"):
            en = attrs.get(f"SAI_WRED_ATTR_{color}_ENABLE")
            if en == "true":
                colors_on.append(color)
                mn = _int(attrs.get(f"SAI_WRED_ATTR_{color}_MIN_THRESHOLD"))
                mx = _int(attrs.get(f"SAI_WRED_ATTR_{color}_MAX_THRESHOLD"))
                if mn is None or mx is None or not (0 <= mn < mx):
                    bad.append((_oid(w), color, "thresh", mn, mx))
                dp = _int(attrs.get(f"SAI_WRED_ATTR_{color}_DROP_PROBABILITY"))
                if dp is not None and not (0 <= dp <= 100):
                    bad.append((_oid(w), color, "dropprob", dp))
        ecn = attrs.get("SAI_WRED_ATTR_ECN_MARK_MODE")
        # ECN mode may be omitted (a pure WRED drop profile), but if given it must be a valid enum
        if ecn is not None and not ecn.startswith("SAI_ECN_MARK_MODE_"):
            bad.append((_oid(w), "ecn_mode", ecn))
        if not colors_on and ecn in (None, "SAI_ECN_MARK_MODE_NONE"):
            bad.append((_oid(w), "no-color-enabled-and-no-ecn", None))
    assert not bad, f"WRED profiles with invalid thresholds/probability/ecn: {bad}"



def _buffer_absent_sched(cli, what):
    """Same as test_qos_config._buffer_absent: product CLI-configured images' buffers follow their own model
    (no default SAI pool objects, and profiles do not reference pools) -- template-based checks do not apply,
    structural skip; community images FAIL honestly."""
    if qos.has_qos_cli(cli):
        pytest.skip(f"this image manages buffers via its own CLI model; template-based "
                    f"{what} checks not applicable (structural)")
    pytest.fail(_BUFFERS_DEFECT + f" [{what}]")

# ============================ BUFFER_POOL / BUFFER_PROFILE ============================
def test_buffer_pool_attrs_valid(cli, asicdb, qos_loaded):
    """Each ASIC BUFFER_POOL: type in {ingress,egress,both}, size>0, valid threshold_mode enum.
    Verifies buffer-pool attribute correctness, not just presence."""
    pools = asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL")
    if not pools:
        _buffer_absent_sched(cli, "BUFFER_POOL")
    bad = []
    for p in pools:
        typ = asicdb.field(p, "SAI_BUFFER_POOL_ATTR_TYPE")
        size = _int(asicdb.field(p, "SAI_BUFFER_POOL_ATTR_SIZE"))
        tm = asicdb.field(p, "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE")
        if typ not in _POOL_TYPES or size is None or size <= 0 or \
                (tm is not None and tm not in _THRESH_MODES):
            bad.append((_oid(p), typ, size, tm))
    assert not bad, f"BUFFER_POOL objects with invalid type/size/threshold_mode: {bad}"


def test_buffer_profile_attrs_and_pool_ref(cli, asicdb, qos_loaded):
    """Each ASIC BUFFER_PROFILE: POOL_ID points to a real existing BUFFER_POOL (not dangling); buffer_size is a non-negative integer;
    if dynamic mode then SHARED_DYNAMIC_TH exists. Verifies profile->pool reference consistency + attribute correctness."""
    profs = asicdb.objects("SAI_OBJECT_TYPE_BUFFER_PROFILE")
    if not profs:
        _buffer_absent_sched(cli, "BUFFER_PROFILE")
    pools = {_oid(p) for p in asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL")}
    if not pools and qos.has_qos_cli(cli):
        # SONiC's buffer profiles do not reference SAI pools (own model), so pool_ref semantics do not apply
        pytest.skip("this image's buffer profiles do not reference SAI pools (own buffer "
                    "model, no default SAI_BUFFER_POOL objects); pool-ref check not applicable")
    bad = []
    for pr in profs:
        pool = asicdb.field(pr, "SAI_BUFFER_PROFILE_ATTR_POOL_ID")
        if not pool or pool == "oid:0x0" or (pools and pool not in pools):
            bad.append((_oid(pr), "pool_ref", pool))
            continue
        sz = _int(asicdb.field(pr, "SAI_BUFFER_PROFILE_ATTR_BUFFER_SIZE"))
        if sz is None or sz < 0:
            bad.append((_oid(pr), "buffer_size", sz))
        tm = asicdb.field(pr, "SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE")
        if tm is not None and tm not in _THRESH_MODES:
            bad.append((_oid(pr), "threshold_mode", tm))
    assert not bad, f"BUFFER_PROFILE objects with bad pool_ref/size/threshold: {bad}"


def test_ingress_pg_bound_to_buffer_profile(cli, asicdb, qos_loaded):
    """Ingress priority groups (IPG) bound to a buffer profile: at least some INGRESS_PRIORITY_GROUP objects'
    BUFFER_PROFILE points to a real existing BUFFER_PROFILE (PG really has a buffer quota, not dangling). No profile programmed -> known defect xfail."""
    profs = {_oid(p) for p in asicdb.objects("SAI_OBJECT_TYPE_BUFFER_PROFILE")}
    if not profs:
        _buffer_absent_sched(cli, "BUFFER_PROFILE (PG binding)")
    if not asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL") and qos.has_qos_cli(cli):
        # As above: an own buffer model without SAI pools; PG->profile binding is managed internally, not via SAI PG attributes
        pytest.skip("this image manages PG buffers internally (no SAI pools); "
                    "PG->profile SAI binding check not applicable")
    pgs = asicdb.objects("SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP")
    assert pgs, "no INGRESS_PRIORITY_GROUP objects in ASIC_DB"
    bound, dangling = 0, []
    for pg in pgs:
        bp = asicdb.field(pg, "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE")
        if bp and bp != "oid:0x0":
            if bp in profs:
                bound += 1
            else:
                dangling.append((_oid(pg), bp))
    assert not dangling, f"IPG bound to non-existent BUFFER_PROFILE: {dangling[:10]}"
    assert bound > 0, "no INGRESS_PRIORITY_GROUP references any BUFFER_PROFILE"


# ============================ PFC per-priority (config->ASIC) ============================
def test_pfc_priority_enable_programs_asic(cli, asicdb, topo, config_guard):
    """Enable several PFC priorities on a port -> the ASIC port object's SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL
    bitmap includes those priorities (config->chip closed loop: CLI configures PFC, chip port PFC enable bits are
    actually set), rather than only looking at CONFIG_DB.

    SONiC `config interface pfc priority <iface> <prio> on` adds the priority into the port bitmap.
    Take the port's SAI PORT object and assert the corresponding bitmap bit is set. If the CLI does not support this
    subcommand -> skip (no false pass); if the bitmap is not updated -> FAIL (exposing a config->ASIC break).
    """
    port = topo.misc_port(0).name
    helpr = cli.run("config interface pfc priority")
    if "Usage" not in (helpr.out + helpr.err) and "Error" not in (helpr.out + helpr.err) \
            and helpr.rc not in (0, 2):
        pytest.fail("`config interface pfc priority` CLI not available "
                    "(image should provide per-priority PFC CLI; config->ASIC PFC path cannot be exercised)")

    prios = [3, 4]
    applied = []
    for pr in prios:
        rc, r = cli.config_raw(f"interface pfc priority {port} {pr} on")
        out = r.out + r.err
        assert "Traceback" not in out, f"config interface pfc priority crashed: {out[:200]}"
        if rc != 0:
            # This platform may require lossless queues to be configured first; under a minimal preset it may reject -- the already-applied part is still rolled back
            if not applied:
                pytest.fail("pfc priority enable rejected "
                            f"(image should support per-priority PFC): {out.strip()[:160]}")
            break
        applied.append(pr)
        config_guard.defer_undo(f"interface pfc priority {port} {pr} off")
    assert applied, "no PFC priority could be enabled"

    # Find the port's SAI PORT object (CONFIG_DB PORT order has no direct mapping to ASIC oid, and matching by HOSTIF/port-name is unreliable,
    # so use elimination: the port object whose PFC bitmap is non-zero and matches the bits we set is the target. Poll first to wait for programming).
    want_mask = 0
    for pr in applied:
        want_mask |= (1 << pr)

    def _pfc_masks():
        masks = []
        for k in asicdb.objects("SAI_OBJECT_TYPE_PORT"):
            v = _int(asicdb.field(k, "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"))
            if v:
                masks.append(v)
        return masks

    hit = False
    for _ in range(20):
        masks = _pfc_masks()
        # At least one port object's PFC bitmap contains all the priority bits we enabled
        if any((m & want_mask) == want_mask for m in masks):
            hit = True
            break
        time.sleep(0.5)
    assert hit, (
        f"enabled PFC priorities {applied} on {port} but no ASIC PORT has "
        f"SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL covering mask {want_mask:#x} "
        f"(config→ASIC PFC programming broken)")


# ============================ scheduler weight hot-change (config->ASIC sync) ============================
def test_scheduler_weight_change_reflects_asic(cli, asicdb, qos_loaded):
    """Change a CONFIG_DB SCHEDULER's weight -> orchagent programs the new weight to the ASIC SCHEDULER's
    SCHEDULING_WEIGHT (config hot-change really takes effect on the chip). Operate on a weighted (WRR/DWRR) scheduler.

    No weighted scheduler (buffers.json.j2 missing) -> known defect xfail. No SCHEDULER table in CONFIG_DB -> same.
    Restore the original value when done."""
    # Find a weighted ASIC scheduler's current weight as a baseline
    weighted = [s for s in asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")
                if asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE") in _WEIGHTED]
    if not weighted:
        pytest.fail(_BUFFERS_DEFECT + " [weighted SCHEDULER]")

    # Find a SCHEDULER config entry in CONFIG_DB that has a weight field to change
    sched_keys = cli.db_keys("CONFIG_DB", "SCHEDULER|*")
    target = None
    for k in sched_keys:
        h = cli.db_hgetall("CONFIG_DB", k)
        if h.get("type") in ("WRR", "DWRR") and str(h.get("weight", "")).isdigit():
            target = (k, h)
            break
    if not target:
        pytest.fail(_BUFFERS_DEFECT + " [CONFIG_DB SCHEDULER with weight]")
    key, h = target
    name = key.split("|", 1)[1]
    old_w = int(h["weight"])
    new_w = old_w + 1 if old_w < 100 else old_w - 1

    # Changing the weight uses the image-adaptive channel: community = direct CONFIG_DB edit (schedulerorch listens); SONiC's orch
    # does not consume a bare HSET, so use its `config scheduler update -w`.
    if qos.has_qos_cli(cli):
        cli.config_raw(f"scheduler update {name} -w {new_w}")
    else:
        cli.db("CONFIG_DB", f"HSET 'SCHEDULER|{name}' weight {new_w}")
    try:
        # Poll the ASIC: one weighted scheduler should have SCHEDULING_WEIGHT == new_w
        ok = False
        for _ in range(20):
            cur = {_int(asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT"))
                   for s in asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")
                   if asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE") in _WEIGHTED}
            if new_w in cur:
                ok = True
                break
            time.sleep(0.5)
        assert ok, (
            f"changed CONFIG_DB SCHEDULER|{name}.weight {old_w}->{new_w} but no ASIC SCHEDULER "
            f"shows SCHEDULING_WEIGHT={new_w} (config→ASIC weight update broken)")
    finally:
        if qos.has_qos_cli(cli):
            cli.config_raw(f"scheduler update {name} -w {old_w}")
        else:
            cli.db("CONFIG_DB", f"HSET 'SCHEDULER|{name}' weight {old_w}")
        time.sleep(1)


# ============================ Dataplane: scheduled egress queue count increments with real forwarding ============================
@pytest.mark.traffic
def test_egress_queue_counter_increments(traffic, cli, asicdb, qos_loaded):
    """Loopback traffic -> some SAI_QUEUE_STAT_PACKETS on the injection port ports[0]'s own egress queue
    (a CPU-injected frame egresses first then loops back) increments, and cross-confirm: (1) the incremented queue oid
    really has a SAI_OBJECT_TYPE_QUEUE object in the ASIC (look up each oid in ASIC_DB, not generically);
    (2) the scheduling tree is formed -- that queue's SCHEDULER_PROFILE_ID (or SONiC's SCHEDULER_GROUP-level HQoS binding)
    points to a real existing typed SCHEDULER (queue scheduled -> real forwarding -> chip count closed loop).

    The difference from the generic queue counting in test_stats_full/test_queue_crm is exactly (2): mapping the "incremented queue" to the scheduling tree.
    No typed SCHEDULER = missing qos provisioning (buffers.json.j2 defect); FAIL honestly, consistent with the rest of this module.
    Queue flex counter polling is ~10s by default; confirming read after exit + storm upper bound.
    """
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    qmap = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
    cand = {int(k.split(":")[1]): v for k, v in qmap.items()
            if k.startswith(p_in.name + ":") and k.split(":")[1].isdigit()}
    if not cand:
        pytest.fail(f"no queue oid for {p_in.name} in COUNTERS_QUEUE_NAME_MAP "
                    "(live DUT must expose queue flex counters; empty map = broken counter/dataplane path)")

    def _qpkts(oid):
        v = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}").get("SAI_QUEUE_STAT_PACKETS")
        return int(v) if v is not None and str(v).isdigit() else 0

    from scapy.all import Ether, IP, UDP, Raw
    n = 200
    # Storm upper bound: normal background BUM flooding is thousands~tens of thousands over ~ten seconds, a self-loop storm is millions per second (same calibration as smoke_check)
    storm_cap = 100_000
    # dst static FDB points to ports[1]; after the frame re-enters ports[0] it is unicast-forwarded out (through ports[0]'s egress queue)
    cli.fdb_static_add(traffic.default_vlan, _QDST, p_out.name)
    try:
        base = {q: _qpkts(o) for q, o in cand.items()}
        pkt = (Ether(dst=_QDST, src="00:de:ad:be:ef:72") /
               IP(dst="3.3.3.3") / UDP() / Raw(b"QSCHED" + b"x" * 40))
        traffic.send(p_in, pkt, count=n)
        grew = {}
        for _ in range(16):
            time.sleep(1)
            grew = {q: _qpkts(o) - base[q] for q, o in cand.items() if _qpkts(o) - base[q] > 0}
            if sum(grew.values()) >= n * 0.5:
                break
        # Confirming read + upper bound to guard against storm false positives: normal traffic has settled by now; a self-loop storm is still replicating, pushing the total delta past the upper bound
        time.sleep(1)
        grew = {q: _qpkts(o) - base[q] for q, o in cand.items() if _qpkts(o) - base[q] > 0}
        total = sum(grew.values())
        assert total <= storm_cap, (
            f"loop storm suspected: egress queue deltas on {p_in.name} total {total} > cap "
            f"{storm_cap} for {n} injected pkts (deltas={grew})")
        assert total >= n * 0.5, (
            f"egress queue SAI_QUEUE_STAT_PACKETS did not increment on {p_in.name} "
            f"(sent={n}, deltas={grew})")
        grown_q = max(grew, key=grew.get)
        oid = cand[grown_q]
        # Cross-confirm (1): the incremented queue's oid really has a QUEUE object in the ASIC -- look up each oid in ASIC_DB.
        # (The original assertion `oid in qmap.values()` was a tautology: cand is built from qmap, so it is always true.)
        qkey = f"ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:{oid}"
        assert cli.db_keys("ASIC_DB", qkey), (
            f"grown queue {p_in.name}:{grown_q} counter oid {oid} has no matching "
            f"SAI_OBJECT_TYPE_QUEUE object in ASIC_DB (counter not backed by a real chip queue)")
        # Cross-confirm (2): the scheduling tree is formed. At least one typed SCHEDULER exists; the queue's profile reference (if any) is not dangling;
        # when there is no queue-level reference, accept a SCHEDULER_GROUP-level HQoS binding (attached on the group).
        sched_objs = asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")
        all_scheds = {_oid(s) for s in sched_objs}
        typed = {_oid(s) for s in sched_objs
                 if asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE")}
        if not typed:
            pytest.fail(_BUFFERS_DEFECT +
                        " [no typed SCHEDULER in ASIC -> grown queue cannot be linked to a scheduling tree]")
        sp = cli.db_hgetall("ASIC_DB", qkey).get("SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID")
        if sp and sp != "oid:0x0":
            assert sp in all_scheds, (
                f"grown queue {p_in.name}:{grown_q} bound to non-existent scheduler {sp} (dangling)")
        else:
            group_bound = any(
                (asicdb.field(g, "SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID") or "oid:0x0")
                in typed
                for g in asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER_GROUP"))
            assert group_bound, (
                f"grown queue {p_in.name}:{grown_q} carries no SCHEDULER_PROFILE_ID and no "
                f"SCHEDULER_GROUP references any typed SCHEDULER (scheduling tree not formed; "
                f"queue counter increments outside any scheduler binding)")
    finally:
        cli.fdb_static_del(traffic.default_vlan, _QDST)
