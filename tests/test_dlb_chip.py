"""Standalone DLB (Dynamic Load Balancing) ECMP chip-behaviour suite (vendor-x-sai).

This exercises the standalone-DLB fixes in vendor-x-sai; every check lands on the
**chip logical tables**:

1. Ingress drop (most severe): members joining a DLB group were written FORCE_DOWN
   (`DLB_ECMP_PORT_CONTROL.OVERRIDE=1`), leaving the group with no usable members ->
   100% of packets hitting that route are dropped. After the fix members follow link
   state (OVERRIDE=0) and do not regress after a neighbour relearn.
2. Path quality stuck at "best": port load weight was 0, so the loading term dropped
   out of the quality computation and every member reported quality=7 no matter how
   busy -> DLB degenerates to a static hash. After the fix `DLB_QUALITY_MAP` should be
   quality == port loading, weighed together with TM queue depth.
3. PFC awareness: a member paused by PFC should be recognised by the engine as
   unavailable (filter mode = Idle), and the 4 unicast queues the engine watches must
   follow the **actual lossless config**, not the SDK default 0-3.

Two-level group shape (how standalone DLB is realised): the L1 `ECMP_OVERLAY`
(MAX_PATHS=1) has a single member pointing at the L2 `ECMP_UNDERLAY`, with the DLB
attributes (dynamic mode / ageing / flowset size) hanging off the L2 group.

**On ASIC_DB injection**: SONiC has no config entry point for DLB (see the header
comment in framework/dlb.py), so DLB groups can only be created at the SAI layer.
Apart from the DLB objects under test, everything else (interfaces/IP/neighbours/PFC)
goes through the product CLI or the kernel path.

Every case asserts on **deltas** (a baseline is measured on entry) so it does not
depend on pre-existing ECMP/DLB residue on the device; each case reclaims its own
objects, and the last case does a global health check (no cores, no new
syncd/orchagent errors, port counters intact).
"""
import os
import time

import pytest

from framework import dlb as D
from framework import log as _flog
from framework.l3probe import wait_route as _wait_route

_LOG = _flog.get("dlbtest")

try:
    from scapy.all import IP, UDP, Ether, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False


def _core_files(cli):
    out = cli.sh.run("ls -1 /var/core/ 2>/dev/null", check=False).out
    return {l.strip() for l in out.splitlines() if l.strip()}


def _port_sai_attr(cli, port, attr):
    """Read a SAI attribute of a port object from ASIC_DB (COUNTERS_PORT_NAME_MAP yields the VID).

    The watched queues are driven by the SAI-side pfc_tx, not CONFIG_DB's pfc_enable.
    Confirm the change **actually reached SAI** before asserting whether DLB followed it;
    otherwise a NOS non-push would be misdiagnosed as a DLB defect.
    """
    names = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP") or {}
    vid = names.get(port)
    if not vid:
        return None
    h = cli.db_hgetall("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:%s" % vid) or {}
    return h.get(attr)


def _wait_sai_change(cli, ports, attr, before, timeout=45.0):
    """Wait for some ports' SAI attribute to change relative to `before` (QosOrch push has
    noticeable latency, so a fixed sleep would misjudge it as "not pushed"). On timeout returns
    the last reading, leaving it to the caller to assert or to skip honestly."""
    end = time.time() + timeout
    while True:
        now = {p: _port_sai_attr(cli, p, attr) for p in ports}
        if now != before or time.time() >= end:
            return now
        time.sleep(2.0)


def _sai_errs(cli):
    """Count of syncd/orchagent ERR lines in syslog (a delta tells whether this round added errors)."""
    out = cli.sh.run("grep -cE 'ERR (swss#orchagent|syncd#syncd)' /var/log/syslog 2>/dev/null",
                     check=False).out.strip()
    return int(out) if out.isdigit() else 0

pytestmark = [pytest.mark.dlb, pytest.mark.l3, pytest.mark.chiptab]

_NH1_MAC = "00:aa:bb:00:0d:b1"
_NH2_MAC = "00:aa:bb:00:0d:b2"


# ---------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def dlbnet(l3net, chip):
    """Shared base for the DLB cases: attach one neighbour on each of l3net's two egress ports, yielding two NEXT_HOPs.

    DLB group members must be **existing** NEXT_HOPs (injecting an unknown OID kills syncd),
    so this learns the neighbours through the product path first and then hands their ASIC_DB
    oids to the cases.
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("DLB cases drive SAI objects that SONiC has no config entry for, via the "
                    "sairedis queue; that is intrusive, so they only run with FVT_DLB=1")
    chip.require()
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip (independent DLB unsupported)")
    env = l3net
    cli = env.cli
    h = D.Dlb(cli, chip)
    ip1, ip2 = env.sub_out["peer"], env.sub_o2["peer"]
    cli.neigh_set(ip1, _NH1_MAC, env.p_out.name)
    cli.neigh_set(ip2, _NH2_MAC, env.p_o2.name)
    nh1, nh2 = h.nh_by_ip(ip1), h.nh_by_ip(ip2)
    if not nh1 or not nh2:
        pytest.fail("neighbours %s/%s did not produce SAI next hops in ASIC_DB "
                    "(cannot build a DLB group without members)" % (ip1, ip2))
    import types
    yield types.SimpleNamespace(
        cli=cli, chip=chip, env=env, nh1=nh1, nh2=nh2, ip1=ip1, ip2=ip2,
        base_cores=_core_files(cli), base_errs=_sai_errs(cli),
        port1=chip.port_id(env.p_out.name), port2=chip.port_id(env.p_o2.name),
        p1=env.p_out, p2=env.p_o2)
    for ip, p in ((ip1, env.p_out), (ip2, env.p_o2)):
        try:
            cli.neigh_del(ip, p.name)
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture
def dlb(dlbnet):
    """A clean orchestrator per case; on exit reclaims the objects this case created in reverse order."""
    h = D.Dlb(dlbnet.cli, dlbnet.chip)
    yield h
    h.cleanup()


def _refresh(dlb, net):
    """The base next hops may have been swept away by another case; confirm they still exist before use, and re-resolve by IP if not.

    The module-level fixture resolves the oids only once at setup; any case that reset ports
    invalidates them, and injecting with a stale oid kills syncd. Do a cheap self-heal here to
    avoid sacrificing the device.
    """
    for attr, ip in (("nh1", net.ip1), ("nh2", net.ip2)):
        oid = getattr(net, attr)
        if not dlb.nh_alive(oid):
            fresh = dlb.nh_by_ip(ip, timeout=25.0)
            assert fresh, ("next hop for %s is gone and could not be re-resolved: the L3 base "
                           "was torn down by another case" % ip)
            _LOG.info("re-resolved %s: %s -> %s", attr, oid, fresh)
            setattr(net, attr, fresh)


def _group_with_members(dlb, net, gtype=D.TYPE_DLB_ELIGIBLE):
    """Create a group + attach two members on different egress ports. Fail if any step does not take (no half-way assertions)."""
    _refresh(dlb, net)
    g = dlb.create_group(gtype)
    assert g, ("DLB group type %d was not created (no RID in ASIC_DB): the SAI layer "
               "rejected an independent DLB group" % gtype)
    m1 = dlb.add_member(g, net.nh1, n=1)
    m2 = dlb.add_member(g, net.nh2, n=2)
    assert m1 and m2, ("DLB member create failed (m1=%s m2=%s): members must be able to join "
                       "an independent DLB group" % (m1, m2))
    return g, m1, m2


# ---------------------------------------------------------------- group lifecycle
@pytest.mark.parametrize("name,gtype", D.DLB_TYPES)
def test_dlb_group_create_and_free(dlb, dlbnet, name, gtype):
    """All three DLB group types create, produce an L1 group, and return every chip resource after delete.

    Observed programming order (do not assume): **an empty group only lays down the L1
    `ECMP_OVERLAY`** (NUM_PATHS/MAX_PATHS=1); the L2 `ECMP_UNDERLAY` and the `DLB_ECMP` engine
    instance only appear once members join (for the member-populated shape see
    test_dlb_two_level_group_shape). After deleting the group all three tables must return to
    baseline — a leak shows up here.
    """
    base = dlb.counts()
    g = dlb.create_group(gtype)
    assert g, "DLB group type %s (%d) not created" % (name, gtype)
    after = dlb.counts()
    assert after["ECMP_OVERLAY"] == base["ECMP_OVERLAY"] + 1, (
        "DLB %s group: ECMP_OVERLAY went %d -> %d, expected +1 (the L1 group is created with "
        "the group itself)" % (name, base["ECMP_OVERLAY"], after["ECMP_OVERLAY"]))

    assert dlb.remove(g, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP"), \
        "DLB %s group %s still has a RID after remove" % (name, g)
    end = dlb.counts()
    assert end == base, ("DLB %s group leaked chip resources: %s (baseline %s)"
                         % (name, end, base))


def test_dlb_two_level_group_shape(dlb, dlbnet):
    """Standalone DLB's two-level shape: L1 OVERLAY(MAX_PATHS=1) single member = L2 UNDERLAY, with both members on the L2.

    This is the structural difference between standalone DLB and plain ECMP; if the L1 is not
    1-path or does not point at the L2, the group was not built as standalone DLB (it degenerates
    to plain ECMP and the DLB attributes have nowhere to live).
    """
    base_ol = {e.get("ECMP_ID") for e in dlb.overlay()}
    base_ul = {e.get("ECMP_ID") for e in dlb.underlay()}
    _group_with_members(dlb, dlbnet)

    new_ol = [e for e in dlb.overlay() if e.get("ECMP_ID") not in base_ol]
    new_ul = [e for e in dlb.underlay() if e.get("ECMP_ID") not in base_ul]
    _LOG.info("new L1 entries: %s", new_ol)
    _LOG.info("new L2 entries: %s", new_ul)
    _LOG.info("DLB engine entries: %s", dlb.dlb_ecmp())
    assert len(new_ol) == 1 and len(new_ul) == 1, (
        "expected exactly one new L1 and one new L2 group, got L1=%d L2=%d"
        % (len(new_ol), len(new_ul)))
    ol, ul = new_ol[0], new_ul[0]

    assert ol.get("MAX_PATHS") == 1, (
        "L1 overlay group MAX_PATHS=%s, expected 1 (independent DLB puts a single L2 group "
        "under the L1 group)" % ol.get("MAX_PATHS"))
    assert ol.get("NUM_PATHS") == 1, "L1 overlay NUM_PATHS=%s, expected 1" % ol.get("NUM_PATHS")
    child = D.field_at(ol, "ECMP_UNDERLAY_ID", 0)
    assert child == ul.get("ECMP_ID"), (
        "L1 overlay member points at underlay id %s, but the new L2 group is %s"
        % (child, ul.get("ECMP_ID")))
    assert D.field_at(ol, "ECMP_NHOP_UNDERLAY", 0) == 1, (
        "L1 overlay member 0 is not flagged as an underlay group: the L1 group would point at "
        "a plain next hop and the DLB attributes would have nowhere to live")
    assert ul.get("NUM_PATHS") == 2, (
        "L2 underlay NUM_PATHS=%s, expected 2 (both next hops joined)" % ul.get("NUM_PATHS"))
    assert str(ul.get("LB_MODE")) == "DYNAMIC", (
        "L2 underlay LB_MODE=%s, expected DYNAMIC: without it the group is a plain static "
        "hash group and nothing about DLB is in effect" % ul.get("LB_MODE"))

    ents = dlb.dlb_ecmp()
    assert ents, "no DLB_ECMP engine entry after creating a DLB group"
    eng = ents[-1]
    assert eng.get("NUM_PATHS") == 2, (
        "DLB engine NUM_PATHS=%s, expected 2" % eng.get("NUM_PATHS"))
    assert eng.get("INACTIVITY_TIME") == 256, (
        "DLB inactivity time is %s, expected the 256 default (0 means flows are never "
        "re-assigned and DLB never rebalances)" % eng.get("INACTIVITY_TIME"))
    assert "256" in str(eng.get("FLOW_SET_SIZE")), (
        "DLB flow set size is %s, expected the 256 default" % eng.get("FLOW_SET_SIZE"))
    ports = {D.field_at(eng, "PORT_ID", 0), D.field_at(eng, "PORT_ID", 1)}
    assert ports == {dlbnet.port1, dlbnet.port2}, (
        "DLB engine is tracking chip ports %s but the members egress on %s (%s/%s): the engine "
        "would measure the wrong ports" % (sorted(ports), sorted([dlbnet.port1, dlbnet.port2]),
                                           dlbnet.p1.name, dlbnet.p2.name))


# ---------------------------------------------------------------- member state (ingress drop)
def test_dlb_members_are_not_forced_down(dlb, dlbnet):
    """A DLB member must not be forced down after it joins.

    Before the fix a member was written FORCE_DOWN (OVERRIDE=1, ARS semantics: a port that did
    not explicitly opt into ARS takes no DLB flows); standalone DLB has no per-port opt-in, so
    every member was kicked out of the group -> 100% of packets hitting that route are dropped.
    After the fix the member follows the link (OVERRIDE=0).
    """
    _group_with_members(dlb, dlbnet)
    for pid, name in ((dlbnet.port1, dlbnet.p1.name), (dlbnet.port2, dlbnet.p2.name)):
        ov = dlb.port_override(pid)
        assert ov is not None, (
            "no DLB_ECMP_PORT_CONTROL entry for %s (chip port %s): member port not "
            "programmed into the DLB engine" % (name, pid))
        assert ov == 0, (
            "DLB member port %s (chip port %s) is force-overridden (OVERRIDE=%s): the member "
            "is out of its group and every packet hitting the route is dropped" % (name, pid, ov))


def test_dlb_member_survives_neighbour_relearn(dlb, dlbnet):
    """After a neighbour ages out and is re-learned, the member is still in the group and not forced down.

    Member state is recomputed on every neighbour event; before the fix this path kicked the
    member out of the group **permanently** (sneakier than the first-join case: works first,
    then goes dark).
    """
    _g, m1, _m2 = _group_with_members(dlb, dlbnet)
    cli = dlbnet.cli
    cli.neigh_del(dlbnet.ip1, dlbnet.p1.name)
    time.sleep(6)
    cli.neigh_set(dlbnet.ip1, _NH1_MAC, dlbnet.p1.name)
    time.sleep(10)

    assert dlb.has(m1), "DLB member disappeared after the neighbour was re-learned"
    ov = dlb.port_override(dlbnet.port1)
    assert ov == 0, (
        "after neighbour re-learn DLB member port %s has OVERRIDE=%s: the member was taken "
        "out of its group for good (traffic on that path goes dark)" % (dlbnet.p1.name, ov))


# ---------------------------------------------------------------- path quality
_DLB_LOAD_WEIGHT = 70       # driver's default port load weight for standalone DLB


def test_dlb_quality_tracks_load_and_queue_depth(dlb, dlbnet, chip):
    """The quality quantisation map a DLB member port uses must be driven by both port loading and TM queue depth.

    This implementation has no per-port-queue depth dimension (that weight is forced to INVALID
    at the API layer), so the SDK gives all the remaining weight to TM queue depth and the
    quantisation map is `quality = (loading*w + tm_depth*(100-w)) / 100`.

    Why we cannot assert `quality == loading`: that is the `w=100` shape, in which the queue
    column is completely dead — a member held down by PFC stops sending, its loading reads 0, so
    while its queue overflows it gets the best quality in the whole map and DLB preferentially
    places new flows on it. The driver therefore lowers w to 70, giving queue depth 30%.

    **Multiple maps coexist on the chip** (`DLB_QUALITY_MAP_ID=0` is the SDK default w=100 map,
    `=1` is the driver-built w=70 map, 64 rows each), and each port points at one of them via
    `DLB_PORT_CONTROL`. So the check must **first see which map the member port points at, then
    compare that map** — mixing the two maps together makes half match w=100 and half w=70,
    which looks like "half the table is filled in wrong" (this case's previous version misreported
    exactly that way).
    """
    _group_with_members(dlb, dlbnet)
    w = _DLB_LOAD_WEIGHT

    rows = chip.traverse("DLB_QUALITY_MAP") or []
    assert rows, "DLB_QUALITY_MAP is empty: the DLB engine has no quality quantisation programmed"
    maps = {}
    for r in rows:
        if "QUALITY" not in r or "QUANTIZED_AVG_PORT_LOADING" not in r:
            continue
        maps.setdefault(r.get("DLB_QUALITY_MAP_ID", 0), []).append(
            (r["QUANTIZED_AVG_PORT_LOADING"], r.get("QUANTIZED_AVG_TM_QUEUE_SIZE"),
             r["QUALITY"]))

    used = set()
    for port in (dlbnet.port1, dlbnet.port2):
        ent = chip.lookup("DLB_PORT_CONTROL", PORT_ID=port) or {}
        if "DLB_QUALITY_MAP_ID" in ent:
            used.add(ent["DLB_QUALITY_MAP_ID"])
    assert used, (
        "neither DLB member port (%s, %s) names a quality map in DLB_PORT_CONTROL: the engine "
        "cannot score them at all" % (dlbnet.port1, dlbnet.port2))
    assert len(used) == 1, (
        "the two members of one DLB group point at different quality maps %s: they would be "
        "scored on different scales and the comparison between them is meaningless" % sorted(used))
    mid = used.pop()
    table = maps.get(mid)
    assert table, "DLB member ports point at quality map %s, which has no rows" % mid

    assert all(t is not None for _l, t, _q in table), (
        "quality map %s has no TM queue size column: the engine cannot weigh queue depth" % mid)
    qualities = {q for _l, _t, q in table}
    assert len(qualities) > 1, (
        "DLB quality is constant at %s across quality map %s: every member reports the same "
        "quality however loaded it is (port load weight lost)" % (qualities.pop(), mid))

    bad = [(l, t, q, (l * w + t * (100 - w)) // 100)
           for l, t, q in table if q != (l * w + t * (100 - w)) // 100]
    assert not bad, (
        "the quality map the DLB members use (id %s) does not match "
        "(loading*%d + tm_depth*%d)/100 for %d of %d entries (load, queue, got, expected - "
        "first few: %s): the engine is not weighing the two inputs the way the driver asked for"
        % (mid, w, 100 - w, len(bad), len(table), bad[:4]))

    degenerate = all(q == l for l, _t, q in table)
    assert not degenerate, (
        "quality map %s is the identity on port loading: the members are scored with the queue "
        "column dead, so a PFC paused member reads as idle and scores best" % mid)

    # Monotonicity: if either dimension gets worse, quality must not get better. Independent of
    # the formula, this catches "formula right but table filled in backwards".
    q_of = {(l, t): q for l, t, q in table}
    for (l, t), q in q_of.items():
        for nxt in ((l + 1, t), (l, t + 1)):
            if nxt in q_of:
                assert q_of[nxt] >= q, (
                    "quality drops from %d to %d going from load/queue %s to %s in map %s: a "
                    "more loaded member must not score better" % (q, q_of[nxt], (l, t), nxt, mid))
    _LOG.info("DLB members use quality map %s: %d rows, exact fit at load weight %d",
              mid, len(table), w)


# ---------------------------------------------------------------- PFC awareness
def test_dlb_pfc_filter_mode_enabled(dlb, dlbnet):
    """The DLB engine's PFC filter mode must be on (Idle semantics).

    With it off, a member paused by PFC still takes part in path selection and new flows get sent
    to a port that is being back-pressured; Idle semantics only keep paused members out of
    "new flows / timeout reassignment" while leaving established flows put — the right behaviour
    for a lossless scenario.

    **The member count must cross the allocation increment**: this assertion originally created
    only 2 members, and a group is not REPLACEd wholesale while it stays within the first
    increment (4 on this platform), so it missed the real defect where "the filter is zeroed when
    the group grows on member add" and gave four rounds of review false confidence. This bumps it
    to 6 members to guarantee the REPLACE path is exercised.
    """
    _refresh(dlb, dlbnet)
    g = dlb.create_group(D.TYPE_DLB_ELIGIBLE)
    assert g, "DLB group not created"
    for n, oid in enumerate((dlbnet.nh1, dlbnet.nh2) * 3, start=1):
        assert dlb.add_member(g, oid, n=n, settle=3.0), "member %d could not be added" % n
    # Only look at the engine entry that actually has members: the table may still hold an
    # all-zero default entry, and reading that one yields the opposite conclusion (this reading
    # trap has misled us twice).
    ents = [e for e in dlb.dlb_ecmp() if e.get("NUM_PATHS")]
    assert ents, "no DLB engine entry with members"
    eng = ents[-1]
    mode = eng.get("PFC_STATUS_FILTER_MODE")
    assert mode is not None, "DLB engine entry has no PFC status filter mode field"
    assert str(mode).upper() not in ("DISABLED", "0", "NONE"), (
        "DLB PFC status filter is %s on a %s member group: members paused by PFC still take "
        "new flows" % (mode, eng.get("NUM_PATHS")))


def test_dlb_watched_queues_match_lossless_config(dlb, dlbnet):
    """The 4 unicast queues the engine watches must match the device's actual lossless config, not the SDK default 0-3.

    The expected value is computed live from the product config (each port's pfc_enable + the
    bound PFC-priority->queue map), not hard-coded: take the 4 lowest lossless queues across the
    whole device in ascending order, padding with the smallest non-lossless queues if there are
    fewer than 4 (the padding entries never pause).
    """
    cli = dlbnet.cli
    want = D.expected_watched(cli)
    if want is None:
        pytest.skip("no lossless priority configured on this device: the watched queue set is "
                    "left untouched by design, nothing to assert")
    _group_with_members(dlb, dlbnet)
    got = dlb.watched_queues()
    assert len(got) == 4, "DLB watches %d queues, expected 4: %s" % (len(got), got)
    assert set(got) == set(want), (
        "DLB watched queues %s do not match the lossless config %s (lossless queues on this "
        "device: %s): a member paused on a lossless queue would not be recognised as paused"
        % (sorted(got), sorted(want), sorted(D.lossless_queues(cli))))


def _pick_pfc_mutation(cli):
    """Pick a PFC change that **actually** moves the watched window; return (plan, expected).

    Returns (prep, plan, want): prep is applied first and **must not** move the window; plan is
    the change under test; both are [(port, prio, "on"|"off"), ...]. Selection rules (each one
    learned on real hardware):
      - The watched set only takes the 4 lowest lossless queues, so turning off a high priority
        often changes nothing; every candidate must be **dry-run** (D.expected_watched's on/off
        args) and the one whose expected value really changes is chosen;
      - **Prefer "on" over "off"**: when a port's pfc_enable is reduced to empty, this NOS's
        QosOrch does not push the empty bitmap to SAI (observed: CONFIG_DB changes but
        SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL does not);
      - this NOS's `config interface pfc priority` **only accepts 1-7**, priority 0 cannot be added;
      - so when the only viable change would empty some port, first add a priority **already in
        the union** on that port as prep (the union is unchanged -> the window does not move),
        then make the real change, to avoid hitting the NOS behaviour above;
      - only pick ports with no BUFFER_PG and no bound PFC map: on this NOS PFC and PG buffer
        config cannot coexist.
    Returns (None, None, None) if none can be picked.
    """
    base = D.expected_watched(cli)
    cfg = D.pfc_config(cli)
    usable = [p for p, v in sorted(cfg.items())
              if not v[1] and not cli.db_keys("CONFIG_DB", "BUFFER_PG|%s|*" % p)]
    if not base or not usable:
        return None, None, None
    enabled = {q for p in usable for q in cfg.get(p, (set(), ""))[0]}
    for prio in range(1, 8):                    # try "on" first (0 is not a valid input)
        if prio in enabled:
            continue
        want = D.expected_watched(cli, on={(usable[0], prio)})
        if want and set(want) != set(base):
            return [], [(usable[0], prio, "on")], want
    for prio in sorted(enabled):                # then try "off", adding prep first if needed
        off = {(p, prio) for p in usable if prio in cfg.get(p, (set(), ""))[0]}
        want = D.expected_watched(cli, off=off)
        if not want or set(want) == set(base):
            continue
        prep, ok = [], True
        for p, _q in off:
            if cfg[p][0] != {prio}:             # the port still has other priorities, won't be emptied
                continue
            filler = next((f for f in range(1, 8)
                           if f != prio and f in enabled and f not in cfg[p][0]), None)
            if filler is None:
                ok = False
                break
            prep.append((p, filler, "on"))
        if ok:
            return prep, [(p, q, "off") for p, q in sorted(off)], want
    return None, None, None


def test_dlb_watched_queues_follow_pfc_change(dlb, dlbnet):
    """Change the lossless config at runtime and the watched queues must follow; after reverting they must return to the original.

    Goes through the product CLI `config interface pfc priority <port> <prio> on|off` and
    **reads back CONFIG_DB for the verdict** (on this NOS a rejected config still returns rc=0).
    """
    cli = dlbnet.cli
    prep, plan, want = _pick_pfc_mutation(cli)
    if not plan:
        pytest.skip("no single PFC change on this device would move the watched window (the "
                    "four lowest lossless queues stay the same): nothing observable to assert")

    _group_with_members(dlb, dlbnet)

    attr = "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"
    done = []
    if prep:
        prep_before = {p: _port_sai_attr(cli, p, attr) for p, _q, _a in prep}
        for port, prio, action in prep:
            cli.config_raw("interface pfc priority %s %d %s" % (port, prio, action))
            done.append((port, prio, "off" if action == "on" else "on"))
        prep_after = _wait_sai_change(cli, [p for p, _q, _a in prep], attr, prep_before)
        _LOG.info("prep %s: SAI %s -> %s (must not move the window)",
                  prep, prep_before, prep_after)
    baseline_watch = _wait_watch(dlb, D.expected_watched(cli))
    sai_before = {p: _port_sai_attr(cli, p, attr) for p, _q, _a in plan}
    try:
        for port, prio, action in plan:
            cli.config_raw("interface pfc priority %s %d %s" % (port, prio, action))
            done.append((port, prio, "off" if action == "on" else "on"))
        time.sleep(3)
        bad = [(p, q, a) for p, q, a in plan
               if (q in D.pfc_config(cli).get(p, (set(), ""))[0]) != (a == "on")]
        if bad:
            pytest.skip("DEVICE CLI: `config interface pfc priority` did not take on %s" % bad)
        sai_now = _wait_sai_change(cli, [p for p, _q, _a in plan], attr, sai_before)
        _LOG.info("plan %s, SAI pfc bitmap %s -> %s", plan, sai_before, sai_now)
        if sai_now == sai_before:
            pytest.skip("the NOS did not push the PFC change down to SAI (%s unchanged at %s): "
                        "the DLB engine has no way to see it — a NOS/QoS issue, not DLB"
                        % (attr, sai_before))
        got = _wait_watch(dlb, want)
        assert set(got) == set(want), (
            "after %s the DLB watched queues are %s, expected %s (was %s): the engine did not "
            "follow the lossless config" % (plan, sorted(got), sorted(want),
                                            sorted(baseline_watch)))
    finally:
        for port, prio, action in done:
            cli.config_raw("interface pfc priority %s %d %s" % (port, prio, action))
        time.sleep(4)
    got = _wait_watch(dlb, baseline_watch)
    assert set(got) == set(baseline_watch), (
        "DLB watched queues did not return to %s after the PFC config was restored "
        "(now %s, lossless queues now %s)"
        % (sorted(baseline_watch), sorted(got), sorted(D.lossless_queues(cli))))


def test_dlb_watched_queues_follow_qos_map_content(dlb, dlbnet):
    """Rewrite the content of an **already bound** PFC-priority->queue map and the watched queues must follow.

    This path has no product CLI (SONiC only rebuilds the qos maps wholesale from templates on
    `config qos reload`, and that command wipes the QoS config on this HWSKU), so following the
    framework's existing convention it writes CONFIG_DB directly — structurally identical to what
    the templates generate, with the same qosorch consumption path. The case creates and deletes
    its own objects, unbinding and deleting the map on exit.
    """
    cli = dlbnet.cli
    # Pick a change that "remaps one port/priority to a different queue", requiring the dry-run
    # expected value to really change; the port under test need not be a DLB member port (the
    # watched set is switch-level), only that it has a lossless priority and no map bound.
    port = prio = newq = None
    base_want = D.expected_watched(cli)
    for p, (prios, mapname) in sorted(D.pfc_config(cli).items()):
        if mapname:
            continue
        for pr in sorted(prios):
            for q in range(8):
                if q == pr:
                    continue
                w = D.expected_watched(cli, remap={(p, pr): q})
                if w and base_want and set(w) != set(base_want):
                    port, prio, newq = p, pr, q
                    break
            if port:
                break
        if port:
            break
    if not port:
        pytest.skip("no PFC map edit on this device would move the watched window: nothing "
                    "observable to assert")
    key = "PORT_QOS_MAP|%s" % port
    mapname = "FVTDLB_PFCQ"
    mapkey = "PFC_PRIORITY_TO_QUEUE_MAP|%s" % mapname

    _group_with_members(dlb, dlbnet)
    baseline_watch = _wait_watch(dlb, base_want)
    try:
        for p in range(8):                      # first build an identity map and bind it: the watched set must not change
            cli.db_hset("CONFIG_DB", mapkey, str(p), p)
        # This device's qos map references are **bare names** (like dscp_to_tc_map='default');
        # writing them as [TABLE|name] is rejected by orchagent ("malformed reference ... Must
        # not be surrounded by [ ]").
        cli.db_hset("CONFIG_DB", key, "pfc_to_queue_map", mapname)
        time.sleep(4)
        got = _wait_watch(dlb, baseline_watch)
        assert set(got) == set(baseline_watch), (
            "binding an identity PFC map changed the watched queues %s -> %s; it must not"
            % (sorted(baseline_watch), sorted(got)))

        bound = _port_sai_attr(cli, port, "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP")
        if not bound or bound == "oid:0x0":
            # Characterised on SONiC: writing PORT_QOS_MAP.pfc_to_queue_map at runtime
            # **does not trigger QosOrch at all** (no "Applied QoS maps to ports(...)" log, no new
            # QOS_MAP object in ASIC_DB), whereas a pfc_enable change on the same table does. Since
            # the binding never reaches SAI, a map content change cannot reach the DLB engine
            # either — a NOS QoS capability gap, not a DLB defect. On a NOS that supports runtime
            # rebinding this case takes effect automatically.
            pytest.skip("this NOS does not apply PORT_QOS_MAP.pfc_to_queue_map at runtime "
                        "(%s has no SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP after binding, "
                        "attr=%r, and QosOrch logs nothing): the map edit cannot reach the DLB "
                        "engine on this device — a NOS QoS gap, not a DLB defect" % (port, bound))

        cli.db_hset("CONFIG_DB", mapkey, str(prio), newq)   # content change: prio -> newq
        time.sleep(4)
        want = D.expected_watched(cli)
        _LOG.info("map edit on %s: priority %d -> queue %d, expect watched %s",
                  port, prio, newq, want)
        got = _wait_watch(dlb, want)
        assert set(got) == set(want), (
            "after moving lossless priority %d to queue %d in the bound PFC map, the DLB "
            "watched queues are %s, expected %s: a running map edit is not picked up"
            % (prio, newq, sorted(got), sorted(want)))
    finally:
        cli.sh.run("sonic-db-cli CONFIG_DB HDEL '%s' pfc_to_queue_map" % key, check=False)
        cli.sh.run("sonic-db-cli CONFIG_DB DEL '%s'" % mapkey, check=False)
        time.sleep(4)
    got = _wait_watch(dlb, baseline_watch)
    assert set(got) == set(baseline_watch), (
        "watched queues did not return to %s after the test PFC map was removed (now %s)"
        % (sorted(baseline_watch), sorted(got)))


def _wait_watch(dlb, want, timeout=12.0):
    """The watched queues are programmed asynchronously; wait for them to converge to the expected value (on timeout return the last reading for the assertion message)."""
    got = dlb.watched_queues()
    if want is None:
        return got
    end = time.time() + timeout
    while set(got) != set(want) and time.time() < end:
        time.sleep(1.0)
        got = dlb.watched_queues()
    return got


# ---------------------------------------------------------------- interaction with existing features
def test_dlb_coexists_with_regular_ecmp(dlb, dlbnet):
    """A plain ECMP group and a DLB group coexist: each is created, they do not interfere, and the plain group is intact after the DLB group is deleted.

    Standalone DLB changes switch-level config (engine init, hash offset, PFC watched queues), so
    it must be shown not to corrupt an existing plain ECMP group — the minimal sufficient
    evidence of "no adverse impact on existing features".
    """
    _refresh(dlb, dlbnet)
    base = dlb.counts()
    ecmp = dlb.create_group(D.TYPE_ECMP, n=5)
    assert ecmp, "plain ECMP group could not be created"
    em = dlb.add_member(ecmp, dlbnet.nh1, n=5)
    assert em, "plain ECMP member could not be added"
    mid = dlb.counts()

    g, _m1, _m2 = _group_with_members(dlb, dlbnet)
    assert dlb.has(ecmp) and dlb.has(em), \
        "plain ECMP group/member lost their RID after a DLB group was created"

    for vid in (dlb.member_vid(1), dlb.member_vid(2)):
        dlb.remove(vid, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER")
    assert dlb.remove(g, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP"), \
        "DLB group could not be removed while a plain ECMP group exists"
    assert dlb.has(ecmp) and dlb.has(em), \
        "plain ECMP group/member disappeared when the DLB group was torn down"
    after = dlb.counts()
    assert after["ECMP_UNDERLAY"] == mid["ECMP_UNDERLAY"], (
        "tearing down the DLB group also freed the plain ECMP group: ECMP_UNDERLAY %d -> %d "
        "(expected %d)" % (mid["ECMP_UNDERLAY"], after["ECMP_UNDERLAY"], mid["ECMP_UNDERLAY"]))

    dlb.remove(em, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER")
    dlb.remove(ecmp, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP")
    assert dlb.counts() == base, "coexistence test leaked chip resources"


def test_dlb_group_grows_past_the_allocation_increment(dlb, dlbnet):
    """A DLB group's MAX_PATHS is the **allocation increment**, not a member ceiling — it must grow past the increment.

    Background: a two-member group reads back `MAX_PATHS=4`, easily misread as "an L2 DLB group
    can only hold 4 members". In fact `_vendor-x_SAI_DLB_MAX_PATHS()` rounds the member count up
    to a multiple of `sai_ecmp_group_members_increment`, and this platform does not set that
    attribute so it uses the default. This case learns several extra neighbours on the same egress
    port (members need not be spread across ports), pushes the group past one increment, and
    confirms MAX_PATHS grows accordingly with all members in place.
    """
    cli = dlbnet.cli
    port = dlbnet.p1
    sub = dlbnet.env.sub_out
    base_ip = sub["peer"].rsplit(".", 1)[0]
    extra = ["%s.%d" % (base_ip, n) for n in range(211, 217)]      # 6 extra neighbours
    nhs = []
    try:
        for i, ip in enumerate(extra):
            cli.neigh_set(ip, "00:aa:bb:00:0e:%02x" % i, port.name)
        for ip in extra:
            oid = dlb.nh_by_ip(ip, timeout=25.0)
            if oid:
                nhs.append(oid)
        if len(nhs) < 5:
            pytest.skip("only %d extra next hops came up: cannot exceed the allocation "
                        "increment on this device" % len(nhs))

        base_ul = {e.get("ECMP_ID") for e in dlb.underlay()}
        g = dlb.create_group(D.TYPE_DLB_ELIGIBLE)
        assert g, "DLB group not created"
        seen = []
        for n, oid in enumerate(nhs, start=1):
            m = dlb.add_member(g, oid, n=n)
            assert m, "DLB member %d/%d could not be added" % (n, len(nhs))
            seen.append(m)

        new_ul = [e for e in dlb.underlay() if e.get("ECMP_ID") not in base_ul]
        assert len(new_ul) == 1, "expected one new L2 group, got %d" % len(new_ul)
        ul = new_ul[0]
        _LOG.info("%d members -> NUM_PATHS=%s MAX_PATHS=%s",
                  len(seen), ul.get("NUM_PATHS"), ul.get("MAX_PATHS"))
        assert ul.get("NUM_PATHS") == len(seen), (
            "L2 group carries NUM_PATHS=%s but %d members were added: members were silently "
            "dropped" % (ul.get("NUM_PATHS"), len(seen)))
        assert ul.get("MAX_PATHS") >= len(seen), (
            "L2 group MAX_PATHS=%s is below its %d members: the group did not grow past the "
            "allocation increment (this is the real member ceiling if it never grows)"
            % (ul.get("MAX_PATHS"), len(seen)))
        eng = dlb.dlb_ecmp()[-1]
        assert eng.get("NUM_PATHS") == len(seen), (
            "DLB engine tracks NUM_PATHS=%s for %d members" % (eng.get("NUM_PATHS"), len(seen)))
    finally:
        for ip in extra:
            try:
                cli.neigh_del(ip, port.name)
            except Exception:  # noqa: BLE001
                pass


def test_plain_ecmp_hashing_survives_dlb(dlb, dlbnet):
    """**DLB's impact on plain ECMP**: the plain ECMP data-plane hash spread must keep working while a DLB group is present and after it is torn down.

    Why this must be tested: DLB engine init changes **switch-level** config
    (`bcmSwitchEcmpDynamicHashOffset`, `bcmSwitchHashUseFlowSelEcmpDynamic`, quality map, PFC
    watched queues), and these **do not roll back** when the DLB group is deleted (engine init
    only runs on the 0->1 transition). So merely "having created a DLB group" can corrupt plain
    ECMP path selection on the same device — not detectable by looking at DLB's own tables alone.

    Criteria: on the same plain ECMP route (two egress ports), inject N packets with varying
    5-tuples; in all three phases (before DLB / DLB group present / after DLB torn down) both
    egress ports must receive traffic, the total is close to N, and there is no storm.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    env = dlbnet.env
    cli, dut, bsh = env.cli, env.dut, env.bsh
    p_in, p1, p2 = env.p_in, env.p_out, env.p_o2
    rmac = env.rmac
    if not rmac:
        pytest.fail("router MAC not found")
    ecmp_net = "10.252.44.0/24"
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s"
               % (ecmp_net, env.sub_out["peer"], env.sub_o2["peer"]), check=False)
    try:
        if not _wait_route(cli, ecmp_net):
            pytest.fail("ECMP route %s never entered the kernel" % ecmp_net)

        before = _ecmp_spread(env, p_in, p1, p2, rmac, bsh, dut)
        assert min(before) > 0, (
            "baseline plain ECMP is already broken before any DLB group exists (per port TX "
            "%s): cannot attribute anything to DLB" % (before,))

        _group_with_members(dlb, dlbnet)
        during = _ecmp_spread(env, p_in, p1, p2, rmac, bsh, dut)
        assert min(during) > 0, (
            "with a DLB group present, plain ECMP stopped spreading across its members "
            "(per port TX %s, was %s): the DLB engine init broke plain ECMP hashing"
            % (during, before))

        dlb.cleanup()
        time.sleep(5)
        after = _ecmp_spread(env, p_in, p1, p2, rmac, bsh, dut)
        assert min(after) > 0, (
            "after the DLB group was removed, plain ECMP no longer spreads (per port TX %s, "
            "baseline %s): the switch level state DLB left behind broke plain ECMP hashing"
            % (after, before))
        _LOG.info("plain ECMP per port TX: before=%s during=%s after=%s", before, during, after)
    finally:
        cli.sh.run("ip route del %s" % ecmp_net, check=False)


_ECMP_N = 60                # packets injected per phase (small count + upper-bound assertion guards against a runaway storm)
_ECMP_STORM = 100000


def _ecmp_spread(env, p_in, p1, p2, rmac, bsh, dut):
    """Inject _ECMP_N packets with varying 5-tuples; return the chip TX deltas of the two egress ports."""
    from framework.counters import ChipCounters
    ChipCounters.clear(bsh)
    for i in range(_ECMP_N):
        pkt = (Ether(dst=rmac, src="00:de:ad:be:ef:07") /
               IP(src="10.60.%d.%d" % (i % 250, (i * 7) % 250), dst="10.252.44.%d" % (i % 200)) /
               UDP(sport=30000 + i, dport=80 + (i % 13)))
        sendp(pkt, iface=p_in.name, count=1, verbose=False)
    time.sleep(1.5)
    d1 = ChipCounters.read(bsh, dut.bcm_of(p1)).tx_pkt
    d2 = ChipCounters.read(bsh, dut.bcm_of(p2)).tx_pkt
    assert d1 + d2 < _ECMP_STORM, "storm while probing plain ECMP: TX %d/%d" % (d1, d2)
    return (d1, d2)


@pytest.mark.slow
def test_dlb_physical_port_ceiling(cli, dut, chip, topo, _lb, l3up):
    """**How many physical egress ports one DLB group can hold** — the real spec of a DLB load-sharing group.

    In a DLB engine entry `PORT_ID[]` is an array with **one physical port per path**, and the
    chip echoes indices up to 63, i.e. one DLB instance tracks at most 64 physical paths; a plain
    ECMP group's table has no PORT_ID field at all (members are NHOP_IDs, the physical port is
    resolved in the egress object), so the "physical port spec" is not the same thing for the two.
    This case turns real physical ports into L3 ports + neighbours -> next hops -> DLB members one
    at a time, reading back the engine entry after each add, recording **NUM_PATHS and the
    deduplicated PORT_ID count**, and keeps adding until it fails, printing the real rejection
    point.

    The port count is controlled by FVT_DLB_PORTS (default 16; when probing the spec set it to 68
    to cross the 64 boundary).
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("intrusive DLB case: set FVT_DLB=1")
    chip.require()
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP table on this chip")
    want = int(os.environ.get("FVT_DLB_PORTS", "16"))
    # Must avoid the ports the l3net base occupies: this case uses the function-level l3up to take
    # over ports, and its teardown resets them back to L2, sweeping away the base's neighbours and
    # next hops along with them, so the nh oids cached in the module-level dlbnet become dangling
    # pointers, and a later case injecting with them kills syncd (observed: the whole stack halts).
    reserved = set()
    for getter, idx in ((topo.l3_port, 0), (topo.l3_port, 1), (topo.misc_port, 0)):
        try:
            reserved.add(getter(idx).name)
        except Exception:  # noqa: BLE001
            pass
    names = [p.name for p in dut.ports if p.name not in reserved][:want]
    if len(names) < 4:
        pytest.skip("not enough front panel ports to probe the DLB port ceiling")

    h = D.Dlb(cli, chip)
    up, nhs = [], []
    try:
        for i, name in enumerate(names):
            try:
                p = l3up(name, "10.70.%d.1/30" % (i + 1))
            except Exception as e:  # noqa: BLE001
                _LOG.warning("port %s could not be brought up as L3: %s", name, e)
                continue
            peer = "10.70.%d.2" % (i + 1)
            cli.neigh_set(peer, "00:aa:bb:00:70:%02x" % (i + 1), name)
            up.append((p, peer, name))
        for p, peer, name in up:
            oid = h.nh_by_ip(peer, timeout=20.0)
            if oid:
                nhs.append((oid, name))
        _LOG.info("brought up %d/%d L3 ports, %d next hops resolved",
                  len(up), len(names), len(nhs))
        if len(nhs) < 4:
            pytest.skip("only %d next hops resolved: cannot probe the port ceiling"
                        % len(nhs))

        g = h.create_group(D.TYPE_DLB_ELIGIBLE)
        assert g, "DLB group not created"
        added, last = 0, None
        for n, (oid, name) in enumerate(nhs, start=1):
            m = h.add_member(g, oid, n=n, settle=3.0)
            if not m:
                _LOG.warning("member %d (%s) REFUSED -> this is the ceiling", n, name)
                break
            added = n
            ents = h.dlb_ecmp()
            last = ents[-1] if ents else None
        ports = set()
        if last:
            for k, v in last.items():
                if k.startswith("PORT_ID_") and "-" not in k[len("PORT_ID_"):]:
                    ports.add(v)
        _LOG.info("DLB ceiling probe: %d members accepted out of %d offered, engine "
                  "NUM_PATHS=%s, distinct PORT_ID entries=%d",
                  added, len(nhs), last.get("NUM_PATHS") if last else None, len(ports))
        assert added > 0, "not a single member could join the group"
        assert last and last.get("NUM_PATHS") == added, (
            "engine reports NUM_PATHS=%s but %d members were accepted: members are being "
            "silently dropped" % (last.get("NUM_PATHS") if last else None, added))
        assert len(ports) == added, (
            "%d members on %d distinct physical ports produced only %d PORT_ID entries: "
            "the engine is not tracking one physical path per member"
            % (added, added, len(ports)))

        # Build a **plain ECMP** group over the same physical ports as a control: the plain
        # group's table has no PORT_ID field (members are NHOP_IDs, the physical port is resolved
        # in the egress object), so it is not subject to DLB's per-port entries. Bringing the
        # ports up is the most expensive part of this case, so the control is done here to save
        # another round.
        h.cleanup()
        time.sleep(4)
        base_ul = {e.get("ECMP_ID") for e in h.underlay()}
        e = h.create_group(D.TYPE_ECMP, n=200)
        assert e, "plain ECMP group not created"
        e_added = 0
        for n, (oid, name) in enumerate(nhs, start=200):
            if not h.add_member(e, oid, n=n, settle=3.0):
                _LOG.warning("plain ECMP member %d (%s) REFUSED", n - 199, name)
                break
            e_added = n - 199
        new_ul = [x for x in h.underlay() if x.get("ECMP_ID") not in base_ul]
        ecmp_ent = new_ul[-1] if new_ul else {}
        has_port_field = any(k.startswith("PORT_ID") for k in ecmp_ent)
        _LOG.info("plain ECMP over the same ports: %d/%d members accepted, NUM_PATHS=%s "
                  "MAX_PATHS=%s, per-port field present=%s",
                  e_added, len(nhs), ecmp_ent.get("NUM_PATHS"), ecmp_ent.get("MAX_PATHS"),
                  has_port_field)
        # Observed (68 ports): plain ECMP also stops at 64, the same number as DLB. The chip table
        # itself supports 4096 (ECMP_UNDERLAY.NHOP_ID depth 4096 / MAX_PATHS max 0x1000); what caps
        # it to 64 is the SAI-side `bcm_l3_info_get().l3info_max_ecmp`. So the assertion here is
        # "DLB is no worse than plain ECMP", not some hard-coded number — this case still holds
        # after the device raises max_ecmp.
        assert e_added >= added, (
            "plain ECMP accepted %d members but DLB accepted %d on the same ports: DLB is more "
            "restrictive than plain ECMP here" % (e_added, added))
        _LOG.info("member ceiling: DLB=%d plain ECMP=%d (chip table supports 4096; the cap "
                  "comes from l3info_max_ecmp)", added, e_added)
        assert not has_port_field, (
            "plain ECMP group carries a per-port field (%s): it would then be subject to the "
            "same physical port ceiling as DLB" % sorted(ecmp_ent)[:6])
    finally:
        h.cleanup()
        for _p, peer, name in up:
            try:
                cli.neigh_del(peer, name)
            except Exception:  # noqa: BLE001
                pass


@pytest.mark.slow
def test_dlb_group_churn_leaves_no_residue(dlb, dlbnet):
    """Repeated create/delete (with members) leaks no chip resources and does not kill syncd.

    A DLB group drags along a two-level ECMP group and an engine instance; missing one spot on
    the reclaim path exhausts resources after a few dozen flips — the most realistic failure mode
    under long-run operation (route flapping).
    """
    _refresh(dlb, dlbnet)
    base = dlb.counts()
    for i in range(10):
        # Use a fresh set of VIDs each round: reusing the same VID entangles "did it delete
        # cleanly?" with "can the same VID be recreated?", so on failure you cannot tell a leak
        # from a VID-reuse restriction.
        gn, m1n, m2n = i + 1, 2 * i + 1, 2 * i + 2
        g = dlb.create_group(D.TYPE_DLB_ELIGIBLE, n=gn, settle=3.0)
        assert g, "DLB group create failed on cycle %d/10" % (i + 1)
        m1 = dlb.add_member(g, dlbnet.nh1, n=m1n, settle=3.0)
        m2 = dlb.add_member(g, dlbnet.nh2, n=m2n, settle=3.0)
        assert m1 and m2, "DLB member add failed on cycle %d/10" % (i + 1)
        dlb.remove(m1, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER", settle=3.0)
        dlb.remove(m2, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER", settle=3.0)
        assert dlb.remove(g, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP", settle=3.0), \
            "DLB group not removed on cycle %d/10" % (i + 1)
        now = dlb.counts()
        assert now == base, ("chip resources leaked after cycle %d/10: %s (baseline %s)"
                             % (i + 1, now, base))


def test_dlb_member_release_frees_next_hop(dlb, dlbnet):
    """After a member is deleted it must release its reference to the next hop, or that next hop can never be deleted.

    Background (found on real hardware): while a DLB member holds a next hop, orchagent deleting
    the neighbour gets `SAI_STATUS_OBJECT_IN_USE` (`nh table entry N in use: ecmp = 1`) — which is
    itself correct reference-counting behaviour. But if the **member is already deleted** yet the
    reference was not given back, the next hop becomes an undeletable zombie: the neighbour errors
    on every ageing and the nh table gradually exhausts. This case creates the member, tears it
    down cleanly, then deletes the neighbour via the product path to see whether the reference was
    truly returned.
    """
    cli = dlbnet.cli
    g, m1, m2 = _group_with_members(dlb, dlbnet)
    for vid in (m1, m2):
        assert dlb.remove(vid, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"), \
            "DLB member %s could not be removed" % vid
    assert dlb.remove(g, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP"), "DLB group could not be removed"

    before = _sai_errs(cli)
    cli.neigh_del(dlbnet.ip2, dlbnet.p2.name)
    time.sleep(8)
    grew = _sai_errs(cli) - before
    tail = cli.sh.run("grep -E 'ERR (swss#orchagent|syncd#syncd)' /var/log/syslog | tail -%d"
                      % max(grew, 1), check=False).out
    cli.neigh_set(dlbnet.ip2, _NH2_MAC, dlbnet.p2.name)      # restore the base
    assert dlb.nh_by_ip(dlbnet.ip2), "could not restore the next hop after the test"

    assert "in use" not in tail or grew == 0, (
        "removing the neighbour after the DLB member was released still failed with the next "
        "hop in use: the member did not give its reference back, so that next hop can never "
        "be freed:\n%s" % tail.strip())


def test_dlb_left_no_damage(cli, dlbnet):
    """Closing health check: after the DLB suite there are no **new** cores, no syncd/orchagent errors, and port counters are intact.

    "No adverse impact on existing features" cannot be judged from the tables under test alone —
    finish with an overall look at device health. Cores are diffed against the snapshot taken on
    entry to this module, to avoid pinning a legacy core on this round (and to avoid a legacy core
    permanently masking a real crash from this round).
    """
    new_cores = _core_files(cli) - dlbnet.base_cores
    assert not new_cores, ("processes crashed during the DLB suite (new core files): %s"
                           % sorted(new_cores))

    st = cli.sh.run("docker ps --filter name=syncd --format '{{.Status}}'", check=False).out
    assert st.startswith("Up"), "syncd is not running after the DLB suite: %r" % st

    grew = _sai_errs(cli) - dlbnet.base_errs
    if grew > 0:
        tail = cli.sh.run("grep -E 'ERR (swss#orchagent|syncd#syncd)' /var/log/syslog "
                          "| tail -%d" % grew, check=False).out
        # One expected class: the neighbour-relearn case **deliberately** deletes the neighbour
        # while a member still holds the next hop, and SAI rejecting by reference count
        # (OBJECT_IN_USE) is correct behaviour, not a defect. Whether the reference truly comes
        # back is gated separately by test_dlb_member_release_frees_next_hop, so only this one is
        # allowed through here.
        expected = ("SAI_STATUS_OBJECT_IN_USE", "in use: fwd", "Failed to remove next hop",
                    "SAI_COMMON_API_REMOVE failed")
        unexpected = [l for l in tail.splitlines()
                      if l.strip() and not any(p in l for p in expected)]
        if unexpected:
            pytest.fail("%d unexpected syncd/orchagent errors during the DLB suite:\n%s"
                        % (len(unexpected), "\n".join(unexpected[-15:])))
        _LOG.info("%d expected OBJECT_IN_USE lines from the neighbour-relearn case", grew)

    # Port counter integrity: a whole bulk get once failed because SAI falsely claimed support for
    # some counters, leaving every device port with empty counters, so re-check this each round.
    # The CPU port is in COUNTERS_PORT_NAME_MAP but has no port counters, which is normal; exclude it.
    names = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP") or {}
    front = {n: oid for n, oid in names.items() if n != "CPU"}
    assert front, "no front panel ports in COUNTERS_PORT_NAME_MAP"
    empty = [n for n, oid in sorted(front.items())
             if int(cli.sh.run("sonic-db-cli COUNTERS_DB HLEN COUNTERS:%s" % oid,
                               check=False).out.strip() or 0) < 10]
    assert not empty, ("%d of %d front panel ports have no counters after the DLB suite "
                       "(port stat collection broken): %s"
                       % (len(empty), len(front), empty[:8]))
