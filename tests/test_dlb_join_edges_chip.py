"""Boundary cases for DLB member-join reseed / partial reseed.

Mechanisms under test:
  1. member join into an in-service DLB group reseeds the flowset (otherwise the new member gets no bucket at all);
  2. partial reseed -- when the member count increases and the flowset size is unchanged, only the
     round-robin slots that fall to the new member are rewritten, the rest are pinned; **when all
     members get marked (e.g. REPLACE re-orders member indices) or the size changes, it falls back
     to a full DMA reseed**; meanwhile the default 0/0 of
     REASSIGNMENT_PROBABILITY_THRESHOLD/REASSIGNMENT_QUALITY_DELTA must be wired into every DLB L2
     dynamic-config write point (they should stay 0 after group creation and member add/remove stamps).

Division of labor with test_dlb_flowset_reseed_chip.py (the sibling judgment cases): that one verifies
the "per-slot diff pinning semantics", this one verifies the boundary shapes:
  - test_damping_knobs_stay_zero              damping knobs stay 0/0 after all write points
  - test_replace_reindex_falls_back_to_full_reseed  member index re-order -> fall back to full reseed
  - test_join_and_resize_same_update          join + resize -> new base + full reseed + no bitmap leak
  - test_flowset_instances_pipes_consistent   after a partial reseed the 4 instances x 8 pipes are consistent
  - test_no_member_change_zero_disturbance    zero engine disturbance without member changes (two full scans agree)
  - test_join_with_alternate_path             alternate-path member join (not configurable on the bench, explicit skip)

Bench constraints (measured, same source as test_dlb_flowset_reseed_chip.py):
  - a MAC loopback port is HW_DOWN to the DLB engine: no traffic-statistics assertions, all criteria
    land on chip tables (lt DLB_ECMP / pt DLB_ECMP_FLOWSET_INST0-3m / pt DLB_ECMP_GROUP_CONTROLm);
  - without traffic the engine does no reassignment, so flowset snapshots can be compared stably slot by slot;
  - a DLB group can only be created by the SAI layer (SONiC has no config entry), so this file goes
    through framework/dlb.py's sairedis injection channel; injection produces no sairedis.rec response
    record, so the criteria can only be the chip tables themselves;
  - intrusive cases: gated by FVT_DLB=1 + chip.require() + has_table("DLB_ECMP") skip.

The injection channel is per-op; "add member + change size in the same update" is approximated with
two back-to-back ops; what really needs verifying is that the size-change path falls back to a full
reseed, reallocates base, and returns the old window's bitmap (the 32768 probe).
"""
import os
import re
import time

import pytest

from framework import dlb as D
from framework import log as _flog

# Reuse the sibling cases' physical-table parser (pt dump DLB_ECMP_GROUP_CONTROLm / DLB_ECMP_FLOWSET_INST0m).
import test_dlb_flowset_reseed_chip as reseed

_LOG = _flog.get("dlbjoinedge")

pytestmark = [pytest.mark.dlb, pytest.mark.l3, pytest.mark.chiptab]

_NH1_MAC = "00:aa:bb:00:0e:e1"
_NH2_MAC = "00:aa:bb:00:0e:e2"

_GRP = "SAI_OBJECT_TYPE_NEXT_HOP_GROUP"
_MBR = "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"

_KNOBS = ("REASSIGNMENT_PROBABILITY_THRESHOLD", "REASSIGNMENT_QUALITY_DELTA")

_group_window = reseed._group_window
_read_flowset = reseed._read_flowset


# ---------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def join_env(l3net, chip):
    """Shared base for the DLB boundary cases: two egress ports each learn a neighbor, resolving two NEXT_HOPs.

    Same shape as dlbnet in test_dlb_chip.py, but private to this file (the member sequence must
    distinguish members by port; the nh1->p_out / nh2->p_o2 mapping runs through all cases).
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("DLB cases drive SAI objects that SONiC has no config entry for, via the "
                    "sairedis queue; that is intrusive, so they only run with FVT_DLB=1")
    chip.require()
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip (independent DLB unsupported)")
    cli = l3net.cli
    h = D.Dlb(cli, chip)
    ip1, ip2 = l3net.sub_out["peer"], l3net.sub_o2["peer"]
    cli.neigh_set(ip1, _NH1_MAC, l3net.p_out.name)
    cli.neigh_set(ip2, _NH2_MAC, l3net.p_o2.name)
    nh1, nh2 = h.nh_by_ip(ip1), h.nh_by_ip(ip2)
    if not nh1 or not nh2:
        pytest.fail("DEVICE DEFECT: neighbours %s/%s did not produce SAI next hops in ASIC_DB "
                    "(cannot build a DLB group without members)" % (ip1, ip2))
    import types
    yield types.SimpleNamespace(
        cli=cli, chip=chip, env=l3net, nh1=nh1, nh2=nh2, ip1=ip1, ip2=ip2,
        port1=chip.port_id(l3net.p_out.name), port2=chip.port_id(l3net.p_o2.name))
    for ip, p in ((ip1, l3net.p_out), (ip2, l3net.p_o2)):
        try:
            cli.neigh_del(ip, p.name)
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture
def dlb(join_env):
    """A clean orchestrator per case; on exit reclaim the objects this case built in reverse order."""
    h = D.Dlb(join_env.cli, join_env.chip)
    yield h
    h.cleanup()


def _refresh(dlb, net):
    """If the base next hop was cleared along the way, rebuild the neighbor and re-resolve by IP
    (injecting with a stale oid would kill syncd). Port flap / guard cleanup may wipe the static
    neighbor, so neigh_set it back first and then wait for resolution; on a just-rebooted device SAI
    materialization takes tens of seconds, so the timeout is relaxed to 60s."""
    for attr, ip, mac, port in (("nh1", net.ip1, _NH1_MAC, net.env.p_out),
                                ("nh2", net.ip2, _NH2_MAC, net.env.p_o2)):
        if not dlb.nh_alive(getattr(net, attr)):
            net.cli.neigh_set(ip, mac, port.name)
            fresh = dlb.nh_by_ip(ip, timeout=60.0)
            assert fresh, ("next hop for %s is gone and could not be re-resolved: the L3 base "
                           "was torn down by another case" % ip)
            setattr(net, attr, fresh)


# ---------------------------------------------------------------- read helpers
def _dlb_ids(dlb):
    return {e.get("DLB_ID") for e in dlb.dlb_ecmp() if e.get("DLB_ID") is not None}


def _wait_new_dlb_id(dlb, base, want_paths=None, timeout=15.0):
    """Wait for a DLB_ECMP engine entry outside the baseline that has members, return its DLB_ID."""
    end = time.time() + timeout
    while time.time() < end:
        new = [e for e in dlb.dlb_ecmp()
               if e.get("DLB_ID") not in base and e.get("NUM_PATHS")]
        if want_paths is not None:
            new = [e for e in new if e.get("NUM_PATHS") == want_paths]
        if new:
            return new[-1]["DLB_ID"]
        time.sleep(1.0)
    return None


def _engine(chip, did, want_paths=None, timeout=15.0):
    """Poll lt DLB_ECMP lookup DLB_ID=<did> until NUM_PATHS is in place (programming is asynchronous)."""
    end = time.time() + timeout
    ent = None
    while time.time() < end:
        ent = chip.lookup("DLB_ECMP", DLB_ID=did)
        if ent and ent.get("NUM_PATHS") and \
                (want_paths is None or ent.get("NUM_PATHS") == want_paths):
            return ent
        time.sleep(1.0)
    return ent


def _wait_window(chip, did, timeout=15.0):
    """Poll DLB_ECMP_GROUP_CONTROLm until the group's flowset window is obtained."""
    end = time.time() + timeout
    while time.time() < end:
        win = _group_window(chip, did)
        if win:
            return win
        time.sleep(1.0)
    return None


def _port_seq(ent):
    """The member port sequence in the engine entry: [PORT_ID[0], ..., PORT_ID[NUM_PATHS-1]]."""
    n = ent.get("NUM_PATHS") or 0
    return [D.field_at(ent, "PORT_ID", i) for i in range(n)]


def _assert_full_round_robin(slots, total, seq, ctx):
    """Verify the complete round-robin layout slot by slot: slot j must point at member sequence seq[j % N]."""
    assert len(slots) == total, \
        "%s: only %d/%d flowset slots VALID" % (ctx, len(slots), total)
    n = len(seq)
    bad = [(j, v, seq[j % n]) for j, v in sorted(slots.items()) if v != seq[j % n]]
    assert not bad, (
        "%s: flowset is not a complete round-robin over the current member sequence %s "
        "(%d/%d slots wrong, first few (slot, got, want): %s) — after a full-reseed "
        "fallback every slot must follow j %% N" % (ctx, seq, len(bad), total, bad[:8]))


def _assert_knobs_zero(chip, did, stage):
    """The two damping knobs in lt DLB_ECMP lookup must be 0 (the default 0/0 should be wired into every write point)."""
    ent = chip.lookup("DLB_ECMP", DLB_ID=did)
    assert ent, "no DLB_ECMP entry for DLB_ID=%d %s" % (did, stage)
    for f in _KNOBS:
        assert f in ent, (
            "DLB_ECMP entry %d has no %s field %s: the lt schema on this SDK does not "
            "expose the damping knob, the wiring cannot be verified" % (did, f, stage))
        assert str(ent[f]) == "0", (
            "%s=%r (expected 0) %s: the default 0/0 damping knobs were not wired into "
            "this DLB L2 dynamic config write point" % (f, ent[f], stage))


# ---------------------------------------------------------------- injection extensions (private to this file, does not touch framework)
def _set_group_size(dlb, vid, size, settle=1.0):
    """Sset SAI_NEXT_HOP_GROUP_ATTR_DLB_FLOWSET_SIZE (CREATE_AND_SET) on an in-service DLB group."""
    dlb._push("%s:oid:%s" % (_GRP, vid),
              ["SAI_NEXT_HOP_GROUP_ATTR_DLB_FLOWSET_SIZE", str(size)], "Sset", settle)


def _create_group_sized(dlb, size, n=9, settle=5.0):
    """Create a DLB group with SAI_NEXT_HOP_GROUP_ATTR_DLB_FLOWSET_SIZE (for the bitmap probe)."""
    vid = dlb.group_vid(n)
    dlb._push("%s:oid:%s" % (_GRP, vid),
              ["SAI_NEXT_HOP_GROUP_ATTR_TYPE", str(D.TYPE_DLB_ELIGIBLE),
               "SAI_NEXT_HOP_GROUP_ATTR_DLB_FLOWSET_SIZE", str(size)], "Screate", settle)
    if not dlb.wait_rid(vid):
        return None
    dlb._created.append((vid, _GRP))
    return vid


def _build_group(dlb, net, nhs):
    """Create a DLB_ELIGIBLE group and add members in order, return (group_vid, dlb_id)."""
    _refresh(dlb, net)
    base = _dlb_ids(dlb)
    g = dlb.create_group(D.TYPE_DLB_ELIGIBLE)
    assert g, ("DLB group was not created (no RID in ASIC_DB): the SAI layer rejected an "
               "independent DLB group")
    for n, oid in enumerate(nhs, start=1):
        m = dlb.add_member(g, oid, n=n)
        assert m, "DLB member %d/%d could not be added" % (n, len(nhs))
    did = _wait_new_dlb_id(dlb, base, want_paths=len(nhs))
    assert did is not None, \
        "no fresh DLB_ECMP engine entry with NUM_PATHS=%d after building the group" % len(nhs)
    return g, did


# ---------------------------------------------------------------- damping knobs
def test_damping_knobs_stay_zero(dlb, join_env):
    """**REASSIGNMENT_PROBABILITY_THRESHOLD / QUALITY_DELTA stay 0/0 after all write points.**

    These two knobs' default 0/0 must be wired into every DLB L2 dynamic-config write point; if any
    one is missed, the engine will do reassignment by a nonzero threshold/delta, deviating from spec.
    When an empty group is created the engine entry does not exist yet (DLB_ECMP only lands on member
    join), so the check points are: add member 1 -> add member 2 -> remove member 2, and after each
    step `lt DLB_ECMP lookup DLB_ID=<n>` must be 0/0.
    """
    net, chip = join_env, join_env.chip
    g, did = _build_group(dlb, net, [net.nh1])
    _assert_knobs_zero(chip, did, "after first member join")

    m2 = dlb.add_member(g, net.nh2, n=2)
    assert m2, "second DLB member could not be added"
    _engine(chip, did, want_paths=2)
    _assert_knobs_zero(chip, did, "after second member join")

    assert dlb.remove(m2, _MBR), "second DLB member could not be removed"
    _engine(chip, did, want_paths=1)
    _assert_knobs_zero(chip, did, "after member remove")


# ---------------------------------------------------------------- index re-order -> full
def test_replace_reindex_falls_back_to_full_reseed(dlb, join_env):
    """**Member index re-order (REPLACE) marks all members -> must fall back to a full DMA reseed.**

    Construct: a 3-member group [nh1, nh2, nh1] (port sequence [p1, p2, p1]), remove the **middle**
    member m2 then add nh2 back. If the SDK shifts surviving member indices forward (m3: 2->1, new
    member fills 2), then all surviving members' round-robin indices change -- a partial reseed that
    only touches the new member's share would inevitably leave wrong slots, and the only correct
    result is a complete round-robin reseed over the current member set.

    Criteria (self-calibrating, does not assume whether the SDK actually shifts indices forward):
      - regardless of re-order: the final flowset must equal a complete round-robin over the current
        PORT_ID sequence (slot j == PORT_ID[j % N], checked slot by slot) -- a partial reseed hitting
        a re-order reveals itself here on the spot;
      - if the engine entry's PORT_ID sequence really changed (a re-order happened): the number of
        changed slots must **exceed** the new member's share (total/N), proving it took the full-reseed
        path and not just reseeded the new member.
    """
    net, chip = join_env, join_env.chip
    g, did = _build_group(dlb, net, [net.nh1, net.nh2, net.nh1])
    win = _wait_window(chip, did)
    assert win, "no flowset window for DLB_ID=%d" % did
    total = win[1] * 4
    eng0 = _engine(chip, did, want_paths=3)
    seq0 = _port_seq(eng0)
    assert len(seq0) == 3 and None not in seq0, \
        "engine PORT_ID sequence unreadable: %s" % (eng0,)
    slots0 = _read_flowset(chip, *win)
    _assert_full_round_robin(slots0, total, seq0, "initial 3-member layout")

    m2 = dlb.member_vid(2)
    assert dlb.remove(m2, _MBR), "middle member could not be removed"
    m4 = dlb.add_member(g, net.nh2, n=4)
    assert m4, "re-added member could not join the group"

    eng1 = _engine(chip, did, want_paths=3)
    seq1 = _port_seq(eng1)
    assert len(seq1) == 3 and None not in seq1, \
        "engine PORT_ID sequence unreadable after remove+rejoin: %s" % (eng1,)
    win1 = _wait_window(chip, did)
    assert win1, "flowset window vanished after remove+rejoin"
    assert win1[1] == win[1], \
        "flowset size changed on a same-size member update (%d -> %d lines)" % (win[1], win1[1])
    slots1 = _read_flowset(chip, *win1)
    _assert_full_round_robin(slots1, total, seq1,
                             "layout after middle-member remove + rejoin")

    changed = sum(1 for j in slots1 if slots0.get(j) != slots1[j])
    _LOG.info("remove+rejoin: PORT_ID %s -> %s, %d/%d slots moved",
              seq0, seq1, changed, total)
    if seq1 != seq0:
        share = total // 3
        assert changed > share + 4, (
            "member indices were re-ordered (%s -> %s) but only %d/%d slots moved (new member "
            "share is %d): surviving members shifted slots yet the reseed only rewrote the new "
            "member's share — the all-marked fallback to a full DMA reseed did not happen"
            % (seq0, seq1, changed, total, share))
    else:
        _LOG.info("SDK did not re-index surviving members on this remove; the fallback path "
                  "was not exercised, round-robin correctness still asserted")


# ---------------------------------------------------------------- add member + change size
def test_join_and_resize_same_update(dlb, join_env):
    """**Size change (stacked with a member join) -> reallocate base, update size, full round-robin.**

    The injection channel is per-op; two back-to-back ops (Sset FLOWSET_SIZE=2048, immediately
    followed by adding a third member) approximate "add member + change size in the same update".
    Criteria:
      - FLOW_SET_SIZE grows from 256 to 2048 (cross-checked at both the lt symbol and the GROUP_CONTROL window);
      - allocate a **new** base (window start changes, the old window is returned);
      - the layout is a complete round-robin over the current 3-member set (size change -> full reseed, no pinning obligation);
      - bitmap no-leak probe: creating another size=32768 group afterwards must be able to get its window
        (an 8192 contiguous-line block is still allocatable), then delete it after probing.
    """
    net, chip = join_env, join_env.chip
    g, did = _build_group(dlb, net, [net.nh1, net.nh2])
    win0 = _wait_window(chip, did)
    assert win0, "no flowset window for DLB_ID=%d" % did
    assert win0[1] * 4 == 256, \
        "expected the 256-flow default window, got %d flows" % (win0[1] * 4)

    _set_group_size(dlb, g, 2048)
    m3 = dlb.add_member(g, net.nh1, n=3)
    assert m3, "third member could not join during the resize"

    eng = _engine(chip, did, want_paths=3)
    assert "2048" in str(eng.get("FLOW_SET_SIZE")), \
        "FLOW_SET_SIZE is %r after the resize, expected 2048" % eng.get("FLOW_SET_SIZE")
    win1 = _wait_window(chip, did)
    assert win1, "flowset window vanished after the resize"
    assert win1[1] * 4 == 2048, \
        "GROUP_CONTROL window still covers %d flows after resizing to 2048" % (win1[1] * 4)
    assert win1[0] != win0[0], (
        "flowset base did not move on resize (line %d kept): a size change must reallocate "
        "the window and fall back to a full DMA reseed" % win0[0])
    seq = _port_seq(eng)
    assert len(seq) == 3 and None not in seq, \
        "engine PORT_ID sequence unreadable after resize: %s" % (eng,)
    slots = _read_flowset(chip, *win1)
    _assert_full_round_robin(slots, 2048, seq, "layout after join+resize")

    # Bitmap leak probe: if the old 256 window was not returned, 32768 (8192 contiguous lines) cannot be allocated here.
    base2 = _dlb_ids(dlb)
    g2 = _create_group_sized(dlb, 32768)
    assert g2, "probe group (flowset 32768) could not be created"
    mp = dlb.add_member(g2, net.nh2, n=8)
    assert mp, "probe group member could not be added"
    did2 = _wait_new_dlb_id(dlb, base2, want_paths=1)
    assert did2 is not None, "no engine entry for the 32768 probe group"
    win2 = _wait_window(chip, did2)
    assert win2 and win2[1] * 4 == 32768, (
        "a 32768-flow group could not get its window after the resize (window=%s): the old "
        "flowset block likely leaked from the allocator bitmap" % (win2,))
    _LOG.info("bitmap probe OK: 32768-flow window at line %d after resize", win2[0])
    assert dlb.remove(mp, _MBR), "probe member could not be removed"
    assert dlb.remove(g2, _GRP), "probe group could not be removed"


# ---------------------------------------------------------------- 4 instances x 8 pipes consistent
def _pt_get_row(chip, table, index, instance):
    """pt get reads one row for one instance, returns (raw output, {('v'|'p', subslot): value})."""
    out = chip.cmd("pt get %s BCMLT_PT_INDEX=%d BCMLT_PT_INSTANCE=%d"
                   % (table, index, instance))
    vals = {}
    for ln in out.splitlines():
        m = reseed._VALID_RE.search(ln)
        if m:
            vals[("v", int(m.group(1)))] = m.group(2)
        m = reseed._ASSIGN_RE.search(ln)
        if m:
            vals[("p", int(m.group(1)))] = reseed._dec(m, 2)
    return out, vals


def test_flowset_instances_pipes_consistent(dlb, join_env):
    """**After a partial reseed, the same row must have identical contents across 4 table instances x 8 pipes.**

    After a member join triggers a partial reseed, sample 6 rows (3 rows yielded/rewritten + 3 rows
    pinned/untouched), and for each row do
    `pt DLB_ECMP_FLOWSET_INST{0..3}m get BCMLT_PT_INDEX=<r> BCMLT_PT_INSTANCE=<0..7>`
    for 32 reads total; VALID/PORT_MEMBER_ASSIGNMENT must be byte-identical across all subslots -- if
    the partial reseed's RMW only wrote some instances/pipes, the hash would split into mutually
    contradictory layouts per pipe.
    """
    net, chip = join_env, join_env.chip
    g, did = _build_group(dlb, net, [net.nh1])
    win = _wait_window(chip, did)
    assert win, "no flowset window for DLB_ID=%d" % did
    slots0 = _read_flowset(chip, *win)

    m2 = dlb.add_member(g, net.nh2, n=2)
    assert m2, "second member could not join"
    _engine(chip, did, want_paths=2)
    slots1 = _read_flowset(chip, *win)

    touched_rows = sorted({s // 4 for s in slots1 if slots0.get(s) != slots1[s]})
    untouched_rows = sorted({s // 4 for s in slots1 if slots0.get(s) == slots1[s]})
    assert touched_rows and untouched_rows, (
        "join did not produce a partial pattern (touched=%d untouched=%d rows): cannot sample"
        % (len(touched_rows), len(untouched_rows)))
    rows = ([("touched", r) for r in touched_rows[:3]]
            + [("untouched", r) for r in untouched_rows[:3]])

    for tag, row in rows:
        index = win[0] + row
        ref = None
        mism = []
        for inst in range(4):
            table = "DLB_ECMP_FLOWSET_INST%dm" % inst
            for pipe in range(8):
                out, vals = _pt_get_row(chip, table, index, pipe)
                if not vals:
                    head = out.strip()[:100]
                    if ref is None and inst == 0 and pipe == 0:
                        pytest.skip("pt get per-index/per-instance read returned nothing "
                                    "parseable on this diag channel (%r): this probe "
                                    "form is unsupported here" % head)
                    pytest.fail("pt get %s index=%d instance=%d returned no flowset fields: "
                                "%r" % (table, index, pipe, head))
                key = tuple(sorted(vals.items()))
                if ref is None:
                    ref = key
                elif key != ref:
                    mism.append((inst, pipe))
        assert not mism, (
            "flowset row %d (%s) disagrees across instances/pipes at %s: a partial reseed "
            "must program all 4 instances x 8 pipes of a row identically"
            % (index, tag, mism))
        _LOG.info("row %d (%s): 4 instances x 8 pipes identical", index, tag)


# ---------------------------------------------------------------- zero disturbance
def test_no_member_change_zero_disturbance(dlb, join_env):
    """**Without member changes, the flowset must have zero disturbance.**

    Driving traffic on the bench is not feasible (a MAC loopback port is HW_DOWN to the DLB engine),
    so use a static criterion: after a 2-member group is built and converged, do two full flowset
    scans a few seconds apart, slot-by-slot consistent -- without traffic the engine does no
    reassignment, so any slot drift means the reseed logic acted wrongly with no member event.
    """
    net, chip = join_env, join_env.chip
    _g, did = _build_group(dlb, net, [net.nh1, net.nh2])
    win = _wait_window(chip, did)
    assert win, "no flowset window for DLB_ID=%d" % did
    eng = _engine(chip, did, want_paths=2)
    seq = _port_seq(eng)
    snap0 = _read_flowset(chip, *win)
    _assert_full_round_robin(snap0, win[1] * 4, seq, "first scan")

    time.sleep(6)
    snap1 = _read_flowset(chip, *win)
    drift = [(j, snap0.get(j), snap1.get(j)) for j in sorted(snap1)
             if snap0.get(j) != snap1.get(j)]
    assert not drift, (
        "flowset changed with no member event and no traffic (%d/%d slots drifted, first few "
        "(slot, was, now): %s): the engine rewrote slots it had no reason to touch"
        % (len(drift), len(snap1), drift[:8]))


# ---------------------------------------------------------------- alternate path (not configurable on the bench)
@pytest.mark.skip(reason="alternate path cannot be configured on this stack: SONiC has no matching "
                         "CLI, and this stack's SAI NHG member path does not consume "
                         "SAI_NEXT_HOP_GROUP_MEMBER_ATTR_ARS_ALTERNATE_PATH (used only by the ARS "
                         "object model, marked unsupported in the capability table); injecting that "
                         "attribute would only be rejected or silently treated as the primary path, "
                         "so a real alternate member cannot be constructed")
def test_join_with_alternate_path():
    """**Alternate member join (pending a supporting bench): primary port_id unchanged -> no partial mark -> full reseed.**

    Intended construction (on a stack supporting SAI_NEXT_HOP_GROUP_MEMBER_ATTR_ARS_ALTERNATE_PATH):
    after a 2-member DLB group is built, add a third member with the alternate-path attribute; the
    engine's primary PORT_ID sequence stays unchanged -> the partial reseed has no new primary member
    to mark -> it must fall back to a full reseed, with the final state still a complete round-robin
    over the primary member set. On this bench neither config path exists, so the case explicitly
    skips, with the reason in the skip reason; on a supporting stack, remove the mark to enable it.
    """
