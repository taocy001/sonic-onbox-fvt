"""DLB flowset exhaustion degrade -- on-hardware verdict suite.

Behavior under test (degrade to plain ECMP when flowsets are exhausted): the whole table
holds only 32768 flowset flows, so once one big 32768 group owns the entire table, when
the DLB L2 UNDERLAY create hits a resource-class error (BCM_E_RESOURCE/E_FULL ->
SAI INSUFFICIENT_RESOURCES/TABLE_FULL) it no longer fails the create, but instead
**degrades to plain ECMP**:
  - the group stays on L1 (ECMP_OVERLAY) and forwards as usual, with members hung
    directly off L1; no L2, no DLB_ECMP engine row;
  - the upstream set reports SUCCESS, syslog logs a WARN ("DLB L2 create out of
    resources"), not an ERR;
  - a later member add/remove / flowset update automatically retries the L2 bringup: when
    the flowset has room it upgrades in place to the two-level DLB shape (members migrate
    from L1 to L2, the engine row appears, FLOW_SET_BASE/SIZE non-zero);
  - a non-resource error (e.g. an illegal flowset size) does not degrade and still fails
    loudly as before.

Bench constraints (consistent with test_dlb_flowset_reseed_chip.py):
  - the MAC loopback port is HW_DOWN to the DLB engine, so DLB groups carry no traffic;
    all criteria land on the chip logical tables
    (lt DLB_ECMP / ECMP_OVERLAY / ECMP_UNDERLAY) and syslog, with no traffic-counter
    assertions;
  - the only viable way to fill the whole table reuses the reseed file's path:
    `-s 1 to create the group -> change to -s 8 to resize in place into the 32768 big
    group` (creating with `-s 8` directly is rejected by SAI);
  - intrusive (sairedis injection to create the DLB group + changing the global
    ecmp-mode); the whole file is gated on FVT_DLB=1 + chip.has_table("DLB_ECMP"); each
    case builds and tears down its own state, and the fixture cleans up in reverse order
    (cleanup injected objects -> delete baseline route -> restore ecmp-mode to normal ->
    delete neighbours).

Harness limitations (recorded honestly):
  - an injection produces no sairedis.rec status record (framework/dlb.py header note #5),
    so A6's INVALID_ATTR_VALUE can only be judged by "no RID + an ERR string in syslog";
    the precise status code cannot be read;
  - the degrade WARN is matched as a syslog substring ("DLB L2 create out of resources"),
    with no assertion on the level field.
"""
import os
import re
import time
import types

import pytest

from framework import dlb as D
from framework import log as _flog

_LOG = _flog.get("dlbdegrade")

pytestmark = [pytest.mark.dlb, pytest.mark.l3, pytest.mark.chiptab]

_NET = "100.103.1.0/24"          # route prefix for the baseline 32k big group (offset from the reseed file's 100.101/102)


# ---------------------------------------------------------------- small helpers (family convention)
def _mode(cli):
    return cli.sh.run("show load-balance ecmp-mode", check=False).out.strip()


def _set_mode(cli, words):
    rc, _ = cli.config_raw("load-balance ecmp-mode %s" % words)
    time.sleep(3)
    return rc


def _dlb_rows(chip):
    """All rows of the DLB_ECMP logical table: [{DLB_ID, NUM_PATHS}]."""
    out = chip.cmd("lt DLB_ECMP traverse -l")
    rows, cur = [], None
    for ln in out.splitlines():
        m = re.search(r"DLB_ID=(\d+)", ln)
        if m:
            cur = {"DLB_ID": int(m.group(1))}
            rows.append(cur)
        m = re.search(r"NUM_PATHS=(?:0x\S*\()?(\d+)", ln)
        if m and cur is not None:
            cur["NUM_PATHS"] = int(m.group(1))
    return rows


_PTNUM = r"(?:0x[0-9a-fA-F]+\((\d+)\)|(\d+))"


def _dec(m, n=1):
    return int(m.group(n) or m.group(n + 1))


def _group_window(chip, dlb_id):
    """The group's flowset slot window (line_start, line_cnt); returns None if there is no FLOW_SET_BASE/SIZE.

    pt dump indices/values come in two printed shapes (0-9 plain decimal, >=10 as
    hex + parenthesized decimal); match both with the _PTNUM regex.
    """
    out = chip.cmd("pt dump DLB_ECMP_GROUP_CONTROLm")
    idx = base = size = None
    for ln in out.splitlines():
        m = re.search(r"BCMLT_PT_INDEX=" + _PTNUM, ln)
        if m:
            idx = _dec(m)
        m = re.search(r"FLOW_SET_BASE=" + _PTNUM, ln)
        if m and idx == dlb_id:
            base = _dec(m)
        m = re.search(r"FLOW_SET_SIZE=" + _PTNUM, ln)
        if m and idx == dlb_id:
            size = _dec(m)
    if base is None or not size:
        return None
    flows = 256 << (size - 1)
    return base // 4, flows // 4


def _sai_errs(cli):
    """Count of syncd/orchagent ERR lines in syslog (the delta tells whether this round introduced new errors).

    Exclude pre-existing noise unrelated to DLB: every `config load-balance ecmp-mode`
    switch triggers a burst of ERRs for rejected lag hash field combinations
    (SAI_API_HASH/setHashModeAttr/doAppSwitchTableTask, ~10 lines per mode switch), which
    would drown out the delta assertion.
    """
    out = cli.sh.run(
        "grep -aE 'ERR (swss#orchagent|syncd#syncd)' /var/log/syslog 2>/dev/null"
        " | grep -avE 'SAI_API_HASH|lag_ipv4_hash|setHashModeAttr|doAppSwitchTableTask"
        "|loadbalance hash|SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST|processQuadEvent"
        "|SAI_COMMON_API_SET failed|:- set: set status'"
        " | grep -ac .",
        check=False).out.strip()
    return int(out) if out.isdigit() else 0


def _degrade_warns(cli):
    """Count of degrade WARN ("DLB L2 create out of resources") lines in syslog."""
    out = cli.sh.run("grep -c 'DLB L2 create out of resources' /var/log/syslog 2>/dev/null",
                     check=False).out.strip()
    return int(out) if out.isdigit() else 0


def _routes_with(cli, peers):
    cli.sh.run("ip route replace %s %s"
               % (_NET, " ".join("nexthop via %s" % p for p in peers)), check=False)
    time.sleep(8)


def _route_del(cli):
    cli.sh.run("ip route del %s" % _NET, check=False)
    time.sleep(8)


def _build_peers(env, cli, n):
    """Create 3 neighbours on each of the two egress ports (IP range kept clear of the reseed file's 0x41/0x51 range)."""
    peers = []
    for port, sub, base in ((env.p_out, env.sub_out, 0x62), (env.p_o2, env.sub_o2, 0x72)):
        net = sub["peer"].rsplit(".", 1)[0]
        for k in range(3):
            ip = "%s.%d" % (net, 231 + (base % 16) * 3 + k)
            cli.neigh_set(ip, "00:aa:cc:00:%02x:%02x" % (base, k), port.name)
            peers.append(ip)
    return peers[:n]


# ---------------------------------------------------------------- fixture
@pytest.fixture
def degrade_env(l3net, chip):
    """Per-case independent environment: 6 neighbours (the first 2 feed the 32k baseline route, the last 4 are only members for the injected group), an injection orchestrator, and an entry baseline snapshot. Reverse-order cleanup: injected objects -> route -> ecmp-mode -> neighbours."""
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("changes the global ECMP mode of the device and injects SAI objects: "
                    "set FVT_DLB=1 to run")
    chip.require()
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip (independent DLB unsupported)")
    env = l3net
    cli = env.cli
    h = D.Dlb(cli, chip)
    peers = _build_peers(env, cli, 6)
    nhs = []
    for ip in peers:
        oid = h.nh_by_ip(ip, timeout=25.0)
        if not oid:
            pytest.fail("neighbour %s did not produce a SAI next hop in "
                        "ASIC_DB (cannot build DLB group members)" % ip)
        nhs.append(oid)
    ctx = types.SimpleNamespace(
        env=env, cli=cli, chip=chip, h=h, peers=peers, nhs=nhs,
        before=_mode(cli),
        rows0={r["DLB_ID"] for r in _dlb_rows(chip)},
        ol_base=set(), ul_base=set())
    yield ctx
    h.cleanup()
    _route_del(cli)
    _set_mode(cli, "normal")
    for ip, port in ((p, env.p_out if i < 3 else env.p_o2) for i, p in enumerate(peers)):
        try:
            cli.neigh_del(ip, port.name)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------- shared actions/assertions
def _fill_table(ctx):
    """Build a size=32768 eligible group that fills the whole table (`-s 1` to create -> change to `-s 8` to resize in place).

    This step is also a flowset-bitmap no-leak probe: if a previous round leaked a flowset
    block, the in-place resize here is bound to fail (128 contiguous 256-flow blocks are
    unavailable). Returns the big group's DLB_ID, and refreshes the L1/L2 baseline
    snapshots (including the CLI big group itself), so later code can find "the injected
    group's row".
    """
    cli, chip = ctx.cli, ctx.chip
    _set_mode(cli, "dynamic eligible -s 1")
    _routes_with(cli, ctx.peers[:2])
    # route->DLB group landing is asynchronous, tens of seconds after a restart: poll both rounds, no fixed sleep
    end = time.time() + 90.0
    while time.time() < end:
        big = [r["DLB_ID"] for r in _dlb_rows(chip)
               if r["DLB_ID"] not in ctx.rows0 and r.get("NUM_PATHS") == 2]
        if big:
            break
        time.sleep(3.0)
    assert big, "the baseline route never produced a 2-member DLB group"
    _set_mode(cli, "dynamic eligible -s 8")
    end = time.time() + 90.0
    out = ""
    while time.time() < end:
        out = chip.cmd("lt DLB_ECMP traverse -l")
        if "FLOW_SET_SIZE_32768" in out:
            break
        time.sleep(3.0)
    assert "FLOW_SET_SIZE_32768" in out, (
        "the 32768 in-place resize did not happen: cannot fill the flowset table "
        "(if a previous cycle leaked a flowset block, this probe is catching it)")
    big = [r["DLB_ID"] for r in _dlb_rows(chip) if r["DLB_ID"] not in ctx.rows0]
    assert len(big) == 1, \
        "expected exactly one new DLB row for the 32768 group, got %s" % big
    ctx.ol_base = {e.get("ECMP_ID") for e in ctx.h.overlay()}
    ctx.ul_base = {e.get("ECMP_ID") for e in ctx.h.underlay()}
    return big[0]


def _assert_degraded_shape(ctx, big, npaths):
    """Degrade signature: the single new L1 row directly carries npaths members (not pointing at L2), no new L2, no new engine row (or an engine row with no flowset window). Returns the injected group's L1 row."""
    chip, h = ctx.chip, ctx.h
    new_ol = [e for e in h.overlay() if e.get("ECMP_ID") not in ctx.ol_base]
    assert len(new_ol) == 1, \
        "expected exactly one new L1 overlay group for the injected group, got %d" % len(new_ol)
    ol = new_ol[0]
    assert ol.get("NUM_PATHS") == npaths, (
        "degraded group L1 NUM_PATHS=%s, expected %d: members of a degraded group sit "
        "directly on L1" % (ol.get("NUM_PATHS"), npaths))
    assert D.field_at(ol, "ECMP_NHOP_UNDERLAY", 0) != 1, (
        "L1 member 0 is flagged as an underlay group: the L2 came up despite the full "
        "flowset table (the degrade did not happen)")
    new_ul = [e for e in h.underlay() if e.get("ECMP_ID") not in ctx.ul_base]
    assert not new_ul, \
        "a degraded group must not have an L2 underlay group, got %s" % new_ul
    rows = {r["DLB_ID"] for r in _dlb_rows(chip)} - ctx.rows0 - {big}
    for did in rows:
        assert _group_window(chip, did) is None, (
            "DLB_ID=%d of the degraded group holds a flowset window although the table is "
            "full: the flowset must stay unallocated while degraded" % did)
    return ol


def _assert_upgraded(ctx, big, npaths):
    """Upgrade signature: a new engine row (NUM_PATHS=npaths, FLOW_SET_BASE/SIZE non-zero, 256-flow window), a new L2 with all members, and L1 back to MAX 1 path pointing at L2. Returns the new engine row's DLB_ID.

    The upgrade is asynchronous (member add -> SAI retries the L2 bringup -> SDKLT
    programming), so poll and wait; after the release the big group's DLB_ID may be reused
    for the upgraded group under the same number, so big cannot be excluded by DLB_ID --
    distinguish by NUM_PATHS instead (the big group is always 2 members, the upgraded
    group has npaths>=3).
    """
    chip, h = ctx.chip, ctx.h
    end = time.time() + 25.0
    new_rows = []
    while time.time() < end:
        new_rows = [r for r in _dlb_rows(chip)
                    if r["DLB_ID"] not in ctx.rows0
                    and r.get("NUM_PATHS") == npaths]
        if len(new_rows) == 1:
            win_probe = _group_window(chip, new_rows[0]["DLB_ID"])
            if win_probe:
                break
        time.sleep(1.0)
    assert len(new_rows) == 1, (
        "expected exactly one new DLB engine row with NUM_PATHS=%d after the upgrade "
        "(the 32768 group was DLB_ID=%d; note its id may be legitimately reused), got %s"
        % (npaths, big, new_rows))
    eng = new_rows[0]
    did = eng["DLB_ID"]
    assert eng.get("NUM_PATHS") == npaths, (
        "upgraded group engine NUM_PATHS=%s, expected %d: the upgrade must migrate all "
        "members to L2" % (eng.get("NUM_PATHS"), npaths))
    win = _group_window(chip, did)
    assert win, "upgraded group DLB_ID=%d has no FLOW_SET_BASE/SIZE window" % did
    assert win[1] * 4 == 256, (
        "upgraded group flowset window is %d flows, expected the 256 default"
        % (win[1] * 4))
    new_ul = [e for e in h.underlay() if e.get("ECMP_ID") not in ctx.ul_base]
    assert len(new_ul) == 1, "expected one new L2 underlay group, got %d" % len(new_ul)
    ul = new_ul[0]
    assert ul.get("NUM_PATHS") == npaths, (
        "L2 underlay NUM_PATHS=%s, expected %d after the upgrade"
        % (ul.get("NUM_PATHS"), npaths))
    new_ol = [e for e in h.overlay() if e.get("ECMP_ID") not in ctx.ol_base]
    assert len(new_ol) == 1, "expected the injected group's single L1 row, got %d" % len(new_ol)
    ol = new_ol[0]
    assert ol.get("NUM_PATHS") == 1 and D.field_at(ol, "ECMP_NHOP_UNDERLAY", 0) == 1, (
        "after the upgrade the L1 row must collapse to a single underlay member "
        "(NUM_PATHS=%s, underlay flag=%s): members still sit on L1"
        % (ol.get("NUM_PATHS"), D.field_at(ol, "ECMP_NHOP_UNDERLAY", 0)))
    assert D.field_at(ol, "ECMP_UNDERLAY_ID", 0) == ul.get("ECMP_ID"), (
        "L1 points at underlay id %s but the new L2 group is %s"
        % (D.field_at(ol, "ECMP_UNDERLAY_ID", 0), ul.get("ECMP_ID")))
    return did


def _make_degraded(ctx, big, n0=0):
    """After filling the table, create a DLB group via the injection path with two members (using neighbours not tied to the baseline route), and assert it degraded.
    n0 is the group/member VID index offset: the cyclic case uses a fresh set of VIDs each
    round, to keep "was it cleaned up" and "can it be rebuilt under the same VID" from
    getting entangled. Returns (g, m1, m2)."""
    h, cli = ctx.h, ctx.cli
    warn0 = _degrade_warns(cli)
    g = h.create_group(D.TYPE_DLB_ELIGIBLE, n=n0 + 1)
    assert g, "injected DLB group was not created (no RID in ASIC_DB)"
    m1 = h.add_member(g, ctx.nhs[2], n=n0 + 1)
    m2 = h.add_member(g, ctx.nhs[3], n=n0 + 2)
    assert m1 and m2, (
        "member add on a flowset-starved DLB group returned failure (m1=%s m2=%s): the "
        "shortage must degrade to plain ECMP and report SUCCESS, not fail the set"
        % (m1, m2))
    _assert_degraded_shape(ctx, big, 2)
    assert _degrade_warns(cli) > warn0, (
        "no 'DLB L2 create out of resources' WARN in syslog after the degrade: the "
        "degrade must be audible, not silent")
    _LOG.info("degraded group %s: members on L1, DLB rows unchanged", g)
    return g, m1, m2


# ---------------------------------------------------------------- A2 exhaustion degrade
def test_dlb_flowset_exhaustion_degrades_to_plain_ecmp(degrade_env):
    """**A2 core verdict: once the whole table is filled by the 32768 group, an injected DLB group must degrade to plain ECMP.**

    The create does not error (SAI SUCCESS, RID appears, members join as usual), the
    degrade signature holds (members directly on L1, no L2, engine row allocates no
    flowset), the degrade WARN appears in syslog, and no new ERR appears throughout.
    Before the fix, this path manifested as group/member create failure and a leftover
    drop placeholder on L1 (a routing black hole).
    """
    ctx = degrade_env
    cli = ctx.cli
    err0 = _sai_errs(cli)
    big = _fill_table(ctx)
    _make_degraded(ctx, big)
    assert _sai_errs(cli) == err0, (
        "new syncd/orchagent ERR lines during the degrade: a flowset shortage must be a "
        "WARN, not an error (the pre-fix behavior)")


# ---------------------------------------------------------------- A3 member add/remove while degraded
def test_dlb_degraded_group_member_add_remove(degrade_env):
    """**A3: while degraded, member add/remove lands directly on L1, without error and without reviving L2.**

    Every member add retries the L2 bringup, but the table is still full -> stays
    degraded: after the third member is added, L1 NUM_PATHS=3; removing it goes back to 2;
    no new ERR throughout.
    """
    ctx = degrade_env
    cli, h = ctx.cli, ctx.h
    big = _fill_table(ctx)
    g, _m1, _m2 = _make_degraded(ctx, big)
    err0 = _sai_errs(cli)

    m3 = h.add_member(g, ctx.nhs[4], n=3)
    assert m3, "member add on a degraded group failed: adds must keep working on L1"
    _assert_degraded_shape(ctx, big, 3)

    assert h.remove(m3, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"), \
        "member remove on a degraded group failed"
    _assert_degraded_shape(ctx, big, 2)

    assert _sai_errs(cli) == err0, \
        "syncd/orchagent errors during member churn on a degraded group"


# ---------------------------------------------------------------- A4 auto-upgrade after release
def test_dlb_degraded_group_upgrades_after_flowset_freed(degrade_env):
    """**A4: after deleting the 32k group frees the flowset, a single member add triggers an automatic upgrade to the two-level DLB shape.**

    Upgrade signature: a new engine row appears (distinguished from the 32k big group's
    DLB_ID), FLOW_SET_BASE/SIZE non-zero, a 256-flow window, L2 carrying all 3 members,
    and L1 collapsing to a single member pointing at L2 (member shape L1 -> L2).
    """
    ctx = degrade_env
    cli, h = ctx.cli, ctx.h
    err0 = _sai_errs(cli)
    big = _fill_table(ctx)
    g, _m1, _m2 = _make_degraded(ctx, big)

    _route_del(cli)                      # free the 32768 block, clearing the whole table
    m3 = h.add_member(g, ctx.nhs[4], n=3)
    assert m3, "the member add that should trigger the L2 bringup retry failed"
    _assert_upgraded(ctx, big, 3)

    assert _sai_errs(cli) == err0, "syncd/orchagent errors during the upgrade"


# ---------------------------------------------------------------- A5 delete while degraded
def test_dlb_degraded_group_delete_leaves_no_residue(degrade_env):
    """**A5: deleting a group while degraded must be clean: L1 emptied, no added engine rows, next hop references returned.**

    The reference-return probe uses the same check as test_dlb_member_release_frees_next_hop:
    after the group is torn down, deleting via the product path a neighbour referenced only
    by this group must not produce an OBJECT_IN_USE ("in use") error -- otherwise that next
    hop becomes an undeletable zombie.
    """
    ctx = degrade_env
    cli, h, chip = ctx.cli, ctx.h, ctx.chip
    big = _fill_table(ctx)
    base = h.counts()
    g, m1, m2 = _make_degraded(ctx, big)

    for v in (m1, m2):
        assert h.remove(v, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"), \
            "member %s of a degraded group could not be removed" % v
    assert h.remove(g, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP"), \
        "degraded group could not be removed"
    assert h.counts() == base, (
        "degraded group teardown leaked chip resources: %s (baseline %s)"
        % (h.counts(), base))
    rows = {r["DLB_ID"] for r in _dlb_rows(chip)} - ctx.rows0
    assert rows == {big}, \
        "unexpected DLB engine rows after the degraded group teardown: %s" % sorted(rows)

    before = _sai_errs(cli)
    cli.neigh_del(ctx.peers[2], ctx.env.p_out.name)
    time.sleep(8)
    grew = _sai_errs(cli) - before
    tail = cli.sh.run("grep -E 'ERR (swss#orchagent|syncd#syncd)' /var/log/syslog | tail -%d"
                      % max(grew, 1), check=False).out
    assert "in use" not in tail or grew == 0, (
        "removing the neighbour after the degraded group was torn down still failed with "
        "the next hop in use: the degraded members did not give their references back:\n%s"
        % tail.strip())


# ---------------------------------------------------------------- A6 non-resource error does not degrade
def test_dlb_invalid_flowset_size_fails_loudly(cli, chip):
    """**A6: an illegal flowset size (3333) is not a resource error and must fail loudly, leaving no group.**

    An injected create with SAI_NEXT_HOP_GROUP_ATTR_DLB_FLOWSET_SIZE=3333 (valid values
    are only powers of two in 256..32768): SAI should return INVALID_ATTR_VALUE. The
    injection path cannot read the precise status code (framework/dlb.py header note #5),
    so the criteria = no RID + an "Invalid DLB flowset size 3333" ERR in syslog + zero
    change to the chip group tables + syncd still alive.
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("intrusive DLB case: set FVT_DLB=1")
    chip.require()
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip (independent DLB unsupported)")
    h = D.Dlb(cli, chip)
    try:
        c0 = h.counts()
        vid = h.group_vid(1)
        h._push("SAI_OBJECT_TYPE_NEXT_HOP_GROUP:oid:%s" % vid,
                ["SAI_NEXT_HOP_GROUP_ATTR_TYPE", str(D.TYPE_DLB_ELIGIBLE),
                 "SAI_NEXT_HOP_GROUP_ATTR_DLB_FLOWSET_SIZE", "3333"], "Screate", settle=5.0)
        assert not h.has(vid), (
            "a DLB group with flowset size 3333 got a RID: an invalid attribute must fail "
            "with INVALID_ATTR_VALUE, not be degraded or silently accepted")
        assert h.counts() == c0, (
            "the rejected create left chip state behind: %s (baseline %s)"
            % (h.counts(), c0))
        tail = cli.sh.run("grep 'Invalid DLB flowset size' /var/log/syslog | tail -3",
                          check=False).out
        assert "3333" in tail, (
            "no 'Invalid DLB flowset size 3333' error in syslog: the rejection must be "
            "loud, not silent")
        alive = cli.sh.run("docker exec syncd pgrep -c syncd", check=False).out.strip()
        assert alive and int(alive) >= 1, "syncd died on the invalid-attribute create"
    finally:
        h.cleanup()


# ---------------------------------------------------------------- A7 degrade-upgrade cycle
@pytest.mark.slow
def test_dlb_degrade_upgrade_cycle_no_bitmap_leak(degrade_env):
    """**A7 (slow): fill -> degrade -> release -> upgrade cycled 5 times, with zero flowset-bitmap leak.**

    Each round tears the injected group down cleanly, so the next round's `_fill_table`
    in-place resize is itself the probe: if the bitmap leaked one block, the contiguous
    full table 32768 needs cannot be assembled and the resize fails on the spot. At the
    end, do one more resize as a final-round probe, and assert the three group tables and
    engine rows have all returned to the entry baseline.
    """
    ctx = degrade_env
    cli, h, chip = ctx.cli, ctx.h, ctx.chip
    err0 = _sai_errs(cli)
    c0 = h.counts()
    for i in range(5):
        big = _fill_table(ctx)           # probe that the previous round did not leak (see docstring)
        g, _m1, _m2 = _make_degraded(ctx, big, n0=i * 4)
        _route_del(cli)
        m3 = h.add_member(g, ctx.nhs[4], n=i * 4 + 3)
        assert m3, "upgrade-triggering member add failed on cycle %d/5" % (i + 1)
        _assert_upgraded(ctx, big, 3)
        h.cleanup()
        time.sleep(4)
        now = h.counts()
        assert now == c0, ("chip resources leaked after cycle %d/5: %s (baseline %s)"
                           % (i + 1, now, c0))
        _LOG.info("degrade->upgrade cycle %d/5 clean", i + 1)

    _fill_table(ctx)                     # final-round bitmap probe: a 32768 group can still be built
    _route_del(cli)
    assert h.counts() == c0, "group tables did not return to baseline after the cycles"
    assert {r["DLB_ID"] for r in _dlb_rows(chip)} == ctx.rows0, \
        "DLB engine rows left over after the cycles"
    assert _sai_errs(cli) == err0, "syncd/orchagent errors across the degrade/upgrade cycles"


# ---------------------------------------------------------------- D1 add member immediately after upgrade
def test_dlb_upgraded_group_takes_member_immediately(degrade_env):
    """**D1: adding another member right after a successful upgrade keeps the group healthy and the flowset window intact.**

    The first member join after the upgrade takes the normal join path of an in-service
    DLB group (the seam with the degrade-retry path): the engine row NUM_PATHS goes
    3 -> 4, and the FLOW_SET_BASE/SIZE window stays a valid 256-flow window (no per-slot
    diff; reseed correctness is guarded by test_dlb_flowset_reseed_chip.py).
    """
    ctx = degrade_env
    cli, h, chip = ctx.cli, ctx.h, ctx.chip
    err0 = _sai_errs(cli)
    big = _fill_table(ctx)
    g, _m1, _m2 = _make_degraded(ctx, big)

    _route_del(cli)
    m3 = h.add_member(g, ctx.nhs[4], n=3)
    assert m3, "the member add that should trigger the upgrade failed"
    did = _assert_upgraded(ctx, big, 3)

    m4 = h.add_member(g, ctx.nhs[5], n=4)
    assert m4, "member add immediately after the upgrade failed"
    eng = {r["DLB_ID"]: r for r in _dlb_rows(chip)}.get(did)
    assert eng and eng.get("NUM_PATHS") == 4, (
        "engine row for DLB_ID=%d after the post-upgrade member add: %s (expected "
        "NUM_PATHS=4)" % (did, eng))
    win = _group_window(chip, did)
    assert win and win[1] * 4 == 256, (
        "flowset window broke after the post-upgrade member add: %s (expected a 256-flow "
        "window)" % (win,))
    assert _sai_errs(cli) == err0, \
        "syncd/orchagent errors after the post-upgrade member add"
