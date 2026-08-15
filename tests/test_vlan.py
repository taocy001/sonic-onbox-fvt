"""L2 VLAN: create/member/ASIC_DB programming + delete lifecycle (negative). The command behavior is the object under test."""
import re
import time

import pytest

from framework import vlanchk

pytestmark = [pytest.mark.l2]

# dataplane tolerances (aligned with test_vlan_chip): received lower bound N*0.8; a small background tolerance for the should-not-receive upper bound; upper bound guards against a storm
_N = 100
_RECV_LOWER = _N * 0.8
_ISO_UPPER = 5
_STORM_UPPER = 100_000
_VM = "ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*"


def _flow_totals(traffic, ports, until=None, timeout=3.0):
    """Call after clear_chip_counters -> send: poll and accumulate each port's total TX/RX since
    clear (this diag's `show c` has "change since last show/clear" semantics, so accumulate each
    time); exit early once until(tx,rx) is true; then do one confirming read (catching late-arriving
    leak frames / a slow storm, mirroring traffic.smoke_check). Returns (tx_totals, rx_totals)."""
    tx = {p.name: 0 for p in ports}
    rx = {p.name: 0 for p in ports}
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(0.4)
        for p in ports:
            d = traffic.chip_counters(p)
            tx[p.name] += d.tx_pkt
            rx[p.name] += d.rx_pkt
        if until and until(tx, rx):
            break
    time.sleep(0.5)
    for p in ports:
        d = traffic.chip_counters(p)
        tx[p.name] += d.tx_pkt
        rx[p.name] += d.rx_pkt
    return tx, rx


def test_vlan_create_in_asicdb(cli, asicdb, config_guard):
    """config vlan add -> a new SAI_VLAN object appears in ASIC_DB."""
    vid = 250
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*")
    cli.config(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*", base, timeout=8), \
        "VLAN not programmed to ASIC_DB"


def test_vlan_show_brief(cli, config_guard):
    """Pure CLI: after creation, show vlan brief shows it, and it's idempotent."""
    vid = 251
    cli.config(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    rows = cli.parse_table(cli.show("vlan brief"))
    assert any(str(vid) == r.get("VLAN ID") for r in rows), "new VLAN not shown in show vlan brief"
    # negative: adding the same VLAN again -- the community image rejects with an error (rc!=0);
    # SONiC is designed to be idempotent (rc=0 and produces no duplicate entry). Both are valid
    # contracts, so assert "either reject, or idempotent with no duplicate".
    rc, r = cli.config_raw(f"vlan add {vid}")
    if rc == 0:
        assert "Traceback" not in ((r.out or "") + (r.err or "")), "duplicate vlan add crashed"
        assert len(cli.db_keys("CONFIG_DB", f"VLAN|Vlan{vid}")) == 1, \
            "idempotent duplicate vlan add produced duplicate CONFIG_DB entries"
    # rc != 0 is the community-style rejection, equally valid


def test_vlan_member_add(cli, asicdb, topo, dut, config_guard):
    """Member join -> the member appears in CONFIG_DB + ASIC VLAN_MEMBER really programmed (orchagent->SAI chain).

    Scope: verify "member join really programs to the chip VLAN member table". The post-join
    dataplane flood/isolation behavior is verified with real traffic in
    test_vlan_scenarios.py::test_vlan_isolation (broadcast injection verifies other-VLAN ports don't receive). This case does not pretend to verify flood behavior."""
    import time
    vid = topo.vlan("d")
    port = topo.l2_port(0).name
    cli.config_raw(f"vlan add {vid}")              # idempotent, ensure it exists
    config_guard.defer_undo(f"vlan del {vid}")
    cli.config_raw(f"vlan member del {vid} {port}")   # clear leftover members first (port reuse), so what follows is a net addition
    for _ in range(10):   # wait for the member to really clear from CONFIG_DB, otherwise base still counts it and the net addition below is 0
        if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|{port}"):
            break
        time.sleep(0.3)
    time.sleep(1)   # then wait for the ASIC side to clear too
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*")
    cli.config(f"vlan member add {vid} {port}")
    config_guard.defer_undo(f"vlan member del {vid} {port}")
    # check the specific member key (robust to port reuse / count fluctuation), ASIC count as corroboration
    found = False
    for _ in range(16):
        if cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|{port}"):
            found = True
            break
        time.sleep(0.5)
    assert found, "member not written to CONFIG_DB"
    if vlanchk.sai_member_model(asicdb):
        assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*", base,
                                    timeout=12), "VLAN member not programmed to ASIC"
    else:
        # SONiC: the member takes effect directly on the chip without building a SAI_VLAN_MEMBER
        # object -- use the chip vlan show bitmap as programming evidence.
        assert vlanchk.chip_member(cli, dut, vid, port), \
            f"VLAN {vid} member {port} not present in chip vlan bitmap (not programmed)"


@pytest.mark.traffic
def test_vlan_member_del_lifecycle(cli, asicdb, traffic, config_guard, topo, dut, _lb):
    """vlan/member DELETE really reaches the chip + forwarding plane (negative lifecycle). Existing
    cases only verify the add direction, with del entirely hidden in config_guard.defer_undo and
    never asserted; but undo carries a silent-failure risk -- the delete path is exactly the
    direction most worth verifying:
    (1) member add -> the chip bitmap appears (poll) (add baseline, so the later "disappearance" is meaningful);
    (2) dataplane baseline: pin injects Dot1Q(vid) broadcast -> member pobs (flood_safe) chip TX+≈N;
    (3) `config vlan member del` -> chip bitmap disappears (poll) + under the SAI model the VLAN_MEMBER object count falls back;
    (4) dataplane consequence: same injection -> pobs TX <= isolation upper bound (delete really takes effect on the forwarding plane, from ≈N to ≈0);
    (5) `config vlan del` -> CONFIG_DB key disappears + chip `vlan show` has no row for that VLAN (object really destroyed).

    Storm prevention: pobs is an untagged member of vid (egress has no tag, so a loopback
    re-entry lands on the flood_safe isolation PVID 3993 and terminates; a tagged-egress re-entry
    frame keeps its tag and self-loops, verified in test_vlan_tag_content); pin keeps its default
    VLAN membership and PVID unchanged, joins vid tagged, injects via Dot1Q landing on vid, so the
    flood domain is only pin+pobs. Readings use clear -> poll accumulate + confirming read (change semantics)."""
    from scapy.all import Ether, Dot1Q, IP, UDP, Raw
    from framework import worker as _W

    vid = _W.remap_vid(252)   # parallel lane split: offset by worker, keeping the static-disjoint audit effective for this case's VLAN
    dv = topo.default_vlan
    pin, pobs = traffic.ports[0], topo.l2_port(0)
    if pin.name == pobs.name:
        pytest.skip("need 2 distinct ports for member-del lifecycle test")
    cli.ensure_port_l2(pobs)   # a routed port doesn't do L2 flooding (SONiC), explicitly switch to bridge
    cli.intf_startup(pobs.name)

    cli.config_raw(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")                       # safety net (backstop if this case fails midway)
    # pin: tagged member (keep its default-VLAN untagged membership and PVID, inject via Dot1Q landing on vid)
    cli.config_raw(f"vlan member add {vid} {pin.name}")
    config_guard.defer_undo(f"vlan member del {vid} {pin.name}")
    # pobs: untagged member (remove from default VLAN first, a port can have only one untagged VLAN)
    cli.config_raw(f"vlan member del {dv} {pobs.name}")
    config_guard.defer_undo(f"vlan member add -u {dv} {pobs.name}")  # back to default VLAN (guard runs in reverse)
    cli.config_raw(f"vlan member add -u {vid} {pobs.name}")
    config_guard.defer_undo(f"vlan member del {vid} {pobs.name}")

    # (1) add really programs: the chip bitmap appears on poll (this is the control baseline for the later "disappears after del")
    added = False
    for _ in range(20):
        if vlanchk.chip_member(cli, dut, vid, pobs, untagged=True):
            added = True
            break
        time.sleep(0.5)
    assert added, (
        f"member add not programmed: {pobs.name} not in chip vlan {vid} untagged bitmap; "
        f"cannot verify the delete path without an add baseline")
    _lb.enable_flood_safe(pobs, 3993)   # pobs loopback (TX measurable) + isolation PVID (re-entry terminates)
    time.sleep(1)
    pkt = (Ether(dst=topo.mac("bcast"), src=topo.mac("src")) / Dot1Q(vlan=vid) /
           IP() / UDP() / Raw(b"x" * 40))
    try:
        # (2) dataplane baseline: member present -> a broadcast within vid should flood to pobs (otherwise the later "TX=0" is vacuous evidence)
        traffic.clear_chip_counters()
        traffic.send(pin, pkt, count=_N)
        tx, _rx = _flow_totals(traffic, [pobs],
                               until=lambda tx, rx: tx[pobs.name] >= _RECV_LOWER)
        assert _RECV_LOWER <= tx[pobs.name] < _STORM_UPPER, (
            f"pre-delete baseline failed: VLAN {vid} member {pobs.name} chip TX={tx[pobs.name]} "
            f"(expected ~{_N}); post-delete zero would be vacuous without this baseline")

        # (3) member del -> chip bitmap disappears (+ under the SAI model the object count falls back)
        rc, r = cli.config_raw(f"vlan member del {vid} {pobs.name}")
        assert rc == 0, (
            f"vlan member del failed (rc={rc}): {(r.err or r.out)[:120]}; "
            "'config vlan member del' is standard SONiC CLI and must succeed")
        gone = False
        for _ in range(20):
            if not vlanchk.chip_member(cli, dut, vid, pobs):
                gone = True
                break
            time.sleep(0.5)
        assert gone, (
            f"member DELETE not reaching chip: {pobs.name} still in chip vlan {vid} bitmap after "
            f"'config vlan member del' (silent undo failure)")
        # Note: don't use the `asicdb.count(SAI_VLAN_MEMBER)` aggregate count as delete evidence --
        # it counts device-wide member objects (including default-VLAN members of every port),
        # member_base mixes in other ports' members, and background changes are noise; on SONiC
        # this count also fluctuates (0<->9), fooling the sai_member_model heuristic, and "stuck at
        # 9" is actually other ports' resident members, not this case's leak. The chip bitmap `gone`
        # (above, hardware-authoritative, passes on both platforms) + the dataplane consequence in
        # step (4) below are stronger per-member evidence, so the delete path's programming-side
        # confirmation uses the chip bitmap.

        # (4) dataplane consequence: after deletion, same injection, pobs should no longer receive this VLAN's flood (≈N -> <= upper bound)
        traffic.clear_chip_counters()
        traffic.send(pin, pkt, count=_N)
        tx2, _rx2 = _flow_totals(traffic, [pobs])
        assert tx2[pobs.name] <= _ISO_UPPER, (
            f"member del not effective in dataplane: {pobs.name} still receives VLAN {vid} "
            f"flood (chip TX={tx2[pobs.name]}) after removal from the VLAN")

        # (5) vlan del -> both CONFIG_DB and chip objects disappear (detach the remaining member pin first, SONiC requires an empty VLAN to delete)
        cli.config_raw(f"vlan member del {vid} {pin.name}")
        rc, r = cli.config_raw(f"vlan del {vid}")
        assert rc == 0, (
            f"vlan del failed (rc={rc}): {(r.err or r.out)[:120]}; "
            "'config vlan del' is standard SONiC CLI and must succeed")
        cfg_gone = False
        for _ in range(20):
            if not cli.db_keys("CONFIG_DB", f"VLAN|Vlan{vid}"):
                cfg_gone = True
                break
            time.sleep(0.5)
        assert cfg_gone, f"VLAN|Vlan{vid} still in CONFIG_DB after 'config vlan del'"
        # On SONiC/SDK6 the chip diag `vlan show` pre-provisions all VLAN IDs (2-4095): for any
        # never-created vid it returns the same `vlan N ports none (0x0..), untagged none
        # MCAST_FLOOD_UNKNOWN` row (all 4083 rows resident) -- so "the vlan show row disappears" is
        # unreachable on this platform, and using it as chip-destroy evidence would always FAIL
        # (that's an over-strict case / wrong premise, not a device defect). On this platform the
        # chip-side observable consequence of `config vlan del` is the member bitmap being cleared
        # (ports none), while the VLAN row itself is resident; object-level destruction is
        # corroborated by the CONFIG_DB key disappearing above (control plane). Assertion: after
        # deletion the chip vlan <vid> has no member ports (the last member pin is really detached
        # too). On an image that really destroys the row, line is empty -> also passes.
        chip_empty = False
        for _ in range(20):
            out = _lb.bsh.cmd(f"vlan show {vid}") or ""
            line = next((ln for ln in out.splitlines()
                         if re.match(rf"^\s*vlan\s+{vid}\b", ln)), "")
            m = re.search(r"ports\s+(.*?)\s*\(0x([0-9a-fA-F]+)\)", line)
            if not line or (m and (m.group(1).strip() == "none" or set(m.group(2)) <= {"0"})):
                chip_empty = True
                break
            time.sleep(0.5)
        assert chip_empty, (
            f"chip VLAN {vid} still has member ports after 'config vlan del' (members not removed "
            f"from chip). Note: on this SDK the diag 'vlan show' row itself persists by design "
            f"(all VIDs 2-4095 pre-provisioned, verified with never-created 253/777) — row presence "
            f"is not a destroy signal, empty membership is.")
    finally:
        _lb.disable_flood_safe(pobs)
        # pobs back to default VLAN / leftover members and VLAN are backstopped by config_guard's reverse defer_undo
        cli.sh.run("sonic-clear fdb all", check=False)
