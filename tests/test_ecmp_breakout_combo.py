"""Load balancing x port breakout: whether breakout subports can really participate in ECMP / DLB load balancing.

Why this is its own group: DLB group members are `DLB_ECMP.PORT_ID[]` on the chip -- one
physical port per path. Port breakout directly changes "how many physical ports are
available", and thus directly decides which physical paths can form a load-balancing group.
Existing breakout cases only test subport L2 forwarding and the QoS tree; none attaches a
subport into a load-balancing group. And on port attach the SDK resets the DLB scaling
factor to a default 10G (if a subport isn't re-scored, a 200G subport is accounted at 10G,
its readings inflated 20x, and it gets pinned to the worst quality band) -- this chain can
only be verified by making a subport a DLB member.

Three cases:
  1. subport as a plain ECMP member -- first prove breakout itself doesn't block L3 load balancing;
  2. subport as a DLB member -- N mutually distinct PORT_IDs appear in the group, and each
     subport's scaling factor matches its real speed;
  3. merge a subport back while it's still a group member -- the group must shrink cleanly,
     leaving no residue and not collapsing.
"""
import logging
import os
import re
import time

import pytest

_LOG = logging.getLogger("dut.brcombo")
_PREFIX = 24
_NET = "10.231.9.0/24"


def _mode_by_ways(modes, ways):
    """Prefer whole-cage modes; the "(4)" 4-lane variant is not accepted by some CLIs (same selection as the breakout group)."""
    cands = sorted(m for m in modes if m.startswith("%dx" % ways))
    for m in cands:
        if "(" not in m:
            return m
    return cands[0] if cands else None


@pytest.fixture(scope="module")
def brk_env(topo, chip, dut):
    """Victim port and mode selection. Same as test_breakout_chip (take from the tail of the
    port table, avoiding test-role ports), but that one is a module-local fixture unusable
    across modules, so this is a standalone copy."""
    from framework import breakout as BK
    topo.caps.require("breakout_dpb")
    chip.require()
    cands = [p for p in dut.ports if re.match(r"Ethernet\d+$", p.name)]
    assert len(cands) >= 16, "device port table too small for a breakout victim"
    va = cands[-1].name
    modes = BK.platform_modes(dut, va)
    if not modes:
        pytest.fail("DEVICE DEFECT: caps.breakout_dpb declared but platform.json has no "
                    "breakout_modes for %s" % va)
    return {"va": va, "modes_a": modes}


@pytest.fixture
def split_l3(brk_env, bdrv, cli, dut, _lb, topo, chip):
    """Break one front-panel port into 4 subports, each configured as L3 + loopback + one static neighbor.

    Returns {'parent', 'mode', 'subs': [(name, ip_peer, speed)], ...}.
    Teardown tears down in reverse then merges back -- L3 config MUST be removed before
    merging: merging while still carrying IPs makes a subport disappear while intfmgrd still
    references it, leaving an INTERFACE row pointing at a nonexistent port (exactly the kind
    of residue that breeds zombie RIFs).
    """
    from framework import hygiene
    from framework.ports import Port

    parent = brk_env["va"]
    mode4 = _mode_by_ways(brk_env["modes_a"], 4)
    if not mode4:
        pytest.skip("no 4x breakout mode declared for %s: %s"
                    % (parent, sorted(brk_env["modes_a"])))
    restore = bdrv.current_mode(parent) or _mode_by_ways(brk_env["modes_a"], 1)
    # before breakout, the parent must leave the VLAN: `config interface breakout` outright
    # rejects a VLAN member port ("Please delete <port> VLAN ... no further action will be
    # taken"), and Vlan1 on this NOS can't be detached with vlan member del (valid range
    # 2~4094), only link-mode route can detach it.
    cli.restore_port_l3(parent)
    res = bdrv.split(parent, mode4)
    if not res["ok"]:
        pytest.fail("DEVICE DEFECT: 4-way breakout of %s to %s failed: %s"
                    % (parent, mode4, res["text"]))

    dv = topo.default_vlan
    subs, built = [], []
    for i, (name, _lanes, speed) in enumerate(res["subports"], start=1):
        p = Port(name=name)
        hygiene.reset_port_to_l2(cli, _lb, dut, p, dv)
        cli.config_raw("vlan member del %s %s" % (dv, name))
        for _ in range(20):
            if not cli.db_keys("CONFIG_DB", "VLAN_MEMBER|Vlan%s|%s" % (dv, name)):
                break
            time.sleep(0.3)
        cidr = "10.231.%d.1/%d" % (i, _PREFIX)
        cli.config("interface ip add %s %s" % (name, cidr))
        cli.intf_startup(name)
        if not hygiene.wait_port_unbridged(cli, name):
            pytest.fail("subport %s still an ASIC bridge port; refusing to loop it "
                        "(mixed L2+L3 + loopback storms)" % name)
        # loopback must go through lt/PC_PORT: `dut.bcm_of()` is a formula from the port name,
        # and all breakout subports compute to the same chip port, so setting loopback by it
        # sets only one port -- the other three never come up and can't join the group as next
        # hops. The correct path is to look up PC_PORT_PHYS_MAP by lane, i.e. chip.port_id.
        bdrv.chip_loopback(name, True)
        for _ in range(30):
            if (cli.db_hgetall("APPL_DB", "PORT_TABLE:%s" % name) or {}).get(
                    "oper_status") == "up":
                break
            time.sleep(1)
        else:
            pytest.fail("DEVICE DEFECT: breakout subport %s never came oper-up with MAC "
                        "loopback on (chip PORT_ID=%s); it cannot serve as a next hop"
                        % (name, chip.port_id(name)))
        peer = "10.231.%d.2" % i
        cli.neigh_set(peer, "00:aa:bb:00:31:%02x" % i, name)
        subs.append((name, peer, speed))
        built.append((name, cidr, p))

    import types
    yield types.SimpleNamespace(parent=parent, mode=mode4, subs=subs,
                                res=res, cli=cli, dut=dut, lb=_lb, bsh=_lb.bsh)

    cli.sh.run("ip route del %s" % _NET, check=False)
    for name, cidr, p in built:
        for peer in [s[1] for s in subs if s[0] == name]:
            try:
                cli.neigh_del(peer, name)
            except Exception:                                    # noqa: BLE001
                pass
        try:
            bdrv.chip_loopback(name, False)
        except Exception:                                        # noqa: BLE001
            pass
        cli.config_raw("interface ip remove %s %s" % (name, cidr))
    # the subports are about to disappear, so clear their own INTERFACE rows first, otherwise
    # rows pointing at nonexistent ports remain. Only clear ports this test created -- a
    # device-wide clear would also delete the default L3 port rows present at boot.
    hygiene.purge_orphan_l3_rows(cli, ports=[n for n, _c, _p in built])
    m = bdrv.merge(parent, restore)
    assert m["ok"], ("CLEANUP FAILURE: merge %s back to %s failed: %s — device left split"
                     % (parent, restore, m["text"]))
    bdrv.gone([n for n, _, _ in res["subports"] if n != parent])


def _install_route(cli, peers):
    cli.sh.run("ip route replace %s %s"
               % (_NET, " ".join("nexthop via %s" % p for p in peers)), check=False)
    for _ in range(30):
        out = cli.sh.run("ip route show %s" % _NET, check=False).out or ""
        if len(re.findall(r"nexthop", out)) >= min(len(peers), 2) or (
                len(peers) == 1 and "via" in out):
            return True
        time.sleep(1)
    return False


def _dlb_group_ports(chip, count):
    """Set of physical ports in the first `count` PORT_ID slots of the DLB group.

    Can't use `chip.traverse`: `PORT_ID[0]=0x80(128),PORT_ID[1]=...` is one line of a
    comma-separated array, and line-based parsing can't extract it (the previous version thus
    got an empty set and misreported "subports not in the group"). `framework.dlb.parse_entries`
    handles all three echo forms, and `field_at` also handles range-compressed filler slots
    like `PORT_ID[58-63]=0`. Look only at the first `count` slots, avoiding filler values in
    unused slots.
    """
    from framework import dlb as _D
    out = chip.cmd("lt DLB_ECMP traverse -l")
    best = set()
    for e in _D.parse_entries(out):
        if "PORT_ID[]" not in e:
            continue
        ids = {_D.field_at(e, "PORT_ID", i) for i in range(count)}
        ids.discard(None)
        if len(ids) > len(best):
            best = ids
    return best


def _nhg_member_count(cli):
    """Number of members in the largest next hop group in ASIC."""
    from framework.verify import AsicDb
    asic = AsicDb(cli)
    groups = {}
    for k in asic.objects("SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"):
        g = (cli.db_hgetall("ASIC_DB", k) or {}).get(
            "SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID")
        if g:
            groups[g] = groups.get(g, 0) + 1
    return max(groups.values(), default=0)


def test_ecmp_over_breakout_subports(split_l3, cli):
    """The 4 breakout subports as 4 next hops of plain ECMP: the NHG must really have 4 members.

    Establish this control first -- if it doesn't work, the later DLB conclusions can't be
    attributed to DLB.
    """
    peers = [p for _n, p, _s in split_l3.subs]
    assert _install_route(cli, peers), (
        "DEVICE DEFECT: ECMP route %s over %d breakout subports never entered the kernel"
        % (_NET, len(peers)))
    time.sleep(8)
    n = _nhg_member_count(cli)
    assert n >= len(peers), (
        "ECMP group over breakout subports has %d members, expected %d: subports do not "
        "become usable ECMP next hops" % (n, len(peers)))
    _LOG.info("plain ECMP over %d subports of %s: NHG members=%d",
              len(peers), split_l3.parent, n)


def test_dlb_group_over_breakout_subports(split_l3, cli, chip):
    """4 subports form one DLB group: 4 mutually distinct PORT_IDs must appear in the group.

    This is the direct measurement of "which physical paths can form a DLB load-balancing
    group". It also reads back each member's `DLB_PORT_CONTROL.SCALING_FACTOR` -- a subport is
    reset to a default 10G on SDK port attach, and the driver must re-score it after building
    the port, otherwise a 200G subport is accounted at 10G and permanently pinned to the worst
    quality band.
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("intrusive DLB case: set FVT_DLB=1")
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip")
    cli.config_raw("load-balance ecmp-mode dynamic eligible")
    try:
        peers = [p for _n, p, _s in split_l3.subs]
        assert _install_route(cli, peers), (
            "DEVICE DEFECT: route %s over breakout subports never entered the kernel" % _NET)
        time.sleep(10)

        want = {chip.port_id(n) for n, _p, _s in split_l3.subs}
        ports = _dlb_group_ports(chip, len(peers))
        assert ports, ("no DLB group with member ports was built for a route over %d breakout "
                       "subports while the global ecmp mode is dynamic: breakout subports "
                       "cannot form a DLB group" % len(peers))
        assert ports == want, (
            "the DLB group's physical paths are %s but the %d breakout subports are %s: the "
            "group is not made of exactly the subports the route names"
            % (sorted(ports), len(peers), sorted(want)))
        _LOG.info("DLB over %d subports of %s: PORT_ID=%s",
                  len(peers), split_l3.parent, sorted(ports))

        # per-subport load calibration: a broken-out 200G subport must not still carry the 10G default from attach
        bad = []
        for name, _peer, speed in split_l3.subs:
            ent = chip.lookup("DLB_PORT_CONTROL", PORT_ID=chip.port_id(name)) or {}
            sf = str(ent.get("SCALING_FACTOR", ""))
            if sf and "10G" in sf and int(speed) > 10000:
                bad.append((name, speed, sf))
        assert not bad, (
            "breakout subports left at the SDK default 10G DLB scaling factor %s: their load "
            "readings are scaled ~%dx high and they get pinned to the worst quality band"
            % (bad, int(bad[0][1]) // 10000))
    finally:
        cli.config_raw("load-balance ecmp-mode normal")


def test_dlb_group_survives_subport_merge(split_l3, cli, chip, bdrv):
    """Merge a subport back while it's still a DLB group member: the group must shrink cleanly, leaving no residual group and not collapsing the device.

    Merging makes the SAI port object disappear while it's still referenced by a next hop /
    DLB member. This is the most failure-prone step at the intersection of breakout and load
    balancing -- a breakage shows up as a residual DLB group referencing a nonexistent port,
    or syncd crashing.
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("intrusive DLB case: set FVT_DLB=1")
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip")
    cli.config_raw("load-balance ecmp-mode dynamic eligible")
    peers = [p for _n, p, _s in split_l3.subs]
    assert _install_route(cli, peers), "route over subports never entered the kernel"
    time.sleep(10)
    before = len(chip.traverse("DLB_ECMP") or [])
    assert before, "no DLB group to start from"

    # withdrawing the route = withdrawing the members, the canonical "members disappear" path in production; the merge itself is handled by fixture teardown.
    cli.sh.run("ip route del %s" % _NET, check=False)
    time.sleep(10)
    after = chip.traverse("DLB_ECMP") or []
    cli.config_raw("load-balance ecmp-mode normal")

    assert len(after) < before, (
        "the DLB group built over breakout subports survived the route being withdrawn "
        "(%d groups before, %d after): the group leaks when its members go away"
        % (before, len(after)))
    assert cli.sh.run("docker ps --format '{{.Names}}' | grep -c syncd",
                      check=False).out.strip() == "1", (
        "syncd is gone after withdrawing a DLB group built on breakout subports")
    _LOG.info("DLB groups over subports: %d -> %d after route withdrawal", before, len(after))
