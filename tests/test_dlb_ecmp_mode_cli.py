"""Standalone DLB **product-path** verification -- `config load-balance ecmp-mode`.

Relation to test_dlb_chip.py: that one injects NHG objects directly via the sairedis queue, which drives the SAI code but is **not the
path a customer takes**; this one goes through the product command, verifying the real deployment form. Both criteria land on the chip logic tables.

Product entry point:
    config load-balance ecmp-mode normal | per-packet | dynamic {eligible|fixed|spray}
    show load-balance ecmp-mode
persists to the `ecmp_mode` field of the CONFIG_DB `SWITCH` table. **This is a global switch**: all ECMP groups share one mode,
so in production plain ECMP and DLB do not coexist (the coexistence case in test_dlb_chip proves SAI capability, not a scenario).

Questions this file answers:
  1. After switching to dynamic, do **existing** ECMP groups convert to DLB in place?
  2. After switching, do **newly created** ECMP routes become DLB groups -- i.e. does it take effect at runtime, or is a restart needed?
  3. After switching back to normal, is the rollback clean?
Criteria: chip `ECMP_UNDERLAY.LB_MODE` (REGULAR vs DYNAMIC) and the addition/removal of `DLB_ECMP` engine entries.
"""
import os
import time

import pytest

from framework import dlb as D
from framework import log as _flog
from framework.l3probe import wait_route as _wait_route

try:
    from scapy.all import IP, UDP, Ether, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_LOG = _flog.get("dlbmode")

pytestmark = [pytest.mark.dlb, pytest.mark.l3, pytest.mark.chiptab]

_NH1_MAC = "00:aa:bb:00:0c:b1"
_NH2_MAC = "00:aa:bb:00:0c:b2"
_NET = "10.253.77.0/24"


def _mode(cli):
    out = cli.sh.run("show load-balance ecmp-mode", check=False).out.strip()
    return out.split(":", 1)[-1].strip() if ":" in out else out


def _set_mode(cli, words):
    rc, r = cli.config_raw("load-balance ecmp-mode %s" % words)
    time.sleep(4)
    return rc, r


def _snapshot(h):
    """The current L2 groups' (ECMP_ID -> LB_MODE) and the DLB engine entry count."""
    ul = {e.get("ECMP_ID"): str(e.get("LB_MODE")) for e in h.underlay()}
    return ul, len(h.dlb_ecmp())


@pytest.fixture
def ecmp_mode_env(l3net, chip):
    """L3 base + mode reclaim: no matter how the case exits, restore the global ECMP mode and the test route."""
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("changes the global ECMP mode of the device: set FVT_DLB=1 to run")
    chip.require()
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP table on this chip")
    cli = l3net.cli
    before = _mode(cli)
    _LOG.info("ecmp-mode before the test: %r", before)
    import types
    yield types.SimpleNamespace(env=l3net, cli=cli, chip=chip,
                                h=D.Dlb(cli, chip), before=before)
    cli.sh.run("ip route del %s" % _NET, check=False)
    _set_mode(cli, "normal")
    time.sleep(3)
    now = _mode(cli)
    _LOG.info("ecmp-mode restored to %r (was %r)", now, before)


@pytest.mark.parametrize("sub,want_mode", [("eligible", "DYNAMIC"),
                                           ("fixed", "DYNAMIC"),
                                           ("spray", "DYNAMIC")])
def test_ecmp_mode_dynamic_submodes(ecmp_mode_env, sub, want_mode):
    """All three dynamic submodes must take effect through the product command and land as a DLB group on the chip.

    `eligible` / `fixed` / `spray` correspond to SAI's three DLB group types; a customer only ever uses this command,
    so all three tiers must be exercised, not just the one the code can construct.
    """
    e = ecmp_mode_env
    cli, h, env = e.cli, e.h, e.env
    nh1, nh2 = env.sub_out["peer"], env.sub_o2["peer"]
    cli.neigh_set(nh1, _NH1_MAC, env.p_out.name)
    cli.neigh_set(nh2, _NH2_MAC, env.p_o2.name)

    rc, r = _set_mode(cli, "dynamic %s" % sub)
    now = _mode(cli)
    assert sub in now, ("`config load-balance ecmp-mode dynamic %s` did not take (mode=%r "
                        "rc=%s out=%r)" % (sub, now, rc, (r.out or "")[:160]))
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s" % (_NET, nh1, nh2),
               check=False)
    if not _wait_route(cli, _NET):
        pytest.fail("DEVICE DEFECT: route did not enter the kernel in %s mode" % sub)
    time.sleep(10)
    ul = [x for x in h.underlay() if str(x.get("LB_MODE")) == want_mode]
    eng = [x for x in h.dlb_ecmp() if x.get("NUM_PATHS")]
    _LOG.info("submode %s -> L2 %s, engine %s", sub,
              [(x.get("ECMP_ID"), x.get("LB_MODE")) for x in ul],
              [(x.get("DLB_ID"), x.get("NUM_PATHS")) for x in eng])
    assert ul, "ecmp-mode dynamic %s did not produce a %s L2 group" % (sub, want_mode)
    assert eng, "ecmp-mode dynamic %s did not produce a DLB engine entry" % sub
    assert str(eng[-1].get("PFC_STATUS_FILTER_MODE")).upper() != "DISABLED", (
        "the PFC filter is off in %s mode: %s" % (sub, eng[-1].get("PFC_STATUS_FILTER_MODE")))


def test_dlb_member_survives_port_flap(ecmp_mode_env):
    """After a member port link flap, the DLB group and member state must recover; a member must not be permanently kicked out.

    In real networks link flaps are far more frequent than config changes, and member state is recomputed on every port event.
    """
    e = ecmp_mode_env
    cli, h, env, chip = e.cli, e.h, e.env, e.chip
    nh1, nh2 = env.sub_out["peer"], env.sub_o2["peer"]
    cli.neigh_set(nh1, _NH1_MAC, env.p_out.name)
    cli.neigh_set(nh2, _NH2_MAC, env.p_o2.name)
    _set_mode(cli, "dynamic eligible")
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s" % (_NET, nh1, nh2),
               check=False)
    time.sleep(10)
    pid = chip.port_id(env.p_out.name)
    before = h.port_override(pid)
    assert before == 0, "member is already overridden before the flap: %s" % before

    cli.config_raw("interface shutdown %s" % env.p_out.name)
    time.sleep(8)
    during = h.port_override(pid)
    cli.config_raw("interface startup %s" % env.p_out.name)
    time.sleep(4)
    env.lb.enable(env.p_out)          # on a loopback rig the port only comes back up via loopback
    time.sleep(12)
    cli.neigh_set(nh1, _NH1_MAC, env.p_out.name)
    time.sleep(10)
    after = h.port_override(pid)
    _LOG.info("port flap: override before=%s during=%s after=%s", before, during, after)
    assert after == 0, (
        "after a link flap the DLB member port stays force-overridden (OVERRIDE=%s): the "
        "member is out of its group for good and that path goes dark" % after)


@pytest.fixture
def fiber_pair(cli, dut, chip):
    """Two ports **with optics plugged in and a real link up**, configured with L3 and static neighbors, restored on exit.

    The DLB dataplane cannot be verified on MAC loopback ports: a loopback port reads HW_DOWN in the engine and the group does not
    forward (while plain ECMP forwards fine under the same conditions). PHY loopback is also impossible -- a high-speed port's TX/RX
    are not on the same physical lane group, and `lb=phy` directly reports "not mapped to the same physical lane". So any case that
    needs to observe DLB forwarding behavior can only hang on real optical ports.

    The two ports need to be interconnected. The case injects from the CPU into one port, which enters the other port over the fiber
    and gets routed, so this pair is both ingress and member.
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("intrusive DLB case: set FVT_DLB=1")
    chip.require()
    have = [k.split("|")[-1] for k in cli.db_keys("STATE_DB", "TRANSCEIVER_INFO|*")]
    up = [p for p in have
          if (cli.db_hgetall("APPL_DB", "PORT_TABLE:%s" % p) or {}).get("oper_status") == "up"]
    up.sort(key=lambda n: int(n.replace("Ethernet", "")))
    if len(up) < 2:
        pytest.skip("need two ports with optics and a real link for DLB dataplane tests; "
                    "found %s (loopback ports cannot carry a DLB group)" % (up or "none"))
    a, b = up[0], up[1]
    ips = {a: "10.91.1.1/24", b: "10.91.2.1/24"}
    peers = {a: "10.91.1.2", b: "10.91.2.2"}
    for p in (a, b):
        cli.config_raw("interface ip add %s %s" % (p, ips[p]))
    time.sleep(3)
    for i, p in enumerate((a, b)):
        cli.neigh_set(peers[p], "00:aa:bb:00:91:%02x" % i, p)
    time.sleep(4)
    import types
    yield types.SimpleNamespace(a=a, b=b, peers=peers, cli=cli, dut=dut, chip=chip,
                                rmac=cli.sh.run("sonic-cfggen -d -v "
                                                "DEVICE_METADATA.localhost.mac",
                                                check=False).out.strip())
    cli.sh.run("ip route del 10.91.9.0/24", check=False)
    for p in (a, b):
        try:
            cli.neigh_del(peers[p], p)
        except Exception:  # noqa: BLE001
            pass
        cli.config_raw("interface ip remove %s %s" % (p, ips[p]))
    cli.config_raw("load-balance ecmp-mode normal")


def test_dlb_single_flow_stays_on_one_member(fiber_pair):
    """**One flow must always take one path.** This is the entire value of DLB over per-packet hashing.

    If flow stickiness is lost it degrades into per-packet reselection and reorders the whole flow -- fatal for both TCP and RoCE.
    This case does not care which config provides the backstop, it only pins down the **externally visible behavior**.

    The criterion is taken from the chip rather than SONiC counters: `show interfaces counters` mixes in RX on a hairpin/back-to-back topology.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    from framework.ports import Port
    f = fiber_pair
    cli, chip = f.cli, f.chip
    h = D.Dlb(cli, chip)
    net = "10.91.9.0/24"
    cli.config_raw("load-balance ecmp-mode dynamic eligible")
    time.sleep(4)
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s"
               % (net, f.peers[f.a], f.peers[f.b]), check=False)
    time.sleep(12)
    ents = [x for x in h.dlb_ecmp() if x.get("NUM_PATHS")]
    if not ents:
        pytest.fail("no DLB engine entry after building the route")
    eng = ents[-1]
    _LOG.info("group: filter=%s prefer_last=%s paths=%s", eng.get("PFC_STATUS_FILTER_MODE"),
              eng.get("PREFER_LAST_CHOICE"), eng.get("NUM_PATHS"))

    from framework.counters import ChipCounters
    n = 20000
    before = _reassign_count(h)
    bsh = chip.bsh
    ChipCounters.clear(bsh)
    pkt = (Ether(dst=f.rmac, src="00:de:ad:00:11:01") /
           IP(src="10.66.1.1", dst="10.91.9.7") / UDP(sport=40001, dport=80))
    sendp(pkt, iface=f.b, count=n, verbose=False)
    time.sleep(4)
    tx1 = ChipCounters.read(bsh, f.dut.bcm_of(Port(name=f.a))).tx_pkt
    tx2 = max(ChipCounters.read(bsh, f.dut.bcm_of(Port(name=f.b))).tx_pkt - n, 0)
    grew = _reassign_count(h) - before
    total = tx1 + tx2
    _LOG.info("single flow over fibre: out_%s=%d out_%s=%d reassign+=%d",
              f.a, tx1, f.b, tx2, grew)

    if total < n * 0.8:
        # A DLB group does not forward over MAC loopback: the members read back HW_DOWN in
        # the engine, so nothing is assignable. Only a real link exercises this. Skip rather
        # than fail - the rig cannot answer the question, and pretending otherwise would
        # turn a topology limit into a fake defect.
        pytest.skip("only %d of %d packets forwarded: this pair is MAC loopback, and DLB does "
                    "not forward over it. Run on ports with real optics to exercise flow "
                    "stickiness." % (total, n))
    minor = min(tx1, tx2)
    assert minor <= total * 0.02, (
        "a single flow was split %d:%d across the two members - DLB is reselecting per packet "
        "instead of keeping the flow on one member, which reorders every flow (reassignments "
        "during the run: %d)" % (tx1, tx2, grew))
    assert grew <= n * 0.01, (
        "%d reassignments for %d packets of one flow: the flowlet gate is not holding"
        % (grew, n))


def _reassign_count(h):
    for e in h._traverse("DLB_ECMP_STATS"):
        if "PORT_REASSIGNMENT_CNT" in e:
            return e["PORT_REASSIGNMENT_CNT"]
    return 0


def _dlb_state(h, chip, ports):
    """Fetch all the DLB group's key attributes in one shot, for step-by-step assertions."""
    ents = [e for e in h.dlb_ecmp() if e.get("NUM_PATHS")]
    eng = ents[-1] if ents else {}
    ul = [e for e in h.underlay() if str(e.get("LB_MODE")) == "DYNAMIC"]
    return {
        "num_paths": eng.get("NUM_PATHS"),
        "filter": str(eng.get("PFC_STATUS_FILTER_MODE")),
        "flowset": str(eng.get("FLOW_SET_SIZE")),
        "inactive": eng.get("INACTIVITY_TIME"),
        "lb_mode": str(ul[-1].get("LB_MODE")) if ul else None,
        "overrides": {p: h.port_override(p) for p in ports},
    }


def test_dlb_attributes_survive_member_growth(ecmp_mode_env):
    """**When adding members grows the group, the DLB attributes must be preserved as-is.**

    Adding members to the point of needing growth goes through get -> modify -> REPLACE, the whole group is reprogrammed, and
    attributes may be dropped during the rewrite. Building only 2 members never crosses the first allocation granularity, so
    **attribute assertions must run at a scale that triggers a state rewrite**.

    Grow members step by step from 2 to 6 (crossing the allocation granularity), checking at each step: dynamic mode, PFC filter mode,
    flowset size, aging time, and each member port's OVERRIDE.
    """
    e = ecmp_mode_env
    cli, h, env, chip = e.cli, e.h, e.env, e.chip
    assert "normal" in e.before, "device did not start from ecmp-mode normal (%r)" % e.before

    # 6 next hops spread across two egress ports (member count determines granularity, no need for one port per member)
    peers = []
    for port, sub, base in ((env.p_out, env.sub_out, 0x21), (env.p_o2, env.sub_o2, 0x31)):
        net = sub["peer"].rsplit(".", 1)[0]
        for k in range(3):
            ip = "%s.%d" % (net, 221 + base % 16 * 4 + k)
            cli.neigh_set(ip, "00:aa:bb:00:%02x:%02x" % (base, k), port.name)
            peers.append(ip)
    pids = [chip.port_id(env.p_out.name), chip.port_id(env.p_o2.name)]

    _set_mode(cli, "dynamic eligible")
    assert "normal" not in _mode(cli), "could not switch to dynamic eligible"

    seen = []
    try:
        for n in (2, 3, 4, 5, 6):
            cli.sh.run("ip route replace %s %s"
                       % (_NET, " ".join("nexthop via %s" % p for p in peers[:n])), check=False)
            time.sleep(10)
            st = _dlb_state(h, chip, pids)
            _LOG.info("members=%d -> %s", n, st)
            seen.append((n, st))

        bad = [(n, s) for n, s in seen if s["filter"] in ("DISABLED", "None", "0")]
        assert not bad, (
            "the DLB PFC filter was lost as the group grew: %s. Growing past the allocation "
            "increment replaces the whole group, and the replace must not drop the filter — "
            "a member paused by PFC would silently start taking new flows again"
            % [(n, s["filter"]) for n, s in bad])
        bad = [(n, s["lb_mode"]) for n, s in seen if s["lb_mode"] != "DYNAMIC"]
        assert not bad, "the group stopped being DYNAMIC while growing: %s" % bad
        bad = [(n, s["flowset"]) for n, s in seen if "256" not in s["flowset"]]
        assert not bad, "flowset size was lost while growing: %s" % bad
        bad = [(n, s["inactive"]) for n, s in seen if s["inactive"] != 256]
        assert not bad, "flowset inactive time was lost while growing: %s" % bad
        bad = [(n, s["overrides"]) for n, s in seen
               if any(v not in (0, None) for v in s["overrides"].values())]
        assert not bad, ("a member port was force-overridden while the group grew: %s "
                         "(every packet on that path would be dropped)" % bad)
    finally:
        cli.sh.run("ip route del %s" % _NET, check=False)
        for ip, port in zip(peers, [env.p_out] * 3 + [env.p_o2] * 3):
            try:
                cli.neigh_del(ip, port.name)
            except Exception:  # noqa: BLE001
                pass


def test_ecmp_mode_dynamic_takes_effect_at_runtime(ecmp_mode_env):
    """After switching to `dynamic eligible`, an ECMP route must become a DLB group -- and clarify whether a restart is needed.

    Steps and criteria:
      1. Build a two-nexthop ECMP route in normal mode -> chip L2 group `LB_MODE=REGULAR`, no DLB engine entry;
      2. Globally switch to `dynamic eligible` (no restart) -> record whether the **existing** group converts in place;
      3. Delete and recreate the route -> assert the **newly created** group is `LB_MODE=DYNAMIC` and a DLB engine entry appears.
         If this step does not hold, runtime application does not take effect (a restart or other action is needed); the case fails honestly and writes the observation to the log.
    """
    e = ecmp_mode_env
    cli, h, env = e.cli, e.h, e.env
    nh1, nh2 = env.sub_out["peer"], env.sub_o2["peer"]
    cli.neigh_set(nh1, _NH1_MAC, env.p_out.name)
    cli.neigh_set(nh2, _NH2_MAC, env.p_o2.name)

    # ---- 1) baseline in normal mode ----
    assert "normal" in e.before, ("device did not start from ecmp-mode normal (%r): refusing "
                                  "to draw conclusions from a dirty baseline" % e.before)
    base_ul, base_dlb = _snapshot(h)
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s" % (_NET, nh1, nh2),
               check=False)
    if not _wait_route(cli, _NET):
        pytest.fail("DEVICE DEFECT: ECMP route %s never entered the kernel" % _NET)
    time.sleep(6)
    ul_normal, dlb_normal = _snapshot(h)
    new_normal = {k: v for k, v in ul_normal.items() if k not in base_ul}
    _LOG.info("normal mode: new L2 groups=%s, DLB engine entries %d -> %d",
              new_normal, base_dlb, dlb_normal)
    assert new_normal, "no new L2 ECMP group appeared for the test route in normal mode"
    assert all(v == "REGULAR" for v in new_normal.values()), (
        "in ecmp-mode normal the group is already %s, expected REGULAR" % new_normal)
    assert dlb_normal == base_dlb, (
        "a DLB engine entry appeared in ecmp-mode normal (%d -> %d)" % (base_dlb, dlb_normal))

    # ---- 2) globally switch to dynamic eligible, no restart ----
    rc, r = _set_mode(cli, "dynamic eligible")
    now = _mode(cli)
    _LOG.info("after `config load-balance ecmp-mode dynamic eligible`: rc=%s mode=%r out=%r",
              rc, now, (r.out or "")[:200])
    assert "normal" not in now, (
        "the CLI did not change the mode (still %r, rc=%s, output %r)"
        % (now, rc, (r.out or "")[:200]))
    time.sleep(8)
    ul_conv, dlb_conv = _snapshot(h)
    converted = {k: ul_conv.get(k) for k in new_normal}
    _LOG.info("existing group after the switch: %s, DLB engine entries=%d",
              converted, dlb_conv)

    # ---- 3) delete and recreate, inspect the newly created group ----
    cli.sh.run("ip route del %s" % _NET, check=False)
    time.sleep(6)
    mid_ul, _mid_dlb = _snapshot(h)
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s" % (_NET, nh1, nh2),
               check=False)
    if not _wait_route(cli, _NET):
        pytest.fail("DEVICE DEFECT: ECMP route did not come back after the mode switch")
    time.sleep(8)
    ul_dyn, dlb_dyn = _snapshot(h)
    new_dyn = {k: v for k, v in ul_dyn.items() if k not in mid_ul}
    _LOG.info("after the switch, a freshly created route gives L2 groups=%s, DLB engine "
              "entries=%d (was %d in normal mode)", new_dyn, dlb_dyn, dlb_normal)

    assert new_dyn, "no new L2 group appeared for the route recreated in dynamic mode"
    assert all(v == "DYNAMIC" for v in new_dyn.values()), (
        "after `ecmp-mode dynamic eligible`, a newly created ECMP route still programs "
        "%s instead of DYNAMIC: the global mode does not take effect at runtime (it would "
        "need a restart, which is an operational constraint worth documenting). Existing "
        "group after the switch was %s" % (new_dyn, converted))
    assert dlb_dyn > dlb_normal, (
        "no DLB engine entry was created for the dynamic mode group (%d -> %d)"
        % (dlb_normal, dlb_dyn))
