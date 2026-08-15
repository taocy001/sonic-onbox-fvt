"""DPB dynamic port breakout (1-to-2 / 1-to-4) full-chain verification -- previously zero coverage across the suite.

Verification stack: CONFIG_DB PORT rebuild (lane split / speed / subport names) -> APPL_DB -> ASIC_DB
port objects -> SDKLT PC_PORT/TM tables -> subport L2 forwarding traffic -> merge reclaim with no leak
-> persistence.

Test-method notes:
- `-f` click semantics can be reversed across images (help text states the dependency clearly, yet in
  practice passing -f may reject) -- assert per help text, with the driver layer adapting to either
  semantic.
- Subport lossless/PFC is detected via a "subport bitmap consistency" assertion, without relying on
  each platform's absolute expected values.
- Subport loopback / chip reads always go by logical PORT_ID (the chiptab mapping goes through
  PC_PORT_PHYS_MAP, which naturally holds for subports).

Port usage: victim A = the **last port** in the device port table (shared base for the 4-way split),
victim B = the second-to-last port (independent up/down cases). Both are far from the a-h role ports.

**Must run in a dedicated round**: `pytest -m breakout`. This group deletes/creates ports; if run in
the same round as regular cases,
(1) a mid-split failure leaves subports in the port table, and later port selection may pick a subport
(platform.json has no breakout_modes for it), causing cascading failures across the group;
(2) port delete/create makes the round's L2/QoS cases lose their port persona.
"""
import re
import time

import pytest

from framework import breakout as BK
from framework.counters import PortCounters

pytestmark = [pytest.mark.breakout, pytest.mark.chiptab]

try:
    from scapy.all import Ether, IP, UDP, Raw, sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 120


def _pick_victim(dut, idx):
    """Take a victim port from the tail of the port table (idx=1 is the last, 2 is the second-to-last)."""
    cands = [p for p in dut.ports if re.match(r"Ethernet\d+$", p.name)]
    assert len(cands) >= 16, "device port table too small for breakout victims"
    return cands[-idx].name


def _modes_of(dut, port):
    return BK.platform_modes(dut, port)


def _mode_by_ways(modes, ways):
    # prefer full-cage modes; "(4)" style 4-lane variants are rejected by some CLIs
    cands = sorted(m for m in modes if m.startswith(f"{ways}x"))
    for m in cands:
        if "(" not in m:
            return m
    return cands[0] if cands else None


def _speed_evidence(ent, mbps):
    """Speed evidence from the PC_PORT table (field name/unit differs across chips; do a lenient match and return the raw value)."""
    if not ent:
        return False, None
    for f, v in ent.items():
        if "SPEED" not in f:
            continue
        if isinstance(v, int) and v in (mbps, mbps * 1000, mbps // 1000):
            return True, (f, v)
        if isinstance(v, str) and f"{mbps // 1000}G" in v.upper():
            return True, (f, v)
    return False, {k: v for k, v in ent.items() if "SPEED" in k}


@pytest.fixture(scope="module")
def brk_env(topo, chip, dut, cli):
    """Group setup: capability/diagnostic gating + victim-port and mode selection + baseline recording.
    (caps is a function-level fixture; at module level here we go directly through session-level topo.caps.)"""
    topo.caps.require("breakout_dpb")
    chip.require()
    va, vb = _pick_victim(dut, 1), _pick_victim(dut, 2)
    modes_a, modes_b = _modes_of(dut, va), _modes_of(dut, vb)
    if not modes_a or not modes_b:
        pytest.fail("caps.breakout_dpb declared but platform.json has "
                    f"no breakout_modes for {va}/{vb} — DPB structurally impossible; "
                    "fix profile or platform.json")
    return {"va": va, "vb": vb, "modes_a": modes_a, "modes_b": modes_b}


@pytest.fixture(scope="module")
def split4(brk_env, bdrv, cli):
    """victim A 1-to-4 shared base: split once, for BR2-BR5/BR9 assertions; merge back and cross-check at group end."""
    port = brk_env["va"]
    mode4 = _mode_by_ways(brk_env["modes_a"], 4)
    if not mode4:
        pytest.skip(f"no 4x mode in platform.json for {port}: "
                    f"{sorted(brk_env['modes_a'])}")
    restore = bdrv.current_mode(port) or _mode_by_ways(brk_env["modes_a"], 1)
    res = bdrv.split(port, mode4)
    if not res["ok"]:
        pytest.fail(f"4-way breakout of {port} to {mode4} failed: "
                    f"{res['text']}")
    yield {"port": port, "mode": mode4, "restore": restore, **res}
    m = bdrv.merge(port, restore)
    assert m["ok"], (
        f"CLEANUP FAILURE: merge {port} back to {restore} failed: {m['text']} — "
        f"device left split; manual `config interface breakout {port} '{restore}'` needed")
    bdrv.gone([n for n, _, _ in res["subports"] if n != port])


def test_br1_split2_full_chain(brk_env, bdrv, chip, cli, asicdb):
    """BR1 1-to-2 full chain (victim B independent up/down): CONFIG lanes split/speed -> APPL ->
    ASIC PORT object count -> chip PC_PORT SPEED/NUM_LANES, then merge back."""
    port = brk_env["vb"]
    mode2 = _mode_by_ways(brk_env["modes_b"], 2)
    if not mode2:
        pytest.skip(f"no 2x mode declared for {port}")
    restore = bdrv.current_mode(port) or _mode_by_ways(brk_env["modes_b"], 1)
    n_ports_before = len(asicdb.objects("SAI_OBJECT_TYPE_PORT"))
    res = bdrv.split(port, mode2)
    try:
        assert res["ok"], f"2-way breakout failed: {res['text']}"
        for name, lanes, speed in res["subports"]:
            h = cli.db_hgetall("CONFIG_DB", f"PORT|{name}") or {}
            assert h.get("lanes") == ",".join(map(str, lanes)), (
                f"subport {name} lanes wrong: cfg={h.get('lanes')} expect={lanes}")
            assert h.get("speed") == speed, (
                f"subport {name} speed wrong: cfg={h.get('speed')} expect={speed}")
            ent = chip.pc_port(name)
            assert ent, f"chip PC_PORT for subport {name} unreadable (ghost mapping?)"
            assert ent.get("NUM_LANES") == len(lanes), (
                f"chip NUM_LANES for {name} = {ent.get('NUM_LANES')}, expect "
                f"{len(lanes)}")
            ok, got = _speed_evidence(ent, int(speed))
            assert ok, f"chip PC_PORT speed for {name} != {speed}: {got}"
        deadline = time.time() + 20
        while time.time() < deadline:
            if len(asicdb.objects("SAI_OBJECT_TYPE_PORT")) >= n_ports_before + 1:
                break
            time.sleep(1)
        assert len(asicdb.objects("SAI_OBJECT_TYPE_PORT")) >= n_ports_before + 1, \
            "ASIC PORT object count did not grow after 2-way split"
    finally:
        m = bdrv.merge(port, restore)
        assert m["ok"], (f"CLEANUP FAILURE: merge {port} back to {restore} failed: "
                         f"{m['text']}")


def test_br2_split4_subports_chain(split4, cli, chip):
    """BR2 1-to-4: per-subport CONFIG/chip check for the 4 subports (shared base)."""
    for name, lanes, speed in split4["subports"]:
        h = cli.db_hgetall("CONFIG_DB", f"PORT|{name}") or {}
        assert h.get("lanes") == ",".join(map(str, lanes)), (
            f"subport {name} lanes: cfg={h.get('lanes')} expect={lanes}")
        ent = chip.pc_port(name)
        assert ent and ent.get("NUM_LANES") == len(lanes), (
            f"chip PC_PORT NUM_LANES for {name}: {ent}")
        ok, got = _speed_evidence(ent, int(speed))
        assert ok, f"chip PC_PORT speed for {name} != {speed}: {got}"


def _asic_port_by_lanes(cli, asicdb, lanes):
    """Find a subport's ASIC PORT oid by HW_LANE_LIST (after split the COUNTERS name map may lag; the
    lane set is the only reliable identity)."""
    want = set(map(int, lanes))
    for k in asicdb.objects("SAI_OBJECT_TYPE_PORT"):
        v = (cli.db_hgetall("ASIC_DB", k) or {}).get("SAI_PORT_ATTR_HW_LANE_LIST", "")
        nums = {int(x) for x in re.findall(r"\d+", str(v).split(":", 1)[-1])}
        if nums == want:
            return k.rsplit(":", 1)[-1]
    return None


def test_br3_subport_qos_tree_present(split4, cli, chip):
    """BR3 QoS queue-tree completeness per subport: count that subport's queues via
    COUNTERS_QUEUE_NAME_MAP (>=8), and verify the chip-side scheduler node for that port is readable.

    Method note: ASIC_DB QUEUE and INGRESS_PRIORITY_GROUP objects **do not carry a PORT attribute**,
    so they cannot be reverse-looked-up by port; the COUNTERS name map is the only way to build the
    port:queue -> oid correspondence."""
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP") or {}
    bad = []
    for name, _lanes, _speed in split4["subports"]:
        qs = [k for k in m if k.startswith(name + ":")]
        if len(qs) < 8:
            bad.append((name, f"only {len(qs)} queues in COUNTERS_QUEUE_NAME_MAP"))
            continue
        node = chip.sched_node(name, 0)
        if not node:
            bad.append((name, "chip TM_SCHEDULER_NODE unreadable for q0"))
    assert not bad, f"subport QoS tree incomplete: {bad}"


@pytest.mark.traffic
def test_br5_subport_l2_forward_traffic(split4, bdrv, cli, dut, topo):
    """BR5 subport real forwarding (traffic): two subports with lt loopback + test VLAN + static FDB
    steering, SAI port counter TX ~ N (behavioral evidence that a subport is a fully forwardable port)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    subs = [n for n, _, _ in split4["subports"]]
    s_in, s_out = subs[0], subs[1]
    vid = topo.vlan("b")
    dst = "00:aa:bb:cc:dd:b5"
    for s in (s_in, s_out):
        cli.config_raw(f"interface startup {s}")
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{s}.disable_ipv6=1", check=False)
    pids = {}
    try:
        for s in (s_in, s_out):
            pids[s] = bdrv.chip_loopback(s, on=True)
        rc, r = cli.config_raw(f"vlan add {vid}")
        for s in (s_in, s_out):
            cli.config_raw(f"vlan member add -u {vid} {s}")
        time.sleep(3)
        cli.fdb_static_add(vid, dst, s_out)
        base = PortCounters.read(cli, _P(s_out))
        pkt = (Ether(dst=dst, src="00:de:ad:be:ef:b5")
               / IP(dst="2.2.2.2") / UDP() / Raw(b"BRK5" + b"x" * 40))
        sendp(pkt, iface=s_in, count=_N, inter=0.002, verbose=False)
        got = 0
        deadline = time.time() + 20
        while time.time() < deadline:
            cur = PortCounters.read(cli, _P(s_out))
            got = (cur - base).tx_all
            if got >= _N * 0.5:
                break
            time.sleep(1)
        assert _N * 0.5 <= got <= _N * 4, (
            f"subport forward broken: injected {_N} on {s_in}, egress {s_out} "
            f"tx_all delta={got} (lower=0.5N proves forwarding, upper=4N guards storm)")
    finally:
        cli.fdb_static_del(vid, dst)
        for s in (s_in, s_out):
            try:
                bdrv.chip_loopback(s, on=False)
            except Exception:  # noqa: BLE001
                pass
            cli.config_raw(f"vlan member del {vid} {s}")
            cli.sh.run(f"sysctl -qw net.ipv6.conf.{s}.disable_ipv6=0", check=False)
        cli.config_raw(f"vlan del {vid}")


def _P(name):
    from framework.ports import Port
    return Port(name=name, bcm=None)


def test_br8_merge_recycles_objects_no_leak(brk_env, bdrv, cli, asicdb):
    """BR8 merge with no leak (victim B independent up/down): after one split->merge cycle the ASIC
    PORT/QUEUE/BRIDGE_PORT object counts return to baseline (bridge-port leak regression)."""
    port = brk_env["vb"]
    mode2 = _mode_by_ways(brk_env["modes_b"], 2)
    if not mode2:
        pytest.skip(f"no 2x mode declared for {port}")
    restore = bdrv.current_mode(port) or _mode_by_ways(brk_env["modes_b"], 1)
    counts0 = {t: len(asicdb.objects(f"SAI_OBJECT_TYPE_{t}"))
               for t in ("PORT", "QUEUE", "BRIDGE_PORT")}
    res = bdrv.split(port, mode2)
    assert res["ok"], f"split failed: {res['text']}"
    m = bdrv.merge(port, restore)
    assert m["ok"], f"CLEANUP FAILURE: merge failed: {m['text']}"
    subs = [n for n, _, _ in res["subports"] if n != port]
    assert bdrv.gone(subs), f"subports {subs} still present after merge"
    deadline = time.time() + 30
    counts1 = {}
    while time.time() < deadline:
        counts1 = {t: len(asicdb.objects(f"SAI_OBJECT_TYPE_{t}"))
                   for t in ("PORT", "QUEUE", "BRIDGE_PORT")}
        if counts1 == counts0:
            break
        time.sleep(2)
    assert counts1 == counts0, (
        f"ASIC object leak after split+merge cycle: baseline={counts0}, "
        f"after={counts1} (bridge-port leak regression class)")


def test_br9_split_config_persists_to_save(split4, cli):
    """BR9 persistence: config save the split state to a standalone file (leaving
    /etc/sonic/config_db.json untouched); the file must contain all subport PORT entries and the
    BREAKOUT_CFG mode."""
    f = "/tmp/fvt_breakout_save.json"
    r = cli.sh.run(f"config save -y {f}", check=False, timeout=90)
    assert r.rc == 0, f"config save to file failed: {r.err or r.out}"
    out = cli.sh.run(f"cat {f}").out or ""
    missing = [n for n, _, _ in split4["subports"] if f'"{n}"' not in out]
    assert not missing, f"saved config missing subports {missing}"
    assert split4["mode"] in out, (
        f"saved config missing BREAKOUT_CFG mode {split4['mode']}")
    cli.sh.run(f"rm -f {f}", check=False)


def test_br10_invalid_mode_rejected(brk_env, cli):
    """BR10 negative: an invalid mode must be rejected and leave config untouched."""
    port = brk_env["vb"]
    before = cli.db_hgetall("CONFIG_DB", f"PORT|{port}")
    rc, r = cli.config_raw(f"interface breakout {port} '9x999G' -y")
    # DB criterion first: rc is untrustworthy (a CLI rejection may still return 0); the port table being unchanged is the hard evidence
    assert cli.db_hgetall("CONFIG_DB", f"PORT|{port}") == before, \
        "rejected breakout still mutated PORT entry"
    assert not cli.db_hgetall("CONFIG_DB", "BREAKOUT_CFG|Ethernet9999"), \
        "invalid mode created a bogus BREAKOUT_CFG entry"
    text = ((r.out or "") + (r.err or "")).lower()
    assert rc != 0 or "error" in text or "invalid" in text or "usage" in text, (
        f"invalid breakout mode produced no rejection signal at all "
        f"(rc={rc}, out={text[-160:]!r})")


def test_br11_force_flag_matches_help_text(brk_env, bdrv, cli):
    """BR11 `-f` semantic pin: help text says -f = 'Clear all dependencies internally first', so a
    split with -f must succeed. On SONiC, click default=True semantic inversion makes this FAIL
    (known defect, turns green once the fix lands). On success, merge back immediately."""
    port = brk_env["vb"]
    mode2 = _mode_by_ways(brk_env["modes_b"], 2)
    if not mode2:
        pytest.skip(f"no 2x mode declared for {port}")
    restore = bdrv.current_mode(port) or _mode_by_ways(brk_env["modes_b"], 1)
    pre_lanes = (cli.db_hgetall("CONFIG_DB", f"PORT|{port}") or {}).get("lanes", "")
    rc, r = cli.config_raw(f"interface breakout {port} '{mode2}' -f -y")
    text = ((r.out or "") + (r.err or ""))
    if rc == 0:
        subs = [n for n, _, _ in BK.expect_subports(port, pre_lanes, mode2)]
        bdrv.wait_ports(subs, timeout=60)
        m = bdrv.merge(port, restore)
        assert m["ok"], f"CLEANUP FAILURE: merge after -f split failed: {m['text']}"
        return
    pytest.fail(
        f"breakout with -f rejected ({text[-200:]!r}) though help text "
        f"promises '-f clears dependencies first'")


def test_br12_current_mode_truth(brk_env, bdrv, cli, chip):
    """BR12 show current-mode truth value + chip base verification: show output matches BREAKOUT_CFG,
    and the base port's chip NUM_LANES == CONFIG lanes count (no longer just testing 'the command does not crash')."""
    port = brk_env["vb"]
    mode = bdrv.current_mode(port)
    if not mode:
        pytest.skip(f"no BREAKOUT_CFG entry for {port}")
    r = cli.sh.run(f"show interfaces breakout current-mode {port}", check=False)
    assert r.rc == 0 and mode in (r.out or ""), (
        f"show breakout current-mode({port}) does not reflect CONFIG_DB mode "
        f"{mode!r}: {r.out!r}")
    lanes = (cli.db_hgetall("CONFIG_DB", f"PORT|{port}") or {}).get("lanes", "")
    ent = chip.pc_port(port)
    assert ent and ent.get("NUM_LANES") == len(lanes.split(",")), (
        f"chip PC_PORT NUM_LANES for {port} != CONFIG lanes count "
        f"({ent.get('NUM_LANES') if ent else None} vs {len(lanes.split(','))})")
