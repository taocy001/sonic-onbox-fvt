"""Routed-port default-VLAN fix verification -- the minimal sufficient set.

Scope (only verifies whether this change works, no generalized stress / feature
exploration):
  Scenario A no breakout, Scenario B breakout, each verifying three things:
    1) config correctness  CONFIG_DB INTERFACE / VLAN_MEMBER keys match the port's role
    2) chip table entries   vlan1 member bitmap / PVID / discrd triple
    3) forwarding works     L3 routed-port traffic forwards; L2 bridged-port flood forwards

Cases:
  T1 no breakout   routed port   config+chip+L3 forwarding
  T2 no breakout   bridged port  config+chip+L2 forwarding (RIF-removed-then-readded path)
  T3 breakout      subport       config+chip+L3 forwarding
  T4 breakout      merged base   config+chip+L3 forwarding

Discipline (all learned the hard way in this project):
  * The bcm port name must be **calibrated dynamically**: the profile's EthernetN/8 formula
    only holds without breakout ports; flexport scrambles the lport<->dport mapping (e.g.
    Ethernet96 has SAI OID low bits=24 while the bcmcmd name=d3c8).
  * vlan1 member output **is range-compressed** (cpu,d3c9-d3c16), so it must be expanded to
    a set before judging.
  * The discrd column is read by **value-domain keyword**, not by column offset (empty
    pause/medium columns shift the column count).
  * All three of the triple are required: checking only the member bitmap + PVID misses the
    case where untagged is dropped (black-holed).
  * Forwarding uses real traffic; the receive port must have loopback on (with link down TX
    is stuck at 0, yielding a false conclusion).
"""
import re
import time

import pytest

from framework import log
from framework.counters import ChipCounters, PortCounters
from framework.ports import Port

pytestmark = pytest.mark.traffic

try:
    from scapy.all import Ether, IP, UDP, Raw, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_log = log.get("rdv")
_N = 30
_NH_MAC = "00:11:22:33:44:dd"


# ---------------------------------------------------------------- chip reads
def _vlan1_raw(_lb):
    out = _lb.bsh.cmd("vlan show 1") or ""
    for ln in out.splitlines():
        if "ports" in ln:
            return ln.split("ports", 1)[1].strip().split()[0].rstrip(",")
    return "?"


def _vlan1(_lb):
    """Member set with ranges expanded."""
    raw = _vlan1_raw(_lb)
    members = set()
    for tok in raw.split(","):
        m = re.match(r"^(.*?)(\d+)-(?:\1)?(\d+)$", tok)
        if m:
            members.update(f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1))
        elif tok:
            members.add(tok)
    return members


def _pvid(_lb, bcm):
    m = re.search(r"default VLAN is (\d+)", _lb.bsh.cmd(f"pvlan show {bcm}") or "")
    return m.group(1) if m else "?"


def _discrd(_lb, bcm):
    out = _lb.bsh.cmd(f"ps {bcm}") or ""
    for ln in out.splitlines():
        if re.match(rf"\s*{bcm}\(", ln):
            m = re.search(r"\b(None|Untag|All)\b", ln)
            return m.group(1) if m else "?"
    return "ABSENT"


def _calibrate(cli, _lb, port, timeout=30):
    """Dynamically calibrate a port's real bcm name (set bridge, see who joins vlan1);
    the port ends in route state.

    First force route to establish a known starting point: FVT suite hygiene parks lane
    ports back into an L2 berth, so a direct link-mode bridge here would be a no-op with no
    set change and nothing to calibrate."""
    cli.config_raw(f"interface link-mode {port} route")
    time.sleep(8)                                  # wait for link-mode to take effect (async)
    before = _vlan1(_lb)
    cli.config_raw(f"interface link-mode {port} bridge")
    added, end = set(), time.time() + timeout
    while time.time() < end:
        added = _vlan1(_lb) - before
        if added:
            break
        time.sleep(2)
    assert len(added) == 1, (
        f"cannot calibrate {port}: link-mode bridge added {sorted(added)} to vlan1 "
        f"(expected exactly 1); vlan1={_vlan1_raw(_lb)}")
    bcm = added.pop()
    cli.config_raw(f"interface link-mode {port} route")
    end = time.time() + timeout
    while bcm in _vlan1(_lb) and time.time() < end:
        time.sleep(2)
    assert bcm not in _vlan1(_lb), f"{port}({bcm}) not detached after link-mode route"
    _log.info("calibrated %s -> %s", port, bcm)
    return bcm


def _P(name, bcm):
    """Port carrying a real bcm name: the framework's bcm_of() prefers port.bcm, bypassing
    the EthernetN/divisor static formula (which breaks when the device has breakout ports
    and would enable loopback on the wrong port)."""
    return Port(name=name, bcm=bcm)


# ---------------------------------------------------------------- three-dimensional assertions
def _check_routed(cli, _lb, port, bcm, ctx):
    """Routed port: config has INTERFACE, no VLAN_MEMBER; chip not in vlan1 / PVID 4095 / untagged passed."""
    has_intf = bool(cli.sh.run(f"sonic-db-cli CONFIG_DB keys 'INTERFACE|{port}'",
                               check=False).out.strip())
    has_vmem = bool(cli.sh.run(f"sonic-db-cli CONFIG_DB keys 'VLAN_MEMBER|*|{port}'",
                               check=False).out.strip())
    assert has_intf and not has_vmem, (
        f"{ctx}{port} config wrong for a routed port: INTERFACE={has_intf} VLAN_MEMBER={has_vmem}")
    v1, pv, dc = _vlan1(_lb), _pvid(_lb, bcm), _discrd(_lb, bcm)
    assert bcm not in v1, f"{ctx}{port}({bcm}) still in chip vlan1: {_vlan1_raw(_lb)}"
    assert pv == "4095", f"{ctx}{port}({bcm}) PVID={pv}, expected 4095"
    assert dc == "None", f"{ctx}{port}({bcm}) discrd={dc} — untagged ingress black-holed"


def _check_bridged(cli, _lb, port, bcm, ctx):
    """Bridged port: config has VLAN_MEMBER, no INTERFACE; chip in vlan1 / PVID 1 / untagged passed."""
    has_intf = bool(cli.sh.run(f"sonic-db-cli CONFIG_DB keys 'INTERFACE|{port}'",
                               check=False).out.strip())
    has_vmem = bool(cli.sh.run(f"sonic-db-cli CONFIG_DB keys 'VLAN_MEMBER|*|{port}'",
                               check=False).out.strip())
    assert has_vmem and not has_intf, (
        f"{ctx}{port} config wrong for a bridged port: INTERFACE={has_intf} VLAN_MEMBER={has_vmem}")
    v1, pv, dc = _vlan1(_lb), _pvid(_lb, bcm), _discrd(_lb, bcm)
    assert bcm in v1, f"{ctx}{port}({bcm}) not rejoined chip vlan1: {_vlan1_raw(_lb)}"
    assert pv == "1", f"{ctx}{port}({bcm}) PVID={pv}, expected 1"
    assert dc == "None", f"{ctx}{port}({bcm}) discrd={dc} — untagged ingress dropped"


# ---------------------------------------------------------------- forwarding
def _wait_carrier(cli, port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if (cli.sh.run(f"cat /sys/class/net/{port}/carrier 2>/dev/null",
                       check=False).out or "").strip() == "1":
            return True
        time.sleep(1)
    return False


def _l3_forward(cli, _lb, topo, rmac, p_in, p_out, sub_in, sub_out, dst_net, tag, bcms):
    """Configure L3 + loopback on both ports, inject an untagged IP packet, return p_out's TX delta. bcms: {port name: real bcm name}."""
    for p, sub in ((p_in, sub_in), (p_out, sub_out)):
        cli.config_raw(f"interface ip add {p} {sub['dut']}/{sub['prefix']}")
        cli.config_raw(f"interface startup {p}")
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{p}.disable_ipv6=1", check=False)
        _lb.enable(_P(p, bcms[p]))
    for p in (p_in, p_out):
        _wait_carrier(cli, p)
    time.sleep(3)
    cli.neigh_set(sub_out["peer"], _NH_MAC, p_out)
    cli.sh.run(f"ip route replace {dst_net} via {sub_out['peer']}", check=False)
    time.sleep(3)
    base = PortCounters.read(cli, Port(name=p_out, bcm=None))
    dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".7"
    pkt = (Ether(dst=rmac, src=topo.mac("src"))
           / IP(src=sub_in["peer"], dst=dst_ip, ttl=64) / UDP() / Raw(tag + b"x" * 40))
    sendp(pkt, iface=p_in, count=_N, inter=0.002, verbose=False)
    got, end = 0, time.time() + 20
    while time.time() < end:
        got = (PortCounters.read(cli, Port(name=p_out, bcm=None)) - base).tx_all
        if got >= _N * 0.9:
            break
        time.sleep(1)
    cli.sh.run(f"ip route del {dst_net}", check=False)
    cli.neigh_del(sub_out["peer"], p_out)
    for p, sub in ((p_in, sub_in), (p_out, sub_out)):
        cli.config_raw(f"interface ip remove {p} {sub['dut']}/{sub['prefix']}")
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{p}.disable_ipv6=0", check=False)
    return got


def _rmac(cli):
    return (cli.sh.run("sonic-db-cli CONFIG_DB hget 'DEVICE_METADATA|localhost' mac",
                       check=False).out or "").strip()


def _skip_no_scapy():
    if not _SCAPY:
        pytest.skip("scapy unavailable")


# ================================================================ Scenario A: no breakout
def test_t1_routed_port_config_chip_and_l3_traffic(cli, _lb, topo):
    """T1 no breakout, routed port: config + chip triple + L3 forwarding."""
    _skip_no_scapy()
    p_in, p_out = topo.l3_port(0).name, topo.l3_port(1).name
    sub_in, sub_out = topo.subnet("a"), topo.subnet("b")
    rmac = _rmac(cli)
    assert rmac, "router MAC not found"
    b_in = _calibrate(cli, _lb, p_in)
    b_out = _calibrate(cli, _lb, p_out)
    try:
        for p, b in ((p_in, b_in), (p_out, b_out)):
            _check_routed(cli, _lb, p, b, "routed port: ")
        got = _l3_forward(cli, _lb, topo, rmac, p_in, p_out, sub_in, sub_out,
                          topo.route("a"), b"T1", {p_in: b_in, p_out: b_out})
        assert _N * 0.9 <= got <= _N * 4, (
            f"L3 forwarding broken on routed ports: injected {_N}, {p_out} TX={got}")
        for p, b in ((p_in, b_in), (p_out, b_out)):
            _check_routed(cli, _lb, p, b, "after traffic: ")
    finally:
        for p, b in ((p_in, b_in), (p_out, b_out)):
            try:
                _lb.disable(_P(p, b))
            except Exception:  # noqa: BLE001
                pass


@pytest.mark.chip
def test_t2_bridged_port_config_chip_and_l2_traffic(cli, _lb, topo):
    """T2 no breakout, bridged port: RIF removed then re-added -- config + chip triple + L2 flood forwarding."""
    _skip_no_scapy()
    src, peer = topo.l2_port(0).name, topo.l2_port(1).name
    b_src = _calibrate(cli, _lb, src)
    b_peer = _calibrate(cli, _lb, peer)
    try:
        for p in (src, peer):
            cli.config_raw(f"interface link-mode {p} bridge")
            cli.config_raw(f"interface startup {p}")
        time.sleep(8)
        for p, b in ((src, b_src), (peer, b_peer)):
            _check_bridged(cli, _lb, p, b, "bridged port: ")

        # L2 flood forwarding: loopback on both ports (a link-down receive port keeps TX at 0), receive port discard=all breaks the loop
        for p, b in ((src, b_src), (peer, b_peer)):
            _lb.enable(_P(p, b))
        for p in (src, peer):
            _wait_carrier(cli, p)
        _lb.bsh.cmd(f"port {b_peer} discard=all")
        time.sleep(3)
        ChipCounters.clear(_lb.bsh)
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=topo.mac("src"))
               / IP(src="10.250.0.1", dst="255.255.255.255") / UDP() / Raw(b"T2" + b"x" * 40))
        sendp(pkt, iface=src, count=_N, inter=0.002, verbose=False)
        time.sleep(2)
        rx = ChipCounters.read(_lb.bsh, b_peer).tx_pkt
        _log.info("T2 L2 flood: injected %d on %s -> %s TX=%s", _N, src, peer, rx)
        assert rx >= _N * 0.5, (
            f"L2 forwarding broken after RIF removal: {peer} got {rx}/{_N} flood frames "
            f"(state looked right but the port is not really in the L2 domain)")
    finally:
        _lb.bsh.cmd(f"port {b_peer} discard=none")
        for p, b in ((src, b_src), (peer, b_peer)):
            try:
                _lb.disable(_P(p, b))
            except Exception:  # noqa: BLE001
                pass
            cli.config_raw(f"interface link-mode {p} route")
        time.sleep(4)


# ================================================================ Scenario B: breakout
@pytest.mark.chip
def test_t3_t4_breakout_subport_and_merged_base(bdrv, cli, _lb, topo):
    """T3 breakout subport + T4 merged base port: each verifies config + chip triple + L3 forwarding."""
    _skip_no_scapy()
    topo.caps.require("breakout_dpb")
    victim = topo.misc_port(1).name
    idx = int(victim.replace("Ethernet", ""))
    s_in, s_out = victim, f"Ethernet{idx + 4}"
    sub_in, sub_out = topo.subnet("c"), topo.subnet("d")
    rmac = _rmac(cli)
    restore = bdrv.current_mode(victim) or "1x800G"
    _calibrate(cli, _lb, victim)                  # calibrate and clear the berth config (ends in route state)
    base_v1 = _vlan1(_lb)

    res = bdrv.split(victim, "2x400G[200G]")
    assert res.get("ok"), f"breakout {victim} failed: {res.get('text', res)}"
    try:
        # T3 subport: calibrate first (into route state), then assert -- same reasoning as T4
        b_sin = _calibrate(cli, _lb, s_in)
        b_sout = _calibrate(cli, _lb, s_out)
        new = _vlan1(_lb) - base_v1
        assert not new, f"subport(s) joined chip vlan1 after breakout: {sorted(new)}"
        for p, b in ((s_in, b_sin), (s_out, b_sout)):
            _check_routed(cli, _lb, p, b, "subport: ")
        for s in (s_in, s_out):
            bdrv.chip_loopback(s, on=True)
        got = _l3_forward(cli, _lb, topo, rmac, s_in, s_out, sub_in, sub_out,
                          topo.route("b"), b"T3", {s_in: b_sin, s_out: b_sout})
        assert _N * 0.9 <= got <= _N * 4, (
            f"L3 forwarding broken between subports: {s_in} -> {s_out} TX={got}")
    finally:
        for s in (s_in, s_out):
            try:
                bdrv.chip_loopback(s, on=False)
            except Exception:  # noqa: BLE001
                pass
        mres = bdrv.merge(victim, restore)
        assert mres.get("ok"), f"merge failed: {mres.get('text', mres)}"

    # T4 merged base port. Calibrate first (calibration ends in route state), then assert:
    # a just-merged base port that has no RIF yet is correctly in vlan1 by default -- only
    # after it becomes a routed port can we talk about "should not be in vlan1".
    b_base = _calibrate(cli, _lb, victim)
    new = _vlan1(_lb) - base_v1
    assert not new, f"port(s) left in chip vlan1 after merge: {sorted(new)}"
    _check_routed(cli, _lb, victim, b_base, "merged base port: ")
    other = topo.l3_port(0).name
    b_other = _calibrate(cli, _lb, other)
    _check_routed(cli, _lb, other, b_other, "peer for merged-base traffic: ")
    try:
        got = _l3_forward(cli, _lb, topo, rmac, victim, other, sub_in, sub_out,
                          topo.route("b"), b"T4", {victim: b_base, other: b_other})
        assert _N * 0.9 <= got <= _N * 4, (
            f"L3 forwarding broken on merged base port: {victim} -> {other} TX={got}")
    finally:
        for p, b in ((victim, b_base), (other, b_other)):
            try:
                _lb.disable(_P(p, b))
            except Exception:  # noqa: BLE001
                pass
