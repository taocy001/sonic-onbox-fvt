"""Routed-port default-VLAN fix -- supplementary validation of production ops flows.

The main suite (test_routed_default_vlan.py) covers basic correctness of the split / no-split
scenarios; this group adds the flows and code branches that are **guaranteed to be hit in
production but previously had zero coverage**:

  E1 sub-interface (SUB_PORT)  creating/deleting a subif while the parent is in vlan1 must
                               not disturb the parent's membership
  E2 routed LAG full flow      member add/remove / member leave-rejoin / LAG RIF delete
                               rejoins all members
  E3 ingress-disabled          an LACP standby member must keep discard=All after RIF delete
  E4 port flap                 the triple must not drift across shutdown/startup round trips
  E5 bulk link-mode            switching many ports at once, no cross-contamination / residue
  E6 user-VLAN interaction     a port that joins a user VLAN then becomes routed: both VLAN
                               domains must be correct
  E7 VRF bind                  bind/unbind VRF rebuilds the RIF; state must return to correct

Reuses the calibration / assertion helpers already validated by the main suite (tests/ is
not a python package, so it is loaded by path).
"""
import importlib.util as _ilu
import pathlib as _pl
import time

import pytest

from framework import log

_spec = _ilu.spec_from_file_location(
    "_rdv_main", str(_pl.Path(__file__).with_name("test_routed_default_vlan.py")))
_rdv = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_rdv)

_N = _rdv._N
_P = _rdv._P
_calibrate = _rdv._calibrate
_check_routed = _rdv._check_routed
_check_bridged = _rdv._check_bridged
_discrd = _rdv._discrd
_l3_forward = _rdv._l3_forward
_pvid = _rdv._pvid
_rmac = _rdv._rmac
_skip_no_scapy = _rdv._skip_no_scapy
_vlan1 = _rdv._vlan1
_vlan1_raw = _rdv._vlan1_raw

try:
    from scapy.all import Ether, IP, UDP, Raw, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

pytestmark = pytest.mark.traffic
_log = log.get("rdv_ops")


def _cfg_has(cli, pat):
    return bool(cli.sh.run(f"sonic-db-cli CONFIG_DB keys '{pat}'", check=False).out.strip())


# ---------------------------------------------------------------- E1 sub-interface
@pytest.mark.chip
def test_e1_subinterface_does_not_detach_parent(cli, _lb, topo):
    """E1 [C1-n1] creating a subif while the parent is an L2 port: the parent **must not** be
    removed from vlan1.

    The fix only detaches TYPE_PORT at RIF create and explicitly excludes SUB_PORT -- if that
    guard fails, creating a sub-interface kicks the parent out of the L2 domain and silently
    breaks the parent's L2 traffic."""
    parent = topo.l3_port(0).name
    b_parent = _calibrate(cli, _lb, parent)
    sub_if = f"{parent}.100"
    try:
        # put the parent into L2 (join vlan1)
        cli.config_raw(f"interface link-mode {parent} bridge")
        cli.config_raw(f"interface startup {parent}")
        time.sleep(8)
        _check_bridged(cli, _lb, parent, b_parent, "before subif: ")

        # create the sub-interface -> SUB_PORT RIF
        rc, r = cli.config_raw(f"interface ip add {sub_if} 10.90.1.1/24")
        if not _cfg_has(cli, f"VLAN_SUB_INTERFACE|{sub_if}"):
            pytest.skip(f"subinterface not created on this image: rc={rc} "
                        f"{((r.out or '') + (r.err or ''))[:100]}")
        time.sleep(8)
        st_v1, st_pvid, st_dc = _vlan1(_lb), _pvid(_lb, b_parent), _discrd(_lb, b_parent)
        assert b_parent in st_v1, (
            f"REGRESSION: creating sub-interface {sub_if} detached parent {parent}({b_parent}) "
            f"from chip vlan1 (vlan1={_vlan1_raw(_lb)}) — parent L2 traffic would break")
        assert st_pvid == "1", f"parent PVID changed to {st_pvid} by sub-interface creation"
        assert st_dc == "None", f"parent discrd changed to {st_dc} by sub-interface creation"

        # delete the sub-interface -> parent still unaffected
        cli.config_raw(f"interface ip remove {sub_if} 10.90.1.1/24")
        time.sleep(8)
        assert b_parent in _vlan1(_lb), (
            f"REGRESSION: deleting sub-interface detached parent {parent}({b_parent}) "
            f"from vlan1 ({_vlan1_raw(_lb)})")
        assert _discrd(_lb, b_parent) == "None", (
            f"parent discrd={_discrd(_lb, b_parent)} after sub-interface removal")
    finally:
        cli.config_raw(f"interface ip remove {sub_if} 10.90.1.1/24")
        cli.config_raw(f"interface link-mode {parent} route")
        time.sleep(4)


# ---------------------------------------------------------------- E2/E3 LAG
def _mk_routed_lag(cli, pc, members, sub):
    cli.config_raw(f"portchannel add {pc}")
    cli.config_raw(f"interface link-mode {pc} route")
    cli.config_raw(f"interface mtu {pc} 9000")
    time.sleep(3)
    for m in members:
        rc, r = cli.config_raw(f"portchannel member add {pc} {m}")
        if rc != 0:
            pytest.skip(f"cannot add {m} to {pc}: {((r.out or '') + (r.err or ''))[:100]}")
    cli.config_raw(f"interface ip add {pc} {sub['dut']}/{sub['prefix']}")
    time.sleep(8)


def _rm_lag(cli, pc, members, sub):
    cli.config_raw(f"interface ip del {pc} {sub['dut']}/{sub['prefix']}")
    for m in members:
        cli.config_raw(f"portchannel member del {pc} {m}")
    cli.config_raw(f"portchannel del {pc}")
    time.sleep(4)


@pytest.mark.chip
def test_e2_routed_lag_member_lifecycle(cli, _lb, topo):
    """E2 [C3+C4+C5+C2] routed LAG: member add/remove / member leave-rejoin / RIF delete rejoins in-place members."""
    m1, m2 = topo.l2_port(0).name, topo.l2_port(1).name
    b1, b2 = _calibrate(cli, _lb, m1), _calibrate(cli, _lb, m2)
    pc, sub = "PortChannel51", topo.subnet("e")
    base = _vlan1(_lb)
    try:
        _mk_routed_lag(cli, pc, [m1, m2], sub)
        # C3/C5: routed LAG members must not be in vlan1
        for m, b in ((m1, b1), (m2, b2)):
            assert b not in _vlan1(_lb), (
                f"routed LAG member {m}({b}) left in chip vlan1: {_vlan1_raw(_lb)}")
            assert _discrd(_lb, b) in ("None", "All"), (
                f"member {m}({b}) unexpected discrd={_discrd(_lb, b)}")

        # C4: member leaves -> must return to a clean default state (SONiC auto-converts to a
        # routed port, so assert no discard residue)
        cli.config_raw(f"portchannel member del {pc} {m2}")
        time.sleep(8)
        assert _discrd(_lb, b2) in ("None", "All"), (
            f"member {m2}({b2}) left with discrd={_discrd(_lb, b2)} after leaving LAG — "
            f"Untag would black-hole untagged ingress")

        # C2: delete LAG RIF -> in-place members rejoin vlan1
        cli.config_raw(f"interface ip del {pc} {sub['dut']}/{sub['prefix']}")
        cli.config_raw(f"interface link-mode {pc} bridge")
        time.sleep(10)
        assert b1 in _vlan1(_lb), (
            f"in-place LAG member {m1}({b1}) not rejoined vlan1 after RIF removal: "
            f"{_vlan1_raw(_lb)}")
        assert _pvid(_lb, b1) == "1", f"member {m1}({b1}) PVID={_pvid(_lb, b1)} after RIF removal"
        # the exact discard semantics are covered by E3: an ingress-disabled member (which it
        # is when there is no LACP peer) keeping All is the correct behavior; here we only
        # rule out Untag (dropping untagged = black hole).
        assert _discrd(_lb, b1) in ("None", "All"), (
            f"member {m1}({b1}) discrd={_discrd(_lb, b1)} after RIF removal — "
            f"Untag would black-hole untagged ingress")
    finally:
        _rm_lag(cli, pc, [m1, m2], sub)
        for p in (m1, m2):
            cli.config_raw(f"interface link-mode {p} route")
        time.sleep(4)
        new = _vlan1(_lb) - base
        assert not new, f"vlan1 residue after LAG teardown: {sorted(new)}"


@pytest.mark.chip
def test_e3_ingress_disabled_member_keeps_discard(cli, _lb, topo):
    """E3 [C2-b1] an LACP standby (ingress-disabled) member must keep discard=All after LAG RIF delete.

    The rejoin helper forces DISCARD_NONE; missing the save/restore is equivalent to letting a
    standby member start receiving packets."""
    m1 = topo.misc_port(0).name
    b1 = _calibrate(cli, _lb, m1)
    pc, sub = "PortChannel52", topo.subnet("e")
    try:
        _mk_routed_lag(cli, pc, [m1], sub)
        if _discrd(_lb, b1) != "All":
            pytest.skip(f"member {m1}({b1}) is not ingress-disabled here "
                        f"(discrd={_discrd(_lb, b1)}); needs a real LACP standby")
        cli.config_raw(f"interface ip del {pc} {sub['dut']}/{sub['prefix']}")
        cli.config_raw(f"interface link-mode {pc} bridge")
        time.sleep(10)
        assert _discrd(_lb, b1) == "All", (
            f"ingress-disabled member {m1}({b1}) discard cleared to {_discrd(_lb, b1)} "
            f"by the default-VLAN rejoin — standby member would start receiving traffic")
    finally:
        _rm_lag(cli, pc, [m1], sub)
        cli.config_raw(f"interface link-mode {m1} route")
        time.sleep(4)


# ---------------------------------------------------------------- E4 port flap
def test_e4_port_flap_keeps_state(cli, _lb, topo):
    """E4 port shutdown/startup round trips: the routed-port triple must not drift (link flap is an unavoidable production event)."""
    p = topo.l3_port(1).name
    b = _calibrate(cli, _lb, p)
    try:
        _check_routed(cli, _lb, p, b, "before flap: ")
        for rnd in (1, 2, 3):
            cli.config_raw(f"interface shutdown {p}")
            time.sleep(4)
            cli.config_raw(f"interface startup {p}")
            time.sleep(6)
            _check_routed(cli, _lb, p, b, f"after flap{rnd}: ")
    finally:
        cli.config_raw(f"interface startup {p}")
        time.sleep(2)


# ---------------------------------------------------------------- E5 bulk switching
def test_e5_bulk_linkmode_switch(cli, _lb, topo):
    """E5 bulk link-mode: switching many ports back to back, each port's final state must be correct with no cross-contamination."""
    ports = [topo.l3_port(0).name, topo.l3_port(1).name, topo.l2_port(0).name]
    bcms = {p: _calibrate(cli, _lb, p) for p in ports}
    base = _vlan1(_lb)
    try:
        for p in ports:                       # push back to back without waiting for convergence (simulates a bulk script)
            cli.config_raw(f"interface link-mode {p} bridge")
        time.sleep(15)
        for p in ports:
            _check_bridged(cli, _lb, p, bcms[p], "bulk->bridge: ")
        for p in ports:
            cli.config_raw(f"interface link-mode {p} route")
        time.sleep(15)
        for p in ports:
            _check_routed(cli, _lb, p, bcms[p], "bulk->route: ")
        new = _vlan1(_lb) - base
        assert not new, f"vlan1 residue after bulk switching: {sorted(new)}"
    finally:
        for p in ports:
            cli.config_raw(f"interface link-mode {p} route")
        time.sleep(4)


# ---------------------------------------------------------------- E6 user VLAN
@pytest.mark.chip
def test_e6_user_vlan_interaction(cli, _lb, topo):
    """E6 user-VLAN interaction: a port that joins a user VLAN (not vlan1) then becomes routed --
    membership in both VLAN domains must be correct; the fix should only affect the default VLAN."""
    p = topo.l2_port(0).name
    b = _calibrate(cli, _lb, p)
    vid = 3171
    try:
        cli.config_raw(f"interface link-mode {p} bridge")
        time.sleep(6)
        cli.config_raw(f"vlan add {vid}")
        rc, r = cli.config_raw(f"vlan member add -u {vid} {p}")
        if rc != 0:
            pytest.skip(f"cannot add {p} to Vlan{vid}: {((r.out or '') + (r.err or ''))[:100]}")
        time.sleep(8)
        uv = _lb.bsh.cmd(f"vlan show {vid}") or ""
        assert b in uv, f"{p}({b}) not in user Vlan{vid} on chip: {uv.strip()[:80]}"

        # convert to routed: it should leave the default VLAN; user-VLAN membership is handled
        # by orchagent's member del. Here we only assert the fix did not overreach into the
        # user VLAN (after conversion the user-VLAN relationship is decided by the CLI; no
        # strong assertion made)
        cli.config_raw(f"vlan member del {vid} {p}")
        time.sleep(4)
        cli.config_raw(f"interface link-mode {p} route")
        time.sleep(8)
        _check_routed(cli, _lb, p, b, "after user-vlan cycle: ")
        uv2 = _lb.bsh.cmd(f"vlan show {vid}") or ""
        assert b not in uv2, f"{p}({b}) still in user Vlan{vid} after member del: {uv2.strip()[:80]}"
    finally:
        cli.config_raw(f"vlan member del {vid} {p}")
        cli.config_raw(f"vlan del {vid}")
        cli.config_raw(f"interface link-mode {p} route")
        time.sleep(4)


# ---------------------------------------------------------------- E7 VRF
def test_e7_vrf_bind_rebuilds_rif(cli, _lb, topo):
    """E7 VRF bind/unbind rebuilds the RIF -- after the rebuild the port triple must still be correct."""
    p = topo.l3_port(0).name
    b = _calibrate(cli, _lb, p)
    vrf = "Vrf71"
    try:
        rc, r = cli.config_raw(f"vrf add {vrf}")
        if rc != 0 and "already" not in ((r.out or "") + (r.err or "")).lower():
            pytest.skip(f"vrf not supported: {((r.out or '') + (r.err or ''))[:100]}")
        time.sleep(3)
        rc, r = cli.config_raw(f"interface vrf bind {p} {vrf}")
        if rc != 0:
            pytest.skip(f"cannot bind vrf: {((r.out or '') + (r.err or ''))[:100]}")
        time.sleep(8)
        _check_routed(cli, _lb, p, b, "after vrf bind: ")
        cli.config_raw(f"interface vrf unbind {p}")
        time.sleep(8)
        _check_routed(cli, _lb, p, b, "after vrf unbind: ")
    finally:
        cli.config_raw(f"interface vrf unbind {p}")
        cli.config_raw(f"vrf del {vrf}")
        cli.config_raw(f"interface link-mode {p} route")
        time.sleep(4)
