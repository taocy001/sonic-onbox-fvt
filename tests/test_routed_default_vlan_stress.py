"""Long-stability cases for routed-port default VLAN (skipped by default, enabled with FVT_STRESS=1, rounds via FVT_STRESS_ROUNDS).

What we guard against is cumulative regression (each flexport / link-mode change may add a port
to the default VLAN); passing a short loop doesn't mean passing a long run. This group only
repeats two things at high round counts, checking the chip triple each round:

  SS1 DPB split/merge xN
  SS2 link-mode route<->bridge xN, and on the last round send real traffic once to confirm functionality wasn't worn down

Discipline matches the main cases (see the header of test_routed_default_vlan.py): dynamic bcm
port-name calibration, vlan1 range expansion, discrd taken by value range, assertions made only
after a port has become the target role.
"""
import os
import time

import pytest

from framework import log
from framework.ports import Port

# reuse the already-verified read/calibrate/assert helpers from the main cases, avoiding two implementations drifting apart.
# tests/ is not a python package (no __init__.py), so load by path rather than import tests.xxx.
import importlib.util as _ilu
import pathlib as _pl

_spec = _ilu.spec_from_file_location(
    "_rdv_main", str(_pl.Path(__file__).with_name("test_routed_default_vlan.py")))
_rdv = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_rdv)

_N = _rdv._N
_calibrate = _rdv._calibrate
_check_routed = _rdv._check_routed
_l3_forward = _rdv._l3_forward
_P = _rdv._P
_rmac = _rdv._rmac
_skip_no_scapy = _rdv._skip_no_scapy
_vlan1 = _rdv._vlan1
_vlan1_raw = _rdv._vlan1_raw
_discrd = _rdv._discrd
_pvid = _rdv._pvid

pytestmark = [
    pytest.mark.traffic,
    pytest.mark.slow,
    pytest.mark.skipif(os.environ.get("FVT_STRESS") != "1",
                       reason="long-running stress suite; set FVT_STRESS=1 to run"),
]

_log = log.get("rdv_stress")
_ROUNDS = int(os.environ.get("FVT_STRESS_ROUNDS", "30"))


def _asic_counts(cli):
    """Resource-conservation observation: leak-type defects make these counts rise monotonically."""
    out = {}
    for k, pat in (("rif", "ROUTER_INTERFACE"), ("vmem", "VLAN_MEMBER"), ("bp", "BRIDGE_PORT")):
        r = cli.sh.run(f"sonic-db-cli ASIC_DB keys 'ASIC_STATE:SAI_OBJECT_TYPE_{pat}:*' | wc -l",
                       check=False)
        try:
            out[k] = int((r.out or "0").strip().split("\n")[-1])
        except ValueError:
            out[k] = -1
    return out


@pytest.mark.chip
def test_ss1_breakout_cycles(bdrv, cli, _lb, topo):
    """SS1 split/merge xN: each round, neither the post-split subports nor the post-merge base port may stay in vlan1; resource counts must not grow."""
    topo.caps.require("breakout_dpb")
    victim = topo.misc_port(1).name
    idx = int(victim.replace("Ethernet", ""))
    s_out = f"Ethernet{idx + 4}"
    restore = bdrv.current_mode(victim) or "1x800G"

    _calibrate(cli, _lb, victim)                 # establish a known starting point (route state)
    base, base_cnt = _vlan1(_lb), _asic_counts(cli)
    _log.info("SS1 baseline: vlan1=%s counts=%s rounds=%d", _vlan1_raw(_lb), base_cnt, _ROUNDS)

    for rnd in range(1, _ROUNDS + 1):
        res = bdrv.split(victim, "2x400G[200G]")
        assert res.get("ok"), f"round{rnd} split failed: {res.get('text', res)}"
        # first calibrate both subports as routed ports, then assert no new vlan1 members (staying in vlan1 before becoming a routed port is default behavior)
        b_sin = _calibrate(cli, _lb, victim)
        b_sout = _calibrate(cli, _lb, s_out)
        new = _vlan1(_lb) - base
        assert not new, f"round{rnd} after split: subport(s) left in vlan1 {sorted(new)}"
        for p, b in ((victim, b_sin), (s_out, b_sout)):
            assert _pvid(_lb, b) == "4095", f"round{rnd} subport {p}({b}) PVID={_pvid(_lb, b)}"
            assert _discrd(_lb, b) == "None", (
                f"round{rnd} subport {p}({b}) discrd={_discrd(_lb, b)} — untagged black-holed")

        mres = bdrv.merge(victim, restore)
        assert mres.get("ok"), f"round{rnd} merge failed: {mres.get('text', mres)}"
        b_base = _calibrate(cli, _lb, victim)
        new = _vlan1(_lb) - base
        assert not new, f"round{rnd} after merge: base port left in vlan1 {sorted(new)}"
        assert _pvid(_lb, b_base) == "4095", f"round{rnd} base PVID={_pvid(_lb, b_base)}"
        assert _discrd(_lb, b_base) == "None", (
            f"round{rnd} base discrd={_discrd(_lb, b_base)} — untagged black-holed")

        if rnd % 10 == 0:
            cnt = _asic_counts(cli)
            _log.info("SS1 round%d: vlan1=%s counts=%s", rnd, _vlan1_raw(_lb), cnt)
            for k in ("rif", "vmem", "bp"):
                assert cnt[k] <= base_cnt[k] + 2, (
                    f"round{rnd}: ASIC {k} grew {base_cnt[k]} -> {cnt[k]} (leak?)")


def test_ss2_linkmode_cycles(cli, _lb, topo):
    """SS2 route<->bridge xN: each round the triple is correct in both states with no residue; on the last round send real traffic to confirm functionality wasn't worn down."""
    _skip_no_scapy()
    p_in, p_out = topo.l3_port(0).name, topo.l3_port(1).name
    sub_in, sub_out = topo.subnet("a"), topo.subnet("b")
    rmac = _rmac(cli)
    assert rmac, "DEVICE DEFECT: router MAC not found"
    b_in = _calibrate(cli, _lb, p_in)
    b_out = _calibrate(cli, _lb, p_out)
    base, base_cnt = _vlan1(_lb), _asic_counts(cli)
    _log.info("SS2 baseline: vlan1=%s counts=%s rounds=%d", _vlan1_raw(_lb), base_cnt, _ROUNDS)

    for rnd in range(1, _ROUNDS + 1):
        cli.config_raw(f"interface link-mode {p_out} bridge")
        end = time.time() + 30
        while b_out not in _vlan1(_lb) and time.time() < end:
            time.sleep(2)
        assert b_out in _vlan1(_lb), (
            f"round{rnd}: {p_out}({b_out}) not rejoined vlan1 after 30s ({_vlan1_raw(_lb)})")
        assert _pvid(_lb, b_out) == "1", f"round{rnd}: bridged PVID={_pvid(_lb, b_out)}"
        assert _discrd(_lb, b_out) == "None", f"round{rnd}: bridged discrd={_discrd(_lb, b_out)}"

        cli.config_raw(f"interface link-mode {p_out} route")
        end = time.time() + 30
        while b_out in _vlan1(_lb) and time.time() < end:
            time.sleep(2)
        assert b_out not in _vlan1(_lb), (
            f"round{rnd}: {p_out}({b_out}) still in vlan1 after 30s ({_vlan1_raw(_lb)})")
        assert _pvid(_lb, b_out) == "4095", f"round{rnd}: routed PVID={_pvid(_lb, b_out)}"
        assert _discrd(_lb, b_out) == "None", (
            f"round{rnd}: routed discrd={_discrd(_lb, b_out)} — untagged black-holed")
        new = _vlan1(_lb) - base
        assert not new, f"round{rnd}: unexpected vlan1 members {sorted(new)}"

        if rnd % 10 == 0:
            cnt = _asic_counts(cli)
            _log.info("SS2 round%d: counts=%s", rnd, cnt)
            for k in ("rif", "vmem", "bp"):
                assert cnt[k] <= base_cnt[k] + 2, (
                    f"round{rnd}: ASIC {k} grew {base_cnt[k]} -> {cnt[k]} (leak?)")

    # last-round functional confirmation: L3 forwarding still works after high round counts
    try:
        _check_routed(cli, _lb, p_in, b_in, f"after {_ROUNDS} cycles: ")
        _check_routed(cli, _lb, p_out, b_out, f"after {_ROUNDS} cycles: ")
        got = _l3_forward(cli, _lb, topo, rmac, p_in, p_out, sub_in, sub_out,
                          topo.route("a"), b"SS2", {p_in: b_in, p_out: b_out})
        assert _N * 0.9 <= got <= _N * 4, (
            f"after {_ROUNDS} link-mode cycles, L3 forwarding degraded: TX={got}")
    finally:
        for p, b in ((p_in, b_in), (p_out, b_out)):
            try:
                _lb.disable(_P(p, b))
            except Exception:  # noqa: BLE001
                pass
