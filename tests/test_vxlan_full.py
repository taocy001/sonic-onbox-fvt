"""VXLAN full set: L3VNI (VRF<->VNI) ASIC mapping + encap/decap data-plane localization.

VTEP creation + VLAN<->VNI (L2VNI) ASIC programming paths are covered by test_vxlan.py /
test_vxlan_chip.py (the original test_vtep_and_tunnel / test_vlan_vni_mapping were CONFIG_DB-only
anti-patterns, deleted and delegated to the ASIC assertions in those two). This file keeps only the
L3VNI (VRF<->VNI) mapping chip assertions **not covered elsewhere**, plus the full encap/decap localization.
"""
import time

import pytest

pytestmark = [pytest.mark.vxlan]

VTEP = "vtep_full"


_L3VNI = 5000


def _bare_oid(key):
    """Full ASIC key (ASIC_STATE:SAI_OBJECT_TYPE_X:oid:0x..) -> bare oid:0x...
    VIRTUAL_ROUTER_ID_* in TUNNEL_MAP_ENTRY attributes is a bare oid, while objects() returns the full key,
    so it must be normalized before comparison."""
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def _wait_new_vr(asicdb, before, timeout=8.0):
    """Wait for a new VIRTUAL_ROUTER oid to appear (VRF -> SAI VR mapping), return its bare oid (None if none).
    Same pattern as tests/test_vrf.py -- it is the VR anchor for L3VNI attribute exact matching."""
    end = time.time() + timeout
    while time.time() < end:
        new = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER")) - before
        if new:
            return _bare_oid(next(iter(new)))
        time.sleep(0.4)
    return None


def _wait_stable_count(asicdb, pattern, timeout=10.0, interval=0.6):
    """Wait for a pattern's count to **settle**: return only when two consecutive reads are equal (absorbs
    orch async late-arriving entries). Waiting for growth alone (wait_count_gt) is not enough -- after growth
    there may be further entries in flight, and the baseline would still be polluted."""
    last = asicdb.count(pattern)
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(interval)
        cur = asicdb.count(pattern)
        if cur == last:
            return cur
        last = cur
    return last


def test_vrf_vni_mapping(cli, asicdb, config_guard, topo):
    """L3VNI: VRF<->VNI mapping -> an **attribute-exact-match** SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY appears in ASIC_DB.

    Unlike test_vxlan_chip's VLAN<->VNI (L2VNI), this is the VRF<->VNI (L3VNI) path -- not covered by other
    files in this suite. Exercises the real push chain: config vxlan add -> config vrf add -> config vlan add
    -> config vxlan map add (establishes L2VNI, a prerequisite for the VRF mapping) -> config vrf
    add_vrf_vni_map (associates the VNI with the VRF).

    Anti-race design (the original was a "take baseline -> count grew" assertion; the L2VNI map's
    TUNNEL_MAP_ENTRY arriving late and async would land after the baseline was taken, impersonating L3VNI
    growth -> false pass):
      (1) after L2VNI map add, first wait for its own entries to settle and be **stable across reads** before
          continuing (_wait_stable_count);
      (2) the chip assertion becomes an **attribute exact match**: there must exist TUNNEL_MAP_ENTRY entries where
         encap direction: type==VIRTUAL_ROUTER_ID_TO_VNI and VIRTUAL_ROUTER_ID_KEY==Vrf-vni's VR oid,
                    VNI_ID_VALUE==L3VNI;
         decap direction: type==VNI_TO_VIRTUAL_ROUTER_ID and VNI_ID_KEY==L3VNI,
                    VIRTUAL_ROUTER_ID_VALUE==the same VR oid.
         L2VNI entries have type VLAN_ID_TO_VNI/VNI_TO_VLAN_ID and cannot impersonate.
    CONFIG_DB is used only for intermediate-state checks; if the chip does not precisely program L3VNI the
    assertion FAILs and exposes it faithfully (with static VXLAN and no EVPN/NVO, L3VNI usually does not reach
    the chip; expose the binary outcome without masking via xfail)."""
    topo.caps.require("vxlan")
    src = topo.subnet("b")["dut"]
    vid = topo.vlan("f")
    ent_pat = "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY:*"
    cli.config_raw(f"vxlan add {VTEP} {src}")
    config_guard.defer_undo(f"vxlan del {VTEP}")
    # config vrf add syntax confirmed correct: `config vrf add <vrf_name>`, Vrf-vni is a legal name.
    # The original failure root cause was that a **previous run's teardown did not clean up**, leaving Vrf-vni
    # behind -> this add returns rc=2 "VRF Vrf-vni already exists" (not a device defect). So idempotently
    # pre-clean the remnant once, then add.
    cli.config_raw("vrf del Vrf-vni")   # idempotent pre-clean (ignore rc if it does not exist)
    # record the VR set before add -- later used to obtain the SAI VR oid for Vrf-vni (the anchor for attribute exact matching)
    before_vr = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER"))
    rc, r = cli.config_raw("vrf add Vrf-vni")
    config_guard.defer_undo("vrf del Vrf-vni")
    assert rc == 0, f"config vrf add failed (CLI/device issue): {r.err or r.out}"
    vr_oid = _wait_new_vr(asicdb, before_vr)
    assert vr_oid, (
        "VRF Vrf-vni created but no new SAI_OBJECT_TYPE_VIRTUAL_ROUTER appeared in ASIC "
        "(VRF itself not programmed to chip; L3VNI map entries cannot be attributed)")
    cli.config_raw(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    # first build the L2VNI (VLAN<->VNI) as a prerequisite for the VRF-VNI mapping (add_vrf_vni_map requires
    # that VNI to already be mapped to a VLAN). It also asynchronously produces a TUNNEL_MAP_ENTRY -- must wait
    # for it to settle before proceeding, otherwise it pollutes later judgment (see docstring (1)).
    pre_l2 = asicdb.count(ent_pat)
    rc2, r2 = cli.config_raw(f"vxlan map add {VTEP} {vid} {_L3VNI}")
    config_guard.defer_undo(f"vxlan map del {VTEP} {vid} {_L3VNI}")
    assert rc2 == 0, f"vxlan map add (L2VNI prerequisite) failed (CLI/device issue): {r2.err or r2.out}"
    # (1) first wait for L2VNI entries to grow (if it never happens just record it -- whether L2VNI is programmed is dedicated-tested by test_vxlan_chip), then read until stable
    l2_programmed = asicdb.wait_count_gt(ent_pat, pre_l2, timeout=12)
    base_ent = _wait_stable_count(asicdb, ent_pat)

    # the actual L3VNI push: associate the VNI with the VRF (config vrf add_vrf_vni_map <vrf> <vni>)
    rc3, r3 = cli.config_raw(f"vrf add_vrf_vni_map Vrf-vni {_L3VNI}")
    config_guard.defer_undo("vrf del_vrf_vni_map Vrf-vni")
    assert rc3 == 0, f"vrf add_vrf_vni_map failed (CLI/device issue): {r3.err or r3.out}"
    # intermediate state: VRF<->VNI mapping actually written into CONFIG_DB (VRF|Vrf-vni.vni)
    end = time.time() + 5
    while time.time() < end and cli.db_hgetall("CONFIG_DB", "VRF|Vrf-vni").get("vni") != str(_L3VNI):
        time.sleep(0.4)
    assert cli.db_hgetall("CONFIG_DB", "VRF|Vrf-vni").get("vni") == str(_L3VNI), \
        "VRF-VNI mapping not written to CONFIG_DB VRF|Vrf-vni.vni"
    # (2) chip assertion = attribute exact match (the original "count grew" assertion could be satisfied by any late entry, deprecated):
    #    both the encap (VR->VNI) and decap (VNI->VR) TUNNEL_MAP_ENTRY must exist with fields hitting this VRF / this VNI
    enc, dec = [], []
    end = time.time() + 12
    while time.time() < end:
        enc = asicdb.find(
            "SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY",
            SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE="SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI",
            SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY=vr_oid,
            SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE=str(_L3VNI))
        dec = asicdb.find(
            "SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY",
            SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE="SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID",
            SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY=str(_L3VNI),
            SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE=vr_oid)
        if enc and dec:
            break
        time.sleep(0.5)
    now_ent = asicdb.count(ent_pat)
    assert enc and dec, (
        f"VRF-VNI (L3VNI) mapping in CONFIG_DB but not precisely programmed to ASIC: "
        f"encap VR->VNI entry found={bool(enc)}, decap VNI->VR entry found={bool(dec)} "
        f"(vr={vr_oid}, vni={_L3VNI}; TUNNEL_MAP_ENTRY count {base_ent}->{now_ent}, "
        f"L2VNI prerequisite programmed={l2_programmed}) "
        "-- L3 VNI mapping not on chip")
