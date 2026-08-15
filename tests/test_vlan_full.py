"""VLAN full feature set: member modes/native/range/tagged/VLAN-IF MTU/QinQ/PVLAN/translation/BUM.

Basic create/member/show live in test_vlan.py. This file fills in the advanced features; guard uncertain CLIs with an rc-checked skip.
"""
import time

import pytest

from framework import vlanchk

pytestmark = [pytest.mark.l2]

# ---- ASIC SAI object/attribute constants (VLAN member / RIF) ----
_VLAN = "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*"
_VLAN_MEMBER = "ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*"
_RIF = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*"
_MODE_TAGGED = "SAI_VLAN_TAGGING_MODE_TAGGED"
_MODE_UNTAGGED = "SAI_VLAN_TAGGING_MODE_UNTAGGED"


def _wait_vlan_oid(asicdb, vid, tries=20):
    """Poll ASIC_DB for the VLAN object oid (like 'oid:0x...') where SAI_VLAN_ATTR_VLAN_ID==vid. None if not found."""
    for _ in range(tries):
        for k in asicdb.objects("SAI_OBJECT_TYPE_VLAN"):
            if asicdb.field(k, "SAI_VLAN_ATTR_VLAN_ID") == str(vid):
                return k.split("SAI_OBJECT_TYPE_VLAN:")[-1]
        time.sleep(0.5)
    return None


def _wait_member_modes(asicdb, vlan_oid, tries=20):
    """Poll ASIC_DB and return the tagging_mode list of all SAI_VLAN_MEMBERs belonging to this VLAN(oid) (until non-empty or timeout)."""
    for _ in range(tries):
        modes = [asicdb.field(k, "SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE")
                 for k in asicdb.objects("SAI_OBJECT_TYPE_VLAN_MEMBER")
                 if asicdb.field(k, "SAI_VLAN_MEMBER_ATTR_VLAN_ID") == vlan_oid]
        if any(modes):
            return modes
        time.sleep(0.5)
    return []


def test_vlan_range_high_id(cli, asicdb, config_guard):
    """VLAN range 2-4094: create high-numbered VLAN 4094 and verify it is actually programmed to ASIC (SAI_VLAN count grows)."""
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*")
    cli.config("vlan add 4094")
    config_guard.defer_undo("vlan del 4094")
    assert cli.db_keys("CONFIG_DB", "VLAN|Vlan4094"), "high-numbered VLAN not created"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*", base, timeout=8), \
        "VLAN 4094 not programmed to ASIC (no new SAI_VLAN object)"


def test_vlan_tagged_member(cli, topo, asicdb, dut, config_guard):
    """trunk(tagged) member actually programmed to chip: add a tagged member -> a new SAI_VLAN_MEMBER appears in ASIC
    with tagging_mode==TAGGED. This checks more than the CONFIG_DB config contract; it verifies the chip-side VLAN member
    object lands in tagged mode (orchagent really pushes the member mode down to SAI). Egress push-tag packet content is a
    data-plane check, see test_vlan_tag_content.py."""
    port = topo.l2_port(0).name
    vid = topo.vlan("a")
    cli.config(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    base = asicdb.count(_VLAN_MEMBER)
    rc, r = cli.config_raw(f"vlan member add {vid} {port}")  # tagged by default
    config_guard.defer_undo(f"vlan member del {vid} {port}")
    # tagged member add is standard SONiC CLI (`config vlan member add` without -u is trunk/tagged) and must succeed;
    # a failure is a CLI contract defect, so hard-fail to expose it rather than masking with skip (C -> real assertion).
    assert rc == 0, (
        f"tagged vlan member add failed (rc={rc}): {r.err or r.out}; "
        "'config vlan member add' is standard SONiC CLI and must succeed")
    # Two lines of evidence: first briefly wait for the SAI object model (community); if no object appears, check the chip
    # bitmap (SONiC pass-through model does not create SAI_VLAN_MEMBER; model probing is easily disturbed by runtime state,
    # so we don't make it a global decision).
    if not asicdb.wait_count_gt(_VLAN_MEMBER, base, timeout=6):
        assert vlanchk.chip_member(cli, dut, vid, port, untagged=False), \
            f"tagged member {port} neither as SAI_VLAN_MEMBER nor in chip vlan {vid} bitmap (tagged)"
        return
    vlan_oid = _wait_vlan_oid(asicdb, vid)
    assert vlan_oid, f"VLAN {vid} object not found in ASIC_DB (SAI_OBJECT_TYPE_VLAN)"
    modes = _wait_member_modes(asicdb, vlan_oid)
    assert _MODE_TAGGED in modes, \
        f"VLAN {vid} member tagging mode in ASIC is not TAGGED: got {modes}"


def test_vlan_untagged_pvid(cli, topo, asicdb, dut, config_guard):
    """access(untagged) member actually programmed to chip: add a port untagged into VLAN-b -> the VLAN's SAI_VLAN_MEMBER
    in ASIC has tagging_mode==UNTAGGED (PVID semantics land on the chip side). This checks more than the CONFIG_DB config
    contract; it verifies orchagent really pushes the untagged member mode down to SAI. The data-plane consequence of the
    ingress PVID tag is in test_vlan_chip.py (flooding/isolation scope)."""
    _pobj = topo.l2_port(1)
    port = _pobj.name
    cli.ensure_port_l2(_pobj)   # under SONiC (l2_home_forwarding=false) an L3 port is not an automatic L2 member; explicitly move it to the bridge to program the chip
    vid = topo.vlan("b")
    dvlan = topo.default_vlan
    cli.config(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    # a port can be untagged in only one VLAN, so first remove it from the default VLAN
    cli.config_raw(f"vlan member del {dvlan} {port}")
    config_guard.defer_undo(f"vlan member add -u {dvlan} {port}")
    cli.config_raw(f"vlan member add -u {vid} {port}")
    config_guard.defer_undo(f"vlan member del {vid} {port}")
    # net member count is unchanged (remove 1 from default + add 1 to VLAN-b), so don't rely on a count delta; look up the VLAN's member mode directly in ASIC
    if not vlanchk.sai_member_model(asicdb):
        assert vlanchk.chip_member(cli, dut, vid, port, untagged=True), \
            f"untagged member {port} not in chip vlan {vid} untagged bitmap (PVID semantics not on chip)"
        return
    if vlanchk.chip_member(cli, dut, vid, port, untagged=True):
        return   # chip bitmap already proves the untagged member (SONiC mixed-state fallback)
    vlan_oid = _wait_vlan_oid(asicdb, vid)
    assert vlan_oid, f"VLAN {vid} object not found in ASIC_DB (SAI_OBJECT_TYPE_VLAN)"
    modes = _wait_member_modes(asicdb, vlan_oid)
    assert modes, f"no SAI_VLAN_MEMBER programmed for VLAN {vid} in ASIC (untagged member not on chip)"
    assert _MODE_UNTAGGED in modes, \
        f"VLAN {vid} access member tagging mode in ASIC is not UNTAGGED (PVID): got {modes}"


# ============================ Removed: advanced features with no corresponding CLI (class C) ============================
# The following 4 cases were originally guarded with `if rc != 0: pytest.skip(...)` for "CLI to be confirmed". After checking
# the sonic-utilities source, the corresponding CLIs simply do not exist in this image, which falls under rule C "CLI genuinely
# does not exist -> delete", so they are removed entirely:
#   - test_vlan_interface_mtu: `config interface mtu` only calls portconfig against the physical PORT table (see config/main.py
#     mtu subcommand -> `portconfig -p <intf>`) and has no effect on a VLAN SVI -> VLAN-IF MTU CLI does not exist, removed.
#   - test_qinq_outer_vlan: `interface switchport stacked-vlan` is not defined in sonic-utilities/config, removed.
#   - test_pvlan_isolated: `vlan private-vlan` is not defined, removed.
#   - test_vlan_translation: `interface vlan-translation` is not defined, removed.
# If a later image adds any of these CLIs, create a new case with real assertions (CONFIG_DB/ASIC programming) rather than a skip guard.
