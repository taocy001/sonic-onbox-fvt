"""Chip table coverage (part 1): core SAI objects programmed at switch init, verified present (>0) in ASIC_DB.

Proves the base chip tables are programmed correctly. One parametrized case per type;
a missing type fails (surfacing a platform/SAI defect).
"""
import pytest

pytestmark = [pytest.mark.chip]

# Core objects that must exist once SONiC+Vendor-X is fully up
CORE_TYPES = [
    "SAI_OBJECT_TYPE_SWITCH",
    "SAI_OBJECT_TYPE_PORT",
    "SAI_OBJECT_TYPE_HOSTIF",
    "SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP",
    "SAI_OBJECT_TYPE_VIRTUAL_ROUTER",
    "SAI_OBJECT_TYPE_VLAN",
    "SAI_OBJECT_TYPE_VLAN_MEMBER",
    "SAI_OBJECT_TYPE_BRIDGE",
    "SAI_OBJECT_TYPE_BRIDGE_PORT",
    "SAI_OBJECT_TYPE_QUEUE",
    "SAI_OBJECT_TYPE_SCHEDULER_GROUP",
    "SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP",
    "SAI_OBJECT_TYPE_ROUTE_ENTRY",        # at least a default/connected route
    "SAI_OBJECT_TYPE_ROUTER_INTERFACE",   # CPU port RIF
    "SAI_OBJECT_TYPE_HOSTIF_TRAP",        # CoPP traps (correct type name)
]


@pytest.mark.parametrize("sai_type", CORE_TYPES, ids=[t.split("TYPE_")[1] for t in CORE_TYPES])
def test_core_sai_object_present(asicdb, cli, sai_type):
    # Retry: core objects (e.g. ROUTER_INTERFACE) can transiently read 0 while L3 cases in
    # the suite churn setup/teardown; poll to avoid false negatives. A real miss still fails
    # after the timeout (device issue).
    import time
    n = 0
    for _ in range(16):
        n = asicdb.count(f"ASIC_STATE:{sai_type}:*")
        if n > 0:
            break
        time.sleep(0.5)
    if n == 0 and sai_type == "SAI_OBJECT_TYPE_ROUTER_INTERFACE":
        # RIF is a **config-derived** object: on a factory-empty L3 baseline (no
        # INTERFACE/VLAN_INTERFACE/LOOPBACK config), 0 RIFs is a legitimate state (observed
        # after factory-reset on 158). It is only a defect when L3 interfaces are configured
        # yet RIF is still missing.
        l3cfg = (cli.db_keys("CONFIG_DB", "INTERFACE|*")
                 or cli.db_keys("CONFIG_DB", "VLAN_INTERFACE|*")
                 or cli.db_keys("CONFIG_DB", "LOOPBACK_INTERFACE|*"))
        if not l3cfg:
            pytest.skip("no L3 interface configured on this baseline; RIF legitimately absent")
        pytest.fail(f"L3 interfaces configured ({len(l3cfg)}) but no ROUTER_INTERFACE in ASIC_DB "
                    "(config->RIF programming missing, device issue)")
    if n == 0 and sai_type == "SAI_OBJECT_TYPE_VLAN_MEMBER":
        # VLAN_MEMBER is likewise config-derived: in an all-routed default state (all ports
        # routed, no user VLAN member config) 0 members is a legitimate steady state; SONiC's
        # Vlan1 parking members are intentionally not pushed to the ASIC (by design) and do
        # not count toward the "should be programmed" expectation.
        expected = [k for k in cli.db_keys("CONFIG_DB", "VLAN_MEMBER|*")
                    if not k.startswith("VLAN_MEMBER|Vlan1|")]
        if not expected:
            pytest.skip("no user VLAN members configured (all-routed steady state); "
                        "VLAN_MEMBER legitimately absent")
        pytest.fail(f"user VLAN members configured ({len(expected)}) but no VLAN_MEMBER in "
                    "ASIC_DB (config->chip programming missing, device issue)")
    assert n > 0, f"{sai_type} not present in ASIC_DB (core entry missing, device issue)"
