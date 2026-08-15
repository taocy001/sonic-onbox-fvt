"""VXLAN: VTEP/tunnel creation + VNI mapping -> real ASIC_DB programming.

This file originally had test_vxlan_tunnel_create / test_vxlan_vlan_vni_map asserting that
SAI_OBJECT_TYPE_TUNNEL / TUNNEL_MAP / TUNNEL_MAP_ENTRY appears in the ASIC by
"growing from baseline" (wait_count_gt). But test_vxlan_chip.py in the same suite creates the
tunnel objects first, so the baseline is already 1 and "grow-from-baseline" never triggers --
an ineffective assertion.

Real ASIC programming of VXLAN TUNNEL / TUNNEL_MAP / TUNNEL_MAP_ENTRY, plus data-plane
encap/decap (real traffic + capture), is already fully covered by test_vxlan_chip.py
(test_vtep_programs_asic_tunnel / test_vlan_vni_map_programs_asic_tunnel_map and two
strict=False xfail data-plane tests). So the two redundant config-echo tests here have been
removed and delegated entirely to test_vxlan_chip.py, no longer duplicating the same assertion
path.
"""
import pytest

pytestmark = [pytest.mark.vxlan]
