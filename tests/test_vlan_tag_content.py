"""VLAN tag egress content check -- hard chip limitation, recorded as a documented skip.

Goal: use MirrorCollector to capture the egress frames of a tagged member and verify the
VLAN tag pushed on egress (Dot1Q.vlan). Mirroring real egress frames itself works (see
test_l3_forward_traffic.py::test_l3_forward_content_rewrite, where the L3-rewritten
DMAC/SMAC/TTL were all captured).

But tagged egress cannot be captured storm-free on this chip:
- Capturing egress requires MAC loopback on p_out (front ports have no cable; only loopback
  brings them oper-up so egress triggers mirror);
- a tagged egress frame, when looped back and re-ingressed, keeps VLAN A's tag -> still lands
  in VLAN A -> hits FDB(dst_mac->p_out) -> exits p_out again -> self-loop storm;
- all loop-breaking means fail: (1) asymmetric PVID (hairpin) has no effect on tagged
  re-ingress frames (PVID only applies to untagged frames; tagged frames keep their tag,
  unaffected by PVID); (2) `port discard=all` is accepted but does not drop looped-back
  re-ingress frames, so it cannot break the loop; (3) EDB loopback + IFP-Drop (the CINT
  pattern) is unavailable -- this SDK does not support `lb=edb`.
- The L3 content case works by contrast: after L3 forwarding the frame's DMAC=neighbor MAC
  != router MAC, so on re-ingress it is dropped by DMAC at the L3 port, naturally breaking the loop.

Conclusion: the VLAN tag egress content check needs the ability to "capture tagged egress
frames without the re-ingress frame self-looping" on this chip, and there is currently no
reliable means, so it is skipped (do not storm the device just to force a test). The other
dimensions of egress content checking (L3 DMAC/SMAC/TTL rewrite) are already covered via mirror.
Future unlock path: find a loop-break that works on tagged re-ingress frames (e.g. verify
ingress FP DROP works, or switch to an SDK that supports lb=edb).
"""
import pytest

pytestmark = pytest.mark.traffic

# The original test_vlan_tagged_member_egress_pushes_tag used pytest.skip to record "tagged egress
# content capture is not testable on this chip": capturing egress requires MAC loopback on p_out, but the
# tagged re-ingress frame keeps its VLAN tag -> still lands in the forwarding VLAN -> hits FDB self-loop storm;
# all loop-breaking means (asymmetric PVID only applies to untagged, discard=all does not drop, lb=edb not
# supported by this SDK) fail (see the module docstring above). This is a real chip/SDK content-capture
# measurement limitation (not testable), not a forwarding defect.
# The skip case is removed here (leaving no skip to paper over it). The observable
# dimensions of tagged members (chip member table/PVID state/forwarding scope) are faithfully covered by
# test_vlan_chip.py and test_vlan_full.py; the other dimensions of egress content rewrite (L3 DMAC/SMAC/TTL)
# are covered via mirror by test_l3_forward_traffic::test_l3_forward_content_rewrite.
