"""VRF cross-table route leaking (positive) + selective leaking -- dataplane proof.

Complements test_vrf_chip.py: that one verifies "does **not** leak" (isolation, negative); this file
verifies that **after configuring a leak, traffic truly forwards across VRFs**, and that the leak is
**per-prefix selective** (only the leaked prefix crosses VRFs, the non-leaked one stays isolated).

Topology (VrfHairpin, see framework/vrfhairpin.py): the ingress port is in Vrf-A, the egress port in Vrf-B.
In Vrf-A install a route to a destination prefix whose nexthop/egress interface lands on the Vrf-B egress
port (cross-VRF leak). Inject traffic into the Vrf-A ingress -> if the device supports VRF leaking, it
forwards out the Vrf-B egress port via the leaked route, chip TX +~N. Loop-breaking is the same as l3probe
(the re-ingressing egress frame has DMAC=neighbor MAC != router MAC and is dropped at the L3 port), no storm.

VRF cross-table leaking is an optional feature (some images only support BGP-VPN-style leaking) -> gated by
the `vrf_route_leak` cap: set true in the profile once the device is verified to support it, only then does
it participate in this test group.
"""
import pytest

pytestmark = [pytest.mark.l3]

try:
    from scapy.all import sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 30
_NH_MAC_B = "00:11:22:33:66:b1"     # Vrf-B egress nexthop neighbor MAC (verifies DMAC rewrite target / egress forwarding)
_NH_MAC_B2 = "00:11:22:33:66:b2"


def _host_in(net):
    """Prefix -> a host IP within that prefix (.5), used as the injection destination."""
    return net.split("/")[0].rsplit(".", 1)[0] + ".5"


def test_vrf_route_leak_forwards_dataplane(topo, vrf_hairpin):
    """Cross-VRF leak, positive: install a route in Vrf-A whose nexthop lands on the Vrf-B egress port ->
    inject into the Vrf-A ingress -> it should forward out the Vrf-B egress port (chip TX +~N). If the device
    does not support leaking, the route is not programmed into the ASIC -> TX~0 -> FAIL surfaces it."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("vrf_route_leak")
    vh = vrf_hairpin

    sub_out = topo.subnet("d")
    out_cidr = f"{sub_out['dut']}/{sub_out['prefix']}"
    p_out = topo.misc_port(0)
    ok, why = vh.bind("Vrf-B", p_out, out_cidr)
    assert ok, f"bind egress {p_out.name} to Vrf-B failed: {why}"

    dst_net = topo.route("a")
    vh.leak(dst_net, "Vrf-A", sub_out["peer"], p_out, _NH_MAC_B)
    assert vh.wait_route("Vrf-A", dst_net), (
        f"leaked route {dst_net} not installed in the Vrf-A kernel table "
        f"(cross-VRF nexthop rejected)")

    tx = vh.forward_tx(vh.p_in_a, _host_in(dst_net), vh.in_peer, p_out, n=_N)
    assert _N * 0.9 <= tx < 100_000, (
        f"VRF ROUTE LEAK NOT FORWARDED: injected {_N} into Vrf-A destined to a prefix leaked to "
        f"Vrf-B egress {p_out.name}, chip TX delta={tx} (expected ~{_N}; device did not program "
        f"the cross-VRF leaked route to hardware)")


def test_vrf_route_leak_is_selective(topo, vrf_hairpin):
    """Selective leaking: within Vrf-B the egress port has routes to **both** prefixes P1/P2 (both reachable);
    only **P1** is leaked into Vrf-A. Inject Vrf-A -> P1 -> forwards out the Vrf-B egress (TX+~N); inject Vrf-A
    -> P2 (not leaked) -> does not forward (isolation preserved, TX~0). Proves the leak is per-prefix selective,
    not a whole-table opening."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("vrf_route_leak")
    vh = vrf_hairpin

    sub_out = topo.subnet("d")
    out_cidr = f"{sub_out['dut']}/{sub_out['prefix']}"
    p_out = topo.misc_port(0)
    ok, why = vh.bind("Vrf-B", p_out, out_cidr)
    assert ok, f"bind egress {p_out.name} to Vrf-B failed: {why}"

    p1, p2 = topo.route("a"), topo.route("b")
    # Both prefixes are reachable within Vrf-B (both via the egress port's neighbor)
    vh.route("Vrf-B", p1, sub_out["peer"], p_out.name, _NH_MAC_B)
    vh.route("Vrf-B", p2, sub_out["peer"], p_out.name, _NH_MAC_B2)
    # Leak only P1 into Vrf-A
    vh.leak(p1, "Vrf-A", sub_out["peer"], p_out, _NH_MAC_B)
    assert vh.wait_route("Vrf-A", p1), f"leaked route {p1} not installed in Vrf-A"

    tx_leaked = vh.forward_tx(vh.p_in_a, _host_in(p1), vh.in_peer, p_out, n=_N)
    tx_isolated = vh.no_forward_tx(vh.p_in_a, _host_in(p2), vh.in_peer, p_out, n=_N)

    assert _N * 0.9 <= tx_leaked < 100_000, (
        f"leaked prefix {p1} not forwarded across VRFs: chip TX={tx_leaked} (~{_N} expected)")
    assert tx_isolated < _N * 0.5, (
        f"NON-leaked prefix {p2} (reachable in Vrf-B but not leaked to Vrf-A) reached Vrf-B egress "
        f"{p_out.name}: chip TX={tx_isolated} (expected ~0; leak must be per-prefix, not whole-table)")
