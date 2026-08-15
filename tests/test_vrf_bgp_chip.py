"""BGP-in-VRF: build a real eBGP session inside a VRF, learn the route into that VRF's RIB/FIB/ASIC, and forward data-plane traffic per the VRF route.

Adds a VRF dimension on top of test_bgp.py (default VRF) -- both the session and the data plane
land in one VRF:
  - session: a netns software peer builds the session with the DUT over a veth; the veth (DUT
    side) is enslaved into the VRF, FRR `router bgp <as> vrf <VRF>` (the peer IP goes in the netns
    so it is not local and FRR accepts the neighbor).
  - data plane: the injection port p_in and the nexthop port p_nh are both bound to the VRF
    (VrfHairpin); the BGP-learned route's nexthop lands on that VRF's front-panel RIF ->
    programmed to that VRF's SAI virtual_router; hairpin traffic from the injection port verifies
    it truly forwards per the VRF FIB.

Strong assertion chain (all VRF-scoped): session Established -> `show bgp vrf` RIB ->
  `ip route show vrf` FIB -> the ASIC ROUTE_ENTRY's vr == that VRF's VIRTUAL_ROUTER -> inject
  p_in -> nexthop port p_nh chip TX+≈N -> ASIC route withdrawn after withdraw.

The VRF BGP instance is configured via vtysh (FRR common path; both the community and modified OS
run bgpd); the session link reuses NetnsBgpPeer(vrf=...). Requires the loopback capability; skip
if scapy/router MAC is missing or the session veth cannot be enslaved (test precondition).
"""
import json
import time

import pytest

pytestmark = [pytest.mark.bgp, pytest.mark.l3]

try:
    from scapy.all import sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

VRF = "Vrf-bgp"
_N = 30


def _wait(pred, timeout=30, interval=1.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    return False


def _vtysh(cli, args):
    r = cli.run(f"vtysh -c '{args}'")
    return (r.out or "") + "\n" + (r.err or "")


def _bare_oid(key):
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def _wait_new_vr(asicdb, before, timeout=8.0):
    """Wait for the new VIRTUAL_ROUTER oid corresponding to the VRF to appear; return the bare
    oid."""
    end = time.time() + timeout
    while time.time() < end:
        new = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER")) - before
        if new:
            return _bare_oid(next(iter(new)))
        time.sleep(0.4)
    return None


def _route_vr_oids(asicdb, prefix):
    """The set of vr (virtual_router) oids of the ROUTE_ENTRYs in the ASIC matching this
    prefix."""
    out = set()
    for k in asicdb.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY"):
        body = k.split("SAI_OBJECT_TYPE_ROUTE_ENTRY:", 1)[-1]
        try:
            d = json.loads(body)
        except (ValueError, TypeError):
            continue
        if d.get("dest", "").startswith(prefix) and d.get("vr"):
            out.add(d["vr"])
    return out


def _vrf_netdev_ready(cli, vrf, tries=20):
    for _ in range(tries):
        if cli.sh.run(f"ip link show {vrf}", check=False).rc == 0:
            return True
        time.sleep(0.4)
    return False


def _iface_master(cli, iface):
    import re
    out = cli.sh.run(f"ip -o link show {iface}", check=False).out or ""
    m = re.search(r"master (\S+)", out)
    return m.group(1) if m else None


def test_bgp_in_vrf_session_route_and_dataplane(cli, dut, _lb, asicdb, topo):
    """eBGP session inside a VRF -> route into that VRF's RIB/FIB/ASIC (vr matches that VRF) ->
    hairpin traffic from the injection port forwards out the nexthop port (chip TX+≈N) ->
    withdrawn on withdraw. VRF-scoped throughout."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")

    from framework.vrfhairpin import VrfHairpin
    from topo.netns_peer import NetnsBgpPeer

    sess = topo.subnet("bgp")
    sub_in = topo.subnet("c")           # injection-port subnet
    sub_nh = topo.subnet("d")           # nexthop-port subnet
    DUT_AS, PEER_AS = sess["dut_as"], sess["peer_as"]
    SESS_DUT, SESS_PEER = sess["dut"], sess["peer"]
    NH_IP = sub_nh["peer"]              # BGP route nexthop (in the nexthop-port subnet, has a static neighbor)
    NH_MAC = topo.mac("peer_a")
    ROUTE = topo.route("a")

    vh = VrfHairpin(cli, dut, _lb, topo, asicdb)
    if not vh.rmac:
        pytest.skip("router MAC (DEVICE_METADATA.mac) not found")

    before_vr = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER"))
    p_in, p_nh = topo.l3_port(0), topo.l3_port(1)
    peer = NetnsBgpPeer(cli, SESS_DUT, SESS_PEER, peer_as=PEER_AS,
                        prefix=sess["prefix"], advertise=[(ROUTE, NH_IP)], vrf=VRF)
    bgp_configured = False
    try:
        # 1) create VRF + bind both ports + nexthop static neighbor (the nexthop must land on that
        #    VRF's RIF for it to be programmed to the ASIC)
        vh.add_vrf(VRF)
        vr_oid = _wait_new_vr(asicdb, before_vr)
        assert vr_oid, "VRF created but no SAI VIRTUAL_ROUTER appeared in ASIC"
        ok, why = vh.bind(VRF, p_in, f"{sub_in['dut']}/{sub_in['prefix']}")
        assert ok, f"bind {p_in.name} to {VRF} failed: {why}"
        ok, why = vh.bind(VRF, p_nh, f"{sub_nh['dut']}/{sub_nh['prefix']}")
        assert ok, f"bind {p_nh.name} to {VRF} failed: {why}"
        cli.neigh_set(NH_IP, NH_MAC, p_nh.name)

        # 2) session link: wait for the VRF netdev to be ready, build the netns peer, and enslave
        #    the session veth into the VRF
        assert _vrf_netdev_ready(cli, VRF), f"{VRF} kernel netdev not created by vrfmgrd"
        peer.setup()
        if _iface_master(cli, peer.veth_h) != VRF:
            pytest.skip(f"could not enslave session veth {peer.veth_h} into {VRF} "
                        f"(test precondition, not a BGP defect)")

        # 3) VRF BGP instance (vtysh common path; disable ebgp-requires-policy, otherwise the
        #    received route is blocked by policy and not installed to the FIB)
        cli.vtysh("\n".join([
            f"router bgp {DUT_AS} vrf {VRF}",
            f"bgp router-id {SESS_DUT}",
            "no bgp ebgp-requires-policy",
            f"neighbor {SESS_PEER} remote-as {PEER_AS}",
            "address-family ipv4 unicast",
            f"neighbor {SESS_PEER} activate",
        ]), config=True)
        bgp_configured = True

        # 4) session reaches Established (software peer + FRR double confirmation, both scoped to
        #    the VRF)
        assert peer.start_speaker(established_timeout=25), \
            "BGP speaker failed to reach Established (handshake)"
        assert _wait(lambda: "Established" in _vtysh(cli, f"show bgp vrf {VRF} neighbor {SESS_PEER}"),
                     timeout=20), f"FRR neighbor not Established in {VRF}"

        # 5) VRF RIB learns the prefix
        def _in_rib():
            out = _vtysh(cli, f"show bgp vrf {VRF} ipv4 unicast {ROUTE}")
            return "Paths:" in out and NH_IP in out
        assert _wait(_in_rib, timeout=20), f"announced route {ROUTE} not in {VRF} BGP RIB"

        # 6) VRF kernel FIB: selected via BGP, nexthop lands on the nexthop port
        def _in_fib():
            out = cli.sh.run(f"ip route show {ROUTE} vrf {VRF}", check=False).out or ""
            return "bgp" in out and p_nh.name in out
        assert _wait(_in_fib, timeout=20), f"route {ROUTE} not in {VRF} FIB via BGP/{p_nh.name}"

        # 7) ASIC: this prefix's ROUTE_ENTRY lands on **this VRF's virtual_router** (not the
        #    default VR)
        assert _wait(lambda: vr_oid in _route_vr_oids(asicdb, ROUTE.split("/")[0]), timeout=30), (
            f"BGP-learned route {ROUTE} not programmed to ASIC under {VRF}'s virtual_router {vr_oid} "
            f"(VRF-scoped BGP route not isolated/programmed to hardware)")

        # 8) data plane: hairpin traffic from the injection port toward ROUTE -> routed per the
        #    VRF FIB -> nexthop port chip TX+≈N
        dst_ip = ROUTE.split("/")[0].rsplit(".", 1)[0] + ".5"
        tx = vh.forward_tx(p_in, dst_ip, sub_in["peer"], p_nh, n=_N)
        assert _N * 0.9 <= tx < 100_000, (
            f"traffic to a BGP-in-VRF learned route NOT forwarded: injected {_N} into {p_in.name} "
            f"({VRF}), egress {p_nh.name} chip TX={tx} (~{_N} expected; VRF BGP FIB not driving data plane)")

        # 9) withdraw -> ASIC route withdrawn
        peer.withdraw(ROUTE)
        assert _wait(lambda: vr_oid not in _route_vr_oids(asicdb, ROUTE.split("/")[0]), timeout=30), \
            f"withdrawn route still programmed in ASIC under {VRF}'s virtual_router"
    finally:
        if bgp_configured:
            cli.vtysh(f"no router bgp {DUT_AS} vrf {VRF}", config=True)
        cli.neigh_del(NH_IP, p_nh.name)
        peer.teardown()
        vh.cleanup()
