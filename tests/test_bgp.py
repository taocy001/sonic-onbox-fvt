"""BGP: a stdlib-only on-box software peer builds a **real eBGP session** and announces routes -> DUT learns them -> programmed to ASIC.

No longer depends on exabgp (the old implementation skipped when it was not installed). The peer uses
servers/bgp_speaker.py (a stdlib-only BGP-4 speaker) running in its own network namespace, and builds a
session with the DUT's FRR bgpd over a veth.

Topology (all on the DUT itself, empirically verified, see topo/netns_peer.py):
  Session: host veth (dut side, subnet bgp.dut) <-> netns veth (peer side, subnet bgp.peer)
        -- putting the peer IP in a netns keeps it from being a "local address", so FRR accepts the neighbor config.
  Route nexthop: sits in the **front-panel port subnet** subnet("c") (VirtualLink sets IP + static neighbor + MAC loopback),
        so the BGP-learned route's nexthop resolves to a real RIF -> programmed into the ASIC data plane, rather than resolving to veth/local.

Strong assertion chain: session Established -> BGP RIB -> kernel FIB (selected) -> APPL_DB ROUTE_TABLE
        -> ASIC SAI_OBJECT_TYPE_ROUTE_ENTRY; withdraw the announce -> route removed from ASIC.
"""
import time

import pytest

pytestmark = [pytest.mark.bgp]


def _wait(pred, timeout=30, interval=1.0):
    """Poll until pred() is true; return whether it was reached."""
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    return False


def _vtysh(cli, args):
    r = cli.run(f"vtysh -c '{args}'")
    return (r.out or "") + "\n" + (r.err or "")


def test_bgp_session_and_route_to_asic(cli, dut, _lb, asicdb, appldb, topo):
    """Software peer builds a real eBGP session -> announce a route -> programmed end-to-end to ASIC -> withdraw removes it."""
    topo.caps.require("loopback")   # front-panel port needs MAC loopback to pull oper-up, so the nexthop resolves and programs to ASIC

    from topo.netns_peer import NetnsBgpPeer
    from topo.virtual_link import VirtualLink

    sess = topo.subnet("bgp")          # session subnet (veth+netns)
    dp = topo.subnet("c")              # data-plane / nexthop subnet (front-panel port)
    DUT_AS, PEER_AS = sess["dut_as"], sess["peer_as"]
    SESS_DUT, SESS_PEER = sess["dut"], sess["peer"]
    NH_IP = dp["peer"]                 # nexthop of the announced route (in the front-panel subnet, with a static neighbor)
    ROUTE = topo.route("a")            # announced prefix
    PEER_MAC = topo.mac("peer_a")
    port = dut.pick_test_ports(1)[0]

    # 1) front-panel data-plane port: IP + static neighbor (NH) + MAC loopback (prerequisite for programming the route nexthop to ASIC)
    vl = VirtualLink(cli, dut, _lb, port, dp["dut"], NH_IP,
                     prefix=dp["prefix"], peer_mac=PEER_MAC, vlan=topo.default_vlan)
    # 2) netns software peer + veth session link
    peer = NetnsBgpPeer(cli, SESS_DUT, SESS_PEER, peer_as=PEER_AS,
                        prefix=sess["prefix"], advertise=[(ROUTE, NH_IP)])
    try:
        vl.setup()
        peer.setup()

        # 3) DUT builds the eBGP instance + neighbor (disable ebgp-requires-policy, otherwise received routes are blocked by policy and not installed in FIB).
        # The customized OS follows the product config bgp guidance: all config via config commands, vtysh read-only for FRR state;
        # the community image keeps the vtysh config path.
        if cli.is_switchport_os():
            rc, r = cli.config_raw(
                f"bgp add default -a {DUT_AS} -r {SESS_DUT} -g disable")
            assert rc == 0, f"config bgp add failed: {r.err or r.out}"
            rc, r = cli.config_raw(
                f"bgp neighbor add default {SESS_PEER} -a {PEER_AS} -p external "
                f"-A ipv4-unicast -S activate")
            assert rc == 0, f"config bgp neighbor add failed: {r.err or r.out}"
        else:
            cli.vtysh("\n".join([
                f"router bgp {DUT_AS}",
                f"bgp router-id {SESS_DUT}",
                "no bgp ebgp-requires-policy",
                f"neighbor {SESS_PEER} remote-as {PEER_AS}",
                "address-family ipv4 unicast",
                f"neighbor {SESS_PEER} activate",
            ]), config=True)

        # 4) start the software peer -> session reaches Established (the speaker's first line returns the handshake result)
        established = peer.start_speaker(established_timeout=25)
        assert established, "BGP speaker failed to reach Established (handshake)"

        # confirm Established on the FRR side too
        def _frr_established():
            return "Established" in _vtysh(cli, f"show bgp neighbor {SESS_PEER}")
        assert _wait(_frr_established, timeout=20), \
            "FRR neighbor not Established after speaker connected"

        # 5) BGP RIB learns the prefix
        def _in_rib():
            out = _vtysh(cli, f"show bgp ipv4 unicast {ROUTE}")
            return "Paths:" in out and NH_IP in out
        assert _wait(_in_rib, timeout=20), \
            f"announced route {ROUTE} not in BGP RIB"

        # 6) kernel FIB: selected via BGP, nexthop lands on the front-panel port
        def _in_fib():
            out = _vtysh(cli, f"show ip route {ROUTE.split('/')[0]}")
            return "bgp" in out and port.name in out
        assert _wait(_in_fib, timeout=20), \
            f"route {ROUTE} not installed in FIB via BGP/{port.name}"

        # 7) APPL_DB ROUTE_TABLE (synced by fpmsyncd)
        def _in_appldb():
            return any(ROUTE.split("/")[0] in k
                       for k in cli.db_keys("APPL_DB", "ROUTE_TABLE:*"))
        assert _wait(_in_appldb, timeout=20), \
            f"route {ROUTE} not in APPL_DB ROUTE_TABLE"

        # 8) ASIC: the prefix appears in SAI_OBJECT_TYPE_ROUTE_ENTRY
        assert asicdb.has_route(ROUTE, timeout=30), \
            "BGP-learned route not programmed to ASIC ROUTE_ENTRY"

        # 9) withdraw the announce -> the ASIC route must be removed
        peer.withdraw(ROUTE)

        def _asic_gone():
            return not asicdb.has_route(ROUTE, timeout=1)
        assert _wait(_asic_gone, timeout=30), \
            "withdrawn route still programmed in ASIC ROUTE_ENTRY"
    finally:
        if cli.is_switchport_os():
            cli.config_raw(f"bgp neighbor del default {SESS_PEER}")
            cli.config_raw("bgp del default")
        else:
            cli.vtysh(f"no router bgp {DUT_AS}", config=True)
        peer.teardown()
        vl.teardown()
