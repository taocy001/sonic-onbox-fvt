"""DHCP relay: client broadcasts DISCOVER -> DUT relay adds option-82/giaddr and forwards to a local mock server.

Topology: DUT Vlan1000 SVI=10.99.1.1 acts as the client gateway; server 10.99.2.2 is bound to a local dummy;
scapy broadcasts DISCOVER on a front-panel port (VLAN1000 member), which re-enters via loopback and is captured by the relay.
# The tested config dhcp_relay subcommand is `config dhcp_relay ipv4 helper add/del <vid> <ip>`.
"""
import time

import pytest

pytestmark = [pytest.mark.dhcp]

def _opt82_subopts(hexstr):
    """Parse the TLV sub-options of option-82 (relay agent information): 1=circuit-id, 2=remote-id.
    Returns {sub: bytes}; returns None if the structure is malformed (length overrun / truncated)."""
    raw = bytes.fromhex(hexstr)
    subs, i = {}, 0
    while i + 2 <= len(raw):
        sub, ln = raw[i], raw[i + 1]
        if i + 2 + ln > len(raw):
            return None
        subs[sub] = raw[i + 2:i + 2 + ln]
        i += 2 + ln
    return subs if i == len(raw) else None


def _discover(client_mac, bcast):
    from scapy.all import BOOTP, DHCP, Ether, IP, UDP
    xid = 0x12345678
    chaddr = bytes.fromhex(client_mac.replace(":", ""))
    return (Ether(dst=bcast, src=client_mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=chaddr, xid=xid, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), "end"]))


def test_dhcp_relay_option82(cli, dut, _lb, config_guard, topo):
    from servers.dhcp_server import MockDhcpServer
    from topo.virtual_link import LocalPeerIP

    vid = topo.default_vlan
    svi_ip = topo.subnet("dhcp")["dut"]
    server_ip = topo.server("dhcp_server")
    port = dut.pick_test_ports(1)[0]
    # Precondition: the dhcp_relay feature must be enabled. When the feature is disabled or
    # dhcp_relay.service is masked, the relay forwarding path does not exist and `config dhcp_relay`
    # fails trying to restart the masked service. This is an environment limitation of a
    # feature-not-enabled image, so skip honestly.
    feat = cli.db_hgetall("CONFIG_DB", "FEATURE|dhcp_relay")
    if feat.get("state") != "enabled":
        pytest.skip("dhcp_relay feature disabled / dhcp_relay.service masked on this image; "
                    "relay data path unavailable — cannot verify option-82/giaddr relaying")
    # SVI acts as the client gateway (all ports are already VLAN members)
    cli.config(f"interface ip add Vlan{vid} {svi_ip}/24")
    config_guard.defer_undo(f"interface ip remove Vlan{vid} {svi_ip}/24")
    # server bound to a local dummy; the relay unicast reaches it via the kernel
    peer = LocalPeerIP(cli, server_ip)
    peer.setup()
    # Configure relay (tested syntax: config dhcp_relay ipv4 helper add <vid> <ip>; the old `dhcp_relay add` does not exist)
    rc, _ = cli.config_raw(f"dhcp_relay ipv4 helper add {vid} {server_ip}")
    config_guard.defer_undo(f"dhcp_relay ipv4 helper del {vid} {server_ip}")
    # If the CLI is broken, fail loudly (no longer skip): the config dhcp_relay ipv4 helper subcommand must be accepted.
    assert rc == 0, "config dhcp_relay ipv4 helper add subcommand rejected"

    _lb.enable(port)
    try:
        with MockDhcpServer(server_ip) as srv:
            from scapy.all import AsyncSniffer, BOOTP, sendp
            disc = _discover(topo.mac("client"), topo.mac("bcast"))
            # On the same port, capture the relay's downstream leg (the egress frame where the
            # server OFFER is broadcast by the relay back to the client VLAN); both directions
            # are judged by content (op/xid/yiaddr), not by capture counts.
            sniff = AsyncSniffer(iface=port.name, filter="udp and port 68", store=True)
            sniff.start()
            time.sleep(0.5)
            for _ in range(5):
                sendp(disc, iface=port.name, verbose=False)
                time.sleep(0.2)
            time.sleep(1)
            assert srv.relayed, "mock server did not receive relayed DISCOVER (relay did not forward)"
            assert any(r["giaddr"] == svi_ip for r in srv.relayed), "giaddr is not SVI IP"
            hits = [r for r in srv.relayed if r["option82"]]
            assert hits, "relay did not add option-82"
            # Content-level check: what was relayed must genuinely be a DISCOVER, and option-82
            # must be a well-formed TLV carrying the circuit-id sub-option (sub-option 1) --
            # arbitrary garbage bytes no longer pass.
            assert any(r["msgtype"] == 1 for r in hits), \
                f"relayed packets with option-82 are not DISCOVER: {[r['msgtype'] for r in hits]}"
            subs = _opt82_subopts(hits[0]["option82"])
            assert subs is not None, f"option-82 is not well-formed TLV: {hits[0]['option82']}"
            assert subs.get(1), \
                f"option-82 lacks circuit-id sub-option(1): subs present={sorted(subs)}"
            # Downstream leg: the server has replied with an OFFER (xid=0x12345678, yiaddr=10.99.1.100),
            # which the relay should broadcast back to the client VLAN -- the OFFER must be visible in
            # the egress frames of the member port (completing the first half of the DORA loop).
            time.sleep(2)
            pkts = sniff.stop()
            offers = [p for p in pkts
                      if BOOTP in p and p[BOOTP].op == 2 and p[BOOTP].xid == 0x12345678]
            assert offers, ("server OFFER was not relayed back to the client VLAN "
                            "(downstream relay leg broken)")
            assert str(offers[0][BOOTP].yiaddr) == srv.offered_ip, \
                f"relayed OFFER yiaddr={offers[0][BOOTP].yiaddr} != offered {srv.offered_ip}"
            # Negative control: after deleting the helper, inject the same packets; they should no longer be relayed (delta must be 0)
            rc2, _ = cli.config_raw(f"dhcp_relay ipv4 helper del {vid} {server_ip}")
            assert rc2 == 0, "config dhcp_relay ipv4 helper del rejected"
            time.sleep(5)          # wait for dhcrelay to exit/reload as the config is removed
            n0 = len(srv.relayed)
            for _ in range(5):
                sendp(disc, iface=port.name, verbose=False)
                time.sleep(0.2)
            time.sleep(2)
            assert len(srv.relayed) == n0, (
                f"relay still forwards DISCOVER after helper del "
                f"({len(srv.relayed) - n0} new packets reached the server)")
    finally:
        _lb.disable(port)
        peer.teardown()
