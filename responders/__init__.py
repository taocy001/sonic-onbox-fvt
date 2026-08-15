"""Data-plane peer emulation: use scapy for async tx/rx on the DUT's front-panel netdev to emulate a peer/server.

Working with MAC loopback:
- peer -> DUT: scapy sends a packet on the netdev -> loopback re-ingress -> dst = DUT router MAC ->
  L3-to-CPU -> DUT receives it.
- DUT -> peer: a frame emitted by the DUT egresses this port, and the scapy sniffer catches it via
  AF_PACKET (including the TX direction), so it can "see" the DUT's request and reply without the
  chip having to deliver it again.

Suited to connectionless/broadcast protocols (ARP/ND/DHCP/ICMP/sampling punt). Connection-oriented
protocols (BGP/TCP) use local daemons under servers (exabgp binds the local peer IP and goes through
the kernel local stack); see servers/.
"""
