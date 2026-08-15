"""ARP / ND responder: emulate the peer and answer the DUT's ARP requests for peer_ip.

Lets the DUT resolve the peer and program NEIGHBOR_ENTRY + NEXTHOP (dynamic neighbor cases).
"""
from .base import Responder

try:
    from scapy.all import ARP, Ether
except Exception:  # noqa: BLE001
    ARP = Ether = None


class ArpResponder(Responder):
    bpf = "arp"

    def __init__(self, iface, peer_ip, peer_mac):
        super().__init__(iface)
        self.peer_ip = peer_ip
        self.peer_mac = peer_mac

    def handle(self, pkt):
        if not pkt.haslayer(ARP):
            return None
        arp = pkt[ARP]
        if arp.op != 1 or arp.pdst != self.peer_ip:   # only answer who-has peer_ip
            return None
        self.stats["seen"] += 1
        self.seen.append((arp.psrc, arp.hwsrc))
        return (Ether(dst=arp.hwsrc, src=self.peer_mac) /
                ARP(op=2, hwsrc=self.peer_mac, psrc=self.peer_ip,
                    hwdst=arp.hwsrc, pdst=arp.psrc))
