#!/usr/bin/env python3
"""On-hardware check: CPU sends packet -> MAC loopback -> CPU receives on the same port.

Runs on the DUT. Args: <netdev>  expects the bcm port for that netdev to already be lb=mac.
Sends N frames with a unique signature, captures them back on the same port, and reports the
hit count. Verifies the hairpin mechanism + the send/receive path.
"""
import sys
import time

from scapy.all import AsyncSniffer, Ether, IP, UDP, Raw, sendp, conf

conf.verb = 0

iface = sys.argv[1] if len(sys.argv) > 1 else "Ethernet1"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
SMAC = "00:de:ad:be:ef:01"
MAGIC = b"HWLBPROBE"

pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=SMAC) /
       IP(dst="1.1.1.1", src="2.2.2.2") / UDP(sport=1111, dport=2222) /
       Raw(MAGIC + b"x" * 32))

sn = AsyncSniffer(iface=iface, filter=f"ether src {SMAC}", store=True)
sn.start()
time.sleep(0.5)
sendp(pkt, iface=iface, count=n, inter=0.02)
time.sleep(0.8)
sn.stop()
got = [p for p in (sn.results or []) if MAGIC in bytes(p)]
print(f"iface={iface} sent={n} captured={len(got)} -> "
      f"{'LOOPBACK-OK' if got else 'NO-CAPTURE'}")
sys.exit(0 if got else 1)
