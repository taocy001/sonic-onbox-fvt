#!/usr/bin/env python3
"""Controlled comparison of MAC vs. PHY loopback x different destination MACs, to pin down whether topology/VLAN/dstMAC are misconfigured.
Isolated VLAN 300 (only cd0,cd1, no background traffic). cd0=Ethernet1 is the loopback port; cd1=Ethernet2 does not loop back.
Per group: clear c -> set loopback -> send 10 frames on cd0 -> read cd0/cd1 counters -> disable loopback."""
import re
import subprocess
import sys
import time

N = 10
DMAC_BC = "ff:ff:ff:ff:ff:ff"
DMAC_TO_CD1 = "00:11:22:33:44:b1"
DMAC_TO_CD0 = "00:11:22:33:44:c0"


def bcm(cmd):
    return subprocess.run(["docker", "exec", "syncd", "bcmcmd", cmd],
                          capture_output=True, text=True).stdout


def ctr(p, metric):
    m = re.search(rf"{metric}\.{p}\b[^:]*:\s*([\d,]+)", bcm(f"show c {p}"))
    return int(m.group(1).replace(",", "")) if m else 0


def send(dmac):
    subprocess.run(["python3", "-c",
                    'from scapy.all import *;sendp(Ether(dst="%s",src="00:de:ad:be:ef:90")'
                    '/IP()/UDP()/Raw(b"x"*40),iface="Ethernet1",count=%d,verbose=0)' % (dmac, N)],
                   capture_output=True)


def trial(mode, dmac, label):
    bcm("clear c")
    bcm(f"port cd0 lb={mode}")
    time.sleep(1)
    b0r = ctr("cd0", "MIB_RPKT")
    b1t = ctr("cd1", "MIB_TPKT")
    send(dmac)
    time.sleep(1.5)
    a0r = ctr("cd0", "MIB_RPKT")
    a1t = ctr("cd1", "MIB_TPKT")
    bcm("port cd0 lb=none")
    d0r, d1t = a0r - b0r, a1t - b1t
    storm = " <==storm!" if d0r > 1000 else ""
    print(f"  [{mode:3}] {label:22} cd0(loop)RX+{d0r:<9} cd1 TX+{d1t}{storm}")


bcm("vlan destroy 300")
bcm("vlan create 300 pbm=cd0,cd1 ubm=cd0,cd1")
bcm("pvlan set cd0 300")   # key: untagged membership does not set the PVID, it must be set explicitly
bcm("pvlan set cd1 300")
bcm("l2 clear")
bcm(f"l2 add mac={DMAC_TO_CD1} vlan=300 port=cd1")
bcm(f"l2 add mac={DMAC_TO_CD0} vlan=300 port=cd0")
print("PVID cd0=%s cd1=%s" % (
    re.search(r"is (\d+)", bcm("pvlan show cd0")).group(1),
    re.search(r"is (\d+)", bcm("pvlan show cd1")).group(1)))

mode = sys.argv[1] if len(sys.argv) > 1 else "mac"
print(f"=== loopback={mode} ===")
trial(mode, DMAC_BC, "broadcast")
trial(mode, DMAC_TO_CD1, "unicast->cd1(non-loop)")
trial(mode, DMAC_TO_CD0, "unicast->cd0(self)")

bcm("port cd0 lb=none")
bcm(f"l2 del mac={DMAC_TO_CD1} vlan=300")
bcm(f"l2 del mac={DMAC_TO_CD0} vlan=300")
bcm("vlan destroy 300")
