#!/usr/bin/env python3
"""Test the full forwarding path with dual loopback (cd0+cd1) + known-unicast dst->cd1 (hairpin mode), comparing MAC/PHY."""
import re
import subprocess
import time


def bcm(c):
    return subprocess.run(["docker", "exec", "syncd", "bcmcmd", c],
                          capture_output=True, text=True).stdout


def ctr(p, m):
    x = re.search(rf"{m}\.{p}\b[^:]*:\s*([\d,]+)", bcm(f"show c {p}"))
    return int(x.group(1).replace(",", "")) if x else 0


def send():
    subprocess.run(["python3", "-c",
                    'from scapy.all import *;sendp(Ether(dst="00:11:22:33:44:b1",'
                    'src="00:de:ad:be:ef:90")/IP()/Raw(b"x"*40),iface="Ethernet1",'
                    'count=10,verbose=0)'], capture_output=True)


bcm("vlan destroy 300")
bcm("vlan create 300 pbm=cd0,cd1,cd2 ubm=cd0,cd1,cd2")
bcm("pvlan set cd0 300")
bcm("pvlan set cd1 300")
bcm("pvlan set cd2 300")
bcm("l2 clear")
# two dsts: b1->cd1 (looped port), b2->cd2 (non-looped port)
bcm("l2 add mac=00:11:22:33:44:b1 vlan=300 port=cd1")
bcm("l2 add mac=00:11:22:33:44:b2 vlan=300 port=cd2")


def send_to(dmac):
    subprocess.run(["python3", "-c",
                    'from scapy.all import *;sendp(Ether(dst="%s",src="00:de:ad:be:ef:90")'
                    '/IP()/Raw(b"x"*40),iface="Ethernet1",count=10,verbose=0)' % dmac],
                   capture_output=True)


# cd0,cd1 looped; cd2 not looped. Compare dst->cd1 (looped) vs dst->cd2 (non-looped)
for dmac, tgt in (("00:11:22:33:44:b1", "cd1(LOOPED)"), ("00:11:22:33:44:b2", "cd2(non-loop)")):
    bcm("clear c")
    bcm("port cd0 lb=mac")
    bcm("port cd1 lb=mac")
    time.sleep(1)
    send_to(dmac)
    time.sleep(1.5)
    c0r = ctr("cd0", "MIB_RPKT")
    c2t = ctr("cd2", "MIB_TPKT")
    bcm("port cd0 lb=none")
    bcm("port cd1 lb=none")
    flag = "<==storm!" if c0r > 1000 else "<==no storm"
    print(f"dst->{tgt:14}: cd0(in) RX+{c0r} | cd2 TX+{c2t} {flag}")
bcm("pvlan set cd2 1000")

bcm("pvlan set cd0 1000")
bcm("pvlan set cd1 1000")
bcm("vlan destroy 300")
bcm("l2 clear")
