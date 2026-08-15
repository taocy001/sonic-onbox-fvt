#!/usr/bin/env python3
"""Bounded hairpin diagnostic (correct pvlan set command): check all 4 counters + read back PVID after sending, to locate a residual loop."""
import re
import subprocess
import sys
import time

import sys
N = int(sys.argv[1]) if len(sys.argv)>1 else 20


def bcm(cmd):
    return subprocess.run(["docker", "exec", "syncd", "bcmcmd", cmd],
                          capture_output=True, text=True).stdout


def ctr(p, metric):
    m = re.search(rf"{metric}\.{p}\b[^:]*:\s*([\d,]+)", bcm(f"show c {p}"))
    return int(m.group(1).replace(",", "")) if m else 0


def pvid(p):
    m = re.search(r"default VLAN is (\d+)", bcm(f"pvlan show {p}"))
    return m.group(1) if m else "?"


# The environment is set up by the shell with VLAN110 (cd0,cd1 untagged)/120 (cd1)/FDB (110:44:55->cd1).
bcm("port cd0 lb=mac"); bcm("port cd1 lb=mac")
bcm("pvlan set cd1 120")
print("PVID before send: cd0=%s cd1=%s" % (pvid("cd0"), pvid("cd1")))
time.sleep(1)
b = {(p, m): ctr(p, m) for p in ("cd0", "cd1") for m in ("MIB_RPKT", "MIB_TPKT")}
subprocess.run(["python3", "-c",
                'from scapy.all import *;sendp(Ether(dst="00:11:22:33:44:55",'
                'src="00:de:ad:be:ef:01")/IP()/UDP()/Raw(b"x"*40),iface="Ethernet1",'
                'count=%d,verbose=0)' % N], capture_output=True)
time.sleep(1.5)
a = {(p, m): ctr(p, m) for p in ("cd0", "cd1") for m in ("MIB_RPKT", "MIB_TPKT")}
bcm("port cd0 lb=none"); bcm("port cd1 lb=none")
print("PVID after send:  cd0=%s cd1=%s" % (pvid("cd0"), pvid("cd1")))
print(f"sent={N}")
for p in ("cd0", "cd1"):
    print(f"  {p}: RX +{a[(p,'MIB_RPKT')]-b[(p,'MIB_RPKT')]}  TX +{a[(p,'MIB_TPKT')]-b[(p,'MIB_TPKT')]}")
bcm("pvlan set cd1 110")
