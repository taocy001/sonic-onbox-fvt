#!/usr/bin/env python3
"""Verify the user's hypothesis: whether the PHY loopback storm is due to the dst MAC resolving back to the loopback port itself.
Control: dst->non-loopback port (cd2) vs dst->loopback port (cd1). Small amount each time, disable loopback immediately."""
import re
import socket
import subprocess
import sys
import time

SOCK = "/var/run/sswsyncd/sswsyncd.socket"
N = 10
DST = "00:11:22:33:44:55"


def bcm(cmd, t=5):
    py = ('import socket,time,sys\n'
          's=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.setblocking(True);s.settimeout(%d)\n'
          's.connect("%s");s.sendall(sys.argv[1].encode()+b"\\n");buf=b"";e=time.time()+%d\n'
          'while time.time()<e:\n'
          ' try:c=s.recv(8192)\n'
          ' except socket.timeout:break\n'
          ' if not c or b"BCM.0>" in (buf:=buf+c):break\n'
          's.close();sys.stdout.write(buf.decode("utf-8","replace"))' % (t, SOCK, t))
    return subprocess.run(["docker", "exec", "-i", "syncd", "python3", "-c", py, cmd],
                          capture_output=True, text=True).stdout


def rx(p):
    m = re.search(rf"CLMIB_RPKT\.{p}\b[^:]*:\s*([\d,]+)", bcm(f"show c {p}"))
    return int(m.group(1).replace(",", "")) if m else 0


# Egress port: cd2 = non-loopback, cd1 = the loopback port itself
target = sys.argv[1] if len(sys.argv) > 1 else "cd2"

def tx(p):
    m = re.search(rf"CLMIB_TPKT\.{p}\b[^:]*:\s*([\d,]+)", bcm(f"show c {p}"))
    return int(m.group(1).replace(",", "")) if m else 0


bcm("l2 clear")
bcm("vlan create 200 pbm=cd1,cd2 ubm=cd1,cd2")
bcm("pvlan set cd1 200")
bcm(f"l2 add mac={DST} vlan=200 port={target}")   # dst -> designated egress
bcm("port cd1 lb=phy")
bcm("clear c")
time.sleep(1)
l2 = bcm("l2 show")
dst_line = [l.strip() for l in l2.splitlines() if "11:22:33:44:55" in l]
print(f"l2: dst->{target}:", dst_line[:1])
subprocess.run(["python3", "-c",
                'from scapy.all import *;sendp(Ether(dst="%s",src="02:02:02:02:02:02")'
                '/IP()/Raw(b"x"*30),iface="Ethernet4",count=%d,verbose=0)' % (DST, N)],
               capture_output=True)
time.sleep(1.5)
c1r, c1t, c2r, c2t = rx("cd1"), tx("cd1"), rx("cd2"), tx("cd2")
bcm("port cd1 lb=none")
print(f"target={target} sent={N}: cd1 RX={c1r} TX={c1t} | cd2 RX={c2r} TX={c2t}")
bcm("pvlan set cd1 1")
bcm(f"l2 del mac={DST} vlan=200")
bcm("vlan destroy 200")
