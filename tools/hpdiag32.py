#!/usr/bin/env python3
"""Pure chip-level hairpin (bcmcmd), for some devices: vlan create + l2 static entry + asymmetric PVID + PHY loopback.
Bypasses the SONiC CLI (STP interception / no -u). No shell pre-config needed."""
import re
import socket
import subprocess
import time

SOCK = "/var/run/sswsyncd/sswsyncd.socket"
N = 10


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


def ctr(p, metric):
    m = re.search(rf"{metric}\.{p}\b[^:]*:\s*([\d,]+)", bcm(f"show c {p}"))
    return int(m.group(1).replace(",", "")) if m else 0


def pvid(p):
    m = re.search(r"default VLAN is (\d+)", bcm(f"pvlan show {p}"))
    return m.group(1) if m else "?"


# Chip-level VLANs: 110 (cd0,cd1 untagged forwarding), 120 (cd1+cpu, return frame dst->cpu punted, not sent back out any port)
bcm("vlan create 110 pbm=cd0,cd1 ubm=cd0,cd1")
bcm("vlan create 120 pbm=cd1,cpu0")
bcm("pvlan set cd0 110"); bcm("pvlan set cd1 120")
print("l2 fwd:", bcm("l2 add mac=00:11:22:33:44:55 vlan=110 port=cd1").strip().split(chr(10))[-2:])
print("l2 cpu:", bcm("l2 add mac=00:11:22:33:44:55 vlan=120 port=cpu0").strip().split(chr(10))[-2:])
bcm("port cd0 lb=phy"); bcm("port cd1 lb=phy")
print("PVID: cd0=%s cd1=%s" % (pvid("cd0"), pvid("cd1")))
time.sleep(1)
b = {(p, m): ctr(p, m) for p in ("cd0", "cd1") for m in ("CLMIB_RPKT",)}
subprocess.run(["python3", "-c",
                'from scapy.all import *;sendp(Ether(dst="00:11:22:33:44:55",'
                'src="00:de:ad:be:ef:01")/IP()/UDP()/Raw(b"x"*40),iface="Ethernet0",'
                'count=%d,verbose=0)' % N], capture_output=True)
time.sleep(1.5)
a = {(p, m): ctr(p, m) for p in ("cd0", "cd1") for m in ("CLMIB_RPKT",)}
bcm("port cd0 lb=none"); bcm("port cd1 lb=none")
print(f"sent={N}")
for p in ("cd0", "cd1"):
    print(f"  {p}: RX +{a[(p,'CLMIB_RPKT')]-b[(p,'CLMIB_RPKT')]}")
# cleanup
bcm("pvlan set cd0 1"); bcm("pvlan set cd1 1")
bcm("l2 del mac=00:11:22:33:44:55 vlan=110"); bcm("l2 del mac=00:11:22:33:44:55 vlan=120")
bcm("vlan destroy 110"); bcm("vlan destroy 120")
