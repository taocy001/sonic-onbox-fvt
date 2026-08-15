#!/usr/bin/env python3
"""Run on the host: conclude whether PHY loopback + FDB->cd1 avoids a storm.

Steps: confirm the FDB is programmed into the ASIC -> cd0 lb=phy -> read the cd0 RPKT base ->
scapy sends `count` frames -> immediately lb=none -> read after -> delta. delta~count means no
storm; far exceeding it means a PHY self-loop.
"""
import socket
import subprocess
import sys
import time

SOCK = "/var/run/sswsyncd/sswsyncd.socket"
COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 10
DST = "00:aa:bb:cc:dd:ee"


def bcm(cmd, t=5):
    """Run diag over the unix socket inside the syncd container."""
    py = (f'import socket,time;s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);'
          f's.setblocking(True);s.settimeout({t});s.connect("{SOCK}");'
          f's.sendall(__import__("sys").argv[1].encode()+b"\\n");buf=b"";e=time.time()+{t}\n'
          'while time.time()<e:\n'
          ' try:c=s.recv(8192)\n'
          ' except socket.timeout:break\n'
          ' if not c or b"BCM.0>" in (buf:=buf+c):break\n'
          's.close();__import__("sys").stdout.write(buf.decode("utf-8","replace"))')
    return subprocess.run(["docker", "exec", "-i", "syncd", "python3", "-c", py, cmd],
                          capture_output=True, text=True).stdout


def rpkt(port="cd0"):
    import re
    o = bcm(f"show c {port}")
    m = re.search(rf"CLMIB_RPKT\.{port}\b[^:]*:\s*([\d,]+)", o)
    return int(m.group(1).replace(",", "")) if m else -1


# FDB DST -> Ethernet4 (cd1)
fdb = ('[{"FDB_TABLE:Vlan1000:%s": {"port": "Ethernet4", "type": "static"}, "OP": "SET"}]'
       % DST)
subprocess.run(["docker", "exec", "-i", "swss", "bash", "-c",
                f"echo '{fdb}' > /tmp/f.json && swssconfig /tmp/f.json"],
               capture_output=True)
time.sleep(3)
asic = subprocess.run(["sonic-db-cli", "ASIC_DB", "KEYS",
                       "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*"],
                      capture_output=True, text=True).stdout
print("FDB in ASIC for AA:BB:CC:DD:EE:",
      any("AA:BB:CC:DD:EE" in k.upper() for k in asic.splitlines()))

subprocess.run(["ip", "link", "set", "Ethernet0", "up"])
bcm("port cd0 lb=phy")
time.sleep(1)
b = rpkt()
subprocess.run(
    ["python3", "-c",
     'from scapy.all import *;sendp(Ether(dst="%s",src="00:de:ad:be:ef:01")/IP()/UDP()'
     '/Raw(b"x"*40),iface="Ethernet0",count=%d,verbose=0)' % (DST, COUNT)],
    capture_output=True)
time.sleep(1.5)
bcm("port cd0 lb=none")   # turn off immediately
a = rpkt()
print(f"count={COUNT} cd0 RPKT base={b} after={a} delta={a-b}")
with open("/proc/loadavg") as f:
    print("load:", f.read().split()[0])
subprocess.run(["docker", "exec", "-i", "swss", "bash", "-c",
                f'echo \'[{{"FDB_TABLE:Vlan1000:{DST}": {{}}, "OP": "DEL"}}]\' '
                "> /tmp/fd.json && swssconfig /tmp/fd.json"], capture_output=True)
