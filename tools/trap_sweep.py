#!/usr/bin/env python3
"""Per-trap packet-send verification: find out which SONiC traps can really reach the CPU on some platforms.

Mechanism (verified): enable MAC loopback on the cd port -> inject a protocol packet from that
port's netdev -> it re-enters ingress via loopback -> if it hits a trap it's copied to the CPU ->
`tcpdump -Q in` capturing an inbound packet on that netdev = the trap took effect.

Methodology boundary (evidenced): this method works only for FP-field-match traps (L2/protocol
class: DMAC/EtherType/L4port match -- lldp/lacp/udld/arp x4/nd x4 all PASS); it's ineffective for
L3-lookup-result traps (ip2me/bgp/ttl_error/neighbor_miss) -- a loopback CPU-TX packet doesn't
trigger L3 routing (two-port forwarding cd1 TX=0, and L3 traps aren't received on any netdev, even
with cd0 already in Vlan100 + RIF/route in ASIC_DB). Testing L3-result traps needs an external
traffic source for a real ingress.

Usage (on the DUT, sudo):
    python3 trap_sweep.py [netdev] [cdport] [local_ip]
    default: Ethernet1 cd0  (L3-class can't be tested reliably even with local_ip, see above)

Output: one line per trap PASS (reached CPU) / FAIL (didn't reach CPU) / SKIP (missing prerequisite).
"""
import subprocess, sys, time

NETDEV = sys.argv[1] if len(sys.argv) > 1 else "Ethernet1"
CDPORT = sys.argv[2] if len(sys.argv) > 2 else "cd0"
LOCAL_IP = sys.argv[3] if len(sys.argv) > 3 else None   # needed by the ip2me class

def bcm(c):
    subprocess.run(["docker", "exec", "syncd", "bcmcmd", c],
                   capture_output=True, text=True)

def sniff_inject(bpf, scapy_pkt, n_inject=10, secs=4):
    """Capture the netdev's inbound bpf in the background, inject packets, return the number of frames captured."""
    pcap = "/tmp/trapsweep.pcap"
    subprocess.run(f"rm -f {pcap}", shell=True)
    tp = subprocess.Popen(
        ["timeout", str(secs), "tcpdump", "-i", NETDEV, "-Q", "in",
         "-c", "3", bpf, "-w", pcap],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    subprocess.run(
        ["python3", "-c",
         f"from scapy.all import *; sendp({scapy_pkt}, iface='{NETDEV}', "
         f"count={n_inject}, verbose=0)"],
        capture_output=True)
    time.sleep(1.5)
    tp.wait()
    r = subprocess.run(["tcpdump", "-r", pcap], capture_output=True, text=True)
    return len([l for l in r.stdout.splitlines() if l.strip()])

# ---- trap definitions: (name, category, bpf filter, scapy packet expression, needs local_ip?) ----
# L2 class (DMAC/EtherType, no IP needed)
L2 = [
 ("lldp",  "L2", "ether proto 0x88cc",
  'Ether(dst="01:80:c2:00:00:0e",src="00:de:ad:be:ef:01",type=0x88cc)/Raw(b"\\x02\\x07\\x04"+b"x"*40)', False),
 ("lacp",  "L2", "ether proto 0x8809",
  'Ether(dst="01:80:c2:00:00:02",src="00:de:ad:be:ef:02",type=0x8809)/Raw(b"\\x01\\x01"+b"x"*40)', False),
 ("eapol", "L2", "ether proto 0x888e",
  'Ether(dst="01:80:c2:00:00:03",src="00:de:ad:be:ef:03",type=0x888e)/Raw(b"\\x01\\x00"+b"x"*40)', False),
 ("stp",   "L2", "ether dst 01:80:c2:00:00:00",
  'Ether(dst="01:80:c2:00:00:00",src="00:de:ad:be:ef:04")/LLC()/Raw(b"\\x00"*40)', False),
 ("cdp",   "L2", "ether dst 01:00:0c:cc:cc:cc",
  'Ether(dst="01:00:0c:cc:cc:cc",src="00:de:ad:be:ef:05")/LLC()/SNAP(OUI=0xc,code=0x2000)/Raw(b"x"*40)', False),
 ("udld",  "L2", "ether dst 01:00:0c:cc:cc:cc",
  'Ether(dst="01:00:0c:cc:cc:cc",src="00:de:ad:be:ef:06")/LLC()/SNAP(OUI=0xc,code=0x0111)/Raw(b"x"*40)', False),
 # ARP 4 variants (req/resp x broadcast/unicast DMAC) -- all PASS
 ("arp_req_bc","L2","arp",
  'Ether(dst="ff:ff:ff:ff:ff:ff",src="00:de:ad:be:ef:07")/ARP(op=1,pdst="1.2.3.4")', False),
 ("arp_req_uc","L2","arp",
  'Ether(dst="00:11:22:33:44:55",src="00:de:ad:be:ef:08")/ARP(op=1,pdst="1.2.3.4")', False),
 ("arp_resp_bc","L2","arp",
  'Ether(dst="ff:ff:ff:ff:ff:ff",src="00:de:ad:be:ef:09")/ARP(op=2,pdst="1.2.3.4",psrc="1.2.3.5")', False),
 ("arp_resp_uc","L2","arp",
  'Ether(dst="00:11:22:33:44:55",src="00:de:ad:be:ef:0a")/ARP(op=2,pdst="1.2.3.4",psrc="1.2.3.5")', False),
 # ND 4 variants (NS/NA x multicast/unicast DMAC) -- all PASS
 ("nd_ns_mc","L2","icmp6",
  'Ether(dst="33:33:ff:00:00:01",src="00:de:ad:be:ef:0b")/IPv6(dst="ff02::1:ff00:1")/ICMPv6ND_NS(tgt="fe80::1")', False),
 ("nd_ns_uc","L2","icmp6",
  'Ether(dst="00:11:22:33:44:55",src="00:de:ad:be:ef:0c")/IPv6(dst="fe80::1")/ICMPv6ND_NS(tgt="fe80::1")', False),
 ("nd_na_mc","L2","icmp6",
  'Ether(dst="33:33:00:00:00:01",src="00:de:ad:be:ef:0d")/IPv6(dst="ff02::1")/ICMPv6ND_NA(tgt="fe80::2")', False),
 ("nd_na_uc","L2","icmp6",
  'Ether(dst="00:11:22:33:44:55",src="00:de:ad:be:ef:0e")/IPv6(dst="fe80::2")/ICMPv6ND_NA(tgt="fe80::2")', False),
]
# L3 class (ip2me / L4 port, needs local_ip as DIP)
def L3(ip):
    return [
     ("bgp",  "L3", "tcp port 179",
      f'Ether(src="00:de:ad:be:ef:10")/IP(dst="{ip}")/TCP(dport=179)', True),
     ("ssh",  "L3", "tcp port 22",
      f'Ether(src="00:de:ad:be:ef:11")/IP(dst="{ip}")/TCP(dport=22)', True),
     ("ospf", "L3", "ip proto 89",
      f'Ether(dst="01:00:5e:00:00:05",src="00:de:ad:be:ef:12")/IP(dst="224.0.0.5",proto=89)/Raw(b"x"*20)', False),
     ("snmp", "L3", "udp port 161",
      f'Ether(src="00:de:ad:be:ef:13")/IP(dst="{ip}")/UDP(dport=161)', True),
     ("dhcp", "L3", "udp port 67",
      f'Ether(dst="ff:ff:ff:ff:ff:ff",src="00:de:ad:be:ef:14")/IP(dst="255.255.255.255")/UDP(sport=68,dport=67)', False),
     ("ttl_err","EXC","icmp",
      f'Ether(src="00:de:ad:be:ef:15")/IP(dst="{ip}",ttl=1)/ICMP()', True),
     ("ip2me","L3","icmp",
      f'Ether(src="00:de:ad:be:ef:16")/IP(dst="{ip}")/ICMP()', True),
     ("igmp", "MC", "igmp",
      f'Ether(dst="01:00:5e:00:00:01",src="00:de:ad:be:ef:17")/IP(dst="224.0.0.1",proto=2)/Raw(b"\\x11"+b"x"*20)', False),
    ]

def main():
    traps = L2 + (L3(LOCAL_IP) if LOCAL_IP else [(t[0],t[1],t[2],t[3],t[4]) for t in L3("0.0.0.0")])
    subprocess.run(["ip","link","set",NETDEV,"up"], capture_output=True)
    bcm(f"port {CDPORT} lb=mac")
    time.sleep(1)
    print(f"{'trap':10} {'cat':5} {'result':6} frames")
    print("-"*34)
    rows = []
    for name, cat, bpf, pkt, need_ip in traps:
        if need_ip and not LOCAL_IP:
            print(f"{name:10} {cat:5} SKIP   (needs local_ip)"); rows.append((name,cat,"SKIP")); continue
        bcm("clear c")
        n = sniff_inject(bpf, pkt)
        res = "PASS" if n > 0 else "FAIL"
        print(f"{name:10} {cat:5} {res:6} {n}")
        rows.append((name,cat,res))
    bcm(f"port {CDPORT} lb=none")
    p=sum(1 for _,_,r in rows if r=="PASS"); f=sum(1 for _,_,r in rows if r=="FAIL"); s=sum(1 for _,_,r in rows if r=="SKIP")
    print("-"*34); print(f"summary: PASS={p} FAIL={f} SKIP={s}")

if __name__ == "__main__":
    main()
