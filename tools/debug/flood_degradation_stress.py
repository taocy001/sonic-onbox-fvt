import subprocess, time, sys
from scapy.all import sendp, Ether, IP, UDP

def bcm(c):
    subprocess.run(f'docker exec syncd bcmcmd "{c}"', shell=True, capture_output=True)
def bcmout(c):
    return subprocess.run(f'docker exec syncd bcmcmd "{c}"', shell=True, capture_output=True, text=True).stdout
def clearfdb():
    subprocess.run("sonic-clear fdb all", shell=True, capture_output=True)

MODE = sys.argv[1] if len(sys.argv) > 1 else "dedicated"   # dedicated | default
N = 50
bcm("port all lb=none"); clearfdb(); time.sleep(1)

if MODE == "dedicated":
    bcm("vlan create 2000"); bcm("vlan add 2000 pbm=cd2,cd4,cd6,cd8 ubm=cd2,cd4,cd6,cd8")
    bcm("vlan create 3990")
    bcm("pvlan set cd2 2000")   # injection port PVID=dedicated VLAN -> flooding stays within Vlan2000 (4 ports)
    bcm("pvlan set cd4 3990")   # port under test isolated to break the loop
else:
    bcm("pvlan set cd4 3990")   # default: injection port PVID stays 1000 -> floods to 160 ports; port under test isolated

fails = 0; firstfail = -1
for i in range(N):
    bcm("port cd2 lb=mac"); bcm("port cd4 lb=mac"); time.sleep(0.25)
    mac = f"00:11:22:33:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}"
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / IP() / UDP(), iface="Ethernet3", count=100, verbose=0)
    time.sleep(0.6)
    l2 = bcmout("l2 show").lower().replace(":", "")
    learned = mac.replace(":", "").lower() in l2
    bcm("port cd2 lb=none"); bcm("port cd4 lb=none")
    if not learned:
        fails += 1
        if firstfail < 0: firstfail = i
    clearfdb()

print(f"RESULT mode={MODE}: {N} iters, fails={fails}, firstfail_at={firstfail}")
bcm("port all lb=none")
bcm("pvlan set cd2 1000"); bcm("pvlan set cd4 1000")
bcm("vlan destroy 2000"); bcm("vlan destroy 3990")
clearfdb()
