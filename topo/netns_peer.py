"""BGP peer inside a network namespace: establishes a real eBGP session with the DUT (FRR in the host netns) over veth.

Why a netns is needed (verified in practice, see tests/test_bgp.py): FRR refuses to configure
a local address as a neighbor (% Can not configure the local system as neighbor). Putting the
peer IP into a separate netns makes it "remote" from the host's point of view, so FRR accepts
the config; the veth provides the single-hop link between the two.

setup creates a netns + veth pair (the host-side IP is the local end of the BGP session, the
netns-side IP is the peer), and inside the netns runs servers/bgp_speaker.py as a subprocess
(pure standard library, no exabgp needed), exchanging announce/withdraw over stdin.

WARNING: the session subnet (veth) is decoupled from the route nexthop subnet (front-panel
port): the nexthop must land on a front-panel RIF to be programmed to the ASIC.
teardown deletes the netns + veth (thorough cleanup, leaving no residue).
"""
import os
import subprocess

from framework import log

_log = log.get("netnspeer")

_SPEAKER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "servers", "bgp_speaker.py")


class NetnsBgpPeer:
    def __init__(self, cli, dut_ip, peer_ip, peer_as=65002, prefix=24,
                 ns="nsbgp", veth_h="vbgph", veth_p="vbgpp", advertise=None, vrf=None):
        # dut_ip: host-side veth IP (local end of the FRR session); peer_ip: netns side
        # (the peer, not local). advertise: list[(prefix, nexthop)], nexthop must be within a
        # front-panel port's subnet.
        # vrf: if non-empty, enslave the session veth (dut side) to this VRF  the session
        #      lands in the VRF, and together with FRR `router bgp <as> vrf <vrf>` tests BGP
        #      within a VRF (the VRF netdev must already be created by vrfmgrd).
        from framework import worker as _W
        self.cli = cli
        self.dut_ip, self.peer_ip = dut_ip, peer_ip
        self.peer_as, self.prefix, self.vrf = peer_as, prefix, vrf
        # Parallel laning: netns/veth names are suffixed per worker, so two workers each
        # create their own without colliding (w1/single-process keeps the original name)
        self.ns, self.veth_h, self.veth_p = (
            ns + _W.suffix(), veth_h + _W.suffix(), veth_p + _W.suffix())
        self.advertise = list(advertise or [])
        self._proc = None

    def _run(self, cmd, **kw):
        return self.cli.sh.run(cmd, check=False, **kw)

    # ---- netns / veth ----
    def setup_link(self):
        self._cleanup_link()   # guard against residue from a previous run
        self._run(f"ip netns add {self.ns}")
        self._run(f"ip link add {self.veth_h} type veth peer name {self.veth_p}")
        self._run(f"ip link set {self.veth_p} netns {self.ns}")
        if self.vrf:
            # Enslave to the VRF before assigning the address: the local session address and the connected route land directly in the VRF table (vrfmgrd already created the netdev)
            self._run(f"ip link set dev {self.veth_h} master {self.vrf}")
        self._run(f"ip addr add {self.dut_ip}/{self.prefix} dev {self.veth_h}")
        self._run(f"ip link set {self.veth_h} up")
        self._run(f"ip netns exec {self.ns} ip addr add {self.peer_ip}/{self.prefix} dev {self.veth_p}")
        self._run(f"ip netns exec {self.ns} ip link set {self.veth_p} up")
        self._run(f"ip netns exec {self.ns} ip link set lo up")
        _log.info("netns peer link up: %s(host %s) <-> %s(ns %s)",
                  self.veth_h, self.dut_ip, self.veth_p, self.peer_ip)
        return self

    def _cleanup_link(self):
        self._run(f"ip netns del {self.ns}")
        self._run(f"ip link del {self.veth_h}")

    # ---- speaker subprocess ----
    def start_speaker(self, established_timeout=25):
        adv = ";".join(f"{p},{nh}" for p, nh in self.advertise)
        argv = ["ip", "netns", "exec", self.ns, "python3", _SPEAKER, "--serve",
                self.dut_ip, self.peer_ip, str(self.peer_as), adv]
        self._proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, bufsize=1)
        line = self._proc.stdout.readline().strip()   # block waiting for the first status line
        _log.info("speaker first line: %s", line)
        return line == "ESTABLISHED"

    def _send(self, line):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.stdin.write(line + "\n")
                self._proc.stdin.flush()
                self._proc.stdout.readline()   # read OK/ERR
            except (OSError, ValueError):
                pass

    def announce(self, prefix, nexthop):
        self._send(f"announce {prefix} {nexthop}")

    def withdraw(self, prefix):
        self._send(f"withdraw {prefix}")

    def stop_speaker(self):
        if self._proc:
            try:
                if self._proc.poll() is None:
                    self._proc.stdin.write("quit\n")
                    self._proc.stdin.flush()
                self._proc.wait(timeout=3)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                try:
                    self._proc.kill()
                except OSError:
                    pass
            self._proc = None

    # ---- lifecycle ----
    def setup(self):
        self.setup_link()
        return self

    def teardown(self):
        self.stop_speaker()
        self._cleanup_link()

    def __enter__(self):
        return self.setup()

    def __exit__(self, *exc):
        self.teardown()
        return False
