"""Pure standard-library BGP-4 speaker (minimal IPv4 unicast), acting as an eBGP peer of the DUT FRR.

Depends on neither exabgp nor any third-party library. Actively opens a TCP connection to
DUT bgpd:179, completes the capability-bearing OPEN/KEEPALIVE handshake to Established, then
announces/withdraws IPv4 routes.

Key points of the single-box BGP topology (empirically confirmed, see tests/test_bgp.py):
  - FRR refuses to configure "the local address" as a neighbor (% Can not configure the
    local system as neighbor), so the peer must live in a separate network namespace (the
    peer IP is not local to the host) and build the session with the DUT over a veth.
  - The route nexthop must fall in the **front-panel port subnet** (which has a static
    neighbor + RIF), so the route is programmed into the ASIC data plane rather than
    resolving to the veth/local. The session subnet (veth) and the nexthop subnet
    (front-panel) are decoupled.

Two usages:
  1) In-process (same netns): use the PyBgpPeer class directly.
  2) Cross-netns (for tests): `ip netns exec <ns> python3 bgp_speaker.py --serve <dut_ip> <local_ip> <as>`,
     which reads `announce <prefix> <nh>` / `withdraw <prefix>` / `quit` on stdin and prints
     ESTABLISHED or FAILED on the first stdout line. topo/netns_peer.py wraps this subprocess protocol.
"""
import socket
import struct
import sys
import threading
import time

BGP_PORT = 179
MARKER = b"\xff" * 16
OPEN, UPDATE, NOTIFICATION, KEEPALIVE = 1, 2, 3, 4


def _ip2bytes(ip):
    return socket.inet_aton(ip)


def _prefix2nlri(prefix):
    """'10.251.0.0/24' -> bytes: <plen><ceil(plen/8) bytes of network>。"""
    net, plen = prefix.split("/")
    plen = int(plen)
    octets = _ip2bytes(net)
    nbytes = (plen + 7) // 8
    return bytes([plen]) + octets[:nbytes]


class PyBgpPeer:
    def __init__(self, dut_ip, local_ip, my_as=65002, router_id=None,
                 hold_time=90, advertise=None):
        # advertise: list[(prefix, nexthop_ip)]
        self.dut_ip = dut_ip
        self.local_ip = local_ip
        self.my_as = my_as
        self.router_id = router_id or local_ip
        self.hold_time = hold_time
        self.advertise = list(advertise or [])
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._established = threading.Event()
        self._lock = threading.Lock()
        self.last_error = None

    # ---- Message construction ----
    @staticmethod
    def _msg(mtype, body=b""):
        length = 19 + len(body)
        return MARKER + struct.pack("!HB", length, mtype) + body

    def _open_msg(self):
        bgp_id = _ip2bytes(self.router_id)
        # Capability-bearing OPEN so FRR negotiates AFI/SAFI normally (summary shows PfxRcd instead of NoNeg):
        #   MP-BGP IPv4 unicast (cap 1: AFI=1 res=0 SAFI=1) + 4-octet ASN (cap 65)
        cap_mp = bytes([1, 4, 0, 1, 0, 1])
        cap_as4 = bytes([65, 4]) + struct.pack("!I", self.my_as)
        opt = (bytes([2, len(cap_mp)]) + cap_mp +
               bytes([2, len(cap_as4)]) + cap_as4)
        as2 = self.my_as if self.my_as <= 0xFFFF else 23456   # AS_TRANS
        body = (struct.pack("!BHH", 4, as2, self.hold_time) + bgp_id +
                bytes([len(opt)]) + opt)
        return self._msg(OPEN, body)

    def _keepalive_msg(self):
        return self._msg(KEEPALIVE)

    def _update_announce(self, prefix, nexthop):
        origin = bytes([0x40, 1, 1, 0])                       # ORIGIN IGP
        # AS_PATH: 4-octet ASN negotiated, so encode the AS in 4 bytes (AS_SEQUENCE, 1 AS)
        as_path = bytes([0x40, 2, 6, 2, 1]) + struct.pack("!I", self.my_as)
        next_hop = bytes([0x40, 3, 4]) + _ip2bytes(nexthop)
        attrs = origin + as_path + next_hop
        nlri = _prefix2nlri(prefix)
        body = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs + nlri
        return self._msg(UPDATE, body)

    def _update_withdraw(self, prefix):
        withdrawn = _prefix2nlri(prefix)
        body = struct.pack("!H", len(withdrawn)) + withdrawn + struct.pack("!H", 0)
        return self._msg(UPDATE, body)

    # ---- Send/receive ----
    def _recv_msg(self, sock):
        hdr = self._recv_n(sock, 19)
        if hdr is None:
            return None
        length, mtype = struct.unpack("!HB", hdr[16:19])
        body = self._recv_n(sock, length - 19) if length > 19 else b""
        if body is None:
            return None
        return mtype, body

    @staticmethod
    def _recv_n(sock, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    # ---- Main loop ----
    def _run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.local_ip, 0))   # source address = session peer address (FRR matches the neighbor by it)
            s.settimeout(5)
            s.connect((self.dut_ip, BGP_PORT))
            self._sock = s
            s.sendall(self._open_msg())
            got_open = False
            last_ka = 0
            ka_interval = max(self.hold_time // 3, 5)
            while not self._stop.is_set():
                now = time.time()
                if now - last_ka >= ka_interval:
                    try:
                        s.sendall(self._keepalive_msg())
                    except OSError:
                        break
                    last_ka = now
                msg = self._recv_msg(s)
                if msg is None:
                    break
                mtype, body = msg
                if mtype == OPEN:
                    got_open = True
                    s.sendall(self._keepalive_msg())
                elif mtype == KEEPALIVE:
                    if got_open and not self._established.is_set():
                        self._established.set()
                        self._send_all_announce(s)
                elif mtype == NOTIFICATION:
                    code, sub = (body[0], body[1]) if len(body) >= 2 else (0, 0)
                    self.last_error = f"NOTIFICATION code={code} sub={sub}"
                    break
        except Exception as e:  # noqa: BLE001
            self.last_error = repr(e)
        finally:
            self._established.clear()
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass

    def _send_all_announce(self, s):
        for prefix, nexthop in list(self.advertise):
            try:
                s.sendall(self._update_announce(prefix, nexthop))
            except OSError:
                pass

    # ---- Public API ----
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def wait_established(self, timeout=20):
        return self._established.wait(timeout)

    @property
    def established(self):
        return self._established.is_set()

    def announce(self, prefix, nexthop):
        with self._lock:
            self.advertise.append((prefix, nexthop))
            if self._sock and self._established.is_set():
                try:
                    self._sock.sendall(self._update_announce(prefix, nexthop))
                except OSError:
                    pass

    def withdraw(self, prefix):
        with self._lock:
            self.advertise = [(p, n) for (p, n) in self.advertise if p != prefix]
            if self._sock and self._established.is_set():
                try:
                    self._sock.sendall(self._update_withdraw(prefix))
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        if self._sock:
            for fn in (lambda: self._sock.shutdown(socket.SHUT_RDWR),
                       self._sock.close):
                try:
                    fn()
                except OSError:
                    pass
        if self._thread:
            self._thread.join(timeout=3)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


# ---------------------------------------------------------------------------
# --serve: cross-netns subprocess mode (stdin commands / stdout status line)
# ---------------------------------------------------------------------------
def _serve_main(argv):
    # argv: <dut_ip> <local_ip> <my_as> [adv "p,nh;p,nh"]
    dut_ip, local_ip, my_as = argv[0], argv[1], int(argv[2])
    advertise = []
    if len(argv) > 3 and argv[3]:
        for pair in argv[3].split(";"):
            if "," in pair:
                p, nh = pair.split(",", 1)
                advertise.append((p.strip(), nh.strip()))
    peer = PyBgpPeer(dut_ip, local_ip, my_as=my_as, advertise=advertise)
    peer.start()
    ok = peer.wait_established(25)
    sys.stdout.write(("ESTABLISHED" if ok else f"FAILED {peer.last_error}") + "\n")
    sys.stdout.flush()
    if not ok:
        peer.stop()
        return 1
    # Command loop
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        cmd = parts[0]
        if cmd == "quit":
            break
        elif cmd == "announce" and len(parts) >= 3:
            peer.announce(parts[1], parts[2])
            sys.stdout.write("OK\n"); sys.stdout.flush()
        elif cmd == "withdraw" and len(parts) >= 2:
            peer.withdraw(parts[1])
            sys.stdout.write("OK\n"); sys.stdout.flush()
        else:
            sys.stdout.write("ERR\n"); sys.stdout.flush()
    peer.stop()
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--serve":
        sys.exit(_serve_main(sys.argv[2:]))
    # Simple self-check
    d = sys.argv[1] if len(sys.argv) > 1 else "10.99.1.1"
    lo = sys.argv[2] if len(sys.argv) > 2 else "10.99.1.2"
    nh = sys.argv[3] if len(sys.argv) > 3 else "10.80.3.3"
    pr = PyBgpPeer(d, lo, my_as=65002, advertise=[("10.251.0.0/24", nh)])
    pr.start()
    print("ESTABLISHED" if pr.wait_established(25) else f"FAILED {pr.last_error}")
    time.sleep(10)
    pr.stop()
