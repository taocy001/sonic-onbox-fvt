"""Collector: capture encapsulated/sampled packets (sFlow datagrams, ERSPAN GRE, etc.).

- ERSPAN: mirror-encapsulated packets are produced by the chip and punted to the CPU via
  L3-to-local; capture them inbound on the corresponding netdev.
- sFlow: datagrams are produced by the **user-space hsflowd process on the CPU** and sent
  to a locally-reachable collector IP; the kernel always egresses locally-destined
  addresses via **lo** -- they never appear on a front-panel netdev, so they must be
  captured on lo with inbound=False (see SflowCollector docstring).
"""
import struct
import time

from framework import log

_log = log.get("collector")

try:
    from scapy.all import AsyncSniffer
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False
    AsyncSniffer = None


class PacketCollector:
    """Inbound packet collector (capture only, no send). The inbound filter excludes TX echo."""

    def __init__(self, iface, bpf, inbound=True):
        if inbound and bpf:
            bpf = f"inbound and ({bpf})"
        elif inbound:
            bpf = "inbound"
        self.iface, self.bpf = iface, bpf
        self._sn = None
        self.packets = []

    def start(self):
        if _SCAPY:
            self._sn = AsyncSniffer(iface=self.iface, filter=self.bpf, store=True)
            self._sn.start()
            time.sleep(0.4)
        return self

    def stop(self):
        if self._sn:
            time.sleep(0.3)
            self._sn.stop()
            self.packets = list(self._sn.results or [])
            self._sn = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


class SflowCollector(PacketCollector):
    """sFlow datagram capture + real v5-parsed counting (UDP dst 6343).

    Capture location (review fix): hsflowd sends datagrams to a locally-reachable collector
    IP (127.0.0.1 or a dummy-interface IP), and the kernel egresses locally-destined
    addresses via **lo** -- datagrams never appear on a front-panel netdev, so capture on lo
    by default; and it must be inbound=False: PacketCollector's "inbound and (...)" BPF
    prefix excludes locally-produced lo traffic, so with it enabled you capture nothing on lo.

    Counting semantics (review fix): sample_count() actually parses the sFlow v5 datagram
    and counts only flow sample (format 1/3) records -- counting UDP datagrams alone would
    be falsely satisfied by hsflowd's periodic counter samples (>0 even if sampling is fully
    dead), and a single datagram can batch multiple flow samples (undercounting breaks the
    rate window). When sig (probe smac/dmac etc.) is passed, it further requires that the
    original packet header embedded in the flow sample contains **all** signature bytes,
    pinning the evidence to the probe frames this test case injected.
    """

    def __init__(self, iface="lo", port=6343, sig=None):
        # filter by destination port only (hsflowd source port is random); reason for
        # inbound=False is in the class docstring
        super().__init__(iface, f"udp dst port {port}", inbound=False)
        self.sig = [bytes.fromhex(str(s).replace(":", "").replace("-", ""))
                    for s in (sig or [])]

    @property
    def datagrams(self):
        return self.packets

    @staticmethod
    def _udp_payload(pkt):
        try:
            from scapy.all import UDP
            if pkt.haslayer(UDP):
                return bytes(pkt[UDP].payload)
        except Exception:  # noqa: BLE001
            pass
        return None

    def _flow_samples(self, data):
        """Parse a single sFlow v5 datagram, returning the count of flow sample records
        that match the signature.

        v5 header: version(4) agent_addr_type(4) agent_addr(4/16) sub_agent(4) seq(4)
        uptime(4) nsamples(4), then each sample = type(4) len(4) body(len).
        The low 12 bits of the sample type are the format (enterprise=0 standard domain):
        1=flow sample, 2=counter sample, 3=expanded flow sample, 4=expanded counter sample.
        """
        if len(data) < 28:
            return 0
        try:
            if struct.unpack_from("!I", data, 0)[0] != 5:      # must be sFlow v5
                return 0
            off = 4
            atype = struct.unpack_from("!I", data, off)[0]
            off += 4 + (16 if atype == 2 else 4)               # agent address (v4=4B / v6=16B)
            off += 12                                          # sub-agent id + seq + uptime
            nsamples = struct.unpack_from("!I", data, off)[0]
            off += 4
            n = 0
            for _ in range(min(nsamples, 4096)):               # upper-bound guard: keep a bad header from blowing up the loop
                if off + 8 > len(data):
                    break
                stype, slen = struct.unpack_from("!II", data, off)
                off += 8
                body = data[off:off + slen]
                off += slen
                if (stype >> 12) == 0 and (stype & 0xFFF) in (1, 3):   # (expanded) flow sample
                    # the flow sample's raw-header record embeds the original frame (dmac+smac
                    # first); require all signature bytes present; an empty sig degrades to
                    # counting every flow sample
                    if all(s in body for s in self.sig):
                        n += 1
            return n
        except Exception:  # noqa: BLE001
            return 0

    def sample_count(self):
        """Total signature-matching flow samples across all captured datagrams (deduped by payload to guard against pcap duplicates)."""
        n, seen = 0, set()
        for p in self.packets:
            data = self._udp_payload(p)
            if not data or data in seen:
                # identical payloads can only be capture-layer duplicates: a real datagram's
                # seq increases monotonically and does not repeat
                continue
            seen.add(data)
            n += self._flow_samples(data)
        return n


class ErspanCollector(PacketCollector):
    """ERSPAN/GRE mirror capture (IP proto 47)."""

    def __init__(self, iface):
        super().__init__(iface, "proto gre")

    def inner_frames(self):
        """Extract the original mirrored Ethernet frames from the ERSPAN inner payload."""
        from scapy.all import Ether, GRE
        out = []
        for p in self.packets:
            if p.haslayer(GRE):
                payload = bytes(p[GRE].payload)
                # ERSPAN type II/III has an 8/12B shim; first try parsing directly as Ether
                for off in (0, 8, 12):
                    try:
                        inner = Ether(payload[off:])
                        if inner.haslayer(Ether) and inner.dst != "":
                            out.append(inner)
                            break
                    except Exception:  # noqa: BLE001
                        continue
        return out
