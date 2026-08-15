"""PFC / RoCEv2 packet construction and PFC counter reads.

- PFC pause frame (IEEE 802.1Qbb): a MAC control frame, dst 01:80:C2:00:00:01, ethertype
  0x8808, opcode 0x0101, 8-bit class-enable bitmap + 8 16-bit quanta. scapy has no built-in
  layer, so it is assembled with Raw.
  Purpose: inject on a loopback port -> chip MAC receives PFC -> the PFC RX counter for the
  corresponding priority increments (the port must first have `pfc priority on`). MAC control
  frames are consumed by the MAC layer and never enter the forwarding pipeline  this is a
  pure RX-side check.
- RoCEv2 packet: Eth/IP(DSCP)/UDP(dport 4791)/BTH(12B). Used for QoS classification
  (DSCP->TC->lossless queue) verification  only classification/enqueue is checked, no RDMA
  semantics.
- CNP: BTH opcode 0x81 + DSCP 48 (NVIDIA default), verifies enqueue on the CNP channel.

PFC counters: SAI_PORT_STAT_PFC_<n>_RX/TX_PKTS on the COUNTERS_DB port object (counterpoll
port default group).
"""
import struct

try:
    from scapy.all import IP, UDP, Ether, Raw  # noqa: F401
    HAVE_SCAPY = True
except Exception:  # noqa: BLE001  # build host has no scapy; don't blow up at collection time (repo convention)
    HAVE_SCAPY = False

from . import log

_log = log.get("pfcpkt")

PFC_DST = "01:80:c2:00:00:01"
PFC_ETHERTYPE = 0x8808
PFC_OPCODE = 0x0101
ROCE_UDP_DPORT = 4791
BTH_OPCODE_RC_SEND = 0x04      # RC SEND-only
BTH_OPCODE_CNP = 0x81          # CNP (FECN feedback)


def pfc_frame(priorities, quanta=0xFFFF, src="00:de:ad:0f:c0:01"):
    """Build a PFC pause frame. priorities=iterable[int 0..7]; quanta applies to each enabled priority.

    Frame body: opcode(2B) + class-enable-vector(2B, bit i = priority i) + 8×quanta(2B),
    padded with zeros; scapy/driver pads out to the 60B minimum frame. src defaults to a
    marked MAC to ease capture attribution.
    """
    vec = 0
    for p in priorities:
        vec |= (1 << int(p))
    body = struct.pack("!HH", PFC_OPCODE, vec)
    for i in range(8):
        body += struct.pack("!H", quanta if (vec >> i) & 1 else 0)
    body += b"\x00" * 28   # pad to 46B payload
    return Ether(dst=PFC_DST, src=src, type=PFC_ETHERTYPE) / Raw(body)


def _bth(opcode, dqpn=0x11, psn=0):
    """12B Base Transport Header: opcode(1) flags(1) pkey(2) resv(1) dqpn(3) ack/resv(1) psn(3)."""
    return struct.pack("!BBHB", opcode, 0, 0xFFFF, 0) + \
        dqpn.to_bytes(3, "big") + b"\x00" + psn.to_bytes(3, "big")


def rocev2_pkt(src_mac, dst_mac, src_ip, dst_ip, dscp=26, dqpn=0x11, payload=32):
    """RoCEv2 data packet (for classification/enqueue verification; ICRC is not computed  chip QoS classification does not check ICRC)."""
    return (Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, tos=dscp << 2)
            / UDP(sport=0xC0DE, dport=ROCE_UDP_DPORT)
            / Raw(_bth(BTH_OPCODE_RC_SEND, dqpn=dqpn) + b"\x5a" * payload))


def cnp_pkt(src_mac, dst_mac, src_ip, dst_ip, dscp=48, dqpn=0x11):
    """CNP packet (DSCP defaults to 48/CS6, NVIDIA DCQCN default). CNP has a fixed 16B payload."""
    return (Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, tos=dscp << 2)
            / UDP(sport=0xC0DE, dport=ROCE_UDP_DPORT)
            / Raw(_bth(BTH_OPCODE_CNP, dqpn=dqpn) + b"\x00" * 16))


def pfc_counters(cli, port):
    """Read the PFC RX/TX frame counters for a port's 8 priorities. Returns {"rx":[8],"tx":[8]};
    missing fields are recorded as -1 (when a platform does not collect them, tests should
    treat -1 as skip rather than misreading it as 0)."""
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port}")
    if not oid:
        return None
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    def grab(tpl):
        out = []
        for i in range(8):
            v = h.get(tpl.format(i))
            out.append(int(v) if v is not None and str(v).lstrip("-").isdigit() else -1)
        return out
    return {"rx": grab("SAI_PORT_STAT_PFC_{}_RX_PKTS"),
            "tx": grab("SAI_PORT_STAT_PFC_{}_TX_PKTS")}
