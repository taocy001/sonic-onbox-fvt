"""Mock DHCP server: receives DISCOVER/REQUEST forwarded by the SONiC dhcp_relay, validates giaddr +
option-82 (relay agent info), and replies with OFFER/ACK.

Binds to the local server_ip:67 (server_ip is bound to a dummy interface via LocalPeerIP); the relay's unicast arrives through the kernel.
"""
import struct

from framework import log

from .base import ThreadServer

_log = log.get("dhcp")

MAGIC = b"\x63\x82\x53\x63"  # DHCP magic cookie


def _parse_options(data):
    """Return {code: bytes}. data starts right after the magic cookie."""
    opts, i = {}, 0
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        ln = data[i + 1]
        opts[code] = data[i + 2:i + 2 + ln]
        i += 2 + ln
    return opts


class MockDhcpServer(ThreadServer):
    def __init__(self, server_ip, offered_ip="10.99.1.100", port=67):
        super().__init__(bind_ip=server_ip, port=port)
        self.server_ip = server_ip
        self.offered_ip = offered_ip
        self.relayed = []        # records info from received relay packets (giaddr, option82, msgtype)

    def on_datagram(self, data, addr):
        if len(data) < 240 or data[236:240] != MAGIC:
            return None
        op = data[0]
        if op != 1:               # BOOTREQUEST
            return None
        xid = data[4:8]
        giaddr = ".".join(str(b) for b in data[24:28])
        chaddr = data[28:34]
        opts = _parse_options(data[240:])
        msgtype = opts.get(53, b"\x00")[0]
        opt82 = opts.get(82)
        info = {"giaddr": giaddr, "msgtype": msgtype,
                "option82": opt82.hex() if opt82 else None,
                "client_mac": chaddr.hex()}
        self.relayed.append(info)
        _log.info("relay packet: giaddr=%s msgtype=%d option82=%s",
                  giaddr, msgtype, info["option82"])
        # reply OFFER(2)/ACK(5) to the relay (giaddr:67)
        reply_type = 2 if msgtype == 1 else 5
        return self._build_reply(xid, chaddr, giaddr, reply_type)

    def _build_reply(self, xid, chaddr, giaddr, msgtype):
        pkt = bytearray(240)
        pkt[0] = 2                                   # BOOTREPLY
        pkt[1] = 1
        pkt[2] = 6
        pkt[4:8] = xid
        pkt[16:20] = bytes(int(x) for x in self.offered_ip.split("."))  # yiaddr
        pkt[24:28] = bytes(int(x) for x in giaddr.split("."))           # giaddr
        pkt[28:34] = chaddr
        pkt[236:240] = MAGIC
        pkt += bytes([53, 1, msgtype])               # option 53 msgtype
        pkt += bytes([54, 4]) + bytes(int(x) for x in self.server_ip.split("."))
        pkt += b"\xff"
        return bytes(pkt)
