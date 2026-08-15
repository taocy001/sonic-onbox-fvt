"""Port counter reads and deltas.

Two sources:
- ChipCounters: bcmcmd 'show c <bcm>' -- **instant, accurate, immune to netdev TX
  echo**, the preferred choice for traffic verification (loopback re-injection bumps
  RX_PKT/MIB_RPKT by exactly +N).
- PortCounters: COUNTERS_DB(SAI), cross-platform, but flex counter polls at ~1s and lags.

WARNING: do not use "same-port scapy capture" to prove forwarding: AF_PACKET captures
   the host's own outbound frames back as TX echo, and whether it does depends on the
   port link state, causing false positives.
"""
import re
from dataclasses import dataclass

from . import log

_log = log.get("counters")


@dataclass
class ChipCounters:
    """Vendor-X per-port chip counters (bcmcmd show c)."""
    rx_pkt: int = 0       # MIB_RPKT: frames received on this port (incl. loopback re-injection)
    tx_pkt: int = 0       # MIB_TPKT: frames sent on this port
    rx_ipv4: int = 0
    rx_byt: int = 0

    def __sub__(self, o):
        return ChipCounters(self.rx_pkt - o.rx_pkt, self.tx_pkt - o.tx_pkt,
                            self.rx_ipv4 - o.rx_ipv4, self.rx_byt - o.rx_byt)

    @classmethod
    def read(cls, bcm_shell, bcm_port):
        out = bcm_shell.cmd(f"show c {bcm_port}")
        def grab(metric):
            m = re.search(rf"{metric}\.{re.escape(bcm_port)}\b[^:]*:\s*([\d,]+)", out)
            return int(m.group(1).replace(",", "")) if m else 0
        # Counter names differ across platforms: MIB_RPKT/TPKT or CLMIB_RPKT/TPKT
        return cls(rx_pkt=grab("MIB_RPKT") or grab("CLMIB_RPKT") or grab("RX_PKT"),
                   tx_pkt=grab("MIB_TPKT") or grab("CLMIB_TPKT") or grab("TX_PKT"),
                   rx_ipv4=grab("RX_PKT_IPV4"),
                   rx_byt=grab("RX_BYT"))

    @staticmethod
    def clear(bcm_shell):
        # In parallel mode clear only this worker's port block (range syntax): a global
        # `clear c` would wipe the counter baseline another worker is measuring. In
        # non-parallel mode worker_pbm=None, preserving global semantics.
        pbm = getattr(bcm_shell, "worker_pbm", None)
        bcm_shell.cmd(f"clear c {pbm}" if pbm else "clear c")

# ---- Queue / PG / buffer-pool level counters (unified wrapper; previously 3 test files each had a private helper) ----

def _name_map(cli, map_name):
    out = cli.db("COUNTERS_DB", f"HGETALL {map_name}")
    try:
        import ast
        d = ast.literal_eval(out) if out and out.strip().startswith("{") else {}
        return d if isinstance(d, dict) else {}
    except (ValueError, SyntaxError):
        return {}


def queue_stats(cli, port, fields=("SAI_QUEUE_STAT_PACKETS",)):
    """Read per-queue counters. Returns {qidx: {field: int}} (COUNTERS_QUEUE_NAME_MAP
    keys look like "Ethernet0:5"). Missing fields are omitted (the test decides, we do
    not mask it here)."""
    m = _name_map(cli, "COUNTERS_QUEUE_NAME_MAP")
    out = {}
    for k, oid in m.items():
        p, _, q = k.partition(":")
        if p != port or not q.isdigit():
            continue
        h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
        row = {f: int(h[f]) for f in fields if f in h and str(h[f]).lstrip("-").isdigit()}
        out[int(q)] = row
    return out


def pg_stats(cli, port, fields=("SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES",
                               "SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES")):
    """Read per-PG watermarks. Returns {pg: {field: int}}."""
    m = _name_map(cli, "COUNTERS_PG_NAME_MAP")
    out = {}
    for k, oid in m.items():
        p, _, pg = k.partition(":")
        if p != port or not pg.isdigit():
            continue
        h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
        out[int(pg)] = {f: int(h[f]) for f in fields
                        if f in h and str(h[f]).lstrip("-").isdigit()}
    return out


def buffer_pool_stats(cli):
    """Buffer pool watermarks. Returns {pool_name: {field: int}}; returns {} when the
    pool is not instantiated (surfaced honestly)."""
    m = _name_map(cli, "COUNTERS_BUFFER_POOL_NAME_MAP")
    out = {}
    for name, oid in m.items():
        h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
        out[name] = {f: int(v) for f, v in h.items()
                     if str(v).lstrip("-").isdigit()}
    return out


_FIELDS = {
    "tx_ucast": "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
    "rx_ucast": "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
    "tx_all": "SAI_PORT_STAT_IF_OUT_PKTS",
    "rx_all": "SAI_PORT_STAT_IF_IN_PKTS",
    "tx_drop": "SAI_PORT_STAT_IF_OUT_DISCARDS",
    "rx_drop": "SAI_PORT_STAT_IF_IN_DISCARDS",
}


@dataclass
class PortCounters:
    tx_ucast: int = 0
    rx_ucast: int = 0
    tx_all: int = 0
    rx_all: int = 0
    tx_drop: int = 0
    rx_drop: int = 0

    def __sub__(self, o):
        return PortCounters(**{k: getattr(self, k) - getattr(o, k) for k in _FIELDS})

    @classmethod
    def read(cls, cli, port):
        oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port.name}")
        if not oid:
            _log.warning("no COUNTERS oid for %s (dry-run?)", port.name)
            return cls()
        h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
        vals = {k: int(h.get(sai, 0)) for k, sai in _FIELDS.items()}
        # Some images' flex counter does not collect the IF_IN/OUT_PKTS (total) fields,
        # only UCAST/NON_UCAST -- when totals are missing, synthesize from the two to
        # avoid rx_all/tx_all being stuck at 0 and failing falsely.
        def _i(f):
            v = h.get(f)
            return int(v) if v is not None and str(v).isdigit() else 0
        if "SAI_PORT_STAT_IF_IN_PKTS" not in h:
            vals["rx_all"] = _i("SAI_PORT_STAT_IF_IN_UCAST_PKTS") + _i("SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS")
        if "SAI_PORT_STAT_IF_OUT_PKTS" not in h:
            vals["tx_all"] = _i("SAI_PORT_STAT_IF_OUT_UCAST_PKTS") + _i("SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS")
        return cls(**vals)
