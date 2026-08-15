"""Verification helpers: DB/ASIC/STATE assertions + packet matching.

- AsicDb: proves chip table entries were programmed (after CLI issues config, the
  corresponding SAI object appears in ASIC_DB)
- StateDb / ApplDb: intermediate states in the programming chain
- Packet matchers: common rewrite checks (VLAN tag / TTL / DSCP / MAC)
"""
import time

from . import log

_log = log.get("verify")


class DbView:
    def __init__(self, cli, db):
        self.cli, self.db = cli, db

    def keys(self, pattern):
        return self.cli.db_keys(self.db, pattern)

    def exists(self, pattern, timeout=5.0, interval=0.3):
        """Poll until a key matching pattern appears."""
        end = time.time() + timeout
        while time.time() < end:
            if self.keys(pattern):
                return True
            time.sleep(interval)
        return False

    def count(self, pattern):
        return len(self.keys(pattern))

    def wait_count_gt(self, pattern, base, timeout=8.0, interval=0.4):
        """Poll until the match count > base (waiting for orch's async programming). Returns whether it was reached."""
        end = time.time() + timeout
        while time.time() < end:
            if self.count(pattern) > base:
                return True
            time.sleep(interval)
        return False

    def field(self, key, field):
        return self.cli.db_hgetall(self.db, key).get(field)


class AsicDb(DbView):
    """ASIC_DB view: a SAI object = ASIC_STATE:<SAI_OBJECT_TYPE_*>:oid."""

    def __init__(self, cli):
        super().__init__(cli, "ASIC_DB")

    def objects(self, sai_type):
        return self.keys(f"ASIC_STATE:{sai_type}:*")

    def has(self, sai_type, timeout=5.0):
        return self.exists(f"ASIC_STATE:{sai_type}:*", timeout=timeout)

    def has_route(self, prefix, timeout=10.0, interval=0.5):
        """Poll ASIC_DB for a ROUTE_ENTRY containing the given prefix."""
        import time as _t
        end = _t.time() + timeout
        while _t.time() < end:
            for k in self.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY"):
                if prefix in k:
                    return True
            _t.sleep(interval)
        return False

    def route_is_forwarding(self, prefix, timeout=10.0, interval=0.5):
        """Poll whether this prefix's ROUTE_ENTRY carries **forwarding intent** (not DROP and non-empty next hop).

        Existence (has_route) is an always-true trap for 0.0.0.0/0: at startup SONiC creates
        a DROP fallback default-route entry for every VR  looking only at existence would
        misjudge "orchagent never programmed forwarding intent" (fpmsyncd by design drops
        eth0 next-hop routes) as a chip forwarding defect."""
        import time as _t
        end = _t.time() + timeout
        while _t.time() < end:
            for k in self.objects("SAI_OBJECT_TYPE_ROUTE_ENTRY"):
                if prefix not in k:
                    continue
                attrs = self.cli.db_hgetall("ASIC_DB", k) or {}
                action = attrs.get("SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION", "")
                nh = attrs.get("SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID", "oid:0x0")
                if "DROP" not in action and nh not in ("", "oid:0x0"):
                    return True
            _t.sleep(interval)
        return False

    def find(self, sai_type, **match):
        """Return the list of SAI object keys whose attributes satisfy match."""
        out = []
        for k in self.objects(sai_type):
            attrs = self.cli.db_hgetall("ASIC_DB", k)
            if all(str(attrs.get(f)) == str(v) for f, v in match.items()):
                out.append(k)
        return out

    def hostif_trap_groups(self, exclude_default=True):
        """Return the list of HOSTIF_TRAP_GROUP keys.

        With exclude_default=True, filter out the SAI **default** trap-group (a pre-built
        group with neither QUEUE nor POLICER attribute, e.g. oid:0x11...002a). This default
        group is legitimate but binds no queue/policer (no rate limiting), and should not
        count toward the assertion "every CoPP group must have a complete policer / queue"
        (a legitimate device-level difference).
        """
        groups = self.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP")
        if not exclude_default:
            return groups
        out = []
        for g in groups:
            attrs = self.cli.db_hgetall("ASIC_DB", g)
            q = attrs.get("SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE")
            pol = attrs.get("SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER")
            # SAI default group: both queue and policer absent -> skip (not a user-configured CoPP rate-limit group)
            if (q is None or q == "") and (not pol or pol == "oid:0x0"):
                continue
            out.append(g)
        return out


# ---- Packet matchers (used with traffic.Capture.match) ----
def has_vlan(vid):
    def f(p):
        from scapy.all import Dot1Q
        return p.haslayer(Dot1Q) and p[Dot1Q].vlan == vid
    return f


def no_vlan():
    def f(p):
        from scapy.all import Dot1Q
        return not p.haslayer(Dot1Q)
    return f


def ttl_is(v):
    def f(p):
        from scapy.all import IP
        return p.haslayer(IP) and p[IP].ttl == v
    return f


def dscp_is(v):
    def f(p):
        from scapy.all import IP
        return p.haslayer(IP) and (p[IP].tos >> 2) == v
    return f


def dst_mac_is(mac):
    def f(p):
        from scapy.all import Ether
        return p.haslayer(Ether) and p[Ether].dst.lower() == mac.lower()
    return f


def payload_has(magic):
    def f(p):
        return magic in bytes(p)
    return f
