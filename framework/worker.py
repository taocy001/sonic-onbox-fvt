"""Parallel worker identity (Phase 3 traffic-lane split) -- the single, test-transparent source of truth.

The `FVT_WORKER` environment variable determines this pytest process's worker identity:
  unset (0) = single-process mode, **behavior is fully identical to the legacy serial path** (all
              worker-ization logic short-circuits);
  1         = worker 1, whose port/resource view matches single-process (default port block, Vlan1000,
              original subnets), with only the cleanup primitives narrowed to this group's ports
              (so it does not disturb worker 2);
  2..       = worker 2+, whose port block / default VLAN / subnet / VLAN id / naming are all offset
              per this module's rules.

Design rules:
- Test cases reference only topology roles (topo.port("a")/subnet("c")/route("a")...); all worker
  differences are absorbed in the framework resolution layer -- **no test case may import this module**.
- Offset rules are centralized here (rather than scattered as +100 all over), guaranteeing the two
  workers' resource sets can be statically audited as disjoint.
- Worker 1 has no offset: the only behavioral difference between single-process mode and worker 1 is
  the "cleanup scope", which halves the verification surface.
"""
import os

from . import log

_log = log.get("worker")


def wid():
    """The current worker number; 0 = single-process (non-parallel) mode."""
    try:
        return int(os.environ.get("FVT_WORKER", "0"))
    except ValueError:
        return 0


def is_parallel():
    return wid() > 0


def suffix():
    """Naming suffix (netns/veth/artifact files, etc.): empty string for single-process and w1, "-w<N>" for w2+."""
    return f"-w{wid()}" if wid() >= 2 else ""


# ---- resource-view offsets (only take effect for wid>=2; values are statically audited disjoint from the w1 resource set) ----

def remap_vid(v):
    """VLAN id offset. w1/single-process unchanged; w2: regular vid +430, high-range isolation vid (>=3900) -10/worker.

    Audit (w1 occupied set = {110,120,320-325,360,361,1000,2000,3990-3993}):
    w2 => hairpin 540/550, roles 750-755, mcast 790, erspan 791, default 1430 (see default_vlan),
    test 2430, isolation 3980-3983 -- fully disjoint from the w1 set, and all <4094."""
    w = wid()
    if w <= 1:
        return v
    if v >= 3900:
        return v - 10 * (w - 1)
    return v + 430 * (w - 1)


def remap_default_vlan(dv):
    """Worker-private flood domain: if two bare loopback ports across processes share a VLAN, any kernel noise multicast becomes a perpetual storm.
    w2+ moves its role ports wholesale into a private VLAN (the conftest session baseline handles create/move/restore)."""
    return dv if wid() <= 1 else dv + 430 * (wid() - 1)


def remap_ip4(ip):
    """IPv4 second-octet offset (+100, or -100 on overflow): 10.80.x->10.180.x, 10.251.x->10.151.x.
    Prevents two workers from colliding by building same-subnet RIFs/routes at once.

    **Only offsets the test-owned 10.x space** -- special addresses like 0.0.0.0/0 (default route),
    198.51.100.x (TEST-NET probes), and 127/224/255 are left unchanged (once offset 0.0.0.0/0 into
    0.100.0.0/0 and it got rejected)."""
    if wid() <= 1 or not ip or ":" in str(ip):
        return ip
    parts = str(ip).split(".")
    if len(parts) != 4 or parts[0] != "10":
        return ip
    o2 = int(parts[1]) + 100 * (wid() - 1)
    if o2 > 255:
        o2 = int(parts[1]) - 100 * (wid() - 1)
    return ".".join([parts[0], str(o2), parts[2], parts[3]])


def remap_ip6(ip):
    """IPv6 third hextet +0x100: 2001:db8:83:: -> 2001:db8:183::.
    Only offsets the test-owned 2001:db8 documentation-prefix space (special addresses like ::/0 and fe80 are left unchanged)."""
    if wid() <= 1 or not ip or ":" not in str(ip):
        return ip
    s = str(ip)
    if not s.lower().startswith("2001:db8:"):
        return ip
    parts = s.split(":")
    if len(parts) < 3 or not parts[2]:
        return ip
    try:
        parts[2] = format(int(parts[2], 16) + 0x100 * (wid() - 1), "x")
    except ValueError:
        return ip
    return ":".join(parts)


def remap_cidr(cidr):
    """Offset an address in prefixed form ("10.80.1.1/24" / "2001:db8:83::1/64")."""
    if wid() <= 1 or not cidr:
        return cidr
    s = str(cidr)
    if "/" in s:
        addr, plen = s.rsplit("/", 1)
        return f"{remap_ip6(addr) if ':' in addr else remap_ip4(addr)}/{plen}"
    return remap_ip6(s) if ":" in s else remap_ip4(s)


def remap_asn(asn):
    """BGP AS number offset (+10/worker), to prevent the two workers' FRR instances / peer ASes from colliding."""
    try:
        return int(asn) + 10 * (wid() - 1) if wid() >= 2 else asn
    except (TypeError, ValueError):
        return asn
