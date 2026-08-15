"""Malformed-packet drop test suite -- adapted from sonic-mgmt tests/drop_packets/.

Mechanism: the traffic fixture configures ports[0] as an untagged L2 member of the
default VLAN with MAC loopback enabled. The CPU injects malformed packets via scapy
-> they egress physically out ports[0] -> MAC loopback -> re-enter the pipeline as
ingress. **The drop is performed by the chip's built-in pipeline logic**
(SMAC==DMAC / bad IP header / TTL=0 ... etc.), not by a user ACL.
Inject N malformed packets -> the corresponding drop counter increases by ~N (with tolerance).

Three validation paths (chosen per drop type):
  - L2 ingress drop -> RX_DRP from `portstat -j` (port ingress drops, cross-platform CLI counter);
  - DEBUG_COUNTER   -> `config dropcounters install <name> PORT_INGRESS_DROPS <reason>` +
                       the per-counter column of `show dropcounters counts` (precise attribution
                       by drop reason, works for both L2/L3, and is the primary method of this suite);
  - L3 RIF drop     -> RX_ERR from `intfstat -j` (requires the ingress port to have a RIF; this
                       framework's traffic uses an L2 port with no RIF, so intfstat returns empty
                       -> such cases uniformly switch to DEBUG_COUNTER or skip with a reason).

The PORT_INGRESS_DROPS reasons supported by the device are probed at runtime via
`show dropcounters capabilities`, typically including: FDB_AND_BLACKHOLE_DISCARDS,
IP_HEADER_ERROR, SMAC_MULTICAST, EXCEEDS_L3_MTU, TTL, ACL_ANY, SMAC_EQUALS_DMAC.
Malformed classes with no corresponding reason (multicast/broadcast DMAC, loopback/multicast/
zero/class-E/link-local IP, etc.): they have neither a DEBUG_COUNTER reason nor a RIF on the
traffic port (intfstat empty), so pytest.skip with a reason -- never assert True.

Print/assert/skip in English; comments/docstrings in Chinese. Ports/VLANs come from topo,
not hardcoded.
"""
import contextlib
import json
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.trap]

# Number of malformed packets injected per case. Tolerance: the chip's built-in drop should
# be exactly +N, but the loopback path / background traffic / counter polling introduce jitter,
# so the lower bound is half of N to conclude "the counter did increase because of the injection".
PKT_NUMBER = 100
DROP_LOWER = PKT_NUMBER * 0.5
# Storm/misattribution guard (consistent with test_counters_chip): after per-port attribution the
# port's drop counter should still be approximately the injected amount; runaway growth indicates
# a storm or counter misattribution -- an unbounded "increase == pass" would still PASS (a false pass)
# under a storm.
_STORM_GUARD = 3000

# DEBUG_COUNTER install wait and counter polling (flex counter poll defaults to ~1s, dropcounters
# go through syncd programming).
_PROGRAM_WAIT = 30      # wait for install -> the COUNTERS_DB name->oid mapping to appear
_COUNT_POLL = 20        # after injection, poll `show dropcounters counts` and read the per-counter column


@pytest.fixture
def drop_port(_lb, topo):
    """Dedicated loopback port for malformed-packet injection (independent of the traffic fixture's
    forward/smoke/PVID machinery -- cleaner and more reproducible).
    A drop test only needs one MAC loopback port so CPU-injected malformed frames re-enter the
    pipeline and trigger the chip's built-in drop; no forwarding topology is required."""
    p = topo.misc_port(0)
    _lb.enable(p)
    yield p
    _lb.disable(p)


def _send(port, pkt, count):
    """CPU scapy injection to the given port (then re-enters the pipeline via its MAC loopback)."""
    from scapy.all import sendp
    sendp(pkt, iface=port.name, count=count, verbose=False)


# Injection source MAC (different from the smoke/queue cases to avoid FDB cross-talk). The dst
# does not need to be actually reachable: malformed packets are dropped at the chip's ingress
# stage and never reach forwarding/flooding.
_SRC_MAC = "00:de:ad:be:ef:41"


# ============================ DEBUG_COUNTER primary method ============================
def _supported_reasons(cli):
    """Read `show dropcounters capabilities`, return the set of reasons supported for PORT_INGRESS_DROPS.

    capabilities output looks like:
        PORT_INGRESS_DROPS
                SMAC_EQUALS_DMAC
                IP_HEADER_ERROR
                ...
    Take the indented reason names of the last block. If unreadable, return an empty set
    (the caller skips accordingly).
    """
    out = cli.run("show dropcounters capabilities").out
    reasons = set()
    in_block = False
    for line in out.splitlines():
        if "PORT_INGRESS_DROPS" in line and not line.startswith((" ", "\t")):
            in_block = True
            continue
        if in_block:
            tok = line.strip()
            # A reason line is a single all-uppercase underscore token (e.g. SMAC_EQUALS_DMAC)
            if tok and tok.replace("_", "").isalnum() and tok.upper() == tok and " " not in tok:
                reasons.add(tok)
            elif tok and not tok[0].isspace():
                # left the indented block
                pass
    return reasons


def _counts_for(cli, name, iface=None):
    """Read the debug-counter count named <name> from `show dropcounters counts`.

    The counts header looks like:  IFACE STATE <NAME> [<NAME2> ...], one column per installed counter.
    When iface is given, take only that port's row (per-port precise attribution: background drops on
    unrelated ports / same-reason injections on parallel lanes are not charged to this case, and it is
    parallel-lane safe); otherwise sum across ports (compatible with legacy calls).
    Return None if the column/port row is absent (counter not ready).
    """
    r = cli.run("show dropcounters counts")
    rows = cli.parse_table(r.out)
    if not rows or name not in (rows[0].keys() if rows else []):
        return None
    total = 0
    seen = False
    for row in rows:
        if iface is not None and row.get("IFACE") != iface:
            continue
        v = row.get(name, "")
        if v.lstrip("-").isdigit():
            total += int(v)
            seen = True
    return total if seen else None


def _install_drop_counter(cli, config_guard, name, reason):
    """Install a PORT_INGRESS_DROPS DEBUG_COUNTER and wait for it to be programmed into COUNTERS_DB.

    Return True when ready to read; otherwise pytest.skip (insufficient permission / image unsupported /
    programming incomplete -- never a false pass). Rollback is delegated to config_guard.
    """
    rc, r = cli.config_raw(
        f"dropcounters install {name} PORT_INGRESS_DROPS {reason} -d 'dut-test drop'")
    out = (r.out + r.err)
    if rc != 0:
        if "root" in out.lower() or "permission" in out.lower():
            pytest.skip(f"dropcounters install needs root in this run: {out.strip()[:120]}")
        pytest.skip(f"dropcounters install unsupported/failed: {out.strip()[:120]}")
    config_guard.defer_undo(f"dropcounters delete {name}")

    # wait for the name->oid mapping to appear (proves it is programmed to syncd/ASIC collection)
    for _ in range(_PROGRAM_WAIT * 2):
        m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_DEBUG_NAME_PORT_STAT_MAP")
        if m.get(name):
            return True
        time.sleep(0.5)
    pytest.skip(f"debug counter {name} installed but not in COUNTERS_DEBUG_NAME_PORT_STAT_MAP "
                "(syncd programming/poll pending on this image)")


def _run_debug_counter_case(cli, port, config_guard, reason, pkt_builder, name="DROPTEST"):
    """DEBUG_COUNTER closed-loop validation template: install the reason counter -> inject N
    malformed packets -> verify that counter increases by ~N.

    reason not in the device capabilities -> skip (platform variance, never assert True).
    """
    supported = _supported_reasons(cli)
    if not supported:
        pytest.skip("show dropcounters capabilities reported no PORT_INGRESS_DROPS reasons "
                    "(debug counter unsupported on this image)")
    if reason not in supported:
        pytest.skip(f"drop reason {reason} not supported on this platform "
                    f"(supported: {sorted(supported)})")

    if not _install_drop_counter(cli, config_guard, name, reason):
        return  # _install_drop_counter already skipped

    p_in = port
    pkt = pkt_builder()

    # base must be taken only after it is **stable**: a same-named counter's "delete old + install new"
    # is asynchronous, so a read in the short window after install may still be the old counter's
    # residual value (base=old value -> new counter zeroed -> false-negative delta). Two consecutive
    # equal reads are considered stable.
    # per-port attribution: read only the injection port's row; background drops on unrelated ports /
    # parallel lanes are not counted toward this case.
    base = None
    prev = object()
    for _ in range(10):
        cur = _counts_for(cli, name, p_in.name)
        if cur is not None and cur == prev:
            base = cur
            break
        prev = cur
        time.sleep(1)
    if base is None:
        pytest.skip(f"debug counter {name} column/row absent or unstable in 'show dropcounters "
                    f"counts' for {p_in.name} (counter not yet populated)")
    _send(p_in, pkt, PKT_NUMBER)

    delta = 0
    for _ in range(_COUNT_POLL):
        time.sleep(1)
        cur = _counts_for(cli, name, p_in.name)
        if cur is None:
            continue
        delta = cur - base
        if delta >= PKT_NUMBER:    # wait for full attribution (not stopping at half) so the upper-bound check has an observation window
            break
    # confirming read: normally the counter has settled; a storm/misattribution still growing breaks the upper bound -> honest failure
    time.sleep(1)
    cur = _counts_for(cli, name, p_in.name)
    if cur is not None:
        delta = cur - base
    if delta >= DROP_LOWER:
        # two-sided bounds: this port's reason counter did increase due to injection, and there is no runaway growth (per-port storm guard)
        assert delta < PKT_NUMBER + _STORM_GUARD, (
            f"drop counter {name} on {p_in.name} exploded: +{delta} after only {PKT_NUMBER} "
            f"injected (storm or counter misattribution)")
        return   # pass: the chip did drop this malformed class and attributed it by reason to the injection port
    # reason is supported by the device but the chip does not drop this class by default (delta did not grow) -> FAIL to expose.
    pytest.fail(f"device does not drop {reason} frames by default "
                f"(debug counter {name} installed but delta={delta} after {PKT_NUMBER} injected "
                f"on {p_in.name})")


# ============================ portstat RX_DRP / RX_ERR method ============================
def _portstat(cli, port_name):
    """Read the field dict of a port from `portstat -j` (RX_DRP/RX_ERR etc., comma-thousands strings)."""
    out = cli.run("portstat -j").out
    try:
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return None
    return data.get(port_name)


def _portstat_int(stat, field):
    v = (stat or {}).get(field, "")
    v = str(v).replace(",", "").strip()
    return int(v) if v.lstrip("-").isdigit() else None


def _run_portstat_case(cli, port, field, pkt_builder):
    """portstat closed loop: clear counters -> inject N malformed packets -> verify ports[0]'s
    <field> (RX_DRP/RX_ERR) increases by ~N.

    portstat unparseable / field unreadable -> skip.
    """
    p_in = port
    cli.run("sonic-clear counters")
    time.sleep(2)

    base_stat = _portstat(cli, p_in.name)
    base = _portstat_int(base_stat, field)
    if base is None:
        pytest.skip(f"portstat {field} not readable for {p_in.name} (counter not ready)")

    pkt = pkt_builder()
    _send(p_in, pkt, PKT_NUMBER)

    delta = 0
    for _ in range(15):
        time.sleep(1)
        cur = _portstat_int(_portstat(cli, p_in.name), field)
        if cur is None:
            continue
        delta = cur - base
        if delta >= PKT_NUMBER:    # wait for the full amount (not stopping at half) so the upper-bound check has an observation window
            break
    # confirming read: normally the counter has settled; a storm still growing breaks the upper bound -> honest failure
    time.sleep(1)
    cur = _portstat_int(_portstat(cli, p_in.name), field)
    if cur is not None:
        delta = cur - base
    if delta >= DROP_LOWER:
        # two-sided bounds: portstat is already a per-port reading; the upper bound catches runaway growth from a storm/misattribution
        assert delta < PKT_NUMBER + _STORM_GUARD, (
            f"portstat {field} on {p_in.name} exploded: +{delta} after only {PKT_NUMBER} "
            f"injected (storm or counter misattribution)")
        return   # pass: the chip did drop this class of frame and counted it in portstat
    # the chip does not drop this class of frame into portstat <field> by default -> FAIL to expose.
    pytest.fail(f"device does not drop these frames into {field} by default "
                f"(delta={delta} after {PKT_NUMBER} injected on {p_in.name})")


# ============================ malformed-packet builders (scapy, guarded lazy import) ============================
def _eth_ip_tcp(eth_dst, eth_src, ip_src, ip_dst, **ipkw):
    """Simple Ether/IP/TCP malformed-packet base (corresponds to sonic-mgmt simple_tcp_packet)."""
    from scapy.all import Ether, IP, TCP, Raw
    return (Ether(dst=eth_dst, src=eth_src) /
            IP(src=ip_src, dst=ip_dst, **ipkw) /
            TCP(sport=1234, dport=4321) / Raw(b"x" * 40))


# ---- Class [A]: inject packets -> counter closed loop ----

# [1] SMAC==DMAC (merged into the authoritative case, removed from this file): the same scenario
# has three copies, and this one was the weakest (>=0.5N with no upper bound). Behavioral authority =
# test_counters_chip.test_drop_reason_counter_exact (strict lower bound ==N + noise upper bound);
# programming chain (CONFIG_DB + COUNTERS_DEBUG_NAME_PORT_STAT_MAP) =
# test_stats_full.test_debug_drop_counter_install_and_program. This file keeps the reasons not covered
# by the authoritative case: SMAC_MULTICAST / bad-VLAN RX_DRP / IP_HEADER_ERROR / TTL / EXCEEDS_L3_MTU.

@pytest.mark.traffic
def test_multicast_smac_drop(cli, drop_port, config_guard):
    """[2] Multicast SMAC: a frame whose source MAC is a multicast address (01:00:5e:..) should be
    dropped at L2. DEBUG_COUNTER reason=SMAC_MULTICAST (device-supported)."""
    _run_debug_counter_case(
        cli, drop_port, config_guard, "SMAC_MULTICAST",
        lambda: _eth_ip_tcp("00:aa:bb:cc:dd:52", "01:00:5e:00:01:02", "1.1.1.1", "2.2.2.2"),
        name="DROP_MCSMAC")


@pytest.mark.traffic
def test_not_expected_vlan_tag_drop(cli, drop_port):
    """[3] Tagged frame with an unconfigured VID: an 802.1Q tagged frame carrying an unconfigured
    VLAN ID should be dropped at ingress (RX_DRP). No corresponding DEBUG_COUNTER reason, so verify
    with portstat RX_DRP.

    Pick a definitely-unconfigured VID (a high VID outside the topo test VLAN pool) and inject a
    tagged frame from ports[0]."""
    def _build():
        from scapy.all import Ether, Dot1Q, IP, TCP, Raw
        bad_vid = 3001  # outside the topo VLAN pool (320..361) and default_vlan (1000), definitely unconfigured
        return (Ether(dst="00:aa:bb:cc:dd:53", src=_SRC_MAC) /
                Dot1Q(vlan=bad_vid) / IP(src="1.1.1.1", dst="2.2.2.2") /
                TCP(sport=1234, dport=4321) / Raw(b"x" * 40))
    _run_portstat_case(cli, drop_port, "RX_DRP", _build)


@pytest.mark.traffic
def test_broken_ip_header_version(cli, config_guard, topo, l3up):
    """[10a] Bad IP header version=1: an illegal IP version field should be dropped at **L3**
    (IP_HEADER_ERROR).

    IP header validation happens only when the chip attempts to **route** the packet -- the L2
    switching path does not parse the IP header (a malformed IP frame with an ordinary unicast DMAC
    is L2-forwarded as usual, never entering IP_HEADER_ERROR, and delta=0 is due to the L2 context).
    So use the _l3_routed pattern: outer DMAC=router MAC to make the packet enter the L3 pipeline,
    then verify the drop."""
    topo.caps.require("loopback")
    with _l3_routed(cli, topo, l3up) as (p_in, _p_out, rmac, dst_ip):
        _run_debug_counter_case(
            cli, p_in, config_guard, "IP_HEADER_ERROR",
            lambda: _eth_ip_tcp(rmac, _SRC_MAC, topo.subnet("c")["peer"], dst_ip, version=1),
            name="DROP_IPVER")


@pytest.mark.traffic
def test_broken_ip_header_ihl(cli, config_guard, topo, l3up):
    """[10c] Bad IP header ihl=1: an illegal IP header-length field should be dropped at **L3**
    (IP_HEADER_ERROR). Same context as test_broken_ip_header_version: must go through the L3 routing
    path (DMAC=router MAC)."""
    topo.caps.require("loopback")
    with _l3_routed(cli, topo, l3up) as (p_in, _p_out, rmac, dst_ip):
        _run_debug_counter_case(
            cli, p_in, config_guard, "IP_HEADER_ERROR",
            lambda: _eth_ip_tcp(rmac, _SRC_MAC, topo.subnet("c")["peer"], dst_ip, ihl=1),
            name="DROP_IPIHL")


# ============ [B] L3 routing-path drops: TTL expired / exceeds egress MTU (using the L3-RIF pattern) ============
# TTL-expired / exceeds-L3-MTU drops occur only on the **L3 routing path** (the chip decrements TTL and
# checks the egress MTU only when doing IP forwarding), and can never be triggered on an L2 port (no RIF).
# So these two cases follow the L3-RIF loopback traffic pattern of test_l3_forward_traffic.py:
#   p_in and p_out both get an L3 IP + MAC loopback enabled (have a RIF); add a static route to a
#   "remote destination subnet" (via a static neighbor); inject a packet with "outer DMAC=DUT router MAC,
#   dst IP=the routed remote dst" -> re-enter via p_in loopback -> the chip forwards by route.
# During forwarding: TTL=1 -> decremented to 0 -> TTL_ERROR drop; or the whole frame exceeds the egress
# MTU -> EXCEEDS_L3_MTU drop.
# Use the same DEBUG_COUNTER template (_run_debug_counter_case) to assert the corresponding reason
# (TTL / EXCEEDS_L3_MTU) counter really increases.
# If, once the L3 path is set up correctly, it still does not drop/count -> a real device defect,
# exposed by the template's pytest.fail.

_NH_MAC = "00:11:22:33:44:aa"   # remote neighbor (next-hop) MAC -- an arbitrary static test value (as in l3_forward)


def _wait_route(cli, dst_net, tries=20):
    """Wait for the static route to be programmed into the kernel (FRR/zebra), as in test_l3_forward_traffic."""
    for _ in range(tries):
        if dst_net.split("/")[0] in cli.sh.run(f"ip route show {dst_net}", check=False).out:
            return True
        time.sleep(0.5)
    return False


@contextlib.contextmanager
def _l3_routed(cli, topo, l3up):
    """Set up the L3-RIF routing path (following the test_l3_forward_traffic pattern) and clean up on exit.

    p_in/p_out each get an L3 IP + loopback enabled (l3up factory, have a RIF); add a static route to the
    remote subnet route("a") (via a static neighbor within the p_out subnet). yield (p_in, p_out, rmac, dst_ip):
    injection port, egress port, DUT router MAC, the routed remote destination IP. Route not programmed to
    the kernel -> pytest.fail (real device defect, cannot drive the L3 drop path).
    """
    sub_in, sub_out = topo.subnet("c"), topo.subnet("d")
    p_in = l3up(topo.l3_port(0).name, f"{sub_in['dut']}/{sub_in['prefix']}")
    p_out = l3up(topo.l3_port(1).name, f"{sub_out['dut']}/{sub_out['prefix']}")
    nh = sub_out["peer"]                       # next-hop IP (within the p_out subnet)
    dst_net = topo.route("a")                  # remote destination subnet (e.g. 10.251.0.0/24)
    dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".5"
    cli.neigh_set(nh, _NH_MAC, p_out.name)
    cli.sh.run(f"ip route replace {dst_net} via {nh}", check=False)
    try:
        if not _wait_route(cli, dst_net):
            pytest.fail(f"DEVICE DEFECT: static route {dst_net} not programmed to kernel/FRR "
                        f"with static neighbor; cannot drive L3 drop path")
        rmac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")
        assert rmac, "DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found"
        yield p_in, p_out, rmac, dst_ip
    finally:
        cli.sh.run(f"ip route del {dst_net}", check=False)
        cli.neigh_del(nh, p_out.name)


def _wait_kernel_mtu(cli, port_name, want, tries=12):
    """Wait for the kernel netdev MTU to actually apply to `want` (portmgrd). Return the final value string."""
    val = None
    for _ in range(tries):
        val = cli.sh.run(f"cat /sys/class/net/{port_name}/mtu", check=False).out.strip()
        if val == str(want):
            return val
        time.sleep(1)
    return val


@pytest.mark.traffic
def test_ip_pkt_with_expired_ttl(cli, config_guard, topo, l3up):
    """[9] TTL expired: a packet whose TTL decrements to 0 on the routing path should be dropped
    (DEBUG_COUNTER reason=TTL).

    Use the L3-RIF routing pattern: inject a packet with outer DMAC=router MAC / dst=remote dst / TTL=1
    -> when the chip routes it, TTL decrements to 0 -> TTL_ERROR drop. Assert the PORT_INGRESS_DROPS TTL
    counter really increases (otherwise a real device defect)."""
    from scapy.all import Ether, IP, UDP
    topo.caps.require("loopback")
    with _l3_routed(cli, topo, l3up) as (p_in, _p_out, rmac, dst_ip):
        _run_debug_counter_case(
            cli, p_in, config_guard, "TTL",
            lambda: (Ether(dst=rmac, src=topo.mac("src")) /
                     IP(src=topo.subnet("c")["peer"], dst=dst_ip, ttl=1) / UDP()),
            name="DROP_TTL")


@pytest.mark.traffic
def test_ip_pkt_with_exceeded_mtu(cli, config_guard, topo, l3up):
    """[13] Exceeds egress MTU: a routed packet whose whole frame exceeds the L3 egress interface MTU
    should be dropped (DEBUG_COUNTER reason=EXCEEDS_L3_MTU).

    Use the L3-RIF routing pattern: set a small MTU (1500) on the egress port p_out, inject a packet
    with outer DMAC=router MAC / dst=remote dst / TTL=64 / large payload (whole frame > 1500) -> when the
    chip routes it to p_out it checks the egress MTU -> EXCEEDS_L3_MTU drop. Assert the PORT_INGRESS_DROPS
    EXCEEDS_L3_MTU counter really increases (otherwise a real device defect). The injection port p_in
    keeps the default 9100 so the local netdev can emit large frames."""
    from scapy.all import Ether, IP, UDP, Raw
    topo.caps.require("loopback")
    with _l3_routed(cli, topo, l3up) as (p_in, p_out, rmac, dst_ip):
        low_mtu = 1500
        # set a small MTU on the egress port so an ordinary large frame already overshoots (the EXCEEDS_L3_MTU criterion is exceeding the egress L3 interface MTU)
        rc, r = cli.config_raw(f"interface mtu {p_out.name} {low_mtu}")
        if rc != 0:
            pytest.skip(f"interface mtu CLI unsupported/failed: {(r.out + r.err).strip()[:140]}")
        config_guard.defer_undo(f"interface mtu {p_out.name} 9100")   # restore default
        applied = _wait_kernel_mtu(cli, p_out.name, low_mtu)
        if applied != str(low_mtu):
            pytest.skip(f"MTU {low_mtu} not applied to kernel netdev {p_out.name} "
                        f"(/sys mtu={applied!r}); cannot drive EXCEEDS_L3_MTU")
        _run_debug_counter_case(
            cli, p_in, config_guard, "EXCEEDS_L3_MTU",
            # DF set: without DF the chip may legitimately **punt an over-MTU packet to CPU for software fragmentation** (no drop, no count, not a defect);
            # with DF=1 the hardware can neither fragment nor forward and must drop -- which is the deterministic criterion for EXCEEDS_L3_MTU.
            lambda: (Ether(dst=rmac, src=topo.mac("src")) /
                     IP(src=topo.subnet("c")["peer"], dst=dst_ip, ttl=64, flags="DF") /
                     UDP() / Raw(b"x" * 4000)),   # whole frame > 1500, exceeds egress MTU
            name="DROP_MTU")


# ---- L3 class (bench measurement limitation, removed) ----
# The original test_l3_drop_unsupported_reason parameterized 13 items (loopback/multicast/zero/
# link-local/class-E IP, etc.): capabilities has no corresponding DEBUG_COUNTER reason, and
# traffic/drop_port use an L2 port (no RIF, intfstat empty), so these L3 drops cannot be measured
# closed-loop on this bench -- a bench measurement limitation, hence removed (the original
# implementation was an unconditional pytest.skip, equivalent to a zero-information dummy item).
# Once an L3 RIF ingress bench is available or the platform adds the corresponding reason, re-add
# these as real closed-loop cases.
