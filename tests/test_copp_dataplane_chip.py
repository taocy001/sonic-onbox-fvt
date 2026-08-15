"""CoPP dataplane + chip behavior: drive real protocol packets per trap type, verifying it truly punts to the CPU.

Relationship to test_copp_full.py / test_copp_l3_traps.py (this file extends dataplane coverage on top of both):
  - test_copp_full.py: mainly tests ASIC_DB HOSTIF_TRAP topology/rate-limit + a set of FP-match trap captures;
  - test_copp_l3_traps.py: mainly tests L3-result traps (routed-port cpu0 RPKT);
  - this file: makes "each trap type = real protocol packet -> punt to CPU" the main thread, **every case
    carries a dataplane assertion** (capture matched by unique src MAC / chip-level cpu0 RPKT delta), and
    for each L2 trap additionally asserts the corresponding SAI_OBJECT_TYPE_HOSTIF_TRAP is programmed to
    the ASIC (control plane -> chip), forming "chip programming + dataplane arrival" dual evidence,
    eliminating the anti-pattern of only checking "the DB object exists".

Mechanism:
  The reason for L2/protocol traps (lldp/lacp/udld/arp/nd) is pure FP-match (DMAC/EtherType); a
  MAC-loopback CPU-injected packet re-entering the pipeline hits it -> punt to CPU (cpu0 on VPP). These
  **should PASS**.

  The reason for L3-result traps (ip2me/bgp/ttl_error/neighbor_miss) is a product of the LPP L3 lookup
  (MyStationHit / DstClassL3=IP2ME_CLASS), and the myStation for L3-result traps is added per-port; when
  a MAC-loopback CPU-injected packet re-enters, src_port is reported as the CPU port rather than the
  physical port -> per-port myStation does not match -> the L3 lookup is not triggered -> cpu0 receives
  nothing. This is a **false negative** of this bench's method (CPU injection + loopback); with current
  on-box means it cannot be determined whether it works (a real external ingress is needed: traffic
  generator / physical peer port). So that portion of dataplane cases is removed as a bench boundary
  (see Part 2 note); this file keeps only the L2/protocol traps that loopback can reliably test.

Inputs go only through legal paths: scapy injection (loopback method) + config for the routed port; chip
access is read-only (show c / cpu0 RPKT).
Prints/assert/skip in English; comments/docstrings in English; ports taken from fixture/topo, not hardcoded.
"""
import time

import pytest

from framework import profile as _profile

pytestmark = [pytest.mark.trap, pytest.mark.traffic]

# Full set of SAI trap types declared by this device's profile (same source as test_copp_full; empty = unmatched device dry-run, no gating).
#:the udld parameter previously hard-FAILed on images without a udld declaration -- gate/skip per declaration.
_DECLARED_SAI = {"SAI_HOSTIF_TRAP_TYPE_" + t
                 for sais in _profile.load_current().get("copp", {}).get("trap_id_sai", {}).values()
                 for t in sais}


# ============================================================================
# Part 1: L2 / protocol traps -- should PASS (FP-match, reliably testable by loopback)
# ============================================================================

# Each L2 trap: unique src MAC (for precise attribution in captures, avoiding background-traffic crosstalk)
_L2_SMAC = {
    "lldp":    "02:00:00:cb:00:11",
    "lacp":    "02:00:00:cb:00:12",
    "udld":    "02:00:00:cb:00:13",
    "arp_req": "02:00:00:cb:00:14",
    "arp_resp": "02:00:00:cb:00:15",
    "nd_ns":   "02:00:00:cb:00:16",
    "nd_na":   "02:00:00:cb:00:17",
}

# L2 trap -> HOSTIF_TRAP type expected to be programmed to the ASIC (proving the chip-side trap is installed).
# arp_req/arp_resp/nd share the ARP/ND trap types; any hit means that protocol's trap is ready on the chip side.
_L2_ASIC_TRAP_TYPES = {
    "lldp":     ["SAI_HOSTIF_TRAP_TYPE_LLDP"],
    "lacp":     ["SAI_HOSTIF_TRAP_TYPE_LACP"],
    "udld":     ["SAI_HOSTIF_TRAP_TYPE_UDLD"],
    "arp_req":  ["SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST"],
    "arp_resp": ["SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE"],
    "nd_ns":    ["SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY",
                 "SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_SOLICITATION"],
    "nd_na":    ["SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY",
                 "SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_ADVERTISEMENT"],
}


def _l2_trap_pkt(name, smac):
    """Build the real packet for the corresponding protocol + the capture BPF."""
    from scapy.all import Ether, ARP, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, Raw
    if name == "lldp":
        return (Ether(dst="01:80:c2:00:00:0e", src=smac, type=0x88cc) /
                Raw(b"\x02\x07\x04" + b"x" * 40), "ether proto 0x88cc")
    if name == "lacp":
        return (Ether(dst="01:80:c2:00:00:02", src=smac, type=0x8809) /
                Raw(b"\x01\x01" + b"x" * 40), "ether proto 0x8809")
    if name == "udld":
        return (Ether(dst="01:00:0c:cc:cc:cc", src=smac) / Raw(b"x" * 50),
                "ether dst 01:00:0c:cc:cc:cc")
    if name == "arp_req":
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=smac) /
                ARP(op=1, pdst="1.2.3.4", psrc="1.2.3.6", hwsrc=smac), "arp")
    if name == "arp_resp":
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=smac) /
                ARP(op=2, pdst="1.2.3.4", psrc="1.2.3.5", hwsrc=smac), "arp")
    if name == "nd_ns":
        return (Ether(dst="33:33:ff:00:00:01", src=smac) /
                IPv6(dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="fe80::1"), "icmp6")
    if name == "nd_na":
        return (Ether(dst="33:33:00:00:00:01", src=smac) /
                IPv6(dst="ff02::1") / ICMPv6ND_NA(tgt="fe80::2"), "icmp6")
    raise ValueError(name)


# Injection-context matrix semantic fix, same as test_copp_full._CTX_PARAMS:
# slow protocol -> both contexts; arp/nd protocols -> L3 context only (SVI VLAN) --
# a pure L2 port not punting protocol packets is the correct semantic. l2 params come first (copp_l3_ctx is module-level, order-sensitive).
_SLOW_PROTOS = ["lldp", "lacp", "udld"]
_L3_PROTOS = ["arp_req", "arp_resp", "nd_ns", "nd_na"]
_CTX_PARAMS = ([(n, "l2") for n in _SLOW_PROTOS] +
               [(n, "l3") for n in _SLOW_PROTOS] +
               [(n, "l3") for n in _L3_PROTOS])


@pytest.mark.parametrize("name,ctx", _CTX_PARAMS, ids=[f"{n}-{c}" for n, c in _CTX_PARAMS])
def test_l2_trap_to_cpu(traffic, asicdb, request, name, ctx):
    """L2/protocol trap dataplane + chip-programming dual evidence (should PASS):

    1) Chip side: the corresponding SAI_OBJECT_TYPE_HOSTIF_TRAP is programmed to the ASIC (trap type matches);
    2) Dataplane: inject the protocol packet -> ports[0] egress -> MAC loopback re-entry -> hit the trap ->
       punt to CPU, and capture the punted copy on that port's netdev matched by the unique src MAC.
    Only both holding counts as PASS -- a DB object alone does not (anti-pattern), and capturing a packet
    alone still requires the chip to actually have the trap.
    Injection context: slow protocol tests both L2+L3 contexts; arp/nd only L3 context (conftest.copp_l3_ctx).
    """
    want = _L2_ASIC_TRAP_TYPES[name]
    if _DECLARED_SAI and not any(w in _DECLARED_SAI for w in want):
        pytest.skip(f"trap '{name}' not declared enabled on this device (profile copp); by design")
    if ctx == "l3":
        request.getfixturevalue("copp_l3_ctx")
    smac = _L2_SMAC[name]
    # --- Evidence 1: chip-side trap is installed ---
    installed = {asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE")
                 for t in asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP")}
    assert any(w in installed for w in want), \
        f"trap '{name}': none of {want} programmed to ASIC HOSTIF_TRAP (have {sorted(installed)})"

    # --- Evidence 2: dataplane truly punts to CPU ---
    # (bound review): sending 10 and receiving 1 tolerates 90% loss and masks a half-dead punt queue --
    # 10 frames are far below the lowest CIR tier, so a healthy punt should be nearly lossless; the lower
    # bound is raised to 8 (leaving 2 frames for sniffer start/stop races); under a unique src MAC,
    # exceeding the send count = loopback replication anomaly, so add an upper bound of 10.
    pkt, bpf = _l2_trap_pkt(name, smac)
    p = traffic.ports[0]
    with traffic.capture(p, bpf=bpf, inbound=True) as cap:
        traffic.send(p, pkt, count=10)
        time.sleep(0.6)
    got = cap.match(lambda x: getattr(x, "src", None) == smac)
    assert len(got) >= 8, \
        f"trap '{name}' punt lossy/dead: captured {len(got)}/10 inbound with src {smac} on {p.name}"
    assert len(got) <= 10, \
        f"trap '{name}' punt duplicated: captured {len(got)} > 10 injected (loopback replication?)"


def test_l2_traps_share_one_loopback_no_storm(traffic):
    """Smoke protection: L2 trap cases share a single-port loopback path; injecting N broadcast ARP frames
    should not trigger a storm (the count should be bounded) -- preventing later trap cases from producing
    false positives/negatives due to a flood storm.

    (count-paradigm fix review): on both devices `show c` has "delta since last show" semantics, so the
    old before/after difference gets polluted by the previous case's residue (even going negative) -- and
    the guard rail may silently pass during a real storm. Switch to the smoke_check pattern:
    clear -> traffic -> poll-accumulate + confirmation read; and add a lower bound (proving N frames truly
    loop back and re-enter, so the guard rail no longer falsely PASSes when the bench is dead).
    Upper bound STORM_BOUND: even with in-VLAN BUM flooding / loopback amplification a healthy device only
    reaches the thousands (see traffic.smoke_check comment), while a real storm (PHY self-loop) surges to millions.
    """
    from scapy.all import Ether, ARP
    N = 20                 # number of injected frames
    STORM_BOUND = 50_000   # ~2500xN: above normal BUM amplification (thousands), below a storm (millions)
    p = traffic.ports[0]
    traffic.clear_chip_counters()
    traffic.send(p, Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:cb:00:1f") /
                 ARP(op=1, pdst="9.9.9.9", psrc="9.9.9.8"), count=N)
    # Delta semantics: poll-accumulating gives the total; on cumulative-semantic devices the first read already meets the bar and exits early
    total = 0
    deadline = time.time() + 3.0
    while total < N * 0.9 and time.time() < deadline:
        time.sleep(0.4)
        total += traffic.chip_counters(p).rx_pkt
    # Confirmation read: normal traffic has settled by now (+0); a self-loop storm is still replicating exponentially and pushes total past the upper bound
    time.sleep(0.4)
    total += traffic.chip_counters(p).rx_pkt
    assert total >= N * 0.9, (
        f"loopback dead: chip RX +{total} for {N} injected broadcast ARP -- "
        "trap dataplane results in this module are unreliable (bench, not device verdict)")
    assert total < STORM_BOUND, \
        f"loopback storm suspected (chip RX +{total} for {N} injected frames, " \
        f"bound {STORM_BOUND}); trap dataplane results unreliable"


def test_non_trap_not_punted(traffic, cli):
    """Negative-control review: across the CoPP dataplane suite there was only "what should arrive arrives",
    missing "what should not arrive did not":
    ordinary known-unicast UDP data flow **must not** appear on the punt path -- if a CoPP trap match is
    misconfigured too broadly into full punting, this case exposes it (otherwise the whole suite stays green).

    Positive control that guards against false pass: static FDB points dst to ports[1] (a non-loopback port,
    so the frame forwards out, without flooding or re-injection); clear -> traffic -> accumulate chip counters
    proves N frames truly re-enter the pipeline; under that premise, the capture count on the ports[0] netdev
    inbound matched by the unique src MAC must be 0 (capturing 0 when frames are dropped by the kernel is a
    false negative, which the positive control rules out).
    """
    from scapy.all import Ether, IP, Raw, UDP
    smac = "02:00:00:cb:00:2e"   # unique src MAC (punt-leak attribution)
    dmac = "00:aa:bb:cc:dd:2e"   # static FDB -> ports[1]: known unicast, deterministic forwarding, no flooding
    N = 50
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    vid = traffic.default_vlan
    cli.fdb_static_add(vid, dmac, p_out.name)
    try:
        pkt = (Ether(dst=dmac, src=smac) / IP(src="10.66.6.1", dst="10.66.6.2") /
               UDP(sport=12345, dport=54321) / Raw(b"NONTRAP" + b"x" * 30))
        traffic.clear_chip_counters()
        with traffic.capture(p_in, bpf="udp", inbound=True) as cap:
            traffic.send(p_in, pkt, count=N)
            time.sleep(0.8)
        # Positive control: frames do loop back and re-enter the pipeline (show c delta semantics: poll-accumulate + confirmation read)
        total = 0
        deadline = time.time() + 3.0
        while total < N * 0.9 and time.time() < deadline:
            time.sleep(0.4)
            total += traffic.chip_counters(p_in).rx_pkt
        time.sleep(0.4)
        total += traffic.chip_counters(p_in).rx_pkt
        assert total >= N * 0.9, (
            f"positive control failed: chip RX +{total} for {N} injected frames on {p_in.name} "
            "-- frames never re-entered the pipeline, punt-zero result would be meaningless")
        leaked = cap.match(lambda x: getattr(x, "src", None) == smac)
        assert len(leaked) == 0, (
            f"non-trap unicast UDP punted to CPU: {len(leaked)}/{N} frames with src {smac} "
            f"captured inbound on {p_in.name} -- CoPP trap match too broad (dataplane traffic "
            "must not hit the CPU)")
    finally:
        cli.fdb_static_del(vid, dmac)


# ============================================================================
# Part 2: L3-result traps -- removed (D: bench boundary / bench-limitation)
# ============================================================================
# The former test_l3_trap_to_cpu (ip2me/bgp/ttl_error/neighbor_miss, chip-level cpu0 RPKT) has been removed.
# Reason (bench/measurement-method limitation, neither a pass nor a determinable device behavior): the
# per-port myStation for an L3-result trap is added by physical src_port; when a MAC-loopback CPU-injected
# packet re-enters, src_port is reported as the CPU port rather than the physical port -> per-port myStation
# does not match -> the L3 lookup is not triggered -> cpu0 RPKT=0. This is a **false negative** of this
# bench's method (CPU injection + loopback); with current on-box means it cannot be determined whether that
# trap actually works -- a real external ingress (traffic generator / physical peer port) is needed to
# confirm. So it is no longer hidden with xfail but removed wholesale and explicitly recorded here as a
# bench boundary. The chip-programming side (RIF/route->CPU port/myStation, LPP MyStationHit+DstClassL3 flag)
# is already cross-checked by code + ASIC_DB read-only; dataplane coverage for L2/protocol traps remains in
# Part 1 above (loopback can reliably test it).
