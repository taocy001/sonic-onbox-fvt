"""Mirror chip-behavior verification: local SPAN (ingress/egress) mirror copies + ERSPAN GRE encap + truncation length.

Not just verifying "CONFIG_DB/ASIC has a MIRROR_SESSION object" (that's an anti-pattern), but
sending real traffic to verify the chip really delivers copies to the destination port / encaps them out:
  - SPAN: inject a known unicast frame on the monitored port -> the chip should mirror a full
    copy to the destination port -> verify copy count via the chip TX counter on the destination
    port; plus a negative control (copies must stop after session removal).
  - ERSPAN: the session points at a locally-reachable collector IP, so the encap packet is
    naturally L3-to-local punted -> capture GRE/ERSPAN, extract the inner frame to verify encap
    + the outer encap header (DSCP/TTL/GRE proto) programmed per the session params.
  - Truncation: configure truncate_size, use dst loopback re-entry byte counting (RBYT/RPKT =
    average frame length) to verify the mirror copy length is shortened (real chip truncation,
    not verbatim copy) -- hardware mirror copies don't go through a kernel netdev, so the
    packet-capture method is unusable.

Test method (direct FAIL binary exposure, no xfail masking):
  * The local SPAN session object can program to ASIC (SAI_MIRROR_SESSION) -- already verified in test_mirror.py.
  * But SONiC binds the SPAN/ERSPAN source-port+direction via ACL (each session generates an
    ACL rule invoking a mirror action). If the user ACL rule doesn't program to ASIC (qset too
    wide / group capacity) -> the binding doesn't hold -> the chip produces no mirror copies.
    So all dataplane assertions of "send traffic, see copies at destination/collector" will
    FAIL in that case -- honestly exposing the problem. When ACL is eventually fixed, these
    cases turn PASS, exposing "it's fixed" -- exactly the honest signal we want.

The mechanism relies on the framework's existing, on-device-verified loopback (traffic/_lb)
and ChipCounters; ports/VLAN/IP all come from topo.
Prints/assert in English; comments/docstrings translated. Clean imports, self-contained, idempotent teardown cleanup.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.mirror, pytest.mark.traffic]

try:
    from scapy.all import Ether, IP, UDP, Raw, sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

from framework import hygiene
from framework.counters import ChipCounters

# ---- tolerances for mirror-copy count ----
_N = 80                       # number of injected frames
_MIRROR_LOWER = _N * 0.7      # copy lower bound: real chip mirroring should be ~N (tolerating loopback/counter jitter)
_STORM_UPPER = 200_000        # upper bound: guard against runaway (binding-failure flood / loop)

# copy content signature (used to identify mirror copies when capturing on the destination netdev, distinct from background traffic)
_PROBE_SMAC = "00:de:ad:be:ef:71"
_PROBE_DMAC = "00:aa:bb:cc:dd:71"
_MAGIC = b"MIRRORPROBExx"


def _probe_pkt(payload_len=64):
    """Build a known unicast L2 frame with a unique signature (injected on the monitored port)."""
    pad = max(0, payload_len - len(_MAGIC))
    return (Ether(dst=_PROBE_DMAC, src=_PROBE_SMAC) /
            IP(src="10.66.66.1", dst="10.66.66.2") /
            UDP(sport=1111, dport=2222) / Raw(_MAGIC + b"x" * pad))


@pytest.fixture
def mirror_ports(dut, _lb, topo, cli):
    """Mirror-dedicated port triple: monitored source src / mirror destination dst / final sink for the source frame.

    Layout (key to storm prevention):
      - src (misc_port 0): enable MAC loopback so the CPU-injected probe re-enters the pipeline from this port (becoming the ingress stimulus).
      - dst (misc_port 1): the mirror destination; enable MAC loopback to bring it oper-up (must have egress to mirror), copies leave from this port.
      - sink: the probe DMAC points via static FDB to a third port (an L2-domain port outside
        the misc pool), so the original frame is forwarded away from src and does not
        self-loop-storm on src; this port is NOT looped.
    teardown: delete the FDB, disable all loopbacks.
    """
    src = topo.misc_port(0)
    dst = topo.misc_port(1)
    sink = topo.l2_port(0)        # forwarding destination for the original frame (not looped, to avoid re-entry)
    vlan = topo.default_vlan

    # dst must not be a member of the VLAN under test (the mirror destination should be a bare
    # port). On the rebuilt OS (SONiC): with an access/bridge port as dst, the session doesn't
    # program to ASIC, and an access port can't be removed from Vlan1 with vlan member del --
    # same adaptation as test_mirror.py: restore_port_l3 switches to route mode; the community
    # image keeps removing it from the VLAN.
    if cli.is_switchport_os():
        cli.restore_port_l3(dst)
    else:
        rc, r = cli.config_raw(f"vlan member del {vlan} {dst.name}")
        assert rc == 0 or "not a member" in f"{r.err or ''}{r.out or ''}".lower(), (
            f"failed to detach mirror destination {dst.name} from Vlan{vlan}: {r.err or r.out}")
    _lb.enable(src)
    _lb.enable(dst)               # only to bring dst oper-up; mirror copies leave from dst's physical egress
    # original frame's dst MAC points to sink (known unicast), avoiding a flood self-loop on the src loopback port
    cli.fdb_static_add(vlan, _PROBE_DMAC, sink.name)
    time.sleep(1)
    yield {"src": src, "dst": dst, "sink": sink, "vlan": vlan}
    cli.fdb_static_del(vlan, _PROBE_DMAC)
    _lb.disable(src)
    # restore dst to a clean L2 baseline: hygiene handles both OSes (disable loopback, reset
    # PVID; SONiC goes route->bridge to authoritatively reset then back to default VLAN
    # untagged; community image clears IP then member add) -- symmetric with the setup branch,
    # avoiding a hand-written `vlan member add -u` being rejected on SONiC (access mode doesn't accept the -u flag).
    hygiene.reset_port_to_l2(cli, _lb, dut, dst, vlan)


def _send_probe(src_port, pkt, count=_N):
    sendp(pkt, iface=src_port.name, count=count, verbose=False)


def _measure_mirror_tx(bsh, bcm_port, send_fn):
    """clear -> send -> read once: measure mirror-copy TX on the destination port since clear (= ChipCounters object).

    This diag's `show c` only shows counters that changed since the last show/clear, so the old
    pattern base=read; send; delta=read-base yields garbage/negative deltas on these diags (the
    base read consumes the display + includes background noise). So clear to zero -> send -> read
    once gives the mirror-copy count on that port since clear (frames re-entering after clear also
    count from 0), portable across both platforms, no negative-delta guard needed."""
    ChipCounters.clear(bsh)
    send_fn()
    time.sleep(1.2)
    return ChipCounters.read(bsh, bcm_port)


def _read_rx_pkt_byt(bsh, bcm_port):
    """A single `show c` parses both this port's RX packet count and RX byte count since clear.

    This diag's show c is a consuming display (only shows counters changed since the last
    show/clear) -- packet count and byte count must be parsed from the same output; a second
    show would read empty. Counter names differ across platforms: some MIB_RPKT/MIB_RBYT, some
    CLMIB_*, some diags bare RPKT/RBYT or RX_PKT/RX_BYT."""
    out = bsh.cmd(f"show c {bcm_port}")

    def grab(*names):
        for n in names:
            m = re.search(rf"{n}\.{re.escape(bcm_port)}\b[^:]*:\s*([\d,]+)", out)
            if m:
                return int(m.group(1).replace(",", ""))
        return 0

    return (grab("MIB_RPKT", "CLMIB_RPKT", "RPKT", "RX_PKT"),
            grab("MIB_RBYT", "CLMIB_RBYT", "RBYT", "RX_BYT"))


# ====================== local SPAN: mirror copies to the destination port ======================

def test_span_ingress_copies_to_destination(cli, dut, _lb, asicdb, topo,
                                            mirror_ports, config_guard):
    """SPAN ingress (rx): inject N frames on the monitored source port -> the chip should mirror a full copy to the destination port.

    Real dataplane verification: the destination port's chip TX count should be +≈N (copies
    really sent out). Verifying only that the session object exists is an anti-pattern; here we
    verify copies really reach the destination."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")

    src, dst = mirror_ports["src"], mirror_ports["dst"]
    sess = "span_chip_rx"
    base_obj = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*")
    # SPAN source = monitored port, direction = rx (ingress)
    rc, r = cli.config_raw(f"mirror_session span add {sess} {dst.name} {src.name} rx")
    config_guard.defer_undo(f"mirror_session remove {sess}")
    assert rc == 0, f"failed to create SPAN rx session: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"MIRROR_SESSION|{sess}"), "no MIRROR_SESSION in CONFIG_DB"
    # the session object should program (a local SPAN session can be programmed); the binding (ACL) is the crux
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*", base_obj, timeout=8), \
        "SPAN session object not programmed to ASIC (SAI_MIRROR_SESSION)"
    time.sleep(2)   # wait for the (if any) ACL binding to program

    bsh = _lb.bsh
    pkt = _probe_pkt()
    # clear to zero -> send -> read once (= mirror copies received at destination since clear).
    # This diag's `show c` only shows changes since the last show/clear, so don't subtract
    # base/after (yields negative deltas / garbage).
    ChipCounters.clear(bsh)
    _send_probe(src, pkt)
    time.sleep(1.2)
    delta = ChipCounters.read(bsh, dut.bcm_of(dst))
    # copies really reach destination: TX +≈N, and no storm
    assert _MIRROR_LOWER <= delta.tx_pkt < _STORM_UPPER, (
        f"SPAN ingress: destination {dst.name} chip TX delta={delta.tx_pkt}, "
        f"expected ~{_N} mirror copies (no storm)")


def test_span_egress_copies_to_destination(cli, dut, _lb, asicdb, topo,
                                           mirror_ports, config_guard):
    """SPAN egress (tx): the egress frames of the monitored source port should be mirrored to the destination port.

    The source frame re-enters via src loopback then is forwarded to sink (egressing from src);
    that egress frame should trigger egress mirroring -> destination TX +≈N."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    src, dst = mirror_ports["src"], mirror_ports["dst"]
    sess = "span_chip_tx"
    base_obj = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*")
    rc, r = cli.config_raw(f"mirror_session span add {sess} {dst.name} {src.name} tx")
    config_guard.defer_undo(f"mirror_session remove {sess}")
    assert rc == 0, f"failed to create SPAN tx session: {r.err or r.out}"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*", base_obj, timeout=8), \
        "SPAN session object not programmed to ASIC"
    time.sleep(2)

    bsh = _lb.bsh
    pkt = _probe_pkt()
    # counting: clear -> send -> settle -> read once (change semantics, delta-since-clear; ChipCounters.clear is parallel-safe)
    delta = _measure_mirror_tx(bsh, dut.bcm_of(dst), lambda: _send_probe(src, pkt))
    assert _MIRROR_LOWER <= delta.tx_pkt < _STORM_UPPER, (
        f"SPAN egress: destination {dst.name} chip TX delta={delta.tx_pkt}, "
        f"expected ~{_N} egress mirror copies (no storm)")


def test_span_remove_stops_copies(cli, dut, _lb, asicdb, topo,
                                  mirror_ports, config_guard):
    """Negative control: after `mirror_session remove`, mirror copies must stop.

    Positive phase: build an rx session, inject N frames -> destination chip TX +≈N (also
    proving the positive path's count signal is really caused by the session, not flood/noise);
    negative phase: remove the session, wait for the SAI_MIRROR_SESSION object count to fall
    back to baseline (programming-side confirmation, not just CONFIG_DB), then inject N frames
    again -> destination TX should be ≈0.
    A stuck ACL binding / orphaned SAI session (still mirroring after removal) is exposed
    binarily here.
    Note: this case replaces the former test_span_copy_content_identical -- that one was
    byte-for-byte identical to test_span_ingress_copies_to_destination in stimulus/observation/
    assertion (a pure duplicate at runtime); removed per review and this missing negative
    control added."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    src, dst = mirror_ports["src"], mirror_ports["dst"]
    sess = "span_chip_neg"
    base_obj = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*")
    rc, r = cli.config_raw(f"mirror_session span add {sess} {dst.name} {src.name} rx")
    # backstop undo: if already removed within the test, teardown's delete reports "doesn't exist", tolerated idempotently by config_guard
    config_guard.defer_undo(f"mirror_session remove {sess}")
    assert rc == 0, f"failed to create SPAN rx session: {r.err or r.out}"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*", base_obj, timeout=8), \
        "SPAN session object not programmed to ASIC"
    time.sleep(2)

    bsh = _lb.bsh
    pkt = _probe_pkt()
    # positive phase: with the session present, copies ~N (proving the count signal is really produced by the session, also a positive-path control)
    delta = _measure_mirror_tx(bsh, dut.bcm_of(dst), lambda: _send_probe(src, pkt))
    assert _MIRROR_LOWER <= delta.tx_pkt < _STORM_UPPER, (
        f"positive phase: destination {dst.name} chip TX delta={delta.tx_pkt}, "
        f"expected ~{_N} mirror copies while session exists (no storm)")

    # remove the session and confirm on the programming side (ASIC_DB) that the object falls back to baseline
    rc, r = cli.config_raw(f"mirror_session remove {sess}")
    assert rc == 0, f"failed to remove SPAN session: {r.err or r.out}"
    deadline = time.time() + 10
    while (time.time() < deadline and
           asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*") > base_obj):
        time.sleep(0.5)
    assert asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*") <= base_obj, \
        "SAI_MIRROR_SESSION object still in ASIC after mirror_session remove (orphaned session)"
    time.sleep(1)   # wait for the ACL binding teardown to settle in hardware

    # negative phase: session removed, inject N frames the same way, destination should no longer receive mirror copies
    delta2 = _measure_mirror_tx(bsh, dut.bcm_of(dst), lambda: _send_probe(src, pkt))
    assert delta2.tx_pkt < _N * 0.1, (
        f"mirror copies continue after session removal: destination {dst.name} chip TX "
        f"delta={delta2.tx_pkt} (expected ~0); stuck ACL binding / orphaned SAI session")


# ====================== ERSPAN: GRE encap to collector ======================

def test_erspan_gre_encap_to_collector(cli, dut, _lb, topo, config_guard):
    """ERSPAN: the session points at a locally-reachable collector IP, and monitored-port traffic should be GRE/ERSPAN-encapsulated and sent to the collector.

    Real dataplane verification: it's real encap only if the collector (local) captures a GRE
    encap packet whose inner layer contains the original probe frame; plus an upgraded check
    that the outer encap header is programmed per the session params: outer IP DSCP==8, TTL==100
    (session-configured values), GRE protocol==0x88be (ERSPAN type II, session explicitly
    configures gre_type=0x88be).
    Note: this case has been merged into the equivalent case in tests/test_erspan_traffic.py
    (session params/stimulus/assertions fully duplicated, judged a pure runtime duplicate by
    review); this file keeps only a stub."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")
    from responders.collector import ErspanCollector
    from topo.virtual_link import LocalPeerIP

    net = topo.subnet("erspan")
    src_ip, collector_ip = net["dut"], net["peer"]
    port = dut.pick_test_ports(1)[0]
    sess = "erspan_chip"

    if not cli.has_erspan_cli():
        pytest.skip("ERSPAN session CLI not shipped on this image "
                    "(config mirror_session has only span/del) — structurally untestable")
    peer = LocalPeerIP(cli, collector_ip)
    peer.setup()
    try:
        # ERSPAN: <name> <src_ip> <dst_ip> <dscp> <ttl> <gre_type> [queue], plus binding the source port + direction.
        # gre_type explicitly configured to 0x88be (ERSPAN type II) -- the outer GRE proto assertion treats this as the config-driven value.
        rc, r = cli.config_raw(
            f"mirror_session erspan add {sess} {src_ip} {collector_ip} 8 100 0x88be 0 {port.name} rx")
        config_guard.defer_undo(f"mirror_session remove {sess}")
        assert rc == 0, f"failed to create ERSPAN session: {r.err or r.out}"
        assert cli.db_keys("CONFIG_DB", f"MIRROR_SESSION|{sess}"), "no MIRROR_SESSION in CONFIG_DB"
        time.sleep(2)

        _lb.enable(port)
        try:
            pkt = _probe_pkt()
            with ErspanCollector(port.name) as col:
                _send_probe(port, pkt, count=50)
                time.sleep(1.5)
            inner = col.inner_frames()
            assert inner, ("ERSPAN captured 0 inner frames: GRE encap not attached / ACL mirror "
                           "not programmed to ASIC on this device")
            assert any(_MAGIC in bytes(f) for f in inner), \
                "ERSPAN inner frame does not contain the injected probe payload"
            # real verification of the outer encap header: session params dscp=8/ttl=100/gre_type=0x88be must be reflected in the outer encap
            # (count only GRE packets of this session's 5-tuple src_ip->collector_ip, excluding other encap traffic running in parallel).
            from scapy.all import GRE
            outers = [p for p in col.packets
                      if p.haslayer(GRE) and p.haslayer(IP)
                      and p[IP].src == src_ip and p[IP].dst == collector_ip]
            assert outers, (f"GRE packets captured but none with configured outer "
                            f"src={src_ip} dst={collector_ip}")
            bad_ttl = sorted({p[IP].ttl for p in outers if p[IP].ttl != 100})
            assert not bad_ttl, \
                f"outer IP TTL not honored: got {bad_ttl}, session configured ttl=100"
            bad_dscp = sorted({p[IP].tos >> 2 for p in outers if (p[IP].tos >> 2) != 8})
            assert not bad_dscp, \
                f"outer IP DSCP not honored: got {bad_dscp}, session configured dscp=8"
            protos = {p[GRE].proto for p in outers}
            assert protos == {0x88be}, (
                f"outer GRE protocol {sorted(hex(x) for x in protos)} != 0x88be "
                "(ERSPAN type II as configured via gre_type)")
        finally:
            _lb.disable(port)
    finally:
        peer.teardown()


# ====================== truncation length ======================

def test_span_truncation_shortens_copy(cli, dut, _lb, asicdb, topo,
                                       mirror_ports, config_guard):
    """Mirror truncation length: configure truncate_size on the SPAN session, inject a large
    frame (payload ~1000B), and the copy mirrored to destination should be shortened to
    ~truncate_size (real chip truncation, not verbatim copy).

    Legitimate config path: after creating the SPAN session via CLI, write the MIRROR_SESSION
    truncate_size field via CONFIG_DB (a SONiC-supported session attribute corresponding to
    SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE).

    Dataplane observation method (revised): hardware mirror copies leave from the destination
    physical port and aren't reliably visible via the kernel netdev's AF_PACKET path -- the
    original tcpdump method always captures 0 -> false failure. Instead use loopback re-entry
    byte counting: dst already has MAC loopback on, so a copy TX'd out re-enters verbatim = dst
    RX, hence clear -> send -> single read of dst's RPKT/RBYT, average frame length = RBYT/RPKT
    is the copy's real wire length:
      - control phase (session has no truncation): rx_pkt ∈ [N*0.7, storm upper bound] and
        average frame length ≈ original frame length (copy is complete);
      - truncation phase (after truncate_size programs to SAI): rx_pkt in the same range, and
        average frame length <= trunc+64 and clearly smaller than the control average (real chip truncation)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    src, dst = mirror_ports["src"], mirror_ports["dst"]
    sess = "span_chip_trunc"
    trunc = 200    # target truncation length (bytes)
    big_payload = 1000

    if cli._span_dir_opt():
        # SONiC: the span CLI has no truncate option, and its orchagent doesn't consume session
        # attributes from a bare HSET (SAI TRUNCATE_SIZE absent) -- mirror truncation has no config channel, structural skip.
        pytest.skip("this image's span CLI has no truncate option and raw CONFIG_DB writes "
                    "are not consumed; mirror truncation not configurable (structural)")
    base_obj = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*")
    rc, r = cli.config_raw(f"mirror_session span add {sess} {dst.name} {src.name} rx")
    config_guard.defer_undo(f"mirror_session remove {sess}")
    assert rc == 0, f"failed to create SPAN session: {r.err or r.out}"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*", base_obj, timeout=8), \
        "SPAN session object not programmed to ASIC"
    time.sleep(2)   # wait for the (if any) ACL binding to program

    bsh = _lb.bsh
    bcm_dst = dut.bcm_of(dst)
    pkt = _probe_pkt(payload_len=big_payload)
    orig_len = len(bytes(pkt))

    # ---- control phase (no truncation): copy should be complete -- average frame length ≈ original frame length ----
    ChipCounters.clear(bsh)
    _send_probe(src, pkt)
    time.sleep(1.2)
    ctrl_pkt, ctrl_byt = _read_rx_pkt_byt(bsh, bcm_dst)
    assert _MIRROR_LOWER <= ctrl_pkt < _STORM_UPPER, (
        f"truncation control: destination {dst.name} loopback re-entry RX={ctrl_pkt}, "
        f"expected ~{_N} full-size mirror copies (no storm)")
    if ctrl_byt == 0:
        # copies present (RPKT≈N) but byte count always 0 = this diag doesn't expose RBYT-class
        # counters, so frame length is unobservable via chip counters -- the observation channel
        # is structurally absent, unrelated to device mirror behavior, cannot fake a FAIL/PASS.
        pytest.skip("chip RX byte counter (MIB_RBYT/CLMIB_RBYT/RBYT) not exposed by this diag; "
                    "frame-length observation channel unavailable (structural)")
    ctrl_avg = ctrl_byt / ctrl_pkt
    # 0.8 tolerance accommodates a few small-frame noise in the window (LLDP/ND mirrored/re-entered together via loopback) -- still far above trunc+64
    assert ctrl_avg >= orig_len * 0.8, (
        f"control (no truncation) avg frame size {ctrl_avg:.0f}B unexpectedly small vs "
        f"original {orig_len}B; mirror copies should be full-length before truncation")

    # ---- legitimately write truncate_size (a session attribute) via CONFIG_DB, and wait for the SAI attribute to really program ----
    cli.sh.run(f"sonic-db-cli CONFIG_DB HSET 'MIRROR_SESSION|{sess}' truncate_size {trunc}",
               check=False)

    def _trunc_attr_programmed():
        return any(
            cli.db_hgetall("ASIC_DB", k).get("SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE") == str(trunc)
            for k in asicdb.objects("SAI_OBJECT_TYPE_MIRROR_SESSION"))

    deadline = time.time() + 8
    while time.time() < deadline and not _trunc_attr_programmed():
        time.sleep(0.5)
    assert _trunc_attr_programmed(), (
        f"truncate_size={trunc} not programmed to ASIC "
        "(SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE absent or value mismatched)")
    time.sleep(1)   # wait for hardware to apply

    # ---- truncation phase: the copy's average frame length should be shortened to ~trunc, and clearly smaller than control ----
    ChipCounters.clear(bsh)
    _send_probe(src, pkt)
    time.sleep(1.2)
    tr_pkt, tr_byt = _read_rx_pkt_byt(bsh, bcm_dst)
    assert _MIRROR_LOWER <= tr_pkt < _STORM_UPPER, (
        f"truncation phase: destination {dst.name} loopback re-entry RX={tr_pkt}, "
        f"expected ~{_N} truncated mirror copies (no storm)")
    tr_avg = tr_byt / tr_pkt
    # leave a 64B margin for the mirror added header/CRC/min-frame padding; and require it clearly smaller than the control average (otherwise = not truncated)
    assert tr_avg <= trunc + 64, (
        f"mirror copies not truncated: avg frame {tr_avg:.0f}B > truncate_size {trunc}+64 "
        f"(control avg {ctrl_avg:.0f}B, orig {orig_len}B); chip did not honor truncation")
    assert tr_avg < ctrl_avg * 0.5, (
        f"truncated avg frame {tr_avg:.0f}B not clearly smaller than control avg "
        f"{ctrl_avg:.0f}B; truncation had no effect")
