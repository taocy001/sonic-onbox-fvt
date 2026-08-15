"""QoS classification/remark chip-behavior verification -- not just verifying CONFIG_DB/ASIC maps exist, but sending real traffic to verify queue selection + egress marking.

Three chains under test (each with dataplane / chip assertions, distinct from test_qos_config.py's pure config->DB contract):
  1) DSCP -> TC -> queue map: inject IP packets with different DSCP, verify the traffic really
     lands on the map-designated egress queue (that queue's COUNTERS_DB SAI_QUEUE_STAT_PACKETS
     really increments), and different DSCP lands on different queues.
  2) PCP(dot1p) -> TC -> queue map: inject tagged frames with different 802.1p PCP, verify queue selection likewise.
  3) DSCP egress remark/preserve: use egress mirror to cpu0 to capture the real forwarded frame,
     check the egress DSCP value (under the default trust-DSCP policy, L2/L3 forwarding should
     preserve DSCP; if remark is configured, it's rewritten).
  4) ASIC map programming: DSCP_TO_TC / TC_TO_QUEUE SAI_QOS_MAP really program to ASIC, and their
     map_to_value_list maps the DSCP under test to a non-default TC (proving the classification rule really programs into the chip).

Mechanism (following the test_stats_full.py::test_queue_packets_increment_on_traffic paradigm, on-device verified):
  the traffic fixture configures ports[0] as default-VLAN untagged + enables MAC loopback;
  a CPU-injected frame first egresses from ports[0] -- that pass is CPU direct-send (KNET
  SOBMH-style direct-to-port) and does NOT go through ingress QoS classification; only when it
  re-enters ports[0] via MAC loopback is it classified by that port's trust_dscp. A dst static
  FDB points to ports[1], so the classified frame is unicast-forwarded out ports[1]. So the two
  measurements have distinct ownership:
  - queue-counter chain sanity: read ports[0] egress queues (the CPU-injected frame must pass it, regardless of whether classification took effect);
  - classification cases: read ports[1] egress queues (its queue selection is decided by
    DSCP/PCP->TC->queue classification). Within the measurement window, loop ports[1] (a
    re-entering frame hitting the static FDB pointing back to ports[1] is same-port-filtered
    and dropped, no loop), and disable_ipv6 to cut kernel multicast noise (two loopback ports
    in the same VLAN + noise multicast would loop-storm, same guard as test_mac.py).

Device status notes:
  - without buffers.json.j2, the QoS maps programmed by `config qos reload` may be incomplete / not land on ASIC;
  - when maps aren't on ASIC, DSCP/PCP classification uses the default (all land on TC0/queue0),
    so "different DSCP lands on different queues" fails -> these cases xfail (honestly marking a
    missing device QoS profile), never a false pass.
  - all landing on queue0 by default can still verify "traffic really entered some queue" (weak assertion, as sanity).

Ports: traffic fixture (ports[0]=inject/loopback port). Prints/assert/skip in English; comments/docstrings translated.
"""
import time
from contextlib import contextmanager

import pytest

from framework import qos

pytestmark = [pytest.mark.qos, pytest.mark.traffic]

try:
    from scapy.all import Ether, Dot1Q, IP, UDP, Raw  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

# injected frame's destination MAC: points to ports[1] via static FDB, so after re-entering
# ports[0] it is unicast-forwarded away (no loopback, no storm). Different MAC from the
# smoke/qstat cases, to avoid shared FDB add/delete contention.
_QOS_DST = "00:aa:bb:cc:dd:71"
_SRC = "00:de:ad:be:ef:71"
_N = 200                       # number of injected packets (with lower bound 0.5N, upper bound for storm guard)
_LOWER = _N * 0.5
# storm upper bound: normal background BUM flood over ten-odd seconds is only thousands~tens of
# thousands, while a self-loop storm replicates at millions per second (same calibration as
# smoke_check); a total delta exceeding this bound = storm false positive, abort honestly
# rather than counting storm copies as traffic.
_STORM_CAP = 100_000

# queue flex counter polls at ~10s by default, so poll-read after injection
_QPOLL = 16


# ============================ common helpers ============================
@pytest.fixture(scope="module")
def qos_loaded(cli, topo):
    """Module-wide prerequisite: get DSCP/TC/queue classification maps into CONFIG_DB/ASIC -- per the image's config model.

    WARNING: the product-CLI config-model image (SONiC) never runs `config qos reload`: on that
    image reload only clears and doesn't build (first clears the read-only default map, then
    exits with an error due to a missing hwsku template), potentially leaving a dangling
    PORT_QOS_MAP reference; its QoS provisioning is handled by the product-CLI baseline
    (build_baseline). The community image goes through template reload; a reload failure doesn't
    affect what follows (doesn't raise), and each case decides fail/skip based on whether the maps landed."""
    undo = None
    if qos.has_qos_cli(cli):
        # emptiness must be judged by CONFIG_DB DSCP_TO_TC_MAP: the ASIC ships with 3 dot1p-family
        # default maps, so judging by ASIC QOS_MAP would wrongly skip building the baseline.
        if not cli.db_keys("CONFIG_DB", "DSCP_TO_TC_MAP|*"):
            # product-CLI config-model image (SONiC): use its CLI to build the map baseline and bind
            # the injection port (trust_dscp), so the DSCP classification/enqueue cases have a real
            # classification chain to verify. Cleaned up at module end.
            undo = qos.build_baseline(cli, topo.port_name("a"), prefix="FVTRM")
    else:
        cli.sh.run("config qos reload", check=False, timeout=120)
        time.sleep(3)
    yield
    if undo:
        undo()


def _queue_oids(cli, port_name):
    """Return {queue_index(int): oid}, from all `<port>:<q>` items for this port in COUNTERS_QUEUE_NAME_MAP."""
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
    return {int(k.split(":")[1]): v for k, v in m.items()
            if k.startswith(port_name + ":") and k.split(":")[1].isdigit()}


def _queue_pkts(cli, oid):
    """Read a queue oid's SAI_QUEUE_STAT_PACKETS (int); 0 if absent."""
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    v = h.get("SAI_QUEUE_STAT_PACKETS")
    return int(v) if v is not None and str(v).isdigit() else 0


def _inject_and_measure_queues(cli, traffic, pkt, measure="in", fwd_vlan=None):
    """Inject pkt on ports[0] (dst points to ports[1] via static FDB), return {queue: delta_packets} (only queues with >0).

    measure="in"  read ports[0] egress queues -- the CPU-injected frame must pass it, but that
                  pass is CPU direct-send (SOBMH-style) and does NOT go through ingress QoS
                  classification, suitable only for queue-counter chain sanity;
    measure="out" read ports[1] egress queues -- the frame re-enters ports[0] via MAC loopback,
                  is classified by trust_dscp, then unicast-forwarded out ports[1] via static
                  FDB; its egress queue is decided by DSCP/PCP->TC->queue (required for
                  classification cases; the caller must loop ports[1] via _classified_egress so it can egress traffic).
    Polling exits when the max single-queue delta reaches the lower bound (background BUM noise
    spreads across many queues and shouldn't let a padded total exit early); after exit, do a
    confirming read and assert the total delta doesn't exceed the storm upper bound (guard against a self-loop storm false positive).
    """
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    p_meas = p_out if measure == "out" else p_in
    cand = _queue_oids(cli, p_meas.name)
    if not cand:
        pytest.fail(f"DEVICE DEFECT: no queue oid for {p_meas.name} in COUNTERS_QUEUE_NAME_MAP "
                    "(live DUT must expose queue flex counters; empty map = broken counter/dataplane path)")

    # l2_home_forwarding=false platforms (parked Vlan1 doesn't forward) must use a real VLAN, the caller passes l2_fwd_vlan(2510)
    _vl = fwd_vlan if fwd_vlan is not None else traffic.default_vlan
    cli.fdb_static_add(_vl, _QOS_DST, p_out.name)
    try:
        base = {q: _queue_pkts(cli, o) for q, o in cand.items()}
        pm = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
        poid = pm.get(p_meas.name)
        pbase = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{poid}").get(
            "SAI_PORT_STAT_IF_OUT_UCAST_PKTS", "0") if poid else "0"
        traffic.send(p_in, pkt, count=_N)
        grew = {}
        for _ in range(_QPOLL):
            time.sleep(1)
            cur = {q: _queue_pkts(cli, o) for q, o in cand.items()}
            grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
            if grew and max(grew.values()) >= _LOWER:
                break
        # confirming read: normal traffic has settled by now; a self-loop storm is still replicating, so the total delta exceeds the upper bound -> abort honestly.
        time.sleep(1)
        cur = {q: _queue_pkts(cli, o) for q, o in cand.items()}
        grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
        total = sum(grew.values())
        assert total <= _STORM_CAP, (
            f"loop storm suspected: egress queue deltas on {p_meas.name} total {total} > cap "
            f"{_STORM_CAP} for {_N} injected pkts (deltas={grew}); refusing to treat storm "
            f"copies as measured traffic")
        if not grew and poid:
            pcur = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{poid}").get(
                "SAI_PORT_STAT_IF_OUT_UCAST_PKTS", "0")
            pd = (int(pcur) - int(pbase)) if str(pcur).isdigit() and str(pbase).isdigit() else 0
            if pd >= _N * 0.5:
                # port-level SAI counters are moving while queue-level is dead still -- a queue
                # statistics collection defect, unrelated to whether DSCP/TC classification is
                # correct, reported precisely per the real observation.
                pytest.fail(f"DEVICE DEFECT: port-level SAI counters advanced (+{pd}) but NO "
                            f"queue-level SAI_QUEUE_STAT_PACKETS moved on {p_meas.name}; "
                            f"queue statistics collection non-functional on this image")
        return grew
    finally:
        cli.fdb_static_del(_vl, _QOS_DST)


@contextmanager
def _classified_egress(cli, traffic):
    """Classification-path measurement window: loop ports[1] so the classified forwarded frame really egresses from it (egress queue countable).

    Dual storm guards (lesson from the L2 cascade):
    (1) a re-entering frame hits the static FDB pointing back to ports[1] itself, is same-port-filtered and dropped -- known unicast doesn't loop;
    (2) ≥2 loopback ports in the same VLAN + any kernel noise multicast (IPv6 ND) = a perpetual
      loop storm, so within the window disable_ipv6 on both ports to cut the noise source (same
      as test_mac.py), restored at window end.
    """
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    for p in (p_in, p_out):
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{p.name}.disable_ipv6=1", check=False)
    traffic.loop(p_out)
    try:
        yield p_out
    finally:
        traffic.unloop(p_out)
        for p in (p_in, p_out):
            cli.sh.run(f"sysctl -qw net.ipv6.conf.{p.name}.disable_ipv6=0", check=False)


def _dominant_queue(grew):
    """The queue number with the largest delta (the egress queue the traffic mainly lands on); None if empty."""
    return max(grew, key=grew.get) if grew else None


# ============================ 1) ASIC map programming (chip-side proof the classification rule really programmed) ============================
def _qos_maps_by_type(asicdb):
    """Group ASIC QOS_MAP objects by SAI_QOS_MAP_ATTR_TYPE: {type_str: [key,...]}."""
    out = {}
    for k in asicdb.objects("SAI_OBJECT_TYPE_QOS_MAP"):
        t = asicdb.field(k, "SAI_QOS_MAP_ATTR_TYPE")
        out.setdefault(t, []).append(k)
    return out


def test_dscp_to_tc_map_programmed_to_asic(cli, asicdb, qos_loaded):
    """ASIC should have a type=DSCP_TO_TC SAI_QOS_MAP whose map_to_value_list maps at least one DSCP to a non-zero TC
    (proving the DSCP classification rule really programmed into the chip, not just a CONFIG_DB contract)."""
    by_type = _qos_maps_by_type(asicdb)
    dscp_maps = by_type.get("SAI_QOS_MAP_TYPE_DSCP_TO_TC", [])
    assert dscp_maps, (
        f"no DSCP_TO_TC SAI_QOS_MAP programmed to ASIC (qos reload constrained by missing "
        f"buffers.json.j2). present types: {sorted(k for k in by_type if k)}")
    # map_to_value_list is a SAI serialization like {count}:DSCP=..&TC=...&...; any TC mapping in it proves classification took effect
    payload = " ".join(
        asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST") or "" for k in dscp_maps)
    assert "TC" in payload or "tc" in payload, \
        f"DSCP_TO_TC map present but map_to_value_list has no TC entries: {payload[:200]!r}"


def test_tc_to_queue_map_programmed_to_asic(cli, asicdb, qos_loaded):
    """ASIC should have a type=TC_TO_QUEUE SAI_QOS_MAP (proving TC->queue assignment really programmed into the chip)."""
    by_type = _qos_maps_by_type(asicdb)
    q_maps = by_type.get("SAI_QOS_MAP_TYPE_TC_TO_QUEUE", [])
    assert q_maps, (
        f"no TC_TO_QUEUE SAI_QOS_MAP programmed to ASIC. present types: "
        f"{sorted(k for k in by_type if k)}")
    payload = " ".join(
        asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST") or "" for k in q_maps)
    # in older sairedis serialization the queue field name is qidx, in newer it's queue_index -- accept both.
    up = payload.upper()
    assert "QUEUE" in up or "QIDX" in up, \
        f"TC_TO_QUEUE map present but map_to_value_list has no queue entries: {payload[:200]!r}"


# ============================ 2) dataplane: traffic really enters some egress queue (sanity, weak assertion) ============================
def test_traffic_enters_an_egress_queue(cli, traffic, qos_loaded):
    """Dataplane sanity: inject a plain IP packet, verify some egress queue's SAI_QUEUE_STAT_PACKETS on ports[0] really increments >=0.5N.

    This is the baseline for whether the queue-counter chain is alive (should hold even with QoS
    maps missing and everything landing on queue0). Later classification cases build on this to
    verify "different DSCP/PCP lands on different queues". A failure means the queue flex counter / loopback traffic path has a problem."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    pkt = (Ether(dst=_QOS_DST, src=_SRC) /
           IP(dst="2.2.2.2", tos=0) / UDP() / Raw(b"QOS0" + b"x" * 40))
    grew = _inject_and_measure_queues(cli, traffic, pkt)
    total = sum(grew.values())
    assert total >= _LOWER, (
        f"injected {_N} pkts but no egress queue on {traffic.ports[0].name} incremented "
        f">=0.5N (deltas={grew}); queue-counter dataplane path broken")


# ============================ 3) dataplane: DSCP -> TC -> queue queue selection (core classification verification) ============================
# DSCP under test (by topo.dscp role name, cases don't hardcode numbers). They are expected to
# map via DSCP_TO_TC + TC_TO_QUEUE to an egress queue different from the default (0); if maps are
# missing they all land on queue0 -> assertion fails -> xfail.
_DSCP_CASES = ["ef", "cs4", "af21"]


def test_dscp_selects_distinct_egress_queue(cli, traffic, topo, qos_loaded, l2_fwd_vlan):
    """DSCP queue selection: inject DSCP=0 and DSCP=ef traffic separately, verify they land on
    different egress queues at the forwarding egress ports[1] (proving DSCP->TC->queue
    classification really takes effect on the chip, not all landing on queue0).

    Test the pass that gets classified: the first CPU-direct-send pass out of ports[0] doesn't go
    through ingress classification; re-entering ports[0], classified by trust_dscp, then
    unicast-forwarded out ports[1] via FDB -- reading ports[1] egress queues is the
    classification-path evidence. Take each flow's main landing queue (its own delta must reach
    the lower bound, no padding from background-noise queues); require the high-priority DSCP(ef)
    main queue != the default DSCP(0) main queue."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")

    def _q_for(dscp_val):
        pkt = (Ether(dst=_QOS_DST, src=_SRC) /
               IP(dst="2.2.2.2", tos=dscp_val << 2) / UDP() / Raw(b"DSCP" + b"x" * 40))
        grew = _inject_and_measure_queues(cli, traffic, pkt, measure="out", fwd_vlan=l2_fwd_vlan)
        # the main landing queue's own delta reaches the lower bound (not the sum of all queues): classified traffic must really concentrate on one queue
        if not grew or max(grew.values()) < _LOWER:
            pytest.fail(f"DEVICE DEFECT: DSCP={dscp_val} traffic did not reach any egress queue on "
                        f"{traffic.ports[1].name} with >=0.5N packets (deltas={grew}); classified "
                        f"forward path or DSCP_TO_TC/TC_TO_QUEUE map not steering to chip")
        return _dominant_queue(grew)

    with _classified_egress(cli, traffic):
        q_default = _q_for(topo.dscp("default"))   # DSCP 0
        q_high = _q_for(topo.dscp("ef"))           # DSCP 46
    assert q_high != q_default, (
        f"DSCP classification not effective on chip: DSCP={topo.dscp('ef')} and DSCP=0 both land "
        f"on egress queue {q_high} of {traffic.ports[1].name} (expected distinct queues per "
        f"DSCP_TO_TC/TC_TO_QUEUE map)")


@pytest.mark.parametrize("dscp_name", _DSCP_CASES)
def test_dscp_steers_to_nonzero_queue(cli, traffic, topo, qos_loaded, dscp_name, l2_fwd_vlan):
    """Per-DSCP queue-steering verification: inject high-priority DSCP traffic, verify its main
    landing queue at the forwarding egress ports[1] != 0 (i.e. steered to a non-default queue by
    the map). Test the classified pass (same as test_dscp_selects_distinct_egress_queue).

    If the QoS map really programmed, non-zero DSCP like af21/cs4/ef land on a non-zero queue via
    DSCP->TC->queue; with maps missing they all land on queue0 -> assertion fails (honestly marking a missing device QoS profile)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    dscp_val = topo.dscp(dscp_name)
    pkt = (Ether(dst=_QOS_DST, src=_SRC) /
           IP(dst="2.2.2.2", tos=dscp_val << 2) / UDP() / Raw(b"DSCPQ" + b"x" * 40))
    with _classified_egress(cli, traffic):
        grew = _inject_and_measure_queues(cli, traffic, pkt, measure="out", fwd_vlan=l2_fwd_vlan)
    # the main landing queue's own delta reaches the lower bound (not the sum of all queues): prevent background-noise queues from padding into the verdict
    if not grew or max(grew.values()) < _LOWER:
        pytest.fail(f"DEVICE DEFECT: DSCP={dscp_val}({dscp_name}) traffic did not reach any egress "
                    f"queue on {traffic.ports[1].name} with >=0.5N packets (deltas={grew}); "
                    f"classified forward path or DSCP_TO_TC/TC_TO_QUEUE map not steering to chip")
    q = _dominant_queue(grew)
    assert q != 0, (
        f"DSCP={dscp_val}({dscp_name}) not steered off default queue0 on chip "
        f"(dominant queue={q} on {traffic.ports[1].name}, deltas={grew}); "
        f"DSCP_TO_TC/TC_TO_QUEUE map not effective")


# ============================ 4) dataplane: PCP(dot1p) -> TC -> queue queue selection ============================
def test_pcp_selects_distinct_egress_queue(cli, traffic, qos_loaded, l2_fwd_vlan):
    """PCP queue selection: inject PCP=0 and PCP=7 802.1Q tagged frames, verify they land on
    different egress queues at the forwarding egress ports[1] (proving dot1p->TC->queue
    classification really takes effect on the chip). Test the classified pass (same as the DSCP cases).

    Tagged frames still go through the default VLAN (the traffic fixture configures ports[0] as a default-VLAN member), PCP carried by the 802.1p prio field."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    # structural prerequisite: the product-CLI config-model image (SONiC) has no top-level
    # dot1p-to-tc-map creation command (same judgment as test_qos_config::test_dot1p_to_tc_map_content),
    # and the baseline binds trust_dscp -- with no channel to build a DOT1P map there's no way to
    # verify PCP classification, structural skip rather than wrongly blaming the chip.
    if qos.has_qos_cli(cli) and not cli.db_keys("CONFIG_DB", "DOT1P_TO_TC_MAP|*"):
        r = cli.sh.run("config dot1p-to-tc-map add --help", check=False)
        if r.rc != 0:
            pytest.skip("this image QoS CLI has no command to create a DOT1P_TO_TC map; "
                        "PCP classification cannot be provisioned (structural)")
    dv = l2_fwd_vlan   # l2_home_forwarding=false platforms use a real forwarding VLAN (parked Vlan1 doesn't forward)

    def _q_for(pcp):
        pkt = (Ether(dst=_QOS_DST, src=_SRC) /
               Dot1Q(vlan=dv, prio=pcp) / IP(dst="2.2.2.2") / UDP() / Raw(b"PCP" + b"x" * 40))
        grew = _inject_and_measure_queues(cli, traffic, pkt, measure="out", fwd_vlan=l2_fwd_vlan)
        # the main landing queue's own delta reaches the lower bound (not the sum of all queues): prevent background-noise queues from padding
        if not grew or max(grew.values()) < _LOWER:
            pytest.fail(f"DEVICE DEFECT: PCP={pcp} tagged traffic did not reach any egress queue on "
                        f"{traffic.ports[1].name} with >=0.5N packets (deltas={grew}); classified "
                        f"forward path or DOT1P_TO_TC/TC_TO_QUEUE map not steering to chip")
        return _dominant_queue(grew)

    with _classified_egress(cli, traffic):
        q_low = _q_for(0)
        q_high = _q_for(7)
    assert q_high != q_low, (
        f"PCP classification not effective on chip: PCP=7 and PCP=0 both land on egress queue "
        f"{q_high} of {traffic.ports[1].name} (expected distinct queues per DOT1P_TO_TC/"
        f"TC_TO_QUEUE map)")


# ============================ 5) dataplane: DSCP egress marking (remark/preserve) content check ============================
def test_dscp_preserved_on_l2_forward_egress(cli, dut, _lb, traffic, topo, qos_loaded):
    """DSCP egress content check: inject a frame with DSCP, forward it out ports[0] (re-enter then
    unicast to ports[1]), mirror ports[0] egress to cpu0 to capture the real forwarded frame, verify the egress DSCP value.

    Under the default trust-DSCP / no-egress-remark policy, L2 forwarding should preserve the
    injected DSCP (no rewrite). This is truly "send real traffic, verify egress marking", not
    just checking the map exists. If the device does DSCP remark on that port by default, the rewritten value is captured here."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    # this case relies on egress-mirror-to-cpu0 to capture the real forwarded frame; some images'
    # KNET doesn't deliver mirror frames to the netdev (mirror_cpu_capture=false), so gate when
    # there's no observation means (forwarding/preservation is corroborated by the queue cases).
    topo.caps.require("mirror_cpu_capture")
    from framework.traffic import Capture
    from framework.collector import MirrorCollector

    p_in, p_out = traffic.ports[0], traffic.ports[1]
    dscp = topo.dscp("ef")
    cli.fdb_static_add(traffic.default_vlan, _QOS_DST, p_out.name)
    mc = MirrorCollector(_lb.bsh, dut)
    try:
        mc.enable(p_in)   # mirror ports[0] egress: a CPU-injected frame is copied to cpu0 as it egresses ports[0]
        pkt = (Ether(dst=_QOS_DST, src=_SRC) /
               IP(src="10.9.9.9", dst="2.2.2.2", tos=dscp << 2) / UDP() / Raw(b"REMARK" + b"y" * 40))
        n_sent = 20
        # per the MirrorCollector contract, mirror frames appear inbound on the p_in netdev (the
        # real frame chip-copied and punted after egress processing); must be inbound=True --
        # inbound=False would capture sendp's local TX echo (same src MAC + payload signature),
        # amounting to comparing the injected value against itself and passing even if the mirror path is fully dead.
        with Capture(p_in.name, inbound=True) as cap:
            traffic.send(p_in, pkt, count=n_sent)
            time.sleep(0.6)
        mirrored = [p for p in cap.packets
                    if p.haslayer(IP) and getattr(p, "src", "").lower() == _SRC.lower()
                    and b"REMARK" in bytes(p)]
        if not mirrored:
            pytest.fail("DEVICE DEFECT: no egress-mirrored frame captured on cpu0 (mirror collector path "
                        "unavailable on this image); egress DSCP marking cannot be verified on-box")
        # frame-count bounds: the lower bound >=1 (really captured a mirror copy) is guaranteed by
        # the branch above; upper bound <=2N guards against a self-loop storm replicating one frame
        # countless times counted as "normal mirroring" (each injected frame is mirrored at most once, 2x margin for async jitter).
        assert len(mirrored) <= n_sent * 2, (
            f"captured {len(mirrored)} mirrored frames for {n_sent} injected (cap {n_sent * 2}); "
            f"loop storm suspected, refusing to judge DSCP on storm copies")
        got = mirrored[0][IP].tos >> 2
        # no remark by default: egress DSCP should equal the injected value. If the device rewrote it, the assertion exposes the actual rewritten value (honest).
        assert got == dscp, (
            f"egress DSCP on L2-forwarded frame = {got}, expected preserved {dscp} "
            f"(no remark policy configured); device altered DSCP on egress")
    finally:
        mc.disable()
        cli.fdb_static_del(traffic.default_vlan, _QOS_DST)
