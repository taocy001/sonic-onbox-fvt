"""End-to-end RoCE lossless verification -- config provisioned the proper way + SDKLT chip-table final check + PFC-frame / RoCE-packet traffic.

True-lossless criteria (AIDC RoCE template "SDK-layer final check" as test cases):
    PC_PFC enabled AND TM_ING_PORT_PRI_GRP.LOSSLESS=1 AND headroom limit > 0
-- with PFC=1 but LOSSLESS=0 there is no buffer cushion before backpressure engages,
so "lossless" is not actually in effect, and ASIC_DB cannot reveal it.

Test matrix (each case asserts at least one chip-table layer; drives traffic where possible):
  RC1 lossless-chain chip final check (lt)   RC2 buffer value byte->cell conversion (lt)
  RC3 three maps content ASIC pair-by-pair   RC4 PG buffer binding (ASIC IPG object)
  RC5 port PFC bitmap (ASIC)                 RC6 PFCWD config chain (CONFIG/STATE + prior chip evidence)
  RC7 PFC pause-frame injection -> PFC RX counter (traffic)
  RC8 RoCEv2/CNP packet classification and enqueue (traffic, passes via trust_dscp classification)
"""
import time

import pytest

from framework import pfcpkt, qmeasure, qos
from framework.gcu import Gcu
from framework.lossless import build_lossless

pytestmark = [pytest.mark.qos, pytest.mark.roce]

try:
    from scapy.all import Ether, IP, UDP, Raw  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_DSCP, _TC, _PG, _Q = 26, 3, 3, 3      # AIDC template: RoCE data DSCP26 -> q3/PG3 lossless
_CNP_DSCP = 48
_RC_DST = "00:aa:bb:cc:dd:8c"


@pytest.fixture(scope="module")
def ll_pobj(cli, topo):
    """Pick a port with no stale PFC_WD entry: on a port that has one, `pfc priority`
    is refused yet still returns rc=0 (device defect). A stale entry can be cleared with
    the top-level `pfcwd stop <port>`; we still avoid such ports so state left behind by
    a prior aborted run does not skew the verdict."""
    from framework.lossless import pick_pfc_port
    p, why = pick_pfc_port(cli, topo)
    if p is None:
        pytest.skip("no candidate port for PFC tests")
    if why == "all-blocked":
        pytest.fail(
            f"every candidate port carries a stale PFC_WD entry; PFC configuration "
            f"is refused there (CLI still returns rc=0). Clear with top-level "
            f"`pfcwd stop <port>` and rerun (port={p.name}).")
    return p


@pytest.fixture(scope="module")
def ll(cli, ll_pobj, chip):
    """Module-level lossless baseline: build the full chain on a misc port
    (DSCP26->TC3->q3/PG3 + PFC3 + lossless buffer). Per-step success/failure is recorded
    in ll.steps -- each case uses it to distinguish "config channel unavailable (skip)"
    from "provisioning broke the chain (FAIL)"."""
    b = build_lossless(cli, Gcu(cli), ll_pobj.name, dscp=_DSCP, pg=_PG)
    yield b
    b.undo()


def _step_ok(ll_, name):
    return any(s[0] == name and s[1] for s in ll_.steps)


def test_rc1_lossless_chain_chip_final(ll, chip):
    """RC1 chip final check: PG3's PFC bit and LOSSLESS bit + headroom>0. A defect can
    surface here even when ASIC_DB looks all-green -- this is the final criterion for
    "lossless is truly lossless"."""
    chip.require()
    if not _step_ok(ll, "pfc_on"):
        pytest.fail(f"DEVICE DEFECT: `config interface pfc priority` rejected on this "
                    f"image (steps={ll.steps}); PFC provisioning path broken")
    ok_pfc, flags = chip.wait_field(
        lambda: chip.pg_flags(ll.port, ll.pg), "PFC", lambda v: v == 1, timeout=15)
    assert ok_pfc, (
        f"chip TM_ING_PORT_PRI_GRP(port={ll.port}, pg={ll.pg}).PFC != 1 after "
        f"`pfc priority on` (entry={flags}); PFC enable not programmed to chip")
    assert flags.get("LOSSLESS") == 1, (
        f"PFC enabled but LOSSLESS=0 on chip (entry={flags}) — no headroom accounting "
        f"before backpressure kicks in; 'lossless' is not actually lossless")
    if _step_ok(ll, "bind_pg"):
        thd = chip.pg_thd(ll.port, ll.pg)
        assert thd and thd.get("HEADROOM_LIMIT_CELLS", 0) > 0, (
            f"BUFFER_PG bound but chip headroom limit == 0 (entry={thd}); xoff headroom "
            f"not programmed — PFC will drop before pause takes effect")
    else:
        pytest.skip(f"buffer provisioning channel unavailable on this image "
                    f"(steps={ll.steps}); PFC/LOSSLESS bits verified, headroom untestable")


def test_rc2_buffer_values_cells_to_chip(ll, chip):
    """RC2 buffer value conversion: BUFFER_PROFILE.xoff/size(bytes) -> chip cells (±2 cells).
    This verifies "the configured number is the number in the chip", not "the field exists"."""
    chip.require()
    if not _step_ok(ll, "bind_pg"):
        pytest.skip(f"BUFFER_PG provisioning unavailable (steps={ll.steps})")
    if any(s0[0] == "bind_pg" and str(s0[2]).startswith("existing") for s0 in ll.steps):
        # An existing vendor profile (e.g. a vendor-preset buffer profile) has no xoff
        # field and private size semantics -- byte->cell conversion has known semantics
        # only for profiles freshly created by this framework
        pytest.skip(f"existing vendor buffer profile on {ll.port}/pg{ll.pg} "
                    f"(fields={ll.xoff}/{ll.size}); byte->cell semantics vendor-"
                    "specific, numeric compare only valid for FVT-created profiles")
    if not chip.cell_size():
        pytest.skip("cell_size not declared in device profile; refusing to guess "
                    "byte->cell conversion")
    thd = chip.pg_thd(ll.port, ll.pg)
    assert thd, f"chip TM_ING_THD_PORT_PRI_GRP(port={ll.port}, pg={ll.pg}) unreadable"
    want_hdrm = chip.cells(ll.xoff)
    got_hdrm = thd.get("HEADROOM_LIMIT_CELLS", 0)
    assert abs(got_hdrm - want_hdrm) <= 2, (
        f"headroom cells mismatch: profile xoff={ll.xoff}B -> expect ≈{want_hdrm} cells "
        f"(cell={chip.cell_size()}B), chip has {got_hdrm} (entry={thd})")
    want_min = chip.cells(ll.size)
    got_min = thd.get("MIN_GUARANTEE_CELLS", 0)
    assert abs(got_min - want_min) <= 2, (
        f"PG min-guarantee cells mismatch: profile size={ll.size}B -> expect "
        f"≈{want_min} cells, chip has {got_min}")


def test_rc3_lossless_classification_effective(ll, cli, asicdb):
    """RC3 classification-chain **effectiveness** (no longer requires a custom map object
    to exist): the image's built-in default maps must send RoCE DSCP to the lossless TC and
    that TC to the same-numbered queue; and both default maps are truly in the ASIC
    (pair-by-pair content comparison), with the port actually bound to them.

    Design note: TC->PG does not check a map object -- the chip's default identity mapping
    is the production usage, and its effect is covered by RC1/RC2's PG chip bits and
    headroom assertions."""
    bad = [s for s in ll.steps
           if s[0] in ("default_dscp_to_tc", "default_tc_to_queue") and not s[1]]
    assert not bad, (
        f"stock default QoS maps do not carry the lossless classification: {bad}; "
        f"RoCE DSCP{ll.dscp} must reach TC{ll.pg}/queue{ll.pg} without any custom map")

    pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{ll.port}") or {}
    assert pqm.get("dscp_to_tc_map") and pqm.get("tc_to_queue_map"), (
        f"{ll.port} has no dscp_to_tc/tc_to_queue binding in PORT_QOS_MAP ({pqm}); "
        f"classification cannot work")

    want = {ll.dscp: ll.pg}
    found = False
    for k in asicdb.objects("SAI_OBJECT_TYPE_QOS_MAP"):
        if asicdb.field(k, "SAI_QOS_MAP_ATTR_TYPE") != "SAI_QOS_MAP_TYPE_DSCP_TO_TC":
            continue
        pairs = qos.asic_qos_map_pairs(
            asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"), "dscp", "tc")
        if pairs and all(pairs.get(a) == b for a, b in want.items()):
            found = True
            break
    assert found, (
        f"no DSCP_TO_TC SAI_QOS_MAP in ASIC carries {want}; the stock default map is "
        f"not programmed to the chip")

    wantq = {ll.pg: ll.queue}
    foundq = False
    for k in asicdb.objects("SAI_OBJECT_TYPE_QOS_MAP"):
        if asicdb.field(k, "SAI_QOS_MAP_ATTR_TYPE") != "SAI_QOS_MAP_TYPE_TC_TO_QUEUE":
            continue
        pairs = qos.asic_qos_map_pairs(
            asicdb.field(k, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"), "tc", "queue_index")
        if pairs and all(pairs.get(a) == b for a, b in wantq.items()):
            foundq = True
            break
    assert foundq, f"no TC_TO_QUEUE SAI_QOS_MAP in ASIC carries {wantq}"


def test_rc4_buffer_profile_programmed_to_asic(ll, cli, asicdb):
    """RC4 buffer profile reaches ASIC: the configured headroom (xoff) must appear on some
    SAI_OBJECT_TYPE_BUFFER_PROFILE object; if COUNTERS_PG_NAME_MAP can resolve that PG's
    IPG oid, additionally verify it references the profile.

    Method note: on some platforms the ASIC_DB INGRESS_PRIORITY_GROUP object **carries no
    PORT/INDEX attribute** (the object cannot be matched by port), so it cannot be looked up
    by PORT+INDEX; the PG-to-oid correspondence can only go through COUNTERS_PG_NAME_MAP,
    which has entries only after PG counters are enabled. The authoritative chip-side
    evidence is carried by RC2 (headroom cell conversion)."""
    if not _step_ok(ll, "bind_pg"):
        pytest.skip(f"BUFFER_PG provisioning unavailable (steps={ll.steps})")
    if not ll.xoff:
        pytest.skip(f"no headroom/xoff value on profile {ll.profile}; nothing to match")
    want = int(ll.xoff)
    hits = []
    deadline = time.time() + 20
    while time.time() < deadline and not hits:
        for k in asicdb.objects("SAI_OBJECT_TYPE_BUFFER_PROFILE"):
            attrs = cli.db_hgetall("ASIC_DB", k) or {}
            for f, v in attrs.items():
                if "XOFF" in f and str(v).isdigit() and int(v) == want:
                    hits.append((k.split("oid:")[-1], f, v))
        if not hits:
            time.sleep(2)
    assert hits, (
        f"DEVICE DEFECT: no ASIC BUFFER_PROFILE carries the configured headroom "
        f"xoff={want}B for {ll.port}/pg{ll.pg} (profile={ll.profile}); buffer "
        f"profile not programmed to chip")

    pg_oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PG_NAME_MAP {ll.port}:{ll.pg}")
    if not pg_oid:
        print(f"NOTE: COUNTERS_PG_NAME_MAP has no {ll.port}:{ll.pg}; IPG-object "
              f"reference not checkable, chip evidence covered by RC2")
        return
    attrs = cli.db_hgetall(
        "ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:{pg_oid}")
    prof = (attrs or {}).get("SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE")
    assert prof and prof != "oid:0x0", (
        f"DEVICE DEFECT: IPG {pg_oid} ({ll.port}:{ll.pg}) has no BUFFER_PROFILE "
        f"reference in ASIC_DB (attrs={attrs}) although BUFFER_PG is bound")


def test_rc5_port_pfc_bitmap_in_asic(ll, cli, asicdb):
    """RC5 port PFC bitmap: ASIC PORT.PRIORITY_FLOW_CONTROL contains bit3 (cross-checks
    RC1's chip bit -- ASIC has the bit but chip does not = SAI->SDK break; neither has it =
    orchagent break)."""
    if not _step_ok(ll, "pfc_on"):
        pytest.fail(f"DEVICE DEFECT: pfc priority CLI rejected (steps={ll.steps})")
    poid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {ll.port}")
    key = None
    for k in asicdb.objects("SAI_OBJECT_TYPE_PORT"):
        if k.endswith(poid):
            key = k
            break
    assert key, f"ASIC PORT object for {ll.port} ({poid}) not found"
    deadline = time.time() + 30
    val = None
    while time.time() < deadline:
        val = (cli.db_hgetall("ASIC_DB", key) or {}).get(
            "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL")
        if val is not None and str(val).isdigit() and int(val) & (1 << ll.pg):
            return
        time.sleep(0.5)
    pytest.fail(f"DEVICE DEFECT: ASIC PORT PFC bitmap for {ll.port} never contains "
                f"bit{ll.pg} (last={val!r}); `pfc priority on` accepted but not programmed")


def test_rc6_pfcwd_config_chain(ll, cli, chip):
    """RC6 PFCWD config chain: start -> real CONFIG_DB PFC_WD table field values -> stop
    cleanup. Chip precondition: the PFC bit is already present (RC1 evidence chain); without
    PFC, the watchdog is meaningless."""
    if not _step_ok(ll, "pfc_on"):
        pytest.skip("pfc enable unavailable on this image; pfcwd chain untestable")
    # pfcwd goes through the **top-level** command: `config pfcwd stop` takes no port arg
    # (errors out yet still rc=0); the top-level `pfcwd start/stop <port>` is the correct
    # entry point.
    r = cli.run(f"pfcwd start --action drop {ll.port} 200 --restoration-time 400")
    rc = r.rc
    text = ((r.out or "") + (r.err or ""))
    if rc != 0:
        pytest.fail(f"DEVICE DEFECT: pfcwd start rejected on pfc-enabled port: "
                    f"{text[-200:]}")
    try:
        h = {}
        deadline = time.time() + 8
        while time.time() < deadline:
            h = cli.db_hgetall("CONFIG_DB", f"PFC_WD|{ll.port}") or {}
            if h.get("action") == "drop":
                break
            time.sleep(0.5)
        assert h.get("action") == "drop" and h.get("detection_time") == "200" \
            and h.get("restoration_time") == "400", \
            f"PFC_WD CONFIG_DB entry wrong/absent: {h}"
        if chip.available():
            flags = chip.pg_flags(ll.port, ll.pg)
            print(f"chip PG flags under pfcwd: {flags}")
    finally:
        # Must ensure it really stops: a stale PFC_WD entry silently causes later
        # `pfc priority` config to be refused (CLI refusal still returns rc=0), polluting
        # the whole run's results
        for _ in range(3):
            cli.run(f"pfcwd stop {ll.port}")
            if not cli.db_hgetall("CONFIG_DB", f"PFC_WD|{ll.port}"):
                break
            time.sleep(2)
        else:
            pytest.fail(f"CLEANUP FAILURE: PFC_WD|{ll.port} still present after 3 stop "
                        f"attempts; later PFC config on this port will be refused")


@pytest.mark.traffic
def test_rc7_pfc_pause_frame_rx_counter(ll, ll_pobj, cli, _lb, chip):
    """RC7 PFC-frame data plane (no traffic generator needed): build an 802.1Qbb pause frame
    (priority3), inject it into the looped-back port; after the chip MAC recognizes it,
    PFC3_RX_PKTS increments while other priorities' counters stay put (negative control).
    Chip prior evidence: the PC/TM PFC bit (RC1)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    if not _step_ok(ll, "pfc_on"):
        pytest.fail(f"DEVICE DEFECT: pfc enable unavailable (steps={ll.steps}); "
                    "PFC RX accounting untestable without PFC")
    base = pfcpkt.pfc_counters(cli, ll.port)
    if base is None or base["rx"][ll.pg] < 0:
        pytest.skip("PFC per-priority counters not exposed in COUNTERS_DB on this "
                    f"image (base={base}); RX accounting unobservable")
    _lb.enable(ll_pobj)
    try:
        n = 60
        frame = pfcpkt.pfc_frame([ll.pg], quanta=0xFFFF)
        from scapy.all import sendp
        sendp(frame, iface=ll.port, count=n, inter=0.01, verbose=False)
        got = -1
        deadline = time.time() + 15
        while time.time() < deadline:
            cur = pfcpkt.pfc_counters(cli, ll.port)
            got = cur["rx"][ll.pg] - base["rx"][ll.pg]
            if got >= n * 0.5:
                break
            time.sleep(1)
        assert got >= n * 0.5, (
            f"injected {n} PFC pause frames (prio {ll.pg}) into looped-back {ll.port} but "
            f"PFC_{ll.pg}_RX_PKTS moved only {got}; chip does not recognize/account PFC "
            f"on a pfc-enabled port")
        cur = pfcpkt.pfc_counters(cli, ll.port)
        noisy = [i for i in range(8)
                 if i != ll.pg and cur["rx"][i] >= 0 and base["rx"][i] >= 0
                 and cur["rx"][i] - base["rx"][i] > n * 0.5]
        assert not noisy, (
            f"PFC RX counted on unexpected priorities {noisy} (class-vector decode "
            f"error suspected)")
    finally:
        _lb.disable(ll_pobj)


@pytest.mark.traffic
def test_rc8_rocev2_classified_to_lossless_queue(ll, cli, traffic, l2_fwd_vlan):
    """RC8 RoCE packet classification and enqueue (traffic): inject RoCEv2(BTH/UDP4791,
    DSCP26) -> the dominant egress queue == the lossless queue; CNP(DSCP48) lands on a
    different (high-priority) queue.

    **No QoS config at all**: the image's default maps already map DSCP 26->TC3->q3 and
    48->CS6->q6, and every port's PORT_QOS_MAP is bound to default out of the box -- this is
    precisely the production usage. It reads COUNTERS_DB queue counters (chip-counter-layer
    evidence)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{traffic.ports[0].name}") or {}
    if not (pqm.get("dscp_to_tc_map") and pqm.get("tc_to_queue_map")):
        pytest.skip(f"injection port has no stock QoS map binding ({pqm}); "
                    "classification is not provisioned on this image")
    src = "00:de:ad:be:ef:8c"
    roce = pfcpkt.rocev2_pkt(src, _RC_DST, "10.9.9.1", "10.9.9.2", dscp=ll.dscp)
    cnp = pfcpkt.cnp_pkt(src, _RC_DST, "10.9.9.1", "10.9.9.2", dscp=_CNP_DSCP)
    with qmeasure.classified_egress(cli, traffic):
        grew_r = qmeasure.inject_measure(cli, traffic, roce, _RC_DST,
                                         vlan=l2_fwd_vlan)
        q_roce = qmeasure.dominant(grew_r)
        grew_c = qmeasure.inject_measure(cli, traffic, cnp, _RC_DST,
                                         vlan=l2_fwd_vlan)
        q_cnp = qmeasure.dominant(grew_c)
    if q_roce is None or (grew_r and max(grew_r.values()) < 100):
        pytest.fail(f"DEVICE DEFECT: RoCEv2 traffic reached no egress queue with "
                    f">=0.5N (deltas={grew_r}); classification path or queue stats broken")
    assert q_roce == ll.queue, (
        f"RoCEv2 DSCP{ll.dscp} traffic landed on queue {q_roce}, expected lossless "
        f"queue {ll.queue} per the stock DSCP->TC->queue maps (deltas={grew_r})")
    assert q_cnp is not None and q_cnp != q_roce, (
        f"CNP DSCP{_CNP_DSCP} must ride a distinct (high-priority) queue, got "
        f"q_cnp={q_cnp} vs q_roce={q_roce} (deltas={grew_c})")


def test_rc9_non_lossless_pgs_stay_lossy(ll, chip):
    """RC9 **reverse criterion**: only the PG that was configured with PFC may have
    LOSSLESS=1; every other PG on the same port must be 0.

    RC1 verifies "what should be lossless truly is lossless"; this one verifies "what should
    not be lossless is not accidentally lossless" -- neither can be omitted.

    Background: the lossless bit was once preset to 1 on all PGs, so all 8 PGs were accounted
    as lossless. The consequence was not "safer" but a triple breakage:
      1. a lossless PG's overflow goes to XOFF backpressure instead of drop, so
         `SAI_QUEUE_STAT_DROPPED_PACKETS` stays 0 -- the real cause behind the field ticket
         "cannot see queue drop stats";
      2. every PG requests a reservation from the headroom pool, thinning it out instantly;
      3. priorities with no PFC configured also emit pause-frame semantics, making peer
         behavior unpredictable.
    This case is the nail for that regression: the default must not be lossless; lossless
    must be provisioned explicitly."""
    chip.require()
    bad = []
    for pg in range(8):
        if pg == ll.pg:
            continue
        ent = chip.pg_flags(ll.port, pg)
        if not ent:
            continue
        if ent.get("LOSSLESS") == 1:
            bad.append((pg, ent.get("PFC"), ent.get("LOSSLESS")))
    assert not bad, (
        f"port {ll.port}: PG(s) {[b[0] for b in bad]} carry LOSSLESS=1 without being "
        f"the configured lossless priority (pg{ll.pg}); entries(pg,PFC,LOSSLESS)="
        f"{bad}. Lossless must be provisioned explicitly, never defaulted on: "
        f"a lossless PG backpressures instead of dropping, which zeroes the queue "
        f"drop counters and eats headroom pool for priorities nobody configured")
