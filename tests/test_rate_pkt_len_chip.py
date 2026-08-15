"""Which **packet length** rate limiting / shaping bills against — line length (L1) vs L2 frame.

Background: rate limiting and shaping should bill against line rate (L2 frame + 20 bytes
of wire overhead = preamble + SFD + IPG). A common deviation is an egress shaper that only
adds the 12-byte IPG and misses the 8-byte preamble + SFD, while the ingress meter adds
nothing at all; this makes shaping/policing over-send on small packets, and leaves policing
and shaping accounting for different things.

Chip structure — **all four are controlled by just two per-port fields**:
- `TM_SHAPER_PORT.INTER_FRAME_GAP_BYTE` (hardware `EGR_SHAPING_CONTROL.PACKET_IFG_BYTES`)
  governs the **port shaper + queue shaper**. There is no per-queue IFG field in
  `TM_SHAPER_NODE` at all, so queue shaping can only follow this single per-port value.
- `METER_FP_CONTROL.BYTE_COUNT_ING` (hardware `IFP_METER_CONTROL.PACKET_IFG_BYTES`)
  governs the **port policer + ACL policer**. In vendor-x-sai the port policer is just an
  IFP entry (`_sai_port_policer_group` in `sai_port.c` is a `bcm_field_group_t`), sharing
  the same meter as the ACL policer.
So asserting on these two fields covers all four, without having to actually create
policer/scheduler objects.

**CRC baseline** (the key to making this file's assertions portable across chips): some
datapaths strip the CRC, and the SDK applies a +4 CRC baseline to every port; other
datapaths already include the CRC and have no such layer, giving a baseline of 0. So the
**absolute register value differs across chips** (may be 24, may be 20), but `register -
baseline == 20` holds on both. The baseline is read from the **CPU port** — SAI's global
setting only walks `BCMI_LTSW_PORT_TYPE_PORT` (front-panel ports), leaving the CPU port at
the SDK baseline. Self-calibrating; no hard-coded chip model.

**Do not touch the counters**: `METER_FP_CONTROL.BYTE_COUNT_CTR_ING/EGR` is the compensation
for the port byte counters and must stay at the baseline (= packets counted as L2 incl FCS,
the RFC 2863 convention), pinned by RPL2.
"""
import threading
import time

import pytest

from framework import qmeasure, qos
from framework.lossless import bind_queue, make_scheduler

pytestmark = [pytest.mark.qos, pytest.mark.chiptab]

try:
    from scapy.all import Ether, IP, UDP, Raw  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

# Per-frame Ethernet wire overhead: preamble(7) + SFD(1) + IPG(12)
WIRE_OVERHEAD = 20
FCS = 4

_DST = "00:aa:bb:cc:dd:7a"
_SRC = "00:de:ad:be:ef:7a"


def _baseline(chip):
    """SDK per-device CRC baseline: the CPU port's (PORT_ID=0) INTER_FRAME_GAP_BYTE.

    SAI only programs the convention on front-panel ports; the CPU port stays at the SDK
    baseline, so it can serve as the "zero point". The baseline may be 4 (CRC stripped, SDK
    adds it back) or 0 (datapath already includes the FCS)."""
    ent = chip.lookup("TM_SHAPER_PORT", PORT_ID=0)
    if not ent or not isinstance(ent.get("INTER_FRAME_GAP_BYTE"), int):
        return None
    v = ent["INTER_FRAME_GAP_BYTE"]
    return v if 0 <= v <= FCS else None


def _front_ports(topo, n=3):
    out = []
    for i in range(n):
        try:
            out.append(topo.misc_port(i).name)
        except Exception:  # noqa: BLE001
            break
    return out


def test_rpl1_shaper_and_meter_account_wire_length(cli, chip, topo):
    """RPL1: front-panel port shaper and meter must both add 20 bytes of wire overhead on
    top of the L2 frame, and must be **equal** (if shaper=+12 and meter=+0, they already
    disagree with each other).

    This single check covers port shaping / queue shaping / port policer / ACL policer — see
    the chip-structure note in the module docstring. Portable across chips: it asserts on
    "register - CPU port baseline"."""
    chip.require()
    base = _baseline(chip)
    if base is None:
        pytest.skip("cannot read the SDK CRC baseline from the CPU port "
                    "(TM_SHAPER_PORT PORT_ID=0); without it the register value "
                    "cannot be compared across chips")
    ports = _front_ports(topo)
    if not ports:
        pytest.skip("no front panel port available from topology")
    bad = []
    for name in ports:
        pid = chip.port_id(name)
        sh = chip.lookup("TM_SHAPER_PORT", PORT_ID=pid) or {}
        mt = chip.lookup("METER_FP_CONTROL", PORT_ID=pid) or {}
        sh_v, mt_v = sh.get("INTER_FRAME_GAP_BYTE"), mt.get("BYTE_COUNT_ING")
        if not isinstance(sh_v, int) or not isinstance(mt_v, int):
            pytest.skip(f"{name}: shaper/meter IFG fields not readable "
                        f"(shaper={sh_v!r} meter={mt_v!r}); chip tables differ here")
        # ENCAP=0 means "subtract" rather than "add", flipping the sign of the convention
        if sh.get("INTER_FRAME_GAP_ENCAP") == 0:
            bad.append(f"{name}: INTER_FRAME_GAP_ENCAP=0 (overhead subtracted, "
                       f"not added)")
        if sh_v - base != WIRE_OVERHEAD:
            bad.append(f"{name}: shaper accounts L2+{sh_v - base} "
                       f"(reg={sh_v}, baseline={base}), want L2+{WIRE_OVERHEAD}")
        if mt_v - base != WIRE_OVERHEAD:
            bad.append(f"{name}: meter accounts L2+{mt_v - base} "
                       f"(reg={mt_v}, baseline={base}), want L2+{WIRE_OVERHEAD}")
        if sh_v != mt_v:
            bad.append(f"{name}: shaper({sh_v}) and meter({mt_v}) disagree — "
                       f"policing and shaping would mean different things on the "
                       f"same box")
    assert not bad, (
        "rate accounting is not line rate. A shaper/policer set to X "
        "does not occupy X of wire bandwidth, so it cannot be compared against "
        "SAI_PORT_ATTR_SPEED, and policing and shaping disagree.\n  "
        + "\n  ".join(bad))


def test_rpl2_port_byte_counters_stay_l2(cli, chip, topo):
    """RPL2: the port byte-counter compensation must **stay at the baseline**, and must not
    be dragged along by the rate-accounting convention.

    Per RFC 2863 the byte count in `show interfaces counters` is L2 incl FCS; if
    BYTE_COUNT_CTR_* were also changed to 24, every traffic statistic would gain 20 bytes per
    packet out of nowhere. On some platforms METER_FP_CONTROL has no CTR field (no such
    risk), so skip when the field is absent."""
    chip.require()
    base = _baseline(chip)
    if base is None:
        pytest.skip("SDK CRC baseline unreadable (see rpl1)")
    ports = _front_ports(topo)
    if not ports:
        pytest.skip("no front panel port available from topology")
    checked, bad = 0, []
    for name in ports:
        ent = chip.lookup("METER_FP_CONTROL", PORT_ID=chip.port_id(name)) or {}
        for f in ("BYTE_COUNT_CTR_ING", "BYTE_COUNT_CTR_EGR"):
            v = ent.get(f)
            if not isinstance(v, int):
                continue
            checked += 1
            if v != base:
                bad.append(f"{name}.{f}={v}, want baseline {base}")
    if not checked:
        pytest.skip("this chip has no BYTE_COUNT_CTR_* fields in METER_FP_CONTROL; "
                    "port byte counters cannot be shifted here")
    assert not bad, (
        "port byte counters got shifted along with the rate "
        "accounting; interface octet counts would over-report ~20B per packet "
        "(RFC 2863 wants the L2 frame incl FCS): " + "; ".join(bad))


def _out_pkts(cli, port):
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port}")
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    for f in ("SAI_PORT_STAT_IF_OUT_UCAST_PKTS", "SAI_PORT_STAT_IF_OUT_PKTS"):
        v = h.get(f)
        if v is not None and str(v).isdigit():
            return int(v)
    return None


def _sample_rate(cli, port, window, settle=1.0):
    """Sample the port's egress packet count over `window` seconds, returning (pps, delta).
    The port must stay backlogged throughout, otherwise what is measured is the injection
    rate, not the serve rate — the caller guarantees offered >> shaped."""
    time.sleep(settle)
    c0 = _out_pkts(cli, port)
    t0 = time.time()
    if c0 is None:
        return 0.0, 0
    time.sleep(window)
    c1 = _out_pkts(cli, port)
    t1 = time.time()
    dt = t1 - t0
    if c1 is None or dt <= 0:
        return 0.0, 0
    return (c1 - c0) / dt, (c1 - c0)


@pytest.mark.traffic
def test_rpl3_shaper_serves_by_wire_length(cli, chip, traffic, l2_fwd_vlan, topo):
    """RPL3 behavioral: squeeze the **port** shaper well below the CPU injection rate, flood
    it with **64B minimum frames**, measure egress pps, and back out "how many bytes the chip
    billed per packet" — must be ≈ frame length (incl FCS) + 20, not the frame length.

    Why 64B: it maximizes the proportional difference between conventions — for a 64B frame,
    L1(84B) vs L2(64B) differ by 31%; large packets hide it (1518B differ by only 1.3%, which
    is exactly why "measuring with big packets makes you think it's L2").

    Why the **port** shaper and not the queue shaper: the queue-level
    `TM_SHAPER_NODE.MAX_BANDWIDTH_KBPS` may not accept a small pir — a request for 2Mbps
    actually lands at 100000256 kbps (≈100G, the CLI ceiling), i.e. no rate limit at all (the
    existing CG1 case fails for the same reason, unrelated to this convention change). The
    port-level `port-qos-map -s` -> `TM_SHAPER_PORT.BANDWIDTH_KBPS` converts correctly, and
    the port shaper is itself one of this file's targets under test.

    Back-out formula: shaper serve rate = pir (bytes/s); if the chip bills B bytes per packet,
    then pps = pir / B  =>  B = pir / pps. pir is always read back from the **chip table**;
    the CLI parameter is not trusted.

    VERIFY-ON-HW: thresholds calibrated on first hardware run. This case reliably tells L1(84)
    from L2(64); for the 9.5% gap of "L2+12(76) vs L1(84)", the CPU-injection bench's noise
    cannot resolve it stably — that tier is pinned precisely by RPL1's register assertion, and
    the two are complementary."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    if not qos.has_qos_cli(cli):
        pytest.skip("shaper bench needs the product scheduler CLI")
    r = cli.sh.run("config port-qos-map add --help", check=False)
    if "-s" not in (r.out or ""):
        pytest.skip("product CLI port-qos-map has no -s scheduler knob; no port "
                    "shaper channel on this image")
    p_in, p_out = traffic.ports[0], traffic.ports[1]

    # 64kbps: must be **well** below the CPU injection capability. Measured:
    #   - scapy injection through the kernel netdev tops out at ~400pps, and is **independent
    #     of frame length**;
    #   - at pir=200kbps the shaper passes ~394pps, on par with injection, and both frame
    #     lengths measure the same pps (394.1/394.0) — that measures the injection rate, not
    #     the serve rate, so the back-out necessarily diverges;
    #   - the chip's lower bound for pir is between 50 and 64: 50 is not programmed at all
    #     (BANDWIDTH_KBPS=0), 64 lands exactly at OPER=64kbps, 100 rounds up to OPER=128kbps.
    # Take 64kbps (=8000B/s): 64B passes ~95pps, 516B ~15pps, giving 4x headroom against the
    # ~400pps injection.
    pir_kbps = 64
    ok, undo, why = make_scheduler(cli, "FVTRPL", mode="DWRR", weight=10,
                                   pir=pir_kbps)
    if not ok:
        pytest.skip(f"cannot create shaper: {why}")
    undos = [undo]
    try:
        u = qos.build_baseline(cli, p_out.name, prefix="FVTRPL")
        if u:
            undos.append(u)
        orig_pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
        sub = "update" if orig_pqm else "add"
        cli.config_raw(f"port-qos-map {sub} {p_out.name} -s FVTRPL")
        bound = False
        for _ in range(6):      # rc is not trustworthy: read back CONFIG_DB to decide
            if (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
                    ).get("scheduler"):
                bound = True
                break
            time.sleep(1)
        if not bound:
            pytest.skip("port shaper bind did not land")
        # SONiC has no CLI to unbind the port scheduler field — use GCU to remove it
        # (prevents polluting subsequent cases)
        from framework.gcu import Gcu as _Gcu
        undos.append(lambda: _Gcu(cli).apply_patch(
            [{"op": "remove",
              "path": _Gcu.path("PORT_QOS_MAP", p_out.name, "scheduler")}]))

        # Read the real pir back from the chip (the port-level field is BANDWIDTH_KBPS,
        # different from the queue-level one)
        okc, ent = chip.wait_field(
            lambda: chip.lookup("TM_SHAPER_PORT",
                                PORT_ID=chip.port_id(p_out.name)) or {},
            "BANDWIDTH_KBPS", lambda v: isinstance(v, int) and v > 0, timeout=20)
        got_kbps = (ent or {}).get("BANDWIDTH_KBPS", 0)
        if not okc or not got_kbps:
            pytest.fail(f"port shaper configured but chip "
                        f"TM_SHAPER_PORT.BANDWIDTH_KBPS not programmed (entry={ent}); "
                        f"cannot test rate accounting before the shaper itself works")
        if got_kbps > pir_kbps * 20:
            pytest.skip(f"port shaper pir did not land small enough on this build "
                        f"(asked {pir_kbps}kbps, chip has {got_kbps}kbps): CPU "
                        f"injection cannot saturate it, so serve rate is not "
                        f"observable — the accounting itself is pinned by rpl1")
        # Always take the rate from **OPER**: BANDWIDTH_KBPS is the requested value, and the
        # actual value after the chip rounds up to its granularity is in BANDWIDTH_KBPS_OPER
        # (e.g. request 200 lands at 256, request 100 lands at 128). Backing out from the
        # requested value is systematically low (first run computed a bogus 57B/pkt from 200).
        oper = (ent or {}).get("BANDWIDTH_KBPS_OPER") or got_kbps
        pir_bytes = oper * 1000 / 8.0

        pkt = Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2") / UDP() / Raw(b"R")
        frame = max(len(bytes(pkt)), 60) + FCS      # on-wire L2 frame length (incl FCS, min 64)
        want = frame + WIRE_OVERHEAD

        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                # Keep injecting in the background so offered >> shaped throughout the
                # measurement window (the port never drains)
                stop = threading.Event()

                def _pump():
                    while not stop.is_set():
                        traffic.send(p_in, pkt, count=2000)

                th = threading.Thread(target=_pump, daemon=True)
                th.start()
                try:
                    pps, n = _sample_rate(cli, p_out.name, window=20.0, settle=4.0)
                finally:
                    stop.set()
                    th.join(timeout=60)
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)

        if n < 200:
            pytest.skip(f"only {n} packets left {p_out.name} in the window; the bench "
                        f"never reached steady state (no forwarding to the shaped "
                        f"port, or it never got backlogged)")
        got = pir_bytes / pps if pps > 0 else 0
        detail = (f"pir req={got_kbps}kbps oper={oper}kbps ({pir_bytes:.0f}B/s); "
                  f"{frame}B frame -> {pps:.1f}pps over {n} packets; "
                  f"implied {got:.1f}B accounted per packet (L1 want {want}B, "
                  f"bare L2 would be {frame}B)")
        # Acceptance band (calibrated on first hardware run: at pir=64kbps (OPER 64), a 64B
        # frame is served at 100.2pps -> 79.8B/pkt; L1 theory 84B, bare L2 theory 64B). Take
        # [frame+8, frame+32] i.e. [72,96]: comfortably includes L1(84) and comfortably
        # excludes bare L2(64), with margin covering rate granularity and counter-poll
        # quantization. This bench **cannot resolve** the 8-byte gap between L1(84) and
        # L2+12(76) (both fall in-band); that tier is pinned precisely by RPL1's register
        # assertion, and the two are complementary — do not narrow the band above 76 to "look
        # stricter", that would be fitting noise rather than measuring.
        assert got >= frame + 8, (
            f"the shaper is not accounting the per-frame wire "
            f"overhead — it charges only ~{got:.1f}B for a {frame}B frame, i.e. close "
            f"to the bare L2 frame. A shaper set to R then occupies up to "
            f"R*{want}/{max(got,1):.0f} = {want/max(got,1):.2f}x that much wire "
            f"bandwidth at this frame size. [{detail}]")
        assert got <= frame + 32, (
            f"shaper over-counts per-frame overhead (~{got:.1f}B for a {frame}B "
            f"frame, want ~{want}B): traffic would be throttled below the configured "
            f"rate. [{detail}]")
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_rpl4_ingress_policer_traffic_path_unreachable(cli):
    """RPL4: the ingress policer's **behavioral face** cannot be verified via a production
    path on this image; recorded faithfully.

    - Port policer: no binding CLI (neither `config interface policer` nor `rate-limit`
      exists), same as POL3 in test_policer_chip.py.
    - ACL policer: this aclorch build does not support attaching a policer to an ACL rule.
    - storm control: `_sai_port_storm_control_support = FALSE`
      (`_sai_ltsw_thx_common_features_init()`), does not reach the chip, so it measures
      nothing for rate limiting.

    So the ingress rate-limiting convention is guaranteed by **RPL1's
    `METER_FP_CONTROL.BYTE_COUNT_ING` assertion** — that field is the IFP meter's only byte
    compensation, and when it equals baseline+20 the hardware billing length is L2+20,
    regardless of what CIR is configured. Fabricating an IFP meter via a table-level
    apply-patch does not count as verification (it is not a production path)."""
    def _has_cli(cmd):
        """Same as test_policer_chip._has_cli (tests/ is not a package and cannot be
        imported, so copied in place): can't just look at rc/whether Usage is printed — the
        parent command's error text also carries the word Usage."""
        r = cli.sh.run(f"config {cmd} --help", check=False)
        text = (r.out or "") + (r.err or "")
        return "No such command" not in text and "Usage:" in text

    chans = [c for c in ("interface policer", "interface rate-limit",
                         "interface port-policer") if _has_cli(c)]
    if chans:
        pytest.fail(f"binding channel(s) {chans} now exist — implement the ingress "
                    f"policer traffic bench here (64B frames, offered >> CIR, assert "
                    f"served bytes/packet ≈ frame+{WIRE_OVERHEAD})")
    pytest.skip(
        "COVERAGE GAP (not a defect): no production path binds an ingress policer on "
        "this image (no port-policer CLI, no ACL-rule policer, storm control disabled), "
        "so the policing *behaviour* cannot be traffic-tested here. The "
        "accounting itself is pinned by rpl1 via METER_FP_CONTROL.BYTE_COUNT_ING.")
