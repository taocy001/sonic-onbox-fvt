"""Low-rate congestion bench -- use a shaper to push the service rate below the CPU injection
rate, manufacturing **real congestion** on a single box, bringing "requires a traffic
generator" scheduling/ECN/PFC behavior back into on-box testability (VERIFY-ON-HW: calibrate
thresholds on the first hardware run).

Principle: CPU scapy ~1-3kpps; a 1000B frame is ~8-24Mbps. Push the queue/port shaper down to
2-4Mbps, offered > service -> the queue genuinely backs up -> scheduling ratios / WRED-ECN
marking / PG over-limit PFC generation all become observable behavior. The chip runs the same
TM logic at 2Mbps as at 400G, so the functional conclusions are equivalent (performance specs
remain in the traffic-generator domain, not tested here).

Per-case chip-table evidence: TM_SHAPER_NODE (rate cap actually in effect) / TM_WRED_UC_Q.ECN /
TM_ING_PORT_PRI_GRP.PFC + PFC TX counters.

Evaluation of the "hairpin-storm congestion" alternatives:
- Flood-type hairpin storm (two loopback ports cross-feeding inside an isolated VLAN) **cannot
  test UC queue scheduling** -- flooded frames take the multicast replication path and enter the
  **MC queue** on egress, bypassing the q0-7 UC scheduler nodes;
- Unicast ping-pong type (asymmetric PVID makes frames bounce endlessly between two ports) is
  workable in principle and rate self-limiting, but sustained line-rate loopback risks polluting
  later cases;
- so this file sticks with the shaper low-rate congestion bench: same TM logic, 2Mbps behaves
  equivalently to 400G, zero risk. The line-rate version is left to the performance round with a
  traffic generator.
"""
import time

import pytest

from framework import pfcpkt, qmeasure, qos
from framework.gcu import Gcu
from framework.lossless import bind_queue, build_lossless, make_scheduler

pytestmark = [pytest.mark.qos, pytest.mark.congestion, pytest.mark.traffic,
              pytest.mark.chiptab]

try:
    from scapy.all import Ether, IP, UDP, Raw  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_DST = "00:aa:bb:cc:dd:c9"
_SRC = "00:de:ad:be:ef:c9"
_PIR = 250_000            # bytes/s = 2Mbps, far below CPU injection capacity -> guaranteed congestion
_PAYLOAD = 950            # ~1000B frame


def _verify_shaper_gone(cli, port, q, name="FVTCGS"):
    """Confirm the small queue shaper was actually removed. A leftover = the port stays rate-limited to
    pir, and every later traffic case would "never reach the queue", so the caller must hard-fail
    rather than silently continue."""
    for _ in range(6):
        qh = cli.db_hgetall("CONFIG_DB", f"QUEUE|{port}|{q}") or {}
        sh = (qh.get("scheduler", "") or "").strip("[]").split("|")[-1]
        if sh != name and not cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{name}"):
            return True
        time.sleep(1)
    return False


def _mk_queue_shaper(cli, port, q, pir):
    """Install a small shaper on queue q of port (pir argument in bytes/s). Product CLI preferred
    (its -pr takes Kbps, converted internally), community GCU writes bytes/s directly. Returns (ok, undo, why)."""
    name = "FVTCGS"
    if qos.has_qos_cli(cli):
        ok, undo_s, why = make_scheduler(cli, name, mode="DWRR", weight=50,
                                         pir=max(1, pir * 8 // 1000))
        if not ok:
            return False, lambda: None, f"scheduler add (with pir) rejected: {why}"
        cfg = cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{name}") or {}
        if "pir" not in cfg:
            undo_s()
            return False, lambda: None, f"scheduler CLI has no pir knob (cfg={cfg})"
        ok2, undo_q = bind_queue(cli, port, q, sched=name)
        if not ok2:
            undo_s()
            return False, lambda: None, "port-queue bind rejected"
        def _undo_cli():
            undo_q()
            undo_s()
            if not _verify_shaper_gone(cli, port, q):
                pytest.fail(
                    f"CLEANUP FAILURE: queue shaper still bound on {port} q{q} after "
                    f"undo; that port stays rate-limited to {pir}B/s and will poison "
                    f"every later traffic case. Remove SCHEDULER|FVTCGS and the "
                    f"QUEUE|{port}|{q} binding by hand before rerunning.")
        return True, _undo_cli, ""
    gcu = Gcu(cli)
    r1 = gcu.apply_patch(gcu.add_entry(
        "SCHEDULER", name,
        {"type": "DWRR", "weight": "50", "meter_type": "bytes",
         "pir": str(pir), "pbs": "8192"}))
    if r1.rc != 0:
        return False, lambda: None, f"GCU SCHEDULER rejected: {(r1.out or r1.err or '')[-160:]}"
    r2 = gcu.apply_patch(gcu.add_entry("QUEUE", f"{port}|{q}", {"scheduler": name}))
    if r2.rc != 0:
        gcu.apply_patch(gcu.remove_entry("SCHEDULER", name))
        return False, lambda: None, f"GCU QUEUE bind rejected: {(r2.out or r2.err or '')[-160:]}"

    def _undo():
        gcu.apply_patch(gcu.remove_entry("QUEUE", f"{port}|{q}"))
        gcu.apply_patch(gcu.remove_entry("SCHEDULER", name))
    return True, _undo, ""


def _out_octets(cli, port):
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port}")
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get("SAI_PORT_STAT_IF_OUT_OCTETS")
    return int(v) if v is not None and str(v).isdigit() else None


def test_cg1_queue_shaper_caps_egress_rate(cli, chip, traffic, l2_fwd_vlan):
    """CG1 shaper rate-cap behavior: q0 pushed to 2Mbps, inject a ~8Mbps-equivalent burst; within the
    measurement window the egress byte rate must be capped to the pir order of magnitude (chip
    evidence: TM_SHAPER_NODE.MAX_BANDWIDTH_KBPS actually programmed). This is the shaper's
    **behavioral** verification."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_out = traffic.ports[1]
    ok, undo, why = _mk_queue_shaper(cli, p_out.name, 0, _PIR)
    if not ok:
        pytest.skip(f"no channel to install a queue shaper on this image: {why}")
    try:
        want_kbps = _PIR * 8 // 1000
        okc, ent = chip.wait_field(
            lambda: chip.shaper_node(p_out.name, 0), "MAX_BANDWIDTH_KBPS",
            lambda v: 0 < v <= want_kbps * 2, timeout=15)
        if not okc:
            pytest.fail(f"DEVICE DEFECT: shaper configured (pir={_PIR}B/s) but chip "
                        f"TM_SHAPER_NODE not programmed (entry={ent}); rate-cap chain "
                        f"broken before behavior can be tested")
        n = 1500
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=0)
               / UDP() / Raw(b"CG1" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                base = _out_octets(cli, p_out.name)
                if base is None:
                    pytest.skip("IF_OUT_OCTETS not collected on this image; egress "
                                "rate unobservable")
                t0 = time.time()
                traffic.send(traffic.ports[0], pkt, count=n)
                # measurement window: a fixed 8s after send start (includes the send period); egress bytes should be ~pir*window
                while time.time() - t0 < 8:
                    time.sleep(0.5)
                delta = (_out_octets(cli, p_out.name) or base) - base
                window = time.time() - t0
                cap = _PIR * window * 2.0 + 20_000     # 2x tolerance + counter noise
                floor = _PIR * window * 0.1
                assert delta <= cap, (
                    f"egress NOT rate-capped: {delta}B in {window:.1f}s "
                    f"(≈{delta * 8 / window / 1e6:.1f}Mbps) vs pir 2Mbps — chip shaper "
                    f"programmed ({ent.get('MAX_BANDWIDTH_KBPS')}kbps) but not enforcing")
                assert delta >= floor, (
                    f"no traffic served through shaped queue ({delta}B in "
                    f"{window:.1f}s); queue wedged rather than shaped")
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
    finally:
        undo()


def test_cg2_dwrr_ratio_under_congestion(cli, chip, traffic, topo, l2_fwd_vlan):
    """CG2 DWRR service ratio: two queues with 80/20 weights + whole-egress-port rate cap to create a
    common bottleneck; after pre-filling backlog with two flows, measure the two queues' service
    volume ratio ~4:1 within the congestion window (±0.5 order-of-magnitude tolerance, VERIFY-ON-HW
    first-run calibration). Needs a port-level shaper channel; skip honestly if there is none."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    if not qos.has_qos_cli(cli):
        pytest.skip("port-level shaper channel unknown on community image; "
                    "DWRR-ratio bench needs product port-qos-map -s (VERIFY-ON-HW)")
    r = cli.sh.run("config port-qos-map add --help", check=False)
    if "-s" not in (r.out or ""):
        pytest.skip("product CLI port-qos-map has no -s scheduler knob; no port "
                    "shaper channel for a common bottleneck")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    gcu = Gcu(cli)
    b = build_lossless(cli, gcu, p_in.name, dscp=10, pg=1, prefix="FVTCG2A")
    undos = [b.undo]
    try:
        # second flow DSCP18 -> TC2 -> q2; each queue gets a DWRR weight 80/20; port shaping 4Mbps
        okm, viam, tm = True, "", ""
        for cmd in (f"dscp-to-tc-map add FVTCG2A_D2T -d 18 -t {qos.tc_name(2)}",
                    f"tc-to-queue-map add FVTCG2A_T2Q -t {qos.tc_name(2)} -q 2"):
            rc, rr = cli.config_raw(cmd)
            if rc != 0:
                pytest.skip(f"cannot provision second flow map: "
                            f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        ok1, u1, w1 = make_scheduler(cli, "FVTCG2W8", mode="DWRR", weight=80)
        ok2, u2, w2 = make_scheduler(cli, "FVTCG2W2", mode="DWRR", weight=20)
        okp, up, wp = make_scheduler(cli, "FVTCG2P", mode="DWRR", weight=50,
                                     pir=4_000)   # CLI unit is Kbps: 4Mbps port bottleneck
        undos += [u1, u2, up]
        if not (ok1 and ok2 and okp):
            pytest.skip(f"scheduler provisioning incomplete for ratio bench: "
                        f"{[w for w in (w1, w2, wp) if w]}")
        okb1, ub1 = bind_queue(cli, p_out.name, 1, sched="FVTCG2W8")
        okb2, ub2 = bind_queue(cli, p_out.name, 2, sched="FVTCG2W2")
        undos += [ub1, ub2]
        orig_pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
        sub = "update" if orig_pqm else "add"
        rc, rr = cli.config_raw(f"port-qos-map {sub} {p_out.name} -s FVTCG2P")
        # rc is not trustworthy: read back PORT_QOS_MAP.scheduler for the verdict
        bound = False
        for _ in range(5):
            if (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
                    ).get("scheduler"):
                bound = True
                break
            time.sleep(1)
        if not bound:
            pytest.skip(f"port shaper bind did not land ({sub}): "
                        f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        # SONiC has no CLI to unbind a port scheduler (neither update -s '' nor port-qos-map del clears
        # that field); a leftover scheduler would rate-limit p_out and pollute later traffic cases; the
        # only workable config path is GCU-deleting the /PORT_QOS_MAP/<port>/scheduler field (see
        # hygiene.sweep_test_qos_artifacts).
        from framework.gcu import Gcu as _Gcu
        undos.append(lambda: _Gcu(cli).apply_patch(
            [{"op": "remove", "path": _Gcu.path("PORT_QOS_MAP", p_out.name, "scheduler")}]))
        if not (okb1 and okb2):
            pytest.skip("queue scheduler binds incomplete")
        w8 = chip.sched_node(p_out.name, 1)
        w2 = chip.sched_node(p_out.name, 2)
        assert w8 and w8.get("WEIGHT") == 80 and w2 and w2.get("WEIGHT") == 20, (
            f"chip TM_SCHEDULER_NODE weights not programmed: q1={w8} q2={w2}")
        pkt1 = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=10 << 2)
                / UDP() / Raw(b"CG2A" + b"x" * _PAYLOAD))
        pkt2 = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=18 << 2)
                / UDP() / Raw(b"CG2B" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                # pre-fill backlog (alternating small batches to approximate concurrency)
                for _ in range(6):
                    traffic.send(p_in, pkt1, count=150)
                    traffic.send(p_in, pkt2, count=150)
                oids = qmeasure.queue_oids(cli, p_out.name)
                if 1 not in oids or 2 not in oids:
                    pytest.fail("queue oids for q1/q2 missing in COUNTERS map")
                t0 = {q: qmeasure.queue_stat(cli, oids[q]) for q in (1, 2)}
                # keep supplying flow within the congestion window and measure the two queues' service volume
                for _ in range(4):
                    traffic.send(p_in, pkt1, count=150)
                    traffic.send(p_in, pkt2, count=150)
                time.sleep(4)
                t1 = {q: qmeasure.queue_stat(cli, oids[q]) for q in (1, 2)}
                s1, s2 = t1[1] - t0[1], t1[2] - t0[2]
                if s1 + s2 < 100:
                    pytest.fail(f"DEVICE DEFECT: queue counters barely moved "
                                f"(q1+{s1}, q2+{s2}) under sustained congestion; "
                                f"queue stats frozen or port wedged")
                ratio = s1 / max(s2, 1)
                assert 2.0 <= ratio <= 8.0, (
                    f"DWRR 80:20 service ratio out of band: q1={s1} q2={s2} "
                    f"ratio={ratio:.2f} (expected ≈4.0, band [2,8] — VERIFY-ON-HW "
                    f"calibration; persistent violation = scheduler weights not "
                    f"honored in arbitration)")
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_cg5_sp_dominates_weighted_under_congestion(cli, chip, traffic, topo,
                                                    l2_fwd_vlan):
    """CG5 strict-priority behavior (CG2 only verified the DWRR ratio; SP's **service behavior** has
    zero coverage): q5=STRICT, q1=DWRR w20, whole-egress-port cap at 4Mbps to create a common
    bottleneck, EF(dscp46)->q5 and AF1(dscp10)->q1 concurrent flows -> within the congestion window
    the SP queue's service volume must significantly dominate the weighted queue (band:
    sp/weighted >= 3, VERIFY-ON-HW first-run calibration; SP entirely starving the low queue is
    also legal behavior, so no lower bound is set on weighted).
    Chip prerequisite: TM_SCHEDULER_NODE q5 SCHED_MODE=SP, q1 WEIGHT=20 actually programmed.
    Classification uses build_baseline's trust_dscp default table (46->EF->q5, 8-15->AF1->q1).

    Known jitter (infrastructure layer, not this case's assertions):
    (1) the traffic fixture's smoke_check occasionally fails (loopback link has second-scale
        propagation jitter, already retried inside the fixture);
    (2) occasional q5+0/q1+0 (static FDB landing in ASIC is a race -> frames take the flood/MC
        queue) -- reruns pass;
    only continuously reproducible zero counts are treated as a DEVICE DEFECT (counter-frozen class)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    if not qos.has_qos_cli(cli):
        pytest.skip("SP-vs-weighted bench needs the product port-shaper channel "
                    "(port-qos-map -s) for a common bottleneck; unknown on community")
    r = cli.sh.run("config port-qos-map add --help", check=False)
    if "-s" not in (r.out or ""):
        pytest.skip("product CLI port-qos-map has no -s scheduler knob")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    for q in (1, 5):
        if cli.db_hgetall("CONFIG_DB", f"QUEUE|{p_out.name}|{q}"):
            pytest.skip(f"{p_out.name} q{q} already bound; refusing to clobber "
                        f"existing scheduling config")
    undos = []
    try:
        u = qos.build_baseline(cli, p_in.name, prefix="FVTCG5")
        if u:
            undos.append(u)
        ok1, u1, w1 = make_scheduler(cli, "FVTCG5SP", mode="STRICT")
        ok2, u2, w2 = make_scheduler(cli, "FVTCG5W2", mode="DWRR", weight=20)
        # bottleneck 1Mbps: must be well below the scapy injection average rate (at 4Mbps it does not
        # saturate, both flows fully drain and the ratio stays ~1) -- pre-filling ~14Mb of backlog at
        # 1Mbps keeps real congestion across the whole measurement window.
        okp, up, wp = make_scheduler(cli, "FVTCG5P", mode="DWRR", weight=50,
                                     pir=1_000)   # CLI unit is Kbps: 1Mbps port bottleneck
        undos += [u1, u2, up]
        if not (ok1 and ok2 and okp):
            pytest.skip(f"scheduler provisioning incomplete: "
                        f"{[w for w in (w1, w2, wp) if w]}")
        okb1, ub1 = bind_queue(cli, p_out.name, 5, sched="FVTCG5SP")
        okb2, ub2 = bind_queue(cli, p_out.name, 1, sched="FVTCG5W2")
        undos += [ub1, ub2]
        if not (okb1 and okb2):
            pytest.skip("queue scheduler binds incomplete")
        orig_pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
        sub = "update" if orig_pqm else "add"
        rc, rr = cli.config_raw(f"port-qos-map {sub} {p_out.name} -s FVTCG5P")
        bound = False
        for _ in range(5):      # rc is not trustworthy: read back PORT_QOS_MAP.scheduler for the verdict
            if (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
                    ).get("scheduler"):
                bound = True
                break
            time.sleep(1)
        if not bound:
            pytest.skip(f"port shaper bind did not land ({sub}): "
                        f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        # SONiC has no CLI to unbind the port scheduler field -- same as CG2, only GCU-deleting the field can clear it (prevents polluting later cases)
        from framework.gcu import Gcu as _Gcu
        undos.append(lambda: _Gcu(cli).apply_patch(
            [{"op": "remove",
              "path": _Gcu.path("PORT_QOS_MAP", p_out.name, "scheduler")}]))
        # closed-loop calibration that the bottleneck is really programmed: read TM_SHAPER_PORT.BANDWIDTH_KBPS
        # (the port-level table field name differs from the queue-level TM_SHAPER_NODE's MAX_BANDWIDTH_KBPS).
        # If deviation is >2x, back-compute the parameter from the deviation and rebind once; a normal build
        # takes zero extra operations.
        want_kbps = 1_000
        okc, pent = chip.wait_field(
            lambda: chip.lookup("TM_SHAPER_PORT",
                                PORT_ID=chip.port_id(p_out.name)) or {},
            "BANDWIDTH_KBPS", lambda v: isinstance(v, int) and v > 0, timeout=20)
        got = (pent or {}).get("BANDWIDTH_KBPS", 0)
        if not okc or not got:
            pytest.skip(f"port shaper not visible in chip TM_SHAPER_PORT ({pent}); "
                        "no common bottleneck -> ratio bench meaningless")
        if got > want_kbps * 2:
            arg2 = max(1, want_kbps * want_kbps // got)
            okp2, up2, wp2 = make_scheduler(cli, "FVTCG5P2", mode="DWRR", weight=50,
                                            pir=arg2)
            if okp2:
                undos.append(up2)
                cli.config_raw(f"port-qos-map update {p_out.name} -s FVTCG5P2")
                okc2, pent2 = chip.wait_field(
                    lambda: chip.lookup("TM_SHAPER_PORT",
                                        PORT_ID=chip.port_id(p_out.name)) or {},
                    "BANDWIDTH_KBPS",
                    lambda v: isinstance(v, int) and 0 < v <= want_kbps * 2, timeout=20)
                assert okc2, (
                    f"pir closed-loop calibration failed: retry arg {arg2}Kbps "
                    f"still lands chip BANDWIDTH={((pent2 or {}).get('BANDWIDTH_KBPS'))} "
                    f"(first try {got}); cannot build a real bottleneck")
        # chip prerequisite: SP/weight really programmed (how to read it: SP via the node's SCHED_MODE;
        # weighted via WEIGHT; the node "RR" symbol does not distinguish WRR/DRR -- see the
        # test_qos_shaper_chip module docstring)
        oksp, esp = chip.wait_field(
            lambda: chip.sched_node(p_out.name, 5), "SCHED_MODE",
            lambda v: v == "SP", timeout=30)
        assert oksp, f"q5 STRICT not programmed to chip before bench: {esp}"
        w2e = chip.sched_node(p_out.name, 1)
        assert w2e and w2e.get("WEIGHT") == 20, \
            f"q1 DWRR w20 not programmed to chip before bench: {w2e}"
        pkt_sp = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=46 << 2)
                  / UDP() / Raw(b"CG5A" + b"x" * _PAYLOAD))
        pkt_w = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=10 << 2)
                 / UDP() / Raw(b"CG5B" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                for _ in range(6):          # pre-fill backlog (alternating small batches to approximate concurrency)
                    traffic.send(p_in, pkt_sp, count=150)
                    traffic.send(p_in, pkt_w, count=150)
                oids = qmeasure.queue_oids(cli, p_out.name)
                if 1 not in oids or 5 not in oids:
                    pytest.fail("queue oids for q1/q5 missing in COUNTERS map")
                t0 = {q: qmeasure.queue_stat(cli, oids[q]) for q in (1, 5)}
                for _ in range(4):          # keep supplying flow within the congestion window
                    traffic.send(p_in, pkt_sp, count=150)
                    traffic.send(p_in, pkt_w, count=150)
                time.sleep(4)
                t1 = {q: qmeasure.queue_stat(cli, oids[q]) for q in (1, 5)}
                s_sp, s_w = t1[5] - t0[5], t1[1] - t0[1]
                if s_sp + s_w < 100:
                    pytest.fail(f"DEVICE DEFECT: queue counters barely moved "
                                f"(q5+{s_sp}, q1+{s_w}) under sustained congestion; "
                                f"stats frozen or port wedged")
                ratio = s_sp / max(s_w, 1)
                assert ratio >= 3.0, (
                    f"strict-priority q5 did not dominate weighted q1 under a common "
                    f"4Mbps bottleneck: q5={s_sp} q1={s_w} ratio={ratio:.2f} "
                    f"(expected >=3, SP may legally starve q1 entirely — persistent "
                    f"violation = SP not honored in arbitration)")
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_cg3_wred_ecn_marks_under_congestion(cli, chip, traffic, l2_fwd_vlan):
    """CG3 ECN marking behavior: q0 rate cap + small-threshold WRED(ECN) + ECT(0) traffic burst ->
    that queue's WRED_ECN_MARKED counter increments (chip evidence: TM_WRED_UC_Q.ECN=1).
    Previously ECN only verified object-enumeration validity; marking behavior had zero coverage."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_out = traffic.ports[1]
    ok, undo, why = _mk_queue_shaper(cli, p_out.name, 0, _PIR)
    if not ok:
        pytest.skip(f"no queue shaper channel: {why}")
    undos = [undo]
    try:
        if qos.has_qos_cli(cli):
            rc, rr = cli.config_raw(
                "wred-profile add FVTCG3W -en true -ecn ecn_all "
                "-gmin 4000 -gmax 40000 -ymin 4000 -ymax 40000 "
                "-rmin 4000 -rmax 40000")
            if rc != 0:
                pytest.skip(f"wred-profile add rejected: "
                            f"{((rr.out or '') + (rr.err or ''))[-140:]}")
            undos.append(lambda: cli.config_raw("wred-profile del FVTCG3W"))
            # the queue was already bound by _mk_queue_shaper: the CLI has no update semantics (a
            # repeat add reports "already exists"), so delete then rebind with wred
            cli.config_raw(f"port-queue del {p_out.name} 0")
            time.sleep(1)
            rc, rr = cli.config_raw(f"port-queue add {p_out.name} 0 -s FVTCGS "
                                    f"-w FVTCG3W")
            wred_bound = False
            for _ in range(5):     # rc is not trustworthy: read back QUEUE.wred_profile
                if (cli.db_hgetall("CONFIG_DB", f"QUEUE|{p_out.name}|0") or {}
                        ).get("wred_profile"):
                    wred_bound = True
                    break
                time.sleep(1)
            if not wred_bound:
                pytest.skip(f"port-queue wred rebind did not land: "
                            f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        else:
            gcu = Gcu(cli)
            r1 = gcu.apply_patch(gcu.add_entry(
                "WRED_PROFILE", "FVTCG3W",
                {"wred_green_enable": "true", "ecn": "ecn_all",
                 "green_min_threshold": "4000", "green_max_threshold": "40000",
                 "green_drop_probability": "100"}))
            if r1.rc != 0:
                pytest.skip(f"GCU WRED_PROFILE rejected: "
                            f"{(r1.out or r1.err or '')[-140:]}")
            undos.append(lambda: gcu.apply_patch(
                gcu.remove_entry("WRED_PROFILE", "FVTCG3W")))
            r2 = gcu.apply_patch([{"op": "add",
                                   "path": gcu.path("QUEUE", f"{p_out.name}|0")
                                   + "/wred_profile", "value": "FVTCG3W"}])
            if r2.rc != 0:
                pytest.skip(f"GCU QUEUE wred bind rejected: "
                            f"{(r2.out or r2.err or '')[-140:]}")
        okw, went = chip.wait_field(
            lambda: chip.wred_uc_q(p_out.name, 0) or {}, "ECN",
            lambda v: v == 1, timeout=15) if chip.has_table("TM_WRED_UC_Q") else (None, None)
        if okw is False:
            pytest.fail(f"DEVICE DEFECT: WRED/ECN not programmed to chip "
                        f"TM_WRED_UC_Q (entry={went}) though CONFIG accepted")
        n = 1200
        # ECT(0)=0b10: the IP ECN field declares the packet is markable
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=(0 << 2) | 2)
               / UDP() / Raw(b"CG3" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            grew = qmeasure.inject_measure(
                cli, traffic, pkt, _DST, count=n, vlan=l2_fwd_vlan,
                field="SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS", lower=1)
        marked = sum(grew.values())
        assert marked > 0, (
            f"no WRED_ECN_MARKED packets counted on {p_out.name} despite shaped-queue "
            f"congestion with ECT(0) traffic (deltas={grew}); ECN marking chain "
            f"(WRED bind -> chip curve -> CE mark) not effective"
            + ("" if okw is None else f"; chip TM_WRED_UC_Q={went}"))
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_cg4_pfc_tx_generated_on_pg_congestion(cli, chip, traffic, l2_fwd_vlan):
    """CG4 PFC generation (PFC TX verification without a traffic generator): ingress-port lossless
    chain (small static_th) + egress q3 rate cap -> PG3 backlog exceeds the limit -> the chip sends
    PFC -> PFC_3_TX_PKTS increments.
    Chip prerequisite: TM_ING_PORT_PRI_GRP.PFC=1 (same as RC1). VERIFY-ON-HW."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    gcu = Gcu(cli)
    b = build_lossless(cli, gcu, p_in.name, dscp=26, pg=3,
                       headroom_bytes=40_000, min_bytes=5_000,
                       static_th_bytes=60_000, dynamic_th=None, prefix="FVTCG4")
    undos = [b.undo]
    try:
        if not any(s[0] == "pfc_on" and s[1] for s in b.steps):
            pytest.skip(f"pfc enable unavailable (steps={b.steps}); PFC TX bench "
                        "needs PFC")
        if not any(s[0] == "bind_pg" and s[1] for s in b.steps):
            pytest.skip(f"lossless buffer provisioning unavailable (steps={b.steps})")
        # shrink the PG shared threshold (static) so that ~1MB of backlog already exceeds the limit
        r = gcu.apply_patch([{"op": "add",
                              "path": gcu.path("BUFFER_PROFILE", "FVTCG4_prof")
                              + "/static_th", "value": "60000"}])
        if r.rc != 0:
            pytest.skip(f"cannot set small static_th: {(r.out or r.err or '')[-140:]}")
        ok, undo, why = _mk_queue_shaper(cli, p_out.name, 3, _PIR)
        if not ok:
            pytest.skip(f"no queue shaper channel on egress q3: {why}")
        undos.append(undo)
        base = pfcpkt.pfc_counters(cli, p_in.name)
        if base is None or base["tx"][3] < 0:
            pytest.skip("PFC TX counters not exposed on this image")
        pkt = pfcpkt.rocev2_pkt(_SRC, _DST, "10.9.9.1", "10.9.9.2", dscp=26,
                                payload=_PAYLOAD)
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                for _ in range(6):
                    traffic.send(p_in, pkt, count=250)
                got = 0
                deadline = time.time() + 15
                while time.time() < deadline:
                    cur = pfcpkt.pfc_counters(cli, p_in.name)
                    got = cur["tx"][3] - base["tx"][3]
                    if got > 0:
                        break
                    time.sleep(1)
                assert got > 0, (
                    f"no PFC_3_TX_PKTS generated on {p_in.name} despite PG3 pressure "
                    f"(lossless+static_th 60KB, egress q3 shaped to 2Mbps, ~1.5MB "
                    f"offered); PFC generation chain (PG accounting -> xoff -> MAC "
                    f"pause TX) not effective — VERIFY-ON-HW: check PG watermark to "
                    f"confirm backlog actually crossed threshold")
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# CG6-CG8: supplements for queue stats / ECN stats / scheduling behavior.
# Background and companion: field-existence guards are in test_queue_stats_fields.py
# (run the field guards first, then look at behavioral attribution).
# ---------------------------------------------------------------------------

def _cint_run(cli, chip, name, text):
    """Send a cint snippet into syncd for execution and return the output. The file write goes via
    base64 (escape-free), the execution goes through chip's BcmShell channel. Used only by CG7's
    queue-threshold fixture -- a controlled chip write of the same nature as bcmcmd lb=, restored in
    pairs (see the discipline note in the CG7 docstring)."""
    import base64 as _b64
    b64 = _b64.b64encode(text.encode()).decode()
    r = cli.sh.run(f"echo {b64} | base64 -d > /tmp/{name} && "
                   f"docker cp /tmp/{name} syncd:/{name} && rm -f /tmp/{name}",
                   check=False)
    if r.rc != 0:
        pytest.skip(f"cannot stage cint file into syncd: {(r.err or r.out or '')[-120:]}")
    return chip.bsh.cmd(f"cint /{name}") or ""


def _cint_rvs_ok(out, tags):
    """Check that every tagged line in the cint output has rv=0."""
    bad = []
    for t in tags:
        line = next((l for l in out.splitlines() if t in l), None)
        if line is None or "rv=0" not in line:
            bad.append(line or f"{t}: <no output>")
    return bad


def test_cg6_wred_drops_counted_for_non_ect(cli, chip, traffic, l2_fwd_vlan):
    """CG6 WRED drop counting: the same congestion bench as CG3 (q0 rate cap + small-threshold
    WRED/ecn_all), but inject **non-ECT** traffic (IP ECN=00) -- WRED can only drop packets that are
    not markable -> SAI_QUEUE_STAT_WRED_DROPPED_PACKETS must increment. This is the counterpart to
    CG3 (ECT traffic -> marking count); together they pin both of WRED's drop/mark outcomes to
    counters.
    VERIFY-ON-HW: calibrate the lower threshold on the first hardware run."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_out = traffic.ports[1]
    ok, undo, why = _mk_queue_shaper(cli, p_out.name, 0, _PIR)
    if not ok:
        pytest.skip(f"no queue shaper channel: {why}")
    undos = [undo]
    try:
        if qos.has_qos_cli(cli):
            rc, rr = cli.config_raw(
                "wred-profile add FVTCG6W -en true -ecn ecn_all "
                "-gmin 4000 -gmax 40000 -ymin 4000 -ymax 40000 "
                "-rmin 4000 -rmax 40000")
            if rc != 0:
                pytest.skip(f"wred-profile add rejected: "
                            f"{((rr.out or '') + (rr.err or ''))[-140:]}")
            undos.append(lambda: cli.config_raw("wred-profile del FVTCG6W"))
            cli.config_raw(f"port-queue del {p_out.name} 0")
            time.sleep(1)
            rc, rr = cli.config_raw(f"port-queue add {p_out.name} 0 -s FVTCGS "
                                    f"-w FVTCG6W")
            wred_bound = False
            for _ in range(5):
                if (cli.db_hgetall("CONFIG_DB", f"QUEUE|{p_out.name}|0") or {}
                        ).get("wred_profile"):
                    wred_bound = True
                    break
                time.sleep(1)
            if not wred_bound:
                pytest.skip(f"port-queue wred rebind did not land: "
                            f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        else:
            gcu = Gcu(cli)
            r1 = gcu.apply_patch(gcu.add_entry(
                "WRED_PROFILE", "FVTCG6W",
                {"wred_green_enable": "true", "ecn": "ecn_all",
                 "green_min_threshold": "4000", "green_max_threshold": "40000",
                 "green_drop_probability": "100"}))
            if r1.rc != 0:
                pytest.skip(f"GCU WRED_PROFILE rejected: "
                            f"{(r1.out or r1.err or '')[-140:]}")
            undos.append(lambda: gcu.apply_patch(
                gcu.remove_entry("WRED_PROFILE", "FVTCG6W")))
            r2 = gcu.apply_patch([{"op": "add",
                                   "path": gcu.path("QUEUE", f"{p_out.name}|0")
                                   + "/wred_profile", "value": "FVTCG6W"}])
            if r2.rc != 0:
                pytest.skip(f"GCU QUEUE wred bind rejected: "
                            f"{(r2.out or r2.err or '')[-140:]}")
        okw, went = chip.wait_field(
            lambda: chip.wred_uc_q(p_out.name, 0) or {}, "ECN",
            lambda v: v == 1, timeout=15) if chip.has_table("TM_WRED_UC_Q") else (None, None)
        if okw is False:
            pytest.fail(f"DEVICE DEFECT: WRED not programmed to chip TM_WRED_UC_Q "
                        f"(entry={went}) though CONFIG accepted")
        n = 1200
        # ECN=00 (non-ECT): when WRED hits the curve it can only drop, not mark
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=0)
               / UDP() / Raw(b"CG6" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            grew = qmeasure.inject_measure(
                cli, traffic, pkt, _DST, count=n, vlan=l2_fwd_vlan,
                field="SAI_QUEUE_STAT_WRED_DROPPED_PACKETS", lower=1)
        wred_dropped = sum(grew.values())
        assert wred_dropped > 0, (
            f"no WRED_DROPPED packets counted on {p_out.name} despite shaped-queue "
            f"congestion with non-ECT traffic over a 4KB..40KB WRED curve "
            f"(deltas={grew}); WRED drop chain (bind -> chip curve -> drop -> "
            f"counter) not effective"
            + ("" if okw is None else f"; chip TM_WRED_UC_Q={went}"))
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_cg7_tail_drop_counted_deterministically(cli, chip, traffic, l2_fwd_vlan):
    """CG7 queue tail-drop counting (deterministic congestion bench):
      q0 rate cap 2Mbps (drain throttle; at line rate the queue does not back up, so limit alone is
        ineffective)
      + a chip fixture sets q0's static shared limit to 1 cell (disable the dynamic threshold;
        SharedLimitBytes=0 means "no limit" rather than "limit 0", so it must be set to 1 and let the
        chip round to a single cell)
      -> a burst injection is almost entirely tail-dropped -> SAI_QUEUE_STAT_DROPPED_PACKETS
         increments, while WRED_DROPPED stays put (no WRED bound; semantic separation: tail-drop
         only lands in DROPPED_*).

    Chip-write discipline: the threshold change is a **controlled test fixture** (same nature as
    bcmcmd lb=): read the original value first, restore in pairs, and FAIL loudly if restore fails (a
    leftover 1-cell limit would make that queue drop all traffic thereafter and pollute the whole
    round -- the same lesson as _verify_shaper_gone)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_out = traffic.ports[1]
    lport = chip.port_id(p_out.name)
    if not lport:
        pytest.skip(f"cannot resolve logical port for {p_out.name}")
    ok, undo, why = _mk_queue_shaper(cli, p_out.name, 0, _PIR)
    if not ok:
        pytest.skip(f"no queue shaper channel: {why}")
    undos = [undo]
    armed = False
    orig_dyn, orig_lim = 1, 0
    try:
        arm = _cint_run(cli, chip, "fvt_cg7_arm.c", f"""
cint_reset();
int rv; int p={lport};
int od=-1, ol=-1;
rv = bcm_cosq_control_get(0, p, 0, bcmCosqControlEgressUCSharedDynamicEnable, &od);
printf("ARM_GDYN rv=%d val=%d\\n", rv, od);
rv = bcm_cosq_control_get(0, p, 0, bcmCosqControlEgressUCQueueSharedLimitBytes, &ol);
printf("ARM_GLIM rv=%d val=%d\\n", rv, ol);
rv = bcm_cosq_control_set(0, p, 0, bcmCosqControlEgressUCSharedDynamicEnable, 0);
printf("ARM_SDYN rv=%d\\n", rv);
rv = bcm_cosq_control_set(0, p, 0, bcmCosqControlEgressUCQueueSharedLimitBytes, 1);
printf("ARM_SLIM rv=%d\\n", rv);
""")
        bad = _cint_rvs_ok(arm, ["ARM_GDYN", "ARM_GLIM", "ARM_SDYN", "ARM_SLIM"])
        if bad:
            pytest.skip(f"queue threshold fixture unavailable on this SDK: {bad}")
        armed = True
        for line in arm.splitlines():
            if "ARM_GDYN" in line:
                orig_dyn = int(line.split("val=")[1])
            if "ARM_GLIM" in line:
                orig_lim = int(line.split("val=")[1])
        oids = qmeasure.queue_oids(cli, p_out.name)
        if 0 not in oids:
            pytest.fail(f"queue 0 oid missing for {p_out.name}")
        wred_base = qmeasure.queue_stat(cli, oids[0],
                                        "SAI_QUEUE_STAT_WRED_DROPPED_PACKETS")
        n = 1200
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=0)
               / UDP() / Raw(b"CG7" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            grew = qmeasure.inject_measure(
                cli, traffic, pkt, _DST, count=n, vlan=l2_fwd_vlan,
                field="SAI_QUEUE_STAT_DROPPED_PACKETS", lower=n // 2)
        dropped = sum(grew.values())
        wred_delta = qmeasure.queue_stat(
            cli, oids[0], "SAI_QUEUE_STAT_WRED_DROPPED_PACKETS") - wred_base
        assert dropped >= n // 2, (
            f"tail drops undercounted on {p_out.name}: DROPPED_PACKETS deltas={grew} "
            f"(injected {n} against a 1-cell queue limit + 2Mbps drain; expected "
            f">= {n // 2}); queue drop stat chain (MMU counter -> SAI -> flexcounter "
            f"-> COUNTERS_DB) broken or drops not happening at egress queue")
        assert wred_delta * 10 <= max(dropped, 1), (
            f"WRED_DROPPED grew ({wred_delta}) during a pure tail-drop bench with no "
            f"WRED bound; drop-source accounting is misattributed")
    finally:
        if armed:
            rst = _cint_run(cli, chip, "fvt_cg7_rst.c", f"""
cint_reset();
int rv; int p={lport};
rv = bcm_cosq_control_set(0, p, 0, bcmCosqControlEgressUCQueueSharedLimitBytes, {orig_lim});
printf("RST_SLIM rv=%d\\n", rv);
rv = bcm_cosq_control_set(0, p, 0, bcmCosqControlEgressUCSharedDynamicEnable, {orig_dyn});
printf("RST_SDYN rv=%d\\n", rv);
int cd=-1;
rv = bcm_cosq_control_get(0, p, 0, bcmCosqControlEgressUCSharedDynamicEnable, &cd);
printf("RST_VDYN rv=%d val=%d\\n", rv, cd);
""")
            bad = _cint_rvs_ok(rst, ["RST_SLIM", "RST_SDYN", "RST_VDYN"])
            for u in reversed(undos):
                try:
                    u()
                except Exception:  # noqa: BLE001
                    pass
            if bad or f"val={orig_dyn}" not in rst.replace(" ", ""):
                vd = next((l for l in rst.splitlines() if "RST_VDYN" in l), "?")
                pytest.fail(
                    f"CLEANUP FAILURE: queue threshold fixture not restored on "
                    f"{p_out.name} q0 (lport {lport}): {bad or vd}. A leftover "
                    f"1-cell limit drops ALL traffic on that queue and poisons every "
                    f"later case. Restore by hand: bcm_cosq_control_set dyn="
                    f"{orig_dyn} lim={orig_lim}.")
        else:
            for u in reversed(undos):
                try:
                    u()
                except Exception:  # noqa: BLE001
                    pass


def test_cg8_dwrr_weight_hot_change_flips_ratio(cli, chip, traffic, topo,
                                                l2_fwd_vlan):
    """CG8 **behavioral** closed loop for hot scheduler-weight change (test_qos_sched_chip only
    verified ASIC attribute sync; arbitration behavior had zero coverage): on the CG2 congestion
    bench, measure ratio R1 at q1:q2=80:20, GCU-swaps the two schedulers' weights in place
    (80<->20), and after the chip TM_SCHEDULER_NODE.WEIGHT flips, measure R2 ->
    R1 >= 2 and R2 <= 0.5 (the ratio truly follows the weights, not a one-shot snapshot at bind time).
    VERIFY-ON-HW: calibrate both-side bands on the first hardware run."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    if not qos.has_qos_cli(cli):
        pytest.skip("ratio bench needs the product port-shaper channel; unknown "
                    "on community image")
    r = cli.sh.run("config port-qos-map add --help", check=False)
    if "-s" not in (r.out or ""):
        pytest.skip("product CLI port-qos-map has no -s scheduler knob")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    for q in (1, 2):
        if cli.db_hgetall("CONFIG_DB", f"QUEUE|{p_out.name}|{q}"):
            pytest.skip(f"{p_out.name} q{q} already bound; refusing to clobber")
    gcu = Gcu(cli)
    undos = []

    def _ratio(pkt1, pkt2, oids):
        for _ in range(6):
            traffic.send(p_in, pkt1, count=150)
            traffic.send(p_in, pkt2, count=150)
        t0 = {q: qmeasure.queue_stat(cli, oids[q]) for q in (1, 2)}
        for _ in range(4):
            traffic.send(p_in, pkt1, count=150)
            traffic.send(p_in, pkt2, count=150)
        time.sleep(4)
        t1 = {q: qmeasure.queue_stat(cli, oids[q]) for q in (1, 2)}
        return t1[1] - t0[1], t1[2] - t0[2]

    try:
        u = qos.build_baseline(cli, p_in.name, prefix="FVTCG8")
        if u:
            undos.append(u)
        for cmd in (f"dscp-to-tc-map add FVTCG8_D2T -d 18 -t {qos.tc_name(2)}",
                    f"tc-to-queue-map add FVTCG8_T2Q -t {qos.tc_name(2)} -q 2"):
            rc, rr = cli.config_raw(cmd)
            if rc != 0:
                pytest.skip(f"cannot provision second flow map: "
                            f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        ok1, u1, w1 = make_scheduler(cli, "FVTCG8A", mode="DWRR", weight=80)
        ok2, u2, w2 = make_scheduler(cli, "FVTCG8B", mode="DWRR", weight=20)
        okp, up, wp = make_scheduler(cli, "FVTCG8P", mode="DWRR", weight=50,
                                     pir=1_000)
        undos += [u1, u2, up]
        if not (ok1 and ok2 and okp):
            pytest.skip(f"scheduler provisioning incomplete: "
                        f"{[w for w in (w1, w2, wp) if w]}")
        okb1, ub1 = bind_queue(cli, p_out.name, 1, sched="FVTCG8A")
        okb2, ub2 = bind_queue(cli, p_out.name, 2, sched="FVTCG8B")
        undos += [ub1, ub2]
        if not (okb1 and okb2):
            pytest.skip("queue scheduler binds incomplete")
        orig_pqm = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
        sub = "update" if orig_pqm else "add"
        rc, rr = cli.config_raw(f"port-qos-map {sub} {p_out.name} -s FVTCG8P")
        bound = False
        for _ in range(5):
            if (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{p_out.name}") or {}
                    ).get("scheduler"):
                bound = True
                break
            time.sleep(1)
        if not bound:
            pytest.skip(f"port shaper bind did not land ({sub}): "
                        f"{((rr.out or '') + (rr.err or ''))[-140:]}")
        undos.append(lambda: gcu.apply_patch(
            [{"op": "remove", "path": Gcu.path("PORT_QOS_MAP", p_out.name, "scheduler")}]))
        okw, e1 = chip.wait_field(lambda: chip.sched_node(p_out.name, 1), "WEIGHT",
                                  lambda v: v == 80, timeout=30)
        assert okw, f"q1 w80 not programmed to chip before bench: {e1}"
        pkt1 = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=10 << 2)
                / UDP() / Raw(b"CG8A" + b"x" * _PAYLOAD))
        pkt2 = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=18 << 2)
                / UDP() / Raw(b"CG8B" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                oids = qmeasure.queue_oids(cli, p_out.name)
                if 1 not in oids or 2 not in oids:
                    pytest.fail("queue oids for q1/q2 missing in COUNTERS map")
                s1, s2 = _ratio(pkt1, pkt2, oids)
                if s1 + s2 < 100:
                    pytest.fail(f"DEVICE DEFECT: queue counters barely moved "
                                f"(q1+{s1}, q2+{s2}); stats frozen or port wedged")
                r1 = s1 / max(s2, 1)
                # hot change: GCU swaps the weights in place (config channel; if rejected, skip as a
                # channel gap -- on that image scheduler weights can only be set at build time, and the
                # hot change is itself the capability under test)
                p1 = gcu.apply_patch([{"op": "add",
                                       "path": Gcu.path("SCHEDULER", "FVTCG8A") + "/weight",
                                       "value": "20"}])
                p2 = gcu.apply_patch([{"op": "add",
                                       "path": Gcu.path("SCHEDULER", "FVTCG8B") + "/weight",
                                       "value": "80"}])
                if p1.rc != 0 or p2.rc != 0:
                    pytest.skip(f"GCU in-place SCHEDULER weight update rejected: "
                                f"{(p1.out or p1.err or '')[-100:]} / "
                                f"{(p2.out or p2.err or '')[-100:]}")
                okw2, e2 = chip.wait_field(
                    lambda: chip.sched_node(p_out.name, 1), "WEIGHT",
                    lambda v: v == 20, timeout=30)
                assert okw2, (f"hot weight change accepted by CONFIG but chip "
                              f"TM_SCHEDULER_NODE q1 weight not updated: {e2}")
                s1b, s2b = _ratio(pkt1, pkt2, oids)
                if s1b + s2b < 100:
                    pytest.fail(f"DEVICE DEFECT: queue counters barely moved after "
                                f"hot change (q1+{s1b}, q2+{s2b})")
                r2 = s1b / max(s2b, 1)
                assert r1 >= 2.0 and r2 <= 0.5, (
                    f"DWRR service ratio did not follow the hot weight swap: "
                    f"before q1/q2={r1:.2f} (want >=2), after={r2:.2f} (want <=0.5) "
                    f"— weights update in chip but arbitration keeps the old "
                    f"proportions (snapshot-at-bind class defect)")
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# CG9: **attribution** criterion for congestion drops.
# ---------------------------------------------------------------------------
def _port_stat(cli, port, field):
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port}")
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get(field)
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else 0


def test_cg9_congestion_drops_land_on_egress_not_ingress(cli, chip, traffic,
                                                         l2_fwd_vlan):
    """CG9 under egress congestion, drops must be counted on the **egress queue** ledger, not the
    ingress port.

    Why this matters: the field reported "two flows into q2/q3, configured with 80:20 weights, yet it
    had no effect at all, and the ingress was also dropping packets". The diagnosis was that the
    ingress PG shared threshold tops out before the egress queue threshold -- packets are dropped at
    the **admission stage**, both flows cut equally, so the egress scheduler never even gets to
    arbitrate, and the ratio collapses to 1:1. This is not a broken scheduler; the buffer budget was
    configured backwards (the ingress shared threshold must be >= the total reachable egress
    occupancy).

    Criterion: after creating egress congestion, `SAI_QUEUE_STAT_DROPPED_PACKETS` must rise, while
    the ingress port's `SAI_PORT_STAT_IF_IN_DISCARDS` must not rise by the same order of magnitude.
    More ingress drops than egress = the budget is backwards, and any scheduling case's conclusions
    are then untrustworthy -- so this case is a preflight check for CG2/CG5/CG8.

    Read-only decision, does not change the buffer config (changing pools requires a restart, see
    Buffer/QoS design section 11)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    ok, undo, why = _mk_queue_shaper(cli, p_out.name, 0, _PIR)
    if not ok:
        pytest.skip(f"no queue shaper channel: {why}")
    try:
        oids = qmeasure.queue_oids(cli, p_out.name)
        if 0 not in oids:
            pytest.skip(f"no queue0 oid for {p_out.name}")
        pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.2", tos=0)
               / UDP() / Raw(b"CG9" + b"x" * _PAYLOAD))
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                q_before = qmeasure.queue_stat(
                    cli, oids[0], "SAI_QUEUE_STAT_DROPPED_PACKETS")
                in_before = _port_stat(cli, p_in.name, "SAI_PORT_STAT_IF_IN_DISCARDS")
                for _ in range(8):
                    traffic.send(p_in, pkt, count=400)
                time.sleep(5)
                q_drop = qmeasure.queue_stat(
                    cli, oids[0], "SAI_QUEUE_STAT_DROPPED_PACKETS") - q_before
                in_drop = _port_stat(
                    cli, p_in.name, "SAI_PORT_STAT_IF_IN_DISCARDS") - in_before
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
        if q_drop <= 0 and in_drop <= 0:
            pytest.skip(f"neither ledger moved (egress q0 drops={q_drop}, ingress "
                        f"discards={in_drop}); offered rate never exceeded the "
                        f"{_PIR}B/s shaper — bench did not congest, nothing to attribute")
        assert q_drop > 0, (
            f"congestion produced {in_drop} ingress discards on {p_in.name} but ZERO "
            f"egress queue drops on {p_out.name} q0 — packets are being rejected at "
            f"admission (ingress PG shared threshold tops out before the egress queue "
            f"does). Every flow gets cut equally there, so egress scheduling never "
            f"arbitrates and weighted ratios collapse to 1:1. Fix the pool budget "
            f"(ingress shared >= reachable egress occupancy) before trusting any "
            f"scheduling result — see Buffer/QoS design section 1/section 6.")
        assert in_drop <= max(q_drop // 4, 50), (
            f"ingress discards ({in_drop} on {p_in.name}) are the same order as "
            f"egress queue drops ({q_drop} on {p_out.name} q0) under a purely "
            f"EGRESS-side bottleneck. The ingress ledger should barely move: it "
            f"tops out only when the ingress pool is undersized relative to what "
            f"the egress queues can hold. Scheduling/ECN conclusions measured in "
            f"this state are not trustworthy.")
    finally:
        try:
            undo()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# CG10: PG / buffer pool stats under congestion (measured live with traffic). In the non-congested
# state these counters are always 0, and only on this low-rate congestion bench is there a criterion
# -- which is also why they had long-standing zero coverage.
# ---------------------------------------------------------------------------
_PG_DROP_F = "SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS"
_PG_SHWM_F = "SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"
_POOL_OCC_F = "SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"


def _cdb(cli, oid, field):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get(field)
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else None


def test_cg10_pg_and_pool_stats_move_under_congestion(cli, chip, traffic,
                                                      l2_fwd_vlan):
    """CG10 under real congestion the ingress-side stats must move: PG shared watermark rises, and the
    pool's live occupancy is readable.

    Why it must be measured on the congestion bench: without congestion, packets do not dwell as they
    traverse the pipeline, so PG shared occupancy and pool occupancy are always 0, and any
    "send traffic, read counters" approach measures nothing -- exactly why these two stats had
    long-standing zero coverage. Only after pushing egress q0 down to 2Mbps does the queue genuinely
    back up and the ingress PG start occupying the shared pool, giving both sides a criterion.

    The PG drop counter (DROPPED_PACKETS) only rises when the **ingress ledger tops out first**. Under
    a healthy config it should stay put (drops are attributed on egress, see CG9), so here we only
    read and record it and do not make a "must rise" assertion: if it rises, that instead indicates
    the pool budget is configured backwards -- which CG9 is responsible for deciding."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    chip.require()
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    pgmap = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PG_NAME_MAP") or {}
    pg_oids = [v for k, v in pgmap.items() if k.startswith(p_in.name + ":")]
    if not pg_oids:
        pytest.skip(f"no PG oid for {p_in.name} (see test_counter_infra.py CI1)")
    if all(_cdb(cli, o, _PG_SHWM_F) is None for o in pg_oids):
        pytest.skip(f"{_PG_SHWM_F} not sampled on {p_in.name}; PG watermark group "
                    f"not collecting on this image")
    ok, undo, why = _mk_queue_shaper(cli, p_out.name, 0, _PIR)
    if not ok:
        pytest.skip(f"no queue shaper channel: {why}")
    try:
        cli.run("sonic-clear priority-group watermark")
        time.sleep(2)
        base_wm = {o: (_cdb(cli, o, _PG_SHWM_F) or 0) for o in pg_oids}
        base_dr = {o: (_cdb(cli, o, _PG_DROP_F) or 0) for o in pg_oids}
        with qmeasure.classified_egress(cli, traffic):
            cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
            try:
                pkt = (Ether(dst=_DST, src=_SRC) / IP(dst="2.2.2.3", tos=0)
                       / UDP() / Raw(b"CG10" + b"x" * _PAYLOAD))
                for _ in range(8):
                    traffic.send(p_in, pkt, count=400)
                moved = 0
                for _ in range(16):
                    time.sleep(1)
                    moved = max((_cdb(cli, o, _PG_SHWM_F) or 0) - base_wm[o]
                                for o in pg_oids)
                    if moved > 0:
                        break
                pg_drop = max((_cdb(cli, o, _PG_DROP_F) or 0) - base_dr[o]
                              for o in pg_oids)
            finally:
                cli.fdb_static_del(l2_fwd_vlan, _DST)
        pools = cli.db_hgetall("COUNTERS_DB", "COUNTERS_BUFFER_POOL_NAME_MAP") or {}
        occ = {p: _cdb(cli, o, _POOL_OCC_F) for p, o in pools.items()}
        pool_wm = {p: _cdb(cli, o, "SAI_BUFFER_POOL_STAT_WATERMARK_BYTES")
                   for p, o in pools.items()}
        print(f"CG10: pg_shared_watermark_delta={moved} pg_dropped_delta={pg_drop} "
              f"pool_occupancy={occ} pool_watermark={pool_wm}")
        assert moved > 0, (
            f"PG shared watermark on {p_in.name} did not move even with the egress "
            f"queue shaped to {_PIR}B/s and {8 * 400} frames offered (deltas base="
            f"{base_wm}); under real congestion the ingress side must accumulate "
            f"shared-pool occupancy — the PG watermark counter is not tracking it")
        assert any(v for v in pool_wm.values()), (
            f"buffer pool watermark stayed at zero/absent while the egress queue was "
            f"demonstrably backed up (PG watermark moved +{moved}B): pool_wm="
            f"{pool_wm}. The pool IS holding those cells, so a flat watermark means "
            f"the BUFFER_POOL_WATERMARK group is not sampling")
        assert pools and any(v is not None for v in occ.values()), (
            f"buffer pool instantaneous occupancy unreadable during congestion "
            f"({occ}); with the queue backed up the pool is demonstrably in use, so "
            f"CURR_OCCUPANCY_BYTES reading empty means the pool counter group is not "
            f"sampling that field")
    finally:
        try:
            undo()
        except Exception:  # noqa: BLE001
            pass
