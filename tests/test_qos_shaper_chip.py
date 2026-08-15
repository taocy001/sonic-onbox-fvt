"""Scheduler/shaper value-chain validation -- CONFIG_DB -> ASIC_DB -> SDKLT TM chip table (layer 4).

Background (a class of hidden failure): sch_q0~q7 configured with a 100G template's cir/pir
bound to a 400G port programs "correctly" all the way through CONFIG_DB->ASIC_DB, and the chip
TM_SHAPER_NODE actually takes effect -> RoCE q5 is throttled to 1/4 and performance collapses.
Checking only "programming consistency" never catches this class -- this file adds two kinds of
assertion:
  1) value chain: config value -> SAI attribute value -> chip KBPS **including unit conversion**
     (bytes/s vs bits/s off by one step = throttled 8x);
  2) sanity lint: a shaper pir bound to a front-panel port queue must not fall below the port's
     line rate (incident detector).

Chip table facts (documented from `lt list` on real hardware): TM_SHAPER_NODE key={PORT_ID,
TM_SCHEDULER_NODE_ID} (no SCHED_NODE), MAX_BANDWIDTH_KBPS=0 = no rate limit; the cap follows
MAX(pir) not MIN(cir). TM_SCHEDULER_NODE key includes SCHED_NODE=L0_SCHED_NODE.

Scheduling-mode chip semantics:
- asic-b's cosq_sched_mode table maps **both** WRR and WERR(DRR) to the node-table symbol "RR" --
  TM_SCHEDULER_NODE.SCHED_MODE only distinguishes SP/RR; the WRR(packet-mode) vs DRR(byte-mode)
  distinction lives at the **port level** in TM_SCHEDULER_PORT_PROFILE.WRR (1=WRR, 0=WERR/DRR),
  with the weight on the node's WEIGHT. Seeing "RR" in the node table and concluding weighted
  scheduling did not take effect is a **misread**.
- a queue has exactly one scheduler profile at a time; binding a **type-less pure shaping
  profile (no -t)** replaces it wholesale and resets the scheduling mode to the default
  WRR/weight=1 (a newly created profile defaults to algorithm=WRR/w=1) -- SP is silently wiped.
  Scheduling + rate-limit must be in the same profile.
This file locks these two interpretation rules/semantics into regression cases
(sp_wrr_whole_port / mode_flag / shaper_only_rebind).
"""
import time

import pytest

from framework import lossless, qos
from framework.gcu import Gcu

pytestmark = [pytest.mark.qos, pytest.mark.chiptab]

_Q = 2               # queue under test (avoids 0/5/6/7 commonly used by CoPP/default traffic)
_WEIGHT = 77
# Two representations of 10Gbps: the SONiC CLI -pr takes Kbps and converts to bytes/s when
# writing CONFIG_DB (-pr 10000000 -> pir=1250000000); community GCU writes bytes/s directly.
_PIR_KBPS = 10_000_000
_PIR_BYTES = 1_250_000_000


@pytest.fixture(scope="module")
def sched_port(topo):
    return topo.misc_port(0).name


def _mk_sched_bound(cli, name, port, q, weight=None, pir=None):
    """Create a scheduler and bind it to port's queue q. Product CLI preferred, community
    image falls back to GCU. Returns (ok, undo, via, text)."""
    if qos.has_qos_cli(cli):
        ok, undo_s, why = lossless.make_scheduler(cli, name, mode="DWRR",
                                                  weight=weight, pir=pir)
        if not ok:
            return False, lambda: None, "cli", f"scheduler add rejected: {why}"
        ok2, undo_q = lossless.bind_queue(cli, port, q, sched=name)
        if not ok2:
            undo_s()
            return False, lambda: None, "cli", "port-queue add rejected"

        def _undo():
            undo_q()
            undo_s()
        return True, _undo, "cli", ""
    gcu = Gcu(cli)
    val = {"type": "DWRR", "meter_type": "bytes"}
    if weight is not None:
        val["weight"] = str(weight)
    if pir is not None:
        val["pir"] = str(pir)
        val["pbs"] = "8192"
    via = "gcu"
    r1 = gcu.apply_patch(gcu.add_entry("SCHEDULER", name, val))
    if r1.rc != 0 and pir is not None:
        # YANG rejects SCHEDULER.pir (Data Loading Failed) --
        # fall back to a shaper-less scheduler; the caller uses via to decide "this image has
        # no shaper channel".
        for k in ("pir", "pbs", "meter_type"):
            val.pop(k, None)
        via = "gcu-nopir"
        r1 = gcu.apply_patch(gcu.add_entry("SCHEDULER", name, val))
    if r1.rc != 0:
        return False, lambda: None, via, ((r1.out or "") + (r1.err or ""))[-200:]
    r2 = gcu.apply_patch(gcu.add_entry("QUEUE", f"{port}|{q}", {"scheduler": name}))
    if r2.rc != 0:
        gcu.apply_patch(gcu.remove_entry("SCHEDULER", name))
        return False, lambda: None, via, ((r2.out or "") + (r2.err or ""))[-200:]

    def _undo():
        gcu.apply_patch(gcu.remove_entry("QUEUE", f"{port}|{q}"))
        gcu.apply_patch(gcu.remove_entry("SCHEDULER", name))
    return True, _undo, via, ""


def _wait_asic_sched(asicdb, cli, timeout=12, **want):
    """Poll ASIC for a SCHEDULER object whose attributes satisfy want; return its key or None."""
    end = time.time() + timeout
    while time.time() < end:
        for k in asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER"):
            attrs = cli.db_hgetall("ASIC_DB", k) or {}
            if all(str(attrs.get(f)) == str(v) for f, v in want.items()):
                return k
        time.sleep(0.5)
    return None


def test_scheduler_weight_chain_to_chip(cli, asicdb, chip, sched_port):
    """DWRR weight full chain: CONFIG(weight=77) -> ASIC SCHEDULING_WEIGHT=77 ->
    chip TM_SCHEDULER_NODE.WEIGHT=77 (previously only verified down to the ASIC layer)."""
    chip.require()
    ok, undo, via, text = _mk_sched_bound(cli, "FVTSHW", sched_port, _Q, weight=_WEIGHT)
    if not ok:
        pytest.fail(f"cannot provision scheduler+queue binding (via={via}): {text}")
    try:
        skey = _wait_asic_sched(asicdb, cli,
                                SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT=_WEIGHT)
        assert skey, f"no ASIC SCHEDULER with SCHEDULING_WEIGHT={_WEIGHT} appeared"
        soid = "oid:" + skey.split("oid:")[-1]
        bound = False
        deadline = time.time() + 12
        while time.time() < deadline and not bound:
            for t, attr in (("SAI_OBJECT_TYPE_QUEUE",
                             "SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID"),
                            ("SAI_OBJECT_TYPE_SCHEDULER_GROUP",
                             "SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID")):
                for k in asicdb.objects(t):
                    if (cli.db_hgetall("ASIC_DB", k) or {}).get(attr) == soid:
                        bound = True
                        break
                if bound:
                    break
            time.sleep(1)
        assert bound, (
            f"ASIC SCHEDULER {soid} exists but is not referenced by any QUEUE/"
            f"SCHEDULER_GROUP object — orchagent did not consume the queue binding "
            f"(qos infra absent?); scheduler never reaches a chip node")
        ok2, ent = chip.wait_field(
            lambda: chip.sched_node(sched_port, _Q), "WEIGHT",
            lambda v: v == _WEIGHT, timeout=30)
        assert ok2, (
            f"chip TM_SCHEDULER_NODE(port={sched_port}, node={_Q}) WEIGHT != {_WEIGHT} "
            f"(chip entry={ent}); ASIC accepted the scheduler but chip TM node not "
            f"programmed — SAI->SDK break")
    finally:
        undo()


def test_shaper_pir_chain_units_to_chip(cli, asicdb, chip, sched_port):
    """shaper value+unit full chain (the incident's root-cause dimension, previously zero
    coverage). Target bandwidth 10Gbps:
    - product CLI: -pr 10^7(Kbps) -> CONFIG_DB pir should be 1.25e9 bytes/s (CLI conversion hop)
    - both channels converge: CONFIG_DB pir(bytes/s) -> chip MAX_BANDWIDTH_KBPS == pir*8/1000 (+/-2%)
    Any hop with the wrong unit step (Kbps/bytes/bits confusion) blows up this assert."""
    chip.require()
    pir_arg = _PIR_KBPS if qos.has_qos_cli(cli) else _PIR_BYTES
    ok, undo, via, text = _mk_sched_bound(cli, "FVTSHP", sched_port, _Q,
                                          weight=50, pir=pir_arg)
    if not ok:
        pytest.fail(f"cannot provision shaper scheduler (via={via}): {text}")
    if via == "gcu-nopir":
        undo()
        pytest.skip("this image's YANG rejects SCHEDULER.pir (no shaper channel) "
                    "— shaper value chain untestable here")
    try:
        cfg = cli.db_hgetall("CONFIG_DB", "SCHEDULER|FVTSHP") or {}
        if "pir" not in cfg:
            pytest.skip("this image's scheduler CLI has no pir/shaper knob "
                        f"(CONFIG_DB entry={cfg}); shaper value chain untestable here")
        pir_cfg = int(cfg["pir"])
        if cfg.get("meter_type", "bytes") != "bytes":
            pytest.skip(f"meter_type={cfg.get('meter_type')} — packet-mode shaper "
                        "out of scope for the byte-rate unit chain")
        if via == "cli":
            assert pir_cfg == _PIR_KBPS * 125, (
                f"CLI unit-conversion hop wrong: -pr {_PIR_KBPS} Kbps must store "
                f"pir={_PIR_KBPS * 125} bytes/s in CONFIG_DB, got {pir_cfg}")
        want_kbps = pir_cfg * 8 // 1000
        ok2, ent = chip.wait_field(
            lambda: chip.shaper_node(sched_port, _Q), "MAX_BANDWIDTH_KBPS",
            lambda v: isinstance(v, int) and v > 0, timeout=30)
        assert ok2, (
            f"chip TM_SHAPER_NODE(port={sched_port}, node={_Q}) has no MAX_BANDWIDTH "
            f"programmed (entry={ent}) though CONFIG_DB pir={pir_cfg}")
        got = ent["MAX_BANDWIDTH_KBPS"]
        tol = want_kbps * 0.02
        assert abs(got - want_kbps) <= tol, (
            f"shaper unit-conversion mismatch: CONFIG_DB pir={pir_cfg} bytes/s, "
            f"expected chip MAX_BANDWIDTH_KBPS≈{want_kbps}, got {got} "
            f"(off by {got / max(want_kbps, 1):.2f}x — bytes/bits confusion class bug)")
    finally:
        undo()


def test_shaper_cir_zero_means_no_cap(cli, chip, sched_port):
    """cir=0 / no-pir semantics: chip MIN/MAX_BANDWIDTH_KBPS both 0 = no rate limit (locking
    the conclusion into a regression case; when the CLI requires cir/cbs to be present,
    make_scheduler auto-supplies cir=0)."""
    chip.require()
    if not qos.has_qos_cli(cli):
        pytest.skip("community image: scheduler w/o pir via GCU exercised in weight "
                    "test already; cir-zero CLI-gate semantics is a product-CLI trait")
    ok, undo_s, why = lossless.make_scheduler(cli, "FVTSH0", mode="DWRR", weight=40)
    if not ok:
        pytest.fail(f"scheduler add (no shaper) rejected even with cir=0/cbs=0 "
                    f"fallback: {why}")
    ok2, undo_q = lossless.bind_queue(cli, sched_port, _Q, sched="FVTSH0")
    if not ok2:
        undo_s()
        pytest.fail("port-queue bind of shaper-less scheduler rejected "
                    "(cir/cbs CLI-gate regression?)")
    try:
        ok3, ent = chip.wait_field(
            lambda: chip.shaper_node(sched_port, _Q), "MAX_BANDWIDTH_KBPS",
            lambda v: v == 0, timeout=30)
        assert ok3, (
            f"scheduler without pir must leave chip MAX_BANDWIDTH_KBPS=0 (line rate), "
            f"got {ent} — a residual shaper would silently cap this queue")
        assert ent.get("MIN_BANDWIDTH_KBPS", 0) == 0, \
            f"cir=0 must program MIN_BANDWIDTH_KBPS=0, got {ent}"
    finally:
        undo_q()
        undo_s()


def test_bound_queue_shapers_meet_linerate_lint(cli, chip, dut):
    """Incident detector (read-only lint, changes no config): walk the SCHEDULER bound to each
    QUEUE|<port>|<q>; any that carries a pir must not have a bandwidth below that port's line
    rate (otherwise the queue is silently throttled -- the incident shape where a 400G port's
    q5 is capped to 100G). Also spot-checks the chip TM_SHAPER_NODE to confirm the cap actually
    takes effect rather than being mere config residue."""
    viol, checked = [], 0
    for qk in cli.db_keys("CONFIG_DB", "QUEUE|*"):
        parts = qk.split("|")
        if len(parts) != 3 or not parts[1].startswith("Ethernet"):
            continue
        port, q = parts[1], parts[2]
        sch = (cli.db_hgetall("CONFIG_DB", qk) or {}).get("scheduler", "")
        sch = sch.strip("[]").split("|")[-1]
        if not sch:
            continue
        s = cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{sch}") or {}
        pir = s.get("pir") or s.get("cir")
        if not pir or not str(pir).isdigit():
            continue
        checked += 1
        speed_mbps = int((cli.db_hgetall("CONFIG_DB", f"PORT|{port}") or {})
                         .get("speed", 0))
        # meter_type defaults to bytes; under bits semantics dividing by 1e6 gives Mbps
        mtype = s.get("meter_type", "bytes")
        pir_mbps = int(pir) * 8 // 1_000_000 if mtype == "bytes" else int(pir) // 1_000_000
        if pir_mbps < speed_mbps:
            ent = None
            if chip.available() and q.isdigit():
                ent = chip.shaper_node(port, int(q))
            viol.append((port, q, sch, f"{pir_mbps}Mbps<{speed_mbps}Mbps",
                         f"chip_MAX={ent.get('MAX_BANDWIDTH_KBPS') if ent else 'n/a'}"))
    if checked == 0:
        pytest.skip("no front-panel queue carries a shaper-bearing scheduler "
                    "(nothing to lint on this device)")
    assert not viol, (
        f"queue shaper caps below port line rate — the incident class "
        f"(100G-template pir on 400G port silently throttling RoCE): {viol}")


# ---- Whole-port SP+WRR template (q7=SP + q0~6=WRR weights 10..70) ----

# queue -> (scheduling type, weight). q7 strict priority; q0~6 WRR weight gradient, with the
# weights all distinct so a "weight landed on the wrong node" programming error is detectable.
_SPWRR_PLAN = {q: ("WRR", (q + 1) * 10) for q in range(7)}
_SPWRR_PLAN[7] = ("STRICT", None)


def _mk_many_sched_bound(cli, port, plan, prefix):
    """Create profiles per plan {q: (mode, weight)} and bind queues. Product CLI preferred,
    community image falls back to GCU. Returns (ok, undo, why); undo runs in reverse (unbind
    before deleting the profile, since deleting a referenced profile is rejected)."""
    undos = []

    def _undo():
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass

    if qos.has_qos_cli(cli):
        for q, (mode, w) in plan.items():
            name = f"{prefix}{q}"
            ok, undo_s, why = lossless.make_scheduler(cli, name, mode=mode, weight=w)
            if not ok:
                _undo()
                return False, lambda: None, f"scheduler add for q{q} rejected: {why}"
            undos.append(undo_s)
            ok2, undo_q = lossless.bind_queue(cli, port, q, sched=name)
            if not ok2:
                _undo()
                return False, lambda: None, f"port-queue add for q{q} rejected"
            undos.append(undo_q)
        return True, _undo, ""
    gcu = Gcu(cli)
    for q, (mode, w) in plan.items():
        name = f"{prefix}{q}"
        val = {"type": mode}
        if w is not None:
            val["weight"] = str(w)
        r1 = gcu.apply_patch(gcu.add_entry("SCHEDULER", name, val))
        if r1.rc != 0:
            _undo()
            return False, lambda: None, \
                f"GCU SCHEDULER q{q}: {(r1.out or r1.err or '')[-160:]}"
        undos.append(lambda n=name: gcu.apply_patch(gcu.remove_entry("SCHEDULER", n)))
        r2 = gcu.apply_patch(gcu.add_entry("QUEUE", f"{port}|{q}", {"scheduler": name}))
        if r2.rc != 0:
            _undo()
            return False, lambda: None, \
                f"GCU QUEUE q{q}: {(r2.out or r2.err or '')[-160:]}"
        undos.append(lambda qq=q: gcu.apply_patch(
            gcu.remove_entry("QUEUE", f"{port}|{qq}")))
    return True, _undo, ""


def _skip_if_queues_bound(cli, port, qlist):
    """If a queue under test already has a binding, skip honestly -- refuse to overwrite
    existing config (tearing down someone else's scheduling state cannot restore its semantics)."""
    busy = [q for q in qlist
            if cli.db_hgetall("CONFIG_DB", f"QUEUE|{port}|{q}")]
    if busy:
        pytest.skip(f"{port} queues {busy} already carry QUEUE bindings; refusing to "
                    f"clobber existing scheduling config (pick a clean misc port or "
                    f"clean up first)")


def _clean_sched_port(cli, topo, qlist):
    """Pick a front-panel port whose qlist queues are all free: try the misc domain (g/h)
    first, then fall back across the whole PORT table (field debugging often finds test ports
    with scheduling residue -- test ports get occupied a lot; since this only validates
    config/chip tables and sends no traffic, using a non-topo port is safe, and FVT* bindings
    are cleaned up by end-of-session hygiene as a backstop). Skip if all are occupied."""
    cand = []
    for i in (0, 1):
        try:
            cand.append(topo.misc_port(i).name)
        except Exception:  # noqa: BLE001
            pass
    others = sorted((k.split("|", 1)[1] for k in cli.db_keys("CONFIG_DB", "PORT|*")
                     if k.split("|", 1)[1].startswith("Ethernet")),
                    key=lambda n: int(n[8:]))
    cand += [p for p in others if p not in cand]
    for p in cand:
        if not any(cli.db_hgetall("CONFIG_DB", f"QUEUE|{p}|{q}") for q in qlist):
            return p
    pytest.skip(f"no front-panel port with queues {qlist} free of QUEUE bindings; "
                f"clean up leftover scheduling config first")


def test_sp_wrr_whole_port_pattern_to_chip(cli, chip, topo):
    """Whole-port scheduling template full chain ("q7 SP, q0~6 WRR each weighted" pattern):
    q7=STRICT + q0~6=WRR w10..70 -> per-node chip asserts:
      - node7 SCHED_MODE=SP;
      - node0~6 SCHED_MODE=RR and WEIGHT exactly 10..70 (weights distinct, so misplacement blows up);
      - port-level TM_SCHEDULER_PORT_PROFILE.WRR=1 (WRR packet mode; this flag, not the node
        table's "RR", is the WRR/DRR distinguishing bit -- see module docstring for the reading).
    Previously only a single-queue DWRR weight chain existed (test_scheduler_weight_chain_to_chip);
    SP and whole-port mode had zero chip coverage. The port is chosen with all 8 queues free
    (misc first, whole-table fallback)."""
    chip.require()
    sched_port = _clean_sched_port(cli, topo, list(_SPWRR_PLAN))
    ok, undo, why = _mk_many_sched_bound(cli, sched_port, _SPWRR_PLAN, "FVTSPW")
    if not ok:
        pytest.fail(f"cannot provision whole-port SP+WRR pattern: {why}")
    try:
        okc, ent = chip.wait_field(
            lambda: chip.sched_node(sched_port, 7), "SCHED_MODE",
            lambda v: v == "SP", timeout=30)
        assert okc, (
            f"q7 STRICT not programmed to chip: TM_SCHEDULER_NODE(port={sched_port}, "
            f"node=7)={ent} (expected SCHED_MODE=SP) — SAI->SDK strict-priority break")
        bad = []
        for q in range(7):
            want_w = _SPWRR_PLAN[q][1]
            okw, e = chip.wait_field(
                lambda q=q: chip.sched_node(sched_port, q), "WEIGHT",
                lambda v, w=want_w: v == w, timeout=15)
            e = e or {}
            if not okw or e.get("SCHED_MODE") != "RR":
                bad.append((q, {"got_mode": e.get("SCHED_MODE"),
                                "got_weight": e.get("WEIGHT"),
                                "want": ("RR", want_w)}))
        assert not bad, (
            f"WRR nodes mis-programmed on {sched_port}: {bad} — weight ladder must "
            f"land exactly on its own L0 node (weight on a wrong node = scheduling "
            f"applied to the wrong queue)")
        prof = chip.lookup("TM_SCHEDULER_PORT_PROFILE",
                           PORT_ID=chip.port_id(sched_port))
        assert prof and prof.get("WRR") == 1, (
            f"TM_SCHEDULER_PORT_PROFILE(port={sched_port})={prof}: WRR flag must be 1 "
            f"for WRR profiles (0 would mean WERR/DRR byte-mode — the flag, not the "
            f"node-level 'RR' symbol, distinguishes WRR from DRR)")
    finally:
        undo()


def test_wrr_vs_dwrr_port_mode_flag_to_chip(cli, chip, sched_port):
    """WRR/DRR distinguishing bit full chain: bind DWRR to a queue -> port WRR flag=0 (WERR
    byte mode), rebind WRR -> flag=1. Locks in the chip semantics that "the node-table RR
    symbol does not distinguish WRR/DRR; the distinction is the port-profile flag" (misreading
    that symbol = the false conclusion that "DRR was configured but has no effect").
    Note the flag is **port-level**: mixing WRR and DWRR bindings on the same port, the last
    write wins -- this case also locks in the constraint that "per-queue mixing of WRR/DRR on
    one port is unsupported"."""
    chip.require()
    _skip_if_queues_bound(cli, sched_port, [_Q])
    ok, undo, via, text = _mk_sched_bound(cli, "FVTFLGD", sched_port, _Q, weight=40)
    if not ok:
        pytest.fail(f"cannot provision DWRR scheduler (via={via}): {text}")
    undos = [undo]
    try:
        okc, ent = chip.wait_field(
            lambda: chip.sched_node(sched_port, _Q), "WEIGHT",
            lambda v: v == 40, timeout=30)
        assert okc, f"DWRR w40 not on chip node: {ent}"
        okf, prof = chip.wait_field(
            lambda: chip.lookup("TM_SCHEDULER_PORT_PROFILE",
                                PORT_ID=chip.port_id(sched_port)) or {},
            "WRR", lambda v: v == 0, timeout=15)
        assert okf, (
            f"DWRR bound but TM_SCHEDULER_PORT_PROFILE.WRR != 0 ({prof}); DRR must "
            f"select byte-mode WERR at port level")
        # rebind the WRR profile (del+add; SONiC's duplicate add is rejected as already exists)
        if qos.has_qos_cli(cli):
            ok2, undo_s2, why2 = lossless.make_scheduler(cli, "FVTFLGW", mode="WRR",
                                                         weight=40)
            if not ok2:
                pytest.skip(f"scheduler add -t WRR rejected: {why2}")
            undos.append(undo_s2)
            cli.config_raw(f"port-queue del {sched_port} {_Q}")
            ok3, undo_q2 = lossless.bind_queue(cli, sched_port, _Q, sched="FVTFLGW")
            if not ok3:
                pytest.fail("port-queue rebind to WRR profile rejected")
            undos.append(undo_q2)
        else:
            gcu = Gcu(cli)
            r = gcu.apply_patch([{"op": "replace",
                                  "path": gcu.path("SCHEDULER", "FVTFLGD") + "/type",
                                  "value": "WRR"}])
            if r.rc != 0:
                pytest.skip(f"GCU cannot flip scheduler type to WRR: "
                            f"{(r.out or r.err or '')[-140:]}")
        okf2, prof2 = chip.wait_field(
            lambda: chip.lookup("TM_SCHEDULER_PORT_PROFILE",
                                PORT_ID=chip.port_id(sched_port)) or {},
            "WRR", lambda v: v == 1, timeout=15)
        assert okf2, (
            f"WRR bound but TM_SCHEDULER_PORT_PROFILE.WRR != 1 ({prof2}); WRR must "
            f"select packet-mode weighted RR at port level")
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_shaper_only_rebind_replaces_sp_on_chip(cli, chip, sched_port):
    """"pure shaping profile clobbers SP" semantics lock-in (a common human root cause of "SP
    was configured but has no effect"):
      1) bind STRICT to q -> chip SCHED_MODE=SP;
      2) rebind the same queue with a profile **that has no -t, only pir** -> the chip must
         fall back to RR/WEIGHT=1 (one profile per queue, wholesale replacement; default
         algorithm=WRR/w=1).
    Step 2 asserts the **replacement semantics itself**: if a future image changes to "preserve
    the original scheduling type", this case flags the semantic change; the test team can use it
    to self-check the "configuring SP then rate-limit as two separate profiles" config error.
    Ops rule: scheduling type and cir/pir must be written in the **same** scheduler profile."""
    chip.require()
    if not qos.has_qos_cli(cli):
        pytest.skip("community YANG requires SCHEDULER.type; a type-less shaper-only "
                    "profile is an klish-only construct")
    _skip_if_queues_bound(cli, sched_port, [_Q])
    ok, undo_s, why = lossless.make_scheduler(cli, "FVTSPX", mode="STRICT")
    if not ok:
        pytest.fail(f"scheduler add -t STRICT rejected: {why}")
    undos = [undo_s]
    try:
        okb, undo_q = lossless.bind_queue(cli, sched_port, _Q, sched="FVTSPX")
        if not okb:
            pytest.fail("port-queue bind of STRICT profile rejected")
        undos.append(undo_q)
        okc, ent = chip.wait_field(
            lambda: chip.sched_node(sched_port, _Q), "SCHED_MODE",
            lambda v: v == "SP", timeout=30)
        assert okc, f"STRICT not programmed before rebind: {ent}"
        # pure shaping profile: no -t, only pir/pbs (cir gating follows make_scheduler logic)
        rc, r = cli.config_raw("scheduler add FVTSHONLY -m bytes -pr 300000 -ps 8192")
        text = ((r.out or "") + (r.err or "")).lower()
        if rc != 0 and "cir" in text:
            rc, r = cli.config_raw(
                "scheduler add FVTSHONLY -m bytes -cr 0 -cs 0 -pr 300000 -ps 8192")
        if not cli.db_hgetall("CONFIG_DB", "SCHEDULER|FVTSHONLY"):
            pytest.skip(f"cannot create a type-less shaper-only scheduler: "
                        f"{((r.out or '') + (r.err or ''))[-140:]}")
        undos.append(lambda: cli.config_raw("scheduler del FVTSHONLY"))
        cli.config_raw(f"port-queue del {sched_port} {_Q}")
        okb2, undo_q2 = lossless.bind_queue(cli, sched_port, _Q, sched="FVTSHONLY")
        if not okb2:
            pytest.fail("port-queue rebind to shaper-only profile rejected")
        undos.append(undo_q2)
        okc2, ent2 = chip.wait_field(
            lambda: chip.sched_node(sched_port, _Q), "SCHED_MODE",
            lambda v: v != "SP", timeout=30)
        assert okc2, (
            f"chip still SCHED_MODE=SP after rebinding a shaper-only profile "
            f"({ent2}) — replace semantics changed (queue keeps stale SP?); "
            f"update this test AND the ops guidance if intentional")
        assert ent2 and ent2.get("SCHED_MODE") == "RR" and ent2.get("WEIGHT") == 1, (
            f"expected fallback to default RR/WEIGHT=1 after shaper-only rebind, got "
            f"{ent2} — the silent SP-clobber semantics (one profile per queue; "
            f"type-less profile defaults to WRR w=1) no longer holds as documented")
    finally:
        for u in reversed(undos):
            try:
                u()
            except Exception:  # noqa: BLE001
                pass


def test_chip_threshold_mode_visible(chip):
    """Global TM threshold mode readability + valid domain (LOSSY / LOSSY_AND_LOSSLESS). In a
    lossless deployment it should be LOSSY_AND_LOSSLESS (global LOSSY is inconsistent with a
    lossless workload) -- here we only read/record and validate the valid domain; the
    workload judgment is asserted by the RoCE group's cases together with the config."""
    chip.require()
    ent = chip.thd_config()
    assert ent and "THRESHOLD_MODE" in ent, \
        f"TM_THD_CONFIG unreadable via lt (entry={ent})"
    mode = str(ent["THRESHOLD_MODE"])
    print(f"chip THRESHOLD_MODE={mode}")
    assert mode in ("LOSSY", "LOSSY_AND_LOSSLESS", "LOSSLESS"), \
        f"unexpected THRESHOLD_MODE value {mode!r}"
