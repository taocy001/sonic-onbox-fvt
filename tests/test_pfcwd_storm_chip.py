"""PFCWD storm full cycle and chip DLR mode -- DEBUG_STORM driven, no real XOFF source needed.

DEBUG_STORM is the official test hook of pfc_detect lua: HSET DEBUG_STORM enabled on
`COUNTERS:<queue_oid>` declares a storm directly, and after HDEL it restores by the real criterion.
CPU injection on the bench cannot sustain XOFF (at 800G a 0xffff quanta lasts only 42us), so this is
the only automatable full-cycle entry point.

pfcwd has two action channels, fixed at orchagent startup by the SAI capability bit
(STATE_DB PFC_DLR_INIT_CAPABLE): false = software action (change the PFC bitmap / swap buffer
profile), true = chip DLR (SAI_QUEUE_ATTR_PFC_DLR_INIT -> SDKLT manual recovery state machine).

  PW1 storm -> action -> restore full cycle (runs in both modes); DLR mode adds chip assertions:
      during the storm TM_PFC_DEADLOCK_RECOVERY_MANUAL_STATE=RECOVERY, back to IDLE after restore.
  PW2 DLR-mode programming chain: create_switch already wrote MANUAL_RECOVERY=1 for all ports;
      the recovery-action register switches with the pfcwd action (forward=TRANSMIT/drop=DISCARD, global granularity).
  PW3 unarmed priority (DLR mode only): after an armed priority completes storm->restore
      (DLR_INIT true->false), a priority that never armed hardware detection must have its
      TM_PFC_DEADLOCK_RECOVERY_TIMER_CONTROL entry unchanged -- recovery_end only rebuilds a DD timer
      for priorities that were armed; a mistaken rebuild exposes a regression;
  PW4 multi-port multi-priority (slow): >=2 ports x >=2 lossless priorities concurrent storm -> restore full cycle,
      asserting per (port,pri) that state transitions independently, without cross-talk.

Note: while DEBUG_STORM is set, some NOSes' restore does not consult that flag, so storm/restore
oscillate periodically -- all state assertions poll-sample rather than making a single-snapshot judgment.
"""
import time

import pytest

from framework.gcu import Gcu
from framework.lossless import build_lossless, pfcwd_blocked, pick_pfc_port

pytestmark = [pytest.mark.qos]

_DET_MS, _RST_MS = 200, 400


@pytest.fixture(scope="module")
def wd_pobj(cli, topo):
    p, why = pick_pfc_port(cli, topo)
    if p is None:
        pytest.skip("no candidate port for PFC tests")
    if why == "all-blocked":
        pytest.fail("every candidate port carries a stale PFC_WD entry; clear with "
                    f"top-level `pfcwd stop <port>` and rerun (port={p.name})")
    return p


@pytest.fixture(scope="module")
def wd(cli, wd_pobj):
    """Lossless baseline (same as the roce suite): PFC enable is a precondition for pfcwd start."""
    b = build_lossless(cli, Gcu(cli), wd_pobj.name)
    if not any(s[0] == "pfc_on" and s[1] for s in b.steps):
        b.undo()
        pytest.skip(f"pfc enable unavailable on this image (steps={b.steps})")
    yield b
    b.undo()


def _dlr_mode(cli):
    h = cli.db_hgetall("STATE_DB", "SWITCH_CAPABILITY|switch") or {}
    return h.get("PFC_DLR_INIT_CAPABLE") == "true"


def _queue_oid(cli, port, q):
    qmap = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP") or {}
    return qmap.get(f"{port}:{q}")


def _wd_status(cli, qoid):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{qoid}") or {}
    return h.get("PFC_WD_STATUS")


def _wait(pred, timeout=10.0, interval=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(interval)
    return pred()


def _wd_start(cli, port, action):
    r = cli.run(f"pfcwd start --action {action} {port} {_DET_MS} "
                f"--restoration-time {_RST_MS}")
    if r.rc != 0:
        pytest.fail(f"pfcwd start rejected on pfc-enabled port: "
                    f"{((r.out or '') + (r.err or ''))[-160:]}")
    ok = _wait(lambda: (cli.db_hgetall("CONFIG_DB", f"PFC_WD|{port}") or {})
               .get("action") == action, timeout=8)
    assert ok, f"PFC_WD|{port}.action != {action} after pfcwd start"


def _wd_stop(cli, port):
    """Must really stop: a leftover PFC_WD causes subsequent `pfc priority` config to be silently rejected."""
    for _ in range(3):
        cli.run(f"pfcwd stop {port}")
        if not cli.db_hgetall("CONFIG_DB", f"PFC_WD|{port}"):
            return
        time.sleep(2)
    pytest.fail(f"CLEANUP FAILURE: PFC_WD|{port} still present after 3 stop attempts")


def _manual_state(cli, chip, port, pri):
    ent = chip.lookup("TM_PFC_DEADLOCK_RECOVERY_MANUAL_STATE",
                      PORT_ID=chip.port_id(port), PFC_PRI=pri)
    return ent and ent.get("STATE")


def test_pw1_storm_restore_cycle(wd, cli, chip):
    """PW1: DEBUG_STORM set -> queue declared storm; HDEL -> restored to operational.
    DLR mode adds: during the storm chip MANUAL_STATE reached RECOVERY, back to IDLE after restore."""
    port, q = wd.port, wd.queue
    qoid = _queue_oid(cli, port, q)
    assert qoid, f"COUNTERS_QUEUE_NAME_MAP has no {port}:{q}"
    dlr = _dlr_mode(cli)
    chip_ok = (dlr and chip.available()
               and chip.has_table("TM_PFC_DEADLOCK_RECOVERY_MANUAL_STATE"))
    _wd_start(cli, port, "drop")
    try:
        cli.db_hset("COUNTERS_DB", f"COUNTERS:{qoid}", "DEBUG_STORM", "enabled")
        stormed = _wait(lambda: _wd_status(cli, qoid) not in (None, "operational"),
                        timeout=10)
        assert stormed, (
            f"queue {port}:{q} never left operational after DEBUG_STORM=enabled "
            f"(status={_wd_status(cli, qoid)}); pfcwd detection not running")
        if chip_ok:
            hit = _wait(lambda: _manual_state(cli, chip, port, q) == "RECOVERY",
                        timeout=12)
            assert hit, (
                f"DLR mode: chip MANUAL_STATE never reached RECOVERY during storm "
                f"(last={_manual_state(cli, chip, port, q)}); PFC_DLR_INIT is a "
                f"silent no-op (state machine only honored "
                f"DEADLOCK->RECOVERY)")
    finally:
        cli.db("COUNTERS_DB", f'HDEL "COUNTERS:{qoid}" DEBUG_STORM')
        restored = _wait(lambda: _wd_status(cli, qoid) == "operational", timeout=15)
        _wd_stop(cli, port)
    assert restored, (
        f"queue {port}:{q} never restored to operational after DEBUG_STORM removed "
        f"(status={_wd_status(cli, qoid)})")
    if chip_ok:
        idle = _wait(lambda: _manual_state(cli, chip, port, q) == "IDLE", timeout=10)
        assert idle, (
            f"DLR mode: chip MANUAL_STATE stuck at "
            f"{_manual_state(cli, chip, port, q)} after restore; recovery exit "
            f"not programmed")


def test_pw2_dlr_mode_programming(wd, cli, chip):
    """PW2 (DLR mode only): MANUAL_RECOVERY already programmed by create_switch;
    the recovery-action register switches with the pfcwd action. The action is a **global** register --
    the whole box's pfcwd can only uniformly forward or drop, which is also why this case only needs to verify on one port."""
    if not _dlr_mode(cli):
        pytest.skip("image runs software pfcwd (PFC_DLR_INIT_CAPABLE=false)")
    chip.require()
    if not chip.has_table("TM_PFC_DEADLOCK_RECOVERY"):
        pytest.skip("no TM_PFC_DEADLOCK_RECOVERY on this chip generation")
    port, pri = wd.port, wd.pg
    ent = chip.lookup("TM_PFC_DEADLOCK_RECOVERY",
                      PORT_ID=chip.port_id(port), PFC_PRI=pri)
    assert ent and ent.get("MANUAL_RECOVERY") == 1, (
        f"MANUAL_RECOVERY != 1 for {port}/pri{pri} (entry={ent}); capability "
        f"advertised but manual mode not programmed at create_switch — every "
        f"PFC_DLR_INIT will fail INVALID_PARAMETER")
    try:
        for action, want in (("forward", "TRANSMIT"), ("drop", "DISCARD")):
            _wd_start(cli, port, action)
            ok = _wait(lambda: (chip.lookup("TM_PFC_DEADLOCK_RECOVERY_CONTROL") or {})
                       .get("ACTION") == want, timeout=8)
            assert ok, (
                f"pfcwd action={action} not reflected in "
                f"TM_PFC_DEADLOCK_RECOVERY_CONTROL.ACTION (want {want}, got "
                f"{(chip.lookup('TM_PFC_DEADLOCK_RECOVERY_CONTROL') or {}).get('ACTION')})")
    finally:
        _wd_stop(cli, port)


def _pfc_err_count(cli):
    """Count of pfc/deadlock/dlr-related ERR lines in syslog (fingerprint of recovery_end mistakenly building a timer)."""
    r = cli.sh.run("grep -ai err /var/log/syslog | grep -aicE 'pfc|deadlock|dlr'",
                   check=False)
    out = (r.out or "").strip()
    return int(out) if out.isdigit() else 0


def _timer_ctrl(cli, chip, port, pri):
    return chip.lookup("TM_PFC_DEADLOCK_RECOVERY_TIMER_CONTROL",
                       PORT_ID=chip.port_id(port), PFC_PRI=pri)


def test_pw3_unarmed_priority_no_timer_rebuild(wd, cli, chip):
    """PW3 (DLR mode only): after an armed priority completes storm->restore (DLR_INIT true->false),
    a priority on the same port that **never armed hardware detection** must have its TIMER_CONTROL entry unchanged
    (a nonexistent one stays nonexistent) -- if recovery_end does not filter by the armed bit, it will
    mistakenly build a DD timer for the unarmed priority."""
    if not _dlr_mode(cli):
        pytest.skip("image runs software pfcwd (PFC_DLR_INIT_CAPABLE=false)")
    chip.require()
    if not chip.has_table("TM_PFC_DEADLOCK_RECOVERY_TIMER_CONTROL"):
        pytest.skip("no TM_PFC_DEADLOCK_RECOVERY_TIMER_CONTROL on this chip generation")
    port, q, armed = wd.port, wd.queue, wd.pg
    unarmed = 4 if armed != 4 else 2   # a non-lossless priority on this port that never armed detection
    before = _timer_ctrl(cli, chip, port, unarmed)
    base = _pfc_err_count(cli)
    qoid = _queue_oid(cli, port, q)
    assert qoid, f"COUNTERS_QUEUE_NAME_MAP has no {port}:{q}"
    _wd_start(cli, port, "drop")
    try:
        cli.db_hset("COUNTERS_DB", f"COUNTERS:{qoid}", "DEBUG_STORM", "enabled")
        stormed = _wait(lambda: _wd_status(cli, qoid) not in (None, "operational"),
                        timeout=10)
        assert stormed, (
            f"queue {port}:{q} never left operational after DEBUG_STORM=enabled "
            f"(status={_wd_status(cli, qoid)}); pfcwd detection not running")
    finally:
        cli.db("COUNTERS_DB", f'HDEL "COUNTERS:{qoid}" DEBUG_STORM')
        restored = _wait(lambda: _wd_status(cli, qoid) == "operational", timeout=15)
        _wd_stop(cli, port)
    assert restored, (
        f"queue {port}:{q} never restored to operational after DEBUG_STORM removed "
        f"(status={_wd_status(cli, qoid)})")
    time.sleep(2)   # recovery_end's DD timer rebuild (if mistakenly triggered) lands within this window
    after = _timer_ctrl(cli, chip, port, unarmed)
    assert after == before, (
        f"TIMER_CONTROL entry for never-armed {port}/pri{unarmed} changed by the "
        f"armed priority's recovery cycle: before={before} after={after}; "
        f"recovery_end rebuilt a DD timer for a priority that never armed "
        f"detection")
    got = _pfc_err_count(cli)
    assert got == base, (
        f"pfc/deadlock ERR lines in syslog during unarmed-priority cycle: "
        f"+{got - base}")


@pytest.mark.slow
def test_pw4_multi_port_multi_priority(wd, cli, chip, topo):
    """PW4 (slow): 2 ports x 2 lossless priorities concurrent storm -> restore full cycle.
    First storm only (port1,pri1); the other three (port,pri) must stay operational (no cross-talk);
    then storm all, asserting per (port,pri) that storm is reached (DLR mode adds MANUAL_STATE=RECOVERY);
    after HDEL all, assert per (port,pri) back to operational (DLR mode adds MANUAL_STATE back to IDLE)."""
    port1, pri1 = wd.port, wd.pg
    pri2 = 4 if pri1 != 4 else 2
    port2 = None
    for role in ("g", "h", "e", "f"):
        try:
            p = topo.port(role)
        except KeyError:
            continue
        if p.name != port1 and not pfcwd_blocked(cli, p.name):
            port2 = p.name
            break
    if port2 is None:
        pytest.skip("no second candidate port free of stale PFC_WD entries")
    gcu = Gcu(cli)
    builds = []
    for p, pg, prefix in ((port1, pri2, "FVTPW4A"),
                          (port2, pri1, "FVTPW4B"), (port2, pri2, "FVTPW4C")):
        b = build_lossless(cli, gcu, p, pg=pg, prefix=prefix)
        builds.append(b)
        if not any(s[0] == "pfc_on" and s[1] for s in b.steps):
            for bb in reversed(builds):
                bb.undo()
            pytest.skip(f"second lossless priority unavailable on this image "
                        f"({p}/pg{pg}, steps={b.steps})")
    matrix = [(port1, pri1), (port1, pri2), (port2, pri1), (port2, pri2)]
    qoid = {k: _queue_oid(cli, k[0], k[1]) for k in matrix}
    missing = [k for k, v in qoid.items() if not v]
    assert not missing, f"COUNTERS_QUEUE_NAME_MAP has no queue oid for {missing}"
    dlr = _dlr_mode(cli)
    chip_ok = (dlr and chip.available()
               and chip.has_table("TM_PFC_DEADLOCK_RECOVERY_MANUAL_STATE"))
    started = []
    try:
        for p in (port1, port2):
            _wd_start(cli, p, "drop")
            started.append(p)
        # Stage 1: storm only the first matrix cell; the rest must be unaffected (cross-talk check)
        first = matrix[0]
        cli.db_hset("COUNTERS_DB", f"COUNTERS:{qoid[first]}", "DEBUG_STORM", "enabled")
        assert _wait(lambda: _wd_status(cli, qoid[first]) not in (None, "operational"),
                     timeout=10), (
            f"{first} never left operational after DEBUG_STORM=enabled "
            f"(status={_wd_status(cli, qoid[first])})")
        time.sleep(1)
        for k in matrix[1:]:
            st = _wd_status(cli, qoid[k])
            assert st == "operational", (
                f"cross-talk: {k} left operational (status={st}) while only "
                f"{first} was stormed")
        # Stage 2: storm all, wait per (port,pri) for storm (DLR mode also waits for chip RECOVERY)
        for k in matrix[1:]:
            cli.db_hset("COUNTERS_DB", f"COUNTERS:{qoid[k]}", "DEBUG_STORM", "enabled")
        for k in matrix:
            assert _wait(lambda k=k: _wd_status(cli, qoid[k])
                         not in (None, "operational"), timeout=10), (
                f"{k} never stormed with DEBUG_STORM set on all four "
                f"(status={_wd_status(cli, qoid[k])})")
            if chip_ok:
                assert _wait(lambda k=k: _manual_state(cli, chip, k[0], k[1])
                             == "RECOVERY", timeout=12), (
                    f"DLR mode: {k} MANUAL_STATE never reached RECOVERY "
                    f"(last={_manual_state(cli, chip, k[0], k[1])})")
    finally:
        for k in matrix:
            cli.db("COUNTERS_DB", f'HDEL "COUNTERS:{qoid[k]}" DEBUG_STORM')
        restored = {k: _wait(lambda k=k: _wd_status(cli, qoid[k]) == "operational",
                             timeout=15) for k in matrix}
        for p in started:
            _wd_stop(cli, p)
        for b in reversed(builds):
            b.undo()
    for k in matrix:
        assert restored[k], (
            f"{k} never restored to operational after DEBUG_STORM removed "
            f"(status={_wd_status(cli, qoid[k])})")
        if chip_ok:
            assert _wait(lambda k=k: _manual_state(cli, chip, k[0], k[1]) == "IDLE",
                         timeout=10), (
                f"DLR mode: {k} MANUAL_STATE stuck at "
                f"{_manual_state(cli, chip, k[0], k[1])} after restore")
