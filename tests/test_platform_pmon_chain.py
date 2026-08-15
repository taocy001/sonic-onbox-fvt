"""Full-chain platform fault injection (mock BMC -> real sync daemon -> real cache
-> real platform API -> real psud/thermalctld -> STATE_DB -> real show).

Mechanism: a local MockBmc impersonates the OpenBMC REST endpoint, and an iptables
REDIRECT points 240.1.1.1:8080 at the mock (pmon runs on host networking, so the
in-container direct path is captured too). Baseline data is snapshotted from the real
BMC before testing, and each scenario mutates that baseline. While redirected, every
write (POST) lands on the mock and never touches the real BMC.

Groups (scenario IDs align with sonic-buildimage
platform/.../tests/bmc_testkit/fault_scenarios.py):
    Group S: real-hardware versions of the S1-S9 injection scenarios (boot-class cases
             that restart pmon come last, as they are slow)
    Group B: sync daemon survivability under BMC behavioral faults (refused / bad JSON)
    Group W: write path (content pushed to the BMC on fan set-speed, plus a latency bound)

Assertions encode the [expected/post-fix] behavior -- if platform/pmon carries the
related defect, these cases honestly FAIL on real hardware and turn PASS once fixed.

Destructive note: kills the sync daemon, rewrites the cache, restarts pmon. The whole
group is skipped by default and only runs with an explicit `FVT_PLATFORM_FAULT=1`; test
devices only. Each case restores state in a finally block, and the suite re-checks the S0
baseline gate before exiting (must not be worse than on entry).
"""
import json
import os
import time

import pytest

from framework.pmon_fault import (BmcRedirect, PmonCtl, PlatformState,
                                  SYNC_UNIT, wait_s)
from servers.mock_bmc import MockBmc

pytestmark = [pytest.mark.platform, pytest.mark.platform_fault]

if os.environ.get("FVT_PLATFORM_FAULT", "0") != "1":
    pytest.skip("disruptive pmon fault-injection suite; "
                "set FVT_PLATFORM_FAULT=1 to run", allow_module_level=True)


class Env:
    def __init__(self, sh):
        self.sh = sh
        self.ctl = PmonCtl(sh)
        self.state = PlatformState(sh)
        self.mock = MockBmc()
        self.redirect = BmcRedirect(sh, self.mock.port)
        self.entry_problems = []


@pytest.fixture(scope="module")
def env(sh):
    e = Env(sh)
    if not e.ctl.has_sync_unit():
        pytest.skip("no %s: not a bmc-cache platform" % SYNC_UNIT)
    if not e.state.has_cache_arch():
        pytest.skip("no bmc_cache file on this platform")
    # Preferred: derive the baseline from the on-disk cache (real shape, independent of
    # live BMC latency); fallback: snapshot the real BMC directly (jittery latency,
    # retried per endpoint).
    if not e.mock.snapshot_from_cache(e.state.read_cache()) \
            and not e.mock.snapshot_from_real():
        pytest.skip("cannot baseline the mock (no readable cache, BMC unreachable)")
    e.mock.start()
    e.redirect.mock_port = e.mock.port
    e.entry_problems = e.state.baseline_problems()
    e.entry_states = e.ctl.supervisor_states()
    yield e
    # Teardown: restore everything and re-check the baseline (must not be worse than entry)
    e.redirect.restore()
    e.mock.stop()
    e.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    e.state.wait_cache_fresh()
    left = [p for p in e.state.baseline_problems() if p not in e.entry_problems]
    assert not left, "suite left device unhealthy: %s" % left


def _require_healthy(env, need_thermalctld=False, need_psud_20=False):
    """Healthy-baseline precondition for injection cases: honestly skip when the device is already in the defect state (results would be misleading)."""
    if need_thermalctld:
        st = env.ctl.supervisor_states().get("thermalctld")
        if st != "RUNNING":
            pytest.skip("thermalctld=%s before injection (live defect on this "
                        "device); fix startup crash first" % st)
    if need_psud_20:
        if env.state.psu_detail_blank():
            pytest.skip("psud already in 1.0 fallback before injection "
                        "(live defect on this device); fix startup crash first")


def _recover(env, boot=False):
    """Uniform per-case recovery: reset mock + drop redirect + bring daemon back up (+ restart pmon)."""
    env.mock.reset()
    env.redirect.restore()
    env.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    env.state.wait_cache_fresh()           # event-driven wait for the cache to actually refresh (BMC is slow)
    states = env.ctl.supervisor_states()
    # only touch pmon if a daemon is worse off than on entry (device may arrive with a pre-existing defect)
    degraded = [d for d in ("psud", "thermalctld")
                if states.get(d) != env.entry_states.get(d)
                and states.get(d) != "RUNNING"]
    if boot or degraded:
        env.ctl.restart_pmon()
        wait_s(20, "daemons first cycles after pmon restart")
    left = [p for p in env.state.baseline_problems()
            if p not in env.entry_problems]
    assert not left, "recovery failed, device still unhealthy: %s" % left


# =====================================================================
# Group S (runtime, no pmon restart)
# =====================================================================

def test_s5_sentinel_voltage_not_zero(env):
    """Dead-sensor sentinel -99999 must be reported as N/A, not 0.0 (0.0 trips a psud
    voltage-out-of-range false alarm and an attempt to set the LED red; show displaying
    0.00 with Status OK is highly misleading)."""
    _require_healthy(env, need_psud_20=True)
    env.mock.set_psu_field("PSU1", ["Outputs", "Voltage", "Value"], -99999)
    env.redirect.to_mock()
    try:
        wait_s(20, "sync(10s)+psud(3s) cycles")
        row = env.state.db_row("PSU_INFO|PSU 1")
        assert row.get("voltage") != "0.0", \
            "sentinel voltage reported as 0.0; expect N/A"
    finally:
        _recover(env)


def test_s9_sensor_vanish_row_must_not_freeze(env):
    """When the BMC stops reporting OcmBoard at runtime, the row must update to N/A rather than freezing forever as stale/dead data (value and timestamp)."""
    _require_healthy(env, need_thermalctld=True)
    before = env.state.db_row("TEMPERATURE_INFO|OcmBoard")
    if not before:
        pytest.skip("no OcmBoard row on this device")
    env.mock.drop_sensor("OcmBoard")
    env.redirect.to_mock()
    try:
        wait_s(80, "one thermalctld cycle (60s) after cache refresh")
        after = env.state.db_row("TEMPERATURE_INFO|OcmBoard")
        assert after.get("temperature") == "N/A", \
            ("OcmBoard row frozen at stale value %r (ts %s -> %s)"
             % (after.get("temperature"), before.get("timestamp"),
                after.get("timestamp")))
    finally:
        _recover(env)


def test_s7_fan_key_vanish_must_not_kill_thermalctld(env):
    """The BMC dropping the FAN1 key at runtime must not kill the whole thermalctld."""
    _require_healthy(env, need_thermalctld=True)
    env.mock.drop_fan("FAN1")
    env.redirect.to_mock()
    try:
        wait_s(80, "one thermalctld cycle after cache refresh")
        states = env.ctl.supervisor_states()
        assert states.get("thermalctld") == "RUNNING", \
            ("thermalctld state=%s after single fan key vanished"
             % states.get("thermalctld"))
        row = env.state.db_row("FAN_INFO|FAN 1")
        assert str(row.get("presence")).lower() == "false", \
            "vanished fan should report Not Present, got %r" % row.get("presence")
    finally:
        _recover(env)


def test_s6_fan_zero_maxspeed_not_reported_faulty(env):
    """With SpeedMax=0, a spinning fan must not be silently reported as 0%/Not OK (otherwise a false fault, amber LED, and an inflated faulty count)."""
    _require_healthy(env, need_thermalctld=True)
    for rotor in ("Rotor1", "Rotor2"):
        env.mock.set_fan_field("FAN1", [rotor, "SpeedMax"], 0)
    env.redirect.to_mock()
    try:
        wait_s(80, "one thermalctld cycle after cache refresh")
        row = env.state.db_row("FAN_INFO|FAN 1")
        assert str(row.get("status")).lower() != "false", \
            ("spinning fan reported faulty (speed=%s) on SpeedMax=0"
             % row.get("speed"))
    finally:
        _recover(env)


def test_s1_sync_crash_must_be_restarted(env):
    """After the sync daemon crashes, systemd must bring it back up (Restart=on-failure).

    A crash/kill is a failure exit, so Restart=on-failure applies and is unaffected by
    RemainAfterExit (RemainAfterExit only kicks in on a clean exit 0, and this daemon
    never exits cleanly)."""
    env.ctl.crash_sync()
    try:
        wait_s(60, "systemd Restart window (RestartSec=30)")
        props = env.ctl.sync_props()
        alive = env.ctl.sync_proc_alive()
        assert alive, \
            ("sync daemon not restarted after crash: unit=%s/%s (zombie "
             "active(exited); RemainAfterExit defeats Restart)"
             % (props.get("ActiveState"), props.get("SubState")))
    finally:
        _recover(env)


# =====================================================================
# Group B (sync daemon survivability under BMC behavioral faults)
# =====================================================================

def test_b1_sync_survives_bmc_refused(env):
    """When the BMC refuses connections, the sync daemon should skip the cycle rather than crash out."""
    env.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    wait_s(5, "sync fresh start")
    env.redirect.refuse()
    try:
        wait_s(45, "several sync cycles under refused BMC")
        assert env.ctl.sync_proc_alive(), \
            ("sync daemon died while BMC refused connections; journal: %s"
             % env.ctl.journal_tail(lines=8))
    finally:
        _recover(env)


def test_b2_sync_survives_malformed_json(env):
    """The sync daemon should survive the BMC returning malformed JSON."""
    env.mock.set_mode("malformed")
    env.redirect.to_mock()
    env.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    try:
        wait_s(30, "sync cycles under malformed JSON")
        assert env.ctl.sync_proc_alive(), \
            "sync daemon died on malformed BMC JSON"
    finally:
        _recover(env)


# =====================================================================
# Group W (write path)
# =====================================================================

def test_w1_setspeed_reaches_bmc_bounded(env):
    """Fan set-speed is pushed to the BMC through the platform API -- verify the request
    actually goes out, carries config_fan, and a single call is bounded (<60s)."""
    _require_healthy(env, need_psud_20=True)
    env.redirect.to_mock()      # POST lands on the mock, does not touch the real BMC
    try:
        t0 = time.time()
        r = env.sh.run(
            "python3 -c \"import sonic_platform.platform as p;"
            "c=p.Platform().get_chassis();print(c.get_all_fans()[0].set_speed(60))\"",
            container="pmon", timeout=120)
        elapsed = time.time() - t0
        assert elapsed < 60, \
            "set_speed took %.0fs (unbounded HTTP timeouts)" % elapsed
        posts = [p for p, body in env.mock.posts if "rawcmd" in p]
        assert posts, ("no POST reached BMC for set_speed (rc=%s out=%r); "
                       "write path broken or not routed" % (r.rc, r.out))
        bodies = [body for p, body in env.mock.posts if "rawcmd" in p]
        assert any("config_fan" in json.dumps(b) for b in bodies), \
            "set_speed POST body does not carry config_fan command: %s" % bodies
    finally:
        _recover(env)


# =====================================================================
# Group S (boot-class: involves a pmon restart, slow, kept last)
# =====================================================================

def test_s8_partial_sensor_boot_must_not_kill_daemons(env):
    """Booting while the BMC is missing the single OcmBoard key must not kill pmon daemons at startup."""
    env.mock.drop_sensor("OcmBoard")
    env.redirect.to_mock()
    try:
        env.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
        wait_s(15, "sync writes OcmBoard-less cache")
        states = env.ctl.restart_pmon()
        assert states.get("thermalctld") == "RUNNING", \
            ("thermalctld=%s after boot with one sensor key missing"
             % states.get("thermalctld"))
        wait_s(20, "psud first cycles")
        blanks = env.state.psu_detail_blank()
        assert not blanks, \
            ("psud fell back to 1.0 psuutil, PSU detail columns blank: %s "
             "(the exact field symptom: presence only, no values)" % blanks)
    finally:
        _recover(env, boot=True)


def test_s2_corrupt_cache_boot_must_not_kill_daemons(env):
    """Booting onto a power-loss-corrupted cache (truncated JSON) must not kill daemons at startup; the sync daemon rewrites a good cache within 10s."""
    env.redirect.to_mock()
    try:
        env.ctl.stop_sync()
        env.sh.run("echo '{\"psu_info\": {\"PSU1\"' | sudo tee %s >/dev/null"
                   % env.state.cache_path(), check=True)
        states = env.ctl.restart_pmon()
        env.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
        assert states.get("thermalctld") == "RUNNING", \
            ("thermalctld=%s after boot on corrupt cache"
             % states.get("thermalctld"))
        wait_s(20, "psud cycles after cache repaired")
        assert not env.state.psu_detail_blank(), \
            "psud stuck in 1.0 fallback after cache repaired (needs pmon restart)"
    finally:
        _recover(env, boot=True)


def test_s4_minmax_not_poisoned_by_empty_boot_window(env):
    """A pmon started during a cache-empty window must recover real temperature readings once the BMC/cache are ready."""
    env.redirect.to_mock()
    try:
        env.ctl.stop_sync()
        env.sh.run("sudo rm -f %s" % env.state.cache_path(), check=True)
        env.ctl.restart_pmon()                    # construct the empty window
        env.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
        wait_s(140, "two thermalctld cycles after cache became healthy")
        rows = env.state.db_table("TEMPERATURE_INFO")
        assert rows, "no TEMPERATURE_INFO rows at all"
        na = [k for k, r in rows.items() if r.get("temperature") == "N/A"]
        assert len(na) < len(rows), \
            ("ALL %d temperature rows stuck at N/A after cache became healthy"
             % len(rows))
    finally:
        _recover(env, boot=True)
