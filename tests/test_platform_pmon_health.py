"""Platform pmon health checks (read-only, no injection): detect field signatures of "a defect happening on this device".

Each check targets one class of platform health signature:
    1) pmon daemons free of FATAL/EXITED
    2) sync daemon unit not in a "playing dead" state
    3) bmc_cache is fresh (mtime + timestamp field)
    4) TEMPERATURE_INFO rows are fresh and not all-N/A frozen
    5) PSU_INFO presence=true rows must carry detail fields
    6) every thermal sensor declared in config has a row
    7) FAN_INFO rows not collapsed by duplicate names

Conventions: STATE_DB dynamic enumeration, do not hard-code counts; honestly skip on platforms without the
architecture / without data; assert/skip messages, docstrings, and comments all in English.
"""
import datetime
import re

import pytest

from framework.pmon_fault import PmonCtl, PlatformState, PMON_DAEMONS

pytestmark = [pytest.mark.platform, pytest.mark.cli]


@pytest.fixture(scope="module")
def ctl(sh):
    return PmonCtl(sh)


@pytest.fixture(scope="module")
def state(sh):
    return PlatformState(sh)


def _require(cond, why):
    if not cond:
        pytest.skip(why)


# 1 -------------------------------------------------------------------

def test_pmon_daemons_alive(sh, ctl):
    """Critical pmon daemons must not be in FATAL/EXITED/STOPPED (field signature of the startup-death family)."""
    _require(sh.run("docker ps --format '{{.Names}}'").out.find("pmon") >= 0,
             "pmon container not running on this device")
    states = ctl.supervisor_states()
    _require(states, "supervisorctl not available in pmon")
    bad = {d: s for d, s in states.items()
           if d in PMON_DAEMONS and s in ("FATAL", "EXITED", "STOPPED", "BACKOFF")}
    assert not bad, ("pmon daemons dead: %s (startup-crash family)" % bad)


# 2 -------------------------------------------------------------------

def test_sync_unit_not_zombie(ctl):
    """The sync daemon unit must not "play dead": active(exited) with no live process = crashed and never restarted."""
    _require(ctl.has_sync_unit(), "no bmc2cpu_cache_sync unit (non bmc-cache platform)")
    props = ctl.sync_props()
    alive = ctl.sync_proc_alive()
    zombie = (props.get("ActiveState") == "active"
              and props.get("SubState") == "exited" and not alive)
    assert not zombie, ("sync unit shows active(exited) but process is gone: "
                        "RemainAfterExit defeats Restart; props=%s" % props)
    assert alive, "sync daemon process not running (unit=%s)" % props


# 3 -------------------------------------------------------------------

def test_bmc_cache_fresh(state):
    """The cache file must be fresh: both mtime and content timestamp should be within 6x the sync period (10s)."""
    _require(state.has_cache_arch(), "no bmc_cache file (non bmc-cache platform)")
    # 120s threshold: with a slow real BMC one sync period can reach ~90s, so leave margin or freshness is misjudged as a failure.
    age = state.cache_age_s()
    assert age is not None and age <= 120, \
        "bmc_cache mtime stale: age=%ss (sync daemon dead?)" % age
    cache = state.read_cache()
    assert cache is not None, "bmc_cache is not valid JSON (torn write)"
    ts = cache.get("timestamp")
    assert ts, "bmc_cache missing timestamp field"
    dt = datetime.datetime.strptime(ts, "%Y%m%d %H:%M:%S")
    drift = abs((datetime.datetime.now() - dt).total_seconds())
    assert drift <= 180, \
        "bmc_cache content timestamp stale: %s (drift=%ss)" % (ts, drift)


# 4 -------------------------------------------------------------------

def test_temperature_rows_fresh_not_frozen(state):
    """Temperature rows must be updating and not all N/A: all-N/A + a stalled timestamp is treated as a fault."""
    rows = state.db_table("TEMPERATURE_INFO")
    _require(rows, "no TEMPERATURE_INFO rows on this device")
    now = datetime.datetime.now()
    stale, na = [], []
    for key, row in rows.items():
        if row.get("temperature") in ("N/A", None, ""):
            na.append(key)
        ts = row.get("timestamp")
        if ts:
            dt = datetime.datetime.strptime(ts, "%Y%m%d %H:%M:%S")
            if abs((now - dt).total_seconds()) > 3 * 60 + 30:
                stale.append("%s(ts=%s)" % (key, ts))
    assert len(na) < len(rows), \
        "ALL temperature rows are N/A (sensor readings not updating)"
    assert not stale, \
        "temperature rows frozen (not updating): %s" % stale


# 5 -------------------------------------------------------------------

def test_psu_detail_fields_present(state):
    """PSU rows with presence=true must carry detail fields: missing model/voltage = psud has fallen back to 1.0."""
    rows = state.db_table("PSU_INFO")
    _require(rows, "no PSU_INFO rows on this device")
    blanks = state.psu_detail_blank()
    assert not blanks, \
        ("PSU rows have presence but no detail fields %s: psud is running in "
         "1.0 psuutil fallback (Chassis() failed at startup; blank columns in "
         "'show platform psustatus')" % blanks)


# 6 -------------------------------------------------------------------

def test_configured_thermal_sensors_all_reported(sh, state):
    """Every sensor declared in the platform thermal config should have a TEMPERATURE_INFO row (missing-key detection)."""
    cfg = "/usr/share/sonic/device/%s/sonic_platform_config/thermal.json" % \
        state.platform()
    r = sh.run("sudo cat %s" % cfg)
    _require(r.ok and r.out.strip(), "no sonic_platform_config/thermal.json")
    import json as _json
    names = _json.loads(r.out).get("get_name", {}).get("value_list", [])
    _require(names, "thermal.json has no get_name value_list")
    rows = state.db_table("TEMPERATURE_INFO")
    _require(rows, "no TEMPERATURE_INFO rows on this device")
    missing = [n for n in names if n not in rows]
    assert not missing, \
        ("configured thermal sensors missing from TEMPERATURE_INFO: %s "
         "(BMC not reporting the key, or row lost)" % missing)


# 7 -------------------------------------------------------------------

def test_fan_rows_not_collapsed_by_duplicate_names(sh, state):
    """FAN_INFO row count must not collapse due to duplicate fan names."""
    cfg = "/usr/share/sonic/device/%s/sonic_platform_config/fan.json" % \
        state.platform()
    r = sh.run("sudo cat %s" % cfg)
    _require(r.ok and r.out.strip(), "no sonic_platform_config/fan.json")
    import json as _json
    fan_cfg = _json.loads(r.out)
    names = fan_cfg.get("get_name", {}).get("value_list", [])
    _require(names, "fan.json has no get_name value_list")
    dup = sorted({n for n in names if names.count(n) > 1})
    rows = state.db_table("FAN_INFO")
    _require(rows, "no FAN_INFO rows on this device")
    chassis_rows = [k for k in rows if "PSU" not in k]
    assert not dup or len(chassis_rows) >= len(names), \
        ("duplicate fan names %s collapse FAN_INFO rows: %d configured fans -> "
         "%d rows (a faulty rotor can hide behind its twin's row)"
         % (dup, len(names), len(chassis_rows)))
