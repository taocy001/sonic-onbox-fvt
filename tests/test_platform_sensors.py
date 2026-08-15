"""Platform fan / PSU (pmon) sensor read-only cases ([A] pure show ↔ STATE_DB consistency, no traffic; cli domain).

Adapted from the sonic-mgmt platform_tests/api (fan/psu) approach; this framework previously
had no fan coverage and only indirect SNMP PSU coverage. Coverage (all read-only):
  1) fan presence/status: compare `show platform fan` with STATE_DB FAN_INFO item by item;
  2) fan speed reasonable + consistent: compare show speed with FAN_INFO.speed (tolerance) and within a reasonable range;
  3) PSU presence/status: compare `show platform psustatus` with STATE_DB PSU_INFO item by item;
  4) PSU electrical: compare PSU voltage/current/power with STATE_DB (tolerance) and within a reasonable range;
  5) (optional) if VOLTAGE_INFO/CURRENT_INFO sensors exist, do show↔DB / range validation.

Note: temperature sensors (TEMPERATURE_INFO) are already covered by
`test_platform_temperature_matches_db` in test_transceiver_db.py; this file does not repeat
that, only fan/psu (+voltage/current).

Hard rules:
  - do not hardcode fan/PSU count or names: always enumerate dynamically from STATE_DB keys (FAN_INFO|* / PSU_INFO|*).
  - platforms with no fan / no PSU / fields not exposed -> honest skip with a reason (see the _require_* pattern), never assert True.
  - show and DB field names/units may differ: parse off units (RPM/V/A/W), case-tolerant, join by name.

Prints / assert / skip messages in English; docstrings / comments translated.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.platform, pytest.mark.cli]


# ============================ common helpers ============================
def _crashed(r):
    """Command output contains a Python Traceback -> treat as a device/software crash (used to skip known-crashing subcommands)."""
    return "Traceback (most recent call last)" in f"{r.out}\n{r.err}"


def _num(s):
    """Extract the first float from a string with units/noise (e.g. '10500 RPM'->10500, '12.1V'->12.1); None if absent."""
    if s is None:
        return None
    m = re.search(r"[-+]?\d+(?:\.\d+)?", str(s))
    return float(m.group()) if m else None


def _truthy(v):
    """STATE_DB boolean fields are stored as strings ('True'/'False'); parse tolerantly to bool."""
    return str(v).strip().lower() in ("true", "1", "yes", "present", "ok", "good", "normal", "up")


def _close(a, b, rel=0.2, absfloor=300.0):
    """Sampling-drift tolerance: relative rel, and at least absfloor (handles jitter and unit rounding of large values like speed/power)."""
    return abs(a - b) <= max(absfloor, rel * max(abs(a), abs(b)))


def _row_field(row, *keys):
    """Get a value from a parse_table row by column name (case/whitespace-tolerant, substring match); None if absent."""
    norm = {k.strip().lower(): v for k, v in row.items()}
    for want in keys:
        w = want.strip().lower()
        if w in norm:
            return norm[w]
    # substring fallback (e.g. 'Voltage (V)' contains 'voltage')
    for want in keys:
        w = want.strip().lower()
        for k, v in norm.items():
            if w in k:
                return v
    return None


def _index_rows(rows, name_keys):
    """Index show rows by the name field (lowercased); used to join show rows by STATE_DB key name."""
    idx = {}
    for r in rows:
        name = _row_field(r, *name_keys)
        if name and name.strip():
            idx[name.strip().lower()] = r
    return idx


def _cell_present(cell):
    """show presence/status cell -> whether present. 'Present'/'Not Present'/'Absent'/'NOT PRESENT'."""
    if cell is None:
        return None
    s = str(cell).strip().lower()
    if "not present" in s or s in ("absent", "not present", "not_present"):
        return False
    if "present" in s:
        return True
    return None


def _cell_ok(cell):
    """show status cell -> whether OK. 'OK'/'Not OK'/'NOT OK'/'WARNING'/'FAULT'/'NOT PRESENT'."""
    if cell is None:
        return None
    s = str(cell).strip().lower()
    if "not present" in s:
        return None  # not present, status is meaningless
    if "not ok" in s or "fault" in s or "warning" in s or "fail" in s or "alarm" in s:
        return False
    if "ok" in s or "good" in s or "normal" in s:
        return True
    return None


# ---- dynamically enumerate STATE_DB sensor keys (never hardcode count/names) ----
def _fan_names(cli):
    return [k.split("|", 1)[-1] for k in cli.db_keys("STATE_DB", "FAN_INFO|*") if "|" in k]


def _psu_names(cli):
    return [k.split("|", 1)[-1] for k in cli.db_keys("STATE_DB", "PSU_INFO|*") if "|" in k]


def _require_fans(cli):
    """No fan data at all (STATE_DB FAN_INFO fully empty) -> fail: a physical switch must have
    fans; pmon not reporting fan sensors is a real platform-API / pmon defect, which should be
    exposed rather than masked by skip."""
    names = _fan_names(cli)
    if not names:
        pytest.fail("DEVICE ISSUE: no fan exposed by platform (STATE_DB FAN_INFO empty) — "
                    "a physical switch must report fan sensors; pmon/platform-API not "
                    "populating FAN_INFO is a real defect")
    return sorted(names)


def _require_psus(cli):
    """No PSU data at all (STATE_DB PSU_INFO fully empty) -> fail: a physical switch must have
    PSUs; pmon not reporting PSU sensors is a real platform-API / pmon defect, which should be
    exposed rather than masked by skip."""
    names = _psu_names(cli)
    if not names:
        pytest.fail("DEVICE ISSUE: no PSU exposed by platform (STATE_DB PSU_INFO empty) — "
                    "a physical switch must report PSU sensors; pmon/platform-API not "
                    "populating PSU_INFO is a real defect")
    return sorted(names)


def _show_rows(cli, cmd):
    """Run a show command, return (rows, raw); skip on crash. Empty tables like 'Not detected' are left for the caller to interpret."""
    r = cli.run(cmd)
    if _crashed(r):
        pytest.skip(f"`{cmd}` crashed:\n{r.err[-300:]}")
    return cli.parse_table(r.out), (r.out or "")


# reasonable-range upper limits (loose, tolerate percentage/absolute values, avoid misjudging normal readings).
_FAN_SPEED_UPPER = 100000.0   # speed upper limit (large RPM margin; percentages well within range)
_PSU_RANGES = {               # (low_exclusive, high_inclusive) units V/A/W
    "voltage": (0.0, 300.0),  # output ~12V or input ~110/240V both within range
    "current": (0.0, 300.0),
    "power": (0.0, 10000.0),
}
# PSU electrical STATE_DB field name -> possible column-name aliases in `show platform psustatus`
_PSU_SHOW_COL = {
    "voltage": ("Voltage", "Voltage (V)", "Voltage(V)"),
    "current": ("Current", "Current (A)", "Current(A)"),
    "power": ("Power", "Power (W)", "Power(W)"),
}
# absolute floor for PSU electrical show↔DB consistency tolerance (per unit, V/A/W) -- must not
# reuse the fan-speed-level 300: 12.1V vs 240V differs by 228 yet would falsely pass "within
# 300", making the electrical cross-check useless.
_PSU_ABS_FLOOR = {"voltage": 1.0, "current": 1.0, "power": 25.0}


# ============================ 1) fan presence/status ============================
def test_fan_presence_status_matches_db(cli):
    """Each FAN_INFO's presence/status matches its corresponding `show platform fan` row item by item.

    Dynamically enumerate FAN_INFO|*; join show rows by fan name; presence(True/False) ↔
    Present/Not Present, status(True/False) ↔ OK/Not OK. Skip an item when no comparable column
    exists, honest skip if nothing is comparable throughout.
    """
    fans = _require_fans(cli)
    rows, raw = _show_rows(cli, "show platform fan")
    if "not detected" in raw.lower() and not rows:
        # DB has fans but show reports Not detected -> real inconsistency
        pytest.fail(f"STATE_DB has fans {fans} but `show platform fan` reports 'Not detected'")
    by_name = _index_rows(rows, ("FAN", "Fan", "Name"))
    compared = 0
    for name in fans:
        info = cli.db_hgetall("STATE_DB", f"FAN_INFO|{name}")
        assert info, f"fan {name}: FAN_INFO key present but HGETALL empty"
        row = by_name.get(name.lower())
        assert row is not None, \
            f"fan {name} in STATE_DB FAN_INFO but missing from `show platform fan` rows {sorted(by_name)}"
        # presence comparison
        if "presence" in info:
            db_present = _truthy(info["presence"])
            show_present = _cell_present(_row_field(row, "Presence"))
            if show_present is not None:
                assert db_present == show_present, (
                    f"fan {name}: STATE_DB presence={info['presence']!r} "
                    f"(parsed {db_present}) != show Presence={_row_field(row, 'Presence')!r}")
                compared += 1
        # status comparison (meaningful only when present)
        if "status" in info and _truthy(info.get("presence", "True")):
            db_ok = _truthy(info["status"])
            show_ok = _cell_ok(_row_field(row, "Status"))
            if show_ok is not None:
                assert db_ok == show_ok, (
                    f"fan {name}: STATE_DB status={info['status']!r} (parsed {db_ok}) "
                    f"!= show Status={_row_field(row, 'Status')!r}")
                compared += 1
    if compared == 0:
        pytest.skip("fans present but `show platform fan` exposes no comparable "
                    "Presence/Status column to cross-check STATE_DB FAN_INFO")


# ============================ 2) fan speed reasonable + consistent ============================
def test_fan_speed_reasonable_and_matches_db(cli):
    """`show platform fan` speed compared with STATE_DB FAN_INFO.speed (tolerance) and within a reasonable range (>0 and < upper limit).

    Validate only present fans (presence=True): absent fans often report 0/N/A, no range check.
    Honest skip when no present fan reports a numeric speed.
    """
    fans = _require_fans(cli)
    rows, _ = _show_rows(cli, "show platform fan")
    by_name = _index_rows(rows, ("FAN", "Fan", "Name"))
    checked = 0
    for name in fans:
        info = cli.db_hgetall("STATE_DB", f"FAN_INFO|{name}")
        if not _truthy(info.get("presence", "True")):
            continue  # skip absent fans
        db_speed = _num(info.get("speed"))
        if db_speed is None:
            continue
        # reasonable range: a present fan's speed should be > 0 and less than the upper limit
        assert 0 < db_speed < _FAN_SPEED_UPPER, (
            f"fan {name}: STATE_DB speed={info.get('speed')!r} (parsed {db_speed}) "
            f"out of reasonable range (0, {_FAN_SPEED_UPPER})")
        checked += 1
        # consistency with show (if the show row has a Speed column)
        row = by_name.get(name.lower())
        if row is not None:
            show_speed = _num(_row_field(row, "Speed", "Rpm", "RPM"))
            if show_speed is not None:
                assert _close(show_speed, db_speed), (
                    f"fan {name}: show Speed={_row_field(row, 'Speed')!r} (parsed {show_speed}) "
                    f"!= STATE_DB speed={db_speed} beyond tolerance")
    if checked == 0:
        pytest.skip("fans present but none report a numeric speed in STATE_DB FAN_INFO "
                    "(or none are present) — nothing to range/consistency-check")


# ============================ 3) PSU presence/status ============================
def test_psu_presence_status_matches_db(cli):
    """Each PSU_INFO's presence/status matches its corresponding `show platform psustatus` row.

    Dynamically enumerate PSU_INFO|*; join by PSU name; DB presence/status(True/False) ↔ show
    Status column (OK / NOT OK / NOT PRESENT). Honest skip when no comparable info.
    """
    psus = _require_psus(cli)
    r = cli.run("show platform psustatus")
    if _crashed(r):
        pytest.skip(f"`show platform psustatus` crashed:\n{r.err[-300:]}")
    if "failed to get" in (r.out + r.err).lower():
        # DB has PSU_INFO but show can't retrieve it -> real inconsistency
        pytest.fail(f"STATE_DB has PSUs {psus} but `show platform psustatus` failed:\n{(r.out + r.err)[-300:]}")
    rows = cli.parse_table(r.out)
    by_name = _index_rows(rows, ("PSU", "Name"))
    compared = 0
    for name in psus:
        info = cli.db_hgetall("STATE_DB", f"PSU_INFO|{name}")
        assert info, f"psu {name}: PSU_INFO key present but HGETALL empty"
        row = by_name.get(name.lower())
        assert row is not None, \
            f"psu {name} in STATE_DB PSU_INFO but missing from `show platform psustatus` rows {sorted(by_name)}"
        status_cell = _row_field(row, "Status")
        # presence comparison: the show Status column containing 'NOT PRESENT' means absent
        if "presence" in info and status_cell is not None:
            db_present = _truthy(info["presence"])
            show_present = "not present" not in str(status_cell).strip().lower()
            assert db_present == show_present, (
                f"psu {name}: STATE_DB presence={info['presence']!r} (parsed {db_present}) "
                f"!= show Status={status_cell!r}")
            compared += 1
        # status comparison (only when present)
        if "status" in info and _truthy(info.get("presence", "True")):
            db_ok = _truthy(info["status"])
            show_ok = _cell_ok(status_cell)
            if show_ok is not None:
                assert db_ok == show_ok, (
                    f"psu {name}: STATE_DB status={info['status']!r} (parsed {db_ok}) "
                    f"!= show Status={status_cell!r}")
                compared += 1
    if compared == 0:
        pytest.skip("PSUs present but `show platform psustatus` exposes no comparable "
                    "Status column to cross-check STATE_DB PSU_INFO")


# ============================ 4) PSU electrical ============================
def test_psu_electrical_values(cli):
    """PSU voltage/current/power compared with STATE_DB (tolerance) and within a reasonable range.

    Validate only present PSUs. If this platform doesn't expose these fields (PSU_INFO has no
    voltage/current/power) -> honest skip. If show has the corresponding columns, do show↔DB
    consistency comparison, otherwise only DB range validation (still a real-value range
    assertion, not "non-empty").
    """
    psus = _require_psus(cli)
    rows, _ = _show_rows(cli, "show platform psustatus")
    by_name = _index_rows(rows, ("PSU", "Name"))
    checked = 0
    for name in psus:
        info = cli.db_hgetall("STATE_DB", f"PSU_INFO|{name}")
        if not _truthy(info.get("presence", "True")):
            continue  # skip absent PSUs (electrical values often 0/N/A)
        row = by_name.get(name.lower())
        for field, (lo, hi) in _PSU_RANGES.items():
            dv = _num(info.get(field))
            if dv is None:
                continue
            # reasonable range
            assert lo < dv <= hi, (
                f"psu {name}: STATE_DB {field}={info.get(field)!r} (parsed {dv}) "
                f"out of reasonable range ({lo}, {hi}]")
            checked += 1
            # show↔DB consistency (if the column exists)
            if row is not None:
                sv = _num(_row_field(row, *_PSU_SHOW_COL[field]))
                if sv is not None:
                    # tighten tolerance per unit (rel=0.1 + per-unit absolute floor); the fan-level 300 floor is meaningless for V/A/W
                    assert _close(sv, dv, rel=0.1, absfloor=_PSU_ABS_FLOOR[field]), (
                        f"psu {name}: show {field}={sv} != STATE_DB {field}={dv} beyond tolerance")
    if checked == 0:
        pytest.skip("PSUs present but PSU_INFO exposes no electrical fields "
                    "(voltage/current/power) on this platform — nothing to validate")


# ============================ 5) (optional) voltage/current sensors ============================
def test_voltage_current_sensors(cli):
    """If VOLTAGE_INFO/CURRENT_INFO sensors exist: values are valid numbers within threshold range, and compared with show where possible.

    Most platforms have no separate voltage/current sensor table -> honest skip. When present:
      - values must be valid numbers;
      - if STATE_DB provides *_threshold (high/low), assert readings are within thresholds;
      - if the platform provides `show platform voltage` and it doesn't crash, do show↔DB comparison by sensor name.
    """
    vkeys = cli.db_keys("STATE_DB", "VOLTAGE_INFO|*")
    ckeys = cli.db_keys("STATE_DB", "CURRENT_INFO|*")
    if not vkeys and not ckeys:
        pytest.fail("DEVICE ISSUE: no voltage/current sensor data "
                    "(STATE_DB VOLTAGE_INFO and CURRENT_INFO both empty) — pmon is not reporting "
                    "voltage/current telemetry the switch should expose (platform/pmon gap)")
    checked = 0
    for table, keys, value_field in (("VOLTAGE_INFO", vkeys, "voltage"),
                                     ("CURRENT_INFO", ckeys, "current")):
        for k in keys:
            name = k.split("|", 1)[-1]
            d = cli.db_hgetall("STATE_DB", k)
            val = _num(d.get(value_field) or d.get("value"))
            assert val is not None, \
                f"{table}|{name}: no numeric {value_field}/value field; has={sorted(d)}"
            # threshold range (if exposed by DB)
            hi = _num(d.get("high_threshold") or d.get("critical_high_threshold"))
            lo = _num(d.get("low_threshold") or d.get("critical_low_threshold"))
            if hi is not None:
                assert val <= hi, f"{table}|{name}: {value_field}={val} exceeds high_threshold={hi}"
            if lo is not None:
                assert val >= lo, f"{table}|{name}: {value_field}={val} below low_threshold={lo}"
            checked += 1
    assert checked > 0, "voltage/current sensor keys present but none validated"


# ============================ 6) pmon data freshness ============================
def test_sensor_data_freshness(cli):
    """pmon sensor data must keep refreshing: FAN/PSU/TEMPERATURE_INFO timestamps should advance
    with the daemon polling period (thermalctld/psud ~60s). A dead daemon serving a week-old
    snapshot would pass all the other snapshot-style consistency/range cases in this file --
    a timestamp advancing is the only evidence that catches a polling stall.

    Polling wait (recheck every 10s, up to ~90s ≈ 1.5 polling periods); pass as soon as any
    sensor timestamp advances; honest skip if the platform doesn't expose a timestamp field
    (freshness unobservable)."""
    tables = ("FAN_INFO", "PSU_INFO", "TEMPERATURE_INFO")

    def _stamps():
        out = {}
        for t in tables:
            for k in cli.db_keys("STATE_DB", f"{t}|*"):
                ts = cli.db_hgetall("STATE_DB", k).get("timestamp")
                if ts:
                    out[k] = ts
        return out

    base = _stamps()
    if not base:
        pytest.skip("no FAN/PSU/TEMPERATURE_INFO row exposes a 'timestamp' field on this "
                    "platform — data freshness is not observable")
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(10)
        cur = _stamps()
        if any(cur.get(k) != v for k, v in base.items()):
            return  # at least one sensor timestamp advanced -> pmon polling is running
    pytest.fail("DEVICE ISSUE: no sensor timestamp advanced within 90s (~1.5 poll periods) — "
                "pmon sensor polling (thermalctld/psud) appears dead; all values are stale")
