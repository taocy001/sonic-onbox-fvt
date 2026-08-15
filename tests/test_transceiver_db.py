"""Transceiver / SFP read-only tests ([A] pure show <-> STATE_DB consistency, no traffic; cli domain).

Ported from sonic-mgmt tests/platform_tests/sfp and transceiver/; this framework had zero
coverage before. Four groups (all read-only):
  1) TRANSCEIVER_INFO has all fields (ported from test_xcvr_info_in_db.py);
  2) TRANSCEIVER_DOM_SENSOR has valid numeric sensors;
  3) show <-> STATE_DB consistency (ported from test_sfp_thermal_state_db.py);
  4) sfputil / sfpshow read-only subcommands do not crash and agree with the DB.

Hard requirements:
  - **gracefully skip ports with no optic**: on this image/device many ports (or even all)
    may have no optic in practice -- skip each port with no TRANSCEIVER_INFO individually; if
    no port on the device has a module, skip the whole group (with a reason, never assert True).
  - **read-only**: no OIR / reset / lpmode-set (those are Pattern B).
  - skip a crashing subcommand with an explanation (some show/sfputil subcommands may crash
    due to a missing platform module or being unimplemented).

Print / assert / skip messages are in English; docstrings / comments are in English.
"""
import re

import pytest

pytestmark = [pytest.mark.transceiver, pytest.mark.cli]

# TRANSCEIVER_INFO key fields (the core subset of sonic-mgmt test_xcvr_info_in_db.py;
# fields vary by module model, so we take only the minimal key set every module should have).
# The truly cross-module / cross-image mandatory fields. vendor_name/vendor_pn have different
# field names in some product images (SONiC: manufacturer/model), so they are moved out of the
# mandatory set and go through the alias check below (the data itself exists, just under a
# different key name -- we must not misjudge "field missing / STATE_DB empty" over a key-name
# difference).
INFO_KEY_FIELDS = ["type", "vendor_oui"]
# serial / model / vendor have field-name aliases across schemas, checked leniently on their
# own (see _has_any).
INFO_SERIAL_ALIASES = ["serial", "vendor_sn"]
INFO_MODEL_ALIASES = ["model", "vendor_pn"]
INFO_VENDOR_ALIASES = ["vendor_name", "manufacturer"]

# TRANSCEIVER_DOM_SENSOR key sensor fields (must be valid numbers).
DOM_FIELDS = ["temperature", "voltage", "rx1power", "tx1bias"]


# ============================ common helpers ============================
def _all_ports(cli):
    """Get all physical port names from `show interface status` (does not hard-code EthernetX)."""
    rows = cli.parse_table(cli.run("show interface status").out)
    ports = []
    for r in rows:
        name = r.get("Interface") or r.get("Port") or ""
        if re.match(r"Ethernet\d+$", name):
            ports.append(name)
    return sorted(ports, key=lambda n: int(re.search(r"\d+$", n).group()))


def _ports_with_module(cli):
    """Return the list of port names that have an optic (STATE_DB TRANSCEIVER_INFO|EthernetX non-empty)."""
    keys = cli.db_keys("STATE_DB", "TRANSCEIVER_INFO|*")
    out = []
    for k in keys:
        name = k.split("|", 1)[-1]
        if re.match(r"Ethernet\d+$", name) and cli.db_hgetall("STATE_DB", k):
            out.append(name)
    return sorted(out, key=lambda n: int(re.search(r"\d+$", n).group()))


def _require_modules(cli):
    """When STATE_DB TRANSCEIVER_INFO is empty across the whole device, cross-check with the
    product's `show interfaces transceiver presence`:
      - presence available and all Not-present => the device really has no modules plugged in,
        so an empty STATE_DB is **self-consistent** => skip (with a reason);
      - presence reports some Present while STATE_DB is empty => xcvrd is not reporting => a real
        pmon defect, fail;
      - the presence command itself crashes / is missing => keep the original defect verdict, fail.
    Returns the list of port names that have a module."""
    ports = _ports_with_module(cli)
    if not ports:
        r = cli.run("show interfaces transceiver presence")
        out = (r.out or "") + (getattr(r, "err", "") or "")
        if r.rc == 0 and "Presence" in out and "Traceback" not in out:
            rows = [l for l in out.splitlines() if l.strip().startswith("Ethernet")]
            present = [l.split()[0] for l in rows
                       if "not present" not in l.lower() and "present" in l.lower()]
            if rows and not present:
                pytest.skip("no transceiver physically present on any port "
                            "(`show interfaces transceiver presence` reports all Not-present, "
                            "consistent with empty STATE_DB); nothing to validate")
            if present:
                pytest.fail(f"DEVICE ISSUE: modules present per show ({present[:4]}) but "
                            "STATE_DB TRANSCEIVER_INFO empty for all ports -- xcvrd not "
                            "reporting plugged optics (pmon gap)")
        pytest.fail("DEVICE ISSUE: no transceiver data on any port "
                    "(STATE_DB TRANSCEIVER_INFO is empty for all ports) — pmon/xcvrd is not "
                    "reporting any plugged optic's EEPROM/vendor info; a switch should expose "
                    "TRANSCEIVER_INFO for present modules (platform/pmon gap, not an optional resource)")
    return ports


def _is_number(s):
    """DOM values may carry units (e.g. '36.5C'/'3.30Volts'/'-40.0dBm'/'N/A'); extract the first float to judge a valid number."""
    if s is None:
        return False
    s = str(s).strip()
    if s in ("", "N/A", "n/a", "None"):
        return False
    return re.match(r"^[-+]?\d+(\.\d+)?", s) is not None


def _has_any(d, aliases):
    return any(d.get(a, "").strip() for a in aliases)


def _crashed(r):
    """Command output contains a Python Traceback -> treat as a device/software crash (used to skip known-crashing subcommands)."""
    return "Traceback (most recent call last)" in f"{r.out}\n{r.err}"


# tolerance for comparing show output against STATE_DB (sampling drift).
_TEMP_TOL_C = 5.0


def _num(s):
    """Extract the first float from a unit-bearing / noisy string (e.g. '36.5C' -> 36.5); None if none."""
    if s is None:
        return None
    m = re.search(r"[-+]?\d+(?:\.\d+)?", str(s))
    return float(m.group()) if m else None


def _section(out, port):
    """From output segmented by `EthernetX:`, extract this port's section text (up to the next 'EthernetN:'); None if absent."""
    m = re.search(rf"^{re.escape(port)}:(.*?)(?=^Ethernet\d+:|\Z)", out, re.S | re.M)
    return m.group(1) if m else None


def _assert_eeprom_block_matches_db(cli, port, block):
    """This port's eeprom text block should truly reflect STATE_DB TRANSCEIVER_INFO's
    vendor/pn/serial (real-value comparison, not merely "not 'Not detected'"). Returns the
    number of fields actually compared (0 means the DB has no comparable field)."""
    assert "Not detected" not in block, \
        f"{port}: module in DB but eeprom block reports 'Not detected'"
    info = cli.db_hgetall("STATE_DB", f"TRANSCEIVER_INFO|{port}")
    compared = 0
    for field in ("vendor_name", "vendor_pn", "vendor_sn", "serial"):
        v = info.get(field, "").strip()
        if v:
            assert v.lower() in block.lower(), \
                f"{port}: STATE_DB {field}={v!r} not reflected in eeprom block"
            compared += 1
    return compared


# ==================== 1) TRANSCEIVER_INFO has all fields ====================
def test_transceiver_info_fields_in_db(cli):
    """For every port with an optic, STATE_DB TRANSCEIVER_INFO|EthernetX has the key fields.

    Ported from test_xcvr_info_in_db.py. Ports with no module are skipped individually (achieved
    here by only iterating over ports that have a module); if no port has a module, _require_modules
    skips the whole group.
    """
    ports = _require_modules(cli)
    checked = 0
    for p in ports:
        info = cli.db_hgetall("STATE_DB", f"TRANSCEIVER_INFO|{p}")
        assert info, f"{p}: TRANSCEIVER_INFO present in KEYS but HGETALL empty"
        missing = [f for f in INFO_KEY_FIELDS if not info.get(f, "").strip()]
        assert not missing, f"{p}: TRANSCEIVER_INFO missing/empty fields {missing}; has={sorted(info)}"
        assert _has_any(info, INFO_SERIAL_ALIASES), \
            f"{p}: TRANSCEIVER_INFO has no serial field (tried {INFO_SERIAL_ALIASES}); has={sorted(info)}"
        assert _has_any(info, INFO_MODEL_ALIASES), \
            f"{p}: TRANSCEIVER_INFO has no model field (tried {INFO_MODEL_ALIASES}); has={sorted(info)}"
        assert _has_any(info, INFO_VENDOR_ALIASES), \
            f"{p}: TRANSCEIVER_INFO has no vendor/manufacturer field (tried {INFO_VENDOR_ALIASES}); has={sorted(info)}"
        checked += 1
    assert checked > 0, "no transceiver-bearing port validated"


# ==================== 2) TRANSCEIVER_DOM_SENSOR valid numbers ====================
def test_transceiver_dom_sensor_values(cli):
    """For every port with an optic, STATE_DB TRANSCEIVER_DOM_SENSOR|EthernetX has valid numeric sensors.

    DOM data is optional (some modules / passive copper do not report it) -- skip each module-bearing
    port with no DOM individually, and if every module-bearing port has no DOM, skip the whole group.
    """
    ports = _require_modules(cli)
    validated = 0
    for p in ports:
        dom = cli.db_hgetall("STATE_DB", f"TRANSCEIVER_DOM_SENSOR|{p}")
        if not dom:
            continue  # this port has no DOM (e.g. a DAC copper cable) -> skip
        present = [f for f in DOM_FIELDS if f in dom]
        if not present:
            continue
        bad = {f: dom[f] for f in present if not _is_number(dom[f])}
        assert not bad, f"{p}: DOM sensor fields not numeric: {bad}"
        validated += 1
    # unsure whether these are genuinely DOM-less optics (by design) -> per the rules classify as
    # A (device defect) and fail to expose it: a present optic should report DOM sensors, and none
    # at all = platform/xcvrd is not collecting the optics' DOM data.
    assert validated > 0, (
        "DEVICE DEFECT: transceivers present but none report DOM sensors "
        "(TRANSCEIVER_DOM_SENSOR empty for all module ports) — platform/xcvrd not collecting DOM")


# ==================== 3) show <-> STATE_DB consistency ====================
def test_show_presence_matches_db(cli):
    """The Present port set from `show interfaces transceiver presence` agrees with STATE_DB TRANSCEIVER_INFO.

    Ported from the test_sfp_thermal_state_db.py approach (show values must align with STATE_DB).
    """
    db_ports = set(_require_modules(cli))
    r = cli.run("show interfaces transceiver presence")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `show interfaces transceiver presence` crashed on this image:\n{r.err[-300:]}")
    rows = cli.parse_table(r.out)
    show_present = set()
    for row in rows:
        port = row.get("Port") or row.get("Interface") or ""
        pres = (row.get("Presence") or "").strip().lower()
        if re.match(r"Ethernet\d+$", port) and "present" in pres and "not" not in pres:
            show_present.add(port)
    # ports show considers present should be a superset of ports with TRANSCEIVER_INFO in the DB
    # (DB persistence may lag slightly behind physical presence).
    missing_in_db = show_present - db_ports
    assert not missing_in_db, \
        f"ports present in `show ... presence` but absent in STATE_DB TRANSCEIVER_INFO: {sorted(missing_in_db)}"
    # reverse: ports with a module in the DB should also be judged present by show.
    missing_in_show = db_ports - show_present
    assert not missing_in_show, \
        f"ports with STATE_DB TRANSCEIVER_INFO but not Present in `show ... presence`: {sorted(missing_in_show)}"


def test_show_eeprom_matches_db(cli):
    """`show interfaces transceiver eeprom` yields EEPROM (not 'Not detected') for module-bearing
    ports, and its vendor aligns with STATE_DB TRANSCEIVER_INFO.
    """
    ports = _require_modules(cli)
    r = cli.run("show interfaces transceiver eeprom")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `show interfaces transceiver eeprom` crashed on this image:\n{r.err[-300:]}")
    out = r.out
    checked = 0
    for p in ports:
        # eeprom output is segmented by 'EthernetX:'; locate this port's section up to the next 'EthernetN:'.
        m = re.search(rf"^{re.escape(p)}:(.*?)(?=^Ethernet\d+:|\Z)", out, re.S | re.M)
        assert m, f"{p}: not found in `show interfaces transceiver eeprom` output"
        block = m.group(1)
        assert "Not detected" not in block, \
            f"{p}: has TRANSCEIVER_INFO in DB but `show ... eeprom` reports 'Not detected'"
        info = cli.db_hgetall("STATE_DB", f"TRANSCEIVER_INFO|{p}")
        vendor = info.get("vendor_name", "").strip()
        # if vendor_name exists it should appear in this port's eeprom text block (case-insensitive loose match).
        if vendor:
            assert vendor.lower() in block.lower(), \
                f"{p}: DB vendor_name='{vendor}' not reflected in `show ... eeprom` block"
        checked += 1
    assert checked > 0


def test_show_status_matches_db(cli):
    """The status fields of `show interfaces transceiver status` agree with the corresponding values in STATE_DB TRANSCEIVER_STATUS.

    Upgraded: no longer just checks 'Not detected' -- it takes a meaningful string status value
    from STATE_DB TRANSCEIVER_STATUS (e.g. cmis_state='ready') and asserts it appears verbatim in
    show's section for that port. When there is no TRANSCEIVER_STATUS table / no comparable string
    field, skip honestly (leave no weak check).
    """
    ports = _require_modules(cli)
    r = cli.run("show interfaces transceiver status")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `show interfaces transceiver status` crashed on this image:\n{r.err[-300:]}")
    out = r.out
    # absent / placeholder values: status words when a module is unplugged or not ready
    # (cmis_state=REMOVED, error=N/A, etc.) are not a "comparable operational state"; in that
    # case `show ... status` prints "not applicable", which we attribute to nothing to compare
    # rather than a show<->DB mismatch.
    _ABSENT = {"removed", "n/a", "na", "none", "not present", "unknown", "removing"}
    compared = 0
    module_present = False
    for p in ports:
        block = _section(out, p)
        if block is None:
            continue  # the platform may not support a status section for this port
        if "not applicable" in block.lower() or "not detected" in block.lower():
            continue  # this port currently has no ready module (unplugged/removing); show says
                      # explicitly not applicable -- skip, do not misjudge as a mismatch
        # the status table name may be TRANSCEIVER_STATUS_SW (software state); fall back to the standard TRANSCEIVER_STATUS
        st = (cli.db_hgetall("STATE_DB", f"TRANSCEIVER_STATUS_SW|{p}")
              or cli.db_hgetall("STATE_DB", f"TRANSCEIVER_STATUS|{p}"))
        if not st:
            continue
        for f, v in st.items():
            v = str(v).strip()
            # only compare meaningful **operational-state** strings (skip pure numbers/boolean bits and absent placeholders to avoid trivial matches or misjudgments)
            if v and len(v) >= 3 and not _is_number(v) and v.lower() not in _ABSENT:
                module_present = True
                assert v.lower() in block.lower(), \
                    f"{p}: STATE_DB TRANSCEIVER_STATUS_SW {f}={v!r} not in `show ... status` block"
                compared += 1
    # no "comparable operational state of a ready module" anywhere on the device (all unplugged/removing) -> nothing to compare, skip honestly (not a show<->DB mismatch defect).
    if compared == 0 and not module_present:
        pytest.skip("no operational transceiver with comparable STATUS string on this DUT "
                    "(all modules removed/not-ready); nothing to cross-check show vs STATE_DB")
    assert compared > 0, (
        "no comparable TRANSCEIVER_STATUS string field between "
        "`show ... status` and STATE_DB on this DUT")


def test_platform_temperature_matches_db(cli):
    """`show platform temperature` sensor readings vs STATE_DB TEMPERATURE_INFO temperature, **compared per sensor**.

    Upgraded: no longer just verifies "has a number + table non-empty" -- it joins show rows with
    STATE_DB TEMPERATURE_INFO|<name> by sensor name and asserts the readings agree within tolerance.
    Skip honestly when there is no thermal sensor / no temperature in STATE_DB / no matching sensor.
    Ported from test_sfp_thermal_state_db.py (thermal show <-> STATE_DB).
    """
    r = cli.run("show platform temperature")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `show platform temperature` crashed on this image:\n{r.err[-300:]}")
    text = r.out
    # thermal sensor data the platform should have is missing -> fail to expose it (platform data that should exist doesn't).
    assert "Not detected" not in text and text.strip(), (
        "DEVICE DEFECT: no thermal sensors detected by `show platform temperature` on this DUT")
    rows = cli.parse_table(text)
    assert rows, "DEVICE DEFECT: `show platform temperature` produced no parseable rows"
    # STATE_DB ground truth: sensor name -> temperature
    db_keys = cli.db_keys("STATE_DB", "TEMPERATURE_INFO|*")
    assert db_keys, (
        "DEVICE DEFECT: no STATE_DB TEMPERATURE_INFO to compare `show platform temperature` against")
    db = {}
    for k in db_keys:
        name = k.split("|", 1)[1]
        t = _num(cli.db_hgetall("STATE_DB", k).get("temperature"))
        if t is not None:
            db[name] = t
    assert db, "DEVICE DEFECT: STATE_DB TEMPERATURE_INFO has no numeric temperature field"
    name_keys = ("Sensor", "Name", "Sensor Name")
    temp_keys = ("Temperature", "Temperature(C)", "Reading", "Current")
    matched = 0
    for row in rows:
        sensor = next((row[k] for k in name_keys if k in row), None)
        val = _num(next((row[k] for k in temp_keys if k in row), None))
        if not sensor or val is None or sensor not in db:
            continue
        assert abs(val - db[sensor]) <= _TEMP_TOL_C, (
            f"sensor {sensor!r}: `show platform temperature` {val}C != "
            f"STATE_DB TEMPERATURE_INFO {db[sensor]}C (tol {_TEMP_TOL_C}C)")
        matched += 1
    # inverse: no matching sensor name between show and STATE_DB -> platform data inconsistent/missing, fail to expose it.
    assert matched > 0, (
        "no sensor name overlaps between `show platform temperature` and "
        "STATE_DB TEMPERATURE_INFO to compare readings")


# ==================== 4) sfputil / sfpshow read-only subcommands ====================
def test_sfputil_show_presence_readonly(cli):
    """`sfputil show presence` is read-only and does not crash, and its Present set agrees with STATE_DB.

    Known device issue: on this image sfputil crashes when the sonic_platform module is missing -> skip with an explanation.
    """
    db_ports = set(_require_modules(cli))
    r = cli.run("sudo sfputil show presence")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `sfputil show presence` crashed:\n{r.err[-300:]}")
    rows = cli.parse_table(r.out)
    show_present = set()
    for row in rows:
        port = row.get("Port") or row.get("Interface") or ""
        pres = (row.get("Presence") or "").strip().lower()
        if re.match(r"Ethernet\d+$", port) and "present" in pres and "not" not in pres:
            show_present.add(port)
    assert db_ports <= show_present, \
        f"STATE_DB modules {sorted(db_ports - show_present)} not Present in `sfputil show presence`"


def test_sfputil_show_eeprom_readonly(cli):
    """`sfputil show eeprom` is read-only and does not crash, and for module-bearing ports its EEPROM
    output is compared **field by field** against STATE_DB TRANSCEIVER_INFO's vendor/pn/serial (not
    merely "not 'Not detected'")."""
    ports = _require_modules(cli)
    r = cli.run("sudo sfputil show eeprom")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `sfputil show eeprom` crashed:\n{r.err[-300:]}")
    out = r.out
    compared_ports = 0
    for p in ports:
        block = _section(out, p)
        if block is None:
            continue
        if _assert_eeprom_block_matches_db(cli, p, block) > 0:
            compared_ports += 1
    # inverse: a present module's EEPROM should have comparable vendor/pn/serial fields; none at all -> fail to expose it.
    assert compared_ports > 0, (
        "`sfputil show eeprom` present but STATE_DB TRANSCEIVER_INFO has no "
        "vendor/pn/serial field to cross-check")


def test_sfpshow_eeprom_readonly(cli):
    """`sfpshow eeprom` is read-only and does not crash, and for module-bearing ports its EEPROM
    output is compared **field by field** against STATE_DB TRANSCEIVER_INFO's vendor/pn/serial (not
    merely "not 'Not detected'")."""
    ports = _require_modules(cli)
    r = cli.run("sfpshow eeprom")
    assert not _crashed(r), (
        f"DEVICE DEFECT: `sfpshow eeprom` crashed on this image:\n{r.err[-300:]}")
    out = r.out
    assert out.strip(), "`sfpshow eeprom` produced no output"
    compared_ports = 0
    for p in ports:
        block = _section(out, p)
        if block is None:
            continue
        if _assert_eeprom_block_matches_db(cli, p, block) > 0:
            compared_ports += 1
    # inverse: a present module's EEPROM should have comparable vendor/pn/serial fields; none at all -> fail to expose it.
    assert compared_ports > 0, (
        "`sfpshow eeprom` present but STATE_DB TRANSCEIVER_INFO has no "
        "vendor/pn/serial field to cross-check")
