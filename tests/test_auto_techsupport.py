"""AUTO_TECHSUPPORT feature tests: global/per-feature config <-> show consistency, enable/disable toggle really takes effect, and end-to-end verification of the trigger mechanism (core_pattern pipe + coredump_gen_handler consuming state + dump package structure).

The trigger path is verified by **actually crashing a disposable python process** (os.abort,
non-destructive: touches no service process):
  - /proc/sys/kernel/core_pattern pipes to coredump-compress; after the crash a new core really
    appears under /var/core (deleted afterwards);
  - coredump_gen_handler.py's consumption of CONFIG_DB AUTO_TECHSUPPORT state is checked with a
    disabled/enabled two-leg comparison (different syslog landing points + no heavy techsupport
    package generated throughout), restored by config_guard;
  - existing/newly generated /var/dump/*.tar.gz techsupport packages have a sane structure
    (containing dump/ + log/ + CONFIG_DB.json);
  - show auto-techsupport history <-> STATE_DB records are consistent.

Follows the show<->DB + config toggle-restore pattern from tests/test_system_mgmt.py.
"""
import time

import pytest

pytestmark = [pytest.mark.mgmt, pytest.mark.cli]

GLOBAL_KEY = "AUTO_TECHSUPPORT|GLOBAL"
FEATURE_PAT = "AUTO_TECHSUPPORT_FEATURE|*"


def _num_or_str(a, b):
    """Field comparison: if convertible to float, compare numerically (DB stores '10.0' vs show displays '10'), otherwise compare as strings."""
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        return str(a).strip() == str(b).strip()


def _single_row(cli, text):
    """`show auto-techsupport global` is a single-data-row table; return that row as a dict(header->value)."""
    rows = cli.parse_table(text)
    return rows[0] if rows else {}


# ---------------------------------------------------------------------------
# 1. Global config <-> show consistency
# ---------------------------------------------------------------------------
def test_global_config_matches_show(cli):
    """`show auto-techsupport global` columns == corresponding CONFIG_DB AUTO_TECHSUPPORT|GLOBAL fields, compared field by field."""
    cfg = cli.db_hgetall("CONFIG_DB", GLOBAL_KEY)
    # AUTO_TECHSUPPORT|GLOBAL table should exist but is missing = device defect (feature not installed) -> fail to expose.
    assert cfg, (
        "DEVICE DEFECT: CONFIG_DB AUTO_TECHSUPPORT|GLOBAL absent (feature not present on this image)")

    r = cli.run("show auto-techsupport global")
    blob = r.out + r.err
    assert "Traceback" not in blob, f"show auto-techsupport global crashed: {blob[-300:]}"
    row = _single_row(cli, r.out)
    assert row, f"show auto-techsupport global produced no data row: {r.out[-300:]}"

    # show column-header substring -> CONFIG_DB field name
    col_to_field = {
        "STATE": "state",
        "RATE LIMIT INTERVAL": "rate_limit_interval",
        "MAX TECHSUPPORT LIMIT": "max_techsupport_limit",
        "MAX CORE LIMIT": "max_core_limit",
        "AVAILABLE MEM THRESHOLD": "available_mem_threshold",
        "MIN AVAILABLE MEM": "min_available_mem",
        "SINCE": "since",
    }
    checked = 0
    for col, show_val in row.items():
        field = next((f for sub, f in col_to_field.items() if sub in col.upper()), None)
        if field is None or field not in cfg:
            continue
        assert _num_or_str(cfg[field], show_val), (
            f"global field {field}: CONFIG_DB={cfg[field]!r} but show column {col!r}={show_val!r}")
        checked += 1
    # state is a mandatory column; at least it plus a few fields should be cross-checked, otherwise parsing/mapping failed
    assert checked >= 2, f"too few global fields cross-checked ({checked}); show parse may be off: {row}"
    assert any("STATE" in c.upper() for c in row), "show global missing STATE column"


# ---------------------------------------------------------------------------
# 2. per-feature config <-> show consistency
# ---------------------------------------------------------------------------
def test_feature_config_matches_show(cli):
    """Each `show auto-techsupport-feature` row == CONFIG_DB AUTO_TECHSUPPORT_FEATURE|<name> fields, compared feature by feature."""
    keys = cli.db_keys("CONFIG_DB", FEATURE_PAT)
    # per-feature config should exist but is missing = device defect -> fail to expose.
    assert keys, (
        "DEVICE DEFECT: CONFIG_DB AUTO_TECHSUPPORT_FEATURE|* absent (per-feature config not present)")

    r = cli.run("show auto-techsupport-feature")
    blob = r.out + r.err
    # show command should exist but is unavailable = device defect -> fail to expose.
    assert not ("No such command" in blob or ("Usage:" in blob and "Error" in blob)), (
        "DEVICE DEFECT: `show auto-techsupport-feature` not available on this image")
    assert "Traceback" not in blob, f"show auto-techsupport-feature crashed: {blob[-300:]}"
    rows = cli.parse_table(r.out)
    assert rows, f"show auto-techsupport-feature produced no rows: {r.out[-300:]}"

    # FEATURE NAME of the show row -> that row's dict
    name_col = next((c for c in rows[0] if "FEATURE NAME" in c.upper() or c.upper() == "FEATURE"), None)
    assert name_col, f"show feature table missing FEATURE NAME column: {rows[0]}"
    show_by_name = {row[name_col]: row for row in rows}

    col_to_field = {
        "STATE": "state",
        "RATE LIMIT INTERVAL": "rate_limit_interval",
        "AVAILABLE MEM THRESHOLD": "available_mem_threshold",
    }
    compared = 0
    for k in keys:
        feat = k.split("|", 1)[1]
        cfg = cli.db_hgetall("CONFIG_DB", k)
        assert feat in show_by_name, (
            f"feature {feat!r} in CONFIG_DB but missing from `show auto-techsupport-feature` "
            f"({list(show_by_name)})")
        row = show_by_name[feat]
        for col, val in row.items():
            field = next((f for sub, f in col_to_field.items() if sub in col.upper()), None)
            if field is None or field not in cfg:
                continue
            assert _num_or_str(cfg[field], val), (
                f"feature {feat} field {field}: CONFIG_DB={cfg[field]!r} but show {col!r}={val!r}")
            compared += 1
    assert compared >= len(keys), (
        f"expected >=1 field compared per feature ({len(keys)} features) but only {compared} compared")


# ---------------------------------------------------------------------------
# 3. Enable/disable toggle really takes effect (CONFIG_DB state truly changes + show reflects it), restored in teardown
# ---------------------------------------------------------------------------
def test_global_state_toggle(cli, config_guard):
    """`config auto-techsupport global state <enabled|disabled>` truly changes CONFIG_DB state and show tracks it,
    restored to the original value by config_guard."""
    cfg = cli.db_hgetall("CONFIG_DB", GLOBAL_KEY)
    orig = cfg.get("state")
    # state should exist but is missing/unknown = device defect (when unsure, classify as A) -> fail to expose.
    assert orig in ("enabled", "disabled"), (
        f"DEVICE DEFECT: AUTO_TECHSUPPORT|GLOBAL state not present/unknown ({orig!r})")
    new = "disabled" if orig == "enabled" else "enabled"

    rc, r = cli.config_raw(f"auto-techsupport global state {new}")
    # Register the restore first, so it rolls back even if a later assertion fails
    config_guard.defer_undo(f"auto-techsupport global state {orig}")
    # If the CLI is broken, fail to expose (no longer skip): the config subcommand must be accepted.
    assert rc == 0, f"config auto-techsupport global state syntax to be confirmed: {r.err or r.out}"

    # CONFIG_DB truly changed
    assert cli.db_hgetall("CONFIG_DB", GLOBAL_KEY).get("state") == new, (
        f"CONFIG_DB AUTO_TECHSUPPORT state did not change to {new!r}")
    # show reflects the new value
    sr = cli.run("show auto-techsupport global")
    assert "Traceback" not in (sr.out + sr.err), "show auto-techsupport global crashed after toggle"
    row = _single_row(cli, sr.out)
    state_col = next((c for c in row if "STATE" in c.upper()), None)
    assert state_col and row[state_col] == new, (
        f"show auto-techsupport global state {row.get(state_col)!r} != configured {new!r}")


# ---------------------------------------------------------------------------
# 4. Trigger mechanism (end-to-end real trigger: crash a disposable process to produce a core + two-leg comparison of handler consuming state)
# ---------------------------------------------------------------------------
def test_coredump_trigger_wiring(cli, config_guard):
    """End-to-end real verification of the auto-techsupport trigger path (the old implementation
    grepped handler source strings = fake behavior verification, passing even if the handler had a
    syntax error / missing dependency; now changed to a real trigger):

    1) core_pattern pipes to coredump-compress (core capture entry point);
    2) after `ulimit -c unlimited`, crash a disposable python3 process (os.abort), and poll
       /var/core/ for a new core file attributed by the crash pid -- proving the
       kernel->coredump-compress pipe really works (deleted afterwards);
    3) two-leg comparison of state consumption (restored by config_guard, no heavy techsupport
       package generated throughout):
       - global state=disabled: directly invoke coredump_gen_handler (the downstream entry of the
         core_pattern chain); it should stop at the global gate (syslog "auto_invoke_ts is disabled"
         + no new dump);
       - global state=enabled + a nonexistent feature name: it should pass the global gate and stop
         at the feature gate (syslog "...is not enabled...skipped" + no new dump) -- the two legs
         have different syslog landing points, proving CONFIG_DB state is really consumed by the
         handler rather than being decorative.
    """
    handler = "/usr/local/bin/coredump_gen_handler.py"
    # coredump handler should exist but is missing = device defect -> fail to expose.
    assert cli.sh.run(f"test -f {handler} && echo ok", check=False).out.strip() == "ok", (
        f"DEVICE DEFECT: {handler} absent (auto-techsupport coredump trigger not installed)")

    # core_pattern should pipe the core to coredump-compress (auto-techsupport core capture entry point)
    cp = cli.sh.run("cat /proc/sys/kernel/core_pattern", check=False).out.strip()
    assert cp.startswith("|") and "coredump-compress" in cp, (
        f"core_pattern not piped to coredump-compress (auto-techsupport core capture disabled): {cp!r}")

    # cleanup script exists (the enforcer of max_techsupport_limit/max_core_limit)
    assert cli.sh.run("test -f /usr/local/bin/techsupport_cleanup.py && echo ok",
                      check=False).out.strip() == "ok", (
        "techsupport_cleanup.py absent; max-techsupport-limit/max-core-limit not enforced")

    # --- 2) Actually crash a disposable process: core_pattern pipe end-to-end ---
    baseline = set(cli.sh.run("ls -1 /var/core 2>/dev/null", check=False).out.split())
    r = cli.sh.run(
        "bash -c 'ulimit -c unlimited; "
        "python3 -c \"import os,sys; sys.stdout.write(str(os.getpid())); "
        "sys.stdout.flush(); os.abort()\"'", check=False)
    pid = (r.out or "").strip().splitlines()[-1].strip() if (r.out or "").strip() else ""
    assert pid.isdigit(), f"failed to launch/abort the disposable python3 process (out={r.out!r})"

    core = None
    end = time.time() + 45   # coredump-compress writeout + compression has a second-scale delay
    while time.time() < end and core is None:
        ls = cli.sh.run("ls -1 /var/core 2>/dev/null", check=False).out
        for f in ls.split():
            # Naming <comm>.<ts>.<pid>.core.gz -- attribute precisely by crash pid, excluding interference from concurrent real crashes
            if f.startswith("python3.") and f".{pid}.core" in f and f not in baseline:
                core = f
                break
        if core is None:
            time.sleep(1)
    assert core, (
        f"no core for the aborted python3 (pid {pid}) appeared under /var/core within 45s -- "
        "core_pattern pipeline (coredump-compress) not functioning")

    try:
        # --- 3) handler consumes state: disabled/enabled two-leg comparison ---
        orig = cli.db_hgetall("CONFIG_DB", GLOBAL_KEY).get("state")
        assert orig in ("enabled", "disabled"), (
            f"DEVICE DEFECT: AUTO_TECHSUPPORT|GLOBAL state not present/unknown ({orig!r})")
        fake_feat = "fvtnofeature"   # nonexistent feature: the enabled leg stops at the feature gate, never actually generating a heavy package

        def _dumps():
            out = cli.sh.run("ls -1 /var/dump/sonic_dump_*.tar.gz 2>/dev/null", check=False).out
            return {l.strip() for l in out.splitlines() if l.strip()}

        def _invoke():
            # the handler has a core freshness check (created within ~20s by default) -- touch our own core to refresh mtime
            cli.sh.run(f"touch /var/core/{core}", check=False)
            cli.sh.run(f"python3 {handler} {core} {fake_feat} 2>&1", check=False, timeout=60)
            time.sleep(1)   # wait for syslog writeout
            return cli.sh.run(f"grep -a '{core}' /var/log/syslog | tail -5", check=False).out or ""

        pre = _dumps()
        # Leg 1: disabled -> handler should stop at the global gate
        rc, cr = cli.config_raw("auto-techsupport global state disabled")
        config_guard.defer_undo(f"auto-techsupport global state {orig}")
        assert rc == 0, f"config auto-techsupport global state disabled failed: {cr.err or cr.out}"
        log1 = _invoke()
        assert "disabled" in log1, (
            f"handler did not honor AUTO_TECHSUPPORT state=disabled (no 'disabled' syslog line "
            f"for core {core}): {log1[-300:]!r}")
        assert _dumps() == pre, "handler generated a techsupport dump while state=disabled"

        # Leg 2: enabled -> handler should pass the global gate and stop at the feature gate (syslog landing point changes = state really consumed)
        rc, cr = cli.config_raw("auto-techsupport global state enabled")
        assert rc == 0, f"config auto-techsupport global state enabled failed: {cr.err or cr.out}"
        log2 = _invoke()
        assert ("not enabled" in log2 and "skipped" in log2.lower()), (
            f"handler did not pass the global gate with state=enabled (expected feature-gate "
            f"skip syslog for core {core}): {log2[-300:]!r}")
        assert _dumps() == pre, "handler unexpectedly generated a dump for a nonexistent feature"
    finally:
        cli.sh.run(f"rm -f /var/core/{core}", check=False)


def test_existing_dump_structure(cli):
    """techsupport-generated package has a sane structure (containing dump/ + log/ + CONFIG_DB.json).

    When no existing dump is present, **actively generate one** (constrained with --since to a recent
    window, shrinking size/time) -- this is the real verification of the techsupport feature; failing
    to produce a package = techsupport is broken = a real defect. The generated temporary package is
    cleaned up at the end. (The old implementation's docstring said "skip if no dump" yet asserted
    dumps and failed outright, a contradiction; now changed to actually exercise the feature.)"""
    ls = cli.sh.run("ls -1 /var/dump/sonic_dump_*.tar.gz 2>/dev/null", check=False).out.strip()
    dumps = [l for l in ls.splitlines() if l.strip()]
    generated = None
    if not dumps:
        # Actively generate: --since limits to the last 10 minutes, small size and bounded time (not a full techsupport, avoids overwhelming SSH)
        r = cli.sh.run("show techsupport --since '10 minutes ago' 2>/dev/null",
                       check=False, timeout=300)
        cand = [l.strip() for l in (r.out or "").splitlines()
                if l.strip().endswith(".tar.gz")]
        if cand:
            generated = cand[-1]
            dumps = [generated]
    assert dumps, (
        "DEVICE DEFECT: techsupport produced no dump under /var/dump/ "
        "(`show techsupport` failed to generate a package)")
    try:
        newest = dumps[-1]
        # List member relative paths inside the package (strip the top-level sonic_dump_*/ directory prefix)
        listing = cli.sh.run(f"tar tzf {newest} 2>/dev/null | sed 's#^sonic_dump_[^/]*/##'",
                             check=False, timeout=60).out
        members = [m for m in listing.splitlines() if m.strip()]
        assert members, f"techsupport dump {newest} unreadable/empty"
        # Key subset: log directory, DB dump directory, contains CONFIG_DB.json, generator script snapshot
        assert any(m.startswith("log/") for m in members), f"{newest} missing log/ ({members[:5]})"
        assert any(m.startswith("dump/") for m in members), f"{newest} missing dump/ ({members[:5]})"
        assert any(m.endswith("CONFIG_DB.json") for m in members), (
            f"{newest} missing dump/CONFIG_DB.json; techsupport DB snapshot incomplete")
        assert any("syslog" in m for m in members), f"{newest} missing syslog logs"
    finally:
        if generated:
            cli.sh.run(f"rm -f {generated}", check=False)


def test_history_matches_state_db(cli):
    """`show auto-techsupport history` <-> STATE_DB AUTO_TECHSUPPORT* records match one by one.
    If the device has no techsupport events yet (no STATE_DB records and empty history table), honestly skip."""
    r = cli.run("show auto-techsupport history")
    blob = r.out + r.err
    # show command should exist but is unavailable = device defect -> fail to expose.
    assert not ("No such command" in blob or ("Usage:" in blob and "Error" in blob)), (
        "DEVICE DEFECT: `show auto-techsupport history` not available on this image")
    assert "Traceback" not in blob, f"show auto-techsupport history crashed: {blob[-300:]}"
    rows = cli.parse_table(r.out)

    keys = cli.db_keys("STATE_DB", "AUTO_TECHSUPPORT*")
    if not keys and not rows:
        # No techsupport history = the device never crashed / triggered auto-collection, a healthy state ("no data = healthy", not a defect).
        # Both STATE_DB and the history table empty = the two are consistent -> pass (neither skip to mask nor fail to false-alarm).
        return

    # The dump name of each STATE_DB history record should appear in the history table
    dump_col = None
    if rows:
        dump_col = next((c for c in rows[0] if "TECHSUPPORT DUMP" in c.upper() or "DUMP" in c.upper()),
                        None)
    shown = {row.get(dump_col, "") for row in rows} if dump_col else set()
    for k in keys:
        name = k.split("|", 1)[1]
        assert any(name in s or name == s for s in shown), (
            f"STATE_DB history record {name!r} not shown in `show auto-techsupport history` ({shown})")
    # Reverse: history row count should match the STATE_DB record count (when there are no STATE_DB records, only require history to be empty too)
    if not keys:
        assert not rows, f"history shows {len(rows)} rows but STATE_DB has no AUTO_TECHSUPPORT records"
