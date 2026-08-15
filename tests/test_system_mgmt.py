"""System management: hostname/banner/user/time/config persistence/ping/traceroute/SCP/reboot-cause."""
import pytest

pytestmark = [pytest.mark.mgmt]


def test_hostname_config(cli, config_guard):
    """hostname: written to CONFIG_DB + **hostcfgd actually applies it to the kernel** (/etc/hostname
    truly changes / the `hostname` command returns the new value), not merely a CONFIG_DB lookup."""
    import time
    orig = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hostname", "sonic")
    rc, r = cli.config_raw("hostname duttest-host")
    config_guard.defer_undo(f"hostname {orig}")
    # Contract: the CLI must succeed; a syntax mismatch should FAIL to surface it
    assert rc == 0, f"config hostname syntax to be confirmed: {r.err or r.out}"
    assert cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hostname") == \
        "duttest-host"
    # Behavior: hostcfgd should apply the new hostname to the kernel (/etc/hostname or `hostname` command)
    applied = ""
    for _ in range(10):
        applied = (cli.sh.run("cat /etc/hostname 2>/dev/null", check=False).out.strip()
                   or cli.sh.run("hostname", check=False).out.strip())
        if "duttest-host" in applied:
            break
        time.sleep(1)
    assert "duttest-host" in applied, \
        f"hostname configured in CONFIG_DB but hostcfgd did not apply it to kernel: got {applied!r}"


def test_banner_config(cli, config_guard):
    """banner: written to CONFIG_DB + **hostcfgd actually renders** the login banner to /etc/issue(.net),
    not merely a CONFIG_DB lookup."""
    import time
    rc, r = cli.config_raw("banner login 'DUT TEST BANNER'")
    config_guard.defer_undo("banner login ''")
    # Contract: the CLI must succeed; a syntax mismatch should FAIL to surface it
    assert rc == 0, f"config banner syntax to be confirmed: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", "BANNER_MESSAGE|*"), "banner not written to CONFIG_DB"
    # The banner feature defaults to state=disabled and must be explicitly enabled to render --
    # this is a legitimate precondition, not a device defect.
    re, ee = cli.config_raw("banner state enabled")
    config_guard.defer_undo("banner state disabled")
    assert re == 0 and "Traceback" not in (ee.out + ee.err), \
        f"config banner state enabled rejected: {(ee.out + ee.err)[:160]}"
    # Behavior: hostcfgd should render the login banner to /etc/issue / /etc/issue.net
    time.sleep(3)
    issue = (cli.sh.run("cat /etc/issue 2>/dev/null", check=False).out
             + cli.sh.run("cat /etc/issue.net 2>/dev/null", check=False).out)
    # A: banner written to CONFIG_DB but not rendered to /etc/issue = hostcfgd did not render = device defect
    assert "DUT TEST BANNER" in issue, (
        "DEVICE DEFECT: banner in CONFIG_DB but hostcfgd did not render it to /etc/issue on this "
        "image (banner feature inactive)")


def test_config_persistence(cli):
    """Change a specific config value -> `config save` -> the saved json can be **grepped for that value**,
    proving save truly persists the running config to /etc/sonic/config_db.json (not just a non-empty file).
    Change CONFIG_DB with a temporary marker field, then delete and re-save to clean up."""
    import time
    save_file = "/etc/sonic/config_db.json"
    marker_field = "test_save_marker"
    marker_val = f"svtest-{int(time.time())}"
    # Change a specific value (add a temporary marker field to DEVICE_METADATA; no daemon reads it, safe and reversible)
    cli.sh.run(f"sonic-db-cli CONFIG_DB HSET 'DEVICE_METADATA|localhost' "
               f"'{marker_field}' '{marker_val}'", check=False)
    try:
        r = cli.sh.run("config save -y", check=False, timeout=60)
        assert r.rc == 0, f"config save failed: {r.err}"
        assert cli.sh.run(f"test -s {save_file} && echo ok", check=False).out.strip() == "ok", \
            f"{save_file} missing/empty after save"
        # Key upgrade: the saved json must truly contain the value just changed
        grep = cli.sh.run(f"grep -F '{marker_val}' {save_file}", check=False)
        assert grep.rc == 0 and marker_val in grep.out, \
            f"changed config value {marker_val!r} not found in saved {save_file} " \
            "(config save did not persist the running config)"
    finally:
        # teardown: delete the marker and re-save to avoid polluting the saved file / running config
        cli.sh.run(f"sonic-db-cli CONFIG_DB HDEL 'DEVICE_METADATA|localhost' '{marker_field}'",
                   check=False)
        cli.sh.run("config save -y", check=False, timeout=60)


def test_ping_loopback(cli):
    r = cli.run("ping -c 2 -W 2 127.0.0.1")
    assert "2 received" in r.out or "2 packets received" in r.out, "local ping failed"


def test_traceroute_available(cli):
    # A: traceroute tool should be present but is missing = device defect
    assert cli.run("which traceroute").rc == 0, "DEVICE DEFECT: no traceroute tool on this image"
    r = cli.run("traceroute -m 2 -w 1 127.0.0.1", timeout=15)
    # traceroute to localhost: the first hop should be 127.0.0.1 (verify it actually runs, not just that it doesn't crash)
    assert "127.0.0.1" in r.out, f"traceroute to loopback did not reach 127.0.0.1: {r.out[-200:]}"


def test_reboot_cause(cli):
    """show reboot-cause vs. **row-by-row comparison against the STATE_DB REBOOT_CAUSE table**: the cause
    in the show output must truly come from a STATE_DB record (not merely "contains a keyword, no crash") --
    proving the reboot-cause subsystem's records and display are consistent."""
    # Real STATE_DB records (the reboot-cause subsystem writes one on each boot, keyed by timestamp)
    keys = cli.db_keys("STATE_DB", "REBOOT_CAUSE|*")
    # A: the reboot-cause subsystem should write STATE_DB on every boot; empty table = missing record = device defect
    assert keys, ("DEVICE DEFECT: STATE_DB REBOOT_CAUSE table empty (reboot-cause subsystem has not "
                  "recorded any cause)")
    db_causes = {}
    for k in keys:
        ts = k.split("|", 1)[1]
        cause = cli.db_hgetall("STATE_DB", k).get("cause")
        if cause:
            db_causes[ts] = cause
    assert db_causes, f"REBOOT_CAUSE keys present but no 'cause' field recorded: {keys}"

    # Current reboot-cause: the cause in the show output should equal the cause of some STATE_DB record (not an arbitrary keyword)
    r = cli.run("show reboot-cause")
    blob = (r.out + r.err)
    assert "Traceback" not in blob, "show reboot-cause crashed"
    cur = r.out.strip().splitlines()[-1].strip() if r.out.strip() else ""
    assert cur, f"show reboot-cause returned empty output: {blob[-200:]}"
    assert any(cur == c or cur in c or c in cur for c in db_causes.values()), (
        f"show reboot-cause {cur!r} not found among STATE_DB REBOOT_CAUSE records "
        f"{list(db_causes.values())}")

    # history: every STATE_DB record (timestamp + cause) should appear verbatim in the `show reboot-cause history` table
    rh = cli.run("show reboot-cause history")
    assert "Traceback" not in (rh.out + rh.err), "show reboot-cause history crashed"
    rows = cli.parse_table(rh.out)
    hist = {row.get("Name", ""): row.get("Cause", "") for row in rows}
    for ts, cause in db_causes.items():
        assert ts in hist, (
            f"STATE_DB REBOOT_CAUSE record {ts} missing from 'show reboot-cause history': "
            f"{list(hist)}")
        assert hist[ts] == cause, (
            f"history cause for {ts} {hist[ts]!r} != STATE_DB record {cause!r}")


def test_user_management_config(cli):
    """Create a test user -> the user truly appears in /etc/passwd (getent), proving system user management works -> delete to restore."""
    user = "svtestuser"
    # Defensive pre-cleanup of any leftover from a previous run
    cli.sh.run(f"sudo userdel -r {user} 2>/dev/null", check=False)
    create = cli.sh.run(f"sudo useradd -M -s /usr/sbin/nologin {user}", check=False)
    # A: system user management should be available but cannot create a user = device defect
    assert create.rc == 0, (f"DEVICE DEFECT: cannot create test user on this DUT (user mgmt "
                            f"unavailable): {create.err or create.out}")
    try:
        # The user should truly land in /etc/passwd (system user management works); show users should not crash either
        passwd = cli.sh.run(f"getent passwd {user}", check=False)
        assert passwd.rc == 0 and user in passwd.out, \
            f"created user {user!r} not present in /etc/passwd: {passwd.out!r} {passwd.err!r}"
        su = cli.run("show users")
        assert "Traceback" not in (su.out + su.err), "show users crashed"
    finally:
        # teardown: always delete the test user
        cli.sh.run(f"sudo userdel -r {user} 2>/dev/null", check=False)
    # Deletion should take effect: the user no longer exists in /etc/passwd
    gone = cli.sh.run(f"getent passwd {user}", check=False)
    assert gone.rc != 0 and user not in gone.out, \
        f"test user {user!r} still present after userdel"
