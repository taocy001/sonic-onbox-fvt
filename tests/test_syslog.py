"""Remote syslog: config syslog pointing at the local collector -> generate a log -> collector receives it (end-to-end)."""
import time

import pytest

pytestmark = [pytest.mark.mgmt]


def _collector_ip(cli):
    """Collector address = the device's own management-port IP (cached in-process).

    Cannot use 127.0.0.1: the reworked OS (SONiC) validates "Loopback ip is not valid" and rejects loopback,
    while the own management IP is accepted by both image types, and the packet loops back via local routing
    and is received the same by the 0.0.0.0-listening collector -- the end-to-end semantics are unchanged."""
    if getattr(cli, "_syslog_col", None) is None:
        out = cli.sh.run(
            "ip -4 addr show eth0 | grep -oP '(?<=inet )[0-9.]+' | head -1", check=False).out
        cli._syslog_col = out.strip() or "127.0.0.1"
    return cli._syslog_col


def test_remote_syslog_forwarding(cli, config_guard):
    from servers.collectors import SyslogServer

    COLLECTOR = _collector_ip(cli)
    srv = SyslogServer(bind_ip="0.0.0.0", port=514)
    srv.start()
    try:
        rc, r = cli.config_raw(f"syslog add {COLLECTOR}")
        config_guard.defer_undo(f"syslog del {COLLECTOR}")
        # C: the CLI should succeed; if the subcommand differs, FAIL to expose (no longer hidden by skip)
        assert rc == 0, f"config syslog add subcommand differs from expected: {r.err or r.out}"
        time.sleep(5)  # wait for rsyslog to reload the remote-forwarding config
        marker = "DUTTEST-SYSLOG-PROBE-12345"
        for _ in range(3):
            cli.sh.run(f"logger -p user.err {marker}", check=False)
            time.sleep(2)
            if srv.has(marker):
                break
        # A: remote syslog should be received but was not = rsyslog remote forwarding not effective
        assert srv.has(marker), (
            "remote syslog NOT received by the collector after config + 3 logger "
            "attempts -- rsyslog remote forwarding not working")
        # marker received: end-to-end remote syslog forwarding genuinely verified
    finally:
        srv.stop()


def test_syslog_config_in_db(cli, config_guard):
    """config syslog add: (1) CONFIG_DB SYSLOG_SERVER key + (2) **rsyslog really renders a forwarding rule**
    (the syslog-config service renders this server into an omfwd action in /etc/rsyslog.conf or /etc/rsyslog.d/,
    Target=that server), not merely checking CONFIG_DB. After add, /etc/rsyslog.conf shows
    `action(type="omfwd" Target="127.0.0.1" Port="514" ...)`."""
    COLLECTOR = _collector_ip(cli)
    rc, _ = cli.config_raw(f"syslog add {COLLECTOR}")
    config_guard.defer_undo(f"syslog del {COLLECTOR}")
    # C: the CLI should succeed; if the subcommand differs, FAIL to expose
    assert rc == 0, "config syslog add subcommand differs from expected"
    assert cli.db_keys("CONFIG_DB", f"SYSLOG_SERVER|{COLLECTOR}"), "no syslog server in CONFIG_DB"
    # Behavior: the syslog-config service renders this server into an rsyslog omfwd forwarding rule (restart rsyslog-config is async)
    rendered = ""
    for _ in range(10):
        # -i: the 158 new rsyslog template uses `Target="ip"`, SONiC uses lowercase `target="ip"`, same semantics
        rendered = cli.sh.run(
            'grep -rni \'target="%s"\' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null' % COLLECTOR,
            check=False).out
        if "omfwd" in rendered:
            break
        time.sleep(1)
    assert "omfwd" in rendered, (
        f"SYSLOG_SERVER {COLLECTOR} in CONFIG_DB but NOT rendered to an rsyslog omfwd forwarding rule "
        f"in /etc/rsyslog.conf or /etc/rsyslog.d/ (syslog-config did not apply it): {rendered[:200]!r}")
