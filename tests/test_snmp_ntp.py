"""SNMP / NTP: config provisioning + reachability verification."""
import re

import pytest

pytestmark = [pytest.mark.mgmt]

# Type prefix in snmpget's default output ("OID = TYPE: value"); must be stripped before comparison.
_TYPE_RE = re.compile(r"^(?:Hex-STRING|STRING|INTEGER|Timeticks|OID)\s*:\s*", re.IGNORECASE)

# The net-snmp tools (snmpget) are only inside the snmp container, not on the host PATH.
SNMP_CONTAINER = "snmp"


def _sysdescr_value(out):
    """Extract the bare sysDescr value from snmpget's default output (strip type prefix and quotes)."""
    for line in out.splitlines():
        if "=" in line and "No Such" not in line:
            rhs = line.split("=", 1)[1].strip()
            return _TYPE_RE.sub("", rhs).strip().strip('"')
    return None


def test_snmp_community_config(cli, config_guard):
    """SNMP community: persisted to CONFIG_DB + **snmpd actually serves the community**
    (snmpget with the new community succeeds), not merely checking it was "written to CONFIG_DB"."""
    import time
    before = set(cli.db_keys("CONFIG_DB", "SNMP_COMMUNITY|*"))
    rc, r = cli.config_raw("snmp community add DUTTESTRO ro")
    config_guard.defer_undo("snmp community del DUTTESTRO")
    # C: if the CLI is broken, FAIL to expose it (was previously skip "subcommand differs")
    assert rc == 0, f"config snmp community subcommand failed: {r.err or r.out}"
    # The persistence check tolerates two storage styles: a plaintext key
    # SNMP_COMMUNITY|DUTTESTRO; or encrypted storage (the key is ciphertext, e.g.
    # SNMP_COMMUNITY|V8N7ZMYRStQ=) — for the latter, "the key set grew" is enough; the
    # real functional assertion is below in "snmpd actually serves the community".
    after = set(cli.db_keys("CONFIG_DB", "SNMP_COMMUNITY|*"))
    assert ("SNMP_COMMUNITY|DUTTESTRO" in after) or (after - before), \
        "snmp community not written to CONFIG_DB (neither plaintext nor encrypted key appeared)"
    # A: the net-snmp tools should be inside the snmp container; their absence is a device defect
    assert cli.sh.run("which snmpget", container="snmp", check=False).rc == 0, \
        "DEVICE DEFECT: snmpget not present in snmp container"
    # Behavior: after snmpcfgd renders, snmpd should accept the new community (poll to allow render time)
    served = None
    for _ in range(8):
        served = cli.sh.run("snmpget -v2c -c DUTTESTRO -t 2 -r 1 localhost 1.3.6.1.2.1.1.1.0",
                            container="snmp", check=False, timeout=15)
        if served.rc == 0 and ("STRING" in served.out or "sonic" in served.out.lower()):
            break
        time.sleep(2)
    # A: once the community is persisted, snmpd should actually serve it; not serving it is a device defect
    assert served is not None and served.rc == 0 and \
        ("STRING" in served.out or "sonic" in served.out.lower()), \
        "DEVICE DEFECT: community in CONFIG_DB but snmpd did not serve it " \
        "(snmpcfgd render/reload not applied on this image)"


def test_snmpget_localhost(cli):
    """When snmpd is present, a local snmpget of sysDescr should be compared against the
    DB's real values (CONFIG_DB hwsku / build version), not merely checking the output
    contains the word 'sonic'."""
    # A: the net-snmp client should be inside the snmp container; its absence is a device defect
    assert cli.sh.run("which snmpget", container=SNMP_CONTAINER, check=False).rc == 0, \
        "DEVICE DEFECT: snmpget not present in snmp container"
    # Poll: the previous community test triggers snmpcfgd to restart snmpd; a query timeout during the restart window is timing, not a defect
    import time
    r = None
    for _ in range(10):
        r = cli.sh.run("snmpget -v2c -c public -t 2 -r 1 localhost 1.3.6.1.2.1.1.1.0",
                       container=SNMP_CONTAINER, check=False, timeout=15)
        if r.rc == 0:
            break
        time.sleep(2)
    # A: snmpd not ready / community mismatch = SNMP not ready, a device defect
    assert r.rc == 0, \
        f"DEVICE DEFECT: snmpd not ready / community mismatch: {r.err[-200:]}"
    descr = _sysdescr_value(r.out)
    assert descr, f"snmpget returned no sysDescr: {r.out}"
    assert "sonic" in descr.lower(), f"sysDescr missing SONiC marker: {descr!r}"
    # Compare against the DB's real values: CONFIG_DB DEVICE_METADATA.hwsku must appear in sysDescr; otherwise fall back to build version
    hwsku = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hwsku")
    ver = cli.run("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version").out.strip()
    if hwsku:
        assert hwsku in descr, f"sysDescr hwsku mismatch: want {hwsku!r} in {descr!r}"
    elif ver:
        assert ver in descr, f"sysDescr build_version mismatch: want {ver!r} in {descr!r}"
    else:
        # A: a real box should have real hwsku/build_version values; their absence is a DB data defect
        pytest.fail("DEVICE DEFECT: no CONFIG_DB hwsku nor build_version available to compare sysDescr")


def test_ntp_server_config(cli, config_guard):
    """NTP server: persisted to CONFIG_DB + **the NTP daemon actually consumes it** (the
    chrony/ntp config file renders the server, or `show ntp` lists it), not merely
    checking it was "written to CONFIG_DB"."""
    import time
    srv = "8.8.8.8"   # use a public address to avoid a 127.0.0.1 self-reference being filtered by the daemon
    _pre_src = (cli.db_hgetall("CONFIG_DB", "NTP|global") or {}).get("src_intf")
    rc, r = cli.config_raw(f"ntp add {srv}")
    config_guard.defer_undo(f"ntp del {srv}")

    # Defensive teardown: some ntp config chains **side-write** NTP|global.src_intf, and
    # that value may be rejected by this box's YANG (leafref not a front-panel port);
    # leaving it causes subsequent full-validation config commands to fail with "Data
    # Loading Failed". If teardown finds a src_intf that newly appeared during this test,
    # remove it with the product command `ntp source del` (leaving any preset value alone).
    def _clear_side_effect_src_intf():
        cur = (cli.db_hgetall("CONFIG_DB", "NTP|global") or {}).get("src_intf")
        if cur and cur != _pre_src:
            cli.config_raw(f"ntp source del {cur}")
        return (cli.db_hgetall("CONFIG_DB", "NTP|global") or {}).get("src_intf") == _pre_src
    config_guard.defer_undo("ntp del 0.0.0.0", verify=_clear_side_effect_src_intf)  # placeholder cmd; verify performs the real cleanup
    # C: if the CLI is broken, FAIL to expose it (was previously skip "subcommand differs")
    assert rc == 0, f"config ntp add subcommand failed: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"NTP_SERVER|{srv}"), "no NTP server in CONFIG_DB"
    time.sleep(3)   # give hostcfgd/ntp-config time to render
    # Behavior: the daemon config (chrony.conf/ntp.conf) or show ntp should contain the server
    rendered = cli.sh.run("cat /etc/chrony/chrony.conf /etc/ntp.conf /etc/ntpsec/ntp.conf 2>/dev/null",
                          check=False).out
    shown = cli.run("show ntp").out if cli.run("which show").rc == 0 else ""
    # A: once the NTP server is persisted, the daemon should actually consume it; not rendering it is a device defect
    assert srv in rendered or srv in shown, \
        f"DEVICE DEFECT: NTP server {srv} in CONFIG_DB but not rendered to ntp/chrony daemon " \
        "config or `show ntp` on this image"
