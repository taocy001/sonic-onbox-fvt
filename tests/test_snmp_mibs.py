"""SNMP MIBs: v2c/v3, RFC1213, IF-MIB, ifXTable, Q-BRIDGE, LLDP-MIB, ENTITY, HOST-RES.

Requires snmpd ready + community; if not ready, skip (no fabrication).

Upgrade: no longer only checks "can walk it / output contains STRING", but compares each SNMP return value against DB ground truth
(sysDescr<->CONFIG_DB hwsku/build version, sysName<->DEVICE_METADATA hostname,
ifNumber<->CONFIG_DB port count, ifDescr/ifName<->CONFIG_DB alias, ifOperStatus<->STATE_DB oper,
locChassisId<->DEVICE_METADATA mac, etc.). If this image does not expose the OID / there is no DB ground truth to compare -> honest skip.
"""
import re

import pytest

pytestmark = [pytest.mark.mgmt]

# net-snmp tools (snmpget/snmpwalk) live only in the snmp container, not on the host PATH ->
# all snmp commands run via cli.sh.run(..., container=SNMP_CONTAINER) (following test_snmp_mibs_full.py).
SNMP_CONTAINER = "snmp"

# community probe cache (once per process). Cannot hardcode "public": SONiC stores the community encrypted
# (SNMP_COMMUNITY|V8N7ZMYRStQ=), with the real value in plaintext in /etc/sonic/snmp.yml -- a hardcoded value on
# another device times out across the board -> everything wrongly flagged as DEVICE DEFECT. The probe approach shares
# its source with test_snmp_mibs_full._community (device differences should be absorbed into the adaptation layer;
# once the framework unifies them the two files will share it).
_COMM_CACHE = []


def _community(cli):
    """Probe the SNMP community actually in effect: candidates = (snmp.yml plaintext, CONFIG_DB key, 'public'),
    probed one by one with a sysDescr get, taking the first responder; only cache success (do not cache None during the snmpd restart window)."""
    import time as _t
    if _COMM_CACHE:
        return _COMM_CACHE[0]
    cands = []
    y = cli.sh.run("grep -s snmp_rocommunity /etc/sonic/snmp.yml", check=False).out or ""
    if ":" in y:
        cands.append(y.split(":", 1)[1].strip().strip("'\""))
    for k in cli.db_keys("CONFIG_DB", "SNMP_COMMUNITY|*"):
        if "|" in k:
            cands.append(k.split("|", 1)[1])
    cands.append("public")
    uniq = [c for i, c in enumerate(cands) if c and c not in cands[:i]]
    deadline = _t.time() + 40
    while True:
        for c in uniq:
            r = cli.sh.run(f"snmpget -v2c -c {c} -t 2 -r 0 localhost 1.3.6.1.2.1.1.1.0",
                           container=SNMP_CONTAINER, check=False, timeout=10)
            if r.rc == 0 and r.out and "No Such" not in r.out:
                _COMM_CACHE.append(c)
                return c
        if _t.time() > deadline:
            return None
        _t.sleep(3)

# Type prefix in the default snmpget/snmpwalk output ("OID = TYPE: value"), to be stripped before comparison.
_TYPE_RE = re.compile(
    r"^(?:Hex-STRING|STRING|INTEGER|Gauge32|Gauge64|Counter32|Counter64|Timeticks|"
    r"OID|IpAddress|Network Address|BITS|Opaque|Integer32|Unsigned32)\s*:\s*",
    re.IGNORECASE,
)

# (name, OID) -- snmpwalk/get verifies it returns
MIBS = [
    ("RFC1213_sysDescr", "1.3.6.1.2.1.1.1.0"),
    ("RFC1213_sysName", "1.3.6.1.2.1.1.5.0"),
    ("RFC1213_sysUpTime", "1.3.6.1.2.1.1.3.0"),
    ("IF-MIB_ifNumber", "1.3.6.1.2.1.2.1.0"),
    ("IF-MIB_ifDescr", "1.3.6.1.2.1.2.2.1.2"),
    ("IF-MIB_ifOperStatus", "1.3.6.1.2.1.2.2.1.8"),
    ("IF-MIB_ifInOctets", "1.3.6.1.2.1.2.2.1.10"),
    ("ifXTable_ifHCInOctets", "1.3.6.1.2.1.31.1.1.1.6"),
    ("ifXTable_ifName", "1.3.6.1.2.1.31.1.1.1.1"),
    ("ENTITY_physClass", "1.3.6.1.2.1.47.1.1.1.1.5"),
    ("HOST-RES_hrSystemUptime", "1.3.6.1.2.1.25.1.1.0"),
    ("LLDP_locChassisId", "1.0.8802.1.1.2.1.3.2.0"),
]


def _snmp_ready(cli):
    # net-snmp tools live only in the snmp container, so probe inside the container; community is probed (do not hardcode public)
    if cli.sh.run("which snmpget", container=SNMP_CONTAINER, check=False).rc != 0:
        return False
    comm = _community(cli)
    if not comm:
        return False
    r = cli.sh.run(f"snmpget -v2c -c {comm} -t 2 -r 1 localhost 1.3.6.1.2.1.1.1.0",
                   container=SNMP_CONTAINER, check=False, timeout=12)
    return r.rc == 0 and "STRING" in r.out


# ---------------------------------------------------------------------------
# SNMP default-output parsing helpers ("OID = TYPE: value", strip type prefix/quotes)
# ---------------------------------------------------------------------------
def _val(line):
    """Extract the bare value from a `OID = TYPE: value` line (removing type prefix and quotes). Returns None if there is no '='."""
    if "=" not in line:
        return None
    rhs = line.split("=", 1)[1].strip()
    rhs = _TYPE_RE.sub("", rhs)
    return rhs.strip().strip('"')


def _scalar_out(out):
    """Take the first valid value (scalar) from walk/get output. Returns None if there is no valid line."""
    for line in out.splitlines():
        if "=" in line and "No Such" not in line and "No more" not in line:
            return _val(line)
    return None


def _entries(out):
    """Parse a table walk into {ifIndex (trailing integer): value}."""
    d = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "=" not in line or "No Such" in line or "No more" in line:
            continue
        oidpart = line.split("=", 1)[0].strip()
        m = re.search(r"(\d+)\s*$", oidpart)
        if m:
            d[m.group(1)] = _val(line)
    return d


def _int(s):
    m = re.search(r"-?\d+", s or "")
    return int(m.group()) if m else None


def _walk(cli, oid, timeout=20):
    # snmpwalk runs inside the snmp container
    return cli.sh.run(f"snmpwalk -v2c -c {_community(cli)} -t 2 -r 1 localhost {oid}",
                      container=SNMP_CONTAINER, check=False, timeout=timeout).out


def _ports(cli):
    """{name: cfg-dict} for all CONFIG_DB PORTs."""
    out = {}
    for k in cli.db_keys("CONFIG_DB", "PORT|*"):
        name = k.split("|", 1)[1]
        out[name] = cli.db_hgetall("CONFIG_DB", k)
    return out


# ---------------------------------------------------------------------------
# Per-MIB "value vs DB ground truth" validators: validator(cli, name, oid, out)
# No DB ground truth to compare / this image does not expose it -> pytest.skip inside the validator (never pass on presence alone)
# ---------------------------------------------------------------------------
def _v_sysDescr(cli, name, oid, out):
    descr = _scalar_out(out)
    assert descr, f"{name}: sysDescr returned no value"
    assert "SONiC" in descr, f"sysDescr missing SONiC marker: {descr!r}"
    hwsku = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hwsku")
    ver = cli.run("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version").out.strip()
    checked = False
    if hwsku:
        assert hwsku in descr, f"sysDescr hwsku mismatch: want {hwsku!r} in {descr!r}"
        checked = True
    if ver and ver in descr:
        checked = True
    # A: a real device should have hwsku/build_version ground truth to compare; missing = DB data defect
    assert checked, "no CONFIG_DB hwsku nor build_version available to compare sysDescr"


def _v_sysName(cli, name, oid, out):
    val = _scalar_out(out)
    assert val, f"{name}: sysName returned no value"
    db_host = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hostname") \
        or cli.run("hostname").out.strip()
    # A: a real device should have DEVICE_METADATA hostname / `hostname` ground truth; missing = data defect
    assert db_host, "no DEVICE_METADATA hostname / `hostname` to compare sysName"
    assert val == db_host, f"sysName {val!r} != hostname {db_host!r}"


def _v_uptime(cli, name, oid, out):
    """sysUpTime/hrSystemUptime: should be positive and monotonically increasing across two samples (proving the agent is really running; uptime has no DB ground truth)."""
    import time
    v1 = _int(_scalar_out(out))
    assert v1 is not None and v1 > 0, f"{name} not positive: {out[-120:]!r}"
    time.sleep(2)
    v2 = _int(_scalar_out(_walk(cli, oid)))
    assert v2 is not None and v2 >= v1, f"{name} did not grow: {v1} -> {v2}"


def _v_ifNumber(cli, name, oid, out):
    n = _int(_scalar_out(out))
    assert n is not None and n > 0, f"{name} not positive"
    nports = len(cli.db_keys("CONFIG_DB", "PORT|*"))
    assert n >= nports, f"ifNumber {n} < CONFIG_DB PORT count {nports}"


def _v_alias_table(cli, name, oid, out):
    """ifDescr/ifName table: each CONFIG_DB PORT's alias or name should appear in the set of returned values."""
    ports = _ports(cli)
    # A: a real device should have CONFIG_DB PORT; missing = data defect
    assert ports, "no CONFIG_DB PORT to compare ifDescr/ifName"
    vals = set(_entries(out).values())
    # A: the table should return rows (this MIB is exposed); an empty table = device defect
    assert vals, f"{name}: no table rows returned"
    missing = [n for n, cfg in ports.items()
               if not ({cfg.get("alias"), n} & vals)]
    assert not missing, \
        f"{name}: CONFIG_DB ports not found in SNMP table (alias/name): {missing[:5]}"


def _ifindex_map(cli):
    """A probe-based port -> ifIndex mapping (the two kinds of agent differ: the newer sonic-snmpagent uses
    CONFIG_DB index+2, older/custom agents use EthernetN+1 -- a fixed offset would read the wrong rows across the board,
    comparing port A's expectation against port B's actual, misjudging both ways). Prefer walking ifDescr to build a
    value->ifIndex reverse lookup (an alias/name hit is authoritative); when an older agent uses its own naming (DGE#),
    fall back to ethnum+1, then to index+2 (which must exist in the table)."""
    descr = _entries(_walk(cli, "1.3.6.1.2.1.2.2.1.2"))
    rev = {}
    for idx, val in descr.items():
        rev.setdefault(val, idx)
    out = {}
    for pname, cfg in _ports(cli).items():
        idx = rev.get(cfg.get("alias")) or rev.get(pname)
        if idx is None:
            m = re.search(r"(\d+)$", pname)
            cands = [str(int(m.group(1)) + 1)] if m else []
            if cfg.get("index") is not None:
                cands.append(str(int(cfg["index"]) + 2))
            idx = next((c for c in cands if c in descr), None)
        if idx is not None:
            out[pname] = idx
    return out


def _v_ifOperStatus(cli, name, oid, out):
    """ifOperStatus[ifIndex] (1=up,2=down) should match STATE_DB oper (per-port comparison, probe-based ifIndex)."""
    entries = _entries(out)
    # A: the table should return rows; an empty table = device defect
    assert entries, f"{name}: no table rows returned"
    idx_map = _ifindex_map(cli)
    compared = 0
    for pname, cfg in _ports(cli).items():
        ifindex = idx_map.get(pname)
        if ifindex is None or ifindex not in entries:
            continue
        state = cli.db_hgetall("STATE_DB", f"PORT_TABLE|{pname}")
        oper = state.get("netdev_oper_status") or state.get("oper_status")
        if not oper:
            continue
        want = 1 if oper == "up" else 2
        got = _int(entries[ifindex])
        assert got == want, \
            f"{pname}: ifOperStatus {got} != expected {want} (STATE_DB oper={oper})"
        compared += 1
    # A: a real device should have at least one port mappable ifIndex<->STATE_DB oper; none comparable = data defect
    assert compared > 0, \
        "no port could be mapped ifIndex<->STATE_DB oper to compare ifOperStatus"


def _v_counter_table(cli, name, oid, out):
    """ifInOctets/ifHCInOctets: counters have no static ground truth, but the row count should be >= the CONFIG_DB port count and all be non-negative integers."""
    entries = _entries(out)
    # A: the table should return rows; an empty table = device defect
    assert entries, f"{name}: no table rows returned"
    nums = [_int(v) for v in entries.values()]
    assert all(v is not None and v >= 0 for v in nums), \
        f"{name}: non-numeric/negative counter value present: {list(entries.values())[:5]}"
    nports = len(cli.db_keys("CONFIG_DB", "PORT|*"))
    assert len(nums) >= nports, f"{name}: {len(nums)} rows < CONFIG_DB PORT count {nports}"


def _v_entPhysClass(cli, name, oid, out):
    """The entPhysicalClass subtree should contain chassis(=3)."""
    vals = [_int(v) for v in _entries(out).values()]
    # A: if entPhysicalClass is exposed it should have rows; empty = device defect
    assert vals, f"{name}: no rows returned"
    assert 3 in vals, f"entPhysicalClass has no chassis(3): {vals[:8]}"


def _v_locChassisId(cli, name, oid, out):
    """lldpLocChassisId should be a stable unique MAC on the device (chassis-id subtype=mac).

    Correction: lldpd by default takes the management-port eth0 MAC as the ChassisID (no chassisid explicitly configured);
    on most platforms eth0 MAC == base MAC, so the historical assertion "== DEVICE_METADATA.mac" passed; the two need not
    be equal. Accept either the eth0 MAC or the base MAC."""
    chassis = _scalar_out(out)
    assert chassis, f"{name}: returned no value"
    norm = lambda s: "".join(c for c in s.lower() if c in "0123456789abcdef")
    db_mac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac", "")
    eth0 = cli.sh.run("ip link show eth0", check=False).out or ""
    import re as _re
    m = _re.search(r"link/ether\s+([0-9a-fA-F:]+)", eth0)
    mgmt_mac = m.group(1) if m else ""
    valid = {norm(x) for x in (mgmt_mac, db_mac) if x}
    assert valid, "neither eth0 MAC nor DEVICE_METADATA mac to compare lldpLocChassisId"
    assert norm(chassis) in valid, \
        f"lldpLocChassisId {chassis!r} matches neither eth0 mgmt MAC {mgmt_mac!r} nor base MAC {db_mac!r}"


_VALIDATORS = {
    "RFC1213_sysDescr": _v_sysDescr,
    "RFC1213_sysName": _v_sysName,
    "RFC1213_sysUpTime": _v_uptime,
    "IF-MIB_ifNumber": _v_ifNumber,
    "IF-MIB_ifDescr": _v_alias_table,
    "IF-MIB_ifOperStatus": _v_ifOperStatus,
    "IF-MIB_ifInOctets": _v_counter_table,
    "ifXTable_ifHCInOctets": _v_counter_table,
    "ifXTable_ifName": _v_alias_table,
    "ENTITY_physClass": _v_entPhysClass,
    "HOST-RES_hrSystemUptime": _v_uptime,
    "LLDP_locChassisId": _v_locChassisId,
}


def test_snmp_v2c_reachable(cli):
    """snmpd really in effect: compare sysDescr against DB ground truth (CONFIG_DB hwsku / build version), not just checking that output contains STRING."""
    # A: snmpd not ready / community not configured = SNMP not ready, a device defect
    assert _snmp_ready(cli), \
        "snmpd not ready / community not configured"
    r = cli.sh.run(f"snmpget -v2c -c {_community(cli)} -t 2 -r 1 localhost 1.3.6.1.2.1.1.1.0",
                   container=SNMP_CONTAINER, check=False, timeout=12)
    assert r.rc == 0, f"snmpd did not return sysDescr: {r.out[-150:]}"
    descr = _scalar_out(r.out)
    assert descr, f"snmpd did not return sysDescr value: {r.out[-150:]}"
    assert "SONiC" in descr, f"sysDescr missing SONiC marker: {descr!r}"
    hwsku = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hwsku")
    ver = cli.run("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version").out.strip()
    if hwsku:
        # sysDescr looks like "SONiC Software Version: SONiC.<ver> - HwSku: <hwsku> - ..."
        assert hwsku in descr, f"sysDescr hwsku mismatch: want {hwsku!r} in {descr!r}"
    elif ver:
        assert ver in descr, f"sysDescr build_version mismatch: want {ver!r} in {descr!r}"
    else:
        # A: a real device should have hwsku/build_version ground truth; missing = DB data defect
        pytest.fail("no CONFIG_DB hwsku nor build_version available to compare sysDescr")


@pytest.mark.parametrize("name,oid", MIBS, ids=[m[0] for m in MIBS])
def test_snmp_mib_oid(cli, name, oid):
    """Each OID: first verify it can be walked (presence), then compare against DB ground truth via _VALIDATORS."""
    # A: snmpd not ready = device defect
    assert _snmp_ready(cli), "snmpd not ready"
    r = cli.sh.run(f"snmpwalk -v2c -c {_community(cli)} -t 2 -r 1 localhost {oid}",
                   container=SNMP_CONTAINER, check=False, timeout=20)
    # A: this MIB should be exposed; not exposed = device defect
    assert not (r.rc != 0 or "=" not in r.out or "No Such" in r.out), \
        f"{name} ({oid}) not exposed: {r.out[-150:]}"
    validator = _VALIDATORS.get(name)
    # A: every MIBS entry should have a DB ground-truth validator; missing = test-case defect
    assert validator is not None, f"{name}: no DB ground-truth mapping defined"
    validator(cli, name, oid, r.out)


def test_snmp_v3_user_config(cli, config_guard):
    """SNMP v3 user: written to CONFIG_DB + snmpd really serves v3 authentication (an authNoPriv snmpget with that user succeeds),
    not just checking that it is "written into CONFIG_DB"."""
    import time
    # CLI syntax: snmp user add <user> <noAuthNoPriv|AuthNoPriv|Priv> <RO|RW> <MD5|SHA|...> <pass> [DES|AES]
    rc, r = cli.config_raw("snmp user add testv3 AuthNoPriv RO MD5 authpass123")
    config_guard.defer_undo("snmp user del testv3")
    # C: if the CLI is broken, FAIL to expose it (was previously skip "syntax to be confirmed")
    assert rc == 0, f"snmp v3 user config command failed: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", "SNMP_USER|testv3"), \
        "SNMP v3 user testv3 not written to CONFIG_DB SNMP_USER|testv3"
    # A: net-snmp tools should be in the snmp container; missing = device defect
    assert cli.sh.run("which snmpget", container="snmp", check=False).rc == 0, \
        "snmpget not in snmp container to verify v3 behavior"
    # Behavior: snmpd should accept a v3-authenticated get (poll to give snmpcfgd rendering time)
    got = None
    for _ in range(8):
        got = cli.sh.run("snmpget -v3 -u testv3 -l authNoPriv -a MD5 -A authpass123 -t 2 -r 1 "
                         "localhost 1.3.6.1.2.1.1.1.0", container="snmp", check=False, timeout=15)
        if got.rc == 0 and ("STRING" in got.out or "sonic" in got.out.lower()):
            break
        time.sleep(2)
    # A: after the v3 user is stored, snmpd should really authenticate; not authenticating = device defect
    assert got is not None and got.rc == 0 and \
        ("STRING" in got.out or "sonic" in got.out.lower()), \
        "v3 user in CONFIG_DB but snmpd did not authenticate it"

    def _served(res):
        return res.rc == 0 and ("STRING" in res.out or "sonic" in res.out.lower())

    # Negative (1): a wrong password must be rejected (if snmpd were rendered to not verify the USM digest, the positive path
    # would still pass -- only the rejection path proves authentication is really running). A bad digest is silently dropped per protocol -> timeout rc!=0 (-t 2 -r 0 keeps it fast).
    bad = cli.sh.run("snmpget -v3 -u testv3 -l authNoPriv -a MD5 -A wrongpass999 -t 2 -r 0 "
                     "localhost 1.3.6.1.2.1.1.1.0", container="snmp", check=False, timeout=10)
    assert not _served(bad), \
        "snmpd served a v3 get with a WRONG password (USM auth not enforced)"
    # Negative (2): after an explicit del the user goes from served to rejected (the deletion chain really takes effect; the guard's repeated del is an idempotent cleanup)
    rc, r = cli.config_raw("snmp user del testv3")
    assert rc == 0, f"snmp user del failed: {r.err or r.out}"
    denied = False
    for _ in range(8):
        g = cli.sh.run("snmpget -v3 -u testv3 -l authNoPriv -a MD5 -A authpass123 -t 2 -r 0 "
                       "localhost 1.3.6.1.2.1.1.1.0", container="snmp", check=False, timeout=10)
        if not _served(g):
            denied = True
            break
        time.sleep(2)
    assert denied, "deleted v3 user is still served by snmpd (user removal not applied)"
