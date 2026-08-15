"""SNMP MIB value-vs-DB broad coverage (drawn from sonic-mgmt tests/snmp/ + snmp_facts.py DefineOid).

Unlike test_snmp_mibs.py (presence-only), this file compares SNMP return values against SONiC
DB / system ground truth one by one (with the necessary tolerances), not just "can it be walked".

Key environment facts:
  - The net-snmp tools (snmpget/snmpwalk) live only in the **snmp container**, not on the host
    PATH -> all snmp commands run via `cli.sh.run(..., container=SNMP_CONTAINER)`.
  - sysName/sysLocation and other scalars, IF-MIB ifTable, ifXTable, UCD memory, ENTITY chassis,
    and LLDP locChassisId all return.
  - ipCidrRoute(4.24)/ipAddrTable(4.20)/entPhySensor(99)/cefcFRUPowerOperStatus are **not
    exposed** on this image (No Such Object/Instance) -> pytest.skip each (never assert True).
  - ifDescr/ifName = the SONiC port **alias** (e.g. Eth200GE0/26), ifIndex = CONFIG_DB index + 2.
    ifAlias(.18) is empty here (no description configured) -> compare only if it has a value,
    else skip.
  - ifSpeed(.5) saturates to 4294967295 above 4Gbps, so value comparison uses ifHighSpeed(Mbps).

snmpd not ready / community not configured / MIB not exposed on this image -> a justified
pytest.skip, never assert True.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.mgmt]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

SNMP_CONTAINER = "snmp"

# ifHCInOctets traffic magnitude + storm-guard-dedicated DST
_TRAFFIC_N = 200
_HC_DST = "00:aa:bb:cc:dd:55"

# ifIndex offset relative to the CONFIG_DB PORT index field (e.g. index 25 -> ifIndex 27).
IFINDEX_FROM_PORT_INDEX = 2

# UCD/meminfo tolerance: FreeMem/Cached drift between two samples, so allow +/-15% + 200MB floor.
MEM_TOL_FRAC = 0.15
MEM_TOL_ABS_KB = 200 * 1024


# ---------------------------------------------------------------------------
# SNMP execution / parsing helpers
# ---------------------------------------------------------------------------
_COMM_CACHE = []   # [community or None], probed once per process


def _community(cli):
    """Get the **actually effective** SNMP community (probe-based, cached once per process).

    Cannot trust CONFIG_DB alone: some SONiC builds store the community **encrypted** (key
    like SNMP_COMMUNITY|V8N7ZMYRStQ=) while snmpd.conf is rendered in plaintext (sourced from
    /etc/sonic/snmp.yml snmp_rocommunity: public). Querying with the CONFIG_DB key name as the
    community would time out entirely. So candidates = (snmp.yml plaintext, CONFIG_DB key,
    'public'), probed one by one with a sysDescr get, taking the first that answers."""
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
    uniq = []
    for c in cands:
        if c and c not in uniq:
            uniq.append(c)
    # Overall probe retry + **cache only on success**: prior cases (e.g. test_snmp_mibs's v3
    # user config) make snmpcfgd restart snmpd, and during the restart window (~10s+) no
    # candidate answers. The first implementation cached None -> every case in this file falsely
    # failed. Do not cache failures, so the next case still gets a chance to re-probe.
    deadline = time.time() + 40
    while True:
        for c in uniq:
            r = cli.sh.run(f"snmpget -v2c -c {c} -On -Oq -t 2 -r 0 localhost 1.3.6.1.2.1.1.1.0",
                           container=SNMP_CONTAINER, check=False, timeout=10)
            if _exposed(r):
                _COMM_CACHE.append(c)
                return c
        if time.time() > deadline:
            return None
        time.sleep(3)


def _snmp(cli, verb, oid, comm, timeout=20):
    """Run snmpget/snmpwalk inside the snmp container (numeric OID output). Returns Result."""
    cmd = f"{verb} -v2c -c {comm} -On -Oq -t 3 -r 1 localhost {oid}"
    return cli.sh.run(cmd, container=SNMP_CONTAINER, check=False, timeout=timeout)


def _ready(cli):
    """snmpd ready + community configured + snmpget present in the container. Returns (ok, community, reason)."""
    comm = _community(cli)
    if not comm:
        return False, None, ("no usable SNMP community (yaml/CONFIG_DB/public all failed to "
                             "answer sysDescr; snmpd may be down or restarting)")
    which = cli.sh.run(f"which snmpget", container=SNMP_CONTAINER, check=False)
    if which.rc != 0:
        return False, comm, "snmpget not present in snmp container"
    r = _snmp(cli, "snmpget", "1.3.6.1.2.1.1.1.0", comm, timeout=12)
    # Note: -Oq output has no type name (STRING), only "<oid> <value>", so use _exposed to judge a valid reply
    if not _exposed(r):
        return False, comm, f"snmpd not answering sysDescr: {(r.out or r.err)[-120:]}"
    return True, comm, ""


def _require_snmp(cli):
    ok, comm, reason = _ready(cli)
    # A: SNMP not ready is a device defect (snmpd down / community unconfigured / container missing snmpget)
    assert ok, f"DEVICE DEFECT: snmp not ready: {reason}"
    return comm


def _exposed(r):
    """OID actually has a value (not No Such / empty / error). Under -Oq the value looks like `.1.3... value`."""
    if r.rc != 0:
        return False
    out = r.out
    if not out or "No Such" in out or "No more variables" in out:
        return False
    return True


def _scalar(cli, oid, comm):
    """get a scalar, returning the value string with the OID prefix stripped (-Oq: `<oid> <value>`); None if absent."""
    r = _snmp(cli, "snmpget", oid, comm)
    if not _exposed(r):
        return None
    line = r.out.strip().splitlines()[0]
    # -Oq output: "<oid> <value>"; the value may contain spaces (string)
    parts = line.split(None, 1)
    return parts[1].strip().strip('"') if len(parts) == 2 else ""


def _walk(cli, oid, comm):
    """walk a subtree, returning a {suffix: value} dict (suffix = OID with the walked prefix removed)."""
    r = _snmp(cli, "snmpwalk", oid, comm, timeout=30)
    if not _exposed(r):
        return None
    out = {}
    base = "." + oid.lstrip(".")
    for line in r.out.splitlines():
        line = line.strip()
        if not line or "No Such" in line or "No more" in line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        full, val = parts[0], parts[1].strip().strip('"')
        if full.startswith(base + "."):
            out[full[len(base) + 1:]] = val
        elif full == base:
            out[""] = val
    return out


def _int(s):
    m = re.search(r"-?\d+", s or "")
    return int(m.group()) if m else None


def _timeticks(s):
    """Convert the -Oq sysUpTime value (`d:h:m:s.cs` or plain number) to total centiseconds, to compare growth."""
    if s is None:
        return None
    s = s.strip()
    if re.fullmatch(r"\d+", s):
        return int(s)
    m = re.fullmatch(r"(?:(\d+):)?(\d+):(\d+):(\d+)(?:\.(\d+))?", s)
    if not m:
        return _int(s)
    d, h, mi, sec, cs = m.groups()
    total = ((int(d or 0) * 24 + int(h)) * 60 + int(mi)) * 60 + int(sec)
    return total * 100 + int(cs or 0)


# ---------------------------------------------------------------------------
# Pick a real port (CONFIG_DB PORT), returning (port_name, hash, ifindex, alias)
# ---------------------------------------------------------------------------
_IFIDX_MODE = []   # ["cfg_index+2"] or ["ethnum+1"], probed once per process


def _ifindex_of(cli, name, cfg):
    """**Probe-based** derivation of port -> ifIndex (cached per process).

    The two agent classes map differently, and a fixed offset would read the whole row wrong
    (cascading false failures in content comparison):
      - one agent class: ifIndex = CONFIG_DB PORT.index + 2 (index 25 -> 27)
      - another class: ifIndex = the N of EthernetN + 1 (Ethernet4 -> 5, with its own ifDescr naming)
    Probe: fetch ifDescr under both assumptions for this port; use whichever returns a value
    (and, for the first class, equals alias)."""
    import re as _re
    m = _re.search(r"(\d+)$", name)
    ethnum = int(m.group(1)) if m else None
    cand = [("cfg_index+2", int(cfg["index"]) + IFINDEX_FROM_PORT_INDEX)]
    if ethnum is not None:
        cand.append(("ethnum+1", ethnum + 1))
    if _IFIDX_MODE:
        mode = _IFIDX_MODE[0]
        return dict(cand).get(mode, cand[0][1])
    comm = _community(cli)
    if comm:
        alias = cfg.get("alias", "")
        for mode, idx in cand:
            descr = _scalar(cli, f"1.3.6.1.2.1.2.2.1.2.{idx}", comm)
            if descr is None:
                continue
            # first agent class: ifDescr == alias -> locked on hit; the other: own naming, any value is fine
            if (alias and descr == alias) or mode == "ethnum+1":
                _IFIDX_MODE.append(mode)
                return idx
        # both returned but neither matches alias -> conservatively use the first (matches old behavior)
    _IFIDX_MODE.append("cfg_index+2")
    return cand[0][1]


def _pick_port(cli, topo=None):
    """Prefer the topo-allocated port; if it has no CONFIG_DB record, fall back to any PORT. Returns dict or None."""
    candidates = []
    if topo is not None:
        try:
            candidates.append(topo.port_name("a"))
        except Exception:  # noqa: BLE001
            pass
    for k in cli.db_keys("CONFIG_DB", "PORT|*"):
        candidates.append(k.split("|", 1)[1])
    seen = set()
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        h = cli.db_hgetall("CONFIG_DB", f"PORT|{name}")
        if h and h.get("index") is not None:
            return {
                "name": name,
                "cfg": h,
                "ifindex": _ifindex_of(cli, name, h),
                "alias": h.get("alias", ""),
            }
    return None


# ===========================================================================
# SNMPv2-MIB scalars: value vs DB / system
# ===========================================================================
def test_snmpv2_sysDescr_contains_hwsku_kernel(cli):
    """sysDescr should contain HwSku / Kernel / version substrings (vs CONFIG_DB hwsku + uname -r)."""
    comm = _require_snmp(cli)
    descr = _scalar(cli, "1.3.6.1.2.1.1.1.0", comm)
    assert descr, "sysDescr returned no value"
    hwsku = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hwsku")
    kernel = cli.sh.run("uname -r", check=False).out.strip()
    assert "SONiC" in descr, f"sysDescr missing SONiC marker: {descr!r}"
    if hwsku:
        assert hwsku in descr, f"sysDescr hwsku mismatch: want {hwsku!r} in {descr!r}"
    if kernel:
        assert kernel in descr, f"sysDescr kernel mismatch: want {kernel!r} in {descr!r}"


def test_snmpv2_sysName_vs_hostname(cli):
    """sysName should equal hostname (CONFIG_DB DEVICE_METADATA.hostname / `hostname`)."""
    comm = _require_snmp(cli)
    name = _scalar(cli, "1.3.6.1.2.1.1.5.0", comm)
    assert name, "sysName returned no value"
    db_host = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hostname")
    sys_host = cli.sh.run("hostname", check=False).out.strip()
    expect = db_host or sys_host
    assert name == expect, f"sysName {name!r} != hostname {expect!r}"


# sysObjectId expected prefix: iso.org.dod.internet.private.enterprises = 1.3.6.1.4.1.<PEN>
_ENTERPRISE_PREFIX = "1.3.6.1.4.1."
# Enterprise numbers (PENs) known to be used by SONiC as sysObjectId:
#   8072  = net-snmp (SONiC default sysObjectId = netSnmpAgentOIDs.10 = .1.3.6.1.4.1.8072.3.2.10)
#   40310 = Cumulus Networks (legacy images)
#   311   = Microsoft (SONiC upstream owner)
_KNOWN_ENTERPRISES = {"8072", "40310", "311"}


def test_snmpv2_sysObjectId_is_oid(cli):
    """sysObjectId should be an OID under the enterprises subtree, compared against known
    SONiC/net-snmp enterprise-number prefixes, not just regex-checked as "a dotted OID"."""
    comm = _require_snmp(cli)
    oid = _scalar(cli, "1.3.6.1.2.1.1.2.0", comm)
    assert oid, "sysObjectId returned no value"
    norm = oid.strip().lstrip(".")
    # 1) still must be a dotted numeric OID
    assert re.match(r"(\d+\.){3,}\d+$", norm), f"sysObjectId not a numeric OID: {oid!r}"
    # 2) must fall under the enterprises (1.3.6.1.4.1.) subtree
    assert norm.startswith(_ENTERPRISE_PREFIX), \
        f"sysObjectId not under enterprises subtree {_ENTERPRISE_PREFIX!r}: {oid!r}"
    # 3) the enterprise number (PEN) should be a known SONiC/net-snmp/Cumulus value
    arc = norm[len(_ENTERPRISE_PREFIX):].split(".")[0]
    assert arc in _KNOWN_ENTERPRISES, \
        f"sysObjectId enterprise {arc} not a known SONiC/net-snmp/Cumulus PEN: {oid!r}"
    # 4) for net-snmp default it should also exactly equal netSnmpAgentOIDs.10 (SONiC default)
    if arc == "8072":
        assert norm == "1.3.6.1.4.1.8072.3.2.10", \
            f"net-snmp sysObjectId unexpected (want .1.3.6.1.4.1.8072.3.2.10): {oid!r}"


def test_snmpv2_sysUpTime_positive_and_grows(cli):
    """sysUpTime should be a positive TimeTicks and grow monotonically between two samples (proving the agent is really running)."""
    import time
    comm = _require_snmp(cli)
    t1 = _scalar(cli, "1.3.6.1.2.1.1.3.0", comm)
    assert t1 is not None, "sysUpTime returned no value"
    v1 = _timeticks(t1)
    assert v1 and v1 > 0, f"sysUpTime not positive: {t1!r}"
    time.sleep(2)
    v2 = _timeticks(_scalar(cli, "1.3.6.1.2.1.1.3.0", comm))
    assert v2 >= v1, f"sysUpTime did not grow: {v1} -> {v2}"


def test_snmpv2_sysContact_and_sysLocation_present(cli):
    """sysContact / sysLocation should have values (SONiC defaults injected by snmp.yml; vs CONFIG_DB if configured)."""
    comm = _require_snmp(cli)
    contact = _scalar(cli, "1.3.6.1.2.1.1.4.0", comm)
    location = _scalar(cli, "1.3.6.1.2.1.1.6.0", comm)
    # A: sysContact/sysLocation should be exposed; neither being exposed is a device defect
    assert not (contact is None and location is None), \
        "DEVICE DEFECT: sysContact/sysLocation not exposed on this image"
    # If CONFIG_DB configured SNMP|CONTACT/LOCATION, they should match exactly
    snmp_cfg = cli.db_hgetall("CONFIG_DB", "SNMP|localhost") or {}
    if snmp_cfg.get("sysContact"):
        assert contact == snmp_cfg["sysContact"], \
            f"sysContact {contact!r} != CONFIG_DB {snmp_cfg['sysContact']!r}"
    if snmp_cfg.get("sysLocation"):
        assert location == snmp_cfg["sysLocation"], \
            f"sysLocation {location!r} != CONFIG_DB {snmp_cfg['sysLocation']!r}"
    # When CONFIG_DB is unset, no longer just check non-empty: **exact compare** against the value rendered in the snmp container's snmpd.conf.
    conf = cli.sh.run("cat /etc/snmp/snmpd.conf 2>/dev/null",
                      container=SNMP_CONTAINER, check=False).out
    if not snmp_cfg.get("sysContact") and contact is not None:
        m = re.search(r"(?im)^\s*sysContact\s+(.+?)\s*$", conf)
        if m:
            assert contact == m.group(1).strip(), \
                f"sysContact {contact!r} != snmpd.conf {m.group(1).strip()!r}"
    if not snmp_cfg.get("sysLocation") and location is not None:
        m = re.search(r"(?im)^\s*sysLocation\s+(.+?)\s*$", conf)
        if m:
            assert location == m.group(1).strip(), \
                f"sysLocation {location!r} != snmpd.conf {m.group(1).strip()!r}"
    assert (contact or "") != "" or (location or "") != "", \
        "both sysContact and sysLocation empty"


# ===========================================================================
# IF-MIB ifTable / ifNumber: value vs CONFIG_DB PORT / STATE_DB PORT_TABLE
# ===========================================================================
def test_ifmib_ifNumber_matches_port_count(cli):
    """ifNumber should **exactly equal** the real IF-MIB ifTable entry count (walk ifDescr and
    count), and be >= the CONFIG_DB physical port count (including mgmt/internal ports, so
    against the port count only >= holds)."""
    comm = _require_snmp(cli)
    n = _int(_scalar(cli, "1.3.6.1.2.1.2.1.0", comm))
    assert n is not None and n > 0, "ifNumber not positive"
    nports = len(cli.db_keys("CONFIG_DB", "PORT|*"))
    assert n >= nports, f"ifNumber {n} < CONFIG_DB PORT count {nports}"
    # Exact: ifNumber must equal the actual ifTable entry count (RFC1213: ifNumber = ifTable row count).
    descrs = _walk(cli, "1.3.6.1.2.1.2.2.1.2", comm)  # ifDescr subtree
    # A: ifTable(ifDescr) should be walkable; missing is a device defect
    assert descrs is not None, \
        "DEVICE DEFECT: ifTable (ifDescr) not walkable to validate ifNumber exactly"
    assert n == len(descrs), \
        f"ifNumber {n} != actual ifTable entry count {len(descrs)}"


def test_ifmib_ifDescr_vs_config_alias(cli, topo):
    """ifDescr[ifIndex] should equal the port's CONFIG_DB alias (SONiC uses alias as ifDescr/ifName)."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT mappable to an ifIndex
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT to map ifIndex"
    descr = _scalar(cli, f"1.3.6.1.2.1.2.2.1.2.{p['ifindex']}", comm)
    # A: this port's ifDescr should be exposed
    assert descr is not None, f"DEVICE DEFECT: ifDescr for ifIndex {p['ifindex']} not exposed"
    assert descr == p["alias"], \
        f"{p['name']}: ifDescr {descr!r} != CONFIG_DB alias {p['alias']!r}"


def test_ifmib_ifMtu_vs_db(cli, topo):
    """ifMtu[ifIndex] should equal the STATE_DB (preferred) or CONFIG_DB mtu (default 9100)."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    snmp_mtu = _int(_scalar(cli, f"1.3.6.1.2.1.2.2.1.4.{p['ifindex']}", comm))
    # A: this port's ifMtu should be exposed
    assert snmp_mtu is not None, f"DEVICE DEFECT: ifMtu for ifIndex {p['ifindex']} not exposed"
    state = cli.db_hgetall("STATE_DB", f"PORT_TABLE|{p['name']}")
    db_mtu = _int(state.get("mtu") or p["cfg"].get("mtu") or "9100")
    assert snmp_mtu == db_mtu, f"{p['name']}: ifMtu {snmp_mtu} != DB mtu {db_mtu}"


def test_ifmib_ifAdminStatus_vs_db(cli, topo):
    """ifAdminStatus[ifIndex] (1=up,2=down) should match CONFIG_DB admin_status."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    val = _int(_scalar(cli, f"1.3.6.1.2.1.2.2.1.7.{p['ifindex']}", comm))
    # A: this port's ifAdminStatus should be exposed
    assert val is not None, f"DEVICE DEFECT: ifAdminStatus for ifIndex {p['ifindex']} not exposed"
    db_admin = (cli.db_hgetall("STATE_DB", f"PORT_TABLE|{p['name']}").get("admin_status")
                or p["cfg"].get("admin_status") or "down")
    want = 1 if db_admin == "up" else 2
    assert val == want, \
        f"{p['name']}: ifAdminStatus {val} != expected {want} (db admin_status={db_admin})"


def test_ifmib_ifOperStatus_vs_state_db(cli, topo):
    """ifOperStatus[ifIndex] (1=up,2=down) should match STATE_DB oper (netdev_oper_status/oper_status)."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    state = cli.db_hgetall("STATE_DB", f"PORT_TABLE|{p['name']}")
    db_oper = state.get("netdev_oper_status") or state.get("oper_status")
    # A: a real device's STATE_DB should have this port's oper status
    assert db_oper, f"DEVICE DEFECT: STATE_DB PORT_TABLE|{p['name']} has no oper status"
    val = _int(_scalar(cli, f"1.3.6.1.2.1.2.2.1.8.{p['ifindex']}", comm))
    # A: this port's ifOperStatus should be exposed
    assert val is not None, f"DEVICE DEFECT: ifOperStatus for ifIndex {p['ifindex']} not exposed"
    want = 1 if db_oper == "up" else 2
    assert val == want, \
        f"{p['name']}: ifOperStatus {val} != expected {want} (STATE_DB oper={db_oper})"


def test_ifmib_ifSpeed_consistent_with_highspeed(cli, topo):
    """ifSpeed(bps, saturable) and ifHighSpeed(Mbps) should be self-consistent: when not saturated, ifSpeed == ifHighSpeed*1e6."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    lo = _int(_scalar(cli, f"1.3.6.1.2.1.2.2.1.5.{p['ifindex']}", comm))
    hi = _int(_scalar(cli, f"1.3.6.1.2.1.31.1.1.1.15.{p['ifindex']}", comm))
    # A: ifSpeed/ifHighSpeed should be exposed
    assert lo is not None and hi is not None, "DEVICE DEFECT: ifSpeed/ifHighSpeed not exposed"
    SAT = 4294967295  # ifSpeed ceiling (saturates above 4.29Gbps); at/above this, do not compare the low value
    if lo < SAT:
        assert lo == hi * 1_000_000, f"ifSpeed {lo} != ifHighSpeed {hi}*1e6"


# ===========================================================================
# IF-MIB ifXTable: ifHighSpeed vs CONFIG_DB speed, ifAlias, ifHCInOctets
# ===========================================================================
def test_ifxtable_ifHighSpeed_vs_config_speed(cli, topo):
    """ifHighSpeed(Mbps) should equal CONFIG_DB speed(Kbps)/1000."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    hi = _int(_scalar(cli, f"1.3.6.1.2.1.31.1.1.1.15.{p['ifindex']}", comm))
    # A: this port's ifHighSpeed should be exposed
    assert hi is not None, f"DEVICE DEFECT: ifHighSpeed for ifIndex {p['ifindex']} not exposed"
    db_speed_mbps = _int(p["cfg"].get("speed"))   # SONiC CONFIG_DB PORT speed is in Mbps
    # A: a real device's CONFIG_DB PORT should have speed
    assert db_speed_mbps, f"DEVICE DEFECT: {p['name']} has no CONFIG_DB speed"
    assert hi == db_speed_mbps, \
        f"{p['name']}: ifHighSpeed {hi}Mbps != CONFIG_DB speed {db_speed_mbps}Mbps"


def test_ifxtable_ifName_vs_config_alias(cli, topo):
    """ifName[ifIndex] should equal CONFIG_DB alias (same source as ifDescr)."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    name = _scalar(cli, f"1.3.6.1.2.1.31.1.1.1.1.{p['ifindex']}", comm)
    # A: this port's ifName should be exposed
    assert name is not None, f"DEVICE DEFECT: ifName for ifIndex {p['ifindex']} not exposed"
    if _IFIDX_MODE and _IFIDX_MODE[0] == "ethnum+1":
        # This agent class's ifName uses its own naming with no correspondence to the SONiC
        # alias (a by-design naming difference, not a defect) -- no CONFIG_DB ground truth to
        # compare, so skip honestly.
        pytest.skip(f"custom snmpagent uses its own interface naming ({name!r}); "
                    "no CONFIG_DB alias ground truth to compare")
    assert name == p["alias"], \
        f"{p['name']}: ifName {name!r} != CONFIG_DB alias {p['alias']!r}"


def test_ifxtable_ifAlias_vs_config_description(cli, topo):
    """ifAlias[ifIndex] should equal CONFIG_DB PORT.description; empty here when no description is configured -> skip."""
    comm = _require_snmp(cli)
    p = _pick_port(cli, topo)
    # A: a real device should have a CONFIG_DB PORT
    assert p, "DEVICE DEFECT: no usable CONFIG_DB PORT"
    alias = _scalar(cli, f"1.3.6.1.2.1.31.1.1.1.18.{p['ifindex']}", comm)
    desc = p["cfg"].get("description", "")
    if alias is None and not desc:
        # Some snmpagents do not expose ifAlias(.18) at all for ports with **no description
        # configured** (others expose an empty string) -- no ground truth to compare, and the
        # missing column is by-design, consistent with this file's other "OID not exposed on
        # this image -> skip" convention. A configured description that is still not exposed
        # remains a defect fail.
        pytest.skip("ifAlias(.18) not exposed on this older snmpagent and no PORT.description "
                    "configured to compare against")
    assert alias is not None, f"DEVICE DEFECT: ifAlias for ifIndex {p['ifindex']} not exposed " \
                              f"despite configured description {desc!r}"
    # D: when no description is configured both sides are empty strings, so a direct compare passes (by-design, not a defect); the original skip guard is removed
    assert alias == desc, f"{p['name']}: ifAlias {alias!r} != CONFIG_DB description {desc!r}"


@pytest.mark.traffic
def test_ifxtable_ifHCInOctets_is_counter(cli, traffic, topo):
    """ifHCInOctets[ifIndex] should grow with **real traffic** (a Counter64 high-capacity byte counter really being sampled, not just checked non-negative).

    Take the already-looped-back ports[0], derive its ifIndex from its CONFIG_DB index; read a
    baseline, then inject N known-unicast frames (dst static FDB points at ports[1], so
    re-ingressing frames forward deterministically and do not storm), with the chip RX delta
    corroborating that traffic reached hardware, then poll for ifHCInOctets increment > 0. If an
    oper-down loopback port is not sampled by the flex counter and the SNMP byte count does not
    advance, handle it honestly (never just check non-negative)."""
    # Test dependency: FAIL if scapy is unavailable (not a device defect, purely a test-environment dependency)
    assert _SCAPY, "scapy unavailable (dry-run/build host)"
    comm = _require_snmp(cli)
    port = traffic.ports[0]
    cfg = cli.db_hgetall("CONFIG_DB", f"PORT|{port.name}")
    # A: a real device's CONFIG_DB should have this port's index for ifIndex mapping
    assert cfg.get("index"), f"DEVICE DEFECT: no CONFIG_DB index for {port.name} to map ifIndex"
    ifindex = _ifindex_of(cli, port.name, cfg)   # probe-based mapping (the two agent classes offset differently)
    oid = f"1.3.6.1.2.1.31.1.1.1.6.{ifindex}"
    v0 = _int(_scalar(cli, oid, comm))
    # A: this port's ifHCInOctets should be exposed
    assert v0 is not None, f"DEVICE DEFECT: ifHCInOctets for ifIndex {ifindex} not exposed"

    cli.fdb_static_add(traffic.default_vlan, _HC_DST, traffic.ports[1].name)
    try:
        cbase = traffic.chip_counters(port)
        pkt = (Ether(dst=_HC_DST, src="00:de:ad:be:ef:55") /
               IP(dst="9.9.9.55") / UDP() / Raw(b"HCIN" + b"x" * 100))
        traffic.send(port, pkt, count=_TRAFFIC_N)
        time.sleep(1.0)
        chip_rx = (traffic.chip_counters(port) - cbase).rx_pkt
        assert chip_rx >= _TRAFFIC_N * 0.9, (
            f"traffic did not reach chip on {port.name}: chip RX +{chip_rx}, sent {_TRAFFIC_N}")
        # Quantitative attribution: frame length is fixed, so the SNMP-side increment must be
        # of the same magnitude as the injected traffic -- merely delta>0 could be satisfied by
        # kernel noise (IPv6 ND multicast) on a same-VLAN loopback port and could not be
        # attributed to this flow; under a storm delta is MB-scale, so the upper bound is sealed
        # too (chip_rx corroboration + byte-count lower/upper bounds together prove the flex
        # counter sampled this specific flow).
        frame_len = len(pkt) + 4                       # on-the-wire bytes (including FCS)
        lower = int(_TRAFFIC_N * frame_len * 0.9)
        upper = _TRAFFIC_N * frame_len * 10 + 65536
        delta = 0
        # Polling window 25s: the snmp-subagent counter refresh period is ~18s (COUNTERS_DB is
        # in place within 3s); the window must cover that refresh period or it would false-FAIL.
        for _ in range(25):
            time.sleep(1)
            v = _int(_scalar(cli, oid, comm))
            if v is not None:
                delta = v - v0
            if delta >= lower:
                break
        # A: the chip received traffic but the SNMP byte count is short -> device defect
        #    (an oper-down loopback port not sampled by the flex counter)
        assert delta >= lower, (
            f"DEVICE DEFECT: ifHCInOctets advanced only +{delta}B on {port.name} "
            f"(ifIndex {ifindex}), expected >= {lower}B for {_TRAFFIC_N} x {frame_len}B frames "
            f"despite chip RX +{chip_rx}: flex counter not sampling this flow")
        assert delta <= upper, (
            f"ifHCInOctets advanced +{delta}B >> injected {_TRAFFIC_N * frame_len}B "
            f"(upper bound {upper}B): runaway/storm bytes on {port.name}; "
            "delta cannot be attributed to the test flow")
    finally:
        cli.fdb_static_del(traffic.default_vlan, _HC_DST)


# ===========================================================================
# UCD-SNMP memory (1.3.6.1.4.1.2021.4): value vs /proc/meminfo (with tolerance)
# ===========================================================================
def _meminfo(cli):
    out = cli.sh.run("cat /proc/meminfo", check=False).out
    d = {}
    for line in out.splitlines():
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            d[m.group(1)] = int(m.group(2))
    return d


def _mem_close(snmp_kb, sys_kb):
    tol = max(MEM_TOL_ABS_KB, int(sys_kb * MEM_TOL_FRAC))
    return abs(snmp_kb - sys_kb) <= tol


@pytest.mark.parametrize("name,oid,meminfo_key,exact", [
    ("TotalMem", "1.3.6.1.4.1.2021.4.5.0", "MemTotal", True),
    ("FreeMem", "1.3.6.1.4.1.2021.4.6.0", "MemFree", False),
    ("BuffMem", "1.3.6.1.4.1.2021.4.14.0", "Buffers", False),
    ("TotalSwap", "1.3.6.1.4.1.2021.4.3.0", "SwapTotal", True),
    ("FreeSwap", "1.3.6.1.4.1.2021.4.4.0", "SwapFree", True),
], ids=lambda v: v if isinstance(v, str) else "")
def test_ucd_memory_vs_meminfo(cli, name, oid, meminfo_key, exact):
    """UCD memory counts(kB) vs /proc/meminfo: Total/Swap exact, Free/Buff with tolerance (sampling drift)."""
    comm = _require_snmp(cli)
    snmp_kb = _int(_scalar(cli, oid, comm))
    # A: the UCD memory MIB should be exposed; not exposed is a device defect
    assert snmp_kb is not None, f"DEVICE DEFECT: UCD {name} ({oid}) not exposed on this image"
    mem = _meminfo(cli)
    sys_kb = mem.get(meminfo_key)
    # A: /proc/meminfo should have this field (standard kernel item); missing is a data defect
    assert sys_kb is not None, f"DEVICE DEFECT: /proc/meminfo has no {meminfo_key}"
    if exact:
        assert snmp_kb == sys_kb, f"UCD {name} {snmp_kb}kB != /proc/meminfo {meminfo_key} {sys_kb}kB"
    else:
        assert _mem_close(snmp_kb, sys_kb), \
            f"UCD {name} {snmp_kb}kB not within tol of {meminfo_key} {sys_kb}kB"


# ===========================================================================
# IP-FORWARD ipCidrRoute (1.3.6.1.2.1.4.24.4.1): default route vs FRR (validate only if a default route exists)
# ===========================================================================
def test_ipforward_default_route(cli):
    """The ipCidrRouteStatus subtree should contain the default route 0.0.0.0; skip if this image does not expose the MIB."""
    comm = _require_snmp(cli)
    # First confirm FRR/kernel actually has a default route, otherwise there is nothing to compare
    has_def = "0.0.0.0/0" in cli.sh.run("vtysh -c 'show ip route 0.0.0.0/0'",
                                        check=False).out or \
        "default" in cli.sh.run("ip route show default", check=False).out
    walk = _walk(cli, "1.3.6.1.2.1.4.24.4.1.16", comm)  # ipCidrRouteStatus
    # Optional MIB: ipCidrRoute (IP-FORWARD-MIB) is not exposed on this image (the mgmt/eth0
    # default route is not tracked by sonic_ax_impl), nothing to compare -> skip (not an SNMP defect).
    if not walk:
        pytest.skip("ipCidrRoute (IP-FORWARD-MIB) not exposed on this image; nothing to compare")
    # No default route means nothing to compare
    if not has_def:
        pytest.skip("no default route present to validate ipCidrRoute")
    # A suffix starting with 0.0.0.0 is the default route
    assert any(suf.startswith("0.0.0.0") for suf in walk), \
        f"ipCidrRoute has no 0.0.0.0 default entry: {list(walk)[:5]}"


# ===========================================================================
# ENTITY-MIB (1.3.6.1.2.1.47): chassis entity vs platform
# ===========================================================================
def test_entity_chassis_present(cli):
    """The entPhysicalClass subtree should contain chassis(=3), and entPhysicalName.1 should contain 'chassis'."""
    comm = _require_snmp(cli)
    classes = _walk(cli, "1.3.6.1.2.1.47.1.1.1.1.5", comm)  # entPhysicalClass
    # A: ENTITY-MIB entPhysicalClass should be exposed; not exposed is a device defect
    assert classes, "DEVICE DEFECT: ENTITY-MIB entPhysicalClass not exposed"
    vals = [_int(v) for v in classes.values()]
    assert 3 in vals, f"entPhysicalClass has no chassis(3): {classes}"
    name1 = _scalar(cli, "1.3.6.1.2.1.47.1.1.1.1.7.1", comm)
    if name1 is not None:
        assert "chassis" in name1.lower(), f"entPhysicalName.1 not chassis: {name1!r}"


def test_entity_serial_matches_db(cli):
    """If STATE_DB has a platform EEPROM serial, entPhysicalSerialNum should match; skip if there is no real serial."""
    comm = _require_snmp(cli)
    serial = _scalar(cli, "1.3.6.1.2.1.47.1.1.1.1.11.1", comm)  # chassis serial
    # STATE_DB EEPROM_INFO (if present) records the serial
    eeprom = cli.db_keys("STATE_DB", "EEPROM_INFO|*")
    # Optional/no platform data: OID returns N/A and there is no EEPROM_INFO ground truth to
    # compare -> skip (missing platform sensor/EEPROM data is itself a REAL defect, already
    # covered by test_platform_sensors; do not re-judge the defect here).
    if serial is None or serial in ("", "N/A") or not eeprom:
        pytest.skip("no platform EEPROM serial (entPhysicalSerialNum N/A or no STATE_DB EEPROM_INFO)")
    db_blob = " ".join(cli.sh.run(f"sonic-db-cli STATE_DB HGETALL '{k}'", check=False).out
                       for k in eeprom)
    assert serial in db_blob, f"entPhysicalSerialNum {serial!r} not found in STATE_DB EEPROM_INFO"


# ===========================================================================
# ENTITY-SENSOR (1.3.6.1.2.1.99) / CISCO-FRU PSU: validate only with real platform sensor/PSU data, else skip
# ===========================================================================
# The entPhySensorType enum value denoting temperature (RFC 3433 EntitySensorDataType: celsius(8)).
_ENTPHY_CELSIUS = 8
# SNMP and STATE_DB temperatures drift across sampling instants, so allow a 5C tolerance.
_SENSOR_TOL_C = 5.0


def test_entity_sensor_values_vs_state_db(cli):
    """entPhySensorValue (scaled to actual temperature by Scale/Precision) should match some
    temperature in STATE_DB TEMPERATURE_INFO within tolerance -- not just checking both sides
    non-empty, but that at least one temperature sensor reading lines up with the DB ground
    truth. Skip if this image has no entPhySensor MIB.

    Scaling formula (RFC 3433): actual = raw * 10^((scale-9)*3) / 10^precision, where scale is
    the EntitySensorDataScale enum (units(9)=10^0, each +/-1 corresponds to a +/-3 power of 10)."""
    comm = _require_snmp(cli)
    values = _walk(cli, "1.3.6.1.2.1.99.1.1.1.4", comm)  # entPhySensorValue
    temp_keys = cli.db_keys("STATE_DB", "TEMPERATURE_INFO|*")
    # Optional/no platform data: entPhySensor MIB not exposed, or no STATE_DB TEMPERATURE_INFO
    # ground truth to compare -> skip (missing platform sensors is itself a REAL defect, already
    # covered by test_platform_sensors; do not re-judge the defect here).
    if not values or not temp_keys:
        pytest.skip("no platform sensors (entPhySensor MIB not exposed or no STATE_DB TEMPERATURE_INFO)")
    types = _walk(cli, "1.3.6.1.2.1.99.1.1.1.1", comm) or {}   # entPhySensorType
    scales = _walk(cli, "1.3.6.1.2.1.99.1.1.1.2", comm) or {}  # entPhySensorScale
    precs = _walk(cli, "1.3.6.1.2.1.99.1.1.1.3", comm) or {}   # entPhySensorPrecision
    db_temps = []
    for k in temp_keys:
        t = cli.db_hgetall("STATE_DB", k).get("temperature")
        if t:
            try:
                db_temps.append(float(t))
            except ValueError:
                pass
    # A: STATE_DB TEMPERATURE_INFO should contain a numeric temperature field
    assert db_temps, "DEVICE DEFECT: STATE_DB TEMPERATURE_INFO has no numeric temperature field"

    # Take celsius-type sensors and scale the raw integer to actual degrees Celsius by Scale/Precision
    scaled = []
    for idx, raw in values.items():
        v = _int(raw)
        if v is None:
            continue
        stype = _int(types.get(idx, ""))
        if stype is not None and stype != _ENTPHY_CELSIUS:
            # Known type but not temperature (voltage/fan RPM etc.) -> skip, to avoid comparing it as a temperature
            continue
        scale = _int(scales.get(idx, "9"))
        prec = _int(precs.get(idx, "0"))
        exp = ((scale if scale is not None else 9) - 9) * 3 - (prec if prec is not None else 0)
        scaled.append(v * (10.0 ** exp))
    # A: the platform should have celsius sensor entries to compare against STATE_DB
    assert scaled, "DEVICE DEFECT: no celsius entPhySensor entries to compare with STATE_DB temperatures"

    # At least one SNMP temperature reading matches some STATE_DB temperature within tolerance (ground-truth compare, not just non-empty)
    ok = any(abs(s - d) <= _SENSOR_TOL_C for s in scaled for d in db_temps)
    assert ok, (
        f"no entPhySensor temperature matches STATE_DB within {_SENSOR_TOL_C}C: "
        f"snmp(scaled)={[round(s, 2) for s in scaled]}, state_db={db_temps}")


def test_cisco_fru_psu_status_vs_state_db(cli):
    """cefcFRUPowerOperStatus should reflect STATE_DB PSU_INFO: not only PSU **count** matching,
    but the number of PSUs SNMP reports as on(2) should equal the number of PSUs in STATE_DB
    that are powered normally (status/presence). Skip if there is no PSU platform data."""
    comm = _require_snmp(cli)
    psu = _walk(cli, "1.3.6.1.4.1.9.9.117.1.1.2.1.2", comm)  # cefcFRUPowerOperStatus
    psu_keys = cli.db_keys("STATE_DB", "PSU_INFO|*")
    # Optional/no platform data: cefcFRUPowerOperStatus not exposed, or no STATE_DB PSU_INFO
    # ground truth to compare -> skip (missing PSU platform data is itself a REAL defect, already
    # covered by test_platform_sensors; do not re-judge the defect here).
    if not psu or not psu_keys:
        pytest.skip("no PSU platform data (cefcFRUPowerOperStatus not exposed or no STATE_DB PSU_INFO)")
    # The SNMP PSU entry count should match the STATE_DB PSU count
    assert len(psu) == len(psu_keys), \
        f"cefcFRUPower PSU count {len(psu)} != STATE_DB PSU_INFO count {len(psu_keys)}"
    # Status compare: count of PSUs present and powered-normal in STATE_DB == count of SNMP cefcFRUPowerOperStatusOn(2).
    _TRUE = ("true", "1", "ok", "on", "yes")
    db_on = 0
    for k in psu_keys:
        h = cli.db_hgetall("STATE_DB", k)
        st = (h.get("status") or "").strip().lower()
        pres = (h.get("presence") or "").strip().lower()
        # the presence field may be absent (some platforms do not report it) -> treat as present; status indicates whether power is normal
        present = pres in _TRUE or pres == ""
        powered = st in _TRUE
        if present and powered:
            db_on += 1
    snmp_on = sum(1 for v in psu.values() if _int(v) == 2)  # cefcFRUPowerOperStatusOn = 2
    assert snmp_on == db_on, (
        f"cefcFRUPowerOperStatus 'on'(2) count {snmp_on} != STATE_DB powered PSU count {db_on} "
        f"(snmp={dict(psu)})")


# ===========================================================================
# LLDP-MIB Local: locChassisId vs DEVICE_METADATA mac
# ===========================================================================
def test_lldp_locChassisId_vs_device_mac(cli):
    """lldpLocChassisId should be a stable, unique MAC on the device (chassis-id subtype=mac).

    Correction: lldpd defaults to using the mgmt port eth0 MAC as ChassisID (SONiC does not
    explicitly configure chassisid); on most platforms eth0 MAC == base MAC, so the historical
    assert "== DEVICE_METADATA.mac" passed. The two need not be equal -- ChassisID only needs to
    be one real, stable MAC of this device. Accept either the eth0 MAC or the base MAC."""
    comm = _require_snmp(cli)
    chassis = _scalar(cli, "1.0.8802.1.1.2.1.3.2.0", comm)
    # A: LLDP-MIB lldpLocChassisId should be exposed
    assert chassis is not None, "DEVICE DEFECT: LLDP-MIB lldpLocChassisId not exposed"
    # net-snmp may render it as 'aa bb cc..' (space-hex), 'aa:bb:..' (colons) or 'aa-bb-..'
    # (hyphens) -- collapse all to bare hex before comparing.
    norm = lambda s: "".join(c for c in s.lower() if c in "0123456789abcdef")
    db_mac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac", "")
    eth0 = cli.sh.run("ip link show eth0", check=False).out or ""
    import re as _re
    m = _re.search(r"link/ether\s+([0-9a-fA-F:]+)", eth0)
    mgmt_mac = m.group(1) if m else ""
    valid = {norm(x) for x in (mgmt_mac, db_mac) if x}
    assert valid, "DEVICE DEFECT: no eth0/DEVICE_METADATA mac to compare lldpLocChassisId"
    assert norm(chassis) in valid, \
        f"lldpLocChassisId {chassis!r} matches neither eth0 mgmt MAC {mgmt_mac!r} nor base MAC {db_mac!r}"


def test_lldp_locSysName_vs_hostname(cli):
    """lldpLocSysName should equal hostname."""
    comm = _require_snmp(cli)
    name = _scalar(cli, "1.0.8802.1.1.2.1.3.3.0", comm)
    # A: LLDP-MIB lldpLocSysName should be exposed
    assert name is not None, "DEVICE DEFECT: LLDP-MIB lldpLocSysName not exposed"
    db_host = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("hostname") \
        or cli.sh.run("hostname", check=False).out.strip()
    assert name == db_host, f"lldpLocSysName {name!r} != hostname {db_host!r}"
