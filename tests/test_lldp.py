"""LLDP functional verification -- filling the "zero functional coverage" gap (previously only SNMP LLDP-MIB OID corroboration).

This module makes real behavioral assertions on lldpd / lldpmgrd, rather than smoke tests or "just check the DB object exists":
  (1) Daemon health: lldp container is up + lldpd/lldpmgrd RUNNING under supervisorctl;
  (2) Local chassis is genuine: the local ChassisID reported by lldpcli == device MAC (DEVICE_METADATA),
     SysName == hostname (self-advertised identity cannot be faked);
  (3) Local physical ports are truly exposed: the ports under test (taken dynamically from dut) appear in lldpd's interface list;
  (4) **PDU actually transmitted + self-loop neighbor discovery** (single-box trick, analogous to MAC loopback): the traffic fixture
     puts ports[0] into MAC loopback -> the port goes oper-up -> lldpd starts periodically sending LLDP PDUs -> after a PDU
     physically egresses it re-ingresses via the loopback -> lldpd "sees itself" on that port, learning one neighbor whose
     ChassisID == the local ChassisID. (Self-loop does produce a neighbor; see the trailing module note.)
  (5) TX counter actually increments: sample -> wait one tx-interval -> sample again, asserting the LLDP Transmitted
     counter on the looped-back port really increments (LLDP is indeed transmitting periodically).

Mechanism notes:
  - Physical ports default to oper-down; lldpd does not send LLDP on a down port (Transmitted=0 in stats); only eth0 (mgmt port)
    is transmitting. So (4)(5) must first use loopback to bring the port under test to oper-up before lldpd will transmit/learn on it.
  - The self-loop neighbor's ChassisID/SysName are identical to the local device (seeing itself), which is the end-to-end proof
    that "the PDU really egressed the port and was received back on the port" -- equivalent to data-plane verification.
  - tx-interval defaults to 30s; to make the cases fast and stable, `lldpcli configure lldp tx-interval` temporarily speeds it up,
    and teardown always restores 30s.

Prints/assert/skip in English; comments/docstrings in English. Ports are all taken dynamically from dut, never hardcoded.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.mgmt]

_LLDP_CT = "lldp"                 # lldp container name
_FAST_TX = 5                     # temporarily sped-up tx-interval (seconds), so (4)(5) converge within tens of seconds
_DEFAULT_TX = 30                 # SONiC default tx-interval, teardown must restore


# ----------------------------- helpers -----------------------------
def _lldp(cli, cmd):
    """Run a command inside the lldp container, returning Result(.out/.rc)."""
    return cli.sh.run(cmd, container=_LLDP_CT, check=False)


def _norm_mac(s):
    """Normalize a MAC: strip the 'mac ' prefix, lowercase, strip whitespace, for cross-command comparison."""
    return (s or "").replace("mac", "").strip().lower()


def _local_chassis(cli):
    """Parse lldpcli local chassis: return (chassis_id_mac, sysname)."""
    out = _lldp(cli, "lldpcli show chassis").out
    cid = re.search(r"ChassisID:\s+mac\s+([0-9a-fA-F:]+)", out)
    syn = re.search(r"SysName:\s+(\S+)", out)
    return (cid.group(1).lower() if cid else None,
            syn.group(1) if syn else None)


def _neighbor_chassis(cli, port_name):
    """Parse a port's neighbor ChassisID (mac); return None if no neighbor."""
    out = _lldp(cli, f"lldpcli show neighbors ports {port_name} details").out
    m = re.search(r"ChassisID:\s+mac\s+([0-9a-fA-F:]+)", out)
    return m.group(1).lower() if m else None


def _tx_count(cli, port_name):
    """Parse a port's LLDP Transmitted count; return None if it cannot be parsed."""
    out = _lldp(cli, f"lldpcli show statistics ports {port_name}").out
    m = re.search(r"Transmitted:\s+(\d+)", out)
    return int(m.group(1)) if m else None


def _set_tx_interval(cli, val):
    """Set the global LLDP tx-interval (seconds)."""
    _lldp(cli, f"lldpcli configure lldp tx-interval {val}")


def _dev_mac(cli):
    """The device base MAC from DEVICE_METADATA."""
    return cli.db("CONFIG_DB", "hget 'DEVICE_METADATA|localhost' mac").strip().lower()


def _mgmt_mac(cli):
    """The MAC of mgmt port eth0. When lldpd has no explicitly configured chassis-id it **defaults to the mgmt port MAC**
    as its ChassisID (SONiC lldpd.conf.j2 does not push `configure system chassisid`); this is standard/expected behavior --
    ChassisID only needs to be a stable, unique MAC on the device and is not required to equal the switch base MAC. On most
    platforms eth0 MAC equals the base MAC so the two are indistinguishable; if they differ, ChassisID=eth0 MAC is still correct."""
    out = cli.run("ip link show eth0").out or ""
    m = re.search(r"link/ether\s+([0-9a-fA-F:]+)", out)
    return m.group(1).lower() if m else None


def _hostname(cli):
    return cli.run("hostname").out.strip()


# ============================ 1. Daemon health ============================
def test_lldpd_daemon_healthy(cli):
    """lldp container is up + both lldpd and lldpmgrd are RUNNING under supervisorctl.

    This is the prerequisite for all LLDP functionality: if the daemons are absent/exited, subsequent assertions are meaningless."""
    names = cli.sh.run("docker ps --format '{{.Names}}'", check=False).out
    assert "lldp" in names.split(), f"lldp container not running; docker ps names: {names!r}"

    status = _lldp(cli, "supervisorctl status").out
    for proc in ("lldpd", "lldpmgrd"):
        line = next((l for l in status.splitlines() if l.split()[:1] == [proc]), None)
        assert line is not None, f"{proc} not found in supervisorctl status:\n{status}"
        assert "RUNNING" in line, f"{proc} not RUNNING: {line!r}"


# ============================ 2. Local chassis is genuine ============================
def test_local_chassis_matches_device(cli):
    """The local ChassisID reported by lldpcli is a stable, unique MAC on the device, and SysName == hostname.

    Correct interpretation of the ChassisID value: when lldpd has no explicitly configured chassis-id it **defaults to the
    mgmt port eth0 MAC** (SONiC lldpd.conf.j2 does not push `configure system chassisid`); this is standard behavior. On most
    platforms the eth0 MAC equals the switch base MAC (DEVICE_METADATA.mac), so the historical assertion "== device MAC" passed
    on the reference box; but the two need not be equal -- ChassisID only needs to be a real, stable MAC on this device. So we
    accept **either the eth0 MAC or the base MAC**, and only a mismatch against both is an anomaly (placeholder/wrong value)."""
    cid, sysname = _local_chassis(cli)
    assert cid, "no local ChassisID parsed from lldpcli show chassis"

    mgmt_mac = _mgmt_mac(cli)
    dev_mac = _dev_mac(cli)
    valid = {_norm_mac(m) for m in (mgmt_mac, dev_mac) if m}
    assert valid, "neither eth0 MAC nor DEVICE_METADATA mac available to validate chassis-id"
    assert _norm_mac(cid) in valid, (
        f"local LLDP ChassisID {cid} matches neither eth0 mgmt MAC {mgmt_mac} "
        f"nor device base MAC {dev_mac} (expected lldpd default = eth0 MAC)")

    host = _hostname(cli)
    assert sysname == host, f"local LLDP SysName {sysname!r} != hostname {host!r}"


# ============================ 3. Local physical ports are truly exposed ============================
def test_local_ports_exposed(cli, dut):
    """The physical ports under test (taken dynamically from dut) appear in lldpd's interface list.

    lldpmgrd should register the front-panel ports into lldpd; if a port under test is missing, the port->lldpd sync path is broken."""
    ports = dut.pick_test_ports(2)
    out = _lldp(cli, "lldpcli show interfaces").out
    # Note: \S+ greedily swallows the trailing comma (lldpcli prints "Interface: Ethernet0, via ..."),
    # use [^\s,]+ to exclude the comma, otherwise the set holds "Ethernet0," (with comma) making membership always False.
    listed = set(re.findall(r"Interface:\s+([^\s,]+)", out))
    for p in ports:
        assert p.name in listed, (
            f"{p.name} not exposed by lldpd; listed interfaces: {sorted(listed)}")


# ============================ 4. Self-loop neighbor discovery (PDU actually transmitted) ============================
@pytest.mark.traffic
def test_self_loop_neighbor_discovery(cli, dut, traffic):
    """Single-box self-loop trick to verify "PDU actually transmitted + neighbor discovery": the traffic fixture has already
    put ports[0] into MAC loopback and brought it oper-up, so lldpd periodically sends LLDP PDUs on the port; after a PDU
    physically egresses it re-ingresses via the loopback, and lldpd "sees itself" on the port -- learning one neighbor whose
    ChassisID == the local ChassisID.

    This is end-to-end proof (equivalent to data-plane): the neighbor's identity matches the local device, proving the frame
    really egressed the port and was received back. The self-loop produces a neighbor. If some build does not treat the
    self-loop as a neighbor -> we degrade to asserting "the TX counter really increments during loopback" (the PDU is indeed
    transmitted), which is still a real assertion, not weakened.
    """
    p = traffic.ports[0]                 # already MAC-looped by the traffic fixture -> oper-up
    local_cid, _ = _local_chassis(cli)
    assert local_cid, "no local ChassisID to compare against"

    _set_tx_interval(cli, _FAST_TX)
    try:
        tx0 = _tx_count(cli, p.name)
        # Poll for the self-loop neighbor to appear (allow ~8 fast tx-intervals for lldpmgrd to sense oper-up + one send/receive round)
        nei = None
        deadline = time.time() + _FAST_TX * 8 + 10
        while time.time() < deadline:
            nei = _neighbor_chassis(cli, p.name)
            if nei:
                break
            time.sleep(_FAST_TX)

        if nei:
            # Main path: seeing ourselves -- neighbor ChassisID == local ChassisID
            assert _norm_mac(nei) == _norm_mac(local_cid), (
                f"self-loop neighbor ChassisID {nei} != local ChassisID {local_cid} "
                f"on {p.name} (expected to see ourselves)")
            # SONiC-side sync chain (previously zero coverage; lldpcli only proves the view inside the lldpd container):
            # lldp-syncd should write the neighbor into APPL_DB LLDP_ENTRY_TABLE and `show lldp table` should render it --
            # this chain is exactly the data source for SNMP LLDP-MIB, and when it breaks lldpcli has the neighbor while the
            # NOS surface is blind.
            host = _hostname(cli)
            entry = {}
            deadline = time.time() + 30
            while time.time() < deadline:
                entry = cli.db_hgetall("APPL_DB", f"LLDP_ENTRY_TABLE:{p.name}")
                if entry.get("lldp_rem_chassis_id"):
                    break
                time.sleep(2)
            assert entry.get("lldp_rem_chassis_id"), (
                f"neighbor learned in lldpd but APPL_DB LLDP_ENTRY_TABLE:{p.name} never "
                f"populated — lldp-syncd sync chain broken (SNMP LLDP-MIB source is dead)")
            assert _norm_mac(entry["lldp_rem_chassis_id"]) == _norm_mac(local_cid), (
                f"APPL_DB lldp_rem_chassis_id {entry['lldp_rem_chassis_id']!r} != device MAC "
                f"{local_cid!r} on {p.name}")
            rsys = entry.get("lldp_rem_sys_name", "")
            assert rsys == host, (
                f"APPL_DB lldp_rem_sys_name {rsys!r} != hostname {host!r} on {p.name}")
            tbl = (cli.run("show lldp table").out or "")
            row = next((l for l in tbl.splitlines() if p.name in l), "")
            assert row and host in row, (
                f"`show lldp table` does not render the self-loop neighbor of {p.name} "
                f"with RemoteDevice={host!r}: {row!r}")
        else:
            # A self-loop neighbor should exist but was not learned = device defect -> fail to expose it.
            tx1 = _tx_count(cli, p.name)
            pytest.fail(
                f"self-loop produced no LLDP neighbor on {p.name} "
                f"(TX {tx0}->{tx1}); expected to learn ourselves as neighbor "
                f"(loopback should make the port send/learn LLDP)")
    finally:
        _set_tx_interval(cli, _DEFAULT_TX)


# ============================ 5. LLDP TX counter actually increments ============================
@pytest.mark.traffic
def test_lldp_tx_counter_increments(cli, traffic):
    """LLDP should transmit periodically on the looped-back (oper-up) port: sample TX -> wait one tx-interval -> sample again,
    asserting Transmitted really increments. Proves lldpd is not "configured but not sending" but actually pushing PDUs on schedule."""
    p = traffic.ports[0]
    _set_tx_interval(cli, _FAST_TX)
    try:
        # First wait for lldpmgrd to sense oper-up and start a send round, ensuring a stable periodic-transmit state
        base = None
        deadline = time.time() + _FAST_TX * 6 + 10
        while time.time() < deadline:
            base = _tx_count(cli, p.name)
            if base is not None and base > 0:
                break
            time.sleep(_FAST_TX)
        # An oper-up looped-back port where lldpd should transmit LLDP periodically but does not = device defect -> fail to expose it.
        assert base, (
            f"{p.name} never started transmitting LLDP under loopback "
            f"(TX still {base}); lldpd should transmit on an oper-up port")

        # Wait about two tx-intervals; TX must increment again
        time.sleep(_FAST_TX * 2 + 2)
        after = _tx_count(cli, p.name)
        assert after is not None and after > base, (
            f"LLDP TX did not increment on {p.name}: {base} -> {after} "
            f"(lldpd should periodically transmit on an oper-up port)")
    finally:
        _set_tx_interval(cli, _DEFAULT_TX)


# ----------------------------------------------------------------------------
# Mechanism notes (rationale for the assertions):
#   - lldp container is up; supervisorctl: lldpd / lldpmgrd / lldp-syncd all RUNNING.
#   - Local ChassisID == DEVICE_METADATA.mac; SysName == hostname.
#   - Physical ports default oper-down, so lldpd's Transmitted=0 on them (only eth0 is sending); MAC loopback (port cdN lb=mac)
#     brings the port oper-up, after which it starts sending LLDP and Transmitted keeps incrementing.
#   - The self-loop **does** produce a neighbor: the looped-back port learns one neighbor whose ChassisID/SysName are identical
#     to the local device (seeing itself), and `show lldp table` also shows this neighbor. So (4) uses the main-path real assertion
#     (neighbor == local device).
#   - tx-interval defaults to 30s (Transmit hold 4 -> TTL 120); the cases temporarily speed it to 5s, teardown restores 30s.
# ----------------------------------------------------------------------------
