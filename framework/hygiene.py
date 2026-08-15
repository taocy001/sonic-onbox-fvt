"""Test-isolation hygiene: reset ports/global state to a clean baseline, clearing **non-config state** that config_guard cannot roll back.

config_guard only rolls back config commands in reverse order; it cannot clear:
chip loopback/PVID/discard, stale RIFs (orchagent may leave residue after IP
removal), or dynamic MAC/neighbor entries. This module fills the gap, called from
the three-level teardown (suite / feature / case).

Design point: every reset goes through the **SONiC path** (config CLI / DB), and
the chip layer only clears what the test fixture set itself (loopback).
"""
import time

from . import log
from .loopback import BcmShell

_log = log.get("hygiene")


def clean_frr_orphan_routemaps(cli):
    """Self-heal: clear orphan route-map residue in FRR (vtysh layer, config_guard cannot roll back).

    (1) RM_SET_SRC -- SONiC bgpcfgd renders `route-map RM_SET_SRC (set src <lo>)`
      + `ip protocol bgp route-map RM_SET_SRC` off Loopback0. On the clean path,
      deleting Loopback0 un-renders it; but an **interrupted run** (process killed,
      GCU rollback/undo not completed) can leave an orphan -- set src pointing at a
      now-nonexistent address -> zebra permanently queues FIB installs for **all
      subsequent BGP routes** ('q' state) -> nothing reaches the kernel/APPL_DB/ASIC,
      a silent blackhole. Only treated as an orphan when CONFIG_DB no longer has
      Loopback0 (on a healthy device RM_SET_SRC is a normal mechanism, must never
      be touched).
    (2) PBR1 -- test_pbr's vtysh route-map (residue from a killed run that never
      ran its finally)."""
    run = cli.sh.run("vtysh -c 'show running-config'", check=False).out or ""
    if "RM_SET_SRC" in run and not cli.db_keys("CONFIG_DB", "LOOPBACK_INTERFACE|Loopback0*"):
        cli.sh.run("vtysh -c 'conf t' -c 'no ip protocol bgp route-map RM_SET_SRC' "
                   "-c 'no route-map RM_SET_SRC permit 10'", check=False)
        _log.warning("cleaned orphan FRR RM_SET_SRC (stale bgpcfgd render after Loopback0 removal; "
                     "was blackholing all BGP FIB installs)")
    if "route-map PBR1" in run:
        cli.sh.run("vtysh -c 'conf t' -c 'no route-map PBR1 permit 10'", check=False)
        _log.warning("cleaned stale FRR route-map PBR1 (test_pbr residue from a killed run)")


def wait_port_unbridged(cli, port_name, timeout=15):
    """Wait until the port's SAI **BRIDGE_PORT object disappears from ASIC_DB** = the chip has truly left L2.

    Mechanism: after `vlan member del`, polling for CONFIG_DB key deletion only
    proves the **write side** is done; orchagent removes the bridge port from the
    chip asynchronously, and under load the window widens. Configuring IP + enabling
    loopback within this window = a "VLAN+IP mixed state" -- frames between the two
    loopback ports take the L2 bridging path (no TTL decrement) and flood each other
    forever into a storm. So we must confirm the bridging personality is gone on the
    **programming side** (ASIC_DB) before continuing.

    Returns True = left L2 (or had no bridge port to begin with). On timeout returns
    False -- the caller must fail honestly, never silently proceed."""
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port_name}")
    if not oid:
        return True          # no port OID mapping (dry-run/anomaly), can't judge; leave it to other upper-layer checks
    # First locate this port's BRIDGE_PORT key (one full-table scan); afterwards only poll this one key's existence (cheap)
    bp_key = None
    for k in cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:*"):
        if cli.db_hgetall("ASIC_DB", k).get("SAI_BRIDGE_PORT_ATTR_PORT_ID") == oid:
            bp_key = k
            break
    if bp_key is None:
        return True          # no bridge port = already a pure routed port (the serial common case, fast path)

    def _no_l2_membership():
        """The bridge-port object exists but has **no VLAN member references** = no
        L2 forwarding personality, so the storm precondition does not hold. On some
        platforms `link-mode route` is functionally complete (member removed + RIF
        built + show=routed) but the SAI BRIDGE_PORT object is **not reclaimed**
        (object leak, still registered); by the old criterion (object disappears)
        this would stay falsely FALSE and block all L3 cases. The real storm
        precondition is "the loopback port still has an L2 forwarding personality"
        (member present -> flood/bridge reachable), so an empty membership is safe
        to proceed."""
        bp_oid = bp_key.rsplit(":", 1)[-1]
        for m in cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*"):
            if cli.db_hgetall("ASIC_DB", m).get("SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID") == bp_oid:
                return False
        return True

    end = time.time() + timeout
    while time.time() < end:
        if not cli.db_keys("ASIC_DB", bp_key):
            return True
        if _no_l2_membership():
            _log.info("port %s: ASIC bridge port %s lingers (SAI object leak) "
                      "but has no VLAN membership -> no L2 personality, safe to proceed",
                      port_name, bp_key)
            return True
        time.sleep(0.3)
    _log.warning("port %s still has ASIC bridge port %s after %ss (L2 exit not programmed)",
                 port_name, bp_key, timeout)
    return False


def reset_port_to_l2(cli, lb, dut, port, default_vlan, wait=True):
    """Reset a single port to a clean L2 baseline: disable loopback, reset chip
    PVID, remove all IPs (revert to L2, clear RIF), return to the default VLAN
    (untagged). Used in fixture setup (self-healing, unaffected by the previous
    case's residue) and teardown."""
    name = port.name
    bcm = dut.bcm_of(port)
    bsh = BcmShell(cli.sh, dut)
    # 1) Chip layer: disable loopback + discard + reset PVID (these config_guard cannot clear)
    try:
        lb.disable(port)
    except Exception:  # noqa: BLE001
        pass
    bsh.cmd(f"pvlan set {bcm} {default_vlan}")
    bsh.cmd(f"port {bcm} discard=none")
    # 2) Turn the port from a router port back into an L2 port that can bridge
    if cli.is_switchport_os():
        # Modified OS: ports default to L3, use link-mode to convert to L2 (access,
        # the INTERFACE row is removed). Do not use `interface ip remove` -- on the
        # modified OS it is a del and requires an IP, and a bare port with no IP
        # errors out. The L2 conversion is recorded/restored by ensure_port_l2.
        cli.ensure_port_l2(name)
    else:
        # Standard SONiC: remove all IPv4/IPv6 on the port (turn it from a router port back into an L2 port)
        for k in cli.db_keys("CONFIG_DB", f"INTERFACE|{name}|*"):
            ip = k.split("|")[-1]
            cli.config_raw(f"interface ip remove {name} {ip}")
        # Fallback: a **bare** INTERFACE|<port> key (residue from vrf bind / ip
        # remove on some images) keeps the port a router port, and `vlan member add`
        # is rejected with "is a router interface" -- self-healing then fails. First
        # try vrf unbind (the proper path); if residue remains, DEL the CONFIG_DB key
        # directly (intfmgrd watches table changes and tears down the RIF).
        if cli.db_keys("CONFIG_DB", f"INTERFACE|{name}"):
            cli.config_raw(f"interface vrf unbind {name}")
            for _ in range(8):
                if not cli.db_keys("CONFIG_DB", f"INTERFACE|{name}"):
                    break
                time.sleep(0.4)
            if cli.db_keys("CONFIG_DB", f"INTERFACE|{name}"):
                cli.sh.run(f"sonic-db-cli CONFIG_DB DEL 'INTERFACE|{name}'", check=False)
                time.sleep(1)
    # 3) Ensure it is in the default VLAN (untagged member) -- a prerequisite for L2 forwarding/FDB
    if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{default_vlan}|{name}"):
        cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {default_vlan} {name}")
    # 4) Wait until the port truly returns to L2 (no INTERFACE row for the port in CONFIG_DB + in the default VLAN)
    if wait:
        for _ in range(10):
            # Match this port's INTERFACE key exactly (bare port `INTERFACE|Eth4`
            # and with-IP `INTERFACE|Eth4|...`), avoiding the `INTERFACE|Eth4*`
            # prefix wrongly matching Eth40/Eth400 (on the modified OS this would
            # always judge non-empty).
            no_ip = (not cli.db_keys("CONFIG_DB", f"INTERFACE|{name}")
                     and not cli.db_keys("CONFIG_DB", f"INTERFACE|{name}|*"))
            in_vlan = cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{default_vlan}|{name}")
            if no_ip and in_vlan:
                break
            time.sleep(0.4)


def sweep_test_qos_artifacts(cli):
    """End-of-session fallback: delete any leftover FVT*-named test QoS objects (scheduler / wred / buffer-profile).

    Root cause: on SONiC, "unbinding port-qos-map/port-queue" is asynchronous, and
    an immediately-following `scheduler/wred del` often lands in the "still
    referenced" window and fails (rc is ignored) -> residue. A leftover scheduler
    **still bound to the port** rate-limits that port to pir, polluting all
    subsequent traffic cases. This sweeps by naming prefix at session end: first
    unbind the FVT* objects, then delete the objects with read-back retries, so the
    device returns to a clean baseline at session end."""
    # 1) Unbind the port-qos-map bindings that reference FVT* schedulers.
    # WARNING: on SONiC **no ordinary CLI can unbind a port scheduler**:
    # `port-qos-map del <port>` does not clear the scheduler field, nor does
    # `port-qos-map update <port> -s ''`; and while this leafref exists,
    # `scheduler del` is rejected by YANG (leafref points to non-existing leaf,
    # Aborted). The only viable config path is **GCU removing the field**
    # (config apply-patch remove /PORT_QOS_MAP/<port>/scheduler), after which
    # scheduler del is allowed. Otherwise a leftover scheduler bound to the port
    # rate-limits it to pir and permanently pollutes subsequent runs.
    from .gcu import Gcu
    _g = Gcu(cli)
    for k in cli.db_keys("CONFIG_DB", "PORT_QOS_MAP|*"):
        sch = (cli.db_hgetall("CONFIG_DB", k).get("scheduler", "") or "").strip("[]").split("|")[-1]
        if sch.startswith("FVT"):
            port = k.split("|")[-1]
            r = _g.apply_patch([{"op": "remove",
                                 "path": Gcu.path("PORT_QOS_MAP", port, "scheduler")}])
            if "Patch applied successfully" not in (r.out or ""):
                _log.warning("sweep: GCU unbind scheduler on %s failed: %s",
                             port, (r.err or r.out or "")[-160:])
    for k in cli.db_keys("CONFIG_DB", "QUEUE|*"):
        sch = (cli.db_hgetall("CONFIG_DB", k).get("scheduler", "") or "").strip("[]").split("|")[-1]
        parts = k.split("|")
        if sch.startswith("FVT") and len(parts) == 3:
            cli.config_raw(f"port-queue del {parts[1]} {parts[2]}")
    # 2) Delete FVT*-named scheduler / wred / buffer-profile objects (read-back retries, fault-tolerant)
    for tbl, cmd in (("SCHEDULER", "scheduler del"),
                     ("WRED_PROFILE", "wred-profile del"),
                     ("BUFFER_PROFILE", "buffer profile del")):
        for k in cli.db_keys("CONFIG_DB", f"{tbl}|FVT*"):
            name = k.split("|", 1)[-1]
            for _ in range(4):
                if not cli.db_keys("CONFIG_DB", k):
                    break
                cli.config_raw(f"{cmd} {name}")
                time.sleep(0.3)
            if cli.db_keys("CONFIG_DB", k):
                _log.warning("sweep_test_qos_artifacts: %s survived cleanup", k)


def count_l3_rows(cli):
    """Return (count of addressless `INTERFACE|<port>` rows, count of ROUTER_INTERFACE in the ASIC).

    WARNING: on **this device these two numbers are not a "leak count"**: ports on
    the modified OS default to L3 routed ports, so after boot every port already has
    one INTERFACE row and one RIF. Therefore only **growth within the same session**
    indicates this run leaked something; the absolute values are meaningless.

    Why watch them: `config interface ip del <port> <cidr>` only deletes the address
    sub-key, leaving the parent row (after one add/remove cycle the RIF count does
    not drop; deleting the leftover row returns to baseline). A full run does
    hundreds of L3 port create/teardown cycles, and if it truly leaks the count
    climbs steadily. Do not use these two numbers as a conclusion.
    """
    orphan = 0
    for key in cli.db_keys("CONFIG_DB", "INTERFACE|*"):
        parts = key.split("|")
        if len(parts) != 2:
            continue
        if not cli.db_keys("CONFIG_DB", f"INTERFACE|{parts[1]}|*"):
            orphan += 1
    return orphan, len(cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*"))


def purge_orphan_l3_rows(cli, ports=None):
    """Clear addressless `INTERFACE|<port>` leftover rows on the given ports; return (rows purged, RIF count after purge).

    WARNING: **ports must be passed** (a case only clears the ports it created). Not
    passing it means a device-wide sweep that also deletes the one-row-per-port that
    ships at boot -- that is not residue, it is this device's "ports default to L3"
    default state, and deleting it amounts to changing the device's default config.

    Root cause: `config interface ip del <port> <cidr>` only deletes the address
    sub-key, **leaving** the parent row with `mtu`/`arp_aging_time`/`nd_aging_time`;
    intfmgrd still emits `APPL_DB INTF_TABLE:<port>`, and orchagent still maintains a
    `ROUTER_INTERFACE_TYPE_PORT` for it. After one add/remove cycle the RIF count
    does not drop; deleting the leftover row makes it drop.

    Why the sweep is required: a full run leaks one RIF per L3 port configured, so a
    long run accumulates steadily, and excessive residue can degrade that port's L3
    forwarding, which recovers once cleaned.

    `reset_port_to_l2` already has the same fallback, but only on the standard SONiC
    branch; the modified OS goes through `ensure_port_l2`, which is per-port and
    **session-cached**, covering only ports that need converting back to L2 and
    missing ports left in the L3 state. Hence one global sweep here.

    What is deleted is a CONFIG_DB row, going through the normal intfmgrd ->
    orchagent -> RIF path (INTF_TABLE and RIF disappear together), not touching the
    ASIC; no CLI can delete a bare row, so this is the only path.
    """
    purged = []
    want = set(ports) if ports else None
    for key in cli.db_keys("CONFIG_DB", "INTERFACE|*"):
        parts = key.split("|")
        if len(parts) != 2:                      # `INTERFACE|<port>|<ip>`, leave the address sub-key alone
            continue
        name = parts[1]
        if want is not None and name not in want:
            continue
        if cli.db_keys("CONFIG_DB", f"INTERFACE|{name}|*"):
            continue                             # still has an address, an in-use L3 port
        row = cli.db_hgetall("CONFIG_DB", key) or {}
        if row.get("vrf_name"):
            continue                             # a VRF-bound bare row has semantics, not residue
        cli.sh.run(f"sonic-db-cli CONFIG_DB DEL 'INTERFACE|{name}'", check=False)
        purged.append(name)
    if purged:
        time.sleep(2)                            # wait for intfmgrd/orchagent to tear down the RIF
    rifs = len(cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*"))
    if purged:
        _log.warning("purged %d orphan INTERFACE rows (%s%s); RIF now %d",
                     len(purged), ", ".join(purged[:6]),
                     " ..." if len(purged) > 6 else "", rifs)
    return len(purged), rifs


def reset_ports(cli, lb, dut, ports, default_vlan):
    """Reset a group of ports to a clean L2 baseline in batch."""
    for p in ports:
        reset_port_to_l2(cli, lb, dut, p, default_vlan, wait=False)
    time.sleep(1)   # wait for programming to settle


def flush_fdb(cli, dut=None, topo=None):
    """Clear only dynamic FDB (inter-case cleanup for the l2net-family fixtures). In
    parallel mode, narrow to this worker's VLAN set (chip-level `l2 clear vlan=`) --
    `sonic-clear fdb all` would clear another worker's learned state under test."""
    from . import worker as W
    if W.is_parallel() and dut is not None and topo is not None:
        bsh = BcmShell(cli.sh, dut)
        for v in sorted({topo.default_vlan, W.remap_vid(2000), topo.hp_vlan_a, topo.hp_vlan_b}):
            bsh.cmd(f"l2 clear vlan={v}")
        return
    cli.sh.run("sonic-clear fdb all", check=False)


def flush_dynamic(cli, dut=None, topo=None):
    """Clear dynamic learned state (FDB/neighbors) so entries learned by the previous
    case do not interfere with the next. Uses SONiC commands.

    In parallel mode (when dut/topo are passed), narrow to this worker's resources:
    chip-level `l2 clear vlan=` clears only this worker's flood-domain/test-VLAN
    dynamic FDB, and neighbors are flushed only for this group's ports --
    `sonic-clear fdb all` / `sonic-clear arp` would clear another worker's learned
    state under test. Non-parallel keeps the global semantics."""
    from . import worker as W
    if W.is_parallel() and dut is not None and topo is not None:
        bsh = BcmShell(cli.sh, dut)
        vids = {topo.default_vlan, W.remap_vid(2000), topo.hp_vlan_a, topo.hp_vlan_b}
        for v in sorted(vids):
            bsh.cmd(f"l2 clear vlan={v}")
        for p in (dut.worker_block() or []):
            cli.sh.run(f"ip neigh flush dev {p.name}", check=False)
            cli.sh.run(f"ip -6 neigh flush dev {p.name}", check=False)
        return
    cli.sh.run("sonic-clear fdb all", check=False)
    cli.sh.run("sonic-clear arp", check=False)
    cli.sh.run("ip -6 neigh flush all", check=False)


def suite_reset(cli, lb, dut, topo):
    """Suite-level full reset: all test-role ports back to L2 baseline + clear dynamic state + destroy test-created chip VLANs."""
    # Self-heal: if SONiC's read-only default QoS maps get cleared, whole-DB YANG
    # validation fails (cascading to lock out GCU/acl/mirror/bgp); restore here as a
    # fallback (see the qos.ensure_default_qos_maps comment).
    try:
        from . import qos as _qos
        _qos.ensure_default_qos_maps(cli)
    except Exception as e:  # noqa: BLE001
        _log.warning("ensure_default_qos_maps failed (non-fatal): %s", e)
    # Sweep leftover FVT* test QoS objects (scheduler/wred/buffer-profile) at session
    # end -- a leftover scheduler bound to a port rate-limits and pollutes subsequent
    # runs; a uniform fallback by naming prefix (see sweep_test_qos_artifacts).
    try:
        sweep_test_qos_artifacts(cli)
    except Exception as e:  # noqa: BLE001
        _log.warning("sweep_test_qos_artifacts failed (non-fatal): %s", e)
    # Self-heal: leftover static FDB entries in SONiC CONFIG_DB FDB| reject any VLAN
    # move of the attached port with "VLAN_MEMBER related static FDB" -- a
    # suite-level fallback to clear test residue.
    if cli.is_switchport_os():
        for k in cli.db_keys("CONFIG_DB", "FDB|Vlan*|*"):
            parts = k.split("|")
            if len(parts) == 3:
                cli.config_raw(f"mac static del {parts[1].replace('Vlan', '')} {parts[2]}")
        for k in cli.db_keys("CONFIG_DB", "FDB|Vlan*|*"):
            _log.warning("static FDB residue %s survived cleanup, DB-deleting via sonic-db-cli", k)
            cli.sh.run(f"sonic-db-cli CONFIG_DB DEL '{k}'", check=False)
    roles = ["a", "b", "c", "d", "e", "f", "g", "h"]
    ports = []
    for r in roles:
        try:
            ports.append(topo.port(r))
        except KeyError:
            pass
    reset_ports(cli, lb, dut, ports, topo.default_vlan)
    flush_dynamic(cli, dut, topo)   # parallel mode auto-narrows to this worker's resources
    # Destroy **pure chip-level** VLANs created by traffic/hairpin (not SONiC-managed:
    # 110/120/200/300 and the isolation VLANs).
    # WARNING: never destroy the topo pool (320-325) -- those are SONiC-managed via
    # `config vlan add`, and an out-of-band destroy at the chip layer desyncs
    # orchagent's internal state from the chip (internally believed to exist ->
    # subsequent config vlan add no longer programs the chip). SONiC-managed VLANs
    # can only go through config vlan del.
    from . import worker as W
    bsh = BcmShell(cli.sh, dut)
    if not W.is_parallel():
        bsh.cmd("l2 clear")          # in parallel, a whole-chip l2 clear would clear the other's dynamic table; flush_dynamic clears per-VLAN
    # WARNING: 110/120 are created by hairpin via **SONiC config** (topo/hairpin.py
    # setup), not pure chip-level -- once wrongly on the destroy list: if some
    # hairpin teardown's `vlan del` fails and leaves CONFIG residue, an out-of-band
    # destroy here causes permanent orch/chip desync (config vlan add on the same
    # number becomes a no-op forever, only a swss restart fixes it). SONiC-managed
    # VLANs can only go through config vlan del (the next two lines clear residue as a fallback).
    for v in (topo.hp_vlan_a, topo.hp_vlan_b):
        if cli.db_keys("CONFIG_DB", f"VLAN|Vlan{v}"):
            cli.config_raw(f"vlan del {v}")
    for v in (200, 300, 2000, 3990, 3991, 3992, 3993):
        bsh.cmd(f"vlan destroy {W.remap_vid(v)}")
    _log.info("suite_reset done: %d ports back to L2, dynamic flushed", len(ports))
