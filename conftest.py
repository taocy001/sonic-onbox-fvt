"""pytest global fixture wiring.

Layers: session scope discovers the device once; function scope isolates each test
(loopback / collector / config snapshot).
"""
import time as _time

import pytest


# ---------- Device-issue collection (record crashes/failures faithfully, never soften tests) ----------
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    issues = []
    for rep in terminalreporter.stats.get("failed", []):
        txt = rep.longreprtext if hasattr(rep, "longreprtext") else str(rep.longrepr)
        line = next((l.strip() for l in (txt or "").splitlines()
                     if "device issue" in l.lower() or "crash" in l.lower()), None)
        issues.append((rep.nodeid, line or (txt or "").splitlines()[-1][:200]))
    if not issues:
        return
    import os
    _wk = os.environ.get("FVT_WORKER")
    path = os.path.join(os.path.dirname(__file__),
                        f"run_issues{'-w' + _wk if _wk else ''}.md")  # separate file; in parallel, one file per worker
    try:
        with open(path, "a") as f:
            f.write(f"\n## Run record ({len(issues)} failures/device issues)\n")
            for nid, msg in issues:
                f.write(f"- `{nid}`\n  - {msg}\n")
        terminalreporter.write_line(f"[device-issues] recorded {len(issues)} entries to {path}")
    except OSError:
        pass  # an unwritable file must not affect test results
    # Contamination-sentinel brief (when FVT_SENTINEL=1): print the leak map at the terminal tail
    from framework import sentinel as _sent
    for _l in _sent.summary_lines():
        terminalreporter.write_line(_l)


import pytest as _pytest_hook


@_pytest_hook.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item, nextitem):
    """Contamination-sentinel hook: after yield, all fixture finalizers have run, so the device
    state at this point is this test's "fully cleaned up" final state -- compare it against the
    previous quiescent baseline to attribute any residue precisely to this test."""
    outcome = yield
    del outcome
    from framework import sentinel as _sent
    if _sent.enabled():
        try:
            _sent.check_after_test(item.nodeid)
        except Exception:  # noqa: BLE001  the sentinel must never affect test results
            pass

from framework import cli as C
from framework import collector as COL
from framework import config_guard as G
from framework import dut as D
from framework import loopback as L
from framework import shell as S
from framework import traffic as T
from framework import verify as V

# ---------- safe lane (the observation lane of the two parallel lanes) ----------
# When FVT_LANE=safe this process is a "pure observation lane": it runs show/DB/SNMP-style tests in
# parallel with the dataplane lane (a separate pytest process).
# Iron rule: the observation lane MUST have no session-level global side effects -- force_clear_all
# (`port all lb=none`) would tear down the dataplane lane's loopbacks, suite_reset/sonic-clear fdb
# would wipe the dataplane lane's learned state, and baseline snapshots would overwrite each other.
# So the safe lane skips these setup/teardowns, and dataplane fixtures (traffic/l2net/l3up/l3net)
# explicitly refuse to run in the safe lane to guard against misconfiguration.
import os as _os
SAFE_LANE = _os.environ.get("FVT_LANE", "") == "safe"


def _no_dataplane_in_safe_lane():
    if SAFE_LANE:
        pytest.skip("dataplane fixture disabled in safe lane (FVT_LANE=safe): "
                    "run this test in the dataplane lane")


# ---------- session ----------
@pytest.fixture(scope="session")
def sh():
    return S.Shell()


@pytest.fixture(scope="session")
def dut(sh):
    d = D.discover(sh)
    # opt a device into klish routing via profiles.yaml caps (KLISH_FLAVOR env
    # takes precedence).  Discovery above ran native, which is fine; from here on
    # host config/show route through klish on opted-in devices only.
    if not sh.cli_flavor:
        sh.cli_flavor = (d.profile.get("caps", {}) or {}).get("cli_flavor")
    return d


@pytest.fixture(scope="session")
def cli(sh, dut):
    return C.Cli(sh, syncd=dut.syncd)


@pytest.fixture(scope="session")
def topo(dut):
    """Test topology (port roles / VLAN / IP / capabilities) -- tests reference it instead of hard-coding fields."""
    from framework.topology import Topology
    return Topology(dut)


@pytest.fixture
def caps(topo):
    """Device capability set. Use caps.require('xxx') to skip when unsupported."""
    return topo.caps


@pytest.fixture(scope="session")
def chip(_lb, dut, cli):
    """SDKLT chip-table (lt) assertion layer -- layer 4 of the verification stack (private
    plugins/chiptab.py, the Broadcom SDKLT layer). Reuses _lb's BcmShell channel; on public
    repos where this private plugin is not installed the whole chiptab suite skips gracefully,
    and devices where lt is unavailable skip via chip.require()."""
    try:
        from plugins.chiptab import ChipTab
    except ImportError:
        pytest.skip("chiptab plugin not installed (private Broadcom-SDKLT chip-table layer)")
    return ChipTab(_lb.bsh, dut, cli)


@pytest.fixture(scope="session")
def bdrv(cli, dut, chip):
    """DPB breakout driver (framework/breakout.py). Session scope: the module-level breakout base
    (split4) needs it too, and function scope would raise ScopeMismatch."""
    from framework.breakout import BreakoutDriver
    return BreakoutDriver(cli, dut, chip=chip)


@pytest.fixture(scope="session")
def _lb(sh, dut, cli):
    mgr = L.LoopbackManager(sh, dut, sdk=dut.sdk, cli=cli)
    if SAFE_LANE:           # observation lane: never force_clear (`port all lb=none` would tear down the dataplane lane's loopbacks)
        yield mgr
        return
    mgr.force_clear_all()   # session-start safety net: clear residual loopbacks leaked by the previous run / manual diagnosis (start from a clean baseline)
    yield mgr
    mgr.cleanup()           # disable loopbacks tracked in this session
    mgr.force_clear_all()   # force-clear all again on exit: catch any left untracked by an exception that skipped finally, leaving no residue for the next run


@pytest.fixture(scope="session", autouse=True)
def _suite_baseline(cli, dut, _lb, topo):
    """Suite-level setup/teardown (isolation level 1): on entry, save a config baseline snapshot;
    on exit, do a full reset -- return all test ports to the L2 baseline, clear dynamic FDB/neighbors,
    and destroy test-created chip VLANs (see framework/hygiene.suite_reset). Depends on _lb, so this
    teardown runs before _lb.cleanup() (reset ports first, then disable all loopbacks)."""
    from framework import hygiene
    from framework import worker as W
    if SAFE_LANE:
        # observation lane: no session-level side effects (snapshot / clear FDB / role-port homing /
        # suite_reset are all the dataplane lane's responsibility, executed exclusively by the
        # dataplane-lane process when parallel); keep only self-heal (1) AAA=local (idempotent, no parallel conflict).
        cli.sh.run("config aaa authentication login local", check=False)
        yield
        return
    cli.sh.run(f"config save -y /tmp/dut_test_suite_baseline{W.suffix() or ''}.json", check=False)
    if not W.is_parallel():
        # Global one-shot side effects run only in single-process mode; in parallel mode the
        # orchestrator (run_lanes.sh pre-phase) does them once -- if each worker did them itself,
        # `sonic-clear fdb all` would wipe learned state another worker is already exercising.
        cli.sh.run("sonic-clear fdb all", check=False)   # clear residual dynamic FDB at session start (prevent last run's leaks from polluting learning/forwarding)
        # Self-heal (1): force management auth = local. If the previous run crashed mid-AAA test
        # (leaving tacacs+ first and the server unreachable), a new SSH would hang on TACACS timeout
        # -> a device with only SSH and no serial console gets locked out. Restore local at session
        # start so management SSH can always authenticate.
        cli.sh.run("config aaa authentication login local", check=False)
        # Self-heal (3): clean FRR orphan route-maps left by a previously killed run (an orphan RM_SET_SRC blackholes all BGP FIB installs).
        try:
            hygiene.clean_frr_orphan_routemaps(cli)
        except Exception as e:  # noqa: BLE001
            from framework import log
            log.get("conftest").warning("FRR orphan route-map cleanup failed (non-fatal): %s", e)
    # Parallel worker >= 2: move this worker's role ports as a group into a private flood-domain
    # VLAN (this worker's view of default_vlan). Iron rule: if two bare loopback ports across
    # processes share a VLAN, any kernel noise multicast becomes a perpetual storm (the cross-process
    # version of the storm mechanism). w1 keeps the device default VLAN (matching single-process, minimal
    # behavioral drift); a migration failure is a hard failure -- never open the lane while broken.
    if W.wid() >= 2:
        base_dv, wdv = topo.base_default_vlan, topo.default_vlan
        assert wdv != base_dv
        cli.config_raw(f"vlan add {wdv}")
        for _r in ("a", "b", "c", "d", "e", "f", "g", "h"):
            try:
                _p = topo.port(_r).name
            except KeyError:
                continue
            cli.config_raw(f"vlan member del {base_dv} {_p}")
            for _ in range(20):
                if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{base_dv}|{_p}"):
                    break
                _time.sleep(0.3)
            rc, r = cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {wdv} {_p}")
            if rc != 0 or not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{wdv}|{_p}"):
                pytest.exit(f"worker{W.wid()} baseline failed: cannot move {_p} into "
                            f"private Vlan{wdv} ({(r.err or r.out or '').strip()[:120]}); "
                            f"refusing to run parallel lane", returncode=3)
    # Session-level deterministic baseline (2) (retrofit OS): the device's default ports are L3 routed
    # ports, and this fixture's teardown restores every port converted to L2 back to route (doesn't
    # change the default config after a run) -- so at every session start all 8 test role ports are in
    # L3 state. The traffic fixture only homes ports[0..1]; if no one converts the misc/l2 ports to L2,
    # tests that use them directly (static FDB / hairpin / MAC-family) fail falsely because the port is
    # not in the default VLAN, and whether you hit it depends on execution order in practice: running one
    # test always fails, the full suite is luck of the draw. Here we symmetrically home all role ports to
    # L2 at session start (route->bridge authoritative primitive, implemented inside ensure_port_l2), fully
    # transparent to tests; on non-retrofit OSes ports are L2 by default and ensure_port_l2 is a no-op.
    for _r in ("a", "b", "c", "d", "e", "f", "g", "h"):
        try:
            cli.ensure_port_l2(topo.port(_r).name)
        except KeyError:
            pass
        except Exception as e:  # noqa: BLE001
            from framework import log
            log.get("conftest").warning("session L2 baseline for role %s failed: %s", _r, e)
    # Session canary: two classes of device runtime problems make L2 dataplane tests fail falsely in
    # bulk; detect them explicitly before the run and log the root cause (warn only, don't block the
    # run -- non-L2 tests are unaffected):
    #  (1) STP|GLOBAL=enable: every vlan member move is rejected with "stp used"; the CLI gate plus the
    #      absence of a GCU model means no config path can disable it (product defect).
    #  (2) orchagent bridge-port leak accumulation: once degraded, member add no longer sets the chip
    #      learn bit (learn-ops=D), killing all forwarding/learning; the framework self-heals the learn
    #      bit after member add (l2_fwd_vlan/use_test_vlan), but a deep wedge (ACL/TM path) needs a swss restart.
    if cli.is_switchport_os():
        from framework import log as _flog
        _cl = _flog.get("conftest")
        if (cli.db_hgetall("CONFIG_DB", "STP|GLOBAL") or {}).get("enabled") == "enable":
            _cl.warning("CANARY: STP|GLOBAL=enable on this image -- ALL vlan member moves "
                        "will be rejected ('stp used'); every L2 dataplane test will fail "
                        "at precondition. No CLI/GCU path can disable it (product defect).")
        _r = cli.sh.run("grep -c 'removeBridgePort: Failed' /var/log/syslog", check=False)
        _n = int((_r.out or "0").strip() or 0) if (_r.out or "").strip().isdigit() else 0
        if _n >= 50:
            _cl.warning("CANARY: %d bridge-port removal failures in syslog (SAI BRIDGE_PORT "
                        "leak) -- orchagent L2 state likely degraded; member adds may leave "
                        "chip learn-ops=D. Framework self-heals learn bits, but deep wedges "
                        "(ACL/TM path) need 'systemctl restart swss'.", _n)
    # Contamination-sentinel baseline: after everything is homed and before any test, take the first quiescent fingerprint (when FVT_SENTINEL=1)
    from framework import sentinel as _sent
    _sent.capture_baseline(cli.sh)
    yield
    try:
        hygiene.suite_reset(cli, _lb, dut, topo)
    except Exception as e:  # noqa: BLE001
        from framework import log
        log.get("conftest").warning("suite_reset failed (non-fatal): %s", e)
    # Parallel worker >= 2: restore role ports from the private VLAN back to the device default VLAN, and delete the private VLAN (leave no private domain after the run).
    if W.wid() >= 2:
        base_dv, wdv = topo.base_default_vlan, topo.default_vlan
        for _r in ("a", "b", "c", "d", "e", "f", "g", "h"):
            try:
                _p = topo.port(_r).name
            except KeyError:
                continue
            cli.config_raw(f"vlan member del {wdv} {_p}")
            for _ in range(20):
                if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{wdv}|{_p}"):
                    break
                _time.sleep(0.3)
            rc, r = cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {base_dv} {_p}")
            if rc != 0:
                from framework import log
                log.get("conftest").warning(
                    "worker%d teardown: %s not restored to Vlan%s: %s",
                    W.wid(), _p, base_dv, (r.err or r.out or "").strip()[:120])
        cli.config_raw(f"vlan del {wdv}")
    # Retrofit OS: restore every port this session converted to bridge (L2) back to route (the device's
    # default L3 config). User requirement: don't change the default config after a run. Reachable across
    # cli instances -- cli is a session-scoped fixture and self._bridged accumulates the ports converted
    # over the whole session. Placed after suite_reset: suite_reset's teardown may convert test ports back
    # to L2, so this does the final unified restore.
    try:
        for _name in list(getattr(cli, "_bridged", set())):
            cli.restore_port_l3(_name)
    except Exception as e:  # noqa: BLE001
        from framework import log
        log.get("conftest").warning("restore bridged ports to route failed (non-fatal): %s", e)
    # Self-heal (2): force management auth = local after the run (even if some AAA test's config_guard never reached teardown), leaving no hazard for later SSH.
    cli.sh.run("config aaa authentication login local", check=False)


@pytest.fixture(scope="session", autouse=True)
def _snmp_community_ready(cli):
    """Session scope: ensure a usable 'public' RO community exists.

    SNMP needs a community configured before it can be queried -- a factory image with no community
    configured is not a device defect (it's an unconfigured state, a normal precondition). After
    `config snmp community add public ro`, snmpd.conf renders rocommunity and snmpget works immediately.
    This idempotently sets it up so SNMP tests can actually exercise MIBs (instead of stalling on
    "community not configured"). If already usable, leave it alone."""
    probe = "snmpget -v2c -c public -t 2 -r 1 localhost 1.3.6.1.2.1.1.1.0"
    r = cli.sh.run(probe, container="snmp", check=False)
    if "STRING" not in (r.out or "") and "1.3.6.1" not in (r.out or ""):
        cli.sh.run("config snmp community add public ro", check=False)
        for _ in range(20):    # wait for the SNMP service to restart + render
            _time.sleep(2)
            r = cli.sh.run(probe, container="snmp", check=False)
            if "STRING" in (r.out or "") or "1.3.6.1" in (r.out or ""):
                break
    yield


@pytest.fixture(scope="session", autouse=True)
def _l3_row_leak_guard(cli):
    """Observe only: count "address-less INTERFACE rows / RIFs" once at session start and end, warn if it grew, never touch the device.

    Why observe but not clean: on this device the ports are L3 routed by default, so a clean reboot
    already has 128 rows / 131 RIFs -- these are not residue, they're the default state, and deleting
    them all would change the ports' default mode. Only growth within the same session indicates a real
    leak this run (`config interface ip del` only removes the address subkey, the parent row stays, so
    one add/remove cycle goes RIF 5->6->6). A full run does hundreds of L3 port create/teardown cycles;
    if there's a real leak the tail count is noticeably higher. Treat these two numbers as a trend hint, not a conclusion.
    """
    from framework import hygiene
    from framework import log as _flog2
    _lg = _flog2.get("conftest")
    orphan0, rif0 = hygiene.count_l3_rows(cli)
    _lg.info("session start: %d address-less INTERFACE rows, %d RIFs", orphan0, rif0)
    yield
    orphan1, rif1 = hygiene.count_l3_rows(cli)
    _lg.info("session end: %d address-less INTERFACE rows, %d RIFs (start: %d / %d)",
             orphan1, rif1, orphan0, rif0)
    if rif1 > rif0:
        _lg.warning("this run grew the RIF count by %d (%d -> %d): L3 interfaces are being "
                    "left behind, and long runs degrade as they pile up", rif1 - rif0, rif0, rif1)


# ---------- function ----------
@pytest.fixture(autouse=True)
def _per_test_lb_guard(_lb):
    """Force-clear all loopbacks after every test (per-test safety net).

    Root cause: the session-level force_clear only backstops at the suite's start and end, but if a test
    within the run errors without hitting finally, or misses _lb.disable, it leaves loopbacks for the next
    test -- residual loopback + the next test's flood/broadcast traffic = a self-looping flood storm that
    drags down all subsequent L2 forwarding/learning tests. This autouse fixture force-clears once more at
    the tail of every test's teardown (later than the teardown of explicit fixtures like traffic/_lb),
    guaranteeing every test starts from a clean loopback baseline and leaves no residue for the next. Note:
    dynamic MAC learning itself works fine on a loopback port (a simulated frame's src is correctly learned
    to the physical port); the problem is solely the flood storm caused by residual loopbacks.

    Performance: the safety net (force_clear + 2s settle) is only needed when this test actually used a
    loopback. Non-loopback tests (SNMP/config/DB-query style, the majority) skip it, saving ~2s/test (over
    the ~800-test suite that's ten-plus minutes). Tests that hold a loopback at group level (module fixture
    `_lb.hold`) are managed by the group, so per-test does not force_clear (avoids repeatedly disabling/enabling the held port).
    """
    yield
    used = _lb._touched          # did this test actually enable a loopback (enable/flood/test_vlan set the flag)
    _lb._touched = False
    try:
        if _lb._held:
            return               # group-held: the group manages it (build/tear down once), per-test does not clear or settle
        if used:
            cleared = _lb.force_clear_all()   # used a loopback: clear residual loopbacks (prevent leaks + the next test's traffic looping into a storm)
            _lb.wait_cleared_down(cleared)    # event-driven wait for cleared ports to reach oper-down = control plane drained (replaces a fixed sleep 2)
        # loopback not used: skip force_clear + settle (fast path)
    except Exception:  # noqa: BLE001
        pass


@pytest.fixture(autouse=True)
def _port_l2_baseline_guard(request, cli, dut, topo, _lb):
    """Self-heal guard (goal #1 stability): after every test, authoritatively restore role ports that
    drifted into routed (L3) ports back to the L2 baseline, so that "even if a test fails / teardown is
    incomplete, the environment returns to a clean baseline".

    Root cause: on SONiC/switchport OS many L3 tests convert role ports to routed, and their teardown
    fails to restore under this box's semantics (`interface ip remove` only deletes the IP, leaving a bare
    INTERFACE|<port> routed port that doesn't return to the default VLAN automatically; or the undo
    order/command fails on SONiC) -- the port is then stranded in L3, polluting any later L2 test that
    needs it in the default VLAN. Fixing each teardown one by one is both tedious and easily reintroduced
    by new tests; this guard detects drift + authoritatively restores over the role-port set, a systematic
    backstop for this class of leak.

    Discipline:
      - Effective only on switchport OS (SONiC) -- community SONiC ports are L2 by default (a different
        model); the safe observation lane performs no side effects.
      - Restore only ports not held by a group-level fixture (_lb._held): l3net/l2net_mod hold L3/L2 bases
        across modules, never touch them.
      - Act only when drift is actually detected (one INTERFACE| key scan, cheap); zero overhead in the common case.
      - Record the restore in the sentinel report (heal event): both clean up and preserve the diagnostic
        clue of "who left which ports in routed state".
      - The last test's teardown also runs the session teardown (restoring ports to route per device
        default); this guard runs before it, symmetrically: the session-level reset is unaffected.
      - Restore only ports that newly drifted during this test: at setup, first record role ports that are
        already routed (pre); at teardown, only handle those "now routed but not in pre" -- so if some
        module base configured a port as L3 before this test without holding it via _lb.hold, it will
        never be restored by mistake (double insurance: pre snapshot + _held).
    """
    _sw = (not SAFE_LANE) and cli.is_switchport_os()

    def _routed_role_ports():
        role = {}
        for _r in ("a", "b", "c", "d", "e", "f", "g", "h"):
            try:
                p = topo.port(_r)
                role[p.name] = p
            except KeyError:
                pass
        iface = set(cli.db_keys("CONFIG_DB", "INTERFACE|Ethernet*"))
        return {name: p for name, p in role.items()
                if f"INTERFACE|{name}" in iface
                or any(k.startswith(f"INTERFACE|{name}|") for k in iface)}

    pre = set()
    if _sw:
        try:
            pre = set(_routed_role_ports())
        except Exception:  # noqa: BLE001
            pre = set()
    yield
    if not _sw:
        return
    try:
        held = {getattr(p, "name", p) for p in getattr(_lb, "_held", {}) or {}}
        now = _routed_role_ports()
        drifted = [p for name, p in now.items() if name not in pre and name not in held]
        if not drifted:
            return
        from framework import hygiene, sentinel as _sent
        for p in drifted:
            try:
                hygiene.reset_port_to_l2(cli, _lb, dut, p, topo.default_vlan)
            except Exception:  # noqa: BLE001
                pass
        _sent.record_heal(request.node.nodeid, [p.name for p in drifted])
    except Exception:  # noqa: BLE001  the self-heal guard must never affect test results
        pass


@pytest.fixture
def asicdb(cli):
    return V.AsicDb(cli)


@pytest.fixture
def statedb(cli):
    return V.DbView(cli, "STATE_DB")


@pytest.fixture
def appldb(cli):
    return V.DbView(cli, "APPL_DB")


@pytest.fixture
def config_guard(cli):
    with G.ConfigGuard(cli) as g:
        yield g


@pytest.fixture
def gcu(cli):
    """GCU (generic_config_updater) helper + per-test checkpoint/rollback isolation.
    GCU's native checkpoint/rollback is stronger than config_guard's targeted rollback (a system-level snapshot rollback back to baseline)."""
    from framework import gcu as _gcu
    g = _gcu.Gcu(cli)
    g.checkpoint()
    yield g
    try:
        g.rollback()
    finally:
        g.delete_checkpoint()


@pytest.fixture
def traffic(cli, dut, _lb, topo):
    """Pick two ports, admin up, loop back only the ingress port ports[0] by default (prevent broadcast storms), and provide a send/receive API.

    If the device has no loopback capability the whole class skips automatically.

    Warning: both ports looped back + broadcast/unknown-unicast = a self-looping flood storm! So:
      - flood/broadcast tests: keep a single-port loopback;
      - known-unicast forwarding tests (Pattern B/C): the test explicitly calls tr.loop(ports[1]) and sends only known unicast.
    teardown disables all loopbacks + the collector.
    """
    import time
    _no_dataplane_in_safe_lane()
    ports = dut.pick_test_ports(2)
    bcm_shell = L.BcmShell(cli.sh, dut)
    dv = topo.default_vlan
    # Defensive pre-cleanup: disable loopbacks + reset PVID + ensure both ports are back in the default
    # VLAN. Earlier hairpin tests move ports out of the default VLAN and their teardown's restore has an
    # async race that may not have succeeded -- if ports[1] is not in the default VLAN, smoke's
    # dst->ports[1] FDB miss becomes unknown-unicast flooding -> collides with the looped-back ports[0]
    # -> storm. So force-restore here and wait for programming.
    changed = False
    for p in ports:
        _lb.disable(p)
        if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{p.name}"):
            changed = True
            rc, _r = cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {dv} {p.name}")
            if rc != 0:
                # A member add failure is usually a residual RIF ("is a router interface") blocking it --
                # escalate to a full reset (tear down IP/RIF -> back to default VLAN). Without this layer,
                # one bad teardown kicks the port out of the VLAN permanently, and all subsequent L2 tests
                # fail in cascade.
                from framework import hygiene
                hygiene.reset_port_to_l2(cli, _lb, dut, p, dv)
    if changed:   # common case (both ports already in the default VLAN): no wait -- only wait for member programming to settle if config actually changed
        for _ in range(12):   # wait for members to be actually programmed
            if all(cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{p.name}") for p in ports):
                break
            time.sleep(0.5)
        time.sleep(1)
    # Reset chip PVID to the default VLAN and read back to confirm (untagged membership does not set the
    # chip PVID; an earlier test / historical cleanup may have set it to something else -- if PVID != dv,
    # re-entering frames land in the wrong VLAN, FDB miss floods -> loopback-port storm).
    for p in ports:
        cd = dut.bcm_of(p)
        if f"default VLAN is {dv}" in bcm_shell.cmd(f"pvlan show {cd}"):
            continue   # already in the default VLAN (common case): skip set+settle, read-back-confirm semantics unchanged
        for _ in range(8):
            bcm_shell.cmd(f"pvlan set {cd} {dv}")
            time.sleep(0.3)
            if f"default VLAN is {dv}" in bcm_shell.cmd(f"pvlan show {cd}"):
                break
    for p in ports:
        cli.intf_startup(p.name)
    _lb.enable(ports[0])  # ingress port only
    _lb.wait_learn_ready(ports[0])   # wait for the bridge port's admin/learning to actually come up (portsorch is async after oper-up)
    collector = COL.Collector(bcm_shell, dut, sdk=dut.sdk)
    tr = T.Traffic(cli, _lb, collector, ports)
    assert tr.smoke_check(), "loopback hairpin link self-check failed: check oper status/STP (see docs/DEPLOY.md)"
    yield tr
    collector.disable()
    for p in ports:
        _lb.disable(p)


@pytest.fixture
def copp_l3_ctx(cli, dut, _lb, topo, traffic):
    """Semantic correction: the L3 injection context for CoPP protocol traps.

    Semantics: protocol traps like ARP/ND/DHCP only punt to the CPU for packets ingressing from an L3
    interface (routed port / SVI) -- pure L2-switched packets should not bother the CPU (SONiC's IFP trap
    entry carries an InterfaceClassL2=L3_IIF class qualifier, which is exactly this semantics). Slow
    protocols (LLDP/LACP/UDLD) are link-local protocols that must punt on both L2 and L3 ports (the entry
    has no class qualifier), so not parameterizing this fixture's l3 yields the L2 context.

    Implementation: move traffic.ports[0] into a dedicated VLAN (topo.vlan("coppl3")) and configure an SVI
    -- a packet re-entering via loopback then carries the SVI's L3_IIF class and hits the trap. Chose an
    SVI over a routed port: (1) reuse traffic's loopback/capture base; (2) the punt semantics of this
    context match; (3) avoid SONiC's link-mode conversion path. Storm-safe: single-member VLAN + ingress-only
    loopback, so a broadcast re-entry has nowhere to replicate.

    Function scope (traffic is function-scoped, so scope can't be higher than it): built/torn down once per
    l3 test (SONiC YANG config ~10s each, acceptable); the l2 context parameter doesn't request this
    fixture, zero overhead. Fetched dynamically inside the test via request.getfixturevalue, which also
    prevents pytest from reordering the parametrization by fixture grouping.
    """
    p = traffic.ports[0]
    vid = topo.vlan("coppl3")
    net = topo.subnet("coppl3")
    bsh = L.BcmShell(cli.sh, dut)
    dv = topo.default_vlan
    rif_glob = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*"
    rifs_before = len(cli.db_keys("ASIC_DB", rif_glob))
    cli.config_raw(f"vlan add {vid}")
    # The SONiC product forbids member operations on Vlan1 ('1' out of range 2~4094), and under access
    # semantics a member add to a new VLAN auto-migrates; only the community image (where the default VLAN
    # is a real VLAN) needs an explicit del first.
    if str(dv) != "1":
        cli.config_raw(f"vlan member del {dv} {p.name}")
    flag = cli.vlan_untagged_flag()
    cli.config_raw(f"vlan member add {flag} {vid} {p.name}".replace("  ", " "))
    cli.config_raw(f"interface ip add Vlan{vid} {net['dut']}/{net['prefix']}")
    # Wait for the SVI RIF to actually program to the ASIC -- a punt hit depends on the L3_IIF class and
    # RIF programming is async; fail honestly on timeout
    for _ in range(30):
        if len(cli.db_keys("ASIC_DB", rif_glob)) > rifs_before:
            break
        _time.sleep(0.4)
    else:
        pytest.fail(f"SVI Vlan{vid} RIF not programmed to ASIC within 12s -- "
                    "cannot build L3 punt context for protocol traps")
    # Explicitly point the chip PVID at this VLAN and read back (untagged membership does not guarantee
    # the PVID is set; the product sets it automatically, this is an idempotent confirmation)
    cd = dut.bcm_of(p)
    for _ in range(10):
        if f"default VLAN is {vid}" in bsh.cmd(f"pvlan show {cd}"):
            break
        bsh.cmd(f"pvlan set {cd} {vid}")
        _time.sleep(0.3)
    yield {"vid": vid, "svi": net["dut"], "port": p}
    bsh.cmd(f"pvlan set {cd} {dv}")
    cli.config_raw(f"interface ip remove Vlan{vid} {net['dut']}/{net['prefix']}")
    cli.config_raw(f"vlan member del {vid} {p.name}")
    if str(dv) != "1":   # SONiC: member del auto-homes back to Vlan1, no manual step; community image explicitly returns to the default VLAN
        cli.config_raw(f"vlan member add {flag} {dv} {p.name}".replace("  ", " "))
    cli.config_raw(f"vlan del {vid}")


@pytest.fixture
def l2_fwd_vlan(cli, dut, _lb, topo, traffic):
    """The forwarding VLAN for L2 learning / static-FDB dataplane tests.

    Regular devices: the ports are already in default_vlan (a real VLAN that forwards / learns / syncs to
    ASIC_DB) -- returned as-is, zero behavioral change. `l2_home_forwarding=false` devices (SONiC: Vlan1
    is a parking berth whose members don't reach the ASIC, don't forward or learn, by design): build a
    real test VLAN (topo.vlan("l2fwd")) and migrate both traffic ports into it (under SONiC access
    semantics member add auto-migrates + the product self-sets the chip PVID), making the full chain of
    learning / swssconfig static FDB / ASIC_DB sync usable; the chip PVID is read back to confirm (same
    discipline as hairpin.arm); teardown migrates back to the berth (member del auto-homes to Vlan1). The
    misc / third port is added by the test itself using the returned vid."""
    if topo.caps.has("l2_home_forwarding"):
        yield topo.default_vlan
        return
    vid = topo.vlan("l2fwd")
    flag = cli.vlan_untagged_flag()
    cli.config_raw(f"vlan add {vid}")
    for p in traffic.ports:
        rc, r = cli.config_raw(f"vlan member add {flag} {vid} {p.name}".replace("  ", " "))
        # A member-migration failure must be loud: when STP|GLOBAL=enable, moving an access port out of
        # the berth is rejected with "stp used" -- if rc is swallowed, all subsequent L2 dataplane
        # assertions become misleading failures like "TX+0/not learned" (looks like forwarding broke, but
        # it's the environment precondition being rejected). Put the root cause right in your face here;
        # the STP switch itself can't be disabled via the CLI gate or GCU (no model) -- a product defect.
        if rc != 0 or not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|{p.name}"):
            pytest.fail(
                f"l2_fwd_vlan precondition failed: cannot move {p.name} into Vlan{vid}: "
                f"{(r.err or r.out or '').strip()[:160]} -- if this mentions 'stp used', the "
                f"image ships STP|GLOBAL=enable which blocks all VLAN member moves (product "
                f"defect; no CLI/GCU path can disable it)")
    bsh = L.BcmShell(cli.sh, dut)
    for p in traffic.ports:
        cd = dut.bcm_of(p)
        for _ in range(15):
            if f"default VLAN is {vid}" in bsh.cmd(f"pvlan show {cd}"):
                break
            _time.sleep(0.4)
    # Validate / self-heal the chip learn bit after member add: the traffic fixture's wait_learn_ready
    # self-heal happens during the Vlan1 berth phase, but member add rebuilds the bridge port -- a
    # degraded orchagent no longer sets learn on member add, and the chip learn-ops falls to D (SLF, i.e.
    # drop + don't learn), killing that port's L2 forwarding/flooding/learning entirely. Validate both
    # ports here: the ingress port preserves injection/learning, the egress port preserves mac-move /
    # flood-class return path. A healthy orchagent is ARL on the first pass, zero extra overhead.
    for p in traffic.ports:
        _lb.wait_learn_ready(p, timeout=4)
    yield vid
    for p in traffic.ports:
        cli.config_raw(f"vlan member del {vid} {p.name}")
    cli.config_raw(f"vlan del {vid}")


@pytest.fixture
def l2net(cli, dut, topo, _lb, traffic):
    """A dedicated test VLAN (chip-level, containing only this group's 4 test ports) for L2 dataplane tests + provides (vlan, p_in, p_out, p3, sink).

    Shrinks the flood domain from production Vlan1000's 160 ports to 4 ports -- root cause: repeatedly
    flooding in the 160-port default VLAN, where each frame's massive replication to 160 ports drags the
    chip into degradation (after a few consecutive L2 tests the loopback hairpin / learning / aging all
    go unstable, and eventually bcmcmd hangs). A dedicated VLAN (4 ports) survives 50 stress iterations at
    equal intensity with zero degradation. The injection port's PVID is pointed at this VLAN by
    use_test_vlan, so flooding replicates only within the 4 ports; when a port under test later
    temporarily changes its PVID via enable_flood_safe/isolate_pvid, it reads orig=this VLAN and restores
    automatically. This fixture runs after traffic (overriding its PVID reset); teardown restores the PVID
    + destroys the VLAN. Static FDB uses _lb.chip_fdb_add (a dedicated VLAN is chip-level, not in CONFIG_DB, so swssconfig doesn't apply).
    """
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    p3, sink = topo.misc_port(0), topo.misc_port(1)
    if len({p_in.name, p_out.name, p3.name, sink.name}) < 4:
        pytest.skip("need 4 distinct ports for scoped L2 dataplane tests")
    # Retrofit OS: p3/sink enter this VLAN via a chip-level VLAN (bcmcmd), not via config vlan member add,
    # so they aren't transparently converted to L2 -- explicitly convert them to bridge here, otherwise
    # they remain L3 routed ports and the chip does no L2 flooding/learning for them (no-op on non-retrofit OS).
    for p in (p_in, p_out, p3, sink):
        cli.ensure_port_l2(p)
    for p in (p3, sink):
        cli.intf_startup(p.name)
    vid = _lb.use_test_vlan(2000, [p_in, p_out, p3, sink], restore_vid=topo.default_vlan)
    from framework import hygiene as _hy
    _hy.flush_fdb(cli, dut, topo)   # in parallel mode, narrow to this worker's VLAN set, don't clear the other's learned state
    _time.sleep(1)
    yield (vid, p_in, p_out, p3, sink)
    _lb.drop_test_vlan()
    _hy.flush_fdb(cli, dut, topo)


@pytest.fixture(scope="module")
def l2net_mod(cli, dut, topo, _lb):
    """A module-level shared L2 dataplane base (a group of tests for the same feature shares one setup/teardown) -- the L2 counterpart of l3net.

    Mirrors the function-level `l2net` but made scope="module": one-shot ensure_port_l2 + startup of the 4
    test ports + build a dedicated test VLAN 2000 (use_test_vlan shrinks the flood domain from all of the
    production VLAN's ports to these 4, preventing 160-port flooding from dragging the chip into
    degradation) + loop back the ingress port p_in and hold it at group level via `_lb.hold` (the per-test
    force_clear safety net auto-reopens it and doesn't clear held ports). Tests only add their own
    FDB/traffic increments, and the base stays unchanged across tests -- reducing a group of L2 flood
    tests' boilerplate overhead from O(#tests) to O(1) (each SONiC config goes through slow YANG validation).

    Yields an object exposing vid, p_in, p_out, p3, sink, cli, dut, _lb, bsh, topo. Teardown once:
    release + disable the ingress-port loopback, drop_test_vlan (restore PVID + destroy VLAN), clear FDB.

    Storm-prevention key: use_test_vlan shrinks the flood domain to these 4 ports (not all of the
    production VLAN's ports), which must be preserved; per-test flood-safe/isolate_pvid is still done
    per-test inside the test body (each port under test uses a different isolation VLAN to break the loop),
    while the base only manages the VLAN + ports + ingress-port loopback. Per-test dynamic FDB/learned
    state is cleared by the consuming module itself (see `l2net_clean`, or mirror l3net's `_l3_clean` with
    a module-local autouse cleanup fixture -- one that doesn't disable the base's held ingress-port loopback).

    Scope: only for pure flood/reflood tests (a dedicated VLAN is chip-level and doesn't sync to ASIC_DB,
    so it's only for tests that don't need ASIC_DB) where the whole group shares the same 4 ports +
    dedicated VLAN base. Tests that change the base (change the VLAN / down a port / use a different port
    set, or need the default VLAN + ASIC_DB) still use the function-level `l2net`/`traffic` -- do not mix
    this module-level base with default-VLAN tests in the same file: this base's dedicated-VLAN PVID (on
    shared misc ports like p3/sink) is held across tests and leaks into interleaved default-VLAN tests,
    breaking their learning/forwarding semantics.
    """
    import types
    _no_dataplane_in_safe_lane()
    topo.caps.require("loopback")             # devices with no loopback capability skip the whole group gracefully (consistent with function-level l2net)
    p_in, p_out = topo.port("a"), topo.port("b")           # = traffic.ports[0/1] (same pick_test_ports order)
    p3, sink = topo.misc_port(0), topo.misc_port(1)
    if len({p_in.name, p_out.name, p3.name, sink.name}) < 4:
        pytest.skip("need 4 distinct ports for scoped L2 dataplane tests")
    # Convert the 4 ports to L2 (a dedicated VLAN is chip-level; on non-retrofit OS an L3 port does no L2 flooding/learning) + startup (no traffic base to do it for us)
    for p in (p_in, p_out, p3, sink):
        cli.ensure_port_l2(p)
        cli.intf_startup(p.name)
    # Dedicated test VLAN (shrink the flood domain to 4 ports) + loop back the ingress port and hold it at group level (per-test safety net doesn't clear it; the group does a unified release+disable at the end)
    vid = _lb.use_test_vlan(2000, [p_in, p_out, p3, sink], restore_vid=topo.default_vlan)
    _lb.enable(p_in)
    _lb.hold(p_in)
    from framework import hygiene as _hy
    _hy.flush_fdb(cli, dut, topo)   # in parallel mode, narrow to this worker's VLAN set, don't clear the other's learned state
    _time.sleep(1)
    env = types.SimpleNamespace(
        vid=vid, p_in=p_in, p_out=p_out, p3=p3, sink=sink,
        cli=cli, dut=dut, _lb=_lb, bsh=_lb.bsh, topo=topo)
    yield env
    try:
        _lb.release(p_in)
        _lb.disable(p_in)
    except Exception:  # noqa: BLE001
        pass
    _lb.drop_test_vlan()
    _hy.flush_fdb(cli, dut, topo)


@pytest.fixture
def l2net_clean(cli, dut, topo):
    """(opt-in for l2net_mod consuming modules) Per-test dynamic FDB cleanup: clear dynamic FDB before and
    after each test (in parallel mode, narrowed to this worker's VLAN set), keeping the l2net_mod base
    (VLAN + ports + loopback) unchanged and clearing only the dynamic FDB left by each test's
    learning/traffic. Not autouse -- referenced explicitly by the consuming module, or mirror
    test_l3_forward_traffic.py's `_l3_clean` with a module-local autouse cleanup fixture."""
    from framework import hygiene as _hy
    _hy.flush_fdb(cli, dut, topo)
    yield
    _hy.flush_fdb(cli, dut, topo)


# ---------- Topology / server integration (batch 1+) ----------
@pytest.fixture
def l3up(cli, dut, _lb, topo):
    """L3 port factory: l3up(port_name, cidr) -> Port. Clear residue + configure IP + startup + enable
    loopback to bring it up, with unified reclamation. For tests that need "port oper-up + L3 interface"
    before ASIC routes/neighbors/FDB can be installed. Setup first resets the port to a clean L2 baseline
    (self-healing, unaffected by the previous test's residual IP/RIF/loopback); teardown resets back to L2."""
    from framework import hygiene
    from framework.ports import Port
    _no_dataplane_in_safe_lane()
    dv = topo.default_vlan
    created = []

    def _up(port_name, cidr):
        import time
        p = Port(name=port_name)
        hygiene.reset_port_to_l2(cli, _lb, dut, p, dv)   # self-heal: clear residual IP/RIF/loopback/PVID
        # SONiC Vlan1 berth: member del 1 is rejected by the product (valid range 2~4094), the key never
        # disappears, so waiting 6s idly is pointless; leaving the berth is done by ip add's fixup chain
        # (restore_port_l3 -> link-mode route self-removes membership). Other devices keep the original
        # "del + wait for real deletion" to prevent a mixed-state storm.
        if str(dv) != "1" or not cli.is_switchport_os():
            cli.config_raw(f"vlan member del {dv} {port_name}")
            # Wait for the VLAN member to be actually deleted before configuring the IP: otherwise the port
            # is in a "both in VLAN and has IP" mixed state, and a re-entering frame is flooded/forwarded
            # into a loop within the VLAN -> storm (a measured source of cross-test races).
            for _ in range(20):
                if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{port_name}"):
                    break
                time.sleep(0.3)
        cli.config(f"interface ip add {port_name} {cidr}")
        cli.intf_startup(port_name)
        # Wait for the ASIC bridge port to be actually removed before bringing up the loopback (programming
        # side): deleting the CONFIG_DB key is only the write side; under high orchagent load bridge-port
        # removal slows down, widening the "VLAN+IP mixed state" window -- frames between loopback ports
        # then go through L2 bridging (no TTL decrement) and cross-feed each other forever. Placed after ip
        # add: on SONiC the Vlan1 member del is rejected by the product, so the bridge port only starts
        # being removed after ip add's fixup chain converts to route mode; and the storm danger window is
        # only after the loopback is up (a frame can only re-enter via the loopback), so gating before
        # enable is common to both OS types and sufficient.
        if not hygiene.wait_port_unbridged(cli, port_name):
            pytest.fail(f"port {port_name} still an ASIC bridge port before loopback enable; "
                        f"refusing to bring up L3 port (mixed L2+L3 state would storm)")
        _lb.enable(p)
        created.append((p, port_name, cidr))
        return p

    yield _up
    for p, name, cidr in reversed(created):
        try:
            hygiene.reset_port_to_l2(cli, _lb, dut, p, dv)   # reset back to L2, leaving no RIF for the next test
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture(scope="module")
def l3net(cli, dut, _lb, topo):
    """A module-level shared L3 dataplane base (a group of tests for the same feature shares one setup/teardown).

    Configures l3_port(0)/l3_port(1)/misc_port(0) as L3 in one shot (IP + startup + loopback, with the
    loopback held at group level via `_lb.hold` so the per-test force_clear safety net auto-reopens it and
    doesn't clear it), providing the router MAC and each port's subnet. Tests only add/clear their own
    route/neighbor increments, and the base stays unchanged across tests -- avoiding per-test repetition of
    reset_port_to_l2 + `config interface ip add` (each SONiC config goes through slow YANG validation) +
    loopback toggling, reducing a group of L3 tests' boilerplate overhead from O(#tests) to O(1). Special
    tests that need to change the base (change IP / down a port) still use the function-level l3up.
    """
    import types
    from framework import hygiene, l3probe
    from framework.ports import Port
    _no_dataplane_in_safe_lane()
    topo.caps.require("loopback")             # devices with no loopback capability skip the whole group gracefully (consistent with the original tests)
    dv = topo.default_vlan
    spec = {"in": (topo.l3_port(0), topo.subnet("c")),
            "out": (topo.l3_port(1), topo.subnet("d")),
            "o2": (topo.misc_port(0), topo.subnet("e"))}
    built = {}
    for key, (pobj, sub) in spec.items():
        p = Port(name=pobj.name)
        hygiene.reset_port_to_l2(cli, _lb, dut, p, dv)
        # SONiC Vlan1 berth: del is rejected and the key doesn't disappear, so skip del and skip waiting
        # (same as the l3up comment); leaving the berth is done by ip add's fixup chain (restore_port_l3).
        # Other devices keep "del + wait for real deletion" to prevent a mixed-state storm.
        if str(dv) != "1" or not cli.is_switchport_os():
            cli.config_raw(f"vlan member del {dv} {p.name}")
            # Wait for the member to be actually deleted before configuring the IP (same as l3up): vlanmgrd
            # is async, and without waiting it lands in a "both in VLAN and has IP" mixed state -- a
            # re-entering frame floods within the VLAN and the two loopback egresses cross-feed into a
            # hardware-level loop.
            for _ in range(20):
                if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{p.name}"):
                    break
                _time.sleep(0.3)
        cli.config(f"interface ip add {p.name} {sub['dut']}/{sub['prefix']}")
        cli.intf_startup(p.name)
        # Wait for the ASIC bridge port to be actually removed before bringing up the loopback (same gate
        # as l3up, see l3up for the placement rationale; mixed state + two loopback ports = perpetual L2
        # cross-feeding with no TTL decrement).
        if not hygiene.wait_port_unbridged(cli, p.name):
            pytest.fail(f"port {p.name} still an ASIC bridge port before loopback enable; "
                        f"refusing to build shared L3 base (mixed L2+L3 state would storm)")
        _lb.enable(p)
        _lb.hold(p)                       # group-held: per-test safety net doesn't clear it; unified release+disable at the group's end
        built[key] = (p, sub)
    env = types.SimpleNamespace(
        p_in=built["in"][0], p_out=built["out"][0], p_o2=built["o2"][0],
        sub_in=built["in"][1], sub_out=built["out"][1], sub_o2=built["o2"][1],
        rmac=l3probe.router_mac(cli), cli=cli, dut=dut, lb=_lb, bsh=_lb.bsh, topo=topo)
    yield env
    for key, (p, sub) in built.items():
        try:
            _lb.release(p)
            _lb.disable(p)
            hygiene.reset_port_to_l2(cli, _lb, dut, p, dv)
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture
def vrf_hairpin(cli, dut, _lb, topo, asicdb):
    """VRF hairpin base: create Vrf-A / Vrf-B, each bound to one ingress L3 port (same subnet, same IP,
    landing in their respective VRFs -> naturally isolated), leaving the egress port for the test to bind
    as needed. Yields a framework.vrfhairpin.VrfHairpin handle; teardown reclaims idempotently
    (delete routes -> unbind ports -> delete VRFs).

    A VRF-create / bind / IP-config failure = device defect -> FAIL; only missing loopback capability /
    router MAC is a runtime-precondition skip.
    """
    from framework.vrfhairpin import VrfHairpin
    _no_dataplane_in_safe_lane()
    topo.caps.require("loopback")
    vh = VrfHairpin(cli, dut, _lb, topo, asicdb)
    if not vh.rmac:
        pytest.skip("router MAC (DEVICE_METADATA.mac) not found")
    sub = topo.subnet("c")
    cidr = f"{sub['dut']}/{sub['prefix']}"
    try:
        vh.add_vrf("Vrf-A").add_vrf("Vrf-B")
        p_in_a, p_in_b = topo.l3_port(0), topo.l3_port(1)
        ok, why = vh.bind("Vrf-A", p_in_a, cidr)
        assert ok, f"DEVICE DEFECT: bind {p_in_a.name} to Vrf-A failed: {why}"
        ok, why = vh.bind("Vrf-B", p_in_b, cidr)
        assert ok, f"DEVICE DEFECT: bind {p_in_b.name} to Vrf-B failed: {why}"
        vh.p_in_a, vh.p_in_b, vh.in_peer = p_in_a, p_in_b, sub["peer"]
        yield vh
    finally:
        vh.cleanup()


@pytest.fixture
def vlink(cli, dut, _lb):
    """Virtual L3 link factory: vlink(port_index, dut_ip, peer_ip[, peer_mac]) -> VirtualLink.

    Auto-selects a front-panel port, builds the link, and reclaims it on teardown. For dataplane protocol
    tests like BGP/neighbor/DHCP/sFlow/ERSPAN that need "the DUT has an L3 interface + one peer".
    """
    from topo.virtual_link import VirtualLink

    created = []
    pool = dut.pick_test_ports(4)

    def _make(idx, dut_ip, peer_ip, prefix=24, peer_mac="00:de:ad:be:ef:a2"):
        vl = VirtualLink(cli, dut, _lb, pool[idx], dut_ip, peer_ip,
                         prefix=prefix, peer_mac=peer_mac)
        vl.setup()
        created.append(vl)
        return vl

    yield _make
    for vl in reversed(created):
        try:
            vl.teardown()
        except Exception:  # noqa: BLE001
            pass
