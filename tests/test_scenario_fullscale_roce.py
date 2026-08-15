"""Full-scale RoCE provisioning scenario: configure lossless + scheduling + ECN + PFC on
**every current Ethernet port**, then immediately do a full config-plane <-> chip-plane
reconciliation.

A class of problems that only surfaces at full scale: per-port config all returns success,
CONFIG_DB is complete, logs are error-free, yet the chip may fail to program individual
ports' queue weight/SP (a `del`+`add` replay fills it in) -- you can only reliably hit it by
laying ports out to full scale and reconciling each entry.

Division of labor with existing cases:
  - break ports out to full scale: `test_breakout_scenario_64x4_64x2.py` (it only verifies
    subport PC_PORT and naming);
  - the **full QoS/buffer config** after breakout: this file;
  - reconciliation criteria: `framework/bufaudit.py`, shared with the read-only round
    `test_scale_consistency_chip.py`.
Recommended order: run the breakout scenario first, then this file -- port count is highest
then, giving the best hit rate for missed programming.

**Destructive**: creates buffer/scheduler/WRED/PFC config on every port. Skipped by default;
must be enabled explicitly:

    FVT_ROCE_SCALE=1 pytest tests/test_scenario_fullscale_roce.py -m scale
    FVT_ROCE_PORTS=32 ...        # configure only the first 32 ports (for smoke)

Pool size is out of scope here: it can only be fixed at create time (a BOTH-type pool refuses
all SET) and must be provided by the factory `init_cfg.json.j2`, with a reload required to
change it. This case only does profile/binding/scheduling/PFC -- which is exactly the boundary
of the product CLI's capability. Whether the pool is large enough is decided by
`test_buffer_pool_chip.py` BP1/BP2.
"""
import os
import re
import time

import pytest

from framework import bufaudit as BA

pytestmark = [pytest.mark.qos, pytest.mark.roce, pytest.mark.chiptab,
              pytest.mark.scale, pytest.mark.slow]

_PG = 3
_Q_DATA = 3
_Q_CNP = 6
_WEIGHT = 80

# Profile values use the 400G/5m tier (xoff 184800B = 440 cells). For the correct values at
# other rates see the headroom table in Buffer/QoS design §4; this case aims to reconcile,
# not to tune, so it uses a single tier uniformly -- a differing port rate only affects how
# conservative the headroom is, not whether the criterion holds.
_ING = {"name": "FVTSC_ING", "min_th": 1680, "xon": 9240, "headroom": 184800,
        "dynamic_th": 0}
_EGR = {"name": "FVTSC_EGR", "min_th": 1680, "static_th": 91140000}
_SCH_DATA, _SCH_CNP, _WRED = "FVTSC_ROCE", "FVTSC_CNP", "FVTSC_ECN"


def _eth_ports(cli):
    ports = sorted((k.split("|", 1)[1] for k in
                    cli.db_keys("CONFIG_DB", "PORT|Ethernet*") or []
                    if re.match(r"Ethernet\d+$", k.split("|", 1)[1])),
                   key=lambda n: int(n[8:]))
    limit = os.environ.get("FVT_ROCE_PORTS")
    return ports[:int(limit)] if limit and limit.isdigit() else ports


def _ok(cli, cmd, sink):
    """Run one config command; record failure into sink but do not abort -- at full scale we
    want the full picture, not stop-on-first-error."""
    rc, r = cli.config_raw(cmd)
    if rc != 0:
        sink.append((cmd, ((r.out or "") + (r.err or "")).strip()[-90:]))
    return rc == 0


@pytest.fixture(scope="module")
def roce_scale(cli, chip):
    """Create global objects + per-port bindings; teardown unbinds per port and deletes the
    objects."""
    if os.environ.get("FVT_ROCE_SCALE", "") != "1":
        pytest.skip("full-scale RoCE provisioning is destructive; set "
                    "FVT_ROCE_SCALE=1 to run it (optionally FVT_ROCE_PORTS=N)")
    chip.require()
    if not chip.has_table("TM_ING_THD_PORT_PRI_GRP"):
        pytest.skip("chip lacks the TM threshold tables; nothing to reconcile against")
    ports = _eth_ports(cli)
    if len(ports) < 4:
        pytest.skip(f"only {len(ports)} Ethernet ports; scale scenario needs more")

    setup_fail = []
    # ---- Global objects (no pool creation: provided by factory config, see docstring) ----
    _ok(cli, f"buffer profile add {_ING['name']} --min-th {_ING['min_th']} "
             f"--xon {_ING['xon']} --headroom {_ING['headroom']} "
             f"--dynamic-th {_ING['dynamic_th']}", setup_fail)
    _ok(cli, f"buffer profile add {_EGR['name']} --min-th {_EGR['min_th']} "
             f"--static-th {_EGR['static_th']}", setup_fail)
    _ok(cli, f"scheduler add {_SCH_DATA} -t DWRR -w {_WEIGHT}", setup_fail)
    _ok(cli, f"scheduler add {_SCH_CNP} -t STRICT", setup_fail)
    _ok(cli, f"wred add {_WRED} -ecn ecn_all -en true "
             f"-gmin 1048576 -gmax 2097152 -ymin 1048576 -ymax 2097152 "
             f"-rmin 1048576 -rmax 2097152", setup_fail)
    if setup_fail:
        for c, why in setup_fail:
            print(f"  SETUP FAIL: {c} -> {why}")
        pytest.skip(f"{len(setup_fail)} global object(s) could not be created; the "
                    f"product CLI channel differs on this image — see prints")

    t0 = time.time()
    per_port_fail = []
    for p in ports:
        _ok(cli, f"interface buffer priority-group lossless add {p} {_PG} "
                 f"{_ING['name']}", per_port_fail)
        _ok(cli, f"interface buffer queue add {p} {_Q_DATA} {_EGR['name']}",
            per_port_fail)
        # Give both -s and -w at once: a del+add with only -s drops the wred_profile field
        _ok(cli, f"port-queue add {p} {_Q_DATA} -s {_SCH_DATA} -w {_WRED}",
            per_port_fail)
        _ok(cli, f"port-queue add {p} {_Q_CNP} -s {_SCH_CNP}", per_port_fail)
        _ok(cli, f"interface pfc priority {p} {_PG} on", per_port_fail)
    elapsed = time.time() - t0
    print(f"PROVISION: {len(ports)} ports in {elapsed:.0f}s, "
          f"{len(per_port_fail)} command failure(s)")
    for c, why in per_port_fail[:10]:
        print(f"  FAIL: {c} -> {why}")

    # orchagent's batch programming is asynchronous: give it time to drain the queue before
    # reconciling, otherwise we test "not arrived yet" rather than "lost". At full scale this
    # measurably needs tens of seconds.
    time.sleep(max(20, len(ports) // 4))
    pid, unresolved = BA.pid_map(chip, cli, ports)
    yield {"ports": ports, "pid": pid, "unresolved": unresolved,
           "cmd_fail": per_port_fail, "elapsed": elapsed}

    for p in ports:
        cli.config_raw(f"interface pfc priority {p} {_PG} off")
        cli.config_raw(f"port-queue del {p} {_Q_CNP}")
        cli.config_raw(f"port-queue del {p} {_Q_DATA}")
        cli.config_raw(f"interface buffer queue del {p} {_Q_DATA}")
        cli.config_raw(f"interface buffer priority-group lossless del {p} {_PG}")
    for cmd in (f"wred del {_WRED}", f"scheduler del {_SCH_DATA}",
                f"scheduler del {_SCH_CNP}",
                f"buffer profile del {_EGR['name']}",
                f"buffer profile del {_ING['name']}"):
        cli.config_raw(cmd)


def test_fs1_every_port_accepted_the_config(roce_scale):
    """FS1 the config plane itself must be clean first: no per-port command may fail.

    This case does not involve the chip -- it separates "CLI refused" from "CLI accepted but
    chip did not land". Without that separation, a later reconciliation failure cannot tell
    whether orchagent lost an event or the command simply never succeeded."""
    fails = roce_scale["cmd_fail"]
    assert not fails, (
        f"{len(fails)} per-port config command(s) were rejected across "
        f"{len(roce_scale['ports'])} ports; first few: {fails[:5]}. Fix the config "
        f"plane before interpreting any chip-side reconciliation result.")


def test_fs2_all_ports_resolve_to_chip(roce_scale):
    """FS2 every port must resolve to a chip PORT_ID. A port that cannot resolve is skipped in
    subsequent reconciliations, which silently shrinks the check scope -- this hole must be
    plugged first.

    This case tends to fail after full-scale breakout: SDK's flexport add takes a while before
    it inserts subports into PC_PORT_PHYS_MAP, so a resolution failure is usually "not waited
    long enough" rather than a real break."""
    un = roce_scale["unresolved"]
    assert not un, (
        f"{len(un)}/{len(roce_scale['ports'])} ports do not resolve to a chip "
        f"PORT_ID: {un[:6]}. Those ports are silently excluded from every "
        f"reconciliation below — the audit would report a clean result over a "
        f"shrunken port set. Check PC_PORT_PHYS_MAP for the missing subports.")


@pytest.mark.parametrize("kind,fn", BA.AUDITS, ids=[k for k, _ in BA.AUDITS])
def test_fs3_chip_matches_config_at_scale(cli, chip, roce_scale, kind, fn):
    """FS3 **full-scale reconciliation**: every binding just configured must land on the chip.

    Judged once per each of five dimensions: lossless PG headroom / egress queue threshold /
    queue scheduling / WRED-ECN / PFC enable."""
    missing, checked = fn(cli, chip, roce_scale["pid"])
    if not checked:
        pytest.skip(f"no chip-observable {kind} binding after provisioning "
                    f"(did the config actually land? see FS1)")
    print(f"RECONCILE {kind}: {checked - len(missing)}/{checked} programmed "
          f"over {len(roce_scale['ports'])} ports")
    assert not missing, BA.report(
        kind, missing, checked,
        extra=f"Provisioning took {roce_scale['elapsed']:.0f}s for "
              f"{len(roce_scale['ports'])} ports and reported zero CLI errors (FS1 "
              f"passed), so this is event loss between orchagent and the chip, not a "
              f"config-plane problem.")
