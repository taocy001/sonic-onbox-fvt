"""Full-scale config: **per-port reconciliation of config plane vs chip plane** -- "CONFIG_DB complete != chip complete".

Origin (a class of silent event-drop at scale): 256 ports configured one by one with
`config port-queue add` **all returned success**, all 256 CONFIG_DB entries present, zero
errors in the logs, yet the chip programmed only **255** (a few ports missing queue
weight/SP). Replaying that port with `del` + `add` filled it in -- meaning orchagent
silently dropped events under batch pressure, with no alarm and no retry.

The signature of this class of defect is that it **only appears at scale, and only
reconciliation can see it**:
- single-port cases (RC1/RC2/CG*/qos_sched_chip) are all green, because each only looks at one port;
- config-plane self-checks are all green, because CONFIG_DB really was written;
- spot checks most likely miss it (1/256 hit rate).

The criterion is implemented in `framework/bufaudit.py`, shared with the full-scale scenario
to avoid two copies drifting. Scale-independent: it runs on 8 ports too (just catches
nothing); it only bites once split out and configured at full scale.

All cases are **read-only** (CONFIG_DB + chip traverse), no config changes; each chip table
is traversed only once.
"""
import pytest

from framework import bufaudit as BA

pytestmark = [pytest.mark.qos, pytest.mark.chiptab, pytest.mark.scale]


@pytest.fixture(scope="module")
def pid(cli, chip):
    chip.require()
    ports = BA.config_ports(cli)
    if len(ports) < 2:
        pytest.skip("no Ethernet ports in CONFIG_DB")
    ok, unresolved = BA.pid_map(chip, cli, ports)
    if not ok:
        pytest.skip("no port resolved to a chip PORT_ID (PC_PORT_PHYS_MAP empty?)")
    if unresolved:
        print(f"NOTE: {len(unresolved)} port(s) unresolved to chip PORT_ID, "
              f"excluded from reconciliation: {unresolved[:4]}")
    return ok


def _run(cli, chip, pid, fn, kind, extra=""):
    missing, checked = fn(cli, chip, pid)
    if not checked:
        pytest.skip(f"no chip-observable {kind} binding in this configuration")
    print(f"RECONCILE {kind}: {checked - len(missing)}/{checked} programmed")
    assert not missing, BA.report(kind, missing, checked, extra=extra)


def test_sc1_all_bound_pgs_programmed(cli, chip, pid):
    """SC1 every lossless BUFFER_PG binding must land in TM_ING_THD_PORT_PRI_GRP, and the headroom
    value must match the xoff derived from the profile. Missing one port = that port's lossless has no buffer backstop."""
    _run(cli, chip, pid, BA.audit_pg_headroom, "lossless PG headroom")


def test_sc2_all_bound_queues_programmed(cli, chip, pid):
    """SC2 every BUFFER_QUEUE binding must take effect in TM_THD_UC_Q (static_th or min).

    A missing binding on the egress side is more insidious than on ingress: the queue
    threshold default is already "usable" (alpha=1/min=0), so it does not break traffic
    immediately, only showing up under congestion as a few ports dropping differently from the rest."""
    _run(cli, chip, pid, BA.audit_queue_thresholds, "egress queue thresholds")


def test_sc3_all_queue_schedulers_programmed(cli, chip, pid):
    """SC3 **queue scheduler landing regression lock**: every QUEUE's scheduler binding must land in
    TM_SCHEDULER_NODE (the config count and the node count must match; one short = a miss)."""
    _run(cli, chip, pid, BA.audit_queue_schedulers, "queue schedulers",
         extra="This is exactly the queue-scheduler reconciliation signature.")


def test_sc4_all_wred_bindings_programmed(cli, chip, pid):
    """SC4 every queue's wred_profile binding must take effect in TM_WRED_UC_Q. Missing one port means
    "that port's RoCE does no ECN marking" -- congestion control fails on that port, invisible in the counters."""
    _run(cli, chip, pid, BA.audit_wred, "queue WRED/ECN")


def test_sc5_all_pfc_enables_programmed(cli, chip, pid):
    """SC5 for every port that declares pfc_enable, both TX and RX in PC_PFC must be enabled. Missing one port =
    a "black-hole port" in the lossless domain: it drops packets itself while making the peer believe the link is healthy."""
    _run(cli, chip, pid, BA.audit_pfc, "port PFC enable")
