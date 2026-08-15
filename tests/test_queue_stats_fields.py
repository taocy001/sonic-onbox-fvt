"""Guard for the **counter-field completeness** of queue stats / ECN stats (a regression lock for the ECN capability defect).

Background: if the SAI capability table does not report WRED_ECN_MARKED_* -> queryStatsCapability excludes ECN ->
syncd never polls -> the COUNTERS_DB queue row is missing the two ECN entries. In this state a behavior-level case
would misreport "counters not polled" as "marking broken" -- this file first pins field existence so that a
behavior failure can be attributed to the marking chain itself.

Drop fields (DROPPED_*) watched in the same table: a missing field is a regression.

MC queue as a separate case: if the SAI MC ECN get fails, syncd double_confirm evicts the **entire MC queue from
polling** (all fields disappear together) -- this shape must be attributed differently from "only the two ECN
entries missing", so it is asserted separately.

Read-only: no traffic, no config change, no chip write.
"""
import time

import pytest

from framework import qmeasure

pytestmark = [pytest.mark.qos, pytest.mark.counters]

# Minimal field set that is in the syncd QUEUE_STAT group's polling list and that the chip should support per the capability table
_REQUIRED = {
    "SAI_QUEUE_STAT_PACKETS",
    "SAI_QUEUE_STAT_BYTES",
    "SAI_QUEUE_STAT_DROPPED_PACKETS",
    "SAI_QUEUE_STAT_DROPPED_BYTES",
    "SAI_QUEUE_STAT_WRED_DROPPED_PACKETS",
}
_ECN = {
    "SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS",
    "SAI_QUEUE_STAT_WRED_ECN_MARKED_BYTES",
}

_ECN_DEFECT = (
    "ECN queue stats absent: the SAI capability table did not report "
    "WRED_ECN_MARKED_* for this queue, so queryStatsCapability omits them and "
    "syncd never polls — the ECN counters are structurally unreadable in COUNTERS_DB")


def _queue_flexcounter_enabled(cli):
    h = cli.db_hgetall("CONFIG_DB", "FLEX_COUNTER_TABLE|QUEUE") or {}
    return h.get("FLEX_COUNTER_STATUS", "enable") == "enable"


def _row_fields(cli, oid, timeout=40):
    """Read the queue counter row's field set; right after swss restarts the flexcounter's first round hasn't landed, so poll and wait."""
    end = time.time() + timeout
    fields = {}
    while time.time() < end:
        fields = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
        if fields:
            return fields
        time.sleep(3)
    return fields


def _queues_by_type(cli, port_name):
    """{qid: oid} grouped by UC/MC. When TYPE_MAP is missing, fall back to the platform convention qid<8=UC."""
    oids = qmeasure.queue_oids(cli, port_name)
    tmap = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_TYPE_MAP") or {}
    uc, mc = {}, {}
    for q, o in oids.items():
        t = tmap.get(o, "")
        if t == "SAI_QUEUE_TYPE_MULTICAST":
            mc[q] = o
        elif t == "SAI_QUEUE_TYPE_UNICAST" or (not t and q < 8):
            uc[q] = o
    return uc, mc


def test_qsf1_uc_queue_counter_fields_complete(cli, topo):
    """QSF1 UC queue counter-field completeness: not one of the drop family or ECN family may be missing, and values must parse as integers.
    The two ECN entries missing on their own -> points precisely at the SAI capability-table defect (not a config problem, not a marking problem)."""
    if not _queue_flexcounter_enabled(cli):
        pytest.skip("QUEUE flex counter group disabled (counterpoll queue disable)")
    port = topo.misc_port(0).name
    uc, _ = _queues_by_type(cli, port)
    if not uc:
        pytest.fail(f"DEVICE DEFECT: no UC queue oids for {port} in "
                    "COUNTERS_QUEUE_NAME_MAP (queue flex counters not exposed)")
    q0 = sorted(uc)[0]
    fields = _row_fields(cli, uc[q0])
    assert fields, (f"COUNTERS row for {port}:{q0} empty after wait; queue stats "
                    f"not polled at all (flexcounter wedged or all counters "
                    f"rejected by capability probe)")
    missing_base = _REQUIRED - set(fields)
    assert not missing_base, (
        f"queue drop/base stats missing from COUNTERS row of {port}:{q0}: "
        f"{sorted(missing_base)} (have {sorted(fields)})")
    missing_ecn = _ECN - set(fields)
    assert not missing_ecn, (
        f"ECN stats missing from COUNTERS row of {port}:{q0}: {sorted(missing_ecn)} "
        f"-- {_ECN_DEFECT}")
    bad = {k: v for k, v in fields.items()
           if k in (_REQUIRED | _ECN) and not str(v).lstrip("-").isdigit()}
    assert not bad, f"non-integer counter values on {port}:{q0}: {bad}"


def test_qsf2_mc_queue_counter_row_intact_with_ecn(cli, topo):
    """QSF2 MC queue row intact + ECN fields present. Two bad shapes attributed separately:
    - the whole row disappears/empty -> syncd double_confirm evicts the entire MC queue from polling because some get failed
      (the typical shape of an MC ECN get regression after the capability is opened up, taking down all MC counters);
    - only the two ECN entries missing -> SAI capability-table regression (same as QSF1)."""
    if not _queue_flexcounter_enabled(cli):
        pytest.skip("QUEUE flex counter group disabled (counterpoll queue disable)")
    port = topo.misc_port(0).name
    _, mc = _queues_by_type(cli, port)
    if not mc:
        pytest.skip(f"no MC queues exposed for {port} on this image")
    qm = sorted(mc)[0]
    fields = _row_fields(cli, mc[qm])
    assert fields, (
        f"COUNTERS row for MC queue {port}:{qm} is empty: MC queue evicted from "
        f"polling (syncd double_confirm: some stat in the group-wide supported set "
        f"fails on MC queues -> the WHOLE queue loses stats). Check syncd log for "
        f"'RID ... can't provide the statistic'")
    missing_ecn = _ECN - set(fields)
    assert not missing_ecn, (
        f"ECN stats missing from MC queue {port}:{qm}: {sorted(missing_ecn)} "
        f"-- {_ECN_DEFECT}")
    missing_base = _REQUIRED - set(fields)
    assert not missing_base, (
        f"base/drop stats missing from MC queue {port}:{qm}: {sorted(missing_base)}")
