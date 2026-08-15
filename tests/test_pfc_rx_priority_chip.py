"""Data-plane verification of PFC Rx per-priority narrowing.

Behavior under test: after a port is configured with `pfc_enable=<subset>`, **only the configured priorities'** PFC XOFF should
pause their corresponding egress queues; XOFF for unconfigured priorities must be ignored.

Hardware background: the chip only has a per-port PFC Rx switch, and the per-priority granularity lives in the PFC class profile
that the port points to (`TM_PFC_PRI_PROFILE`: one PFC enable bit per priority + a queue bitmap). If all ports share a single
fully-enabled profile, then XOFF for any priority pauses the corresponding queue -- exactly the faulty form this case rules out.

Topology (the framework's hairpin paradigm): a CPU-injected frame egresses directly from p_in (skipping ingress classification),
MAC-loops back into p_in where it is classified by trust_dscp, hits a static FDB unicast entry and is forwarded out p_out --
**p_out's egress queue** is determined by DSCP. The XOFF frames egress directly out p_out from the CPU and are received by p_out
itself via its MAC loopback (PFC is a MAC control frame, consumed by the MAC layer and not entering the forwarding pipeline), so
XOFF only acts on p_out's receive side and does not interfere with the egress queue of the data stream under test (the XOFF frames
themselves ride p_out's queue 0, while the queue under test is chosen elsewhere).

Verdict discipline: first do a **baseline sanity** (with no XOFF, the DSCP really lands on the expected queue), then check whether
that queue is blocked after XOFF is applied; the positive control (a configured priority must be paused) and the negative control
(an unconfigured priority must be let through) come as a pair, and if either side does not hold we FAIL honestly, never asserting one side only.
"""
import subprocess
import time

import pytest

from framework import qmeasure

try:
    from scapy.all import IP, UDP, Ether, Raw  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

pytestmark = [pytest.mark.qos, pytest.mark.traffic]

_SRC = "00:11:22:33:44:66"
_DST = "00:aa:bb:cc:dd:77"

_PFC_ON = 3          # the priority configured as lossless on p_out
_PFC_OFF = 1         # the unconfigured priority (negative control)
_DSCP_Q3 = 24        # -> AF3 -> queue 3
_DSCP_Q1 = 10        # -> AF1 -> queue 1
_COUNT = 400
_LOWER = _COUNT * 0.5

_FLOOD = "/home/admin/pfc_flood.py"

_FLOOD_SRC = r'''
import socket, struct, sys, time
D=b"\x01\x80\xc2\x00\x00\x01"; S=b"\x00\xde\xad\x0f\xc0\x01"; T=b"\x88\x08"
def frame(prio, q=0xFFFF):
    vec = 1 << int(prio)
    b = struct.pack("!HH", 0x0101, vec)
    for i in range(8):
        b += struct.pack("!H", q if (vec >> i) & 1 else 0)
    return D + S + T + b + b"\x00" * 28
iface, prio, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
buf = frame(prio)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
end = time.time() + secs
while time.time() < end:
    for _ in range(2000):
        s.send(buf)
s.close()
'''


@pytest.fixture(scope="module")
def _flood_tool(cli):
    """Place the flooding tool on the DUT (a quanta of 0xFFFF is only ~42us at 800G, so we must sustain >24k pps)."""
    cli.sh.run("cat > %s" % _FLOOD, stdin=_FLOOD_SRC)
    yield _FLOOD
    cli.sh.run("sudo pkill -f pfc_flood.py", check=False)


def _flood_start(cli, port, prio, secs=90):
    cli.sh.run("sudo pkill -f pfc_flood.py", check=False)
    time.sleep(2)
    cli.sh.run("sudo nohup python3 %s %s %d %d >/tmp/pfcflood.log 2>&1 &"
               % (_FLOOD, port, prio, secs), check=False)
    time.sleep(6)


def _flood_stop(cli):
    cli.sh.run("sudo pkill -f pfc_flood.py", check=False)
    time.sleep(2)


def _pfc_rx(cli, port, prio):
    oid = (cli.db_hgetall("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP") or {}).get(port)
    if not oid:
        return -1
    h = cli.db_hgetall("COUNTERS_DB", "COUNTERS:%s" % oid) or {}
    v = h.get("SAI_PORT_STAT_PFC_%d_RX_PKTS" % prio)
    return int(v) if v and str(v).isdigit() else -1


def _assert_flood_lands(cli, port, prio):
    """Confirm the XOFF is actually received by the port -- otherwise "the queue was not blocked" is a false negative."""
    a = _pfc_rx(cli, port, prio)
    time.sleep(6)
    b = _pfc_rx(cli, port, prio)
    assert a >= 0 and b - a > 10000, (
        "PFC XOFF flood is not reaching %s prio %d (PFC_%d_RX_PKTS delta=%s); "
        "cannot conclude anything about queue pausing" % (port, prio, prio, b - a))


def _pkt(dscp):
    return (Ether(dst=_DST, src=_SRC)
            / IP(dst="2.2.2.2", tos=dscp << 2) / UDP() / Raw(b"P" + b"x" * 40))


def _measure(cli, traffic, dscp, l2_fwd_vlan):
    return qmeasure.inject_measure(cli, traffic, _pkt(dscp), _DST,
                                   count=_COUNT, measure="out",
                                   lower=_LOWER, vlan=l2_fwd_vlan)


# We cannot use qmeasure.inject_measure while flooding XOFF: the XOFF frames egress directly from p_out's queue 0
# (CPU-directed egress), and a queue 0 delta in the hundreds of thousands would blow past the framework's STORM_CAP total
# upper bound. Here we only count the **queue under test**, and the storm cap only applies to it (queue 0 is the flood's own
# path, irrelevant to the verdict).
_Q_STORM_CAP = 20 * _COUNT


def _measure_queue_under_flood(cli, traffic, dscp, q, l2_fwd_vlan):
    """Inject classified traffic while XOFF is held, returning the delta on the queue under test, q."""
    import pytest as _pt
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    cand = qmeasure.queue_oids(cli, p_out.name)
    if q not in cand:
        _pt.fail("DEVICE DEFECT: no queue oid for %s:%d in COUNTERS_QUEUE_NAME_MAP"
                 % (p_out.name, q))
    oid = cand[q]
    cli.fdb_static_add(l2_fwd_vlan, _DST, p_out.name)
    try:
        base = qmeasure.queue_stat(cli, oid)
        traffic.send(p_in, _pkt(dscp), count=_COUNT)
        got = 0
        for _ in range(qmeasure.QPOLL):
            time.sleep(1)
            got = qmeasure.queue_stat(cli, oid) - base
            if got >= _LOWER:
                break
        time.sleep(1)
        got = qmeasure.queue_stat(cli, oid) - base
        assert got <= _Q_STORM_CAP, (
            "loop storm suspected on %s queue %d: delta %d > cap %d for %d injected"
            % (p_out.name, q, got, _Q_STORM_CAP, _COUNT))
        return got
    finally:
        cli.fdb_static_del(l2_fwd_vlan, _DST)


@pytest.fixture
def _pfc_on_out(cli, traffic):
    """Configure p_out with only lossless priority _PFC_ON (via the product config command)."""
    p_out = traffic.ports[1].name
    rc, r = cli.config_raw("interface pfc priority %s %d on" % (p_out, _PFC_ON))
    if rc != 0:
        pytest.skip("config interface pfc priority unavailable: %s"
                    % ((r.out or "") + (r.err or ""))[-160:])
    time.sleep(12)
    yield p_out
    cli.config_raw("interface pfc priority %s %d off" % (p_out, _PFC_ON))
    time.sleep(8)


def test_pfc_baseline_dscp_reaches_expected_queues(cli, traffic, l2_fwd_vlan):
    """Baseline sanity: with no XOFF, DSCP 24/10 land on queue 3/1 respectively.

    This is the prerequisite for the next two cases -- if the queue is wrong, "blocked / not blocked" is meaningless."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    with qmeasure.classified_egress(cli, traffic):
        g3 = _measure(cli, traffic, _DSCP_Q3, l2_fwd_vlan)
        g1 = _measure(cli, traffic, _DSCP_Q1, l2_fwd_vlan)
    assert qmeasure.dominant(g3) == 3, (
        "DSCP=%d expected to land on queue 3, deltas=%s" % (_DSCP_Q3, g3))
    assert qmeasure.dominant(g1) == 1, (
        "DSCP=%d expected to land on queue 1, deltas=%s" % (_DSCP_Q1, g1))


def test_pfc_configured_priority_pauses_its_queue(cli, traffic, l2_fwd_vlan,
                                                  _flood_tool, _pfc_on_out):
    """Positive control: p_out is configured with priority 3, so while priority-3 XOFF is flooded continuously queue 3 must be paused.

    If this case does not hold, XOFF simply did not take effect (a topology/flooding problem), and the negative control is meaningless."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p_out = _pfc_on_out
    with qmeasure.classified_egress(cli, traffic):
        _flood_start(cli, p_out, _PFC_ON)
        try:
            _assert_flood_lands(cli, p_out, _PFC_ON)
            got = _measure_queue_under_flood(cli, traffic, _DSCP_Q3, 3, l2_fwd_vlan)
        finally:
            _flood_stop(cli)
    assert got < _LOWER, (
        "queue 3 on %s forwarded %d/%d packets while priority %d XOFF was held; "
        "a configured lossless priority must pause its queue"
        % (p_out, got, _COUNT, _PFC_ON))


def test_pfc_unconfigured_priority_does_not_pause(cli, traffic, l2_fwd_vlan,
                                                  _flood_tool, _pfc_on_out):
    """Core case: p_out is configured with only priority 3, so while **unconfigured** priority-1 XOFF is flooded continuously,
    queue 1 must keep forwarding as usual.

    If all ports share a fully-enabled profile -> priority-1 XOFF would wrongly pause queue 1 and this case FAILs; under a correct
    implementation that priority has PFC=0 in the port-specific profile -> the XOFF is ignored."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p_out = _pfc_on_out
    with qmeasure.classified_egress(cli, traffic):
        _flood_start(cli, p_out, _PFC_OFF)
        try:
            _assert_flood_lands(cli, p_out, _PFC_OFF)
            got = _measure_queue_under_flood(cli, traffic, _DSCP_Q1, 1, l2_fwd_vlan)
        finally:
            _flood_stop(cli)
    assert got >= _LOWER, (
        "queue 1 on %s forwarded only %d/%d packets while XOFF was held for "
        "priority %d, which is NOT in its pfc_enable (only %d is); the port is "
        "honouring PFC on an unconfigured priority"
        % (p_out, got, _COUNT, _PFC_OFF, _PFC_ON))
