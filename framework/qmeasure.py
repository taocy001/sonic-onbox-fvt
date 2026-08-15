"""Shared helper for queue-level traffic measurement (generalizing the on-DUT-verified pattern from test_qos_remark_chip).

Mechanism: CPU-injected frames go straight out of p_in (bypassing ingress classification); only
after MAC loopback re-ingresses them into p_in does that port apply trust_dscp/trust_pcp
classification, which hits the static FDB and unicast-forwards them out p_out -- so the **egress
queue of p_out** is what the QoS classification decides. During the measurement window p_out must
also be looped (a re-ingressed frame hits the FDB pointing back to itself, gets filtered/dropped by
the same port, and does not form a loop), and disable_ipv6 mutes kernel multicast noise (a
storm guard for two loopback ports on the same VLAN).

Counting discipline: poll until the max single-queue delta reaches the lower bound, then a
confirming read, with a storm upper bound to abort.
"""
import time
from contextlib import contextmanager

from . import log

_log = log.get("qmeasure")

STORM_CAP = 100_000
QPOLL = 16


def queue_oids(cli, port_name):
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP") or {}
    return {int(k.split(":")[1]): v for k, v in m.items()
            if k.startswith(port_name + ":") and k.split(":")[1].isdigit()}


def queue_stat(cli, oid, field="SAI_QUEUE_STAT_PACKETS"):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
    v = h.get(field)
    return int(v) if v is not None and str(v).lstrip("-").isdigit() else 0


@contextmanager
def classified_egress(cli, traffic):
    """Classified measurement window: loop p_out + disable_ipv6 on both ports (guards against a noisy multicast loop storm)."""
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    for p in (p_in, p_out):
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{p.name}.disable_ipv6=1", check=False)
    traffic.loop(p_out)
    try:
        yield p_out
    finally:
        traffic.unloop(p_out)
        for p in (p_in, p_out):
            cli.sh.run(f"sysctl -qw net.ipv6.conf.{p.name}.disable_ipv6=0", check=False)


def inject_measure(cli, traffic, pkt, dst_mac, count=200, measure="out",
                   field="SAI_QUEUE_STAT_PACKETS", lower=None, vlan=None):
    """Inject count copies of pkt (dst static FDB points at p_out), return {queue: delta>0}.

    measure="out" reads the p_out egress queue (classified path, required for classification cases;
    caller must use classified_egress); measure="in" reads the p_in egress queue (CPU direct-tx
    path, sanity only). Exceeding the storm upper bound aborts via assert (refuses to count storm
    copies as traffic)."""
    import pytest
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    p_meas = p_out if measure == "out" else p_in
    lower = count * 0.5 if lower is None else lower
    cand = queue_oids(cli, p_meas.name)
    if not cand:
        pytest.fail(f"no queue oid for {p_meas.name} in "
                    "COUNTERS_QUEUE_NAME_MAP (queue flex counters not exposed)")
    # The default Vlan1 may be a parking VLAN (no forwarding); the static FDB must land on a real
    # forwarding VLAN, otherwise the frame cannot be sent out. The caller passes it via l2_fwd_vlan.
    vid = traffic.default_vlan if vlan is None else vlan
    cli.fdb_static_add(vid, dst_mac, p_out.name)
    try:
        base = {q: queue_stat(cli, o, field) for q, o in cand.items()}
        traffic.send(p_in, pkt, count=count)
        grew = {}
        for _ in range(QPOLL):
            time.sleep(1)
            cur = {q: queue_stat(cli, o, field) for q, o in cand.items()}
            grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
            if grew and max(grew.values()) >= lower:
                break
        time.sleep(1)
        cur = {q: queue_stat(cli, o, field) for q, o in cand.items()}
        grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
        total = sum(grew.values())
        assert total <= STORM_CAP, (
            f"loop storm suspected: queue deltas on {p_meas.name} total {total} > cap "
            f"{STORM_CAP} for {count} injected (deltas={grew})")
        return grew
    finally:
        cli.fdb_static_del(vid, dst_mac)


def dominant(grew):
    return max(grew, key=grew.get) if grew else None
