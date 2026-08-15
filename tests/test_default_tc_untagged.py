"""Real-traffic verification: SAI_PORT_ATTR_QOS_DEFAULT_TC makes **untagged** traffic land in the egress queue corresponding to the default TC.

Topology follows test_fdb::test_static_fdb_forwarding (a forwarding paradigm already PASSing on this box):
  p_in (=ports[0], with default_tc=CS6 => SAI DEFAULT_TC=6) injects an untagged non-IP frame -> loops back
  and re-enters, classified on ingress as default TC=6 -> static FDB steers unicast to p_out -> read p_out's
  **egress queue** (SAI_QUEUE_STAT_PACKETS), which should land on queue 6. A non-IP frame has no DSCP, so
  trust_dscp cannot classify it and it goes purely through the default-TC path.

Precondition: the orchestrator has already applied `default_tc CS6` + restarted swss so SAI DEFAULT_TC=6 takes effect (asserted/verified within the case, otherwise skip).
"""
import time

import pytest

try:
    from scapy.all import Ether, Dot1Q, IP, UDP, Raw  # noqa: F401
except ImportError:
    pass

pytestmark = [pytest.mark.qos, pytest.mark.traffic]

_QOS_DST = "00:aa:bb:cc:dd:71"
_N = 200
_EXPECT_TC = 6


def _queue_oids(cli, port_name):
    m = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP")
    return {int(k.split(":")[1]): v for k, v in m.items()
            if k.startswith(port_name + ":") and k.split(":")[1].isdigit()}


def _queue_pkts(cli, oid):
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    v = h.get("SAI_QUEUE_STAT_PACKETS")
    return int(v) if v is not None and str(v).isdigit() else 0


def _sai_default_tc(cli, port_name):
    pm = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
    oid = pm.get(port_name)
    if not oid:
        return None
    v = cli.db_hgetall("ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_PORT:{oid}").get(
        "SAI_PORT_ATTR_QOS_DEFAULT_TC")
    return int(v) if v is not None and str(v).isdigit() else None


def _measure(cli, traffic, _lb, vlan, pkt):
    """Static FDB steers p_in->p_out, loop back p_out + isolate_pvid to break self-loop, inject pkt, return p_out per-queue delta."""
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    cand = _queue_oids(cli, p_out.name)
    if not cand:
        pytest.fail(f"no queue oid for {p_out.name} in COUNTERS_QUEUE_NAME_MAP")
    cli.fdb_static_add(vlan, _QOS_DST, p_out.name)
    try:
        traffic.loop(p_out)
        time.sleep(1)
        _lb.isolate_pvid(p_out, 3990)
        base = {q: _queue_pkts(cli, o) for q, o in cand.items()}
        traffic.send(p_in, pkt, count=_N)
        grew = {}
        for _ in range(16):
            time.sleep(1)
            cur = {q: _queue_pkts(cli, o) for q, o in cand.items()}
            grew = {q: cur[q] - base[q] for q in cand if cur[q] - base[q] > 0}
            if grew and max(grew.values()) >= _N * 0.5:
                break
        return grew
    finally:
        try:
            traffic.unloop(p_out)
        except Exception:
            pass
        cli.fdb_static_del(vlan, _QOS_DST)


def test_untagged_lands_in_default_tc_queue(cli, traffic, asicdb, config_guard, topo, _lb, l2_fwd_vlan):
    """Untagged non-IP frame -> lands in the egress queue corresponding to default_tc (=6)."""
    p_in = traffic.ports[0]
    tc = _sai_default_tc(cli, p_in.name)
    if tc != _EXPECT_TC:
        pytest.skip(f"{p_in.name} SAI DEFAULT_TC={tc} != {_EXPECT_TC}; run c2_setup (default_tc CS6 + restart swss) first")
    pkt = Ether(dst=_QOS_DST, src="00:11:22:33:44:55", type=0x88b5) / Raw(b"\xa5" * 60)
    grew = _measure(cli, traffic, _lb, l2_fwd_vlan, pkt)
    assert grew, f"no egress queue advanced on {traffic.ports[1].name} for untagged frames (forwarding broken?)"
    top_q = max(grew, key=grew.get)
    assert top_q == _EXPECT_TC, (
        f"untagged frame with port default_tc={_EXPECT_TC} landed in queue {top_q} "
        f"(deltas={grew}); default TC NOT applied to untagged traffic (fix ineffective)")


def test_dscp_ip_not_overridden_by_default_tc(cli, traffic, asicdb, config_guard, topo, _lb, l2_fwd_vlan):
    """Scope regression: an untagged IP frame with DSCP=46 (EF->TC5->queue5) on a trust_dscp port is
    classified by DSCP to queue5 and not stolen by default_tc(6) -- proving the fix only affects genuinely
    unclassified untagged traffic and does not break DSCP classification."""
    p_in = traffic.ports[0]
    if _sai_default_tc(cli, p_in.name) != _EXPECT_TC:
        pytest.skip("default_tc not applied on injection port")
    pkt = (Ether(dst=_QOS_DST, src="00:11:22:33:44:66")
           / IP(dst="10.0.0.9", tos=0xB8) / UDP() / Raw(b"x" * 40))
    grew = _measure(cli, traffic, _lb, l2_fwd_vlan, pkt)
    assert grew, "no egress queue advanced for DSCP IP frames"
    top_q = max(grew, key=grew.get)
    print(f"DSCP=46 IP -> egress queue deltas {grew} (expect dominant queue 5=EF)")
    assert top_q != _EXPECT_TC, (
        f"untagged DSCP=46 IP frame landed in default_tc queue {top_q} "
        f"(deltas={grew}); default_tc wrongly overrode DSCP classification (fix over-reaches)")
