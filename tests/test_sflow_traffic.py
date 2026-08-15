"""sFlow: sample data-plane traffic -> the local collector receives a flow sample with the probe signature.

The collector IP is bound to a local dummy port (LocalPeerIP) -- an hsflowd datagram sent
to a locally reachable address always egresses via **lo**, so the collector must capture on
lo (it will never be seen on a front-panel netdev).
"""
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.traffic]

# explicit low sample rate: the default rate scales with port speed (1:N, N easily tens of
# thousands), so the original test's 500-packet run expecting ~0 samples was a false failure
IFACE_RATE = 256


def test_sflow_samples_to_collector(cli, dut, _lb, config_guard, topo):
    """Low-rate sampling + a fixed known-unicast injection -> the collector (lo) receives flow samples of the same order of magnitude as the rate.

    Input fixes (review: high):
      1) configure per-interface sample-rate=256 with defer_undo (the original test neither set
         a rate nor cleaned up the leaked interface enable);
      2) inject rate*20 known-unicast packets -- a static FDB pins the dmac to the second port
         (not looped) to keep unknown-unicast flooding from running away;
      3) capture on lo and only count flow samples carrying the probe signature, asserting the
         sample count within two-sided bounds [expected/3, expected*3] (a single >0 bound would
         be falsely passed by counter-sample datagrams).
    """
    topo.caps.require("sflow")   # structural skip if the device self-declares no support
    from scapy.all import Ether, IP, UDP, Raw, sendp
    from responders.collector import SflowCollector
    from topo.virtual_link import LocalPeerIP

    collector_ip = topo.server("sflow_collector")
    p_in, p_out = dut.pick_test_ports(2)
    dv = topo.default_vlan
    smac = "00:de:ad:be:ef:52"   # probe signature: the sampled original header must contain the bytes of these two MACs
    dmac = "00:aa:bb:cc:dd:52"

    peer = LocalPeerIP(cli, collector_ip)
    peer.setup()
    try:
        assert cli.config_raw("sflow enable")[0] == 0, \
            "DEVICE DEFECT: config sflow enable failed"
        config_guard.defer_undo("sflow disable")
        cli.config_raw(f"sflow collector add c1 {collector_ip}")
        config_guard.defer_undo("sflow collector del c1")
        cli.config_raw(f"sflow interface sample-rate {p_in.name} {IFACE_RATE}")
        config_guard.defer_undo(f"sflow interface sample-rate {p_in.name} 0")
        rc, r = cli.config_raw(f"sflow interface enable {p_in.name}")
        config_guard.defer_undo(f"sflow interface disable {p_in.name}")   # fix: the original test leaked this config
        assert rc == 0, f"sflow interface enable failed: {r.err or r.out}"

        # loop only the ingress port (enable waits internally for oper-up); p_out is not looped
        # -- known unicast leaving p_in terminates naturally at the p_out egress and never
        # returns (looping both ports + flooding = a self-looping storm, strictly forbidden)
        _lb.enable(p_in)
        # known unicast: a static FDB pins the dmac to p_out (wait=True waits for the ASIC FDB
        # to actually program before injecting)
        cli.fdb_static_add(dv, dmac, p_out.name)
        try:
            burst = IFACE_RATE * 20           # expect ~20 samples
            expected = burst / IFACE_RATE
            pkt = (Ether(dst=dmac, src=smac) / IP(dst="10.0.0.1") /
                   UDP() / Raw(b"SFLOWTRAF" + b"x" * 120))
            with SflowCollector("lo", sig=[smac, dmac]) as col:
                sendp(pkt, iface=p_in.name, count=burst, inter=0.0005, verbose=False)
                time.sleep(2.5)               # hsflowd batch flush has ~1s-scale latency
            got = col.sample_count()
            # two-sided bounds: the lower bound proves sampling really happens at the rate
            # (non-zero and same order); the upper bound guards against a false pass from
            # flooding / storm amplification
            lo_b, hi_b = max(1, expected / 3), expected * 3
            assert lo_b <= got <= hi_b, (
                f"flow samples with probe signature at collector = {got}, outside "
                f"[{lo_b:.0f},{hi_b:.0f}] (burst={burst}, rate=1/{IFACE_RATE}, "
                f"expected~{expected:.0f})")
        finally:
            cli.fdb_static_del(dv, dmac)
            _lb.disable(p_in)
    finally:
        peer.teardown()
