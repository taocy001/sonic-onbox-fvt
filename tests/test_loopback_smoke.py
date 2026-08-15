"""On-DUT smoke self-check: does hairpin loopback really send frames back into the pipeline (using chip counters, not packet capture).

Mechanism: cd enables lb, the CPU sends N known-unicast frames on EthernetN (dst points via static
FDB at ports[1] -- a different port), the frame loops back and re-enters the ingress port (RX_PKT
+N), then is forwarded out of it (p_out TX +N).
- Storm guard: dst is forwarded to ports[1] rather than back to this port, avoiding a self-loop
  storm of PHY loopback on frames "forwarded back to this port"; when observing p_out TX use
  enable_flood_safe (loopback pulls oper-up + the re-ingressed frame lands on an isolation VLAN and
  terminates, breaking the loop).
- Counting discipline (corrected via multi-expert review): on both devices `show c` has "delta since
  last show" semantics, so before/after subtraction is a known error mode (the base read consumes the
  display and includes the previous window's background noise; the difference can be negative / drowned
  in noise, making the negative assertion trivially true). The correct approach = clear -> drive traffic
  -> poll-accumulate + confirming read (same as framework.traffic.smoke_check).

Note: do not use "same-port scapy capture" to prove forwarding -- AF_PACKET treats the local TX echo
as a received packet, a false positive.
"""
import time

import pytest

pytestmark = pytest.mark.smoke


def _probe(traffic, cli, topo, n=50, smac=None):
    """Send N known-unicast frames on the ingress port (dst points via static FDB at p_out), clear -> drive traffic -> poll-accumulate + confirming read.
    Return (ingress-port RX total, egress-port TX total). All MACs come from topo.

    Forwarding VLAN selection: by default use default_vlan + SONiC static FDB; if the device declares
    `l2_home_forwarding: false` (SONiC: Vlan1 is a parking VLAN whose members are not pushed to ASIC,
    by design), switch to a **chip-level dedicated test VLAN** (bcm vlan + chip fdb, same mechanism as
    l2net) -- p_in joins this VLAN (PVID), p_out only adds an egress member **without touching PVID**
    (keeping the upper-layer enable_flood_safe isolation PVID to break the loop, preventing an FDB
    pointing at itself from forming a loop)."""
    from scapy.all import Ether, IP, UDP, Raw
    probe_dst = topo.mac("probe")
    smac = smac or topo.mac("src")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    chip_vlan = not topo.caps.has("l2_home_forwarding")
    if chip_vlan:
        vid = traffic.lb.use_test_vlan(3985, [p_in], restore_vid=traffic.default_vlan)
        out_bcm = traffic.lb.dut.bcm_of(p_out)
        traffic.lb.bsh.cmd(f"vlan add {vid} pbm={out_bcm} ubm={out_bcm}")  # egress member only
        traffic.lb.chip_fdb_add(vid, probe_dst, p_out)
    else:
        vid = traffic.default_vlan
        cli.fdb_static_add(vid, probe_dst, p_out.name)   # wait=True: internally waits for ASIC FDB to be really programmed
    try:
        pkt = (Ether(dst=probe_dst, src=smac) / IP(dst="1.1.1.1") /
               UDP() / Raw(b"SMOKE" + b"x" * 40))
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=n)
        rx = tx = 0
        deadline = time.time() + 3.0
        while rx < n * 0.9 and time.time() < deadline:
            time.sleep(0.4)
            rx += traffic.chip_counters(p_in).rx_pkt
            tx += traffic.chip_counters(p_out).tx_pkt
        # Confirming read: normal traffic has settled (+0); a slow self-replicating storm keeps growing, letting the upper-layer upper-bound assertion honestly expose it
        time.sleep(0.4)
        rx += traffic.chip_counters(p_in).rx_pkt
        tx += traffic.chip_counters(p_out).tx_pkt
        return rx, tx
    finally:
        if chip_vlan:
            traffic.lb.chip_fdb_del(vid, probe_dst)
            traffic.lb.drop_test_vlan()
        else:
            cli.fdb_static_del(vid, probe_dst)


def test_loopback_reingress_counter(traffic, cli, topo):
    """ports[0] has loopback enabled: send N known-unicast frames, chip RX_PKT should be +~N (real loopback re-ingress), and the
    **forwarding leg** must also be observed: p_out chip TX +~N (the re-ingressed frame is really FDB-directed out of p_out,
    rather than being dropped after re-ingress yet still falsely passing). First use traffic.smoke_check() (with retries + FDB
    waiting for ASIC programming, robust) to verify the loopback base, then use _probe to observe the forwarding leg; p_out uses
    enable_flood_safe to pull oper-up (otherwise TX is not counted) + an isolation PVID to break the re-ingress loop."""
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    assert traffic.smoke_check(), \
        f"{p_in.name} loopback re-ingress self-check failed (see RX delta in log)"
    n = 50
    traffic.lb.enable_flood_safe(p_out, 3990)   # p_out oper-up makes TX countable; the re-ingressed frame lands on the isolation VLAN and terminates
    try:
        rx, tx = _probe(traffic, cli, topo, n=n)
        assert n * 0.9 <= rx < 1_000_000, \
            f"{p_in.name} re-ingress: chip RX +{rx} (sent={n}; expected ~{n}, no storm)"
        assert n * 0.9 <= tx < 1_000_000, \
            f"re-ingressed frames were NOT forwarded out {p_out.name}: chip TX +{tx} (sent={n})"
    finally:
        traffic.lb.disable_flood_safe(p_out)


def test_negative_no_loopback_no_reingress(traffic, cli, topo):
    """Control: after disabling loopback, frames cannot be sent out / do not re-ingress, RX_PKT should be ~0.
    Under the new semantics (clear -> drive traffic -> accumulate read) this assertion truly holds: there is no more before/after noise difference masking a leak as <=2."""
    p = traffic.ports[0]
    traffic.lb.disable(p)
    try:
        rx, _tx = _probe(traffic, cli, topo, n=20, smac=topo.mac("src2"))
        assert rx <= 2, f"{p.name} still has re-ingress after loopback disabled (chip RX +{rx} of 20 sent)"
    finally:
        traffic.lb.enable(p)
