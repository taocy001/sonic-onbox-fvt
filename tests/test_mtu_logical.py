"""MTU and logical interfaces: port/PC/VLAN-IF MTU, jumbo, loopback, oversize-MTU egress routed-forwarding drop.
Ports reference topo.

MTU checks are layered:
- the jumbo case takes triple evidence: (1) ASIC port MTU attribute (SAI_PORT_ATTR_MTU, the dataplane ground truth) (2) ~9000B real-traffic
  jumbo forwarding (the dataplane forwarding chain is healthy) (3) whether the kernel netdev MTU actually takes effect.
- **(3) is an honest FAIL criterion and must not be downgraded**: if CONFIG_DB accepts 9216 but the kernel netdev silently caps it (neither
  rejecting nor honoring it), it stalls CPU-injected 9101-9216B frames (this framework drives traffic via scapy CPU injection, so the cap does
  real harm to the testable injection path). To argue "the cap only affects the CPU path and is harmless to the dataplane" one would have to
  actually send >9100B frames through the dataplane and prove they forward -- but the kernel cap is exactly what makes such injection
  impossible to send, so the cap is a real defect; keep it FAIL.
- egress MTU dataplane enforcement is verified with real traffic by test_egress_mtu_routed_drop (routed-frame path; the L2 flooding path is
  in test_storm_mtu_chip.py).
"""
import time

import pytest

from framework import l3probe
from framework.counters import ChipCounters

pytestmark = [pytest.mark.l3]


def _kernel_mtu(cli, port, want, tries=10):
    """Wait for the kernel netdev MTU to actually change to want (portmgrd->netdev application), return the final value."""
    val = ""
    for _ in range(tries):
        val = cli.sh.run(f"cat /sys/class/net/{port}/mtu", check=False).out.strip()
        if val == str(want):
            return val
        time.sleep(1)
    return val


def _asic_port_mtu(cli, asicdb, port, timeout=10.0):
    """Read SAI_PORT_ATTR_MTU of this port's SAI_OBJECT_TYPE_PORT from ASIC_DB (polling for orch's async programming).
    Returns an int (None if absent). The port oid is mapped via COUNTERS_PORT_NAME_MAP."""
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port}")
    if not oid:
        return None
    key = f"ASIC_STATE:SAI_OBJECT_TYPE_PORT:{oid}"
    end = time.time() + timeout
    val = None
    while time.time() < end:
        raw = asicdb.field(key, "SAI_PORT_ATTR_MTU")
        if raw and str(raw).isdigit():
            val = int(raw)
            if val >= 9216:
                return val
        time.sleep(0.5)
    return val


def test_port_mtu(cli, topo, config_guard):
    """Port MTU: CONFIG_DB persisted + **the kernel interface MTU actually takes effect** (portmgrd applies it to the netdev), not just a
    CONFIG_DB read. Set a value distinct from the default (8000) so a real change is observable. (The dataplane behavior of dropping oversize
    frames is covered with traffic by this file's test_egress_mtu_routed_drop (routed egress) and test_storm_mtu_chip.py (L2 flooding egress).)"""
    port = topo.port_name("c")
    rc, r = cli.config_raw(f"interface mtu {port} 8000")
    config_guard.defer_undo(f"interface mtu {port} 9100")  # restore default
    # previously skipped on CLI failure; `interface mtu` is an existing command (available on this device), so a failure is a real defect -> assert it succeeds
    assert rc == 0, f"interface mtu CLI failed: {r.err or r.out}"
    assert cli.db_hgetall("CONFIG_DB", f"PORT|{port}").get("mtu") == "8000", "CONFIG_DB MTU not written"
    applied = _kernel_mtu(cli, port, 8000)
    assert applied == "8000", f"MTU configured but not applied to kernel netdev {port}: /sys mtu={applied!r}"


@pytest.mark.traffic
def test_jumbo_frame_mtu(cli, traffic, topo, asicdb, config_guard):
    """Jumbo MTU (9216) triple evidence: ASIC port MTU attribute + ~9000B real-traffic forwarding + kernel netdev actually takes effect.

    (1) configure MTU 9216 on the two traffic ports -> CONFIG_DB persisted + ASIC SAI_PORT_ATTR_MTU >= 9216 (SONiC convention adds L2 header
       overhead, hence a >= check);
    (2) dataplane proof: static FDB steering, inject a ~9000B jumbo frame (below the kernel 9100 cap so sendp can emit it),
       clear->send->poll-accumulate and assert egress chip TX >= 0.9N (the jumbo is truly switched and forwarded);
    (3) the kernel netdev MTU must actually be 9216 (**honest FAIL criterion**): if the kernel silently caps it to 9100, it stalls
       CPU-injected 9101-9216B frames -- the device neither rejects nor honors it, keep it FAIL to expose."""
    from scapy.all import Ether, IP, UDP, Raw
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    for p in (p_in, p_out):
        rc, r = cli.config_raw(f"interface mtu {p.name} 9216")
        config_guard.defer_undo(f"interface mtu {p.name} 9100")
        assert rc == 0, f"interface mtu CLI failed on {p.name}: {r.err or r.out}"
        assert cli.db_hgetall("CONFIG_DB", f"PORT|{p.name}").get("mtu") == "9216", \
            f"CONFIG_DB MTU 9216 not written for {p.name}"
    # (1) ASIC dataplane ground truth: SAI_PORT_ATTR_MTU must be >= 9216 (not programmed / still the old value = jumbo did not reach the dataplane)
    for p in (p_in, p_out):
        asic_mtu = _asic_port_mtu(cli, asicdb, p.name)
        assert asic_mtu is not None and asic_mtu >= 9216, (
            f"jumbo MTU 9216 in CONFIG_DB but ASIC SAI_PORT_ATTR_MTU on {p.name} is "
            f"{asic_mtu!r} (< 9216): jumbo NOT applied to the dataplane port")
        # (3) the kernel netdev must actually take effect at 9216 (honest FAIL criterion, must not be downgraded to a warning): accepted into
        #    the DB yet silently capped at 9100 (neither rejecting nor honoring it), stalling CPU-injected >9100B frames -- keep it FAIL to
        #    expose. Placed after (1)/(2) so the ASIC and dataplane evidence is collected into the log first.
        applied = _kernel_mtu(cli, p.name, 9216)
        assert applied == "9216", (
            f"DEVICE DEFECT: jumbo MTU 9216 accepted into CONFIG_DB but kernel netdev {p.name} "
            f"shows mtu={applied!r} (silent cap, no error): "
            f"device neither rejects nor honors 9216; caps CPU-injected >9100B frames")
    # (2) dataplane proof: a ~9000B jumbo frame is truly forwarded to p_out via FDB steering
    n = 20
    vlan = traffic.default_vlan
    probe_dst = topo.mac("probe")
    pad = 9000 - 14 - 20 - 8                     # whole frame ~9000B (< kernel 9100 cap, sendp can emit it)
    pkt = (Ether(dst=probe_dst, src=topo.mac("src")) / IP(dst="1.1.1.1") /
           UDP() / Raw(b"J" * pad))
    traffic.lb.enable_flood_safe(p_out, 3990)    # p_out oper-up makes TX countable; re-ingress frames land in an isolated VLAN to break the loop
    cli.fdb_static_add(vlan, probe_dst, p_out.name)
    try:
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=n)
        # delta semantics: poll-accumulate + confirming read (same paradigm as smoke_check)
        tx = 0
        deadline = time.time() + 3.0
        while tx < n * 0.9 and time.time() < deadline:
            time.sleep(0.4)
            tx += traffic.chip_counters(p_out).tx_pkt
        time.sleep(0.4)
        tx += traffic.chip_counters(p_out).tx_pkt
        assert n * 0.9 <= tx < 1_000_000, (
            f"jumbo (~9000B) frames not forwarded out {p_out.name}: chip TX +{tx} "
            f"(sent={n}); jumbo dataplane forwarding broken despite ASIC MTU programmed")
    finally:
        cli.fdb_static_del(vlan, probe_dst)
        traffic.lb.disable_flood_safe(p_out)


@pytest.mark.traffic
def test_egress_mtu_routed_drop(cli, asicdb, dut, _lb, l3up, topo, config_guard):
    """Egress MTU dataplane enforcement (**routed-forwarding** path, storm-free): egress p_out MTU=1500, an injected >1500B routed frame should
    be dropped by the egress MTU check (does not egress); a same-route same-condition normal-size control flow ~N proves the forwarding path is
    healthy and the difference comes only from frame length. Reuses the l3probe anti-storm paradigm (p_in injects -> route to p_out -> re-ingress
    dropped because DMAC != router MAC, no storm).

    The criterion uses p_out **re-ingress RX** (loopback port: a frame truly emitted must re-ingress; TX may also count "send attempts scored as
    TX_ERR", so looking at TX alone can misjudge). If "egress MTU is not enforced in the dataplane", this case is expected to **honestly FAIL**,
    with the assertion message worded as DEVICE DEFECT."""
    topo.caps.require("loopback")
    from scapy.all import Raw, sendp
    route_a = topo.route("a")
    dst_ip = route_a.split("/")[0].rsplit(".", 1)[0] + ".5"
    n = 30
    with l3probe.TwoPortL3(cli, dut, _lb, topo, l3up) as s:
        assert s.rmac, "DEVICE DEFECT: router MAC (DEVICE_METADATA.mac) not found"
        cli.config_raw(f"route add prefix {route_a} nexthop {s.nh}")
        config_guard.defer_undo(f"route del prefix {route_a} nexthop {s.nh}")
        assert asicdb.has_route(route_a, timeout=10), "static route not programmed to ASIC"
        if not l3probe.wait_route(cli, route_a):
            pytest.fail(f"DEVICE DEFECT: route {route_a} not installed to kernel FIB; "
                        f"cannot drive routed MTU traffic")
        # lower the egress MTU to 1500 (CONFIG_DB + kernel confirm application -- dataplane enforcement is only meaningful once this precondition holds)
        rc, r = cli.config_raw(f"interface mtu {s.p_out.name} 1500")
        config_guard.defer_undo(f"interface mtu {s.p_out.name} 9100")
        assert rc == 0, f"interface mtu CLI failed on {s.p_out.name}: {r.err or r.out}"
        applied = _kernel_mtu(cli, s.p_out.name, 1500)
        assert applied == "1500", \
            f"MTU 1500 not applied to kernel netdev {s.p_out.name}: /sys mtu={applied!r}"
        # (1) normal-size control (~900B < 1500): under the same route/neighbor/MTU config it must forward ~N -- proving it isn't the environment failing to forward
        pkt_ok = s.make_pkt(dst_ip) / Raw(b"c" * 850)
        tx_ok = l3probe.tx_delta(_lb, dut, s.p_out, pkt_ok, s.p_in.name, n=n)
        assert n * 0.9 <= tx_ok < 100_000, (
            f"in-size control (~900B) not forwarded to {s.p_out.name} (chip TX={tx_ok}, sent={n}); "
            f"cannot judge egress MTU enforcement")
        # (2) oversize frame (~1900B > egress 1500): should be dropped by the egress MTU check, not physically egress.
        #    clear->send->poll-accumulate + confirming read; RX (re-ingress) = the hard criterion for a real egress.
        pkt_big = s.make_pkt(dst_ip) / Raw(b"o" * 1850)
        bsh = _lb.bsh
        bcm_out = dut.bcm_of(s.p_out)
        ChipCounters.clear(bsh)
        sendp(pkt_big, iface=s.p_in.name, count=n, verbose=False)
        rx = tx = 0
        deadline = time.time() + 3.0
        while rx < n * 0.9 and time.time() < deadline:
            time.sleep(0.4)
            c = ChipCounters.read(bsh, bcm_out)
            rx += c.rx_pkt
            tx += c.tx_pkt
        time.sleep(0.4)
        c = ChipCounters.read(bsh, bcm_out)
        rx += c.rx_pkt
        tx += c.tx_pkt
        assert rx < n * 0.5, (
            f"DEVICE DEFECT: egress MTU (1500) NOT enforced in the dataplane on {s.p_out.name}: "
            f"{rx}/{n} oversize (~1900B) routed frames physically egressed (loopback re-ingress RX; "
            f"chip TX={tx})")


def test_loopback_interface(cli, asicdb, config_guard, topo):
    """Loopback logical interface, independent of any physical port."""
    lo_ip = topo.loopback("a")
    rc, r = cli.config_raw("loopback add Loopback10")
    config_guard.defer_undo("loopback del Loopback10")
    # previously skipped on CLI failure; loopback add is an existing command, so a failure is a real defect -> assert it succeeds
    assert rc == 0, f"config loopback add failed: {r.err or r.out}"
    cli.config_raw(f"interface ip add Loopback10 {lo_ip}")
    config_guard.defer_undo(f"interface ip remove Loopback10 {lo_ip}")
    assert asicdb.has_route(lo_ip, timeout=8), "Loopback /32 route not programmed"


# test_subinterface: removed per user instruction (the product does not support this feature,
