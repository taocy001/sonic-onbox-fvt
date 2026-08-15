"""Integrated scenarios: VLAN isolation / inter-VLAN L3 routing (chip-counter verified, hairpin loopback)."""
import time

import pytest

from framework import vlanchk

pytestmark = [pytest.mark.scenario, pytest.mark.traffic]

# Injected frame count and tolerances (consistent with test_vlan_chip / test_fdb_chip): chip
# forwarding should be exactly +N, but the loopback path / background traffic / counter
# polling have jitter, so the "received" lower bound is N*0.8; the "should not receive"
# (isolation) upper bound is a small background tolerance; the upper bound catches a runaway
# self-loop storm.
_N = 100
_RECV_LOWER = _N * 0.8
_ISO_UPPER = 5
_STORM_UPPER = 100_000


def _pvlan_default(bsh, cd):
    """Read-only bcmcmd: read a bcm port's default VLAN (PVID). Returns an int or None."""
    import re
    out = bsh.cmd(f"pvlan show {cd}")
    m = re.search(r"default VLAN is (\d+)", out)
    return int(m.group(1)) if m else None


def _flow_totals(traffic, ports, until=None, timeout=3.0):
    """Call after clear_chip_counters -> send: poll and **accumulate** each port's TX/RX
    totals since clear.

    This diag `show c` has "delta since last show/clear" semantics (clear/show are per-port
    independent) -- a before/after subtraction would double-subtract noise (the base read
    already consumed the display, the second read is itself the delta, and subtracting the
    base again can squash the positive control into a false failure and cancel a real leak
    into a false pass, the same known-bad pattern already explicitly fixed in
    traffic.smoke_check). Exits early once until(tx,rx) is true; then does one confirmation
    read to catch a late leak / slow storm. Returns two dicts (tx_totals, rx_totals) as
    {port.name: int}."""
    tx = {p.name: 0 for p in ports}
    rx = {p.name: 0 for p in ports}
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(0.4)
        for p in ports:
            d = traffic.chip_counters(p)
            tx[p.name] += d.tx_pkt
            rx[p.name] += d.rx_pkt
        if until and until(tx, rx):
            break
    time.sleep(0.5)
    for p in ports:
        d = traffic.chip_counters(p)
        tx[p.name] += d.tx_pkt
        rx[p.name] += d.rx_pkt
    return tx, rx


def test_vlan_isolation(cli, traffic, config_guard, topo, _lb, dut):
    """Different VLANs are isolated from each other (positive control + chip-side
    confirmation; **dedicated flood VLAN** to prevent degradation):
    (1) Positive control: member p3, in the same dedicated VLAN-D as pin, should receive
        pin's broadcast flood (chip TX +~= N) -- proves the flood mechanism itself works,
        otherwise a later "received 0" is a false negative and the isolation assert is
        meaningless;
    (2) After moving pother to a separate VLAN-a, read-only `pvlan show` confirms its chip
        PVID has switched to VLAN-a (config really lands on the chip);
    (3) Inject the broadcast again; oper-up pother (VLAN-a) chip TX should be ~= 0 (a
        different VLAN does not receive the flood).

    Degradation prevention: pin's flood domain goes into a **dedicated VLAN-D (pin+p3, a few
    ports)**, so the broadcast is only replicated within these ports, rather than the
    production Vlan1000's massive 160-port replication (which drags into degradation across
    runs). Positive-control member port p3 uses flood_safe (loop gives egress TX + ingress
    isolation breaks the loop); pother gets its own loopback to bring it oper-up (a different
    VLAN receives no flood, and TX=0 is meaningful isolation evidence rather than the constant
    0 of an oper-down port)."""
    from scapy.all import Ether, IP, UDP, Raw

    topo.caps.require("loopback")

    pin, pother = traffic.ports[0], traffic.ports[1]
    p3 = topo.misc_port(0)
    dvlan = topo.default_vlan
    vid = topo.vlan("a")
    if len({pin.name, pother.name, p3.name}) < 3:
        pytest.skip("need 3 distinct ports for scoped isolation test")
    cd = dut.bcm_of(pother)
    pkt = Ether(dst=topo.mac("bcast"), src=topo.mac("src")) / IP() / UDP() / Raw(b"x" * 40)

    cli.intf_startup(p3.name)
    # Dedicated flood VLAN-D: pin + p3 (positive-control member). pin PVID points to VLAN-D,
    # flooding stays within these two ports.
    _lb.use_test_vlan(2098, [pin, p3], restore_vid=dvlan)
    _lb.enable_flood_safe(p3, 3991)   # p3 loop + isolation: gets TX from the flood, re-entry terminates without a storm
    cli.sh.run("sonic-clear fdb all", check=False)
    time.sleep(1)
    try:
        # (1) Positive control: VLAN-D member p3 should receive pin's broadcast flood.
        # Readout clear -> poll-accumulate + confirmation read (delta semantics; no base/after
        # subtraction -- double-subtracting noise would produce a false failure)
        traffic.clear_chip_counters()
        traffic.send(pin, pkt, count=_N)
        tx, _rx = _flow_totals(traffic, [p3],
                               until=lambda tx, rx: tx[p3.name] >= _RECV_LOWER)
        assert _RECV_LOWER <= tx[p3.name] < _STORM_UPPER, (
            f"positive control failed: same-VLAN member {p3.name} did not receive broadcast flood "
            f"(chip TX={tx[p3.name]}, expected ~{_N}); isolation assert would be a false negative")

        # Move pother to a separate VLAN-a (SONiC config, verifies config->chip)
        cli.config_raw(f"vlan add {vid}")
        config_guard.defer_undo(f"vlan del {vid}")
        cli.config_raw(f"vlan member del {dvlan} {pother.name}")
        config_guard.defer_undo(f"vlan member add -u {dvlan} {pother.name}")
        cli.config_raw(f"vlan member add -u {vid} {pother.name}")
        config_guard.defer_undo(f"vlan member del {vid} {pother.name}")
        time.sleep(1)

        # (2) Chip-side confirmation: pother's default VLAN (PVID) has switched to VLAN-a
        pvid = None
        for _ in range(10):
            pvid = _pvlan_default(_lb.bsh, cd)
            if pvid == vid:
                break
            time.sleep(0.5)
        if pvid != vid and not vlanchk.chip_member(cli, dut, vid, pother, untagged=True):
            # A healthy SONiC programs the port default-VLAN register correctly; an unswitched
            # PVID is usually degraded residue of a port leaking out of the default VLAN (undo
            # silently failed); the bitmap is fallback evidence, and data-plane traffic
            # adjudicates true/false.
            pytest.fail(
                f"access-port VLAN change not on chip: {pother.name} PVID={pvid} and not in "
                f"vlan {vid} untagged bitmap; cannot assert isolation before config reaches chip")

        # (3) pother is oper-up (brought up by loopback) but in VLAN-a; it should not receive
        # pin@VLAN-D's broadcast flood. VLAN config churn sits between (1) and (3), so (3)
        # concurrently reads p3 (positive control) and pother (isolation) **within the same
        # injection** -- if the flood breaks midway, p3 fails first and pother=0 no longer
        # passes vacuously.
        _lb.enable(pother)
        time.sleep(1)
        traffic.clear_chip_counters()
        traffic.send(pin, pkt, count=_N)
        tx3, _rx3 = _flow_totals(traffic, [p3, pother],
                                 until=lambda tx, rx: tx[p3.name] >= _RECV_LOWER)
        assert _RECV_LOWER <= tx3[p3.name] < _STORM_UPPER, (
            f"positive control failed during isolation step: same-VLAN member {p3.name} chip "
            f"TX={tx3[p3.name]} (expected ~{_N}); pother reading 0 would be vacuous")
        assert tx3[pother.name] <= _ISO_UPPER, (
            f"VLAN isolation broken: oper-up port {pother.name} in VLAN {vid} received "
            f"{tx3[pother.name]} frames flooded from {pin.name} (VLAN-D; control {p3.name} "
            f"got {tx3[p3.name]})")
    finally:
        _lb.disable(pother)
        _lb.disable_flood_safe(p3)
        _lb.drop_test_vlan()
        cli.sh.run("sonic-clear fdb all", check=False)


def _wait_neigh(asicdb, ip, mac, tries=20):
    """Poll ASIC_DB NEIGHBOR_ENTRY: returns True if it matches this IP and DST_MAC == mac
    (neighbor resolution really reached the chip)."""
    want = mac.upper()
    for _ in range(tries):
        for k in asicdb.objects("SAI_OBJECT_TYPE_NEIGHBOR_ENTRY"):
            if ip in k and (asicdb.field(k, "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS")
                            or "").upper() == want:
                return True
        time.sleep(0.5)
    return False


def test_inter_vlan_routing(cli, traffic, config_guard, asicdb, topo, dut, _lb):
    """Inter-VLAN L3 routing (real traffic): p_in@VLAN-a SVI injects an IP packet with "dest
    in the VLAN-b SVI subnet, outer DMAC = router MAC" -> re-enters the pipeline via p_in MAC
    loopback -> DUT **routes across VLANs** to VLAN-b -> hits the static neighbor/FDB in
    VLAN-b -> physically egresses the destination SVI member port p_out (chip TX +~= N).

    Beyond verifying RIF / connected-route programming, this uses MAC loopback + scapy to
    drive real traffic and asserts the **destination SVI port's chip TX** -- proving L3
    forwarding between two SVIs really happens on the chip.

    Key (same pattern as test_l3_forward_traffic): the destination port p_out must also be
    **oper-up** for its egress chip TX (MIB_TPKT) to increment -- p_out (ports[1]) is only
    admin-up and, without loopback, is oper-down with egress counts stuck at 0 (root cause of
    the TX delta=0 false negative). So enable MAC loopback on p_out to bring it oper-up.
    Storm-free: after routing, the frame leaving p_out has DMAC = neighbor MAC (nbr_mac); on
    re-entry into VLAN-b via loopback it hits the static FDB (nbr_mac->p_out) = the ingress
    port itself and is dropped by split-horizon, not forwarded again (equivalent to the L3
    pattern's mechanism where the re-entering frame is dropped because DMAC != router MAC).
    Neighbor/FDB are programmed in place before injecting, and the assert carries an upper
    bound to catch a runaway storm. Ports/VLANs/subnets all come from topo."""
    from scapy.all import Ether, IP, UDP, Raw
    import ipaddress

    topo.caps.require("loopback")

    p_in, p_out = traffic.ports[0], traffic.ports[1]   # ports[0] already has MAC loopback enabled (ingress stimulus port)
    dvlan = topo.default_vlan
    vid_a = topo.vlan("a")
    vid_b = topo.vlan("b")
    neta = topo.subnet("a")
    netb = topo.subnet("b")
    ipa = f"{neta['dut']}/{neta['prefix']}"
    ipb = f"{netb['dut']}/{netb['prefix']}"
    cidrb = str(ipaddress.ip_network(ipb, strict=False))
    nbr_ip = netb["peer"]            # destination host in the VLAN-b subnet (next-hop)
    nbr_mac = "00:aa:bb:cc:dd:b2"    # that host's MAC (static neighbor + static FDB point to p_out)

    # 1) Create two VLANs, move p_in/p_out into them untagged (leaving the default VLAN)
    cli.config_raw(f"vlan add {vid_a}")
    config_guard.defer_undo(f"vlan del {vid_a}")
    cli.config_raw(f"vlan add {vid_b}")
    config_guard.defer_undo(f"vlan del {vid_b}")
    for port, vid in ((p_in.name, vid_a), (p_out.name, vid_b)):
        cli.config_raw(f"vlan member del {dvlan} {port}")
        config_guard.defer_undo(f"vlan member add -u {dvlan} {port}")
        cli.config_raw(f"vlan member add -u {vid} {port}")
        config_guard.defer_undo(f"vlan member del {vid} {port}")

    # 1.5) First bring p_out oper-up via loopback: **the kernel installs the connected route
    # only when the Vlan interface is up (must have an up member)** (with the member down the
    # ASIC has no such route; it appears immediately once brought up). p_in is already looped
    # by the traffic fixture.
    traffic.loop(p_out)

    # 2) Configure IPs on the two SVIs (generates RIF + connected route)
    ra = cli.config(f"interface ip add Vlan{vid_a} {ipa}")
    config_guard.defer_undo(f"interface ip remove Vlan{vid_a} {ipa}")
    rb = cli.config(f"interface ip add Vlan{vid_b} {ipb}")
    config_guard.defer_undo(f"interface ip remove Vlan{vid_b} {ipb}")

    def _svi_rif(vid):
        # Find this SVI's RIF precisely by VLAN oid -- a count-based assert would be fooled by
        # "only one of the two got created"
        vk = asicdb.find("SAI_OBJECT_TYPE_VLAN", SAI_VLAN_ATTR_VLAN_ID=vid)
        if not vk:
            return None
        # Key looks like ASIC_STATE:SAI_OBJECT_TYPE_VLAN:oid:0x26...; the RIF attribute value
        # carries the "oid:" prefix, which must be kept or it never matches (once produced a
        # false "missing RIF")
        void = vk[0].split(":", 2)[2]
        return asicdb.find("SAI_OBJECT_TYPE_ROUTER_INTERFACE",
                           SAI_ROUTER_INTERFACE_ATTR_VLAN_ID=void) or None

    rif_a = rif_b = None
    for _ in range(20):
        rif_a = rif_a or _svi_rif(vid_a)
        rif_b = rif_b or _svi_rif(vid_b)
        if rif_a and rif_b:
            break
        time.sleep(0.5)
    if not (rif_a and rif_b):
        # Forensics of the programming-path intermediate state: CLI output + CONFIG_DB/APPL_DB
        # keys, to locate which hop broke
        cfg = cli.db_keys("CONFIG_DB", f"VLAN_INTERFACE|Vlan{vid_a}*")
        app = cli.db_keys("APPL_DB", f"INTF_TABLE:Vlan{vid_a}*")
        diag = (f"cli_a rc={getattr(ra, 'rc', '?')} out={getattr(ra, 'out', '')[:120]!r}; "
                f"cli_b rc={getattr(rb, 'rc', '?')} out={getattr(rb, 'out', '')[:120]!r}; "
                f"CONFIG_DB={cfg}; APPL_DB={app}")
        assert rif_a, (
            f"VLAN-a SVI {vid_a} RIF not in ASIC (ingress L3 context missing -> my-station "
            f"hit would blackhole routed frames); {diag}")
        assert rif_b, f"VLAN-b SVI {vid_b} RIF not in ASIC; {diag}"
    assert asicdb.has_route(cidrb, timeout=8), "VLAN-b connected route not programmed"

    # An ingress untagged frame must land in VLAN-a to be routed by the VLAN-a RIF: wait for
    # p_in's chip PVID to switch to vid_a
    cd_in = dut.bcm_of(p_in)
    pvid_in = None
    for _ in range(10):
        pvid_in = _pvlan_default(_lb.bsh, cd_in)
        if pvid_in == vid_a:
            break
        time.sleep(0.5)
    # Chip PVID unreadable (pvlan show not readable on this image) = measurement-mechanism
    # guard, keep the skip (D boundary); readable but not switched to vid_a = access-port PVID
    # config did not land on the chip = device defect, expose via hard failure (A).
    if pvid_in is None:
        pytest.skip("could not read chip PVID via 'pvlan show' on this device")
    if pvid_in != vid_a and not vlanchk.chip_member(cli, dut, vid_a, p_in, untagged=True):
        # Same as test_vlan_isolation: a healthy SONiC programs the PVID correctly; when not
        # switched, fall back to the chip untagged bitmap, and the inter-VLAN routing traffic
        # assert at the end of this test adjudicates true/false.
        pytest.fail(
            f"p_in {p_in.name} chip PVID={pvid_in} and not in vlan {vid_a} "
            f"untagged bitmap; ingress untagged frame would not land in VLAN-a SVI "
            "(config->chip PVID/untagged programming broken)")

    rmac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")
    # Router MAC is a basic attribute of every configured SONiC device; its absence means
    # broken device metadata -- expose via hard failure rather than skip.
    assert rmac, "router MAC (DEVICE_METADATA.mac) not found in CONFIG_DB (device metadata broken)"

    # 3) In VLAN-b: static neighbor (next-hop resolution) + static FDB (points the dest to p_out)
    cli.neigh_set(nbr_ip, nbr_mac, f"Vlan{vid_b}")
    cli.fdb_static_add(vid_b, nbr_mac, p_out.name)
    try:
        assert _wait_neigh(asicdb, nbr_ip, nbr_mac), (
            f"neighbor {nbr_ip}->{nbr_mac} not programmed to ASIC before traffic; "
            "inter-VLAN nexthop unresolved")
        # Bring the destination SVI member port oper-up (so egress chip TX is observable). By
        # now the static FDB (nbr_mac->p_out) is programmed, so after routing the frame
        # re-enters via p_out loopback and hits that FDB = the ingress port itself, dropped by
        # split-horizon, no storm. Teardown disables loopback.
        traffic.loop(p_out)
        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=neta["peer"], dst=nbr_ip, ttl=64) / UDP() / Raw(b"x" * 40))

        def _svi_rx(v):
            # Kernel SVI receive-packet count: used for slow-path discrimination (hardware
            # routing does not enter the kernel; this only increments when frames are trapped
            # to the CPU)
            import json as _json
            r = cli.sh.run(f"ip -s -j link show Vlan{v}", check=False)
            try:
                return int(_json.loads(r.out)[0]["stats64"]["rx"]["packets"])
            except Exception:  # noqa: BLE001
                return None

        # SVI-path content-rewrite evidence (optional capability, same injection window): the
        # router-port path's mirror content evidence (test_l3_forward_content_rewrite) cannot
        # substitute for the SVI path -- the SVI is precisely a known defect hotspot.
        # Platforms with mirror->netdev observation capability mirror p_out egress to cpu0 to
        # capture the real routed-and-rewritten frame (mirror is port-level egress replication,
        # does not depend on p_out loopback re-entry, and is not subject to the tagged
        # content-capture storm limitation); platforms without this capability run only the
        # counting assert (missing capability is not a defect; capability detection is in
        # topology/profiles.yaml).
        mc = cap = None
        if topo.caps.has("mirror_cpu_capture"):
            from framework.collector import MirrorCollector
            from framework.traffic import Capture
            mc = MirrorCollector(_lb.bsh, dut)
            mc.enable(p_out)
            cap = Capture(p_out.name, inbound=False).__enter__()
        try:
            # Readout clear -> poll-accumulate + confirmation read (delta semantics; the
            # original base/after subtraction double-subtracts noise under these semantics and
            # would breach the 0.9N lower bound, causing intermittent false failures)
            traffic.clear_chip_counters()
            ka0 = _svi_rx(vid_a)
            traffic.send(p_in, pkt, count=_N)
            tx, rx = _flow_totals(traffic, [p_out, p_in],
                                  until=lambda tx, rx: tx[p_out.name] >= _N * 0.9)
        finally:
            if cap is not None:
                cap.__exit__(None, None, None)
            if mc is not None:
                mc.disable()
        ka1 = _svi_rx(vid_a)
        krx = (ka1 - ka0) if (ka0 is not None and ka1 is not None) else None
        # Lower bound: >= N*0.9 proves real forwarding to the destination SVI port after
        # inter-VLAN routing; upper bound: catches a runaway storm. The failure message
        # carries an evidence chain: p_in RX (did the frame re-enter the chip) + kernel SVI-a
        # RX (slow-path discrimination: ~N = frames trapped into CPU with hardware L3 not
        # forwarding; 0 = hardware blackhole).
        assert _N * 0.9 <= tx[p_out.name] < _STORM_UPPER, (
            f"inter-VLAN routed traffic not forwarded to dest SVI port {p_out.name}: "
            f"chip TX={tx[p_out.name]} (expected ~{_N}; VLAN-a SVI {vid_a} -> VLAN-b SVI {vid_b}); "
            f"evidence: p_in {p_in.name} chip RX={rx[p_in.name]}, kernel Vlan{vid_a} RX "
            f"delta={krx} (~{_N}=CPU slow-path w/ policer, 0=hw blackhole; known SONiC defect: "
            f"SVI neighbor l3-egress programmed Drop=yes, check `l3 egress show`), rmac={rmac}")
        if cap is not None:
            # Content-rewrite assertions (SVI path): DMAC->neighbor MAC (already in the
            # signature filter), SMAC->router MAC, TTL 64->63
            fwd = [f for f in cap.packets
                   if f.haslayer(IP) and f[IP].dst == nbr_ip
                   and f[Ether].dst.lower() == nbr_mac.lower()]
            assert fwd, (
                f"no routed frame captured via egress mirror on dest SVI port {p_out.name} "
                f"(counting passed but content evidence missing: DMAC-rewritten frame absent)")
            f0 = fwd[0]
            assert f0[Ether].src.lower() == rmac.lower(), (
                f"SVI-path egress SMAC not rewritten to router MAC: got {f0[Ether].src}, "
                f"want {rmac}")
            assert f0[IP].ttl == 63, (
                f"SVI-path TTL not decremented on inter-VLAN routing: got {f0[IP].ttl}, want 63")
    finally:
        traffic.unloop(p_out)
        cli.fdb_static_del(vid_b, nbr_mac)
        cli.neigh_del(nbr_ip, f"Vlan{vid_b}")
