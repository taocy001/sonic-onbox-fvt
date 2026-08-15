"""VXLAN chip-behavior verification: VTEP + VNI<->VLAN map really program to ASIC, and the dataplane really encaps/decaps.

Unlike the existing test_vxlan.py / test_vxlan_full.py (which only verify the CONFIG_DB config
contract and skip encap/decap entirely), this module pushes one layer further:

  1) ASIC programming layer: after VTEP creation, ASIC_DB shows SAI_OBJECT_TYPE_TUNNEL; the
     VLAN<->VNI map shows SAI_OBJECT_TYPE_TUNNEL_MAP / TUNNEL_MAP_ENTRY. Verifying only "CONFIG_DB
     has the key" is the anti-pattern this suite aims to fix -- here we assert orchagent -> SAI
     really programs the tunnel/map objects into the chip.

  2) Dataplane behavior layer (real traffic + capture):
     - encap: re-enter a VLAN member port's overlay frame via loopback -> the DUT should
       encapsulate it as VXLAN/UDP(4789) toward the remote VTEP (next-hop port), mirror the egress
       port's egress to cpu0 to capture the real frame, and check outer IP.dst=remote VTEP,
       UDP.dport=4789, VXLAN.vni == mapped VNI, inner DMAC == original overlay DMAC.
     - decap: inject a VXLAN frame destined to the local VTEP IP into the DUT -> the DUT should
       decapsulate it and deliver the inner frame to the local member port of that VNI's VLAN,
       mirror that member port's egress to cpu0 to capture the inner frame, and check the VXLAN
       header is stripped and DMAC == inner DMAC.

Honest scope: a VXLAN tunnel only truly forms with a Loopback IP + remote VTEP + EVPN/NVO;
static vxlan add/map only builds the decap-side objects. The encap case therefore carries its own
EVPN-equivalent prerequisites: after binding the NVO, following the standard swss VS-test approach,
feed APPL_DB VXLAN_REMOTE_VNI_TABLE (dynamic P2P tunnel + VLAN tunnel member) and VXLAN_FDB_TABLE
(inner DMAC directed into the tunnel) directly via swssconfig (ProducerStateTable), whose orchagent
consumption path is identical to real EVPN; before sending traffic, wait for the P2P TUNNEL object
to appear in ASIC -- if it doesn't, that's "tunnel member not programmed" (device defect), reported
separately from "forwarding doesn't work". The two dataplane cases (encap/decap), like the two ASIC
programming cases, do NOT xfail: with prerequisites fully fed + the capture path really in place,
0 frames is a class-A device defect, exposed binarily with a direct FAIL rather than masked by
xfail -- if the chip really doesn't encap/decap or didn't program the tunnel object, it FAILs honestly.

Clean: all VTEP / VLAN / map / neighbors / mirror / loopback are reclaimed via
config_guard.defer_undo / finally, idempotently.
"""
import time

import pytest

pytestmark = [pytest.mark.vxlan]

try:
    from scapy.all import Ether, IP, UDP, VXLAN, sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

VTEP = "vtep_chip"
_NVO = "nvo_chip"                   # EVPN NVO name (encap prerequisite: without an NVO, orch drops REMOTE_VNI)
_DPORT = 4789                       # standard VXLAN UDP destination port
_INNER_DMAC = "00:11:22:33:44:c1"  # overlay inner destination MAC (should be preserved verbatim in the inner layer after encap)
_INNER_SMAC = "00:de:ad:be:ef:01"  # = collector.PROBE_SMAC, for signature filtering
_REMOTE_NH_MAC = "00:11:22:33:44:aa"  # remote VTEP next-hop neighbor MAC
_N = 30


def _tunnel_objs(asicdb, sai_type):
    return asicdb.objects(f"SAI_OBJECT_TYPE_{sai_type}")


def _wait_obj_gt(asicdb, sai_type, base, timeout=10.0):
    return asicdb.wait_count_gt(f"ASIC_STATE:SAI_OBJECT_TYPE_{sai_type}:*", base, timeout=timeout)


# ---------------------------------------------------------------------------
# 1) ASIC programming layer
# ---------------------------------------------------------------------------
def test_vtep_programs_asic_tunnel(cli, asicdb, config_guard, topo):
    """VTEP creation -> ASIC_DB shows SAI_OBJECT_TYPE_TUNNEL (the tunnel object really programs to the chip).

    Verifying only CONFIG_DB VXLAN_TUNNEL is an anti-pattern; here we assert orchagent/vxlanorch
    -> SAI programs the TUNNEL object into ASIC. If the device didn't really build the tunnel
    object, this case FAILs honestly (no xfail)."""
    topo.caps.require("vxlan")
    src_ip = topo.subnet("a")["dut"]
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:*")
    rc, r = cli.config_raw(f"vxlan add {VTEP} {src_ip}")
    config_guard.defer_undo(f"vxlan del {VTEP}")
    assert rc == 0, f"failed to create VxLAN VTEP: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"VXLAN_TUNNEL|{VTEP}"), "no VXLAN_TUNNEL in CONFIG_DB"
    # dataplane/chip: the tunnel object must really program to ASIC (SAI_OBJECT_TYPE_TUNNEL grows)
    assert _wait_obj_gt(asicdb, "TUNNEL", base, timeout=10), (
        "VTEP created in CONFIG_DB but no SAI_OBJECT_TYPE_TUNNEL programmed to ASIC "
        "(tunnel object not created on chip)")


def test_vlan_vni_map_programs_asic_tunnel_map(cli, asicdb, config_guard, topo):
    """VLAN<->VNI map -> ASIC_DB shows SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY (the VNI mapping really programs to the chip).

    Assert the mapping really programs to ASIC (map + map_entry), not just that the CONFIG_DB VXLAN_TUNNEL_MAP key exists."""
    topo.caps.require("vxlan")
    src_ip = topo.subnet("a")["dut"]
    vid = topo.vlan("c")
    vni = vid * 10
    cli.config_raw(f"vxlan add {VTEP} {src_ip}")
    config_guard.defer_undo(f"vxlan del {VTEP}")
    cli.config_raw(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    base_map = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP:*")
    base_ent = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY:*")
    rc, r = cli.config_raw(f"vxlan map add {VTEP} {vid} {vni}")
    config_guard.defer_undo(f"vxlan map del {VTEP} {vid} {vni}")
    assert rc == 0, f"VLAN-VNI mapping failed: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"VXLAN_TUNNEL_MAP|{VTEP}|*"), "no VNI mapping in CONFIG_DB"
    # chip: the VLAN<->VNI mapping must land on the ASIC tunnel map (container + entry). Either one missing means the mapping didn't really program.
    got_map = _wait_obj_gt(asicdb, "TUNNEL_MAP", base_map, timeout=10)
    got_ent = _wait_obj_gt(asicdb, "TUNNEL_MAP_ENTRY", base_ent, timeout=10)
    assert got_map and got_ent, (
        f"VLAN<->VNI map not programmed to ASIC: TUNNEL_MAP grew={got_map}, "
        f"TUNNEL_MAP_ENTRY grew={got_ent} (vid={vid} vni={vni})")


# ---------------------------------------------------------------------------
# 2) dataplane behavior layer (real encap / decap + capture)
# ---------------------------------------------------------------------------
@pytest.mark.traffic
def test_vxlan_encap_to_remote_vtep(cli, dut, _lb, asicdb, config_guard, topo, l3up):
    """Dataplane ENCAP: a VLAN member port's overlay frame -> DUT encaps it as VXLAN/UDP(4789) to the remote VTEP.

    Topology:
      - VTEP src = local Loopback IP; the remote VTEP IP is in the underlay egress port's subnet, with a static neighbor + host route.
      - one local VLAN member port receives the overlay frame (DMAC=inner destination, already VNI-mapped).
    Prerequisites (EVPN-equivalent; the original's absence would misjudge "the case didn't feed
    prerequisites" as a device defect): after binding the NVO, feed APPL_DB VXLAN_REMOTE_VNI_TABLE
    (build the remote VNI tunnel member) + VXLAN_FDB_TABLE (inner DMAC directed into the tunnel)
    directly via swssconfig, and before sending traffic wait for the dynamic P2P TUNNEL object to
    appear in ASIC -- if it doesn't, that's "tunnel member not programmed" (device defect),
    reported separately from the post-traffic "forwarding doesn't work" of 0 frames.
    Mirror the underlay egress port's egress to cpu0, capture the real encapsulated frame, and
    check outer IP.dst==remote VTEP, IP.src==local Loopback, Ether.dst==neighbor MAC (after egress
    rewrite), UDP.dport=4789, VXLAN.vni==mapped VNI, inner DMAC preserved verbatim. 0 frames ->
    assertion FAIL (class-A device defect, binary exposure)."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("vxlan")
    topo.caps.require("loopback")
    from framework.traffic import Capture
    from framework.collector import MirrorCollector

    lo_ip = topo.loopback("a").split("/")[0]          # local VTEP source IP
    sub_u = topo.subnet("d")                          # underlay egress subnet
    remote_vtep = sub_u["peer"]                       # remote VTEP IP (next hop)
    vid = topo.vlan("d")
    vni = vid * 10

    # underlay egress port (the remote VTEP is reachable via it) + overlay ingress port (VLAN member)
    p_under = l3up(topo.l3_port(1).name, f"{sub_u['dut']}/{sub_u['prefix']}")
    p_acc = topo.l2_port(0)

    cli.config_raw(f"vxlan add {VTEP} {lo_ip}")
    config_guard.defer_undo(f"vxlan del {VTEP}")
    cli.config_raw(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    cli.config_raw(f"vlan member add -u {vid} {p_acc.name}")
    config_guard.defer_undo(f"vlan member del {vid} {p_acc.name}")
    cli.config_raw(f"vxlan map add {VTEP} {vid} {vni}")
    config_guard.defer_undo(f"vxlan map del {VTEP} {vid} {vni}")
    # remote VTEP reachable via the underlay egress port (static neighbor + host route)
    cli.neigh_set(remote_vtep, _REMOTE_NH_MAC, p_under.name)
    cli.sh.run(f"ip route replace {remote_vtep}/32 via {remote_vtep} dev {p_under.name}", check=False)

    # ---- EVPN-equivalent prerequisites (key: static vxlan add/map builds only the decap side; encap needs a tunnel member + remote MAC) ----
    # 1) bind the NVO to the VTEP in CONFIG_DB: without an NVO, vxlanorch silently drops the REMOTE_VNI write.
    #    prefer the product CLI; on images lacking that command fall back to writing CONFIG_DB directly (keyspace notification, equivalent to the CLI).
    rc_nvo, _rn = cli.config_raw(f"vxlan evpn_nvo add {_NVO} {VTEP}")
    if rc_nvo != 0:
        cli.db_hset("CONFIG_DB", f"VXLAN_EVPN_NVO|{_NVO}", "source_vtep", VTEP)
    # 2) APPL_DB remote VNI tunnel member + directed FDB. Must go through swssconfig
    #    (ProducerStateTable, same consumption path as real EVPN as orchagent) -- a direct
    #    sonic-db-cli HSET of APPL_DB doesn't trigger the orch notification (see cli.py).
    _appl_set = (
        '[{"VXLAN_REMOTE_VNI_TABLE:Vlan%d:%s": {"vni": "%d"}, "OP": "SET"},'
        ' {"VXLAN_FDB_TABLE:Vlan%d:%s": {"remote_vtep": "%s", "type": "static", "vni": "%d"},'
        ' "OP": "SET"}]'
        % (vid, remote_vtep, vni, vid, _INNER_DMAC, remote_vtep, vni))
    _appl_del = (
        '[{"VXLAN_FDB_TABLE:Vlan%d:%s": {}, "OP": "DEL"},'
        ' {"VXLAN_REMOTE_VNI_TABLE:Vlan%d:%s": {}, "OP": "DEL"}]'
        % (vid, _INNER_DMAC, vid, remote_vtep))
    # before the baseline, wait for the static VTEP's own TUNNEL object to settle (stable consecutive
    # reads): vxlan add/map objects land asynchronously, and if one arrives after the baseline is
    # sampled it would masquerade as "the P2P tunnel appeared" -- the same class of race as the
    # L3VNI case, uniformly absorbed before sampling the baseline
    _tun_pat = "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:*"
    base_tun = asicdb.count(_tun_pat)
    _end = time.time() + 10
    while time.time() < _end:
        time.sleep(0.6)
        _cur = asicdb.count(_tun_pat)
        if _cur == base_tun:
            break
        base_tun = _cur
    cli._swssconfig(_appl_set)

    _lb.enable(p_acc)
    mc = MirrorCollector(_lb.bsh, dut)
    mc.enable(p_under)
    try:
        time.sleep(1.0)
        # ---- pre-traffic gate: wait for the dynamic P2P TUNNEL to really program (chip evidence
        # that REMOTE_VNI was consumed by orch). If the first round times out, re-feed once (the NVO
        # takes effect asynchronously via CONFIG_DB, possibly later than the first APPL_DB write, and
        # an early-arriving REMOTE_VNI is dropped by orch), then wait another round.
        if not _wait_obj_gt(asicdb, "TUNNEL", base_tun, timeout=8):
            cli._swssconfig(_appl_del)
            cli._swssconfig(_appl_set)
            got_p2p = _wait_obj_gt(asicdb, "TUNNEL", base_tun, timeout=10)
        else:
            got_p2p = True
        assert got_p2p, (
            "remote VNI + remote FDB fed to APPL_DB (VXLAN_REMOTE_VNI_TABLE / VXLAN_FDB_TABLE "
            "via swssconfig, EVPN NVO bound) but no dynamic P2P SAI_OBJECT_TYPE_TUNNEL appeared "
            "in ASIC -- VXLAN tunnel member NOT PROGRAMMED (device defect in orchagent/SAI "
            "consumption, distinct from a dataplane forwarding failure)")
        # whether the remote FDB programmed to the chip: a hit = directed into the tunnel; a miss
        # can still flood into the tunnel via the VLAN tunnel flood member. Only used as
        # failure-triage context, not hard-asserted here.
        fdb_on_chip = False
        for _ in range(20):
            if any(_INNER_DMAC.upper() in k.upper()
                   for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY")):
                fdb_on_chip = True
                break
            time.sleep(0.3)
        # overlay frame: inner DMAC=remote host, entering the VNI's VLAN from the access port
        pkt = (Ether(dst=_INNER_DMAC, src=_INNER_SMAC) /
               IP(src="192.168.1.10", dst="192.168.1.20") / UDP())
        with Capture(p_under.name, inbound=True) as cap:   # MirrorCollector contract: egress mirror frames appear inbound on the mirrored port
            sendp(pkt, iface=p_acc.name, count=_N, verbose=False)
            time.sleep(0.5)
        # encapsulated real frame signature: outer is UDP/4789 and VXLAN.vni hits the mapping
        enc = [p for p in cap.packets
               if p.haslayer(UDP) and p[UDP].dport == _DPORT and p.haslayer(VXLAN)]
        assert enc, (
            f"no VXLAN-encapsulated frame captured at underlay egress {p_under.name} "
            f"(expected outer UDP dport={_DPORT}); P2P tunnel object IS programmed, "
            f"remote FDB on chip={fdb_on_chip} -- encap FORWARDING failure "
            "(preconditions were fed, not a missing-precondition artifact)")
        f = enc[0]
        assert f[IP].dst == remote_vtep, \
            f"outer IP.dst should be remote VTEP {remote_vtep}, got {f[IP].dst}"
        assert f[IP].src == lo_ip, \
            f"outer IP.src should be local VTEP source (Loopback) {lo_ip}, got {f[IP].src}"
        assert f[Ether].dst.lower() == _REMOTE_NH_MAC.lower(), (
            f"outer Ether.dst should be rewritten to underlay next-hop MAC "
            f"{_REMOTE_NH_MAC}, got {f[Ether].dst}")
        assert f[VXLAN].vni == vni, \
            f"VXLAN VNI mismatch: got {f[VXLAN].vni}, expected {vni}"
        inner = f[VXLAN].payload
        assert inner.haslayer(Ether) and inner[Ether].dst.lower() == _INNER_DMAC.lower(), \
            f"inner DMAC not preserved: got {inner[Ether].dst if inner.haslayer(Ether) else None}"
    finally:
        mc.disable()
        _lb.disable(p_acc)
        # symmetrically reclaim the APPL_DB prerequisites (FDB first then REMOTE_VNI, reverse of write order) and the NVO (CLI + redis double insurance)
        cli._swssconfig(_appl_del)
        cli.config_raw(f"vxlan evpn_nvo del {_NVO}")
        cli.sh.run(f"sonic-db-cli CONFIG_DB DEL 'VXLAN_EVPN_NVO|{_NVO}'", check=False)
        cli.sh.run(f"ip route del {remote_vtep}/32", check=False)
        cli.neigh_del(remote_vtep, p_under.name)


@pytest.mark.traffic
def test_vxlan_decap_to_local_member(cli, dut, _lb, asicdb, config_guard, topo, l3up):
    """Dataplane DECAP: inject a VXLAN frame with dst=local VTEP IP -> DUT decapsulates -> the inner frame goes to the VNI's VLAN local member port.

    Topology: local VTEP source = an IP configured directly on the underlay ingress port (so that
    IP can serve as the VXLAN termination point). Inject into that port a frame with outer
    IP.dst=local VTEP, UDP/4789, VXLAN.vni=mapped VNI; mirror the VNI's VLAN local member port's
    egress to cpu0, and what's captured should be the inner frame with the VXLAN header stripped
    (DMAC=inner destination, no UDP/4789 outer). If the local VTEP termination table isn't
    programmed, 0 inner frames -> assertion FAIL (class-A device defect, binary exposure).
    Negative control: the same frame with an unmapped VNI (vni+1) must not be decapsulated into
    that member port -- guarding against a "doesn't validate VNI" implementation falsely passing."""
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("vxlan")
    topo.caps.require("loopback")
    from framework.traffic import Capture
    from framework.collector import MirrorCollector

    sub_u = topo.subnet("c")
    local_vtep = sub_u["dut"]                # local VTEP IP = underlay ingress port IP (VXLAN termination point)
    vid = topo.vlan("e")
    vni = vid * 10

    p_in = l3up(topo.l3_port(0).name, f"{sub_u['dut']}/{sub_u['prefix']}")  # underlay ingress (receives VXLAN)
    p_mem = topo.l2_port(1)                  # local member of the VNI's VLAN (egress for the decapsulated inner frame)

    cli.config_raw(f"vxlan add {VTEP} {local_vtep}")
    config_guard.defer_undo(f"vxlan del {VTEP}")
    cli.config_raw(f"vlan add {vid}")
    config_guard.defer_undo(f"vlan del {vid}")
    cli.config_raw(f"vlan member add -u {vid} {p_mem.name}")
    config_guard.defer_undo(f"vlan member del {vid} {p_mem.name}")
    cli.config_raw(f"vxlan map add {VTEP} {vid} {vni}")
    config_guard.defer_undo(f"vxlan map del {VTEP} {vid} {vni}")
    # static FDB: inner DMAC points to the local member port, so the decapsulated inner frame is directed to p_mem (not flooded). Explicitly deleted in finally.
    cli.fdb_static_add(vid, _INNER_DMAC, p_mem.name)

    rmac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")
    if not rmac:
        pytest.skip("router MAC (DEVICE_METADATA.mac) not found")

    _lb.enable(p_mem)
    mc = MirrorCollector(_lb.bsh, dut)
    mc.enable(p_mem)
    try:
        time.sleep(1.0)
        # outer DMAC=router MAC (L3-to-local termination), dst=local VTEP IP; carries VXLAN/VNI/inner Ethernet frame
        inner = (Ether(dst=_INNER_DMAC, src="00:aa:bb:cc:dd:0e") /
                 IP(src="10.5.5.5", dst="10.5.5.6") / UDP())
        vxpkt = (Ether(dst=rmac, src=_REMOTE_NH_MAC) /
                 IP(src=sub_u["peer"], dst=local_vtep) /
                 UDP(sport=12345, dport=_DPORT) / VXLAN(vni=vni, flags=0x08) / inner)
        # mirror frames appear inbound on the mirrored port's netdev (on-device-verified conclusion
        # in framework/collector.py); inbound=True precisely captures the mirror flow, excluding directionless noise
        with Capture(p_mem.name, inbound=True) as cap:
            sendp(vxpkt, iface=p_in.name, count=_N, verbose=False)
            time.sleep(0.5)
        # decapsulated real frame: inner DMAC, and no longer any VXLAN / outer UDP4789
        dec = [p for p in cap.packets
               if p.haslayer(Ether) and p[Ether].dst.lower() == _INNER_DMAC.lower()
               and not (p.haslayer(UDP) and p[UDP].dport == _DPORT)]
        assert dec, (
            f"no decapsulated inner frame captured at local member {p_mem.name} "
            "(VXLAN term not decapping / inner not forwarded to member)")
        f = dec[0]
        assert not f.haslayer(VXLAN), "captured frame still has VXLAN header (not decapped)"
        assert f[Ether].dst.lower() == _INNER_DMAC.lower(), \
            f"inner DMAC mismatch after decap: got {f[Ether].dst}, want {_INNER_DMAC}"
        # ---- negative control: the same frame with only the VNI changed to the unmapped vni+1 must
        # not be decapsulated into that VLAN member port. Guards against a "termination point doesn't
        # validate VNI, any VXLAN is decapped into that VLAN" implementation falsely passing the positive assertion.
        bad = (Ether(dst=rmac, src=_REMOTE_NH_MAC) /
               IP(src=sub_u["peer"], dst=local_vtep) /
               UDP(sport=12346, dport=_DPORT) / VXLAN(vni=vni + 1, flags=0x08) / inner)
        with Capture(p_mem.name, inbound=True) as cap2:
            sendp(bad, iface=p_in.name, count=_N, verbose=False)
            time.sleep(0.5)
        leak = [p for p in cap2.packets
                if p.haslayer(Ether) and p[Ether].dst.lower() == _INNER_DMAC.lower()
                and not (p.haslayer(UDP) and p[UDP].dport == _DPORT)]
        assert not leak, (
            f"unmapped VNI {vni + 1} got decapsulated and forwarded to member {p_mem.name} "
            f"({len(leak)} inner frames captured) -- VTEP does not validate VNI on termination")
    finally:
        mc.disable()
        _lb.disable(p_mem)
        cli.fdb_static_del(vid, _INNER_DMAC)
