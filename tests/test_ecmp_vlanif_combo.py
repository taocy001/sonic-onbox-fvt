"""**Load balancing across a physical L3 port / VLANIF mix**: one route with next hops on both a physical L3 port and a VLAN interface.

Production networks are rarely all-physical L3 ports -- the access side is often a VLANIF (SVI). The two next-hop kinds take different shapes in the chip:
a physical L3 port's RIF binds the port directly, while an SVI's RIF binds the VLAN and the egress physical port is only resolved via an FDB lookup.
DLB group members are, of all things, **physical ports** (`DLB_ECMP.PORT_ID[]`), so "can an SVI next hop even enter a DLB group, and
what does PORT_ID get filled with once it does" is a question that must be verified -- without a test it is pure guesswork.

The existing VLAN cases only cover L3 reachability between two SVIs; none puts an SVI and a physical port into the same load-balancing group.

Four cases:
  1. an SVI alone as a next hop forwards (control, rules out the SVI itself being broken);
  2. physical port + SVI mixed as plain ECMP: NHG with two members, both paths carry traffic;
  3. the same topology switched to dynamic: record whether the DLB group is built and what PORT_ID holds;
  4. the SVI member port goes down: the SVI path must converge, the physical path must be unaffected.
"""
import logging
import re
import os
import time

import pytest

try:
    from scapy.all import IP, UDP, Ether, sendp
    _SCAPY = True
except Exception:                                    # noqa: BLE001
    _SCAPY = False

_LOG = logging.getLogger("dut.vlanif")
_NET = "10.232.9.0/24"
_VID = 3210                       # steer clear of every test VLAN declared in the topology
_SVI = "10.232.2.1/24"
_SVI_PEER = "10.232.2.2"
_PHY = "10.232.1.1/24"
_PHY_PEER = "10.232.1.2"
_SVI_MAC = "00:aa:bb:00:32:02"


@pytest.fixture
def mixnet(l3net, cli, dut, _lb, topo):
    """Mixed base: p_out is the physical L3 port, p_o2 joins a freshly created VLAN as the SVI's member port, p_in is the injection port.

    p_o2 was configured as an L3 port by l3net, so here it must first be reverted to L2 before it can join the VLAN -- doing it in the
    wrong order hits an "is a router interface" rejection. The kernel only installs the SVI's connected route when it **has an up member**, so
    the member port's loopback must be raised before the SVI address is configured.
    """
    from framework import hygiene
    from framework.ports import Port

    env = l3net
    dv = topo.default_vlan
    p_phy, p_svi = env.p_out, env.p_o2

    # the physical L3 port path: switch to this group's own subnet to avoid confusion with l3net's base subnet
    cli.config_raw("interface ip remove %s %s/%d"
                   % (p_phy.name, env.sub_out["dut"], env.sub_out["prefix"]))
    cli.config("interface ip add %s %s" % (p_phy.name, _PHY))
    cli.neigh_set(_PHY_PEER, "00:aa:bb:00:32:01", p_phy.name)

    # the SVI path: revert member port to L2 -> create VLAN -> add member -> raise loopback -> configure SVI address
    cli.config_raw("interface ip remove %s %s/%d"
                   % (p_svi.name, env.sub_o2["dut"], env.sub_o2["prefix"]))
    hygiene.reset_port_to_l2(cli, _lb, dut, Port(name=p_svi.name), dv)
    cli.vlan_add(_VID)
    cli.vlan_member_add(_VID, p_svi.name)
    cli.intf_startup(p_svi.name)
    _lb.enable(Port(name=p_svi.name))
    _lb.hold(Port(name=p_svi.name))
    time.sleep(2)
    cli.config("interface ip add Vlan%d %s" % (_VID, _SVI))
    cli.neigh_set(_SVI_PEER, _SVI_MAC, "Vlan%d" % _VID)
    # an SVI next hop takes one hop more than a physical L3 port: after the L3 lookup it still needs an FDB lookup by MAC to pin the egress
    # physical port. On the bench the peer is fake and no frame will ever arrive to learn from, so without this static FDB entry it falls back
    # to flooding and the egress port is undetermined.
    cli.fdb_static_add(_VID, _SVI_MAC, p_svi.name)
    time.sleep(4)

    import types
    yield types.SimpleNamespace(env=env, cli=cli, dut=dut, bsh=env.bsh,
                                p_in=env.p_in, p_phy=p_phy, p_svi=p_svi, vid=_VID)

    cli.sh.run("ip route del %s" % _NET, check=False)
    for ip, dev in ((_PHY_PEER, p_phy.name), (_SVI_PEER, "Vlan%d" % _VID)):
        try:
            cli.neigh_del(ip, dev)
        except Exception:                            # noqa: BLE001
            pass
    try:
        cli.fdb_static_del(_VID, _SVI_MAC, p_svi.name)
    except Exception:                                # noqa: BLE001
        pass
    cli.config_raw("interface ip remove Vlan%d %s" % (_VID, _SVI))
    cli.config_raw("vlan member del %d %s" % (_VID, p_svi.name))
    cli.config_raw("vlan del %d" % _VID)
    cli.config_raw("interface ip remove %s %s" % (p_phy.name, _PHY))
    hygiene.purge_orphan_l3_rows(cli, ports=[p_phy.name, p_svi.name, "Vlan%d" % _VID])


def _wait_route(cli, net, want):
    for _ in range(30):
        out = cli.sh.run("ip route show %s" % net, check=False).out or ""
        if len(re.findall(r"nexthop", out)) >= want or (want == 1 and "via" in out):
            return out
        time.sleep(1)
    return ""


def _wait_nhg_members(cli, want, timeout=40):
    """Wait for a next hop group with the required member count to appear in the ASIC."""
    from framework.verify import AsicDb
    asic = AsicDb(cli)
    end = time.time() + timeout
    while time.time() < end:
        groups = {}
        for k in asic.objects("SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"):
            g = (cli.db_hgetall("ASIC_DB", k) or {}).get(
                "SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID")
            if g:
                groups[g] = groups.get(g, 0) + 1
        if max(groups.values(), default=0) >= want:
            return True
        time.sleep(2)
    return False


def _blast(env, dst_last=5, n=120):
    """Send n packets with varying 5-tuples, return (physical port TX, SVI member port TX)."""
    from framework.counters import ChipCounters
    rmac = env.env.rmac
    pkts = [(Ether(dst=rmac, src="00:de:ad:be:ef:32") /
             IP(src="10.232.0.%d" % (10 + i % 200), dst="10.232.9.%d" % dst_last, ttl=64) /
             UDP(sport=20000 + i, dport=80 + (i % 7))) for i in range(n)]
    ChipCounters.clear(env.bsh)
    sendp(pkts, iface=env.p_in.name, verbose=False)
    time.sleep(2)
    return (ChipCounters.read(env.bsh, env.dut.bcm_of(env.p_phy)).tx_pkt,
            ChipCounters.read(env.bsh, env.dut.bcm_of(env.p_svi)).tx_pkt)


def test_vlanif_nexthop_forwards(mixnet):
    """Control: with the SVI as the only next hop, traffic must egress the SVI's member port.

    If this fails, "the SVI path has no traffic" in the later mixed-group cases can't be attributed to load balancing.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    cli = mixnet.cli
    cli.sh.run("ip route replace %s via %s" % (_NET, _SVI_PEER), check=False)
    assert _wait_route(cli, _NET, 1), (
        "route %s via the SVI next hop %s never entered the kernel"
        % (_NET, _SVI_PEER))
    phy, svi = _blast(mixnet)
    assert svi > 0, (
        "a route whose only next hop is on Vlan%d forwarded nothing out its member port "
        "(member TX=%d, physical L3 port TX=%d): SVI next hops do not forward"
        % (mixnet.vid, svi, phy))
    _LOG.info("SVI-only next hop: member port TX=%d (physical port TX=%d)", svi, phy)


def test_ecmp_mixes_physical_port_and_vlanif(mixnet):
    """Physical L3 port + VLANIF mixed as plain ECMP: both paths must get a share of traffic.

    This is the most common shape in production (uplink physical L3 port, downlink access VLAN), yet it is a gap in the existing cases.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    cli = mixnet.cli
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s"
               % (_NET, _PHY_PEER, _SVI_PEER), check=False)
    assert _wait_route(cli, _NET, 2), (
        "mixed physical/SVI ECMP route %s never entered the kernel" % _NET)
    # wait for two members to actually appear in the ASIC before sending. An SVI next hop takes one hop more than a physical port (RIF binds
    # VLAN + FDB pins the port); a fixed sleep would measure before it is programmed, reading 120:0 which looks like "only one path was used"
    # (the previous version raised exactly this false alarm).
    assert _wait_nhg_members(cli, 2), (
        "the mixed physical/SVI route never reached 2 members in ASIC_DB; "
        "one of the two next hop kinds never got programmed")
    phy, svi = _blast(mixnet)
    assert phy + svi > 0, (
        "mixed physical/SVI ECMP forwarded nothing at all (physical TX=%d, SVI member TX=%d)"
        % (phy, svi))
    assert phy > 0 and svi > 0, (
        "mixed physical/SVI ECMP only used one of its two next hops (physical port TX=%d, "
        "SVI member port TX=%d): one of the two next hop kinds is not carrying its share"
        % (phy, svi))
    _LOG.info("mixed ECMP: physical TX=%d SVI member TX=%d", phy, svi)


def test_dlb_over_mixed_physical_and_vlanif(mixnet, chip):
    """The same mixed topology switched to dynamic: record what the DLB group is built as and what PORT_ID holds.

    DLB members are physical ports in the chip. An SVI next hop's egress physical port is only resolved via FDB, so there are two
    reasonable outcomes here, both of which must be recorded faithfully rather than assumed: the group is built and PORT_ID contains the
    SVI member's physical port; or the driver refuses to admit the SVI next hop into DLB. The criterion only clamps down on the truly
    unacceptable one -- **the group is built but PORT_ID points at a port that isn't on this route**, which would send traffic down the
    wrong physical path.
    """
    if os.environ.get("FVT_DLB", "") in ("", "0", "false"):
        pytest.skip("intrusive DLB case: set FVT_DLB=1")
    if not chip.has_table("DLB_ECMP"):
        pytest.skip("no DLB_ECMP logical table on this chip")
    cli = mixnet.cli
    cli.config_raw("load-balance ecmp-mode dynamic eligible")
    try:
        cli.sh.run("ip route replace %s nexthop via %s nexthop via %s"
                   % (_NET, _PHY_PEER, _SVI_PEER), check=False)
        assert _wait_route(cli, _NET, 2), "mixed route never entered the kernel"
        time.sleep(10)

        want = {chip.port_id(mixnet.p_phy.name), chip.port_id(mixnet.p_svi.name)}
        # array fields need dlb.parse_entries: `PORT_ID[0]=..,PORT_ID[1]=..` are comma-separated on one line,
        # chip.traverse's line-based parsing can't extract them (the previous version printed PORT_ID=[] because of this).
        from framework import dlb as _D
        ents = _D.parse_entries(chip.cmd("lt DLB_ECMP traverse -l"))
        got = set()
        for e in ents:
            if "PORT_ID[]" not in e:
                continue
            got |= {_D.field_at(e, "PORT_ID", i) for i in range(2)} - {None}
        if not any("PORT_ID[]" in e for e in ents):
            _LOG.info("mixed physical/SVI route built no DLB group: the driver keeps SVI "
                      "next hops out of DLB on this part")
        else:
            _LOG.info("mixed physical/SVI DLB group: PORT_ID=%s (physical=%s SVI member=%s)",
                      sorted(got), chip.port_id(mixnet.p_phy.name),
                      chip.port_id(mixnet.p_svi.name))
            stray = {p for p in got if p not in want and p != 0}
            assert not stray, (
                "the DLB group for a mixed physical/SVI route lists physical port(s) %s that "
                "are not on either next hop (expected a subset of %s): traffic would be sent "
                "down a path the route never named" % (sorted(stray), sorted(want)))
        # whether or not it is admitted into DLB, forwarding must not break as a result
        if _SCAPY:
            phy, svi = _blast(mixnet)
            assert phy + svi > 0, (
                "switching the global ecmp mode to dynamic killed forwarding on a mixed "
                "physical/SVI route (physical TX=%d, SVI member TX=%d)" % (phy, svi))
            _LOG.info("mixed under dynamic: physical TX=%d SVI member TX=%d", phy, svi)
    finally:
        cli.config_raw("load-balance ecmp-mode normal")


def test_mixed_ecmp_converges_when_vlanif_member_goes_down(mixnet):
    """Bring the SVI's only member port down: the SVI path must converge, the physical path must carry on as usual.

    The SVI's oper state is driven by its member port, and this chain takes one hop more than a physical L3 port, making it the spot in the
    mixed group most prone to black-holing.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    cli = mixnet.cli
    cli.sh.run("ip route replace %s nexthop via %s nexthop via %s"
               % (_NET, _PHY_PEER, _SVI_PEER), check=False)
    assert _wait_route(cli, _NET, 2), "mixed route never entered the kernel"
    time.sleep(6)
    phy0, svi0 = _blast(mixnet)

    cli.config_raw("interface shutdown %s" % mixnet.p_svi.name)
    try:
        time.sleep(12)
        phy1, svi1 = _blast(mixnet)
        assert phy1 > 0, (
            "after the SVI member port went down the surviving physical next hop stopped "
            "forwarding too (physical TX %d -> %d): the whole route black-holed instead of "
            "converging onto the healthy path" % (phy0, phy1))
        assert phy1 >= phy0, (
            "the physical next hop did not absorb the SVI path's share after the SVI member "
            "went down (physical TX %d -> %d, SVI member TX %d -> %d)"
            % (phy0, phy1, svi0, svi1))
        _LOG.info("SVI member down: physical TX %d -> %d, SVI member TX %d -> %d",
                  phy0, phy1, svi0, svi1)
    finally:
        cli.config_raw("interface startup %s" % mixnet.p_svi.name)
        time.sleep(8)
