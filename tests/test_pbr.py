"""PBR policy routing: redirect entries truly programmed to the ASIC + policy-driven data-plane rerouting.

The implementation path is dispatched by device capability (the switchport OS always uses config/show product commands):
- Switchport OS: product `config acl-rule add ... -re <port|nh@port>` (PBR = ACL redirect,
  the CLI help does expose this action); verify ASIC_ENTRY growth + real traffic taking the policy egress.
- Community image: PBR goes through FRR route-map (set ip next-hop uses the kernel ip-rule) or acl-loader
  redirect, neither of which programs the chip (acl_rule_program=False) -- exposed by an honest FAIL.

Prints/assert/skip in English. Ports/subnets are taken from topo, not hard-coded.
"""
import time

import pytest

pytestmark = [pytest.mark.l3]

_N = 100


def _klish_pbr_setup(cli, config_guard, table, port):
    """Product path: create an L3 ACL table bound to the ingress interface (framework fixup routes this to acl-table add)."""
    rc, r = cli.config_raw(f"acl add table {table} L3 -s ingress -p {port}")
    assert rc == 0, f"acl table create failed: {r.err or r.out}"
    config_guard.defer_undo(f"acl remove table {table}")


def test_pbr_v4_configurable(cli, asicdb, topo, l3up, config_guard):
    """PBR (v4) truly programmed: redirect rule -> a SAI_ACL_ENTRY appears **in this table** carrying an SRC_IP
    match + a non-empty ACTION_REDIRECT, and the redirect target object really exists (NEXT_HOP pointing at the policy next-hop / port)."""
    topo.caps.require("loopback")
    sub_in, sub_nh = topo.subnet("c"), topo.subnet("d")
    p_in = l3up(topo.l3_port(0).name, f"{sub_in['dut']}/{sub_in['prefix']}")
    pbr_nh = sub_nh["peer"]          # policy-redirect next-hop
    # The redirect next-hop must be resolvable (directly-connected subnet + static neighbor), otherwise orch
    # will not program the redirect entry -- that would be "entry awaiting resolution" rather than a defect,
    # so set up the precondition first.
    p_nh = l3up(topo.l3_port(1).name, f"{sub_nh['dut']}/{sub_nh['prefix']}")
    cli.neigh_set(pbr_nh, topo.mac('peer_b'), p_nh.name)

    if cli.is_switchport_os():
        # Product path: acl-table + acl-rule -re. The old version only asserted global ACL_ENTRY count growth --
        # any entry (even one where redirect was silently degraded to DROP/FORWARD) would pass, never verifying
        # redirect semantics. Now, following test_acl_egress_l2's table-OID set-difference method, locate this
        # table's entry and verify the REDIRECT action + target object.
        base_acl = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*")
        base_tbls = set(asicdb.objects("SAI_OBJECT_TYPE_ACL_TABLE"))
        _klish_pbr_setup(cli, config_guard, "FVT_PBR1", p_in.name)
        rc, r = cli.config_raw(
            f"acl-rule add FVT_PBR1 R1 -p 100 -si {sub_in['peer']}/32 -re {pbr_nh}")
        assert rc == 0, f"acl-rule redirect add failed: {r.err or r.out}"
        config_guard.defer_undo("acl-rule del FVT_PBR1 R1")
        grew = asicdb.wait_count_gt(
            "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*", base_acl, timeout=10)
        assert grew, ("DEVICE DEFECT: product acl-rule redirect accepted by CLI but no "
                      "SAI_ACL_ENTRY programmed to ASIC (PBR redirect not realized)")
        # This test's own-table OID set-difference -> scope entry ownership + SRC_IP value match (rule out a false pass from a leftover entry)
        hit = None
        for _ in range(20):
            my_tbl_oids = {k.split("SAI_OBJECT_TYPE_ACL_TABLE:", 1)[-1]
                           for k in set(asicdb.objects("SAI_OBJECT_TYPE_ACL_TABLE")) - base_tbls}
            for e in asicdb.objects("SAI_OBJECT_TYPE_ACL_ENTRY"):
                d = cli.db_hgetall("ASIC_DB", e)
                if str(d.get("SAI_ACL_ENTRY_ATTR_TABLE_ID", "")) not in my_tbl_oids:
                    continue
                sip = str(d.get("SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP", ""))
                if sip.split("&")[0].strip() == sub_in["peer"]:
                    hit = d
                    break
            if hit:
                break
            time.sleep(0.5)
        assert hit, (f"no ACL_ENTRY under this test's PBR table carries "
                     f"SRC_IP={sub_in['peer']} (redirect rule not programmed for this table)")
        ract = str(hit.get("SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT", ""))
        assert "oid:" in ract and "oid:0x0" not in ract, (
            f"PBR entry programmed WITHOUT a valid ACTION_REDIRECT (got {ract!r}); "
            f"redirect silently degraded (entry exists but does not redirect)")
        # Reverse-check that the redirect target object really exists: NEXT_HOP (IP should be the policy next-hop) or port/LAG
        roid = ract[ract.find("oid:"):]
        tgt_type, tgt = None, None
        for typ in ("SAI_OBJECT_TYPE_NEXT_HOP", "SAI_OBJECT_TYPE_PORT", "SAI_OBJECT_TYPE_LAG"):
            h = cli.db_hgetall("ASIC_DB", f"ASIC_STATE:{typ}:{roid}")
            if h:
                tgt_type, tgt = typ, h
                break
        assert tgt, f"redirect target {roid} does not exist in ASIC_DB (dangling redirect oid)"
        if tgt_type == "SAI_OBJECT_TYPE_NEXT_HOP":
            assert pbr_nh in str(tgt.get("SAI_NEXT_HOP_ATTR_IP", "")), (
                f"redirect NEXT_HOP {roid} IP is {tgt.get('SAI_NEXT_HOP_ATTR_IP')!r}, "
                f"not the policy next-hop {pbr_nh}")
        return

    # Community image: FRR route-map + interface policy. Architectural fact: `set ip next-hop` is a zebra/kernel
    # ip-rule policy-layer mechanism that on any community SONiC never programs a SAI ACL_ENTRY via aclorch --
    # the old version's use of ASIC_ENTRY growth as an observation point is a layer mismatch that would mislabel
    # a community architectural absence as a DEVICE DEFECT of this box (the hardware-PBR absence is borne by the
    # caps gate's honest FAIL in test_pbr_bind_and_forward; no need to re-adjudicate it here). This case instead
    # verifies the layer it actually configures: FRR policy binding + kernel policy routing truly resolving pbr_nh.
    try:
        cli.vtysh(
            "configure terminal\n"
            "route-map PBR1 permit 10\n"
            f" set ip next-hop {pbr_nh}\n"
            "exit\n"
            f"interface {p_in.name}\n"
            " ip policy route-map PBR1\n", config=False)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"PBR route-map/interface-policy CLI failed on this image: {e}")
    try:
        r = cli.run("show route-map PBR1")
        assert "PBR1" in r.out, "route-map PBR1 did not take effect in FRR (config path broken)"
        run_cfg = cli.run("vtysh -c 'show running-config'").out or ""
        assert "ip policy route-map PBR1" in run_cfg, (
            "interface PBR policy binding absent from FRR running-config "
            "(`ip policy route-map` not accepted/retained by this image's FRR)")
        # Behavioral level: for a packet "ingressing p_in with a source that matches the policy flow", the kernel's policy routing should resolve the next-hop to pbr_nh
        picked = ""
        deadline = time.time() + 10
        while time.time() < deadline:
            rr = cli.run(f"ip -4 route get 8.8.8.8 from {sub_in['peer']} iif {p_in.name}")
            picked = rr.out or ""
            if pbr_nh in picked:
                break
            time.sleep(0.5)
        assert pbr_nh in picked, (
            f"kernel policy routing did not resolve the matched flow via PBR next-hop "
            f"{pbr_nh} (`ip route get ... iif {p_in.name}` -> {picked.strip()!r}); FRR "
            f"interface policy route-map not effective at its own (kernel) layer")
    finally:
        try:
            cli.vtysh(
                "configure terminal\n"
                f"interface {p_in.name}\n"
                " no ip policy route-map PBR1\n"
                "exit\n"
                "no route-map PBR1 permit 10\n", config=False)
        except Exception:  # noqa: BLE001
            pass


def test_pbr_bind_and_forward(cli, asicdb, dut, _lb, topo, l3up, config_guard, traffic):
    """PBR end-to-end data-plane: matched traffic is redirected by policy to the policy egress port (not the route egress port).

    Capability dispatch: on platforms with acl_rule_program=False the redirect is not pushed to the chip and
    policy forwarding cannot be realized in hardware -> honest FAIL; supported platforms use the product
    acl-rule `-re <port>` port redirect + real-traffic assertions.
    """
    if not topo.caps.has("acl_rule_program"):
        pytest.fail(
            "DEVICE DEFECT: PBR redirect (ACL) is not programmed to the ASIC on this platform "
            "(acl_rule_program=False + FRR set-next-hop uses kernel ip-rule, not the chip), so "
            "policy-based data-plane forwarding cannot be realized in hardware")
    if not cli.is_switchport_os():
        pytest.skip("product acl-rule redirect path only implemented for the CLI-model image")
    topo.caps.require("loopback")
    from scapy.all import Ether, IP, UDP, Raw

    sub_in, sub_rt = topo.subnet("c"), topo.subnet("d")
    p_in = l3up(topo.l3_port(0).name, f"{sub_in['dut']}/{sub_in['prefix']}")
    p_rt = l3up(topo.l3_port(1).name, f"{sub_rt['dut']}/{sub_rt['prefix']}")   # route egress
    p_pbr = topo.misc_port(0)                                                  # policy egress
    if p_pbr.name in (p_in.name, p_rt.name):
        pytest.skip("need 3 distinct ports for PBR-vs-route egress check")
    cli.intf_startup(p_pbr.name)
    # Use a **flood-safe loopback** on the policy egress rather than a bare loopback: redirect-to-port does not
    # rewrite L2, so the egress frame still carries dst=router MAC + a routable dst_ip; after a bare loopback
    # re-injects it, it would be routed again to p_rt, blowing out the negative assertion below (p_rt should see
    # no traffic) -> a healthy function would still FAIL. Flood-safe switches the re-injected frame's ingress PVID
    # to an isolated VLAN (no RIF / no members) for a deterministic termination, without affecting egress TX counts.
    _lb.enable_flood_safe(p_pbr, 3990)

    dst_net = topo.route("a")
    dst_ip = dst_net.split("/")[0].rsplit(".", 1)[0] + ".9"
    nh = sub_rt["peer"]
    cli.neigh_set(nh, topo.mac('peer_b'), p_rt.name)
    cli.config_raw(f"route add prefix {dst_net} nexthop {nh}")
    config_guard.defer_undo(f"route del prefix {dst_net} nexthop {nh}")

    _klish_pbr_setup(cli, config_guard, "FVT_PBR2", p_in.name)
    rc, r = cli.config_raw(
        f"acl-rule add FVT_PBR2 R1 -p 100 -di {dst_ip}/32 -re {p_pbr.name}")
    assert rc == 0, f"acl-rule port-redirect add failed: {r.err or r.out}"
    config_guard.defer_undo("acl-rule del FVT_PBR2 R1")

    rmac = cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")
    assert rmac, "router MAC not found"

    def _accum_tx2(p_a, p_b, floor_a, window=3.0):
        """Poll and accumulate the chip TX deltas of both ports + a confirmation read (show-c change-delta
        semantics; a single fixed-sleep read would miss counts that land late via DMA). p_a converges early once
        it reaches floor_a; the confirmation read catches p_b's late-arriving counts (the negative assertion relies on it)."""
        tot_a = tot_b = 0
        deadline = time.time() + window
        while time.time() < deadline:
            time.sleep(0.4)
            tot_a += traffic.chip_counters(p_a).tx_pkt
            tot_b += traffic.chip_counters(p_b).tx_pkt
            if tot_a >= floor_a:
                break
        time.sleep(0.4)
        tot_a += traffic.chip_counters(p_a).tx_pkt
        tot_b += traffic.chip_counters(p_b).tx_pkt
        return tot_a, tot_b

    try:
        time.sleep(2)
        # Matched flow: dst falls within the /32 redirect rule, so it should take the policy egress p_pbr rather than the route egress p_rt
        pkt = (Ether(dst=rmac, src=topo.mac("src")) /
               IP(src=sub_in["peer"], dst=dst_ip, ttl=64) / UDP() / Raw(b"p" * 40))
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(p_in, pkt, count=_N)
        d_pbr, d_rt = _accum_tx2(p_pbr, p_rt, floor_a=_N * 0.8)
        # Matched traffic should take the policy egress, not the route egress (upper bound guards against a storm)
        assert _N * 0.8 <= d_pbr < 100_000, (
            f"PBR redirect not effective in dataplane: policy port {p_pbr.name} "
            f"TX+{d_pbr} (want ~{_N}); route port {p_rt.name} TX+{d_rt}")
        assert d_rt <= _N * 0.2, (
            f"matched traffic still follows the ROUTE egress {p_rt.name} (TX+{d_rt}) "
            f"instead of the PBR port {p_pbr.name} (TX+{d_pbr})")

        # Negative control: traffic in the same subnet that does NOT match the /32 rule should still take the
        # route egress -- distinguishing "selective policy redirect" from "all ingress traffic wrongly diverted
        # wholesale to p_pbr" (rule fields programmed as a wildcard)
        dst_ip2 = dst_net.split("/")[0].rsplit(".", 1)[0] + ".10"
        pkt2 = (Ether(dst=rmac, src=topo.mac("src")) /
                IP(src=sub_in["peer"], dst=dst_ip2, ttl=64) / UDP() / Raw(b"q" * 40))
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(p_in, pkt2, count=_N)
        d_rt2, d_pbr2 = _accum_tx2(p_rt, p_pbr, floor_a=_N * 0.8)
        assert _N * 0.8 <= d_rt2 < 100_000, (
            f"control flow (dst {dst_ip2} outside the /32 PBR rule) not routed out "
            f"{p_rt.name} (TX+{d_rt2}, want ~{_N}); routing baseline broken, "
            f"cannot judge PBR selectivity")
        assert d_pbr2 <= _N * 0.2, (
            f"control flow (dst {dst_ip2}, should NOT match the /32 rule) also redirected "
            f"to PBR port {p_pbr.name} (TX+{d_pbr2}); PBR match not selective "
            f"(rule programmed as wildcard?)")
    finally:
        _lb.disable_flood_safe(p_pbr)
        cli.neigh_del(nh, p_rt.name)
