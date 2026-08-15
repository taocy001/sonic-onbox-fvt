"""Validate the asymmetric VLAN hairpin topology: dual-port loopback but structurally loop-broken (no storm) + correct forwarding + return frames capturable."""
import time

import pytest

pytestmark = [pytest.mark.smoke, pytest.mark.traffic]


def test_hairpin_no_storm_and_forward(cli, dut, _lb, topo):
    """CPU->p_in(A)->forward to p_out->p_out loopback->VLAN B (dead end/SVI). Validate:
    ingress loopback re-entry ~N, **FDB-directed** forwarding to p_out ~N, and p_out's return does
    not leak back into VLAN A (no storm). VLAN/IP/MAC all come from topo, not hardcoded.

    Decidability of "directed vs flooded": the hairpin VLAN A originally had only two ports p_in/p_out --
    when the static FDB is not truly programmed, the only destination for unknown-unicast flooding within
    A is also p_out (RX likewise ~N), and the two mechanisms are indistinguishable. So:
    (1) before injection, hard-confirm that dmac is already in the chip l2 table (fdb_to_out's internal
        timeout only WARNINGs, which is insufficient as evidence);
    (2) add a third member port pctrl (chip-level untagged join to VLAN A + flood_safe isolated VLAN):
        on an FDB hit pctrl TX~0, on flooding ~N -- within the same injection, assert p_out received it
        while pctrl stayed silent, so the conclusion is self-evident.
    Storm prevention: pctrl untagged egress, so loopback re-entry frames without a tag land on the isolated
    PVID and terminate (a tagged re-entry would keep the tag and self-loop)."""
    from scapy.all import Ether, IP, UDP, Raw, sendp
    from framework.counters import ChipCounters
    from topo.hairpin import Hairpin

    dmac = topo.hp_probe_dst
    p_in, p_out = topo.port("e"), topo.port("f")
    pctrl = topo.misc_port(0)
    if pctrl.name in (p_in.name, p_out.name):
        pytest.skip("need a distinct third port as flood-control member")
    hp = Hairpin(cli, dut, _lb, p_in, p_out,
                 topo.hp_vlan_a, topo.hp_vlan_b, svi_ip=(None if __import__("os").environ.get("HP_SVI","1")=="0" else topo.hp_svi))
    hp.setup()
    bsh = _lb.bsh
    cd_ctrl = dut.bcm_of(pctrl)
    ctrl_added = False
    try:
        hp.fdb_to_out(dmac)
        # (1) hard-confirm FDB programming (chip l2 table, compatible with the SONiC model that does not
        # expose an ASIC_DB FDB object): when unprogrammed, "forward to p_out" and "flood happens to reach
        # p_out" are indistinguishable, so honest FAIL rather than continuing with a WARNING
        programmed = False
        norm_dmac = dmac.replace(":", "").upper()
        for _ in range(10):
            out = bsh.cmd("l2 show") or ""
            if norm_dmac in out.replace(":", "").upper():
                programmed = True
                break
            time.sleep(0.5)
        assert programmed, (
            f"static FDB {dmac} not present in chip l2 table after fdb_to_out; "
            f"forwarded-vs-flood would be indistinguishable")
        # (2) control port: chip-level untagged join to VLAN A + flood_safe (isolated VLAN, loopback TX measurable, re-entry terminates)
        cli.ensure_port_l2(pctrl)
        cli.intf_startup(pctrl.name)
        bsh.cmd(f"vlan add {topo.hp_vlan_a} pbm={cd_ctrl} ubm={cd_ctrl}")
        ctrl_added = True
        _lb.enable_flood_safe(pctrl, 3991)
        time.sleep(2)
        hp.arm()              # override PVID at the last moment before sending (asymmetric loop-break); no VLAN/FDB programming is triggered afterwards
        n = 100
        # this diag `show c` only shows counts that changed since the last show/clear (delta semantics),
        # so clear to zero -> send traffic -> read once + confirming read **summed** (to catch late frames /
        # slow storms), not base/after subtraction.
        ChipCounters.clear(bsh)
        pkt = Ether(dst=dmac, src=topo.mac("src")) / IP() / UDP() / Raw(b"x" * 40)
        sendp(pkt, iface=p_in.name, count=n, verbose=0)
        time.sleep(1)
        di = ChipCounters.read(bsh, dut.bcm_of(p_in))
        do = ChipCounters.read(bsh, dut.bcm_of(p_out))
        dc = ChipCounters.read(bsh, cd_ctrl)
        time.sleep(0.5)   # confirming read: under delta semantics the sum is the total since clear
        di2 = ChipCounters.read(bsh, dut.bcm_of(p_in))
        do2 = ChipCounters.read(bsh, dut.bcm_of(p_out))
        dc2 = ChipCounters.read(bsh, cd_ctrl)
        in_rx = di.rx_pkt + di2.rx_pkt
        out_rx = do.rx_pkt + do2.rx_pkt
        ctrl_tx = dc.tx_pkt + dc2.tx_pkt
        # ingress loopback re-entry ~N (CPU-injected frames loop back and re-enter p_in)
        assert in_rx >= n * 0.9, f"Ingress loopback re-entry abnormal RX+{in_rx}"
        # proof of forwarding to p_out uses p_out's RX (forwarded frames egress p_out then loop back and
        # re-enter, so RX is reliable; the loopback port's TX count is unstable on this platform, so TX is
        # not used). p_out RX ~N means "forwarding arrived + egress processing".
        assert out_rx >= n * 0.9, f"Not forwarded to p_out (its RX+{out_rx})"
        # directed, not flooded: the third same-VLAN member pctrl must stay silent (on flooding it would likewise receive ~N)
        assert ctrl_tx <= 5, (
            f"hairpin forwarding was flooding, not FDB-directed: control member {pctrl.name} "
            f"TX+{ctrl_tx} (directed unicast must not reach non-target members)")
        # key: return frames enter the VLAN B dead end and do not leak back into A -> counts bounded, no runaway storm
        assert out_rx < 100000, f"Return frames suspected of looping back into a storm (RX+{out_rx})"
        assert in_rx < 100000, f"Ingress suspected of being flooded into a storm (RX+{in_rx})"
    finally:
        _lb.disable_flood_safe(pctrl)   # no-op when not enabled (restores internally per the tracking table)
        if ctrl_added:
            bsh.cmd(f"vlan remove {topo.hp_vlan_a} pbm={cd_ctrl}")
        hp.teardown()


def test_hairpin_capture_forwarded(cli, dut, _lb, topo):
    """Pattern C: capture the forwarded frame **after p_out egress processing** (validates the forwarding
    path + packet content, not just counters).
    Frame CPU->p_in(A)->forward out p_out->loopback into VLAN B->punt CPU->captured inbound on the p_out netdev."""
    from scapy.all import Ether, IP, UDP, Raw, sendp
    from framework.traffic import Capture
    from topo.hairpin import Hairpin

    dmac = topo.hp_probe_dst
    p_in, p_out = topo.port("e"), topo.port("f")
    hp = Hairpin(cli, dut, _lb, p_in, p_out,
                 topo.hp_vlan_a, topo.hp_vlan_b, svi_ip=topo.hp_svi)
    hp.setup()
    hp.fdb_to_out(dmac)        # VLAN A: probe->p_out forwarding
    hp.punt_b_to_cpu(dmac)     # VLAN B: probe->CPU punt (capture point)
    try:
        time.sleep(2)
        hp.arm()
        magic = b"HAIRPINCAP"
        # a non-trap L2 punt lands on the KNET netdev of the frame's re-entry port (p_out)
        capdev = p_out.name
        with Capture(capdev, bpf=None, inbound=True) as cap:
            pkt = (Ether(dst=dmac, src=topo.mac("src")) /
                   IP() / UDP() / Raw(magic + b"x" * 30))
            sendp(pkt, iface=p_in.name, count=20, verbose=0)
            time.sleep(0.6)
        hits = cap.match(lambda x: magic in bytes(x))
        assert hits, f"Forwarded frame not captured on {capdev} -- Pattern C capture failed"
    finally:
        hp.teardown()
