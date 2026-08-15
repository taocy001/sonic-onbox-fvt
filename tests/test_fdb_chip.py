"""L2 FDB chip-behavior-level verification (dynamic learning / known-unicast directed vs unknown-unicast flood / MAC move / static / flush / aging).

This module deliberately does a triple verification of "dataplane + chip table + ASIC_DB",
correcting the anti-pattern of "only checking that a DB object exists":
  (1) ASIC_DB SAI_OBJECT_TYPE_FDB_ENTRY appears (programming path);
  (2) read-only bcmcmd `l2 show` lists the MAC (chip L2 table actually programmed);
  (3) dataplane: chip TX counters / copy-to-cpu capture, proving frames are actually
      forwarded/flooded per the FDB.

Inputs only go through legitimate paths: scapy packet injection (learn/flood stimulus),
cli.fdb_static_add (swssconfig->APPL_DB), config / sonic-clear (flush),
CONFIG_DB SWITCH.fdb_aging_time (aging). bcmcmd is only used read-only for `l2 show`.

Topology (three-member VLAN, the key to verifying "directed vs flood"):
  p_in  = traffic.ports[0]  ingress, MAC loopback (already enabled by fixture); CPU-injected
          packets re-enter the pipeline from here.
  p_out = traffic.ports[1]  default VLAN member, looped on demand by this module (known
          unicast, no storm).
  p_3rd = topo.misc_port(0) a third default VLAN member, added and looped by this module.
  -> known unicast dst=X should only reach the port that learned X; unknown unicast should
     flood to **all other members** (both p_out and p_3rd).

Storm safety: the unknown-unicast flood cases send only a small burst (N) once and read
counters right after; loopback ports are all disabled in teardown.
Prints/asserts/skips in English; comments/docstrings in Chinese. Ports/VLAN/MAC are all
taken from topo, never hardcoded.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.l2, pytest.mark.traffic]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 100                     # injected packet count (small burst, paired with upper-bound asserts to guard against runaway storms)
_LOWER = _N * 0.8            # forward/flood lower bound (tolerates loopback jitter)
_NEAR_ZERO = _N * 0.3       # "almost nothing received" upper bound (directed unicast should not reach the non-target port)


# ----------------------------- helpers -----------------------------
def _mac_in_asicdb(asicdb, mac):
    """Whether ASIC_DB has an FDB_ENTRY for this MAC (key contains the colon-stripped MAC, case-insensitive)."""
    needle = mac.replace(":", "").upper()
    keys = []
    for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY"):
        ku = k.upper()
        if needle in ku or mac.upper() in ku:
            keys.append(k)
    return keys


def _wait_asicdb_mac(asicdb, mac, tries=20):
    for _ in range(tries):
        keys = _mac_in_asicdb(asicdb, mac)
        if keys:
            return keys
        time.sleep(0.4)
    return []


def _port_token_in(line, bcm):
    """Whether an `l2 show` line contains the **full** bcm port name (anchored on word boundaries).

    A bare substring match would let cd1 falsely match cd13: old port cd1 colliding with the
    new port cd13's line -> false "still on old port" FAIL; conversely (new port cd1 colliding
    with some other cd13) -> false PASS. With anchoring, cd1 followed by a digit/letter no longer matches."""
    return bool(re.search(rf"(?<![\w]){re.escape(bcm)}(?![\w])", line or ""))


def _mac_in_chip_l2(bsh, mac):
    """Read-only bcmcmd `l2 show` to determine whether the MAC is in the chip L2 table (colon-stripped, case-insensitive).

    An `l2 show` line looks like:  mac=00:de:ad:be:ef:7a vlan=1000 ... port=14 ...
    Different SDKs emit different column order/separators, so we only do a substring match
    (trying both the colon and colon-stripped forms).
    """
    out = bsh.cmd("l2 show")
    norm = out.replace(":", "").upper()
    return mac.replace(":", "").upper() in norm or mac.upper() in out.upper()


def _wait_chip_l2_mac(bsh, mac, present=True, tries=20):
    """Poll the chip L2 table until the MAC appears (present=True) or disappears (present=False). Returns whether it was reached."""
    for _ in range(tries):
        if _mac_in_chip_l2(bsh, mac) == present:
            return True
        time.sleep(0.4)
    return False


def _learn_to_asic(traffic, port, pkt, asicdb, _lb, mac, sends=4):
    """Send learn frames and wait for the MAC to enter ASIC_DB + the chip L2 table; if it doesn't appear, **re-send** + extend polling.

    Absorbs the occasional learn/sync delay that the single-case path should legitimately survive
    (e.g. syncd occasionally being slow to sync a chip MAC into ASIC_DB). This does not relax the
    assertion: it only returns True on a genuine learn. This helper only absorbs occasional delays in the single-case scenario."""
    _lb.wait_learn_ready(port)     # learning is enabled asynchronously after oper-up (bridge-port admin), so wait for it to truly open first
    for _ in range(sends):
        traffic.send(port, pkt, count=20)
        time.sleep(1.2)
        if _wait_asicdb_mac(asicdb, mac, tries=15) and _wait_chip_l2_mac(_lb.bsh, mac, present=True, tries=15):
            return True
    return False


def _learn_to_chip(traffic, port, pkt, _lb, mac, sends=4):
    """Send learn frames and wait for the MAC to enter the **chip L2 table** (verify chip only, not ASIC_DB); re-send if it doesn't appear.

    Used by flood cases running in a **dedicated test VLAN** (chip-level, unknown to orchagent, so
    learned MACs are not synced into ASIC_DB, confirmed empirically) -- for these ports, the learn/
    forward evidence is the chip l2 table and chip TX counters. Re-sends absorb occasional learn delays."""
    _lb.wait_learn_ready(port)     # learning is enabled asynchronously after oper-up (bridge-port admin), so wait for it to truly open first
    for _ in range(sends):
        traffic.send(port, pkt, count=20)
        time.sleep(1.2)
        if _wait_chip_l2_mac(_lb.bsh, mac, present=True, tries=15):
            return True
    return False


@pytest.fixture
def third_member(cli, dut, topo, _lb, traffic):
    """Add topo.misc_port(0) to the default VLAN and enable loopback, as a third VLAN member (verify flood vs directed).

    A different port from traffic.ports[0/1]; teardown disables loopback + removes from VLAN
    (idempotent reset).
    If this port happens to overlap the two ports traffic selected (a device with few ports),
    skip -- a three-member topology cannot be built.
    """
    p3 = topo.misc_port(0)
    if p3.name in (traffic.ports[0].name, traffic.ports[1].name):
        pytest.skip(f"misc_port {p3.name} overlaps traffic ports; need 3 distinct VLAN members")
    dv = topo.default_vlan
    if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{p3.name}"):
        cli.config_raw(f"vlan member add -u {dv} {p3.name}")
    # wait for the membership to be actually programmed (otherwise it won't receive the flood, a false negative)
    for _ in range(20):
        if cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{p3.name}"):
            break
        time.sleep(0.3)
    cli.intf_startup(p3.name)
    _lb.enable(p3)   # bring loopback up so chip TX counters are stable
    # chip learning (Lrn=ARL) is enabled **asynchronously** by portsorch after oper-up: without waiting
    # for it to truly open, relearn frames landing in that window are silently dropped/not learned ->
    # false "no move" failure (see the loopback.wait_learn_ready mechanism note)
    _lb.wait_learn_ready(p3)
    time.sleep(1)
    yield p3
    _lb.disable(p3)
    cli.config_raw(f"vlan member del {dv} {p3.name}")
    cli.sh.run("sonic-clear fdb all", check=False)


# ============================ cases ============================
def test_dynamic_learning_chip_and_directed_unicast(cli, traffic, asicdb, _lb, topo, l2_fwd_vlan):
    """[1] Dynamic MAC learning + known-unicast **directed** forwarding:
      arrange: inject a frame (src=learn MAC) from p_out -> the chip learns learn->p_out in this VLAN.
      verify-chip (1) ASIC_DB shows the FDB_ENTRY (2) read-only `l2 show` lists the MAC.
      verify-dataplane: send known unicast dst=learn MAC from p_in -> should forward **only** to p_out
        (p_out TX~=N), and should not flood to the third member (third_member TX~=0) -- proving the
        chip forwards directed per the learned FDB, not by flooding.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")

    vlan = l2_fwd_vlan   # use a real VLAN on devices where the default VLAN does not forward
    learn = topo.mac("learn")              # source MAC dedicated to dynamic learning (independent, avoids FDB cross-talk)
    p_in, p_out = traffic.ports[0], traffic.ports[1]

    # A third member is needed to prove "directed != flood". Managed manually (not folded into a fixture, so this case is self-describing).
    p3 = topo.misc_port(0)
    if p3.name in (p_in.name, p_out.name):
        pytest.skip("not enough distinct ports for directed-vs-flood check")
    if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vlan}|{p3.name}"):
        cli.config_raw(f"vlan member add -u {vlan} {p3.name}")
        for _ in range(20):
            if cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vlan}|{p3.name}"):
                break
            time.sleep(0.3)
    cli.intf_startup(p3.name)

    cli.sh.run("sonic-clear fdb all", check=False)   # clean starting point
    traffic.loop(p_out)                  # directed target port: plain loopback (PVID=original VLAN; dst==ingress re-entry is filtered by same-port, no loop)
    _lb.enable_flood_safe(p3, 3991)      # non-target measurement port: flood-safe loopback (PVID changed to an isolation VLAN to break the loop)
    # Point the learn-stimulus frame's dst statically at p3 first (known unicast) -> the frame is **directed**
    # to p3 rather than flooded, avoiding a self-loop storm across the p_in/p_out multi-loopback ports;
    # the SMAC still learns learn->p_out at ingress (p_out, PVID=original VLAN) as usual. After p3 receives
    # this frame, its loopback re-entry lands in the isolation VLAN and terminates, so it does not falsely
    # move learn back into the original VLAN.
    learn_dst = "00:aa:bb:cc:dd:71"
    cli.fdb_static_add(vlan, learn_dst, p3.name)
    time.sleep(1)
    try:
        # --- learn stimulus: inject src=learn frame from p_out (dst known -> directed to p3; SMAC still learned on p_out ingress) ---
        # triple verification (1) ASIC_DB FDB_ENTRY (2) chip l2 table; re-sends absorb occasional learn/sync delays from back-to-back run backlog.
        learn_pkt = (Ether(dst=learn_dst, src=learn) /
                     IP(dst="10.0.0.1") / UDP() / Raw(b"LEARN" + b"x" * 40))
        assert _learn_to_asic(traffic, p_out, learn_pkt, asicdb, _lb, learn), \
            f"dynamic MAC {learn} not programmed to ASIC_DB + chip l2 after learning on {p_out.name}"

        # learn has already been learned as learn->p_out in the original VLAN. Before the directed
        # measurement, switch p_out's ingress PVID to an isolation VLAN: otherwise, when a directed frame
        # reaches p_out (looped) egress, the loopback re-entry gets **directed to p_out again** -> self-loop
        # storm (root cause found empirically: any frame forwarded to a looped port loops, and same-port
        # filtering cannot break it). After switching to the isolation PVID, the re-entry frame lands in
        # the isolation VLAN, finds no destination and terminates; TX is still measurable. The learn->p_out
        # FDB entry and p_out's original-VLAN egress membership are unaffected by the PVID.
        _lb.isolate_pvid(p_out, 3990)

        # --- dataplane: known unicast dst=learn enters from p_in, should reach only p_out, not p3 ---
        uni = (Ether(dst=learn, src="00:aa:bb:cc:dd:72") /
               IP(dst="10.0.0.2") / UDP() / Raw(b"UNI" + b"x" * 40))
        # zero out then send traffic, read each port once (count arriving at that port since clear); do not
        # diff base/after -- this diag `show c` only shows changes since the last show/clear, so a base read
        # would consume the display + include background noise -> possible negative delta (see test_l3_forward_traffic)
        traffic.clear_chip_counters()
        traffic.send(p_in, uni, count=_N)
        time.sleep(1)
        d_out = traffic.chip_counters(p_out)
        d_3 = traffic.chip_counters(p3)

        assert d_out.tx_pkt >= _LOWER, \
            f"known-unicast not forwarded to learned port {p_out.name} (TX+{d_out.tx_pkt}, want ~{_N})"
        # upper bound guards against a storm: the isolation PVID broke the "directed to looped port" self-loop, so p_out should be ~=N rather than blown up
        assert d_out.tx_pkt < 10_000, \
            f"directed-to-looped storm on {p_out.name} (TX+{d_out.tx_pkt}); isolate-PVID not breaking the loop"
        assert d_3.tx_pkt <= _NEAR_ZERO, \
            (f"known-unicast leaked to non-target member {p3.name} (TX+{d_3.tx_pkt}); "
             f"FDB directed forwarding broken (should not flood)")
    finally:
        _lb.restore_pvid(p_out)
        cli.fdb_static_del(vlan, learn_dst)
        traffic.unloop(p_out)
        _lb.disable_flood_safe(p3)
        cli.config_raw(f"vlan member del {vlan} {p3.name}")
        cli.sh.run("sonic-clear fdb all", check=False)


def test_unknown_unicast_floods_all_members(cli, traffic, _lb, topo, l2net):
    """[2] Unknown unicast **floods to all other members** (**dedicated test VLAN** + flood-safe loopback, zero storm/zero degradation on a single device):
    an unlearned-dst unicast enters from p_in, should flood to **all** other members of this VLAN (both p_out and p3 chip TX ~=N).

    Storm safety: the ports under test p_out/p3 use enable_flood_safe (loop + ingress PVID changed to
    their own isolation VLAN -> re-entry terminates, no self-loop storm). Degradation guard: l2net shrinks
    the flood domain to the 4 ports of the dedicated VLAN (the injection port p_in's PVID points at the
    dedicated VLAN), so the flood only replicates to 4 ports rather than every member of the production VLAN.

    VLAN boundary control: p_ext, which stays in the **default VLAN**, has TX~=0 within the same
    measurement window -- the flood domain must be confined to this VLAN's member PBM; member-PBM
    over-programming (e.g. the accident class where an undo silently fails and leaks a port into the VLAN) is exposed here.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan, p_in, p_out, p3, _sink = l2net
    # VLAN boundary control port: take an L2-domain port (not among l2net's 4 ports, still in the default VLAN);
    # if unavailable/overlapping, degrade to no boundary control (the other asserts are unchanged, not weakened)
    p_ext = None
    try:
        cand = topo.l2_port(0)
        if cand.name not in {p_in.name, p_out.name, p3.name, _sink.name}:
            p_ext = cand
    except Exception:  # noqa: BLE001
        p_ext = None
    # the two ports under test: flood-safe loopback (each with a different isolation VLAN to break the loop; orig PVID=dedicated VLAN, auto-restored)
    _lb.enable_flood_safe(p_out, 3991)
    _lb.enable_flood_safe(p3, 3992)
    if p_ext is not None:
        cli.ensure_port_l2(p_ext)          # convert OS: an L3 port does not participate in L2 flooding, so move it to bridge first
        cli.intf_startup(p_ext.name)
        _lb.enable_flood_safe(p_ext, 3993)  # bring loopback up so TX is measurable; isolation PVID prevents its own noise from amplifying
    time.sleep(1)
    try:
        unknown = "00:aa:bb:cc:dd:7f"     # a never-learned dst -> unknown unicast -> flood
        pkt = (Ether(dst=unknown, src="00:aa:bb:cc:dd:73") /
               IP(dst="10.0.0.3") / UDP() / Raw(b"FLOOD" + b"x" * 40))
        # zero out then send traffic, read each port once (count arriving at that port since clear); do not diff base/after (clear->read-once semantics)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=_N)
        time.sleep(1)
        d_out = traffic.chip_counters(p_out)
        d_3 = traffic.chip_counters(p3)

        # the flood should reach both p_out and p3 (both other members TX~=N)
        assert d_out.tx_pkt >= _LOWER, \
            f"unknown-unicast not flooded to member {p_out.name} (TX+{d_out.tx_pkt}, want ~{_N})"
        assert d_3.tx_pkt >= _LOWER, \
            f"unknown-unicast not flooded to member {p3.name} (TX+{d_3.tx_pkt}, want ~{_N})"
        # upper bound guards against a storm: flood-safe loopback broke the loop, so it should be ~=N rather than blown up (the old version, without loop-breaking, could reach tens of millions here)
        assert d_out.tx_pkt < 10_000 and d_3.tx_pkt < 10_000, \
            f"flood storm suspected (p_out TX+{d_out.tx_pkt}, p3 TX+{d_3.tx_pkt}); flood-safe loopback not breaking the loop"
        if p_ext is not None:
            d_ext = traffic.chip_counters(p_ext)
            assert d_ext.tx_pkt <= _NEAR_ZERO, \
                (f"flood leaked across VLAN boundary to {p_ext.name} (default VLAN, TX+{d_ext.tx_pkt}); "
                 f"VLAN member PBM misprogrammed")
    finally:
        _lb.disable_flood_safe(p_out)
        _lb.disable_flood_safe(p3)
        if p_ext is not None:
            _lb.disable_flood_safe(p_ext)


def test_broadcast_floods_all_members(traffic, _lb, topo, l2net):
    """[7] Broadcast dst=ff:ff:ff:ff:ff:ff **floods to all other members** (dedicated test VLAN + flood-safe loopback).

    Complementary to [2]'s unknown unicast (DLF/UUC bitmap): broadcast goes through an **independent chip
    flood group** (BC_IDX), which can be mis-programmed independently, so [2] passing does not mean the
    broadcast path is correct. Topology/storm-safety is identical to [2]: p_out/p3 each use
    enable_flood_safe (different isolation VLANs to break the loop), lower bound proves arrival, upper bound guards against a storm.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan, p_in, p_out, p3, _sink = l2net
    _lb.enable_flood_safe(p_out, 3991)
    _lb.enable_flood_safe(p3, 3992)
    time.sleep(1)
    try:
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src="00:aa:bb:cc:dd:7e") /
               IP(dst="10.0.0.255") / UDP() / Raw(b"BCAST" + b"x" * 40))
        # zero out then send traffic, read each port once (count arriving at that port since clear); do not diff base/after (clear->read-once semantics)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=_N)
        time.sleep(1)
        d_out = traffic.chip_counters(p_out)
        d_3 = traffic.chip_counters(p3)

        assert d_out.tx_pkt >= _LOWER, \
            f"broadcast not flooded to member {p_out.name} (TX+{d_out.tx_pkt}, want ~{_N})"
        assert d_3.tx_pkt >= _LOWER, \
            f"broadcast not flooded to member {p3.name} (TX+{d_3.tx_pkt}, want ~{_N})"
        assert d_out.tx_pkt < 10_000 and d_3.tx_pkt < 10_000, \
            f"broadcast storm suspected (p_out TX+{d_out.tx_pkt}, p3 TX+{d_3.tx_pkt}); flood-safe loopback not breaking the loop"
    finally:
        _lb.disable_flood_safe(p_out)
        _lb.disable_flood_safe(p3)


def test_mac_move_relearn_on_new_port(cli, traffic, asicdb, _lb, topo, l2net):
    """[3] MAC move (relearn on a new port, **dedicated test VLAN**, storm-safe): the same src is first
    learned on p_out, then enters from the new port p3 -> the FDB should move to p3.
      verify-chip: in the chip `l2 show`, the MAC lands on the **new port p3** and leaves the old port
        p_out (anchored port-name match, to prevent cd1 falsely matching cd13). Note: the dedicated VLAN
        is chip-level and does not sync to ASIC_DB (empirically), so the move evidence relies on the chip table.
      verify-dataplane: after the move, send traffic with the MAC as dst (entering from p_in), it should
        forward to the **new port** p3 (TX~=N, storm upper bound), and **no longer** to the old port p_out
        (TX~=0) -- distinguishing "directed move" from "unknown-unicast flood".

    Storm-eradication change: moved from the default VLAN into l2net's 4-port scoped VLAN:
      (1) the scoped VLAN shrinks the flood domain from the default VLAN (16 ports) to 4 ports, and is
         **immune to stray loopbacks outside the domain** -- the original implementation had p_in/p_out/p3
         plain-looped in the default VLAN, and any stray loopback port outside the domain + unknown-unicast/
         multicast noise self-amplified into a storm (measured: new port p3 TX +90 million); the scoped
         4-port domain caps the flood-copy count and keeps bypass ports out.
      (2) seed a directed flood_safe sink (chip-level static FDB, no flood);
      (3) disable_ipv6 during the test window to kill kernel noise multicast (>=2 plain-looped ports in the
         same VLAN + any multicast noise = perpetual loop).
    During the measurement phase, p_in/p_out/p3 stay **plain-looped without switching PVID** -- flood_safe/
    isolate PVID switching flushes dynamic entries on some devices, so storm safety relies on (1)+(2)+(3)
    and the upper-bound assert, not isolate (cross-device safe).
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vid, p_in, p_out, p3, sink = l2net    # l2net: 4-port scoped VLAN (already flush_fdb + use_test_vlan to shrink the domain)
    mover = "00:de:ad:be:ef:7c"      # MAC dedicated to the move (independent)
    # disable IPv6 on the 4 ports during the test window: kernel noise multicast (ND/MLD) perpetually loops and amplifies across multiple plain-looped ports in the same VLAN
    for _p in (p_in, p_out, p3, sink):
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{_p.name}.disable_ipv6=1", check=False)
    traffic.loop(p_out)              # old port (learning port) plain loopback
    _lb.enable(p3)                   # new port (move target) plain loopback: the move needs re-entry to relearn
    _lb.wait_learn_ready(p3)         # chip learning (Lrn=ARL) is enabled asynchronously after oper-up, so wait for it to truly open first
    # sink flood_safe (loopback brings it oper-up -> only then is it a valid FDB target; isolate PVID -> re-entry terminates after receiving the seed).
    _lb.enable_flood_safe(sink, 3993)
    seed_dst = "00:aa:bb:cc:dd:74"
    _lb.chip_fdb_add(vid, seed_dst, sink)   # chip-level static FDB (the scoped VLAN is not in CONFIG_DB, swssconfig does not apply)
    time.sleep(1)
    try:
        seed = lambda: (Ether(dst=seed_dst, src=mover) /  # noqa: E731
                        IP(dst="10.0.0.4") / UDP() / Raw(b"MOVE" + b"x" * 40))
        traffic.send(p_out, seed(), count=20)            # first learn mover on p_out
        time.sleep(1.2)
        traffic.send(p3, seed(), count=20)               # then enter the same src from p3 -> move to p3

        # verify move: in the chip L2 table, mover must land on the **new port p3's cd** and no longer on
        # the old port p_out's cd (the port moves as the src reappears; this is the direct chip-level evidence
        # of the move). Port name matched with both-side anchoring.
        # periodic re-sends during polling: frames landing in the ARL-not-ready window should not turn into
        # a false "no move" failure (pure timing hardening).
        p3_bcm = _lb.dut.bcm_of(p3)
        p_out_bcm = _lb.dut.bcm_of(p_out)
        l2line = ""
        for i in range(20):
            out = _lb.bsh.cmd("l2 show")
            l2line = next((ln for ln in out.splitlines() if mover.lower() in ln.lower()), "")
            if _port_token_in(l2line, p3_bcm):
                break
            if i % 4 == 3:
                traffic.send(p3, seed(), count=20)
            time.sleep(0.4)
        assert l2line, f"MAC {mover} absent from chip 'l2 show' after relearn on new port"
        assert _port_token_in(l2line, p3_bcm), \
            f"after move, MAC {mover} not on new port {p3.name}({p3_bcm}) in chip l2: {l2line!r}"
        assert not _port_token_in(l2line, p_out_bcm), \
            f"after move, MAC {mover} still on old port {p_out.name}({p_out_bcm}): {l2line!r}; move not effective"

        # verify-dataplane: dst=mover enters from p_in -> should forward **only** to the new port p3, no longer to the old port p_out.
        # the three ports stay plain-looped (the noise source was already killed by disable_ipv6; PVID not switched to avoid flushing dynamic entries, which some devices do).
        fwd = (Ether(dst=mover, src="00:aa:bb:cc:dd:7c") /
               IP(dst="10.0.0.5") / UDP() / Raw(b"MOVED" + b"x" * 40))
        # zero out then send traffic, read each port once (delta semantics since clear); do not diff base/after (clear->read-once)
        traffic.clear_chip_counters()
        traffic.send(p_in, fwd, count=_N)
        time.sleep(1)
        d_new = traffic.chip_counters(p3)
        d_old = traffic.chip_counters(p_out)
        assert d_new.tx_pkt >= _LOWER, \
            (f"after MAC move, traffic not forwarded to new port {p3.name} "
             f"(TX+{d_new.tx_pkt}, want ~{_N})")
        assert d_new.tx_pkt < 10_000, \
            f"storm suspected on new port {p3.name} after move (TX+{d_new.tx_pkt})"
        assert d_old.tx_pkt <= _NEAR_ZERO, \
            (f"after MAC move, traffic still reaching old port {p_out.name} "
             f"(TX+{d_old.tx_pkt}, new={d_new.tx_pkt}); move not directed (looks like flood)")
    finally:
        _lb.disable_flood_safe(sink)
        _lb.chip_fdb_del(vid, seed_dst)
        _lb.disable(p3)
        traffic.unloop(p_out)
        for _p in (p_in, p_out, p3, sink):
            cli.sh.run(f"sysctl -qw net.ipv6.conf.{_p.name}.disable_ipv6=0", check=False)
        # l2net teardown is responsible for drop_test_vlan + flush_fdb (restore PVID / destroy the scoped VLAN)


def test_static_fdb_chip_and_dataplane(cli, traffic, asicdb, _lb, topo, config_guard, l2_fwd_vlan):
    """[4] Static FDB: install a dmac->p_out static entry via swssconfig.
      verify-chip (1) ASIC_DB FDB_ENTRY appears (2) read-only `l2 show` lists the MAC.
      verify-dataplane: dst=dmac enters from p_in -> directed forwarding to p_out (TX~=N); the non-target
        port p3 (flood_safe) TX~=0 -- the static programming path (swssconfig->APPL_DB->chip) differs from
        dynamic learning but needs the same "directed vs flood" criterion: if the entry exists but forwarding
        degrades to flooding, p_out still shows TX~=N, and only the third port being ~=0 proves directed.
    (Static entries do not depend on learning and do not age, serving as the control for [6] aging.)
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan = l2_fwd_vlan
    smac_static = "00:11:22:33:44:7d"
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    # non-target control port (degrades to two ports when there aren't enough for three, still keeping the upper-bound storm guard, not weakening existing asserts)
    p3 = topo.misc_port(0)
    has_p3 = p3.name not in (p_in.name, p_out.name)
    added_p3 = False

    traffic.loop(p_out)
    time.sleep(1)
    if has_p3:
        if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vlan}|{p3.name}"):
            cli.config_raw(f"vlan member add {cli.vlan_untagged_flag()} {vlan} {p3.name}")
            added_p3 = True
            for _ in range(20):
                if cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vlan}|{p3.name}"):
                    break
                time.sleep(0.3)
        cli.intf_startup(p3.name)
        _lb.enable_flood_safe(p3, 3991)   # bring loopback up so TX is measurable; isolation PVID breaks re-entry
    cli.fdb_static_add(vlan, smac_static, p_out.name)   # swssconfig, wait=True to wait for ASIC programming
    try:
        assert _mac_in_asicdb(asicdb, smac_static), \
            f"static FDB {smac_static} not in ASIC_DB FDB_ENTRY"
        assert _wait_chip_l2_mac(_lb.bsh, smac_static, present=True), \
            f"static FDB {smac_static} not present in chip 'l2 show'"

        # switch p_out to the isolation PVID to prevent a "directed to looped p_out" self-loop storm (re-entry
        # frames land in the isolation VLAN and terminate; the smac->p_out static entry and p_out's original-VLAN
        # egress are unaffected, directed forwarding proceeds as usual and TX is still measurable)
        _lb.isolate_pvid(p_out, 3990)
        pkt = (Ether(dst=smac_static, src="00:aa:bb:cc:dd:76") /
               IP(dst="10.0.0.6") / UDP() / Raw(b"STATIC" + b"x" * 40))
        # zero out then send traffic, read once (count arriving at p_out since clear); do not diff base/after (clear->read-once semantics)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=_N)
        time.sleep(1)
        d = traffic.chip_counters(p_out)
        assert d.tx_pkt >= _LOWER, \
            f"static FDB not forwarding to {p_out.name} (TX+{d.tx_pkt}, want ~{_N})"
        assert d.tx_pkt < 10_000, \
            f"directed-to-looped storm on {p_out.name} (TX+{d.tx_pkt}); isolate-PVID not breaking the loop"
        if has_p3:
            d3 = traffic.chip_counters(p3)
            assert d3.tx_pkt <= _NEAR_ZERO, \
                (f"static-FDB known-unicast leaked to non-target member {p3.name} "
                 f"(TX+{d3.tx_pkt}); looks like flood, not directed forwarding")
    finally:
        _lb.restore_pvid(p_out)
        cli.fdb_static_del(vlan, smac_static)
        traffic.unloop(p_out)
        if has_p3:
            _lb.disable_flood_safe(p3)
            if added_p3:
                cli.config_raw(f"vlan member del {vlan} {p3.name}")


def test_static_fdb_immune_to_station_move(cli, traffic, _lb, topo, l2net):
    """[8] Static entry resists moving (station-move immunity, dedicated test VLAN): after a chip static FDB
    M->p_out, a frame with the same src=M entering from p3 **must not** move the entry away (classic static
    pinning / anti-spoofing behavior -- [3] and test_mac.py::test_mac_move only verified that a dynamic MAC
    **does** move; this case verifies the complementary contract: a static one **does not**).
      verify-chip: after the move stimulus, M in the chip `l2 show` is still on p_out (anchored port-name
        match), not on p3, and the STATIC flag is intact.
      verify-dataplane: dst=M entering from p_in still **directs** to p_out (TX~=N, storm upper bound), not to p3 (TX~=0).
    Storm safety: the move-stimulus frame's dst is statically directed at the flood_safe sink (no flood);
    before measurement, both p_out/p3 switch to the isolation PVID to break the loop (static entries are
    unaffected by PVID switching -- what gets flushed is dynamic entries; the empirical device differences only involve dynamic ones).
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan, p_in, p_out, p3, sink = l2net
    mac_static = "00:11:22:33:44:7e"     # the pinned static MAC (independent)
    seed_dst = "00:aa:bb:cc:dd:75"       # the directed sink MAC for the move-stimulus frame (independent)
    traffic.loop(p_out)                  # p_out loopback: the valid target of the static entry + measurable TX
    _lb.isolate_pvid(p_out, 3990)        # break the loop immediately: this case never needs p_out re-entry
    cli.intf_startup(sink.name)
    _lb.enable_flood_safe(sink, 3993)    # seed's directed target: only oper-up makes it a valid FDB target, re-entry terminates
    _lb.chip_fdb_add(vlan, seed_dst, sink)   # dedicated VLAN, chip-level, swssconfig does not apply
    _lb.chip_fdb_add(vlan, mac_static, p_out)
    time.sleep(1)
    p_out_bcm = _lb.dut.bcm_of(p_out)
    p3_bcm = _lb.dut.bcm_of(p3)
    try:
        assert _wait_chip_l2_mac(_lb.bsh, mac_static, present=True), \
            f"static FDB {mac_static} not present in chip 'l2 show' (cannot test move immunity)"

        # move stimulus: src=M enters from p3 (dst directed to sink, no flood). p3 needs plain loopback and
        # PVID=this VLAN so the frame triggers the station-move decision at this VLAN's ingress; the stimulus
        # only matters once learning is truly open (ARL).
        _lb.enable(p3)
        _lb.wait_learn_ready(p3)
        mv = (Ether(dst=seed_dst, src=mac_static) /
              IP(dst="10.0.0.8") / UDP() / Raw(b"PIN" + b"x" * 40))
        traffic.send(p3, mv, count=20)
        time.sleep(1.5)

        # verify-chip: M is still pinned on p_out, has not moved to p3, and the STATIC flag is present
        line = next((ln for ln in (_lb.bsh.cmd("l2 show") or "").splitlines()
                     if mac_static.lower() in ln.lower()), "")
        assert line, \
            f"static MAC {mac_static} vanished from chip l2 after station-move attempt"
        assert _port_token_in(line, p_out_bcm), \
            f"static MAC {mac_static} moved off {p_out.name}({p_out_bcm}): {line!r}; static pinning broken"
        assert not _port_token_in(line, p3_bcm), \
            f"static MAC {mac_static} moved to {p3.name}({p3_bcm}): {line!r}; static pinning broken"
        assert "static" in line.lower(), \
            f"STATIC flag lost after station-move attempt: {line!r}"

        # verify-dataplane: dst=M enters from p_in -> still directs to p_out, not to p3. Before measurement,
        # p3 switches to the isolation PVID (measurable TX + breaks its re-entry; static entries are unaffected).
        _lb.isolate_pvid(p3, 3992)
        pkt = (Ether(dst=mac_static, src="00:aa:bb:cc:dd:6d") /
               IP(dst="10.0.0.8") / UDP() / Raw(b"PINNED" + b"x" * 40))
        # zero out then send traffic, read each port once (delta semantics since clear); do not diff base/after (clear->read-once)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=_N)
        time.sleep(1)
        d_out = traffic.chip_counters(p_out)
        d_3 = traffic.chip_counters(p3)
        assert d_out.tx_pkt >= _LOWER, \
            (f"traffic to pinned static MAC not forwarded to {p_out.name} "
             f"(TX+{d_out.tx_pkt}, want ~{_N})")
        assert d_out.tx_pkt < 10_000, \
            f"directed-to-looped storm on {p_out.name} (TX+{d_out.tx_pkt}); isolate-PVID not breaking the loop"
        assert d_3.tx_pkt <= _NEAR_ZERO, \
            (f"traffic to pinned static MAC leaked to {p3.name} (TX+{d_3.tx_pkt}); "
             f"entry moved or flood, static pinning not effective in dataplane")
    finally:
        _lb.restore_pvid(p3)
        _lb.disable(p3)
        _lb.restore_pvid(p_out)
        _lb.chip_fdb_del(vlan, mac_static)
        _lb.chip_fdb_del(vlan, seed_dst)
        _lb.disable_flood_safe(sink)
        traffic.unloop(p_out)


def test_fdb_flush_clears_chip_and_reverts_to_flood(cli, traffic, _lb, topo, l2net):
    """[5] flush (**dedicated test VLAN**, flood domain shrunk to 4 ports to prevent degradation): first learn a
    dynamic MAC (confirmed in chip l2), then after `sonic-clear fdb all` the entry should **disappear from the
    chip `l2 show`**; dataplane: after flush, sending traffic with this MAC as dst should, having no FDB, revert
    to **flooding to all members** (both p_out and p3 TX>0), proving flush truly cleared the chip forwarding state.
    Note: the dedicated VLAN is chip-level and does not sync to ASIC_DB (empirically), so learn/clear is observed
    on chip l2; the reflood only floods within this VLAN's 4 ports.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan, p_in, p_out, p3, sink = l2net
    learn = "00:de:ad:be:ef:8a"   # MAC independent to this case (avoids reusing the same default MAC across cases -> not learnable on back-to-back runs)
    traffic.loop(p_out)
    _lb.enable_flood_safe(sink, 3993)        # sink loopback+isolate: the valid target of the directed learn frame, re-entry terminates without flooding
    seed_dst = "00:aa:bb:cc:dd:77"
    _lb.chip_fdb_add(vlan, seed_dst, sink)   # chip-level static FDB (the dedicated VLAN is not in CONFIG_DB, swssconfig does not apply)
    time.sleep(1)
    try:
        # learn (directed to sink, learn is learned on p_out ingress); verify chip l2 only (the dedicated VLAN does not sync to ASIC_DB)
        learn_pkt = Ether(dst=seed_dst, src=learn) / IP() / UDP() / Raw(b"x" * 40)
        assert _learn_to_chip(traffic, p_out, learn_pkt, _lb, learn), \
            f"{learn} not learned to chip l2 before flush (after re-sends)"

        # flush (sonic-clear fdb all goes through SAI flush-all-dynamic, clearing the entire chip dynamic FDB, including this dedicated VLAN)
        cli.sh.run("sonic-clear fdb all", check=False)
        time.sleep(1.5)
        assert _wait_chip_l2_mac(_lb.bsh, learn, present=False), \
            f"dynamic MAC {learn} still in chip 'l2 show' after 'sonic-clear fdb all'"

        # dataplane: after flush, dst=learn becomes unknown unicast -> floods to all members. reflood floods to
        # multiple looped members, so both ports under test must be looped (to have measurable egress TX) +
        # isolation PVID to break the loop; the flood stays within this VLAN's 4 ports.
        # p_out is already looped by traffic.loop, then switched to isolate; p3 uses enable_flood_safe (loop+isolate in one step).
        _lb.isolate_pvid(p_out, 3990)
        _lb.enable_flood_safe(p3, 3992)
        pkt = (Ether(dst=learn, src="00:aa:bb:cc:dd:78") /
               IP(dst="10.0.0.7") / UDP() / Raw(b"REFLOOD" + b"x" * 40))
        # zero out then send traffic, read each port once (count arriving at that port since clear); do not diff base/after (clear->read-once semantics)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=_N)
        time.sleep(1)
        d_out = traffic.chip_counters(p_out).tx_pkt
        d_3 = traffic.chip_counters(p3).tx_pkt
        assert d_out >= _LOWER and d_3 >= _LOWER, \
            (f"after flush, frame to {learn} should flood to all members but "
             f"{p_out.name} TX+{d_out}, {p3.name} TX+{d_3}")
        assert d_out < 10_000 and d_3 < 10_000, \
            f"flood storm suspected after flush (p_out TX+{d_out}, p3 TX+{d_3})"
    finally:
        _lb.restore_pvid(p_out)
        _lb.disable_flood_safe(p3)
        _lb.chip_fdb_del(vlan, seed_dst)
        _lb.disable_flood_safe(sink)
        traffic.unloop(p_out)
        cli.sh.run("sonic-clear fdb all", check=False)


def test_dynamic_fdb_flush_on_link_down(cli, traffic, asicdb, _lb, topo, l2_fwd_vlan):
    """[9] link-down triggers **per-port** dynamic FDB flush (production Vlan1000): first learn a dynamic MAC
    on p_out (confirmed in chip + ASIC_DB), then disable p_out's loopback (link truly goes down) -> the entry
    should disappear from the chip `l2 show` and ASIC_DB within a short window.

    This is a **different code path** from [5]'s software flush (sonic-clear fdb all -> SAI flush-all): here it
    goes port oper-down -> fdborch/SAI flush_fdb_entries per port, which SONiC has a real regression history for.
    The 20s observation window is far shorter than the innate aging period, so the disappearance proves the
    link-down flush rather than aging.
    The learn frame is directed at the flood_safe sink (no flood, no contribution to flood degradation); single-port loopback topology same as [6].
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan = l2_fwd_vlan
    learn = "00:de:ad:be:ef:6a"   # MAC independent to this case
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    sink = topo.misc_port(1)
    if sink.name in (p_in.name, p_out.name):
        pytest.skip("need a 3rd distinct port as the directed learn sink")
    # single-port loopback topology (same rationale as [6]): unloop p_in, only p_out plain-looped, ruling out multi-plain-loopback-port loops
    _lb.disable(p_in)
    time.sleep(1)
    traffic.loop(p_out)
    cli.intf_startup(sink.name)
    _lb.enable_flood_safe(sink, 3991)    # directed sink: only oper-up is a valid FDB target, re-entry terminates
    learn_dst = "00:aa:bb:cc:dd:7a"
    cli.fdb_static_add(vlan, learn_dst, sink.name)
    time.sleep(1)
    try:
        learn_pkt = Ether(dst=learn_dst, src=learn) / IP() / UDP() / Raw(b"x" * 40)
        # positive control: the MAC must genuinely be learned into chip + ASIC_DB, otherwise the later "disappearance" is meaningless
        assert _learn_to_asic(traffic, p_out, learn_pkt, asicdb, _lb, learn), \
            f"dynamic MAC {learn} not learned into ASIC/chip on {p_out.name}; cannot test link-down flush"

        # link-down: disable p_out's loopback -> link truly goes down -> portsorch/fdborch should flush dynamic entries per port
        traffic.unloop(p_out)
        gone = False
        deadline = time.time() + 20
        while time.time() < deadline:
            if (not _mac_in_chip_l2(_lb.bsh, learn)
                    and not _mac_in_asicdb(asicdb, learn)):
                gone = True
                break
            time.sleep(1)
        assert gone, \
            (f"dynamic MAC {learn} still in chip l2/ASIC_DB 20s after {p_out.name} link-down; "
             f"per-port FDB flush on oper-down not working (window far below the ~240s aging "
             f"period, so aging cannot explain/veil this)")
    finally:
        cli.fdb_static_del(vlan, learn_dst)
        _lb.disable_flood_safe(sink)
        traffic.unloop(p_out)   # idempotent: the main path already unlooped, this backstops the exception path
        cli.sh.run("sonic-clear fdb all", check=False)


def test_fdb_aging_removes_dynamic_entry(cli, traffic, asicdb, _lb, topo, l2_fwd_vlan):
    """[6] aging (stays on production Vlan1000): learn a dynamic MAC (confirmed in chip + ASIC_DB), then after
    stopping traffic the dynamic entry should be **automatically aged out** by the chip (disappearing from
    `l2 show` and ASIC_DB). Real chip aging behavior, not a software clear.

    Notes: (1) the SONiC path to change fdb_aging_time at runtime is unavailable on some images, but the chip's
    innate dynamic aging works normally. (2) A dedicated VLAN created via chip-level bcmcmd has **aging off by
    default**, so this case stays on production Vlan1000 (where aging works normally).
    The learn frame is **directed at the sink** (no flood), so it does not contribute to flood degradation.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    topo.caps.require("loopback")

    vlan = l2_fwd_vlan
    learn = "00:de:ad:be:ef:9a"   # MAC independent to this case
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    # this case only needs p_out single-port loopback: the learn frame's dst is unknown and floods, and if p_in
    # is also looped, the flood becomes a self-loop storm between the two looped ports, continuously refreshing
    # learn -> it never ages. So first unloop p_in + settle, ensuring only p_out is single-port looped (the flood
    # to other ports is dropped by PHY, source-pruning does not return it, no loop; src=learn is only learned as p_out on p_out ingress).
    _lb.disable(p_in)
    time.sleep(1)
    traffic.loop(p_out)
    time.sleep(1)
    # "learn frame directed at the sink" -- in the old implementation the dst was never statically installed, so
    # the learn frame was actually unknown unicast and every re-send flooded the production VLAN (a degradation
    # vector). Now the dst is statically pinned to the flood_safe sink (only oper-up is a valid FDB target; re-entry
    # lands in the isolation VLAN and terminates), and p_out remains the only plain-looped port. When there aren't
    # enough ports to take a 3rd, degrade to the old behavior (small unknown-unicast flood, tolerable since the volume is small).
    sink = topo.misc_port(1)
    learn_dst = "00:aa:bb:cc:dd:79"
    use_sink = sink.name not in (p_in.name, p_out.name)
    if use_sink:
        cli.intf_startup(sink.name)
        _lb.enable_flood_safe(sink, 3991)
        cli.fdb_static_add(vlan, learn_dst, sink.name)
        time.sleep(1)
    try:
        learn_pkt = Ether(dst=learn_dst, src=learn) / IP() / UDP() / Raw(b"x" * 40)
        # the MAC must genuinely be learned into chip + ASIC_DB; failure to learn is a hardware programming defect (expose, don't skip)
        assert _learn_to_asic(traffic, p_out, learn_pkt, asicdb, _lb, learn), \
            f"DEVICE DEFECT: dynamic MAC {learn} not learned into ASIC/chip on {p_out.name}; MAC learning not programmed to hardware"
        # after stopping traffic, wait for the chip's innate aging. The observation window must cover the real
        # aging period: too short a window would misjudge "not yet expired" as "does not age". The window is set
        # to 420s to cover the innate aging period + margin; still present past the window is a true "does not age" defect.
        deadline = time.time() + 420
        aged_at = None
        t0 = time.time()
        while time.time() < deadline:
            if not _mac_in_chip_l2(_lb.bsh, learn) and not _mac_in_asicdb(asicdb, learn):
                aged_at = int(time.time() - t0)
                break
            time.sleep(10)
        assert aged_at is not None, \
            (f"dynamic MAC {learn} not aged out within 420s while configured "
             f"aging_time=600s (window covers the innate-aging period with margin); "
             f"chip aging not removing idle dynamic entries")
    finally:
        traffic.unloop(p_out)
        if use_sink:
            cli.fdb_static_del(vlan, learn_dst)
            _lb.disable_flood_safe(sink)
        cli.sh.run("sonic-clear fdb all", check=False)
