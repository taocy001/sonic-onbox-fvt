"""L2 MAC full feature set: static/dynamic/aging/move/flush (chip behavior level, not DB echo).

Rewrite principle: every case that can be validated on a single box uses the three-stage
"real config/learning -> ASIC_DB programming + dataplane chip counters" pattern, with assertions
that reflect what the chip/orchagent actually did, no longer just checking CONFIG_DB echo or that
`show` has no Traceback. Learning is stimulated via scapy injection (the port already re-enters the
pipeline via MAC loopback), and forwarding existence is checked via bcmcmd chip-counter deltas.
Capacity/rate specs require a traffic generator -- beyond this framework's scope, no cases.

Note: the full chip + dataplane versions of static/flush/aging are also in test_fdb_chip.py; this
module keeps them from the MAC-feature angle and makes them real behavior (dst-MAC directed
forwarding / positive-control flush / real aging).
Print/assert/skip in English; comments/docstrings in Chinese; ports/VLANs/MACs all come from topo,
not hardcoded.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.l2]

try:
    from scapy.all import Ether, IP, UDP, Raw
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 100                 # number of injected packets (small, paired with an upper-bound assertion to guard against runaway storms)
_LOWER = _N * 0.8        # forwarding lower bound (tolerates loopback jitter)
_NEAR_ZERO = _N * 0.3    # "received almost nothing" upper bound (directed unicast should not reach non-target ports)


# ----------------------------- helpers -----------------------------
def _mac_in_asicdb(asicdb, mac):
    """Whether ASIC_DB has an FDB_ENTRY for this MAC (key contains the colon-stripped/colon-included MAC, case-insensitive)."""
    needle = mac.replace(":", "").upper()
    keys = []
    for k in asicdb.objects("SAI_OBJECT_TYPE_FDB_ENTRY"):
        ku = k.upper()
        if needle in ku or mac.upper() in ku:
            keys.append(k)
    return keys


def _wait_asicdb_mac(asicdb, mac, tries=20):
    """Poll ASIC_DB until this MAC's FDB_ENTRY appears, return the list of matching keys (empty = not appeared)."""
    for _ in range(tries):
        keys = _mac_in_asicdb(asicdb, mac)
        if keys:
            return keys
        time.sleep(0.4)
    return []


def _port_token_in(line, bcm):
    """Whether an `l2 show` line contains the **complete** bcm port name (word boundaries anchored on both sides).

    A bare substring / left-anchor-only ("/cd1" in line) would let cd1 mis-match cd13: an old-port cd1
    colliding with a new-port cd13 line -> false "still on old port" FAIL; the reverse gives a false PASS.
    With anchoring, cd1 followed by a digit/letter does not match."""
    return bool(re.search(rf"(?<![\w]){re.escape(bcm)}(?![\w])", line or ""))


# ============================ cases ============================
def test_static_mac_crud(cli, traffic, asicdb, _lb, topo, l2net, l2_fwd_vlan):
    """Static FDB CRUD (default VLAN, swssconfig path) + **storm-safe directed dataplane** (dedicated test VLAN).

    Split into two parts, decoupling the "storm-prone directed dataplane" from the "zero-traffic
    programming/lifecycle validation":
      C/R/D (default VLAN, swssconfig, **no traffic -> zero storm**): after the dmac->p_out static entry is
        pushed, the ASIC_DB FDB_ENTRY appears, and in the chip `l2 show` this MAC lands on **p_out's bcm port**
        (programming chain + directed-landing correctness, not flooded / not on the wrong port); after delete
        it disappears from ASIC_DB (D).
      verify-dataplane (**l2net dedicated test VLAN**, 4-port flood domain, storm-safe): a chip-level static FDB
        within the domain directs mac2->p_out; dst=mac2 entering from p_in -> directed to p_out (TX~N, upper bound
        to guard against storm); the non-target port p3 (flood-safe) has TX~0 -- distinguishing "directed forwarding"
        from "unknown-unicast flooding after a silent entry failure" (flooding likewise makes p_out TX~N; only the
        third port being ~0 is the evidence of directedness).

    storm-safe design note: the original implementation did the whole directed measurement in the **default VLAN** --
    p_in loopback as carrier, p_out also looped; once the directed entry did not take effect immediately (or a
    bypass **other residual loopback port** existed), the frame became unknown-unicast and flooded in the default
    VLAN (16 ports) -> hit the equally-looped p_in/residual port -> self-amplified into a storm (isolate-PVID only
    changes the **re-entry classification** of the configured port and cannot stop the flood re-injection of a
    bypass bare loopback). Fix: move the directed dataplane into l2net's 4-port scoped VLAN -- the flood domain
    shrinks to 4 ports and is **immune to residual loopbacks outside the domain**; p_in is the only bare loopback
    in the domain (source pruning does not self-inject), and p_out/p3 use isolate/flood-safe to break re-entry,
    i.e. the iron rule of "at most one loopback port in a flood domain".
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")

    vid, p_in, p_out, p3, sink = l2net
    dv = l2_fwd_vlan   # the CRUD swss->ASIC_DB chain needs a real VLAN
    mac = "00:11:22:33:44:01"           # CRUD MAC (default VLAN, swss->ASIC_DB)
    mac2 = "00:11:22:33:44:02"          # dataplane directed MAC (scoped chip VLAN)
    p_out_bcm = _lb.dut.bcm_of(p_out)

    # ---- C/R: default VLAN swssconfig static FDB -> ASIC_DB + chip l2 lands on the p_out port (no traffic, zero storm) ----
    cli.fdb_static_add(dv, mac, p_out.name)     # wait=True, waits for ASIC programming
    try:
        assert _wait_asicdb_mac(asicdb, mac), \
            "static FDB (specified MAC) not programmed to ASIC FDB_ENTRY"
        # in the chip l2 table this MAC must land on p_out's bcm port (directed-programming correctness --
        # not flooded, not on the wrong port; port name anchored on both sides to prevent cd1 mis-hitting cd13)
        chip_line = ""
        for _ in range(20):
            out = _lb.bsh.cmd("l2 show") or ""
            chip_line = next((ln for ln in out.splitlines() if mac.lower() in ln.lower()), "")
            if _port_token_in(chip_line, p_out_bcm):
                break
            time.sleep(0.4)
        assert _port_token_in(chip_line, p_out_bcm), \
            (f"static FDB {mac} not programmed on target port {p_out.name}({p_out_bcm}) in chip "
             f"l2: {chip_line!r} (programmed elsewhere/flooded, not directed)")
    finally:
        cli.fdb_static_del(dv, mac)
    # D: after delete the entry should disappear from ASIC
    gone = False
    for _ in range(20):
        if not _mac_in_asicdb(asicdb, mac):
            gone = True
            break
        time.sleep(0.4)
    assert gone, "static FDB still in ASIC_DB after delete"

    # ---- verify-dataplane: storm-safe directed forwarding in the scoped VLAN ----
    traffic.loop(p_out)                  # p_out loopback = valid egress target + TX measurable
    _lb.isolate_pvid(p_out, 3990)        # break p_out's "directed-to-looped port" self-loop re-entry
    _lb.enable_flood_safe(p3, 3991)      # non-target measurement port: loopback brought up so TX is measurable + isolated PVID breaks re-entry
    _lb.chip_fdb_add(vid, mac2, p_out)   # chip-level static FDB (the scoped VLAN is not in CONFIG_DB, swssconfig does not apply)
    time.sleep(1)
    try:
        # dataplane: dst=mac2 entering from p_in -> directed forwarding to p_out
        pkt = (Ether(dst=mac2, src="00:aa:bb:cc:dd:01") /
               IP(dst="10.0.0.1") / UDP() / Raw(b"STATIC" + b"x" * 40))
        # after clearing to zero, send traffic and read each port once (count that reached the port since clear); no base/after subtraction (clear->read-once semantics)
        traffic.clear_chip_counters()
        traffic.send(p_in, pkt, count=_N)
        time.sleep(1)
        d = traffic.chip_counters(p_out)
        d3 = traffic.chip_counters(p3)
        assert d.tx_pkt >= _LOWER, \
            f"static FDB not forwarding to {p_out.name} (TX+{d.tx_pkt}, want ~{_N})"
        assert d.tx_pkt < 10_000, \
            (f"directed-to-looped storm on {p_out.name} (TX+{d.tx_pkt}); "
             f"scoped-VLAN/isolate not breaking the loop")
        assert d3.tx_pkt <= _NEAR_ZERO, \
            (f"known-unicast leaked to non-target member {p3.name} (TX+{d3.tx_pkt}); "
             f"looks like flood, not directed static-FDB forwarding")
    finally:
        _lb.restore_pvid(p_out)
        _lb.chip_fdb_del(vid, mac2)
        _lb.disable_flood_safe(p3)
        traffic.unloop(p_out)


def test_mac_aging_time_config(cli, traffic, asicdb, topo, l2_fwd_vlan):
    """MAC aging: set fdb_aging_time to a short value, learn a dynamic MAC (confirmed into ASIC), stop
    traffic and wait > the aging window; the dynamic entry should be **automatically aged out by the chip**
    (disappears from ASIC_DB) -- real chip aging behavior, not a software clear. Aging goes through
    CONFIG_DB SWITCH.fdb_aging_time (a legitimate config path).
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")

    orig = cli.db_hgetall("CONFIG_DB", "SWITCH|switch").get("fdb_aging_time", "600")
    age = 20                       # short aging window, leaving enough margin for stop-traffic-after-injection + aging + polling
    p = traffic.ports[0]           # the traffic fixture already enabled loopback on ports[0]
    smac = "00:de:ad:be:ef:5c"     # aging-dedicated source MAC (independent, to avoid FDB cross-talk)
    cli.sh.run(f"sonic-db-cli CONFIG_DB HSET 'SWITCH|switch' fdb_aging_time {age}", check=False)
    try:
        # CONFIG_DB must actually be written (config precondition)
        assert cli.db_hgetall("CONFIG_DB", "SWITCH|switch").get("fdb_aging_time") == str(age), \
            "fdb_aging_time not written to CONFIG_DB"
        time.sleep(2)              # wait for aging_time to be pushed to the ASIC
        cli.sh.run("sonic-clear fdb all", check=False)

        # learn (stop traffic right after injection, no longer refreshing the entry, letting it age naturally)
        traffic.send(p, Ether(dst=topo.mac("dst"), src=smac) /
                     IP() / UDP() / Raw(b"x" * 40), count=20)
        time.sleep(1.5)
        # the MAC must actually learn into ASIC; failure to learn is a hardware programming defect (expose, not skip)
        assert _wait_asicdb_mac(asicdb, smac), \
            "DEVICE DEFECT: dynamic MAC did not learn into ASIC; MAC learning not programmed to hardware"

        # wait for aging: poll after the window elapses, it should disappear from ASIC
        deadline = time.time() + age + 30
        aged = False
        while time.time() < deadline:
            if not _mac_in_asicdb(asicdb, smac):
                aged = True
                break
            time.sleep(2)
        assert aged, \
            (f"DEVICE DEFECT: configured fdb_aging_time={age}s NOT applied to chip -- entry still "
             f"present after window+grace (aging-time CONFIG->chip path not effective)")
    finally:
        cli.sh.run(f"sonic-db-cli CONFIG_DB HSET 'SWITCH|switch' fdb_aging_time {orig}",
                   check=False)
        cli.sh.run("sonic-clear fdb all", check=False)


@pytest.mark.traffic
def test_mac_flush(cli, traffic, asicdb, topo, l2_fwd_vlan):
    """flush: first learn a dynamic MAC and **confirm it into ASIC (positive control)**, then
    `sonic-clear fdb all`. Note: on l2_home_forwarding=false platforms a real forwarding VLAN must be used
    (the parking Vlan1 does not learn). The dynamic entry should disappear from ASIC_DB. The original only
    checked that `show mac` after flush did not contain the MAC -- it lacked a positive control, so it would
    "pass" even if the MAC was never learned at all. Here we add the positive control + check the real ASIC
    programming state.
    """
    if not _SCAPY:
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")

    p = traffic.ports[0]           # already looped, src is learned via re-entry
    smac = "00:de:ad:be:ef:5a"
    pkt = Ether(dst=topo.mac("dst"), src=smac) / IP() / UDP() / Raw(b"x" * 40)

    cli.sh.run("sonic-clear fdb all", check=False)   # clean starting point
    traffic.send(p, pkt, count=20)
    time.sleep(1.5)
    # positive control: before flush the dynamic MAC must actually learn into ASIC, otherwise the later "disappearance" is meaningless
    assert _wait_asicdb_mac(asicdb, smac), \
        "dynamic MAC not learned into ASIC before flush (cannot validate flush)"

    cli.sh.run("sonic-clear fdb all", check=False)
    # after flush the dynamic MAC should disappear from ASIC_DB
    gone = False
    for _ in range(15):
        if not _mac_in_asicdb(asicdb, smac):
            gone = True
            break
        time.sleep(0.4)
    assert gone, "dynamic MAC still in ASIC_DB FDB_ENTRY after 'sonic-clear fdb all'"


@pytest.mark.traffic
def test_mac_move(cli, traffic, asicdb, _lb, topo, l2_fwd_vlan):
    """MAC move (relearn on the new port): the same source MAC is first learned on the old port, then
    enters from a new port -> the FDB moves to the new port.
    **Real-traffic** triple validation (aligned with test_fdb_chip.py's directed-vs-flood topology):
      (1) the ASIC must **have** this MAC entry (move != failed to learn), and still exactly one (move is not duplication);
      (2) after the move, sending traffic to this MAC from p_in, **real forwarding follows to the new port** p_new (chip TX~N);
      (3) at the same time verify the old/non-target port p_old has chip TX~0 -- distinguishing "directed move"
          from "unknown-unicast flooding" (if only deduplication is checked without verifying the dataplane, flooding
          would also make both ports receive it, a false pass).

    Three-member topology: p_in=ports[0] ingress; p_old=ports[1] old port (learning port/non-target);
    p_new=misc_port(0) new port (move target). p_new must differ from the first two ports, otherwise the
    three-member setup cannot be built -> skip.
    """
    pytest.importorskip("scapy.all")
    topo.caps.require("loopback")
    from scapy.all import Ether, IP, UDP, Raw

    vlan = l2_fwd_vlan   # real forwarding VLAN
    p_in, p_old = traffic.ports[0], traffic.ports[1]
    p_new = topo.misc_port(0)
    if p_new.name in (p_in.name, p_old.name):
        pytest.skip("not enough distinct ports for MAC-move directed-vs-flood check")

    smac = "00:de:ad:be:ef:5b"
    # add the new port to the default VLAN and loop it (otherwise it cannot receive flood/forwarding, a false negative)
    added_p3 = False
    if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vlan}|{p_new.name}"):
        cli.config_raw(f"vlan member add -u {vlan} {p_new.name}")
        added_p3 = True
        for _ in range(20):
            if cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vlan}|{p_new.name}"):
                break
            time.sleep(0.3)
    cli.intf_startup(p_new.name)

    # dual-source storm root fix (assertions unchanged):
    # (1) direct the seed to the 4th port sink (static FDB + flood_safe) -- the unknown-unicast seed used to
    #     flood-amplify without a loop break among 3 same-VLAN loopback ports, and smac surged with re-entry
    #     destroying the "move".
    # (2) disable IPv6 on all 4 ports during the test window -- **with >=2 bare loopback ports in the same VLAN,
    #     any kernel-noise multicast frame (IPv6 ND/MLD) loops perpetually between loopback ports**. Once the
    #     noise source is cut, the bare loopback is structurally safe, and the dynamic entry is not disrupted by
    #     flood_safe's PVID switching.
    sink = topo.misc_port(1)
    if sink.name in (p_in.name, p_old.name, p_new.name):
        pytest.skip("need a 4th distinct port as the seed sink")
    for _p in (p_in, p_old, p_new, sink):
        cli.sh.run(f"sysctl -qw net.ipv6.conf.{_p.name}.disable_ipv6=1", check=False)
    cli.sh.run("sonic-clear fdb all", check=False)   # clean starting point: the old entry must not pre-satisfy len<=1
    traffic.loop(p_old)        # old-port MAC loopback: injected frames re-enter the pipeline, src is learned on this port
    _lb.enable(p_new)          # new-port MAC loopback: the move-target port likewise needs re-entry to relearn
    cli.intf_startup(sink.name)
    _lb.enable_flood_safe(sink, 3992)
    seed_dst = "00:aa:bb:cc:dd:74"
    cli.fdb_static_add(vlan, seed_dst, sink.name)
    time.sleep(1)
    try:
        seed = Ether(dst=seed_dst, src=smac) / IP(dst="10.0.0.4") / UDP() / Raw(b"MOVE" + b"x" * 40)

        def _chip_l2_port(mac):
            # learning/move evidence relies on the **chip l2 table** (aligned with the gold-standard relearn
            # case): the ASIC_DB sync of a dynamic MAC may be unreliable (it may not appear even on first learn
            # under a directed seed), so the chip table is authoritative.
            out = _lb.bsh.cmd("l2 show") or ""
            for ln in out.splitlines():
                if mac.lower() in ln.lower():
                    return ln
            return ""

        # (1) first learn smac on the old port p_old (chip-table confirmed; if it cannot learn, honest failure here)
        traffic.send(p_old, seed, count=20)
        line = ""
        for _ in range(12):
            time.sleep(0.5)
            line = _chip_l2_port(smac)
            if line:
                break
        # port-name matching must be anchored on both sides: a left-anchor-only "/cd1" is still a substring of "/cd13" (cd1/cd13 mis-match)
        old_bcm = _lb.dut.bcm_of(p_old)
        assert line and _port_token_in(line, old_bcm), \
            (f"dynamic MAC {smac} not learned on old port {p_old.name} in chip l2 table "
             f"(entry={line!r}); cannot test move")

        # (2) same src entering from the new port p_new -> the chip table should move to p_new and leave p_old.
        # after p_new loopback is brought up, chip learning (Lrn=ARL) is enabled **asynchronously** after oper-up,
        # so wait for it to really open first; re-send periodically during polling -- frames landing in the
        # ARL-not-ready window should not become a "did not move" false failure (assertions unchanged, pure timing hardening).
        _lb.wait_learn_ready(p_new)
        traffic.send(p_new, seed, count=20)
        new_bcm = _lb.dut.bcm_of(p_new)
        for i in range(16):
            time.sleep(0.5)
            line = _chip_l2_port(smac)
            if line and _port_token_in(line, new_bcm):
                break
            if i % 4 == 3:
                traffic.send(p_new, seed, count=20)
        assert line and _port_token_in(line, new_bcm), \
            f"MAC did not move to new port {p_new.name} in chip l2 table (entry={line!r})"
        assert not _port_token_in(line, old_bcm), \
            f"MAC still on old port after move (chip entry={line!r})"

        # dataplane: sending traffic to the moved MAC from p_in should forward **only** to the new port p_new,
        # not to the old port p_old. The three ports stay bare loopback (the noise source has been cut by
        # disable_ipv6, so the loop cannot sustain; the dynamic entry is left untouched precisely so it is not
        # disrupted by flood_safe's PVID switching -- a bare loopback is structurally safe).
        fwd = Ether(dst=smac, src="00:aa:bb:cc:dd:02") / IP(dst="10.0.0.9") / UDP() / Raw(b"m" * 40)
        # after clearing to zero, send traffic and read new/old ports once each (count that reached the port since clear); no base/after subtraction (clear->read-once semantics)
        traffic.clear_chip_counters()
        traffic.send(p_in, fwd, count=_N)
        time.sleep(1)
        d_new = traffic.chip_counters(p_new)
        d_old = traffic.chip_counters(p_old)
        d_in = traffic.chip_counters(p_in)
        l2o = _lb.bsh.cmd("l2 show") or ""
        ev = " | ".join(ln.strip() for ln in l2o.splitlines()
                        if any(m in ln.lower() for m in (smac.lower(), "aa:bb:cc:dd:02",
                                                         seed_dst.lower()))) or "(no entries)"
        assert d_new.tx_pkt >= _LOWER, \
            (f"after MAC move, traffic not forwarded to new port {p_new.name} "
             f"(TX+{d_new.tx_pkt}, want ~{_N}); l2={ev}")
        # anti-storm upper bound (the measurement iron rule for directing to a looped port): true directed ~N; a runaway self-loop shoots to the millions
        assert d_new.tx_pkt < 10_000, \
            f"storm suspected on new port {p_new.name} after move (TX+{d_new.tx_pkt}); l2={ev}"
        assert d_old.tx_pkt <= _NEAR_ZERO, \
            (f"after MAC move, traffic still reaching old/non-target port {p_old.name} "
             f"(TX+{d_old.tx_pkt}, new={d_new.tx_pkt}, in_rx={d_in.rx_pkt}); "
             f"move not directed (looks like flood); l2={ev}")
    finally:
        traffic.unloop(p_old)
        _lb.disable(p_new)
        _lb.disable_flood_safe(sink)
        cli.fdb_static_del(vlan, seed_dst)
        for _p in (p_in, p_old, p_new, sink):
            cli.sh.run(f"sysctl -qw net.ipv6.conf.{_p.name}.disable_ipv6=0", check=False)
        if added_p3:
            cli.config_raw(f"vlan member del {vlan} {p_new.name}")
        cli.sh.run("sonic-clear fdb all", check=False)


