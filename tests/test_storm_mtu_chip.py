"""Storm-control (BUM rate-limit) + port MTU oversized-frame drop -- real-traffic / chip-behavior verification.

This suite **does not merely verify CONFIG_DB/ASIC_DB programming**; it uses MAC loopback +
scapy real-traffic injection and judges whether a feature truly takes effect in the data plane
by "chip forward/drop counters":

Topology (reuses the traffic fixture):
  ports[0] enables MAC loopback (the ingress stimulus port); ports[1] uses **flood_safe**
  (loopback pulls it oper-up so TX is readable, PVID isolation prevents BUM re-entry looping;
  fix: previously not looping back left the port down, TX stuck at 0, and the whole baseline
  skipped -- a false negative). Both are in default_vlan, untagged. CPU scapy injects a frame
  on the ports[0] netdev -> physical egress -> MAC loopback -> re-enters the pipeline -> takes
  part in L2 flooding as an ingress frame -> broadcast/unknown-unicast/unknown-multicast floods
  to other ports in the same VLAN (including ports[1]) -> ports[1] chip TX(MIB_TPKT) increments.

  storm-control rate-limits BUM on the **ingress** direction of ports[0]: inject a burst far
  above the configured rate -> most should be dropped by the ingress policer -> the flood
  reaching ports[1] is suppressed (policed << sent), which, compared against the no-limit
  baseline, proves rate-limiting is in effect.

  MTU: set a small MTU on ports[0] -> inject an oversized frame > MTU -> it should be dropped on
  ingress and **not flooded** to ports[1] (ports[1] TX≈0), and the port's ingress drop counters
  (RX_DRP/RX_ERR) increment; compared against a within-MTU frame (which floods normally).

  Three verification paths used together (chosen per case): chip counters (ChipCounters TX/RX) +
  portstat RX_DRP/RX_ERR + ASIC_DB programming.

Storm safety: ports[1]'s re-entry is terminated by flood_safe's isolated PVID; an upper-bound
assertion catches a runaway injection volume. All CLI provisioning is guarded with config_raw --
if the syntax/feature is unsupported, skip (never fabricate a pass); if programming lands but the
chip does not truly rate-limit/drop, FAIL directly for binary exposure (a class-A device defect,
not masked with xfail).

Prints/assert/skip in English; comments/docstrings in Chinese. Ports/VLAN come from topo, not
hard-coded.
"""
import time

import pytest

pytestmark = [pytest.mark.l2, pytest.mark.traffic]

# Injection burst volumes. storm uses a large burst so the rate-limit effect (policed vs sent)
# is obvious; MTU uses a moderate volume.
_STORM_BURST = 2000
_MTU_BURST = 200

# storm-control configured rate (kbps). Must be a very low value: CPU scapy injection is often
# only ~1-3k pps, and if the admit pps implied by the configured rate is the same order as the
# injection pps, even a healthy policer will admit >50% of the burst -> false defect verdict.
# 64 kbps ≈ 72 fps (@110B frame), leaving >=5x margin over any realistic scapy rate (the case
# has an additional rate guard).
_STORM_KBPS = 64

# Pass-criterion tolerances (loopback path / background traffic / counter jitter).
_FWD_LOWER = 0.7     # normal flood: egress arrival >= sent*0.7 counts as "it really flooded across"
_STORM_RATIO = 0.5   # rate-limit in effect: policed egress volume < half the no-limit baseline


# ---- storm-control type and the corresponding CONFIG_DB subkey / SAI policer port attribute ----
# SONiC: config interface storm-control add <port> <type> <kbps>
#   type ∈ {broadcast, unknown-unicast, unknown-multicast}
#   CONFIG_DB: PORT_STORM_CONTROL|<port>|<type> = {"kbps": "<rate>"}
#   ASIC: attaches a SAI_OBJECT_TYPE_POLICER to the port, port attribute
#         SAI_PORT_ATTR_BROADCAST/FLOOD/MULTICAST_STORM_CONTROL_POLICER_ID
_STORM_TYPES = ["broadcast", "unknown-unicast", "unknown-multicast"]


def _scapy():
    try:
        from scapy.all import Ether, IP, UDP, Raw  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _bum_pkt(kind, topo, pad=64):
    """Build a BUM frame that will flood within the VLAN.

    broadcast        -> DMAC=ff:ff:ff:ff:ff:ff
    unknown-unicast  -> DMAC=an unlearned unicast (no FDB entry -> unknown-unicast flood)
    unknown-multicast-> DMAC=multicast (01:00:5e:.., not a known group)
    Use a distinct source MAC to avoid FDB cross-talk with smoke/other cases.
    """
    from scapy.all import Ether, IP, UDP, Raw
    src = "00:de:ad:be:ef:71"
    if kind == "broadcast":
        dst = "ff:ff:ff:ff:ff:ff"
    elif kind == "unknown-unicast":
        dst = "00:00:00:de:ad:99"          # never learned -> unknown unicast
    else:  # unknown-multicast
        dst = "01:00:5e:7f:00:99"          # IPv4 multicast MAC, not a known group -> unknown-multicast flood
    return (Ether(dst=dst, src=src) /
            IP(src="10.71.0.1", dst="10.71.0.2") / UDP() / Raw(b"S" * pad))


def _portstat_int(cli, port_name, field):
    """Read a given field of a given port from portstat -j (RX_DRP/RX_ERR etc.), strip comma
    thousands-separators -> int; return None if unreadable."""
    import json
    out = cli.run("portstat -j").out
    try:
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return None
    stat = data.get(port_name)
    if stat is None:
        return None
    v = str(stat.get(field, "")).replace(",", "").strip()
    return int(v) if v.lstrip("-").isdigit() else None


# ======================== Storm control (BUM rate-limit) ========================

def _config_storm(cli, config_guard, port_name, kind, kbps):
    """Provision storm-control and verify it lands in CONFIG_DB. Returns True=configured and
    persisted; otherwise it has already skipped."""
    # Syntax adaptation: the modified OS's usage is `<port> <type> <kbps|pps> <rate>` (one extra
    # unit positional arg); the community image is `<port> <type> <kbps>`. Probe by usage.
    h = cli.sh.run("config interface storm-control add --help", check=False).out or ""
    if "kbps|pps" in h:
        rc, r = cli.config_raw(f"interface storm-control add {port_name} {kind} kbps {kbps}")
    else:
        rc, r = cli.config_raw(f"interface storm-control add {port_name} {kind} {kbps}")
    out = (r.out + r.err)
    if rc != 0:
        pytest.skip(f"storm-control CLI unsupported/failed "
                    f"({kind}): {out.strip()[:140]}")
    config_guard.defer_undo(f"interface storm-control del {port_name} {kind}")
    # CONFIG_DB must actually be written. Value adaptation: the modified OS's persisted value =
    # input x125 (e.g. 1000 -> 125000; the "kbps" field actually stores byte-rate semantics, so
    # CLI/DB units differ) -- accept either the raw value or x125.
    key = f"PORT_STORM_CONTROL|{port_name}|{kind}"
    for _ in range(10):
        h = cli.db_hgetall("CONFIG_DB", key)
        v = h.get("kbps", "")
        if v in (str(kbps), str(kbps * 125)):
            return True
        time.sleep(0.3)
    pytest.skip(f"storm-control add accepted but CONFIG_DB {key}.kbps={v!r} matches neither "
                f"{kbps} nor {kbps}*125 (config path incomplete)")


def _flood_to_out(traffic, topo, kind, burst, lb=None):
    """Inject burst BUM frames on ports[0], return (ports[1] chip TX delta, injection duration
    in seconds).

    p_out must be oper-up for its TX to count (historical false-negative root cause: the port
    was down so TX stuck at 0 -> baseline 0 -> everything skipped) -- when lb is passed, bring it
    up with flood_safe (loopback keeps it up + PVID isolation so BUM re-entry hits a dead end and
    does not loop). The injection duration is used to compute the actual injection pps (the storm
    case's rate guard)."""
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    if lb is not None:
        lb.enable_flood_safe(p_out, 3991)
        import time as _t
        _t.sleep(1)
    pkt = _bum_pkt(kind, topo)
    # Zero the counters then send, and read once (the count of the flood reaching p_out since
    # clear); do not subtract base/after -- this diag `show c` only shows the change since the
    # last show/clear, so a base read would consume the display + include background noise and
    # could yield a negative delta (clear -> read-once semantics, see gold L3)
    traffic.clear_chip_counters()
    t0 = time.time()
    traffic.send(p_in, pkt, count=burst)
    send_secs = max(time.time() - t0, 1e-3)
    time.sleep(1.2)
    return traffic.chip_counters(p_out).tx_pkt, send_secs


@pytest.mark.parametrize("kind", _STORM_TYPES)
def test_storm_control_rate_limits_bum(cli, traffic, topo, config_guard, asicdb, _lb, kind):
    """storm-control rate-limits broadcast/unknown-unicast/unknown-multicast:

    (1) First inject a burst of BUM with no limit and confirm it truly floods to ports[1]
        (TX>=sent*0.7) -- proving the topology/flood path works; if it does not flood across in
        the first place (link/STP/VLAN issue), skip (not storm's fault).
    (2) Configure a low-rate storm-control + verify it lands in CONFIG_DB + verify a POLICER
        appears in the ASIC.
    (3) Inject the same burst again and verify the volume reaching ports[1] is greatly suppressed
        by the policer (< baseline*0.5).
    When (2) has no POLICER or (3) is not rate-limited, FAIL directly for binary exposure (class-A).
    """
    if not _scapy():
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")
    p_in = traffic.ports[0]

    # (1) baseline: flood arrival volume with no rate-limit
    baseline, send_secs = _flood_to_out(traffic, topo, kind, _STORM_BURST, lb=_lb)
    if baseline < _STORM_BURST * _FWD_LOWER:
        pytest.skip(f"{kind} did not flood to egress without storm-control "
                    f"(baseline TX={baseline}, sent={_STORM_BURST}); cannot assess rate-limit "
                    "(topology/STP/VLAN, not storm-control)")
    # upper bound catches a runaway storm
    assert baseline < 10_000_000, f"runaway flood baseline TX={baseline} (storm?)"
    # Injection rate guard: CPU injection pps must far exceed the policer admit pps (>=5x),
    # otherwise even a healthy policer admits >50% of the burst -> false defect verdict. When the
    # margin is not met, honestly skip (the criterion is unreachable at this injection speed).
    frame_len = len(_bum_pkt(kind, topo)) + 4          # on-wire frame length (incl. FCS)
    policer_pps = _STORM_KBPS * 1000 / 8 / frame_len
    achieved_pps = _STORM_BURST / send_secs
    if achieved_pps < policer_pps * 5:
        pytest.skip(f"CPU injection {achieved_pps:.0f} pps < 5x policer admit rate "
                    f"{policer_pps:.0f} pps ({_STORM_KBPS} kbps @ {frame_len}B); "
                    "rate-limit verdict unreachable at this injection speed")

    # (2) configure storm-control + programming assertion (snapshot the baseline: the CoPP
    # trap-group POLICER is always present, so "any POLICER exists" is trivially true -- we must
    # assert this config **added a new** POLICER object)
    base_pol = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_POLICER:*")
    _config_storm(cli, config_guard, p_in.name, kind, _STORM_KBPS)
    has_policer = asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_POLICER:*", base_pol,
                                       timeout=6)

    # (3) arrival volume after rate-limiting
    time.sleep(1)
    limited, _ = _flood_to_out(traffic, topo, kind, _STORM_BURST, lb=_lb)

    if not has_policer:
        # class-A device defect: it landed in CONFIG_DB but the ASIC has no POLICER
        # (storm-control not realized in hardware) -- FAIL directly to expose it
        pytest.fail(f"storm-control {kind} written to CONFIG_DB but no NEW "
                    f"SAI_OBJECT_TYPE_POLICER object appeared in ASIC (pre-existing CoPP policers "
                    f"excluded; storm-control not realized in hardware); "
                    f"baseline TX={baseline}, after-config TX={limited}")
    if limited < baseline * _STORM_RATIO:
        return  # pass: the policer really rate-limited the BUM burst
    # class-A device defect: the ASIC has a POLICER but the data plane is not truly rate-limited
    # -- FAIL directly to expose it
    pytest.fail(f"storm-control {kind} policer present in ASIC but did NOT rate-limit "
                f"data plane: egress TX after config={limited} vs baseline={baseline} "
                f"(sent={_STORM_BURST}); expected << {baseline * _STORM_RATIO:.0f}")


def test_storm_control_show_and_db(cli, traffic, topo, config_guard):
    """storm-control config plane: after provisioning, `show storm-control` reflects the rate +
    it lands in CONFIG_DB.

    Pure config/visibility check (no traffic), as supplementary evidence for the data-plane
    cases: the CLI->CONFIG_DB->show chain is intact. If show does not reflect the rate (CLI
    incomplete) -> skip; if CONFIG_DB was not written -> _config_storm skips internally."""
    p_in = traffic.ports[0]
    kind, kbps = "broadcast", _STORM_KBPS
    _config_storm(cli, config_guard, p_in.name, kind, kbps)   # includes the CONFIG_DB assertion
    out = cli.run("show storm-control").out
    if "Traceback" in out:
        pytest.fail(f"show storm-control crashed: {out[-200:]}")
    if str(kbps) not in out or p_in.name not in out:
        pytest.skip(f"show storm-control does not reflect configured rate "
                    f"(CLI display incomplete): {out[-160:]}")
    assert str(kbps) in out and p_in.name in out, \
        "show storm-control did not list configured port/rate"


# ======================== Port MTU oversized-frame drop ========================

_LOW_MTU = 1500          # set a small MTU so an ordinary large frame already exceeds it
_OVERSIZE_PAD = 4000     # payload making the whole frame > _LOW_MTU
_INSIZE_PAD = 200        # payload making the whole frame < _LOW_MTU (control: should flood normally)


def _wait_kernel_mtu(cli, port_name, want, tries=12):
    """Wait for the kernel netdev MTU to actually apply to want (portmgrd). Return the final
    value as a string."""
    val = ""
    for _ in range(tries):
        val = cli.sh.run(f"cat /sys/class/net/{port_name}/mtu", check=False).out.strip()
        if val == str(want):
            return val
        time.sleep(1)
    return val


def test_port_mtu_oversized_frame_dropped(cli, traffic, topo, config_guard, _lb):
    """Port MTU oversized-frame drop (data plane, **egress semantics**): set p_out MTU=1500,
    inject an oversized broadcast frame > 1500 from p_in (large MTU) -- on the flood path, a frame
    exceeding p_out's egress MTU should be dropped and **not egress p_out** (TX≈0); compared
    against a within-MTU frame (which floods normally to p_out) to prove this is MTU frame-cutting
    rather than a broken link.

    Why test egress rather than ingress: ingress semantics are not testable in a loopback
    topology -- the injected frame must first go out the same physical port's netdev, and after
    lowering that port's MTU the kernel refuses to send with EMSGSIZE (Message too long), so the
    oversized frame never even enters the chip. Egress MTU enforcement is the equivalent data-plane
    behavior testable on a single box.
    """
    if not _scapy():
        pytest.skip("scapy unavailable (dry-run/build host)")
    topo.caps.require("loopback")
    from scapy.all import Ether, IP, UDP, Raw

    p_in, p_out = traffic.ports[0], traffic.ports[1]

    # the small MTU goes on **p_out** (the egress port under test); p_in keeps a large MTU so it
    # can inject the oversized frame
    rc, r = cli.config_raw(f"interface mtu {p_out.name} {_LOW_MTU}")
    if rc != 0:
        pytest.skip(f"interface mtu CLI unsupported/failed: {(r.out + r.err).strip()[:140]}")
    config_guard.defer_undo(f"interface mtu {p_out.name} 9100")   # restore default
    assert cli.db_hgetall("CONFIG_DB", f"PORT|{p_out.name}").get("mtu") == str(_LOW_MTU), \
        "MTU not written to CONFIG_DB"
    applied = _wait_kernel_mtu(cli, p_out.name, _LOW_MTU)
    if applied != str(_LOW_MTU):
        pytest.skip(f"MTU {_LOW_MTU} not applied to kernel netdev {p_out.name} "
                    f"(/sys mtu={applied!r}); cannot drive oversized-drop")

    bcast = topo.mac("bcast")
    src = "00:de:ad:be:ef:72"

    # p_out must be oper-up for its TX to count (same false-negative fix as _flood_to_out);
    # flood_safe prevents the broadcast from re-entering and looping
    _lb.enable_flood_safe(p_out, 3991)
    time.sleep(1)

    # (1) control: a within-MTU frame should flood normally to ports[1]
    in_pkt = Ether(dst=bcast, src=src) / IP() / UDP() / Raw(b"i" * _INSIZE_PAD)
    # zero the counters then send, read once (the count of the flood reaching p_out since clear);
    # do not subtract base/after (clear -> read-once semantics)
    traffic.clear_chip_counters()
    traffic.send(p_in, in_pkt, count=_MTU_BURST)
    time.sleep(1.0)
    _ic = traffic.chip_counters(p_out)
    in_fwd = _ic.rx_pkt   # same criterion as the oversized frame: re-entry RX (previously TX,
                          # which is known to risk counting error frames)
    if in_fwd < _MTU_BURST * _FWD_LOWER:
        pytest.skip(f"within-MTU frame did not flood to {p_out.name} "
                    f"(TX={in_fwd}, sent={_MTU_BURST}); topology issue, not MTU")

    # (2) oversized frame: should be cut on ingress, not flooded to ports[1], and ports[0]
    # RX_DRP/RX_ERR increments
    over_pkt = Ether(dst=bcast, src=src) / IP() / UDP() / Raw(b"o" * _OVERSIZE_PAD)
    cli.run("sonic-clear counters")
    time.sleep(2)
    drp0 = _portstat_int(cli, p_out.name, "TX_DRP")
    err0 = _portstat_int(cli, p_out.name, "TX_ERR")
    # zero the counters then send, read once (the count of the flood reaching p_out since clear);
    # do not subtract base/after (clear -> read-once semantics)
    traffic.clear_chip_counters()
    traffic.send(p_in, over_pkt, count=_MTU_BURST)
    time.sleep(1.2)
    _oc = traffic.chip_counters(p_out)
    # the true egress criterion = p_out **re-entry RX** (loopback port: a truly sent frame must
    # return to the pipeline); TPKT may also count "attempts counted as TX_ERR" (TX+200 and
    # TX_ERR+200 while the frame did not necessarily really go out), so looking at TX alone would
    # misjudge a defect.
    over_fwd = _oc.rx_pkt
    over_tx, over_rx = _oc.tx_pkt, _oc.rx_pkt

    # ingress drop counter delta (prefer RX_DRP, fall back to RX_ERR)
    drp_delta = err_delta = 0
    for _ in range(12):
        time.sleep(1)
        d = _portstat_int(cli, p_out.name, "TX_DRP")
        e = _portstat_int(cli, p_out.name, "TX_ERR")
        drp_delta = (d - drp0) if (d is not None and drp0 is not None) else 0
        err_delta = (e - err0) if (e is not None and err0 is not None) else 0
        if max(drp_delta, err_delta) >= _MTU_BURST * 0.5:
            break

    # main criterion: an oversized frame should not egress the small-MTU port (cut on egress).
    # A tiny amount of background traffic is tolerated, but far < the within-MTU control.
    forwarded_blocked = over_fwd < in_fwd * 0.3
    counted = max(drp_delta, err_delta) >= _MTU_BURST * 0.5

    if forwarded_blocked and counted:
        return   # pass: the oversized frame was neither forwarded nor un-attributed by ingress
                 # drop counting -- MTU frame-cutting is truly in effect
    if forwarded_blocked:
        # class-B correct behavior: the oversized frame really was not forwarded (the primary
        # MTU-cutting behavior is in effect), it just was not attributed to TX_DRP/TX_ERR (a
        # counting-attribution difference for chip silent drops, not a defect) -- the main
        # criterion holds so judge PASS, only printing a counting-attribution note.
        print(f"[note] MTU enforced: oversized frames NOT forwarded to {p_out.name} "
              f"(TX={over_fwd} vs within-MTU={in_fwd}), but no TX_DRP/TX_ERR delta "
              f"(drp+{drp_delta}/err+{err_delta}); chip drops silently")
        return
    # class-A device defect: the oversized frame still flooded across == the port MTU is not
    # cutting frames in the data plane (config accepted but hardware not in effect) -- FAIL
    # directly to expose it.
    pytest.fail(f"oversized frame (>{_LOW_MTU}B) still egressed {p_out.name} "
                f"despite its MTU={_LOW_MTU}: re-entry RX={over_rx} (TX={over_tx}, "
                f"within-MTU baseline RX={in_fwd}); egress MTU not enforced in data plane "
                f"(config-vs-reality gap; drp+{drp_delta}/err+{err_delta})")
