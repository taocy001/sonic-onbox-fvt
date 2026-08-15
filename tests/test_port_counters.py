"""Port counters: chip and SAI counts grow with real traffic (Pattern B fast smoke layer).

The authoritative exact-count checks live in test_counters_chip.py (exact lower-bound==N
asserts); this file keeps a fast increment-semantics smoke (0.9N/0.8N lower bounds + storm
upper bound) that runs quickly and surfaces loopback-rig-level failures ahead of the exact cases.

Storm guard (high-risk fix): injected frames' dst goes through a file-local static FDB
pointing at ports[1]. The old implementation used topo.mac("dst") without installing an FDB,
so all 200 frames were unknown unicast, flooded the default VLAN on loopback re-ingress, and
fed a self-sustaining storm if another loopback port shared the VLAN (l2-cascade field lesson).
Chip readings use clear -> polled accumulate + confirm read: this diag `show c` has
"delta since last show" semantics, so an old before/after difference would yield negative /
under-counted false deltas.
"""
import time

import pytest

pytestmark = [pytest.mark.counters, pytest.mark.traffic, pytest.mark.pattern_b]

# Injection count and storm guard: lower bound catches lost counts, upper bound traps a
# runaway self-looping storm (matches test_counters_chip._STORM_GUARD; an assert without an
# upper bound still PASSes under a flood storm == false pass, so both bounds are needed to
# prove the count came from the injection).
_N = 200
_STORM_GUARD = 3000
# File-local DST/SRC MAC: distinct from smoke(...:01)/counters_chip(...:71)/stats(...:11) etc.,
# to avoid cross-case static-FDB add/delete races wiping each other's entries -> unknown
# unicast flood -> storm.
_PB_DST = "00:aa:bb:cc:dd:72"
_PB_SRC = "00:de:ad:be:ef:72"


@pytest.fixture
def _pb_fdb(cli, traffic):
    """Install a static FDB for injected frames (dst -> ports[1]): re-ingressing frames get
    deterministic unicast forwarding out of ports[0], never back to this port and never
    flooded (following the test_counters_chip._cnt_fdb pattern). Removed on teardown."""
    cli.fdb_static_add(traffic.default_vlan, _PB_DST, traffic.ports[1].name)
    yield
    cli.fdb_static_del(traffic.default_vlan, _PB_DST)


def _pkt():
    from scapy.all import Ether, IP, UDP, Raw
    return (Ether(dst=_PB_DST, src=_PB_SRC) /
            IP(dst="10.0.0.9") / UDP() / Raw(b"CNT" + b"x" * 60))


def test_chip_counter_increments(traffic, _pb_fdb):
    """Chip RX count grows with loopback traffic: clear -> inject N -> polled accumulate +
    confirm read, delta falls in [0.9N, N+guard). clear goes through
    traffic.clear_chip_counters() (=ChipCounters.clear; in parallel mode only clears this
    worker's port block)."""
    pytest.importorskip("scapy.all")
    p = traffic.ports[0]
    traffic.clear_chip_counters()
    traffic.send(p, _pkt(), count=_N)
    # Under delta semantics each show is the previous window's increment; summing them gives
    # the total since clear. On a device with cumulative semantics the first read already
    # meets the target and we exit early (same pattern as the framework's smoke_check).
    total, deadline = 0, time.time() + 8.0
    while total < _N and time.time() < deadline:
        time.sleep(0.4)
        total += traffic.chip_counters(p).rx_pkt
    time.sleep(0.4)
    total += traffic.chip_counters(p).rx_pkt   # confirm read: catches late counter DMA and slow storms
    assert _N * 0.9 <= total < _N + _STORM_GUARD, (
        f"chip RX delta out of bounds on {p.name}: +{total}, sent {_N} "
        f"(expected [{_N * 0.9:.0f}, {_N + _STORM_GUARD}); low=frames lost, high=flood storm)")


def test_sai_counter_tracks_loopback(traffic, _pb_fdb):
    """SAI COUNTERS_DB count grows with loopback traffic: send N frames, SAI RX(total) falls
    in [0.8N, N+guard). The flex counter samples accurately while traffic runs on a loopback
    port, so we assert directly. This case does **no chip clear**: `clear c` would zero/wrap
    the SAI readback and destroy the SAI baseline; the SAI raw value is cumulative, so the
    before/after difference is itself correct."""
    pytest.importorskip("scapy.all")
    p = traffic.ports[0]
    base = traffic.counters(p)
    traffic.send(p, _pkt(), count=_N)
    d = 0
    for _ in range(15):    # flex counter polls ~1s + sync delay; poll for the increment
        time.sleep(1)
        d = (traffic.counters(p) - base).rx_all
        if d >= _N * 0.8:
            break
    time.sleep(1)
    d = (traffic.counters(p) - base).rx_all    # confirm read: a slow storm breaches the upper bound -> honest failure
    assert _N * 0.8 <= d < _N + _STORM_GUARD, (
        f"SAI RX delta out of bounds on {p.name}: +{d}, sent {_N} "
        f"(expected [{_N * 0.8:.0f}, {_N + _STORM_GUARD}))")
