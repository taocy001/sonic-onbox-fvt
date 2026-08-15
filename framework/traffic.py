"""Traffic layer: CPU send (scapy) + receive (AsyncSniffer) + counter verification.

Capture-first: by default, use AsyncSniffer on the target port's netdev to capture punted frames for content validation;
forwarding existence falls back to counter deltas.

Guarded scapy import: this module imports even on a build machine without scapy installed (it just cannot actually send packets).
"""
import time

from . import log
from .counters import ChipCounters, PortCounters

_log = log.get("traffic")

try:
    from scapy.all import AsyncSniffer, Ether, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False
    Ether = AsyncSniffer = sendp = None  # placeholder


class Capture:
    """One capture session. Start first, then send packets, then stop to fetch results.

    With inbound=True, only inbound is captured (excluding this host's TX echo); use it only for paths that truly punt to the CPU
    (trap / copy-to-cpu). For ordinary forwarding, verify with counters, not capture.
    """

    def __init__(self, iface, bpf=None, inbound=False):
        if inbound:
            bpf = f"inbound and ({bpf})" if bpf else "inbound"
        self.iface, self.bpf = iface, bpf
        self._sn = None
        self.packets = []

    def __enter__(self):
        if _SCAPY:
            self._sn = AsyncSniffer(iface=self.iface, filter=self.bpf, store=True)
            self._sn.start()
            time.sleep(0.2)  # let the sniffer come up
        return self

    def __exit__(self, *exc):
        if self._sn:
            time.sleep(0.3)
            self._sn.stop()
            self.packets = list(self._sn.results or [])
        return False

    def match(self, predicate):
        """Return the list of packets satisfying predicate(pkt)."""
        return [p for p in self.packets if _safe(predicate, p)]


class Traffic:
    """Send/receive API bound to a set of test ports (loopback already enabled)."""

    def __init__(self, cli, loopback, collector, ports):
        self.cli, self.lb, self.collector, self.ports = cli, loopback, collector, ports

    # ---- Loopback control (storm prevention: dual-port loopback may only carry known unicast) ----
    def loop(self, port):
        self.lb.enable(port)
        # L2-semantics entry: after oper-up, portsorch still **asynchronously** sets the bridge port admin to true before chip learning turns on
        # (Lrn disc->ARL); without waiting, injected learn/forward frames are lost or unlearned within that window.
        self.lb.wait_learn_ready(port)

    def unloop(self, port):
        self.lb.disable(port)

    # ---- send ----
    def send(self, port, pkt, count=1, inter=0.0):
        if not _SCAPY:
            _log.info("[no-scapy] would send %d pkt on %s", count, port.name)
            return
        self._wait_carrier(port)
        sendp(pkt, iface=port.name, count=count, inter=inter, verbose=False)
        _log.info("sent %d pkt on %s", count, port.name)

    def _wait_carrier(self, port, timeout=6):
        """Before sending, confirm the kernel netdev carrier=1 (**the kernel-side gate for injection**). After loopback is set, link-up
        propagates stage by stage via SDK->syncd->APPL_DB->kernel carrier (with second-scale jitter); if carrier is not up,
        sendp's frames are silently dropped by the kernel -> chip RX+0 false failure. On timeout it only warns, letting the test case fail honestly."""
        end = time.time() + timeout
        path = f"/sys/class/net/{port.name}/carrier"
        while time.time() < end:
            r = self.cli.sh.run(f"cat {path} 2>/dev/null", check=False)
            if (r.out or "").strip() == "1":
                return True
            time.sleep(0.3)
        _log.warning("carrier of %s still 0 after %ss; injected frames may be dropped",
                     port.name, timeout)
        return False

    # ---- capture (only for true punt paths; captures inbound only by default) ----
    def capture(self, port, bpf=None, inbound=True):
        return Capture(port.name, bpf, inbound=inbound)

    # ---- counters ----
    def counters(self, port):
        """SAI COUNTERS_DB (has a ~1s polling delay)."""
        return PortCounters.read(self.cli, port)

    def chip_counters(self, port):
        """Vendor-X chip instantaneous counters (bcmcmd show c), preferred for traffic verification."""
        return ChipCounters.read(self.lb.bsh, self.lb.dut.bcm_of(port))

    def clear_chip_counters(self):
        ChipCounters.clear(self.lb.bsh)

    # ---- default VLAN (the port's default VLAN, varies: 1000 or 1) ----
    @property
    def default_vlan(self):
        return self.lb.dut.profile.get("default_vlan", 1000)

    # ---- EDB-style forwarding verification (following the Vendor-X CINT paradigm) ----
    def forward_edb(self, p_in, p_out, pkt, count=50):
        """EDB loopback forwarding verification: p_in EDB loopback (inject and re-ingress), p_out EDB loopback + discard (break the loop without storming).
        Inject pkt at p_in; it should be forwarded to p_out. Returns p_out's chip counter delta.

        Advantages (vs hairpin): no asymmetric VLAN/PVID needed, discard deterministically breaks the loop, self-contained and does not pollute other cases.
        TODO: the EDB loopback point is before the MAC, so p_out's **MAC-level RX/TX counters (MIB_RPKT/TPKT)
        may not increment** -- CINT uses IFP copy-to-cpu capture + flex/pipeline counters. Confirm on hardware which of p_out's
        counters is valid for EDB loopback (RX? flex?); content validation goes through ACL copy-to-cpu (see forward_edb_capture).
        """
        self.lb.enable(p_in, mode="edb")
        self.lb.enable(p_out, mode="edb", discard=True)
        try:
            base = self.chip_counters(p_out)
            self.send(p_in, pkt, count=count)
            time.sleep(0.8)
            return self.chip_counters(p_out) - base
        finally:
            self.lb.disable(p_out)
            self.lb.disable(p_in)

    # ---- Smoke self-check: use chip counters to prove the hairpin loopback really returns frames to the pipeline ----
    # Uses a different MAC than the test case _probe's topo.mac("probe"), to avoid the async FDB delete/add race (the same MAC would let the former's
    # delayed delete command remove the FDB the latter just added -> frame becomes unknown-unicast flood -> storm).
    SMOKE_DST = "00:aa:bb:cc:dd:01"

    def smoke_check(self):
        """Send N known-unicast frames on ports[0] (loopback already enabled), verifying that port's chip RX_PKT increases by ~N.

        Key to storm prevention: the probe dst points via static FDB to ports[1] (a different, **non-looped-back** port), so after re-ingressing ports[0]
        the frame is forwarded away from it and does not return to ports[0] -- avoiding a self-loop storm of PHY loopback on frames "forwarded back to this port".
        Counting uses **clear -> traffic -> read once** (same paradigm as the reworked cases): a before/after difference
        can yield a negative/0 false delta under some `show c` "delta since last show" semantics.
        """
        if not _SCAPY:
            _log.warning("smoke_check skipped (no scapy / dry-run)")
            return True
        from scapy.all import IP, UDP, Raw
        p_in, p_out = self.ports[0], self.ports[1]
        n = 50
        # fdb_static_add(wait=True) already event-drives the wait for ASIC FDB programming internally, so no fixed sleep is needed
        self.cli.fdb_static_add(self.default_vlan, self.SMOKE_DST, p_out.name)
        try:
            pkt = (Ether(dst=self.SMOKE_DST, src="00:de:ad:be:ef:01") /
                   IP(dst="1.1.1.1") / UDP() / Raw(b"SMOKE" + b"x" * 40))
            for attempt in (1, 2):
                self.clear_chip_counters()
                self.send(p_in, pkt, count=n)
                # Event-driven wait for the counter DMA to settle (replacing a fixed sleep 2): some `show c` use the
                # "delta since last show" semantics -> polling accumulates each read into the total; on cumulative-semantics devices the first read meets the bar and exits early.
                total = 0
                deadline = time.time() + 3.0
                while total < n * 0.9 and time.time() < deadline:
                    time.sleep(0.4)
                    total += self.chip_counters(p_in).rx_pkt
                # Confirming read: normal traffic has settled by now (+0); a self-loop storm is still replicating exponentially and pushes total past the upper bound
                # -> honest failure. Without this read, early-exiting polling would miss a slow storm.
                time.sleep(0.4)
                total += self.chip_counters(p_in).rx_pkt
                # Lower bound: proves frames really loop back and re-ingress (>=N). Upper bound: guards against a runaway storm (a PHY self-loop reaches the millions,
                # while normal traffic, even amplified by background BUM flooding, is only in the thousands).
                ok = n * 0.9 <= total < 1_000_000
                _log.info("smoke_check %s (try%d): %s (sent=%d, chip RX +%d)",
                          p_in.name, attempt, "PASS" if ok else "FAIL", n, total)
                if ok:
                    return True
                time.sleep(1)
            return False
        finally:
            self.cli.fdb_static_del(self.default_vlan, self.SMOKE_DST)


def _safe(pred, pkt):
    try:
        return bool(pred(pkt))
    except Exception:  # noqa: BLE001
        return False
