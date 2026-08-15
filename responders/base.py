"""Async protocol responder base class."""
import time

from framework import log

_log = log.get("responder")

try:
    from scapy.all import AsyncSniffer, sendp
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False
    AsyncSniffer = sendp = None


class Responder:
    """Sniff packets on a netdev and reply per rules. Subclasses implement handle(pkt)->reply|None.

    Usage:
        with MyResponder("Ethernet1") as r:
            ... trigger DUT behavior ...
            assert r.stats["replied"] > 0
    """

    bpf = None  # subclasses may override

    def __init__(self, iface, bpf=None):
        self.iface = iface
        self._bpf = bpf or self.bpf
        self._sniffer = None
        self.seen = []          # relevant packets received
        self.stats = {"seen": 0, "replied": 0}

    # implemented by subclasses
    def handle(self, pkt):
        raise NotImplementedError

    def _on_pkt(self, pkt):
        try:
            reply = self.handle(pkt)
            if reply is None:
                return
            self.stats["replied"] += 1
            if _SCAPY:
                sendp(reply, iface=self.iface, verbose=False)
        except Exception as e:  # noqa: BLE001
            _log.debug("responder handle error: %s", e)

    def start(self):
        if not _SCAPY:
            _log.warning("no scapy, responder not starting")
            return self
        self._sniffer = AsyncSniffer(iface=self.iface, filter=self._bpf,
                                     prn=self._on_pkt, store=False)
        self._sniffer.start()
        # Poll until the sniffer thread has actually built its capture socket (scapy only sets the internal stop_cb inside _run).
        # Calling stop() before it is ready triggers scapy's internal `'AsyncSniffer' object has no attribute 'stop_cb'`.
        end = time.time() + 3.0
        while time.time() < end and not self._sniffer_ready():
            time.sleep(0.05)
        time.sleep(0.2)
        _log.info("responder %s started on %s (bpf=%s, ready=%s)",
                  type(self).__name__, self.iface, self._bpf,
                  self._sniffer_ready())
        return self

    def _sniffer_ready(self):
        """Whether the sniffer thread has built its socket (presence of internal stop_cb means it is safe to stop)."""
        sn = self._sniffer
        return sn is not None and hasattr(sn, "stop_cb")

    def stop(self):
        sn = self._sniffer
        self._sniffer = None
        if sn is None:
            return
        try:
            # Only call stop() when the scapy sniffer thread is truly ready (running and internal stop_cb set),
            # otherwise scapy accesses the undefined stop_cb inside stop() and raises AttributeError.
            if getattr(sn, "running", False) and hasattr(sn, "stop_cb"):
                sn.stop()
            else:
                th = getattr(sn, "thread", None)
                if th is not None:
                    th.join(timeout=2.0)
        except Exception as e:  # noqa: BLE001  thread not ready / already exited, swallow to avoid polluting test results
            _log.debug("responder sniffer stop ignored: %s", e)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
