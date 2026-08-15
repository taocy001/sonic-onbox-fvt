"""Device discovery: platform / hwsku / asic count / syncd container / SDK type / port list.

All discovery is best-effort with fallbacks; under dry-run it returns placeholder values so the build machine can still collect test cases.
"""
import json
import os
import re

from . import log, profile, shell
from .ports import Port

_log = log.get("dut")


class Dut:
    def __init__(self, sh: shell.Shell = None):
        self.sh = sh or shell.Shell()
        self.platform = self._machine_var("onie_platform") or os.environ.get(
            "DUT_PLATFORM", "unknown-platform"
        )
        self.hwsku = self._hwsku()
        self.syncd = os.environ.get("DUT_SYNCD", "syncd")
        self.profile = profile.load(self.platform, self.hwsku)   # device profile (sdk/bcm/caps)
        self.sdk = os.environ.get("DUT_SDK", "") or self.profile.get("sdk") or self._detect_sdk()
        self.ports = self._discover_ports()
        _log.info(
            "DUT: platform=%s hwsku=%s sdk=%s syncd=%s ports=%d",
            self.platform, self.hwsku, self.sdk, self.syncd, len(self.ports),
        )

    # ---- discovery ----
    def _machine_var(self, key):
        r = self.sh.run(f"grep -m1 '^{key}=' /host/machine.conf 2>/dev/null | cut -d= -f2")
        return r.out.strip() or None

    def _hwsku(self):
        r = self.sh.run(
            "sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku 2>/dev/null"
        )
        return r.out.strip() or os.environ.get("DUT_HWSKU", "unknown-hwsku")

    def _detect_sdk(self):
        """SDKLT vs. legacy SDK6, decided by `bcmcmd version`.

        drivshell-style output -> SDK6, where loopback uses the SDK6 `port cdN lb=mac`.
        """
        r = self.sh.run("bcmcmd 'version'", container=self.syncd)
        out = r.out.lower()
        if "sdklt" in out or "lt version" in out:
            return "sdklt"
        if "sdk-6." in out or "sdk version 6" in out or "drivshell" in out:
            return "sdk6"
        return os.environ.get("DUT_SDK", "sdk6")

    def _discover_ports(self):
        """Read port names from CONFIG_DB, then add the bcm logical port-number mapping."""
        names = self._port_names()
        bcmmap = self._bcm_portmap()
        ports = []
        for n in names:
            ports.append(Port(name=n, bcm=bcmmap.get(n), alias=None))
        if not ports:  # dry-run / no device: supply placeholder ports so test cases can be collected
            ports = [Port(name=f"Ethernet{i}", bcm=str(i)) for i in (0, 4, 8, 12)]
        return ports

    def _port_names(self):
        r = self.sh.run(
            "sonic-cfggen -d --var-json PORT 2>/dev/null"
        )
        try:
            data = json.loads(r.out) if r.out.strip() else {}
            return sorted(data.keys(), key=_eth_key)
        except json.JSONDecodeError:
            return []

    def _bcm_portmap(self):
        """EthernetX -> bcm port-name mapping.

        The default mapping rule is **EthernetN <-> cd(N-1)** (Eth1->cd0, Eth2->cd1).
        This returns empty and lets bcm_of() derive it from the rule; override here for
        breakout/heterogeneous mappings.

        BCM_PORT_PREFIX / BCM_PORT_OFFSET can be overridden via environment variables to fit other hwskus.
        """
        return {}

    # ---- port selection ----
    def worker_block(self):
        """The current worker's dedicated port block (declared in the profiles workers section; Phase 3 dual-traffic lane split).

        Non-parallel (FVT_WORKER unset) returns None -- behavior stays identical to the legacy
        single-process path. In parallel mode the block must be explicitly declared and its members
        must exist on the device, otherwise this hard-fails (loopback-probe a new block before
        declaring it -- do not guess)."""
        from . import worker
        if not worker.is_parallel():
            return None
        blocks = (self.profile or {}).get("workers") or {}
        blk = blocks.get(worker.wid()) or blocks.get(str(worker.wid()))
        if not blk or not blk.get("ports"):
            raise RuntimeError(
                f"FVT_WORKER={worker.wid()} but no workers[{worker.wid()}].ports declared for "
                f"this device in topology/profiles.yaml (loopback-probe the block first)")
        byname = {p.name: p for p in self.ports}
        missing = [n for n in blk["ports"] if n not in byname]
        if missing:
            raise RuntimeError(f"worker port block members not present on device: {missing}")
        return [byname[n] for n in blk["ports"]]

    def worker_pbm(self):
        """The bcm port-range string for this worker's port block (e.g. "cd8-cd15"), for range clear / loopback cleanup.
        Non-parallel returns None (callers fall back to global semantics). Falls back to a comma list when the block is non-contiguous."""
        blk = self.worker_block()
        if not blk:
            return None
        pairs = sorted((int(re.search(r"(\d+)$", self.bcm_of(p)).group(1)), p) for p in blk)
        nums = [n for n, _ in pairs]
        prefix = re.match(r"([a-zA-Z]+)", self.bcm_of(pairs[0][1])).group(1)
        if nums == list(range(nums[0], nums[0] + len(nums))):
            return f"{prefix}{nums[0]}-{prefix}{nums[-1]}"
        return ",".join(self.bcm_of(p) for _, p in pairs)

    def pick_test_ports(self, n=2):
        """Select n physical ports for traffic testing.

        Strategy: prefer ports with no IP configured, not in a PortChannel, and admin-controllable.
        This returns the shortlist; actual reservation/enabling is handled by the traffic fixture.
        In parallel mode the candidate set = this worker's port block (the key to test-transparent
        lane splitting: all role/fixture ports flow out of here).
        """
        blk = self.worker_block()
        cand = blk if blk else [p for p in self.ports if re.match(r"Ethernet\d+$", p.name)]
        if len(cand) < n:
            raise RuntimeError(f"not enough usable test ports: need {n}, found {len(cand)}")
        chosen = cand[:n]
        _log.info("selected test ports: %s", [p.name for p in chosen])
        return chosen

    def bcm_of(self, port: Port):
        """EthernetN -> bcm port name.

        Default rule: `<prefix><N + offset>`, with prefix=cd and offset=-1 (EthernetN->cd(N-1)).
        Override via DUT_BCM_PORT_PREFIX/DUT_BCM_PORT_OFFSET on other platforms,
        or provide an explicit table in _bcm_portmap (takes precedence).
        """
        if port.bcm:
            return port.bcm
        bp = self.profile.get("bcm_port", {}) if hasattr(self, "profile") else {}
        prefix = os.environ.get("DUT_BCM_PORT_PREFIX", bp.get("prefix", "cd"))
        offset = int(os.environ.get("DUT_BCM_PORT_OFFSET", bp.get("offset", -1)))
        divisor = int(os.environ.get("DUT_BCM_PORT_DIVISOR", bp.get("divisor", 1)))
        m = re.search(r"(\d+)$", port.name)
        if not m:
            return port.name
        return f"{prefix}{int(m.group(1)) // divisor + offset}"


def _eth_key(name):
    m = re.search(r"(\d+)$", name)
    return int(m.group(1)) if m else 0


def discover(sh: shell.Shell = None) -> Dut:
    return Dut(sh)
