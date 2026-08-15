"""copy-to-CPU collector -- in capture-first mode, replicates a "forwarded-to-an-egress-port" frame up to the CPU.

Why it exists: Pattern C must prove a frame was actually forwarded to physical port P2
and validate its rewritten contents. P2 has MAC loopback enabled, so a frame forwarded
out of P2 loops back and re-ingresses on P2; installing an FP rule that
**matches the probe signature with action = CopyToCpu** replicates that frame up to the CPU,
where it can be captured on EthernetP2's netdev, while the original frame keeps going
(so counter verification is not disturbed).

We deliberately use bcmcmd FP rather than SONiC ACL: since we are testing SONiC ACL itself,
the collector must be decoupled from the feature under test.

Match signature: probe packets carry a fixed src MAC (the framework uses PROBE_SMAC uniformly),
and the FP qualifies on SrcMac to avoid capturing unrelated traffic.

# VERIFY-ON-HW: the FP command sequence below is a placeholder template written per
# Vendor-X diag shell conventions; it must be confirmed on SDKLT (SDKLT drives the
# FP_ING_* logical tables, whose syntax differs substantially from SDK6).
# If the FP route does not work smoothly on your SDK, see the fallback plan at the end of this docstring.
"""
from . import log

_log = log.get("collector")

PROBE_SMAC = "00:de:ad:be:ef:01"   # framework-wide uniform probe src MAC; the collector matches on it

# Placeholder template: calibrate against your actual SDK. {gid}=group id, {eid}=entry id, {bcm}=port number, {smac}=signature
FP_TEMPLATES = {
    "sdk6": [
        "fp group create {gid} pri 1 qset SrcMac InPort",
        "fp entry create {gid} {eid}",
        "fp qual {eid} SrcMac {smac} ffffffffffff",
        "fp qual {eid} InPort {bcm} 0xffffffff",
        "fp action add {eid} CopyToCpu 0 0",
        "fp entry install {eid}",
    ],
    "sdklt": [
        # SDKLT: configured via the three tables FP_ING_GRP_TEMPLATE / FP_ING_RULE / FP_ING_POLICY.
        # This is a placeholder only; the real sequence must be expanded per the schema. VERIFY-ON-HW.
        "lt FP_ING_GRP_TEMPLATE insert FP_ING_GRP_TEMPLATE_ID={gid} ...",
        "lt FP_ING_RULE insert FP_ING_RULE_ID={eid} ...",
        "lt FP_ING_POLICY insert FP_ING_POLICY_ID={eid} COPY_TO_CPU=1 ...",
        "lt FP_ING_ENTRY insert FP_ING_ENTRY_ID={eid} ...",
    ],
    "remove": {
        "sdk6": ["fp entry remove {eid}", "fp entry destroy {eid}", "fp group destroy {gid}"],
        "sdklt": ["lt FP_ING_ENTRY delete FP_ING_ENTRY_ID={eid}"],
    },
}


class MirrorCollector:
    """Egress-mirror-to-CPU collector (**verified working on hardware**).

    Mirrors a copy of a port's **egress frames** to cpu0; the mirrored frame appears on
    **that port's netdev (inbound)** and can be captured with `Capture(port.name,
    inbound=True)` -- what you capture is the **real frame after the chip's egress processing**:
    the post-L3-rewrite DMAC(neighbor)/SMAC(router)/TTL-1 and VLAN tag push/pop are all
    **preserved** (unlike the FDB-to-cpu hairpin-punt, which re-applies the VLAN B tag).

    Mechanism: bcmcmd `mirror dest create destport=cpu0` + `mirror dest add id=<id> srcport=<bcm> mode=Egress`.
    We deliberately use SDK6 mirror rather than FP CopyToCpu -- the latter, on this SDK6/knet, replicates packets that never reach the netdev (no trap-reason mapping).

    Usage: the mirrored port must be oper-up (enabling MAC loopback is enough) to have egress traffic;
    inject to the upstream port -> the frame is forwarded out of the mirrored port -> the mirrored frame goes to the CPU.
    """

    def __init__(self, bcm_shell, dut):
        self.bsh, self.dut = bcm_shell, dut
        self._mid = None
        self._src = None

    def enable(self, port):
        import re
        bcm = self.dut.bcm_of(port)
        self.bsh.cmd("mirror init")
        out = self.bsh.cmd("mirror dest create destport=cpu0")
        m = re.search(r"Id\s*=\s*(0x[0-9a-fA-F]+)", out)
        if not m:
            raise RuntimeError(f"mirror dest create failed (no Id): {out[-120:]}")
        self._mid, self._src = m.group(1), bcm
        self.bsh.cmd(f"mirror dest add id={self._mid} srcport={bcm} mode=Egress")
        _log.info("mirror collector ON: %s(%s) egress -> cpu0 (id=%s)", port.name, bcm, self._mid)
        return self

    def disable(self):
        # `mirror port <bcm> mode=off` is the working mirror-off command on this SDK6 (deleting by id reports Invalid parameter)
        if self._src:
            try:
                self.bsh.cmd(f"mirror port {self._src} mode=off")
            except Exception as e:  # noqa: BLE001
                _log.warning("failed to remove mirror collector: %s", e)
        if self._mid:
            self.bsh.cmd(f"mirror dest destroy id={self._mid}")  # best-effort destroy of the dest
        self._mid = self._src = None


class Collector:
    """copy-to-CPU collector. After enable, probe frames forwarded to the port are replicated up to the CPU."""

    def __init__(self, bcm_shell, dut, sdk="sdklt", gid=63, eid=6300):
        self.bsh, self.dut, self.sdk = bcm_shell, dut, sdk
        self.gid, self.eid = gid, eid
        self._active = []

    def enable(self, port, smac=PROBE_SMAC):
        bcm = self.dut.bcm_of(port)
        _log.info("collector ON %s (bcm=%s, sig smac=%s)", port.name, bcm, smac)
        for tpl in FP_TEMPLATES[self.sdk]:
            self.bsh.cmd(tpl.format(gid=self.gid, eid=self.eid, bcm=bcm,
                                    smac=smac.replace(":", "")))
        self._active.append(port)

    def disable(self):
        for tpl in FP_TEMPLATES["remove"][self.sdk]:
            try:
                self.bsh.cmd(tpl.format(gid=self.gid, eid=self.eid))
            except Exception as e:  # noqa: BLE001
                _log.warning("failed to remove collector: %s", e)
        self._active = []


# Fallback plans (if the FP route does not work):
#   1) Pattern A alternative -- have the feature under test itself punt the frame to the CPU (trap/redirect), no collector needed;
#   2) use a SPAN mirror session to mirror P2 egress to a port that "loops back to the CPU";
#   3) do Pattern B counter verification only, giving up content capture (degraded; coverage marked capture=partial).
