"""Asymmetric VLAN hairpin topology: structural loop-break + captureable post-forward packets (Pattern C / ip2me).

  CPU --send--> p_in --loopback--> re-ingress[PVID=A] --forward within VLAN A--> p_out egress (VLAN A egress untagged)
                                                              |
                                            p_out --loopback--> re-ingress[PVID=B] --> VLAN B (dead end or SVI->CPU)
                                                            +- never returns to VLAN A, structural loop-break

Why an asymmetric VLAN breaks the loop (clarified empirically, unrelated to MAC/PHY loopback): if both loopback ports are
in the **same** VLAN, any flood/return bounces back and forth between the two ports into a storm; and if the return frame's
dst still resolves to some loopback port, it self-loops on forwarding. Putting p_in ingress on VLAN A and p_out ingress on
VLAN B (**different** ingress VLANs), the return frame enters the VLAN B dead end, its dst does not resolve to any loopback
port in B, breaking the loop structurally. Configuring an SVI on VLAN B lets the return frame be punted via ip2me/
L3-to-CPU, capturing the frame **after p_out egress processing** (DSCP/TTL/L4/payload etc.) inbound on the p_out netdev,
with no FP copy-to-cpu collector needed.

Implementation: VLAN A is configured via SONiC (so forwarding goes through SONiC's FDB/VLAN orch); the port ingress PVID is
set explicitly with bcmcmd `pvlan set <cd> <vid>` -- **untagged membership does not set the PVID** (verified), and vlanorch
writes back asynchronously, so arm() reads back to confirm after set.
"""
from framework import log
from framework.loopback import BcmShell

_log = log.get("hairpin")


class Hairpin:
    def __init__(self, cli, dut, lb, p_in, p_out, vlan_a, vlan_b, svi_ip=None):
        self.cli, self.dut, self.lb = cli, dut, lb
        self.p_in, self.p_out = p_in, p_out
        self.a, self.b = vlan_a, vlan_b
        self.svi_ip = svi_ip
        self.bsh = BcmShell(cli.sh, dut)
        self.default_vlan = dut.profile.get("default_vlan", 1000)
        self._undo = []

    def _preclean(self):
        """Defensive pre-clean: reset both ports' ingress PVID to the default VLAN (the most common leftover from a previously failed case).
        Do not touch VLANs (chip vlan destroy would desync with SONiC CONFIG_DB); VLANs are handled idempotently by SONiC."""
        for p in (self.p_in, self.p_out):
            self.bsh.cmd(f"pvlan set {self.dut.bcm_of(p)} {self.default_vlan}")

    def setup(self):
        c = self.cli
        self._preclean()
        # 1) VLAN A (SONiC): p_in / p_out both untagged, so forwarding goes through SONiC
        c.config_raw(f"vlan add {self.a}")
        self._undo.append(f"vlan del {self.a}")
        for p in (self.p_in, self.p_out):
            c.config_raw(f"vlan member del {self.default_vlan} {p.name}")
            self._undo.append(f"vlan member add -u {self.default_vlan} {p.name}")
            c.config_raw(f"vlan member add -u {self.a} {p.name}")
            self._undo.append(f"vlan member del {self.a} {p.name}")
        # 2) VLAN B (SONiC): the return VLAN. p_out **only sets ingress PVID=B (see arm), it is not an egress member of B** --
        #    otherwise the return frame in B would exit p_out again -> loopback re-ingress -> loop storm. Not being an egress
        #    member of B => the return frame entering B has no p_out exit => dead end (or punted to CPU via the SVI), structural loop-break.
        c.config_raw(f"vlan add {self.b}")
        self._undo.append(f"vlan del {self.b}")
        if self.svi_ip:
            c.config_raw(f"interface ip add Vlan{self.b} {self.svi_ip}")
            self._undo.append(f"interface ip remove Vlan{self.b} {self.svi_ip}")
        for p in (self.p_in, self.p_out):
            c.intf_startup(p.name)
        # 3) loopback on both ports
        self.lb.enable(self.p_in)
        self.lb.enable(self.p_out)
        _log.info("Hairpin up: %s(in,A=%d) -> %s(out,A egress / in PVID=B=%d) svi=%s "
                  "(call arm() to override PVID before sending)",
                  self.p_in.name, self.a, self.p_out.name, self.b, self.svi_ip)
        return self

    def arm(self, tries=20):
        """Explicitly set both ports' ingress PVID: **p_in -> A, p_out -> B** (the core of the asymmetric loop-break). **Call right before sending.**

        Why set both explicitly: **untagged membership does not set the PVID to the corresponding VLAN** (the port stays in
        the default VLAN), so frames enter the big default VLAN and flood to a pile of ports (including loopback ports) -> a
        storm. So we don't rely on membership; both ports are set explicitly with `pvlan set <port> <vid>` (`port ... pvlan=`
        is illegal); `pvlan show` reads back to confirm.
        Race: vlanorch writes back the PVID asynchronously, so after set **read back to confirm** and retry if it didn't take.
        Once confirmed, send immediately and do not trigger any further VLAN/FDB programming mid-flight."""
        self._set_pvid(self.dut.bcm_of(self.p_in), self.a, tries)
        self._set_pvid(self.dut.bcm_of(self.p_out), self.b, tries)
        return self

    def _set_pvid(self, cd, vid, tries=20):
        import time
        want = f"default VLAN is {vid}"
        for i in range(tries):
            self.bsh.cmd(f"pvlan set {cd} {vid}")
            time.sleep(0.4)
            if want in self.bsh.cmd(f"pvlan show {cd}"):
                _log.info("arm: %s PVID -> %d confirmed (attempt %d)", cd, vid, i + 1)
                return
        raise RuntimeError(f"unable to set {cd} PVID to {vid} (vlanorch keeps overwriting?)")

    def fdb_to_out(self, mac):
        """Static FDB: mac -> p_out (within VLAN A), so a CPU-injected unicast forwards to p_out.
        **Wait until the ASIC FDB is actually programmed** before returning -- otherwise dst is still unknown unicast at send time and floods/amplifies."""
        import time
        self.cli.fdb_static_add(self.a, mac, self.p_out.name)
        self._undo_fdb = (self.a, mac)
        up = mac.upper()
        for _ in range(20):
            keys = self.cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*")
            if any(up in k.upper() for k in keys):
                return self
            time.sleep(0.4)
        _log.warning("FDB %s not confirmed programmed to ASIC, traffic may flood", mac)
        return self

    def punt_b_to_cpu(self, mac):
        """Within VLAN B, punt frames destined for mac to the CPU (Pattern C: capture the forwarded frame **after p_out egress processing**).
        After the forwarded frame exits p_out and loops back into VLAN B, this chip l2 entry sends it to the CPU. The CPU port
        must be added as a VLAN B member, otherwise punted frames are dropped by VLAN membership filtering (empirically only stray frames get punted)."""
        # p_out + CPU join VLAN B members: otherwise frames are dropped by ingress VLAN filtering (never reach l2->cpu).
        # The return frame is punted to CPU via l2->cpu (it does not flood/forward to loopback ports within B), so p_out joining B does not storm.
        cd_out = self.dut.bcm_of(self.p_out)
        self.bsh.cmd(f"vlan add {self.b} pbm={cd_out},cpu0")
        self.bsh.cmd(f"l2 add mac={mac} vlan={self.b} port=cpu0")
        self._undo_l2cpu = (mac, self.b)
        return self

    def teardown(self):
        if getattr(self, "_undo_l2cpu", None):
            mac, vid = self._undo_l2cpu
            self.bsh.cmd(f"l2 del mac={mac} vlan={vid}")
            cd_out = self.dut.bcm_of(self.p_out)
            self.bsh.cmd(f"vlan remove {vid} pbm={cd_out},cpu0")   # remove the members added for capture, to avoid pollution
        if getattr(self, "_undo_fdb", None):
            self.cli.fdb_static_del(*self._undo_fdb)
        # restore both ports' PVID to the device default VLAN (to avoid pollution)
        for p in (self.p_in, self.p_out):
            self.bsh.cmd(f"pvlan set {self.dut.bcm_of(p)} {self.default_vlan}")
        self.lb.disable(self.p_in)
        self.lb.disable(self.p_out)
        for cmd in reversed(self._undo):
            self.cli.config_raw(cmd)
        self._undo.clear()

    def __enter__(self):
        return self.setup()

    def __exit__(self, *exc):
        self.teardown()
        return False
