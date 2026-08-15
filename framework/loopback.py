"""bcmsh port internal loopback management -- the foundation of traffic topologies. Adapts to multi-platform SDK/diag access.

Mechanism: a packet TX'd on EthernetX is directed out of the physical port; if that port has loopback
enabled, the packet loops back and re-enters the pipeline as ingress -- turning a "CPU-directed egress" into an "ingress stimulus".

**Two loopback mechanisms (pick per test case)**:
1) **EDB style (modeled on the Vendor-X CINT pattern, recommended for most forwarding/content cases)**: `lb=edb` (egress-buffer loopback, after
   the egress pipeline and before MAC). The forwarding target port (p_out) also sets `discard=all`, so the **re-ingressing frames are dropped** --
   deterministically breaks the loop, never storms (the CINT comment literally says avoid continuous loopback), with no need for asymmetric VLAN/PVID tricks.
   Capture the post-forwarding packet with ACL/IFP copy-to-cpu (captures the real egress frame, lets you verify VLAN tag/DSCP remark).
   `enable(p, mode="edb")`; add `discard=True` on the egress port.
2) **MAC/PHY style (the original approach, for features that need MAC-layer participation, e.g. port counters)**: `lb=mac`/`lb=phy`, with the loopback point
   at the MAC (or SerDes). Frames traverse the MAC, so **MAC-level TX/RX port counters (MIB_TPKT/RPKT) increment** -- EDB loops back before the
   MAC, so the MAC TX counter may not increment; use this style for port-counter cases.
   `enable(p)` (uses the profile's loopback_mode default).

Platform differences (provided by topology/profiles.yaml):
- diag access diag_access: bcmcmd (over TCP) / socket (over the dsserve unix socket).
- loopback_mode: mac / phy (on some platforms lb=mac has no effect).
  WARNING: on some SDK6 builds `lb=edb` has no effect (Invalid parameter) -- EDB cannot be reached via bcmcmd lb=, so mechanism 1
  and forward_edb are dead code on such devices; for real data-plane traffic use the L3 pattern (test_l3_forward_traffic) or a hairpin. See docs/LOOPBACK_MECHANISMS.md.
- bcm port names are mapped by dut.bcm_of() using the profile's {prefix,divisor,offset}.
"""
import base64

from . import log

_log = log.get("loopback")

# A clean unix-socket diag client that runs inside the syncd container: reads the command from argv[1], connects to the socket, sends it, reads until the prompt, then closes.
_SOCK_CLIENT = r'''
import socket, sys, time
SOCK = "/var/run/sswsyncd/sswsyncd.socket"
PROMPTS = (b"BCM.0>", b"drivshell>", b"BCMLT.0>")
cmd = sys.argv[1] if len(sys.argv) > 1 else "version"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.setblocking(True); s.settimeout(6)
s.connect(SOCK)
try:
    s.sendall(cmd.encode() + b"\n")
    buf = b""; end = time.time() + 6
    while time.time() < end:
        try: c = s.recv(8192)
        except socket.timeout: break
        if not c: break
        buf += c
        if any(p in buf for p in PROMPTS): break
    sys.stdout.write(buf.decode(errors="replace"))
finally:
    s.close()
'''


class BcmShell:
    """Sends a single bcm diag command into the syncd container for execution. Routes bcmcmd / socket per diag_access."""

    def __init__(self, sh, dut):
        self.sh = sh
        self.syncd = dut.syncd
        self.access = (dut.profile.get("diag_access", "bcmcmd")
                       if hasattr(dut, "profile") else "bcmcmd")
        # Phase3 parallelism: the bcm range string for this worker's port block (e.g. cd8-cd15). Whole-chip
        # operations like ChipCounters.clear are narrowed to this port group so they don't disturb the other
        # worker; None when not parallel (global semantics unchanged).
        try:
            self.worker_pbm = dut.worker_pbm() if hasattr(dut, "worker_pbm") else None
        except Exception:  # noqa: BLE001
            self.worker_pbm = None

    def cmd(self, c):
        # Parallel lane splitting: a bare global `clear c` is rewritten to this worker's port range -- a
        # `bsh.cmd("clear c")` scattered across cases/helpers means "clear the counters I care about", but the
        # global version would zero out the counter baseline the other worker is measuring (e.g. w2's _l3_clean
        # clears globally once per case, and w1's flood readings stay stuck at 0).
        if self.worker_pbm and c.strip() == "clear c":
            c = f"clear c {self.worker_pbm}"
        if self.access == "socket":
            return self._sock_cmd(c)
        return self.sh.run(f"bcmcmd '{c}'", container=self.syncd).out

    def _sock_cmd(self, c):
        import shlex
        b64 = base64.b64encode(_SOCK_CLIENT.encode()).decode()
        boot = f'import base64; exec(base64.b64decode("{b64}"))'
        full = (f"docker exec -i {self.syncd} python3 -c {shlex.quote(boot)} "
                f"{shlex.quote(c)}")
        return self.sh.run(full, check=False).out


class LoopbackManager:
    def __init__(self, shell_runner, dut, sdk=None, cli=None):
        self.bsh = BcmShell(shell_runner, dut)
        self.dut = dut
        # config-level CLI. On a switchport OS, testing VLANs must go through the config level
        # (orchagent builds the SAI VLAN/bridge objects, programs chip membership/PVID consistently, static FDB can resolve bv_id),
        # rather than chip-level bcmcmd (which fights orchagent's async writeback and does not create a SAI vlan object = FDB bv_id NULL).
        self.cli = cli
        self.mode = (dut.profile.get("loopback_mode", "mac")
                     if hasattr(dut, "profile") else "mac")   # default loopback type for the MAC/PHY style
        self._on = {}    # port -> (mode, discard)
        self._flood_safe = {}   # port -> (bcm, isolate_vid, orig_pvid)  PVID restore info for flood-safe loopback
        self._test_vlan = None  # (vid, [bcm...], restore_vid)  restore info for the dedicated test VLAN
        self._held = {}  # port -> mode  group-level held loopback (per-test fallback auto-reopens after clearing all, see hold/force_clear_all)
        self._touched = False  # whether this case actually used loopback (enable/flood/test_vlan) -- lets the per-test fallback decide whether to settle

    def hold(self, port, mode=None):
        """Mark this port's loopback as "group-level held": when a group of cases for one feature shares the same loopback
        environment, the group setup opens it once and holds it; the per-case force_clear_all fallback will **auto-reopen**
        these held ports after clearing all (a single cheap bcmcmd), keeping the storm-prevention full-clear safety net while
        not tearing down the group's shared loopback. The group teardown calls release + disable."""
        self._held[port] = mode or self.mode

    def release(self, port):
        """Release a group-level hold (used by group teardown; disable then actually turns it off)."""
        self._held.pop(port, None)

    def use_test_vlan(self, vid, ports, restore_vid=1000):
        """Put this group's ports into a **dedicated test VLAN** (chip-level, containing only these ports) and set their ingress
        PVID to that VLAN -- so flooding replicates only within these few ports, rather than across all 160 ports of the
        production default VLAN.

        Root cause: repeatedly flooding in a large production VLAN, where every frame is replicated to all member ports, drags
        the chip into **degradation** (loopback hairpin/learning/aging become unstable). The same-intensity iteration in a
        dedicated VLAN (~4 ports) has no such degradation. This method shrinks the flood domain for L2 data-plane cases.

        When a port-under-test later temporarily changes its PVID via enable_flood_safe/isolate_pvid, it reads orig=this VLAN and
        restores back to this VLAN (auto-compatible). teardown calls drop_test_vlan to restore the PVID back to restore_vid and
        destroy this VLAN.

        In parallel mode vid is offset per worker (cases still pass the literal 2000; the two workers actually use disjoint vids)."""
        from . import worker as _W
        vid = _W.remap_vid(vid)
        if self.cli is not None and self.cli.is_switchport_os():
            return self._use_test_vlan_cfg(vid, ports, restore_vid)
        bcms = [self.dut.bcm_of(p) for p in ports]
        self.bsh.cmd(f"vlan create {vid}")
        self.bsh.cmd(f"vlan add {vid} pbm={','.join(bcms)} ubm={','.join(bcms)}")
        # PVID set must be **read back to confirm + retry** (same discipline as topo/hairpin.arm): vlanorch/the product portmgr
        # asynchronously writes back the chip PVID (when the PORT table carries a pvid field), so a bare set may be reverted to
        # the default within ~1s -- hence read back to confirm.
        import time as _t
        for b in bcms:
            for _ in range(10):
                self.bsh.cmd(f"pvlan set {b} {vid}")
                if f"default VLAN is {vid}" in self.bsh.cmd(f"pvlan show {b}"):
                    break
                _t.sleep(0.3)
            else:
                _log.warning("use_test_vlan: pvid of %s not holding at %s (async rewrite?)", b, vid)
        self._test_vlan = (vid, bcms, restore_vid)
        self._touched = True
        _log.info("test-VLAN %s up: %d ports scoped (flood domain shrunk from production VLAN)", vid, len(bcms))
        return vid

    def _use_test_vlan_cfg(self, vid, ports, restore_vid):
        """switchport-OS path: the test VLAN goes through the **config level** (config vlan add + access member add).
        From this, orchagent builds the SAI VLAN + BRIDGE_PORT objects, programs members/PVID consistently to the chip, and a
        static FDB (config mac static add / APPL_DB) can resolve into ASIC_DB under that VLAN's bv_id. The access members'
        PVID is set to vid by orchagent (classified untagged), so the flood domain is just these ports. teardown goes through the config level."""
        names = [getattr(p, "name", p) for p in ports]
        self.cli.config(f"vlan add {vid}", check=False)
        for p in ports:
            n = getattr(p, "name", p)
            self.cli.ensure_port_l2(p)          # route -> bridge(access), for config vlan member
            self.cli.intf_startup(n)
            self.cli.vlan_member_add(vid, n)    # access untagged member -> orchagent programs chip + PVID=vid
        # After member add rebuilds the bridge port, verify/self-heal the learn bit (same as the conftest l2_fwd_vlan comment: in some
        # cases orchagent does not set learn on member add, and if chip learning is off the port's L2 is fully dead; on the healthy path the first ARL round is zero-cost)
        for p in ports:
            self.wait_learn_ready(p, timeout=4)
        bcms = [self.dut.bcm_of(p) for p in ports]
        self._test_vlan = (vid, bcms, restore_vid, names)   # 4-tuple = config level (with port names)
        self._touched = True
        _log.info("test-VLAN %s up (config-level, switchport OS): %d ports", vid, len(ports))
        return vid

    def drop_test_vlan(self):
        """Restore the dedicated test VLAN: chip level = restore PVID + destroy; config level = delete members + delete VLAN."""
        info = self._test_vlan
        self._test_vlan = None
        if not info:
            return
        if len(info) == 4:              # config-level path (switchport OS)
            vid, bcms, restore_vid, names = info
            # **Delete all current members of this VLAN** (rather than only the names recorded at build time) -- a case may have
            # moved other ports in/out of this VLAN via flood_safe/isolation, so deleting only names
            # would miss members -> `vlan del` fails with "still has members" -> the VLAN key leaks and pollutes later runs.
            import time as _t
            cur = self.cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|*")
            for k in cur:
                mn = k.split("|")[-1]
                try:
                    self.cli.config(f"vlan member del {vid} {mn}", check=False)
                except Exception:  # noqa: BLE001
                    pass
            # Wait for the member keys to actually disappear (orchagent async) before deleting the VLAN -- otherwise deleting the VLAN races with deleting members, fails, and leaves stale keys
            for _ in range(20):
                if not self.cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|*"):
                    break
                _t.sleep(0.3)
            # Delete the VLAN and **read back to confirm + retry**: under heavy SONiC/orchagent load `vlan del` occasionally does not take effect
            # (the same command run again idempotently succeeds later = a race, not a rejection)
            for _ in range(6):
                if not self.cli.db_keys("CONFIG_DB", f"VLAN|Vlan{vid}"):
                    break
                try:
                    self.cli.config(f"vlan del {vid}", check=False)
                except Exception as e:  # noqa: BLE001
                    _log.warning("drop_test_vlan(cfg) del %s failed: %s", vid, e)
                _t.sleep(0.4)
            else:
                _log.warning("drop_test_vlan(cfg): VLAN %s still in CONFIG_DB after retries", vid)
            return
        vid, bcms, restore_vid = info
        for b in bcms:
            try:
                self.bsh.cmd(f"pvlan set {b} {restore_vid}")
            except Exception:  # noqa: BLE001
                pass
        try:
            self.bsh.cmd(f"vlan destroy {vid}")
        except Exception as e:  # noqa: BLE001
            _log.warning("drop_test_vlan destroy %s failed: %s", vid, e)

    def chip_fdb_add(self, vid, mac, port):
        """Static FDB. switchport-OS (config-level test VLAN): go through config/APPL_DB (cli.fdb_static_add),
        fdborch resolves that VLAN's bridge object (bv_id) and programs ASIC_DB; a chip-level l2 add does not reach ASIC_DB.
        Other products (test VLAN is chip-level, not in CONFIG_DB): go through chip-level l2 add to install the directed known-unicast sink entry."""
        if self.cli is not None and self.cli.is_switchport_os():
            self.cli.fdb_static_add(vid, mac, getattr(port, "name", port))
            return
        self.bsh.cmd(f"l2 add mac={mac} vlan={vid} port={self.dut.bcm_of(port)} static=1")

    def chip_fdb_del(self, vid, mac):
        self.bsh.cmd(f"l2 del mac={mac} vlan={vid}")

    def _set(self, port, val):
        bcm = self.dut.bcm_of(port)
        self.bsh.cmd(f"port {bcm} lb={val}")
        return bcm

    def enable(self, port, mode=None, discard=False, wait_up=True):
        """Enable loopback. mode=None uses the MAC/PHY style default (profile); mode="edb" uses the EDB style.
        When discard=True, set discard=all on that port (used to break the loop on the EDB forwarding target port, dropping re-ingressing frames to prevent storms).

        wait_up=True (default): **wait until the link is actually up before returning**. After `lb=mac`, link-up time
        jitters 2~10+ seconds, and frames injected from the netdev before link-up are silently dropped by the kernel/KNET ->
        random RX+0 false failures in smoke/learning. Polls APPL_DB PORT_TABLE oper_status (SONiC receives link events from the SDK,
        consistent with the chip); on timeout only warn, do not raise -- if the link genuinely can't come up, the case assertion honestly exposes it."""
        mode = mode or self.mode
        bcm = self._set(port, mode)
        if discard:
            self.bsh.cmd(f"port {bcm} discard=all")
        if wait_up:
            self._wait_oper_up(port)
        _log.info("loopback(%s%s) ON  %s (bcm=%s)",
                  mode, "+discard" if discard else "", port.name, bcm)
        self._on[port] = (mode, discard)
        self._touched = True

    def wait_learn_ready(self, port, timeout=12):
        """Wait until the port's chip hardware learning is actually enabled (the `port <bcm>` Lrn contains ARL).

        Mechanism: when the port is oper-down, SONiC sets the bridge port's SAI_BRIDGE_PORT_ATTR_ADMIN_STATE
        to false -> chip Lrn(disc) (learning off). After loopback brings it oper-up, portsorch **asynchronously** sets the bridge port
        admin back to true -> only then does the chip return to Lrn(ARL,FWD). A learning frame sent during this window is never learned (false failure).
        Call it before injecting for dynamic-learning cases; not applicable to L3 ports (no bridge port), where timeout only warns."""
        import time as _t
        bcm = self.dut.bcm_of(port)
        end = _t.time() + timeout
        while _t.time() < end:
            out = self.bsh.cmd(f"port {bcm}") or ""
            if "ARL" in out:
                return True
            _t.sleep(0.5)
        # Self-heal: on some images portsorch unreliably enables the bridge port learn/admin along with oper-up
        # -- the chip learn-mode stays at 0 (SLF drops immediately, ps ops column = D), and all L2 data plane (forwarding/flooding/
        # learning) on that port is dead. Diagnostic key: learnmode value bit0=hardware learning, bit2=forwarding.
        # On most images the wait succeeds normally and never reaches here, so behavior does not regress.
        _log.warning("port %s chip learn not ARL after %ss; self-healing via 'port %s LeaRN=5' "
                     "(portsorch did not enable bridge-port learning on this image)",
                     port.name, timeout, bcm)
        self.bsh.cmd(f"port {bcm} LeaRN=5")
        out = self.bsh.cmd(f"port {bcm}") or ""
        if "ARL" in out:
            return True
        _log.warning("port %s chip learn still not ARL after self-heal; "
                     "dynamic learning will not happen", port.name)
        return False

    def _wait_oper_up(self, port, timeout=15):
        """Poll APPL_DB for this port's oper_status=up (a loopback port's link should come up when lb is set)."""
        import time as _t
        end = _t.time() + timeout
        while _t.time() < end:
            r = self.bsh.sh.run(
                f"sonic-db-cli APPL_DB hget 'PORT_TABLE:{port.name}' oper_status",
                check=False)
            if (r.out or "").strip() == "up":
                return True
            _t.sleep(0.5)
        _log.warning("port %s not oper-up %ss after loopback set (frames may drop)",
                     port.name, timeout)
        return False

    def disable(self, port):
        bcm = self.dut.bcm_of(port)
        _, discard = self._on.get(port, (None, False))
        if discard:
            self.bsh.cmd(f"port {bcm} discard=none")
        self.bsh.cmd(f"port {bcm} lb=none")
        _log.info("loopback OFF %s (bcm=%s)", port.name, bcm)
        self._on.pop(port, None)

    def enable_flood_safe(self, port, isolate_vid):
        """**Flood-safe loopback** (asymmetric VLAN/PVID loop break).

        To test "whether flooding reaches the port-under-test" its egress counter must be readable -> it must loop (oper-up); but a
        looped port hit by flooding self-replicates into a storm via egress->loopback->re-ingress->re-flood. This method: loop (lb=mac) +
        change the port's **ingress PVID** to an isolate VLAN (isolate_vid). The port still egresses untagged into the original VLAN
        (receives the flood, TX measurable), but its **loopback re-ingressing frames land in isolate_vid** (neither the injection port nor
        other ports-under-test are in that VLAN) -> no member to flood to, so it **terminates** -> loop broken, zero storm.

        Key constraint: **each port-under-test must use a different isolate_vid**, otherwise two ports-under-test flood each other within the same isolate VLAN and loop again.
        The injection port uses a plain enable() (its re-ingress floods per the original PVID to each port-under-test, each terminating at its own PVID, so the injection port does not amplify either).

        In parallel mode isolate_vid is offset per worker (cases still pass the literals 3990-3993; the two workers actually stay disjoint).
        """
        from . import worker as _W
        isolate_vid = _W.remap_vid(isolate_vid)
        bcm = self.dut.bcm_of(port)
        out = self.bsh.cmd(f"pvlan show {bcm}")          # "Port cdN default VLAN is X"
        import re as _re
        m = _re.search(r"default VLAN is (\d+)", out or "")
        orig = m.group(1) if m else str(self.dut.profile.get("default_vlan", 1000)
                                        if hasattr(self.dut, "profile") else 1000)
        self.bsh.cmd(f"vlan create {isolate_vid}")
        self.bsh.cmd(f"port {bcm} lb={self.mode}")   # use the profile's loopback_mode (mac/phy), do not hardcode
        self.bsh.cmd(f"pvlan set {bcm} {isolate_vid}")   # re-ingressing frame -> isolate VLAN -> terminates
        self._wait_oper_up(port)                     # link-up jitter same as enable(); wait for up before returning
        self._on[port] = ("mac", False)
        self._touched = True
        self._flood_safe[port] = (bcm, isolate_vid, orig)
        _log.info("flood-safe loopback ON %s (bcm=%s, ingress PVID %s->%s)",
                  port.name, bcm, orig, isolate_vid)

    def isolate_pvid(self, port, isolate_vid):
        """Temporarily switch the ingress PVID of an **already-looped** port to an isolate VLAN (without changing the loopback or the egress membership).

        Used for "two-phase" L2 forwarding cases: first learn/program the FDB in the original VLAN (port PVID=original VLAN), then
        switch to the isolate VLAN for **directed/flood measurement**. Root cause: **any frame forwarded to a looped port (directed dst->this port,
        or flooded) egresses, loops back, and re-ingresses to be forwarded/flooded again -> a self-loop storm** (same-port filtering can't break this loop).
        After switching the isolate PVID, the port-under-test's loopback re-ingressing frames land in the isolate VLAN, find no destination, and terminate ->
        loop broken, TX still measurable. The port-under-test's egress membership and FDB entries in the original VLAN are unaffected by the PVID, so directed forwarding to it works as usual."""
        from . import worker as _W
        isolate_vid = _W.remap_vid(isolate_vid)
        bcm = self.dut.bcm_of(port)
        if self.cli is not None and self.cli.is_switchport_os():
            # switchport-OS: a chip-level pvlan set would remove the access port from the test VLAN's untagged egress membership
            # (PVID is coupled with access membership), and would fight orchagent's writeback from CONFIG_DB -> the reference port receives no
            # forwarding, TX=0. Instead use discard=all to break the re-ingress loop: forwarded frames egress as usual (TX counts), the port's re-ingressing frames are dropped,
            # and egress membership/FDB are unaffected. iso=None marks the discard mode.
            self.bsh.cmd(f"port {bcm} discard=all")
            self._flood_safe[port] = (bcm, None, None)
            _log.info("isolate via discard=all %s (switchport OS; break re-ingress, membership intact)", port.name)
            return
        out = self.bsh.cmd(f"pvlan show {bcm}")
        import re as _re
        m = _re.search(r"default VLAN is (\d+)", out or "")
        orig = m.group(1) if m else str(self.dut.profile.get("default_vlan", 1000)
                                        if hasattr(self.dut, "profile") else 1000)
        self.bsh.cmd(f"vlan create {isolate_vid}")
        self.bsh.cmd(f"pvlan set {bcm} {isolate_vid}")
        self._flood_safe[port] = (bcm, isolate_vid, orig)
        _log.info("isolate ingress PVID %s %s->%s (break directed/flood loop)", port.name, orig, isolate_vid)

    def restore_pvid(self, port):
        """Restore the PVID changed by isolate_pvid + destroy the isolate VLAN (does not turn off loopback; that is managed by the caller/teardown)."""
        info = self._flood_safe.pop(port, None)
        if info:
            bcm, iso, orig = info
            try:
                if iso is None:      # discard mode (switchport OS): just turn off discard, PVID/VLAN untouched
                    self.bsh.cmd(f"port {bcm} discard=none")
                else:
                    self.bsh.cmd(f"pvlan set {bcm} {orig}")
                    self.bsh.cmd(f"vlan destroy {iso}")
            except Exception as e:  # noqa: BLE001
                _log.warning("failed to restore PVID/discard %s: %s", port.name, e)

    def disable_flood_safe(self, port):
        """Turn off flood-safe loopback: restore PVID + destroy isolate VLAN + turn off loopback."""
        info = self._flood_safe.pop(port, None)
        if info:
            bcm, iso, orig = info
            try:
                self.bsh.cmd(f"pvlan set {bcm} {orig}")
                self.bsh.cmd(f"vlan destroy {iso}")
            except Exception as e:  # noqa: BLE001
                _log.warning("failed to restore flood-safe PVID %s: %s", port.name, e)
        self.disable(port)

    def cleanup(self):
        for p in list(self._flood_safe):
            try:
                self.disable_flood_safe(p)
            except Exception as e:  # noqa: BLE001
                _log.warning("failed to disable flood-safe loopback %s: %s", p.name, e)
        for p in list(self._on):
            try:
                self.disable(p)
            except Exception as e:  # noqa: BLE001
                _log.warning("failed to disable loopback %s: %s", p.name, e)

    def force_clear_all(self):
        """Session fallback: **does not rely on the self._on tracking table**; turns off loopback on all ports directly.

        cleanup() can only turn off loopbacks this manager has tracked; but loopbacks opened manually via bcmcmd diag, left on
        because a case errored out and skipped finally, or even leaked from a previous pytest run, are not in the tracking table.
        These residuals accumulate -- multiple ports looped simultaneously + broadcast/unknown unicast = a self-looping flood storm,
        which eventually degrades the device's L2 state (FDB learning). So force a full clear at both session start and end,
        and flush the dynamic FDB, to guarantee each run starts from a clean loopback baseline and leaves no residual for the next run on exit.

        Returns the list of ports whose loopback was actually cleared this time (tracked _on + flood_safe, excluding held ports auto-reopened after clearing),
        so the caller can event-drive a wait for these ports to go oper-down (see wait_cleared_down, replacing a blind fixed settle).
        """
        cleared = [p for p in set(list(self._on) + list(self._flood_safe))
                   if p not in self._held]
        # First restore the PVID changed by flood-safe loopback (otherwise the port-under-test's PVID stays in the isolate VLAN and pollutes later cases' ingress classification)
        for p, (bcm, iso, orig) in list(self._flood_safe.items()):
            try:
                self.bsh.cmd(f"pvlan set {bcm} {orig}")
                self.bsh.cmd(f"vlan destroy {iso}")
            except Exception:  # noqa: BLE001
                pass
        self._flood_safe.clear()
        try:
            # In parallel mode clear only this worker's port block -- `port all lb=none` would tear down the other worker's in-test loopback.
            pbm = getattr(self.bsh, "worker_pbm", None)
            self.bsh.cmd(f"port {pbm or 'all'} lb=none")   # diag shell: turn off MAC/PHY loopback
        except Exception as e:  # noqa: BLE001
            _log.warning("force_clear_all loopback failed: %s", e)
        self._on.clear()
        # Group-level held loopbacks: auto-reopen after clearing all (a single cheap bcmcmd), so the per-case fallback does not tear down the group's shared loopback environment.
        for p, mode in self._held.items():
            try:
                self._set(p, mode)
                self._on[p] = (mode, False)
            except Exception:  # noqa: BLE001
                pass
        return cleared

    def wait_cleared_down(self, ports, timeout=4):
        """Event-drive a wait for a group of ports just cleared of loopback to go oper-down (APPL_DB) -- this is the last link in the
        control-plane chain after clearing loopback (SDK linkscan->syncd->portsorch); once it lands, this round's loopback events are drained.
        Replaces the fixed sleep(2) in the per-test fallback: normally lands in <1s, on timeout only warns (the next case's
        traffic fixture still has a defensive pre-clean fallback)."""
        import time as _t
        end = _t.time() + timeout
        pending = {p.name for p in ports}
        while pending and _t.time() < end:
            for name in list(pending):
                r = self.bsh.sh.run(
                    f"sonic-db-cli APPL_DB hget 'PORT_TABLE:{name}' oper_status",
                    check=False)
                if (r.out or "").strip() != "up":
                    pending.discard(name)
            if pending:
                _t.sleep(0.3)
        if pending:
            _log.warning("ports %s still oper-up %ss after loopback clear", pending, timeout)
