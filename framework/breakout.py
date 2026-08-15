"""DPB (Dynamic Port Breakout) driver -- split/merge + subport-name derivation + wait for port rebuild.

Key facts:
- Subport naming = Ethernet<base + lane_offset> (lane-offset convention, sonic-config-engine
  BreakoutCfg.get_config): Ethernet88 split by 4 (8 lanes) -> 88/90/92/94.
- The `-f` semantics of breakout may be inverted across images -- on some images **omitting -f is
  what auto-clears dependencies**, while passing -f instead reports Dependencies Exist; the
  community build has normal semantics. Driver strategy: try without -f first; if it reports a
  dependency, retry with -f -- covering both semantics.
- `-l` requires /etc/sonic/port_breakout_config_db.json (usually absent from the image); the driver
  does not use it.
- Split/merge deletes and recreates port objects (CONFIG_DB/ASIC_DB/netdev/chip logical ports), so
  after the operation you must call chiptab.invalidate() and wait for the rebuild to finish before
  asserting.
- After a merge the system may auto-recreate the default PORT_QOS_MAP|X and INTERFACE|X entries (by
  design).
"""
import json
import re
import time

from . import log

_log = log.get("breakout")


def platform_modes(dut, port_name):
    """breakout_modes declared for this port in platform.json (dict mode->alias list); returns {} if no file."""
    path = f"/usr/share/sonic/device/{dut.platform}/platform.json"
    r = dut.sh.run(f"cat {path} 2>/dev/null")
    if not (r.out or "").strip():
        return {}
    try:
        data = json.loads(r.out)
    except ValueError:
        return {}
    return (data.get("interfaces", {}).get(port_name, {}) or {}).get("breakout_modes", {})


def parse_mode(mode):
    """'4x200G[100G]' -> (4, '200G'); '1x800G' -> (1, '800G')."""
    m = re.match(r"^(\d+)x(\d+G)", mode)
    if not m:
        raise ValueError(f"unparsable breakout mode: {mode}")
    return int(m.group(1)), m.group(2)


def expect_subports(parent, parent_lanes, mode):
    """Derive subport names and per-port lanes by the lane-offset convention. Returns [(name, lanes_list, speed_str)]."""
    n, spd = parse_mode(mode)
    lanes = [int(x) for x in str(parent_lanes).split(",") if x.strip()]
    per = len(lanes) // n
    base = int(re.search(r"(\d+)$", parent).group(1))
    out = []
    for i in range(n):
        out.append((f"Ethernet{base + i * per}",
                    lanes[i * per:(i + 1) * per],
                    str(int(spd[:-1]) * 1000)))
    return out


class BreakoutDriver:
    def __init__(self, cli, dut, chip=None):
        self.cli, self.dut, self.chip = cli, dut, chip

    def current_mode(self, port):
        h = self.cli.db_hgetall("CONFIG_DB", f"BREAKOUT_CFG|{port}") or {}
        return h.get("brkout_mode")

    def port_entry(self, port):
        return self.cli.db_hgetall("CONFIG_DB", f"PORT|{port}") or {}

    def _drive(self, port, mode):
        """Run the breakout command, adapting to -f semantics (covers both normal and inverted SONiC). Returns (rc, text).

        `echo y |` prefix: -y does not always cover the breakout_warnUser_extraTables
        "Do you wish to Continue? [y/N]" prompt (which appears when the port carries extra tables
        such as PORT_QOS_MAP/BUFFER_PG); in a non-TTY it defaults to N and fails outright."""
        base = f"echo y | config interface breakout {port} '{mode}' -y"
        r = self.cli.run(base, timeout=180)
        rc, text = r.rc, (r.out or "") + (r.err or "")
        if rc != 0 and re.search(r"[Dd]ependenc", text):
            _log.info("breakout w/o -f hit dependencies; retrying with -f "
                      "(community semantics)")
            r = self.cli.run(base.replace(" -y", " -f -y"), timeout=180)
            rc, text = r.rc, (r.out or "") + (r.err or "")
        return rc, text

    def split(self, port, mode, timeout=90):
        """Split and wait for subports to appear in CONFIG_DB + APPL_DB PORT_TABLE to be ready.
        Returns dict: ok/text/subports/pre (pre-split PORT entry and mode)."""
        pre = {"mode": self.current_mode(port), "port": self.port_entry(port)}
        subs = expect_subports(port, pre["port"].get("lanes", ""), mode)
        rc, text = self._drive(port, mode)
        res = {"ok": rc == 0, "text": text[-400:], "subports": subs, "pre": pre}
        if rc != 0:
            _log.warning("breakout %s %s rejected: %s", port, mode, text[-200:])
            return res
        res["ok"] = self.wait_ports([n for n, _, _ in subs], timeout=timeout)
        if self.chip:
            self.chip.invalidate()
        return res

    def merge(self, port, mode, timeout=90):
        """Merge back to mode (usually the pre-split mode). Wait for the base port to return.

        On some platforms the two ports in the same cage form one breakout port group and must all
        be in the same mode; a single-port merge reports "Breakout port group {...} together". In
        that case, drive each group member listed in the error to the same mode."""
        rc, text = self._drive(port, mode)
        if rc != 0 and "port group" in text:
            peers = sorted(set(re.findall(r"Ethernet\d+", text)))
            _log.info("breakout port group %s: driving all members to %s",
                      peers, mode)
            for peer in peers:
                rc, text = self._drive(peer, mode)
        ok = rc == 0 and self.wait_ports([port], timeout=timeout)
        if self.chip:
            self.chip.invalidate()
        return {"ok": ok, "text": text[-400:]}

    def wait_ports(self, names, timeout=90, interval=2.0):
        """Wait for a set of ports: CONFIG_DB PORT entry present + APPL_DB PORT_TABLE present (portsyncd/orch done)."""
        end = time.time() + timeout
        while time.time() < end:
            cfg = all(self.cli.db_hgetall("CONFIG_DB", f"PORT|{n}") for n in names)
            app = all(self.cli.db_hgetall("APPL_DB", f"PORT_TABLE:{n}") for n in names)
            if cfg and app:
                return True
            time.sleep(interval)
        _log.warning("wait_ports timeout: %s", names)
        return False

    def chip_loopback(self, port_name, on=True):
        """Set MAC loopback by logical port (test fixture, an allowed chip write -- same nature as bcmcmd lb=).

        Must go through lt: the 2nd+ subport of a DPB may be a ghost port (no cd/dport diagnostic
        name), so `port <name> lb=mac` has nothing to reference; only PC_PORT.LOOPBACK_MODE is
        reachable by PORT_ID."""
        if not self.chip or not self.chip.available():
            raise RuntimeError("chip lt diag unavailable; cannot loopback subport")
        pid = self.chip.port_id(port_name)
        mode = "PC_LPBK_MAC" if on else "PC_LPBK_NONE"
        self.chip.cmd(f"lt PC_PORT update PORT_ID={pid} LOOPBACK_MODE={mode}")
        return pid

    def gone(self, names, timeout=60, interval=2.0):
        """Wait for a set of ports to disappear from CONFIG_DB (subport reclaimed after merge)."""
        end = time.time() + timeout
        while time.time() < end:
            if not any(self.cli.db_hgetall("CONFIG_DB", f"PORT|{n}") for n in names):
                return True
            time.sleep(interval)
        return False
