"""platform_fault injection primitives: BMC traffic redirect / pmon daemon control / platform state observation.

Safety discipline:
    - Every injector implements restore(); tests must restore in a finally block;
    - BmcRedirect only adds rules it can delete precisely (bookkeeping style), and
      re-checks with iptables -S after restore;
    - During redirection all pushes (POST) to 240.1.1.1:8080 land on the mock and never
      touch the real BMC.

Source: injection scenarios in sonic-buildimage
platform/vendor-x/sonic-platform-modules-vendor-b/tests/ (fault_scenarios S1-S9).
"""
import json
import re
import time

from framework import log

_log = log.get("pmon_fault")

BMC_IP = "240.1.1.1"
BMC_PORT = 8080
SYNC_UNIT = "vendor-vendor-b-bmc2cpu_cache_sync.service"
SYNC_PROC = "bmc2cpu_cache_sync"
PMON_DAEMONS = ("psud", "thermalctld", "syseepromd", "xcvrd")
STATE_DB_ID = 6


class BmcRedirect:
    """Redirect DUT-to-real-BMC traffic to the local mock (or inject refuse/drop)."""

    def __init__(self, sh, mock_port):
        self.sh = sh
        self.mock_port = mock_port
        self._applied = []      # [(table, rule_args)]

    def _add(self, table, rule):
        cmd = "iptables %s -A %s" % (("-t %s" % table) if table else "", rule)
        r = self.sh.run("sudo " + cmd, check=True)
        self._applied.append((table, rule))
        _log.info("iptables + %s", rule)
        return r

    def to_mock(self):
        """DNAT to the local mock: nat OUTPUT REDIRECT (also applies to the host-network pmon container)."""
        self._add("nat", "OUTPUT -d %s -p tcp --dport %d -j REDIRECT --to-ports %d"
                  % (BMC_IP, BMC_PORT, self.mock_port))
        return self

    def refuse(self):
        """Connection refused (REJECT on the BMC port, simulating the service being down)."""
        self._add(None, "OUTPUT -d %s -p tcp --dport %d -j REJECT --reject-with tcp-reset"
                  % (BMC_IP, BMC_PORT))
        return self

    def blackhole(self):
        """Silent drop (simulate a half-started BMC with no TCP response -> triggers the timeout path)."""
        self._add(None, "OUTPUT -d %s -p tcp --dport %d -j DROP"
                  % (BMC_IP, BMC_PORT))
        return self

    def restore(self):
        for table, rule in reversed(self._applied):
            cmd = "iptables %s -D %s" % (("-t %s" % table) if table else "", rule)
            self.sh.run("sudo " + cmd)
        self._applied = []
        leftover = self.sh.run(
            "sudo iptables -S OUTPUT; sudo iptables -t nat -S OUTPUT").out
        assert BMC_IP not in leftover, \
            "iptables cleanup incomplete, manual check required: %s" % leftover
        _log.info("iptables restored")


class PmonCtl:
    """Sync daemon / pmon container / supervisord control and observation."""

    def __init__(self, sh):
        self.sh = sh

    # ---------------- Sync daemon (host side) ----------------

    def has_sync_unit(self):
        """Whether this platform actually uses the BMC->CPU cache sync daemon. The unit
        must exist **and be enabled** to count -- if disabled/masked (some platforms read
        sensors/fans/PSU directly over i2c, so the daemon is unneeded and the vendor
        deliberately leaves it off), this platform does not source data via the BMC cache;
        treat it as a "non-bmc-cache platform" so the upper-layer _require skips and does
        not misjudge "daemon not running" as a defect. `systemctl list-unit-files` line
        format: <unit> <STATE> <preset>."""
        r = self.sh.run("systemctl list-unit-files %s" % SYNC_UNIT)
        for line in (r.out or "").splitlines():
            if SYNC_UNIT in line:
                toks = line.split()
                return len(toks) >= 2 and toks[1] == "enabled"
        return False

    def sync_props(self):
        r = self.sh.run(
            "systemctl show %s -p ActiveState,SubState,ExecMainStatus,NRestarts"
            % SYNC_UNIT)
        return dict(line.split("=", 1) for line in r.out.splitlines() if "=" in line)

    def sync_proc_alive(self):
        return self.sh.run("pgrep -f %s" % SYNC_PROC).ok

    def stop_sync(self):
        self.sh.run("sudo systemctl stop %s" % SYNC_UNIT, check=True)

    def start_sync(self):
        self.sh.run("sudo systemctl restart %s" % SYNC_UNIT, check=True)

    def crash_sync(self):
        """Simulate a crash (kill -9 the main process rather than systemctl stop) -- to
        observe the real RemainAfterExit x Restart behavior."""
        self.sh.run("sudo pkill -9 -f %s" % SYNC_PROC)

    # ---------------- pmon / supervisord ----------------

    def supervisor_states(self):
        r = self.sh.run("supervisorctl status", container="pmon", timeout=60)
        states = {}
        for line in r.out.splitlines():
            cols = line.split()
            if len(cols) >= 2:
                states[cols[0]] = cols[1]
        return states

    def restart_pmon(self, wait=240):
        # pmon.service may report rc=1 (Job failed) at the systemd layer due to an internal
        # daemon crash loop, but the container and supervisord still come up -- do not treat
        # the systemd error as fatal; let wait_pmon_ready observe the real daemon state
        # (returns thermalctld's terminal state when it is crash-looping).
        self.sh.run("sudo systemctl reset-failed pmon 2>/dev/null")
        self.sh.run("sudo systemctl restart pmon", check=False, timeout=180)
        return self.wait_pmon_ready(wait)

    def wait_pmon_ready(self, timeout=240):
        """Wait for psud/thermalctld to reach a stable state (RUNNING or terminal FATAL/EXITED)."""
        settled = ("RUNNING", "FATAL", "EXITED", "BACKOFF")
        deadline = time.time() + timeout
        states = {}
        while time.time() < deadline:
            states = self.supervisor_states()
            watched = {d: states.get(d) for d in ("psud", "thermalctld")}
            if watched and all(watched.values()) \
                    and all(s in settled for s in watched.values()):
                return states
            time.sleep(5)
        return states

    def journal_tail(self, unit=SYNC_UNIT, lines=40):
        return self.sh.run(
            "sudo journalctl -u %s -b --no-pager -n %d" % (unit, lines)).out


class PlatformState:
    """Cache file / STATE_DB / show output observation (all read-only)."""

    def __init__(self, sh):
        self.sh = sh
        self._platform = None

    def platform(self):
        if self._platform is None:
            r = self.sh.run(
                "sonic-cfggen -d -v DEVICE_METADATA.localhost.platform 2>/dev/null"
                " || grep onie_platform /host/machine.conf | cut -d= -f2")
            self._platform = r.out.strip().splitlines()[0].strip() if r.out.strip() else ""
        return self._platform

    def cache_path(self):
        return "/usr/share/sonic/device/%s/bmc_cache" % self.platform()

    def has_cache_arch(self):
        return self.sh.run("test -f %s" % self.cache_path()).ok

    def read_cache(self):
        r = self.sh.run("sudo cat %s" % self.cache_path())
        try:
            return json.loads(r.out)
        except ValueError:
            return None

    def cache_age_s(self):
        r = self.sh.run("echo $(( $(date +%s) - $(stat -c %Y " +
                        self.cache_path() + ") ))")
        try:
            return int(r.out.strip())
        except ValueError:
            return None

    def wait_cache_fresh(self, max_wait=180, fresh_s=45):
        """Poll until the cache mtime refreshes to within fresh_s. A real BMC can take
        a dozen-plus seconds per endpoint and 40~90s per sync cycle, so recovery-style
        waits must be event-driven rather than a fixed sleep.
        Returns the final age (None = file unreadable)."""
        deadline = time.time() + max_wait
        age = self.cache_age_s()
        while time.time() < deadline:
            age = self.cache_age_s()
            if age is not None and age <= fresh_s:
                return age
            time.sleep(5)
        return age

    # ---------------- STATE_DB ----------------

    def db_keys(self, pattern):
        r = self.sh.run("redis-cli -n %d --raw keys '%s'" % (STATE_DB_ID, pattern))
        return [k for k in r.out.splitlines() if k.strip()]

    def db_row(self, key):
        r = self.sh.run('redis-cli -n %d --raw hgetall "%s"' % (STATE_DB_ID, key))
        lines = r.out.splitlines()
        return dict(zip(lines[0::2], lines[1::2]))

    def db_table(self, table):
        return {k: self.db_row(k) for k in self.db_keys("%s|*" % table)}

    # ---------------- show ----------------

    def show(self, what):
        return self.sh.run("show platform %s" % what, timeout=60).out

    def psu_detail_blank(self):
        """psud 1.0 fallback signature: rows with presence=true missing the model/voltage fields."""
        blanks = []
        for key, row in self.db_table("PSU_INFO").items():
            if row.get("presence") == "true" and (
                    "model" not in row or "voltage" not in row):
                blanks.append(key)
        return blanks

    def baseline_problems(self, stale_s=120):
        """S0 baseline gate: returns a list of problems (empty = healthy). Used to re-check
        before an injection test exits. stale_s defaults to 120s: when the real BMC is slow
        a sync cycle can reach 90s, so the threshold must keep margin, otherwise "slow but
        normal" is misjudged as an outage."""
        problems = []
        states = PmonCtl(self.sh).supervisor_states()
        for d in ("psud", "thermalctld"):
            if states.get(d) not in ("RUNNING", None):
                problems.append("pmon %s state=%s" % (d, states.get(d)))
        if "Error" in self.show("psustatus"):
            problems.append("psustatus reports error")
        if self.psu_detail_blank():
            problems.append("PSU detail fields missing (1.0 fallback signature)")
        if self.has_cache_arch():
            age = self.cache_age_s()
            if age is None or age > stale_s:
                problems.append("bmc_cache stale (age=%ss)" % age)
        return problems


def wait_s(seconds, why=""):
    _log.info("wait %ss %s", seconds, why)
    time.sleep(seconds)
