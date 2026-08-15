"""SONiC command-line wrappers.

The arrange phase uniformly goes through the real CLI (the object under test itself),
while the assert phase queries the DB.
Covers: config / show / sonic-db-cli / vtysh / bcmcmd, plus common feature-provisioning helpers.
"""
import ast
import json
import re
import time

from . import log, shell

_log = log.get("cli")


class Cli:
    # ACL table-type mapping across images: SONiC's `acl-table add -t` only accepts concrete types
    # like L3V4/L3V6/L2. Test cases follow the community-edition generic name `L3`, which must be
    # mapped to `L3V4`.
    _ACL_TYPE_MAP = {"L3": "L3V4", "L3V4": "L3V4", "L3V6": "L3V6",
                     "L2": "L2", "L2L3MIX": "L2L3MIX"}

    def __init__(self, sh: shell.Shell, syncd="syncd"):
        self.sh = sh
        self.syncd = syncd
        self._bridged = set()   # ports converted to bridge (L2) via link-mode on the customized OS; restore back to route at session end

    # ---- primitives ----
    def _fixup(self, args):
        """Adapt CLI differences across SONiC versions + transparently switch L2/L3 on the customized OS. Test cases stay unaware of device differences.

        (1) `vlan member add -u`: newer images need `-m untagged`; the customized OS access mode carries no flag. Rewritten transparently.
        (2) On the customized OS, run `link-mode <port> bridge` to switch to L2 before `vlan member add` (ports default to L3 routed ports).
        (3) On the customized OS, run `link-mode <port> route` before `interface ip add <Ethernet port>`: earlier hygiene/other
           cases may have switched the port to bridge (an access member), so a direct ip add reports `is configured as a member of
           vlan`. Switching back to route makes ip add succeed (standard SONiC ports default to L2, and ip add auto-detaches from the bridge, so this is not triggered).
        (4) ACL table CLI: SONiC uses `acl-table add -s <stage> -t <type> -p` (community edition is `acl add table
           <name> <type> -s -p`), and `acl remove table` -> `acl-table del`. Probe-gated; not rewritten on community edition.
        (5) `interface ip remove` -> `interface ip del`: the SONiC subcommand name is del. Probe-gated.
        """
        # (3) Switch to route before creating an L3 port (only on the customized OS + physical ports). `interface vrf bind` is the same:
        #    the customized OS reports "The mode of interface X is not Route! Please set correctly before bind Vrf.",
        #    so switch to route before bind too.
        #    WARNING: you MUST short-circuit on the prefix FIRST, then call is_switchport_os() -- it internally probes
        #    `interface link-mode --help` via config(); unconditionally calling it before every command would make _fixup recurse infinitely.
        if args.startswith(("interface ip add", "interface vrf bind")):
            parts = args.split()
            if (len(parts) >= 4 and parts[3].startswith("Ethernet")
                    and self.is_switchport_os()):
                self.restore_port_l3(parts[3])
        # (5) ip remove -> ip del
        if args.startswith("interface ip remove") and self._ip_del_cli():
            args = args.replace("interface ip remove", "interface ip del", 1)
        # (6) mirror_session remove -> del (SONiC uses a different subcommand name; community edition keeps native remove and is not rewritten). Probe-gated, same pattern as (5).
        if args.startswith("mirror_session remove") and self._mirror_del_cli():
            args = args.replace("mirror_session remove", "mirror_session del", 1)
        # (7) span add direction argument: community edition is a positional argument (<name> <dst> <src> <rx|tx|both>), SONiC
        #    uses a `-d` option. Probe-gated; when the last token is a direction word, convert it to -d.
        if args.startswith("mirror_session span add") and self._span_dir_opt():
            toks = args.split()
            if toks and toks[-1] in ("rx", "tx", "both"):
                args = " ".join(toks[:-1]) + f" -d {toks[-1]}"
        # (4) ACL table CLI rewrite
        if args.startswith("acl add table") and self._acl_table_cli():
            args = self._rewrite_acl_add(args)
        elif args.startswith("acl remove table") and self._acl_table_cli():
            toks = args.split()
            if len(toks) > 3:
                args = f"acl-table del {toks[3]}"
        # (1)(2) vlan member add
        if args.startswith("vlan member add"):
            # (8) Return to the default Vlan1 (SONiC): the product CLI REFUSES `member add` on Vlan1 (usage rc=2),
            #    the only path back is `switchport mode access` (implicitly returns to the default VLAN).
            #    Orphan ports (already access but not in Vlan1, leftover from an undo that once failed silently) switch to hybrid first, then back to
            #    access to force the return.
            nums = [t for t in args.split() if t.isdigit()]
            if nums and nums[0] == "1" and self.is_switchport_os():
                toks = [t for t in args.split()[3:] if not t.startswith("-")]
                pname = toks[-1] if toks else ""
                if pname.startswith("Ethernet"):
                    lm = (self.db_hgetall("CONFIG_DB", f"PORT|{pname}") or {}).get("link_mode")
                    home = self.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan1|{pname}")
                    if lm == "access" and home:
                        # Already home: SONiC refuses duplicate configuration, so issue a harmless help (rc=0) instead
                        return "switchport mode -h"
                    # Returning home goes through the full route->bridge cycle (the authoritative primitive, see _restore_bridge_home);
                    # the real work happens as a side effect, and we return a harmless help to finish.
                    self._restore_bridge_home(pname)
                    return "switchport mode -h"
            untagged_intent = " -u " in f" {args} " or "untagged" in args
            if self.is_switchport_os():
                self._ensure_l2_for_member_add(args)   # customized OS: switch the target port to bridge before adding to a VLAN
                if not untagged_intent:
                    # Community semantics "no -u = tagged": on the customized OS a tagged member requires the port's switchport
                    # mode to be hybrid (`-m tagged` is rejected under access/trunk), and it must be an explicit `-m tagged`
                    # (default is untagged).
                    toks = [t for t in args.split()[3:] if not t.startswith("-")]
                    if len(toks) >= 2:
                        self.config_raw(f"switchport mode hybrid {toks[-1]}")
                        # Switching to hybrid makes the _bridged cache (which records access/bridge state) stale: if not cleared, a later
                        # untagged case's ensure_port_l2 short-circuits on a cache hit and skips the access return,
                        # leaving the port in hybrid -> untagged frames are not forwarded.
                        self._bridged.discard(toks[-1])
                    args = args.replace("vlan member add ", "vlan member add -m tagged ", 1)
            if " -u " in f" {args} ":
                if self.is_switchport_os():
                    # Customized OS: -u is an untagged INTENT signal (vlan_untagged_flag returns -u); the actual flag
                    # on the real CLI follows the port mode: access ports drop the flag (carrying it is rejected); hybrid/trunk ports
                    # must use an explicit `-m untagged` (no flag is rejected).
                    toks = [t for t in args.split()[3:] if not t.startswith("-")]
                    pname = toks[-1] if len(toks) >= 2 else ""
                    lm = (self.db_hgetall("CONFIG_DB", f"PORT|{pname}") or {}).get("link_mode", "")
                    if lm in ("hybrid", "trunk"):
                        args = args.replace(" -u ", " -m untagged ", 1)
                    elif self._stp_locked() and toks and toks[0].isdigit():
                        # When STP|GLOBAL=enable cannot be turned off, an access port's member add implicit
                        # "leave Vlan1 = delete last member" is rejected with "cause:stp" -> take the hybrid ladder
                        # (keep the Vlan1 member, zero deletions throughout). Side effect done,
                        # return a harmless help to finish (same pattern as the Vlan1 return path above).
                        self._hybrid_ladder_add(toks[0], pname)
                        return "switchport mode -h"
                    else:
                        args = args.replace(" -u ", " ", 1)
                else:
                    flag = self.vlan_untagged_flag()
                    if flag == "-m untagged":
                        args = args.replace(" -u ", " -m untagged ", 1)
                    # Older -u images: keep -u as is
        # (9) member del on STP-gated models: hybrid-ladder ports must first return pvid to 1 before deletion (a member of the
        #    VLAN that pvid points to cannot be deleted); after deletion, switchport access returns to Vlan1. The del of Vlan1 (the berth) itself is not intercepted
        #    (the CLI valid range 2~4094 self-rejects; the caller ignores it by rc, so the original semantics are unchanged).
        if args.startswith("vlan member del") and self.is_switchport_os() \
                and self._stp_locked():
            toks = [t for t in args.split()[3:] if not t.startswith("-")]
            if len(toks) >= 2 and toks[0].isdigit() and toks[0] != "1" \
                    and toks[-1].startswith("Ethernet"):
                lm = (self.db_hgetall("CONFIG_DB", f"PORT|{toks[-1]}") or {}).get("link_mode", "")
                if lm in ("hybrid", "trunk"):
                    self._hybrid_ladder_del(toks[0], toks[-1])
                    return "switchport mode -h"
        return args

    def _stp_locked(self):
        """When factory STP|GLOBAL=enable and the CLI gate + GCU lacks a YANG model so no config path can turn it off,
        an access port's VLAN move is always rejected with "cause:stp" and must take the hybrid ladder. Cached probe."""
        if getattr(self, "_stplock", None) is None:
            self._stplock = ((self.db_hgetall("CONFIG_DB", "STP|GLOBAL") or {})
                             .get("enabled") == "enable")
        return self._stplock

    def _hybrid_ladder_add(self, vid, pname):
        """Ladder into the test VLAN on STP-gated models:
        switchport mode hybrid (keep the Vlan1 member) -> vlan member add -m untagged <vid>
        -> interface pvid <port> <vid>. No member deletion throughout, so the STP gate is not triggered.
        Internal commands go directly through sh.run, BYPASSING _fixup (re-entering member add would trigger ensure_port_l2
        and pull the port back to access, destroying the ladder). Returns whether it landed."""
        self.sh.run(f"config switchport mode hybrid {pname}", check=False)
        self._bridged.discard(pname)     # mode is no longer access, invalidate the L2 return cache
        self.sh.run(f"config vlan member add -m untagged {vid} {pname}", check=False)
        ok = False
        for _ in range(5):
            if self.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|{pname}"):
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            _log.warning("hybrid ladder: member add Vlan%s %s did not land", vid, pname)
            return False
        self.sh.run(f"config interface pvid {pname} {vid}", check=False)
        for _ in range(5):
            if (self.db_hgetall("CONFIG_DB", f"PORT|{pname}") or {}).get("pvid") == str(vid):
                return True
            time.sleep(0.4)
        _log.warning("hybrid ladder: pvid of %s not holding at %s", pname, vid)
        return False

    def _hybrid_ladder_del(self, vid, pname):
        """Ladder teardown: point pvid back to the port's REMAINING member VLAN first (the berth is not necessarily Vlan1; pvid must land on
        a member VLAN, and hardcoding 1 would fail on heterogeneous berths)
        -> delete the test VLAN member (the home VLAN is still present = not the last member, so the STP gate lets it through) -> switchport mode
        access to return home (the product automatically returns the port to its original untagged home VLAN)."""
        others = [k.split("|")[1].replace("Vlan", "")
                  for k in self.db_keys("CONFIG_DB", f"VLAN_MEMBER|*|{pname}")
                  if k.split("|")[1] != f"Vlan{vid}"]
        if others:
            self.sh.run(f"config interface pvid {pname} {others[0]}", check=False)
        self.sh.run(f"config vlan member del {vid} {pname}", check=False)
        for _ in range(5):
            if not self.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{vid}|{pname}"):
                break
            time.sleep(0.5)
        self.sh.run(f"config switchport mode access {pname}", check=False)
        self._bridged.discard(pname)

    def _rewrite_acl_add(self, args):
        """`acl add table <name> <type> [-s <stage>] [-p <ports>]`
        -> `acl-table add <name> -s <stage|ingress> -t <MAP(type)> [-p <ports>]` (SONiC).
        When stage is not given, defaults to ingress (SONiC `-s` is required); type is mapped through _ACL_TYPE_MAP."""
        toks = args.split()[3:]   # skip "acl add table"
        if len(toks) < 2:
            return args
        name, typ = toks[0], toks[1]
        rest, stage, ports = toks[2:], "ingress", None
        i = 0
        while i < len(rest):
            t = rest[i]
            if t in ("-s", "--stage") and i + 1 < len(rest):
                stage = rest[i + 1]; i += 2; continue
            if t in ("-p", "--ports") and i + 1 < len(rest):
                ports = rest[i + 1]; i += 2; continue
            i += 1
        out = f"acl-table add {name} -s {stage} -t {self._ACL_TYPE_MAP.get(typ, typ)}"
        if ports:
            out += f" -p {ports}"
        return out

    def _acl_table_cli(self):
        """Whether this is the SONiC-style `config acl-table add` CLI (cached probe). Community edition lacks this command
        (returns No such command) -> False, keep native `acl add table`, no regression."""
        if getattr(self, "_acl_tbl", None) is None:
            r = self.sh.run("config acl-table add --help", check=False)
            self._acl_tbl = (r.rc == 0 and "acl" in (r.out or "").lower())
        return self._acl_tbl

    def _span_dir_opt(self):
        """Whether this image's span add direction is a `-d` option (SONiC) rather than a positional argument (cached probe)."""
        if getattr(self, "_spandir", None) is None:
            h = self.sh.run("config mirror_session span add --help", check=False).out or ""
            self._spandir = "--direction" in h
        return self._spandir

    def has_erspan_cli(self):
        """Whether this image has the ERSPAN session CLI (SONiC only has span/del, no erspan -- a structural gap,
        cases skip based on this; cached probe)."""
        if getattr(self, "_erspan", None) is None:
            r = self.sh.run("config mirror_session erspan --help", check=False)
            self._erspan = (r.rc == 0)
        return self._erspan

    def _mirror_del_cli(self):
        """Whether this image's mirror_session delete subcommand is del (cached probe). Rewrite only when del exists and remove
        does not (SONiC); community edition keeps native remove."""
        if getattr(self, "_mirdel", None) is None:
            d = self.sh.run("config mirror_session del --help", check=False)
            rm = self.sh.run("config mirror_session remove --help", check=False)
            self._mirdel = (d.rc == 0 and rm.rc != 0)
        return self._mirdel

    def _ip_del_cli(self):
        """Whether this image's `interface ip` delete subcommand is del (cached probe). Rewrite only when del exists and remove does not
        (SONiC); community edition keeps native remove, no regression."""
        if getattr(self, "_ipdel", None) is None:
            d = self.sh.run("config interface ip del --help", check=False)
            rm = self.sh.run("config interface ip remove --help", check=False)
            self._ipdel = (d.rc == 0 and rm.rc != 0)
        return self._ipdel

    def _ensure_l2_for_member_add(self, args):
        """Parse the target port from `vlan member add [-m mode] <vid> <port>` and ensure it is L2 (customized OS)."""
        toks = args.split()[3:]   # skip "vlan member add"
        pos, skip = [], False
        for t in toks:
            if skip:
                skip = False
                continue
            if t in ("-m", "--mode"):
                skip = True
                continue
            if t.startswith("-"):
                continue
            pos.append(t)
        if len(pos) >= 2:         # last token is the port (vid precedes it)
            self.ensure_port_l2(pos[-1])

    def _cmdline(self, args):
        # `__toplevel__ <cmd>`: a top-level command without the `config` prefix (e.g. pfcwd).
        # Background: `config pfcwd stop <port>` does not take a port argument and stays rc=0 even on error,
        # so the top-level `pfcwd stop <port>` is the correct entry point.
        if args.startswith("__toplevel__ "):
            return args[len("__toplevel__ "):]
        """Assemble the final shell command. Configuring an IP on an SVI in SONiC, when the interface already has a primary IP,
        pops an interactive confirmation ("The current primary address ... will be replaced, continue? [y/N]") -- under a non-TTY
        it fails falsely with rc=1. Feed y uniformly to `interface ip add Vlan*`,
        with no side effect on images/scenarios that have no prompt."""
        cmd = f"config {self._fixup(args)}"
        # Physical ports also pop this confirmation (with a leftover same-name primary IP, ip add aborts directly) -- relax it to all interface ip add.
        if args.startswith("interface ip add"):
            cmd = f"echo y | {cmd}"
        return cmd

    def config(self, args, check=True):
        """Run `config <args>`; raise on failure by default."""
        return self.sh.run(self._cmdline(args), check=check)

    def config_raw(self, args):
        """Non-raising variant, for negative/idempotency tests. Returns (rc, Result)."""
        r = self.sh.run(self._cmdline(args), check=False)
        return r.rc, r

    def show(self, args):
        return self.sh.run(f"show {args}", check=True).out

    def run(self, cmd, timeout=30):
        """Run an arbitrary command (any show/config path), non-raising, returns Result."""
        return self.sh.run(cmd, check=False, timeout=timeout)

    def vtysh(self, cmd, config=False):
        if config:
            body = "configure terminal\n" + cmd
            inner = "\n".join(f"-c '{l}'" for l in body.splitlines())
        else:
            inner = "\n".join(f"-c '{l}'" for l in cmd.splitlines())
        return self.sh.run("vtysh " + inner.replace("\n", " "), check=True).out

    def bcm(self, c):
        return self.sh.run(c, container=self.syncd).out  # see loopback for the bcmcmd '<c>' form

    # ---- DB ----
    def db(self, db, cmd):
        return self.sh.run(f"sonic-db-cli {db} {cmd}", check=True).out.strip()

    def db_hgetall(self, db, key):
        """The sonic-db-cli HGETALL output is a Python dict repr (single line); parse it with literal_eval.

        Note: a field value itself may contain EMBEDDED newlines (e.g. TRANSCEIVER_INFO's
        host_electrical_interface is multi-line placeholder text), in which case sonic-db-cli's
        dict repr spans multiple lines and literal_eval raises SyntaxError. The old implementation returned {} directly ->
        upper layers misjudged "STATE_DB is entirely empty". So when literal_eval fails,
        read back robustly via the DB connector as JSON instead of giving up."""
        out = self.sh.run(f"sonic-db-cli {db} HGETALL '{key}'", check=True).out.strip()
        if not out:
            return {}
        if out.startswith("{"):
            try:
                return ast.literal_eval(out)
            except (ValueError, SyntaxError):
                robust = self._db_hgetall_json(db, key)
                if robust is not None:
                    return robust
                return {}
        # also support the line-by-line field/value form
        toks = [l for l in out.splitlines() if l != ""]
        return dict(zip(toks[0::2], toks[1::2]))

    def _db_hgetall_json(self, db, key):
        """Fallback when literal_eval fails: read the whole hash via SonicV2Connector and JSON-serialize it
        (json correctly escapes newlines/tabs in values). Returns dict; returns None when the connector is unavailable."""
        script = (
            "import json,sys\n"
            "try:\n"
            "    from swsscommon.swsscommon import SonicV2Connector\n"
            "except Exception:\n"
            "    from swsssdk import SonicV2Connector\n"
            "c=SonicV2Connector(); c.connect(sys.argv[1])\n"
            "sys.stdout.write(json.dumps(c.get_all(sys.argv[1], sys.argv[2]) or {}))\n"
        )

        def _q(s):
            return "'" + str(s).replace("'", "'\\''") + "'"

        cmd = "python3 -c %s %s %s" % (_q(script), _q(db), _q(key))
        r = self.sh.run(cmd, check=False)
        try:
            return json.loads((r.out or "").strip() or "{}")
        except (ValueError, TypeError):
            return None

    def db_keys(self, db, pattern):
        out = self.sh.run(f"sonic-db-cli {db} KEYS '{pattern}'", check=True).out
        return [l for l in out.splitlines() if l]

    def db_hset(self, db, key, field, value):
        """Directly write a DB hash field: sonic-db-cli <db> HSET '<key>' <field> <value>.

        Used to bypass a CLI blocked by the image (some images block the crm CLI, where crm subcommands return rc=0
        yet write nothing): orch consumes CONFIG_DB directly, so a direct write is equivalent to the CLI and works on both kinds of images.
        """
        return self.sh.run(f"sonic-db-cli {db} HSET '{key}' {field} {value}", check=True)

    # ---- CRM (bypass the blocked crm CLI; uniformly direct-write CONFIG_DB CRM|Config; crmorch consumes it, behavior equivalent) ----
    def crm_set_polling(self, interval):
        """Set the CRM polling interval (seconds): direct-write CONFIG_DB CRM|Config polling_interval.

        Equivalent to `crm config polling interval <interval>`, but does not depend on the blocked crm CLI.
        """
        return self.db_hset("CONFIG_DB", "CRM|Config", "polling_interval", interval)

    def crm_set_threshold(self, res_key, ttype=None, low=None, high=None):
        """Set a resource threshold: direct-write CONFIG_DB CRM|Config's <res>_threshold_type/_low_threshold/_high_threshold.

        res_key is the CONFIG_DB resource prefix (e.g. ipv4_route / nexthop_group). Equivalent to
        `crm config thresholds <res> type/low/high <v>`, but does not depend on the blocked crm CLI.
        Only sets the fields passed in (None is skipped).
        """
        if ttype is not None:
            self.db_hset("CONFIG_DB", "CRM|Config", f"{res_key}_threshold_type", ttype)
        if low is not None:
            self.db_hset("CONFIG_DB", "CRM|Config", f"{res_key}_low_threshold", low)
        if high is not None:
            self.db_hset("CONFIG_DB", "CRM|Config", f"{res_key}_high_threshold", high)

    # ---- parsing helpers ----
    @staticmethod
    def parse_table(text):
        """Parse a `show` table into list[dict]. Handles two kinds:
        - fixed-width (columns split by 2+ spaces)
        - tabulate boxed grid (| separators, +---+ borders)
        """
        lines = [l for l in text.splitlines() if l.strip()]
        if not lines:
            return []
        grid = any(l.lstrip().startswith("|") for l in lines)
        if grid:
            def cells(l):
                return [c.strip() for c in l.strip().strip("|").split("|")]
            rowlines = [l for l in lines
                        if l.lstrip().startswith("|") and set(l) - set("|+-= ")]
            if not rowlines:
                return []
            header = cells(rowlines[0])
            rows = []
            for l in rowlines[1:]:
                cols = cells(l)
                if len(cols) == len(header):
                    rows.append(dict(zip(header, cols)))
            return rows
        # SONiC tabulate often has a separator line "-----  ----  ---" (dashes and spaces, 2+ segments). When present, use each
        # dash segment's column span for a FIXED-WIDTH column cut, which correctly parses sparse rows with empty cells (e.g. show platform
        # psustatus's N/A / empty Voltage column) -- the previous `split on 2+ spaces + len==header filter` would drop the whole sparse row.
        # Without a separator line, fall back to the original 2+ space logic, no regression.
        raw = text.splitlines()
        sep_idx = next((i for i, l in enumerate(raw)
                        if l.strip() and set(l.strip()) <= set("- ")
                        and len(re.findall(r"-+", l)) >= 2), None)
        if sep_idx is not None:
            hdr_idx = next((i for i in range(sep_idx - 1, -1, -1) if raw[i].strip()), None)
            if hdr_idx is not None:
                # Use each dash segment's start as a column boundary: column i takes [start_i, start_{i+1}), the last column to end of line.
                # Includes the inter-column gap to avoid right-truncation when data is slightly wider than the separator line.
                starts = [m.start() for m in re.finditer(r"-+", raw[sep_idx])]
                bounds = starts + [10 ** 9]
                cut = lambda l: [l[bounds[i]:bounds[i + 1]].strip() for i in range(len(starts))]
                header = cut(raw[hdr_idx])
                rows = []
                for l in raw[sep_idx + 1:]:
                    if not l.strip() or set(l.strip()) <= set("-+ "):
                        continue
                    cols = cut(l)
                    if any(cols):
                        rows.append(dict(zip(header, cols)))
                return rows
        header = re.split(r"\s{2,}", lines[0].strip())
        rows = []
        for l in lines[1:]:
            if set(l.strip()) <= set("-+ "):
                continue
            cols = re.split(r"\s{2,}", l.strip())
            if len(cols) == len(header):
                rows.append(dict(zip(header, cols)))
        return rows

    # ---- feature-provisioning helpers ----
    def _swssconfig(self, json_str):
        """Write APPL_DB via swssconfig (goes through ProducerStateTable, triggering orchagent).

        Note: sonic-db-cli HSET does not trigger orch notifications, so a static FDB is not programmed -- swssconfig is required.
        base64 transport avoids docker exec quote-escaping issues.
        """
        import base64
        b64 = base64.b64encode(json_str.encode()).decode()
        cmd = (f"docker exec {self.syncd.replace('syncd', 'swss')} bash -c "
               f"'echo {b64} | base64 -d > /tmp/swsscfg.json && swssconfig /tmp/swsscfg.json'")
        return self.sh.run(cmd, check=False)

    def fdb_static_add(self, vlan, mac, port, wait=True):
        """Static FDB. The customized OS goes through the product `config mac static add <mac> <port> <vlan>` (user guidance: always configure via config commands; writes CONFIG_DB for persistence + YANG validation), falling back to swssconfig
        with a WARNING on failure; community images go through swssconfig (APPL_DB FDB_TABLE -> fdborch -> ASIC).
        With wait=True, wait until the ASIC FDB is actually programmed before returning -- otherwise the caller's packet's dst is still an unknown unicast and floods,
        and if the ingress port is already looped back it would storm."""
        used_cli = False
        # The default Vlan1 is product-protected (semantic refusal, like the vlan member family); go straight to swssconfig to avoid noise
        if self.is_switchport_os() and str(vlan) != "1":
            rc, _r = self.config_raw(f"mac static add {mac} {port} {vlan}")
            used_cli = (rc == 0)
            if not used_cli:
                _log.warning("config mac static add failed (%s), falling back to swssconfig",
                             (_r.err or _r.out or "").strip()[:120])
        if not used_cli:
            j = ('[{"FDB_TABLE:Vlan%s:%s": {"port": "%s", "type": "static"}, "OP": "SET"}]'
                 % (vlan, mac, port))
            self._swssconfig(j)
        if wait:
            # Wait for real APPL_DB->fdborch->ASIC_DB programming. WARNING: the timeout must be ~20s, not 6s: in a loaded context
            # (the port under test looped back with lb=mac + the wait_learn_ready bcmcmd chain + a busy syncd), a static FDB landing in
            # ASIC_DB often takes 6~12s, and after a 6s timeout the caller's single _mac_in_asicdb assertion occasionally comes up empty (the FDB
            # actually arrives shortly after). Event-driven polling; return as soon as it arrives.
            up = mac.upper()
            deadline = time.time() + 20
            while time.time() < deadline:
                if any(up in k.upper()
                       for k in self.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*")):
                    break
                time.sleep(0.3)
        return f"FDB_TABLE:Vlan{vlan}:{mac}"

    def fdb_static_del(self, vlan, mac, port=None):
        if self.is_switchport_os():
            # The product del signature = `mac static del <vlan_id> <mac>` (different argument order from add's three args).
            # A leftover CONFIG_DB FDB| entry rejects all VLAN moves on that port with "VLAN_MEMBER related static FDB",
            # so it must never be silent -- after del, verify the key is gone; if still present, redis-delete as a fallback + WARNING.
            self.config_raw(f"mac static del {vlan} {mac}")
            key = f"FDB|Vlan{vlan}|{mac.lower()}"
            for _ in range(6):
                left = [k for k in self.db_keys("CONFIG_DB", f"FDB|Vlan{vlan}|*")
                        if mac.lower() in k.lower()]
                if not left:
                    break
                time.sleep(0.3)
            else:
                _log.warning("static FDB %s still in CONFIG_DB after mac static del, "
                             "redis-deleting (would block VLAN member moves)", key)
                self.sh.run(f"sonic-db-cli CONFIG_DB DEL '{key}'", check=False)
        j = '[{"FDB_TABLE:Vlan%s:%s": {}, "OP": "DEL"}]' % (vlan, mac)
        return self._swssconfig(j)

    def neigh_set(self, ip, mac, dev):
        """Test scaffolding: inject a "resolved neighbor" state (equivalent to a completed ARP/ND resolution), uniformly via the kernel's ip neigh.

        WARNING: does NOT go through the product `config arp static`: product static ARP is a STRONGLY-COUPLED config --
        attaching it to an interface changes the semantics of later `interface ip add` (requiring an extra gateway argument / "remove it first" refusal),
        and a persistent CONFIG_DB leftover implicates all later L3 cases. What the scaffolding
        needs is a volatile, side-effect-free neighbor state, and kernel injection is exactly the standard approach (same as sonic-mgmt). The product's
        `config arp static add/del` correctness is covered by test_routing_policy_cli's dedicated cases."""
        return self.sh.run(f"ip neigh replace {ip} lladdr {mac} dev {dev}", check=False)

    def neigh_del(self, ip, dev):
        self.sh.run(f"ip neigh del {ip} dev {dev}", check=False)

    def vlan_add(self, vid):
        return self.config(f"vlan add {vid}")

    def is_switchport_os(self):
        """Detect whether this is the customized OS (cached): `config interface link-mode --help` output contains both the bridge and
        route subcommands -> customized OS (ports default to L3 routed ports and need an explicit link-mode switch to L2/L3). Standard SONiC
        has no link-mode command (help is empty/errors) -> False, keep the existing logic, no regression."""
        if getattr(self, "_is_swp_os", None) is None:
            h = self.config("interface link-mode --help", check=False).out or ""
            self._is_swp_os = ("bridge" in h and "route" in h)
        return self._is_swp_os

    def _is_port_l2(self, name):
        """Whether the port is already home in an L2 state (both product models are recognized):
        (a) an explicit `VLAN_MEMBER|Vlan1|port` key exists (link-mode bridge creates it);
        (b) `PORT.link_mode` is a switchport mode (access/trunk/hybrid) and there is no bare `INTERFACE|port` L3 marker
            (Vlan1 is the berth, an access port belongs implicitly via pvid and does NOT create an explicit Vlan1 member key --
            recognizing only (a) would make `_restore_bridge_home` always falsely fail on such platforms)."""
        if self.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan1|{name}"):
            return True
        pm = self.db_hgetall("CONFIG_DB", f"PORT|{name}") or {}
        if pm.get("link_mode") in ("access", "trunk", "hybrid") \
                and not self.db_keys("CONFIG_DB", f"INTERFACE|{name}"):
            return True
        return False

    def _restore_bridge_home(self, name):
        """The SONiC authoritative return primitive: restore a port from ANY state to "Vlan1 untagged + access".

        Mechanism: `link-mode <port> bridge` only does a REAL conversion when the route marker (bare INTERFACE key) exists --
        it auto-clears the INTERFACE key + lm=access + returns to Vlan1 untagged; without the marker it reports
        "already a bridge" no-op. So the return sequence = set the marker (route) first, then convert (bridge).
        WARNING: never redis-del the bare key first: without the marker, bridge becomes a no-op and the port is stuck in an "access orphan" state
        (all hybrid/access usage is refused, and the only fix is a route->bridge re-cycle).
        Prerequisite: a VLAN member blocks link-mode route ("Please reset ... default") and an IP blocks the conversion, so clear them first."""
        for k in self.db_keys("CONFIG_DB", f"VLAN_MEMBER|*|{name}"):
            parts = k.split("|")
            if len(parts) == 3:
                self.config_raw(f"vlan member del {parts[1].replace('Vlan', '')} {name}")
        # Clear leftover product static ARP first (NEIGH|port|ip): holding the interface makes ip del/link-mode refuse across all families
        # ("static arp on interface, remove it first"). del argument order = <intf> <ip>.
        for k in self.db_keys("CONFIG_DB", f"NEIGH|{name}|*"):
            self.config_raw(f"arp static del {name} {k.split('|')[-1]}")
        for k in self.db_keys("CONFIG_DB", f"INTERFACE|{name}|*"):
            ip = k.split("|")[-1]
            self.config_raw(f"interface ip remove {name} {ip}")
        vrf = (self.db_hgetall("CONFIG_DB", f"INTERFACE|{name}") or {}).get("vrf_name")
        if vrf:
            self.config_raw(f"interface vrf unbind {name}")
        # hybrid/trunk orphan port: link-mode route is refused ("reset switchport first"), whereas
        # `switchport mode access` returns hybrid/trunk directly home; take it first.
        lm = (self.db_hgetall("CONFIG_DB", f"PORT|{name}") or {}).get("link_mode")
        if lm in ("hybrid", "trunk"):
            self.config_raw(f"switchport mode access {name}")
            for _ in range(6):
                if self._is_port_l2(name):
                    return True
                time.sleep(0.4)
        self.config_raw(f"interface link-mode {name} route")
        self.config_raw(f"interface link-mode {name} bridge")
        for _ in range(8):
            if self._is_port_l2(name):
                return True
            time.sleep(0.4)
        _log.warning("restore_bridge_home %s: not L2 (no Vlan1 member and not access mode) after route->bridge", name)
        return False

    def ensure_port_l2(self, port):
        """Customized OS: convert a port from a default L3 routed port to L2 (bridge, default access mode, INTERFACE entry removed),
        and record it in self._bridged for restoration at session end. Idempotent within a session (already-converted ports are skipped). No-op on a non-customized OS
        (standard SONiC ports are already at L2 by default, no conversion needed). port may be a Port object or a port-name string.

        WARNING: only write the _bridged cache AFTER a SUCCESSFUL verification (the port is no longer route/leftover L3) -- it once cached unconditionally,
        and when link-mode bridge was refused by a bare INTERFACE key the cache was poisoned, making every later L2 restore on this port a permanent no-op."""
        name = getattr(port, "name", port)
        if not self.is_switchport_os():
            return
        if name in self._bridged:
            return
        # Authoritative return primitive route->bridge (also returns to Vlan1); cache only on successful verification (it once cached unconditionally -> poisoning).
        if self._restore_bridge_home(name):
            self._bridged.add(name)
        else:
            _log.warning("ensure_port_l2 %s: restore_bridge_home failed, not caching", name)

    def restore_port_l3(self, port):
        """Customized OS: convert a port back to an L3 routed port (restore the device default config). No-op on a non-customized OS.
        Used to restore ports converted to bridge back to route at session end, and to prepare before L3 port creation (interface ip add).

        Key: if the port is still a member of some VLAN, `link-mode route` is refused ("Please reset ... to the default
        configuration"), and the subsequent ip add reports "is configured as a member of vlan". So you MUST detach from all
        user VLAN members FIRST, then switch to route: vlan member del -> link-mode route -> ip add.

        Vlan1 berth: on some platforms Vlan1 is not a user VLAN (CLI valid domain 2~4094, member del 1 is refused),
        and `link-mode route` REMOVES the Vlan1 berth member ITSELF -- so skip the explicit del for vid==1 and let route handle it.

        Wedge self-heal: a port that was directly `interface ip add`-ed while in access state gets a bare INTERFACE
        marker planted, after which route misjudges "already a route interface" as a permanent no-op.
        Signature = after route, the Vlan1 member is still present + the bare marker is present: delete the marker (redis, the only path) and route again for a real conversion."""
        name = getattr(port, "name", port)
        if not self.is_switchport_os():
            return
        # Detach all VLAN members of the port first. Vlan1: on some platforms del is legal and required; on others it is refused ("out of range
        # 2~4094", tolerate and continue) -- in the latter case link-mode route self-removes the Vlan1 berth member.
        vlan1_del_refused = False
        for k in self.db_keys("CONFIG_DB", f"VLAN_MEMBER|*|{name}"):
            parts = k.split("|")
            if len(parts) == 3:
                vid = parts[1].replace("Vlan", "")
                rc, _r = self.config_raw(f"vlan member del {vid} {name}")
                if vid == "1" and rc != 0:
                    vlan1_del_refused = True
        self.config_raw(f"interface link-mode {name} route")
        # Wedge self-heal (only on semantic devices where del 1 is refused: del 1 being refused is a signature prerequisite; never delete the bare marker on devices where del 1 is legal):
        # after route, the Vlan1 member is still present + the bare INTERFACE marker is present = the "already a route" misjudged state
        if vlan1_del_refused:
            for _ in range(6):
                if not self.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan1|{name}"):
                    break
                time.sleep(0.5)
            else:
                if self.db_keys("CONFIG_DB", f"INTERFACE|{name}"):
                    _log.warning("restore_port_l3 %s: wedged (stale route marker + Vlan1 member); "
                                 "removing marker and retrying link-mode route", name)
                    self.sh.run(f"sonic-db-cli CONFIG_DB DEL 'INTERFACE|{name}'", check=False)
                    self.config_raw(f"interface link-mode {name} route")
        self._bridged.discard(name)

    def vlan_untagged_flag(self):
        """The untagged syntax for `config vlan member add` (cached detection):
        - Customized OS: return `-u` as an untagged INTENT signal. WARNING: an early version returned "" (plain add), but _fixup's
          "no -u means tagged" (community semantics) misjudges this plain add as tagged -> gives the port `switchport
          mode hybrid` + lands an `-m tagged` member, so the framework's self-built untagged forwarding VLAN (l2_fwd_vlan/
          use_test_vlan) turns both ports into tagged members on a hybrid port -> untagged frames are not forwarded. After returning -u,
          _fixup takes the untagged branch and lands it by port mode:
          access ports drop the flag, hybrid/trunk ports use -m untagged (see _fixup) -- on the real CLI, access ports still carry no flag.
        - Newer standard images: `-m untagged`
        - Older images: `-u`
        Adapts to CLI differences across SONiC versions / the customized OS."""
        if self.is_switchport_os():
            return "-u"
        if getattr(self, "_vm_flag", None) is None:
            h = self.config("vlan member add --help", check=False).out or ""
            # WARNING: judge by the option's FULL name, do not match "-m ": some images' -m is --multiple
            # (bulk-add VLANs), and misjudging it as "-m untagged" would make EVERY member add report a usage error (rc=2)
            # -- undo/self-heal/hygiene all die, ports lose their default VLAN membership, and the whole L2 chain fails in cascade.
            if "--untagged" in h:
                self._vm_flag = "-u"
            elif "--mode" in h:
                self._vm_flag = "-m untagged"
            else:
                self._vm_flag = ""
        return self._vm_flag

    def vlan_member_add(self, vid, port, tagged=False):
        if tagged:
            flag = "-m tagged" if self.vlan_untagged_flag().startswith("-m") else ""
        else:
            flag = self.vlan_untagged_flag()
        return self.config(f"vlan member add {flag} {vid} {port}")

    def intf_ip_add(self, port, cidr):
        return self.config(f"interface ip add {port} {cidr}")

    def intf_startup(self, port):
        # Fast path: admin already up (the norm, test ports are up at baseline) skips issuing config -- every SONiC config goes through the YANG
        # validation chain and is slow, while a DB read is ~0.1s; when admin_status is absent (never configured) still issue an explicit startup.
        r = self.sh.run(f"sonic-db-cli CONFIG_DB HGET 'PORT|{port}' admin_status", check=False)
        if (r.out or "").strip() == "up":
            return r
        return self.config(f"interface startup {port}")

    def route_add(self, prefix, nexthop):
        return self.config(f"route add prefix {prefix} nexthop {nexthop}")

    def neigh_add(self, ip, mac, dev):
        # Go directly through the kernel/ip neigh, corresponding to the SONiC NEIGH table
        return self.sh.run(f"ip neigh replace {ip} lladdr {mac} dev {dev}", check=True)
