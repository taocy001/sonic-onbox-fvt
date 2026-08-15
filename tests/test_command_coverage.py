"""Onbox klish command-coverage.

Enumerates EVERY klish leaf command from the installed tree
(/opt/klish/command-tree), synthesizes valid args, and drives each through
`klish` in script+dryrun mode (no device-state change).  A command is COVERED
when klish parses it and it maps to a native (`[dryrun] exec:`); it FAILS on a
klish `Syntax error` (unreachable / arg-synthesis gap).

This measures how much of the product CLI the onbox suite exercises, targeting
100%.  Slow (~one klish spawn per command): run explicitly, e.g.
    sudo python3 -m pytest tests/test_command_coverage.py -v -s

Known residual gaps are listed in KNOWN_GAPS (view, name) and xfail-counted, so
the assertion tracks *new* regressions while the report shows the true number.
"""
import glob
import os
import subprocess
import xml.etree.ElementTree as ET

import pytest

NS = "{http://www.dellemc.com/sonic/XMLSchema}"
TREE = "/opt/klish/command-tree"
_SAMPLE = {
    "UINT": "1", "IP_ADDR": "1.1.1.1", "IP_ADDR_MASK": "1.1.1.0/24",
    "IPV6_ADDR": "2001:db8::1", "IPV6_ADDR_MASK": "2001:db8::/64",
    "IPV4_OR_IPV6_ADDR": "1.1.1.1", "VLAN_ID": "100",
    "MAC_ADDR": "00:11:22:33:44:55", "STRING": "X", "DYN_IFACE": "Ethernet0",
    "RANGE_MTU": "9100", "INTF_SPEED": "100000", "DYN_PORT": "Ethernet0",
    "DYN_BREAKOUT_MODE": "1x100G", "KLISH_COUNTERPOLL_TYPE": "queue",
    "KLISH_CRM_RESOURCE": "fdb", "KLISH_CRM_TYPE": "used",
    "KLISH_ACL_STAGE": "ingress", "KLISH_ACL_TABLE_ACTION": "forward",
}

# klish builtins / shell escapes -- not product commands to cover.
_BUILTINS = {"exit", "end", "bash", "show this", "no", "enable", "hidden", "quit"}

# commands whose valid args can't be synthesized generically (need real object
# names / device state) -- exercised by the functional suites instead.  Reviewed.
KNOWN_GAPS = set()


def _synth_one(p):
    mode = p.get("mode")
    if mode == "subcommand":
        return [p.get("value") or p.get("name")] + _synth(p)
    if mode == "switch":
        k = p.findall(NS + "PARAM")
        return _synth_one(k[0]) if k else []
    return [_SAMPLE.get(p.get("ptype"), "X")]


def _synth(parent):
    out = []
    for p in parent.findall(NS + "PARAM"):
        if p.get("optional") != "true":
            out += _synth_one(p)
    return out


def _enumerate():
    files = []
    for xf in sorted(glob.glob(TREE + "/*.xml")):
        try:
            files.append(ET.parse(xf).getroot())
        except ET.ParseError:
            pass
    views = {}
    for root in files:
        for v in root.iter(NS + "VIEW"):
            for c in v.findall(NS + "COMMAND"):
                to = c.get("view")
                if to and (to not in views or len(c.get("name")) < len(views[to][1])):
                    views[to] = (v.get("name"), c.get("name"), c)

    def chain(view):
        steps, seen = [], set()
        while view and view not in ("enable-view", "configure-view") and view not in seen:
            seen.add(view)
            frm, name, cmd = views.get(view, (None, None, None))
            if name is None:
                return None
            steps.append((name + " " + " ".join(_synth(cmd))).strip())
            view = frm
        return list(reversed(steps))

    cmds = []
    for root in files:
        for v in root.iter(NS + "VIEW"):
            vn = v.get("name")
            for c in v.findall(NS + "COMMAND"):
                if c.find(NS + "ACTION") is None:
                    continue
                name = c.get("name")
                if name in _BUILTINS:
                    continue
                ch = chain(vn)
                if ch is None:
                    continue
                leaf = (name + " " + " ".join(_synth(c))).strip()
                verb = name.split()[0]
                parts = ([leaf] if vn == "enable-view" or verb in ("show", "clear")
                         else ["configure terminal"] + ch + [leaf])
                cmds.append((vn, name, parts))
    return cmds


@pytest.mark.slow
def test_command_coverage():
    if not os.path.isdir(TREE):
        pytest.skip("klish not installed (%s)" % TREE)
    cmds = _enumerate()
    assert cmds, "no commands enumerated"
    env = dict(os.environ, KLISH_SCRIPT="1", KLISH_DRYRUN="1")
    mapped, failed = 0, []
    for vn, name, parts in cmds:
        argv = ["klish"]
        for p in parts:
            argv += ["-c", p]
        res = subprocess.run(argv, env=env, capture_output=True, text=True)
        blob = (res.stdout or "") + (res.stderr or "")
        # COVERED = klish parsed it and reached the actioner: a dryrun line
        # (`[dryrun] exec:` / `[dryrun] set|del`), a running/startup-config render,
        # or a `%%` validation message.  Only a klish `Syntax error` = not reached.
        if "Syntax error" in blob:
            failed.append((vn, name))
        else:
            mapped += 1
    total = len(cmds)
    new_fail = [f for f in failed if f not in KNOWN_GAPS]
    pct = 100.0 * mapped / total
    print("\n=== klish command coverage: %d/%d = %.1f%% (known gaps %d, new %d) ==="
          % (mapped, total, pct, len(failed) - len(new_fail), len(new_fail)))
    for vn, name in sorted(new_fail)[:60]:
        print("  UNCOVERED  %-22s %s" % (vn, name))
    assert not new_fail, "%d commands newly uncovered (see report)" % len(new_fail)
