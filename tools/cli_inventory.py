#!/usr/bin/env python3
"""Enumerate the click CLI command tree (show / config) on the DUT, printing the full path of each leaf command.

Used as the baseline inventory for "covering all CLI commands". Reads --help to recursively expand subcommands.
"""
import json
import subprocess
import sys

ROOTS = sys.argv[1:] or ["show", "config"]
MAXDEPTH = 4


def subcommands(path):
    """Run `<path> --help`, parsing the subcommand names under the Commands: section."""
    try:
        out = subprocess.run(path + ["--help"], capture_output=True, text=True,
                             timeout=20).stdout
    except Exception:
        return []
    cmds, in_cmds = [], False
    for line in out.splitlines():
        if line.strip().startswith("Commands:"):
            in_cmds = True
            # The first command may follow on the same line
            rest = line.split("Commands:", 1)[1].strip()
            if rest:
                cmds.append(rest.split()[0])
            continue
        if in_cmds:
            if not line.strip():
                continue
            if line[:1] not in (" ", "\t"):
                break
            tok = line.strip().split()
            if tok:
                cmds.append(tok[0])
    return cmds


def walk(path, depth, leaves):
    subs = subcommands(path) if depth < MAXDEPTH else []
    if not subs:
        leaves.append(" ".join(path))
        return
    for s in subs:
        walk(path + [s], depth + 1, leaves)


def main():
    result = {}
    for root in ROOTS:
        leaves = []
        walk([root], 0, leaves)
        result[root] = sorted(set(leaves))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
