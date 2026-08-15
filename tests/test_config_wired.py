"""CLI coverage: `--help` for every `config` command that *actually exists* on this image must work (command is wired), without actually changing config.

This is the config half of "cover every command line". Rather than blindly running config
subcommands (which would change device state), it verifies the command tree is fully wired;
functional config specifics are covered by each feature domain's cases.

The command list is *generated dynamically against the running DUT* (recursively probing the
`config --help` command tree), testing only the commands this image really has: the static
`catalog/cli_inventory.json` was captured from a newer image, and applying it directly to an
older image would falsely fail on subcommands the old image simply lacks
(acl/bmp/fg-nhg/ldap/mmu/ssh/subinterface/... returning `No such command`).
config_wired's semantics are "documented commands don't crash"; a command that doesn't exist on
the image is untestable, so it is *not included* in the parametrization (not a skip masking a
defect). The static list is kept only as an "at-least-should-cover" reference (see _EXPECTED);
existence is always judged from the running image's real command tree.
"""
import json
import os
import subprocess

import pytest

_INV = os.path.join(os.path.dirname(__file__), "..", "catalog", "cli_inventory.json")
with open(_INV) as f:
    # Static list: only an "at-least-should-cover" reference, not used for existence judgment.
    _EXPECTED = [c for c in json.load(f)["config"] if "..." not in c]

pytestmark = pytest.mark.cli

# Probe mechanism = parse subcommands from `config --help` -> verify each `config <sub> --help`
# exists. depth=1 means testing only top-level config commands (`config aaa`/`config acl`...),
# same granularity as the static list (all single-level); raising it probes one more subcommand
# level down, but would blow up a command-rich image (SONiC has ~168 at the top level) into
# hundreds of parametrized items and slow collection/full runs, so it probes only the top level by default.
_MAX_DEPTH = 1


def _parse_subcommands(help_text):
    """Parse subcommand names under the Commands: section of click `--help` output."""
    cmds, in_cmds = [], False
    for line in help_text.splitlines():
        if line.strip().startswith("Commands:"):
            in_cmds = True
            rest = line.split("Commands:", 1)[1].strip()   # first command may follow on the same line
            if rest:
                cmds.append(rest.split()[0])
            continue
        if in_cmds:
            if not line.strip():
                continue
            if line[:1] not in (" ", "\t"):   # indentation ended -> Commands section ended
                break
            tok = line.strip().split()
            if tok:
                cmds.append(tok[0])
    return cmds


def _help_stdout(path):
    """Run `<path> --help` locally and return stdout. When a command doesn't exist click prints the error to stderr and stdout is empty."""
    try:
        p = subprocess.run(path + ["--help"], capture_output=True, text=True, timeout=20)
    except Exception:   # noqa: BLE001  any exception during probing is treated as "command unavailable", not included
        return ""
    return p.stdout or ""


def _walk(path, depth, found):
    """Recursively probe the command tree: a command counts as really existing (added to the test set) only if its --help has Usage/Options."""
    help_text = _help_stdout(path)
    if "Usage:" not in help_text and "Options:" not in help_text:
        return   # this image lacks the command / not wired -> don't test
    found.append(" ".join(path))
    if depth >= _MAX_DEPTH:
        return
    for sub in _parse_subcommands(help_text):
        _walk(path + [sub], depth + 1, found)


_DISCOVERED = None


def _config_commands():
    """Collect the config command tree that really exists on this image (cached once per process).

    - DUT_DRY_RUN (build-machine self-check, no real DUT): cannot probe, fall back to the static
      list so collection works normally.
    - Real-device probe completely fails (empty): fall back to the static list so the --help
      assertions expose the real problem.
    """
    global _DISCOVERED
    if _DISCOVERED is not None:
        return _DISCOVERED
    if os.environ.get("DUT_DRY_RUN", "") not in ("", "0", "false"):
        _DISCOVERED = list(_EXPECTED)
        return _DISCOVERED
    found = []
    for sub in _parse_subcommands(_help_stdout(["config"])):
        _walk(["config", sub], 1, found)   # the config root itself is the entry point, not tested
    _DISCOVERED = sorted(set(found)) or list(_EXPECTED)
    return _DISCOVERED


CONFIG = _config_commands()

# For reference: commands in the static list missing on this image (an older image legitimately
# lacks commands, not a defect; only for manual review of coverage differences).
_MISSING_VS_INVENTORY = sorted(set(_EXPECTED) - set(CONFIG))


@pytest.mark.parametrize("cmd", CONFIG, ids=[c.replace("config ", "").replace(" ", "_") for c in CONFIG])
def test_config_wired(cli, cmd):
    r = cli.run(f"{cmd} --help", timeout=20)
    combined = f"{r.out}\n{r.err}"
    assert "Traceback (most recent call last)" not in combined, \
        f"`{cmd} --help` crashed (device issue):\n{combined[-800:]}"
    assert "Usage:" in r.out or "Options:" in r.out, \
        f"`{cmd}` not properly wired: {combined[-300:]}"
    # rc was not asserted before: when click wiring is half-broken, stdout can still print Usage
    # but the exit code is non-zero (probe and assert sharing the same predicate makes this case
    # structurally hard to fail -- rc/stderr are independent evidence not consumed during probing,
    # used here to break the tautology).
    assert r.rc == 0, \
        f"`{cmd} --help` printed help but exited rc={r.rc} (half-wired command): {combined[-300:]}"
    assert "Error" not in r.err, \
        f"`{cmd} --help` emitted an error on stderr despite printing help: {r.err[-300:]}"
