"""CLI coverage: run every `show` command on the DUT, asserting it doesn't crash (no Python Traceback).

This is the show half of "cover all command lines" (287 commands, read-only). Criteria:
- pass: rc==0, or a graceful usage/missing-arg error (the command is wired, it just wants an argument).
- fail (= device/software issue, recorded honestly, not softened): output contains a Python Traceback, i.e. the command crashed.

Crashed commands are collected and summarized by a conftest hook (see conftest's pytest_terminal_summary).
"""
import json
import os

import pytest

_INV = os.path.join(os.path.dirname(__file__), "..", "catalog", "cli_inventory.json")
with open(_INV) as f:
    SHOW = [c for c in json.load(f)["show"] if "..." not in c]

# exclude time-consuming/heavy commands (not crash-verdict targets; techsupport generates a big
# bundle, and muxcable/transceiver/fabric each time out for tens of seconds when the hardware is
# absent, run separately with a short timeout or skipped to keep the whole suite timely)
SKIP = {"show techsupport"}
SHOW = [c for c in SHOW if c not in SKIP]
# slow command group: short timeout (expected slow when the hardware is absent; timeout = crash verdict not reached -> honest skip, no longer a silent pass)
SLOW_PREFIX = ("show muxcable", "show interfaces transceiver", "show fabric")


def _timeout_for(cmd):
    return 8 if cmd.startswith(SLOW_PREFIX) else 30

pytestmark = pytest.mark.cli

# commands that dump arbitrary log/text content: the content may itself contain the word
# "Traceback" (a Python stack logged by some daemon), so we can't judge a crash by content ->
# these are judged by rc only (the command just needs to run to completion).
CONTENT_CMDS = {"show logging"}

# root-caused "platform/feature N/A causes CLI crash" -- not a chip-capability issue, but the
# SONiC CLI lacking a graceful guard for the N/A scenario (fixable by adding a guard in the
# sonic-utilities source). These commands really crash = a device/software defect; no longer
# softened with xfail, but run and asserted as usual -> a crash FAILs to expose it. This table
# is kept only as known-root-cause documentation.
XFAIL_KNOWN = {
    # platform-hardware class: this lab device's vendor platform isn't brought up -- the
    # sonic_platform vendor package isn't integrated into the image + the platform kernel driver
    # isn't loaded (no /sys_switch, no platform services). Installing sonic_platform crashes even
    # more critical commands (interfaces status), so it isn't installed. These platform-hardware
    # commands are N/A on this device. They recover automatically on an image where the platform is brought up.
    "show platform firmware":
        "platform not brought up: sonic_platform pkg missing + no /sys_switch driver; fwutil crashes (N/A on lab device)",
    "show platform syseeprom":
        "platform not brought up: sonic_platform pkg missing (ModuleNotFound); decode-syseeprom crashes (N/A on lab device)",
    "show interfaces transceiver error-status":
        "platform not brought up: sonic_platform pkg missing (ModuleNotFound); sfputil crashes (N/A on lab device)",
    "show interfaces transceiver lpmode":
        "platform not brought up: sonic_platform pkg missing (ModuleNotFound); sfputil crashes (N/A on lab device)",
    "show chassis system-lags":
        "voqutil: VOQ-chassis-only command, N/A on fixed (non-VOQ) switch; CLI lacks graceful guard",
    "show chassis system-neighbors":
        "voqutil: VOQ-chassis-only command, N/A on fixed (non-VOQ) switch; CLI lacks graceful guard",
    "show bmp tables":
        "bmp container not running; CLI crashes instead of graceful message",
    "show system-health detail":
        "system-health monitor not running/configured on this platform; CLI crashes",
    "show system-health summary":
        "system-health monitor not running/configured on this platform; CLI crashes",
    "show system-health monitor-list":
        "system-health monitor not running/configured on this platform; CLI crashes",
}


@pytest.mark.parametrize("cmd", SHOW, ids=[c.replace("show ", "").replace(" ", "_") for c in SHOW])
def test_show_no_crash(cli, cmd, record_property, request):
    # device defect: the former xfail softening for the known-crashing commands in XFAIL_KNOWN is now removed.
    # these commands crashing is a real defect; run and assert as usual -> a crash FAILs directly via the assert below.
    r = cli.run(cmd, timeout=_timeout_for(cmd))
    combined = f"{r.out}\n{r.err}"
    record_property("cmd", cmd)
    record_property("rc", r.rc)
    # a timeout (returned by the shell layer as rc=124) is no longer silently passed as "non-crash":
    # a normal command hanging 30s (e.g. the CLI blocked on a dead-daemon socket) is itself a device
    # issue -> FAIL; the slow command group is short-budget + expected slow with no hardware, not
    # reaching the crash-verdict point -> honest skip (not verified != pass).
    if r.rc == 124:
        if cmd.startswith(SLOW_PREFIX):
            pytest.skip(f"timed out at short budget (no hw); crash-verdict not reached: `{cmd}`")
        assert False, f"command hung >{_timeout_for(cmd)}s (device issue): `{cmd}`"
    if cmd in CONTENT_CMDS:
        # content-dump class: the command running to completion (rc usually 0) counts as non-crash;
        # don't misjudge by the word "Traceback" in the content. rc is untrustworthy (the SONiC CLI
        # returns 0 even on error): the criterion becomes output characteristics -- the command must
        # actually produce content and must not be a "command not found / arg error" echo.
        low = combined.lower()
        assert combined.strip(), f"{cmd} produced no output at all"
        assert "no such command" not in low, \
            f"{cmd}: command not wired: {combined[:160]!r}"
        return
    crashed = "Traceback (most recent call last)" in combined
    assert not crashed, f"command crashed (device issue): `{cmd}`\n{combined[-1000:]}"
