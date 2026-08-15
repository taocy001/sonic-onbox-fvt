"""Config persistence x chip state -- save file contents + chip state restored after reload (gated).

Previously persistence only tested the `config save` writeout side; this file brings
"chip-verified config" into the persistence loop:
1) a scheduler config verified as programmed to the chip must be complete in the save file;
2) chip state restored after config reload re-applies it -- runs only on devices with
   caps.config_reload_safe (off by default, enabled after per-device verification).
"""
import pytest

from framework import qos
from framework.gcu import Gcu
from framework.lossless import bind_queue, make_scheduler

pytestmark = [pytest.mark.mgmt, pytest.mark.chiptab]

_W = 66


def test_saved_config_carries_chip_verified_state(cli, chip, topo):
    """Create scheduler(w=66), bind queue -> chip WEIGHT=66 confirms it took effect -> config save to a separate file
    -> the file contains that SCHEDULER entry (proving "config actually in effect on-chip" is fully persisted)."""
    chip.require()
    port = topo.misc_port(0).name
    if qos.has_qos_cli(cli):
        ok, undo_s, why = make_scheduler(cli, "FVTPST", mode="DWRR", weight=_W)
        if not ok:
            pytest.skip(f"scheduler add rejected: {why}")
        ok2, undo_q = bind_queue(cli, port, 2, sched="FVTPST")
        if not ok2:
            undo_s()
            pytest.skip("port-queue bind rejected")
        undos = [undo_q, undo_s]
    else:
        gcu = Gcu(cli)
        r1 = gcu.apply_patch(gcu.add_entry(
            "SCHEDULER", "FVTPST", {"type": "DWRR", "weight": str(_W)}))
        if r1.rc != 0:
            pytest.skip(f"GCU SCHEDULER rejected: {(r1.out or r1.err or '')[-140:]}")
        r2 = gcu.apply_patch(gcu.add_entry("QUEUE", f"{port}|2",
                                           {"scheduler": "FVTPST"}))
        if r2.rc != 0:
            gcu.apply_patch(gcu.remove_entry("SCHEDULER", "FVTPST"))
            pytest.skip(f"GCU QUEUE bind rejected: {(r2.out or r2.err or '')[-140:]}")
        undos = [lambda: gcu.apply_patch(gcu.remove_entry("QUEUE", f"{port}|2")),
                 lambda: gcu.apply_patch(gcu.remove_entry("SCHEDULER", "FVTPST"))]
    try:
        ok3, ent = chip.wait_field(lambda: chip.sched_node(port, 2), "WEIGHT",
                                   lambda v: v == _W, timeout=30)
        assert ok3, (
            f"chip TM_SCHEDULER_NODE weight never became {_W} (entry={ent}); "
            f"cannot certify persistence of a config that isn't on-chip")
        f = "/tmp/fvt_persist_save.json"
        r = cli.sh.run(f"config save -y {f}", check=False, timeout=90)
        assert r.rc == 0, f"config save failed: {r.err or r.out}"
        out = cli.sh.run(f"cat {f}").out or ""
        assert '"FVTPST"' in out and f'"{_W}"' in out, (
            "saved config missing the chip-verified SCHEDULER entry FVTPST "
            f"(weight {_W})")
        cli.sh.run(f"rm -f {f}", check=False)
    finally:
        for u in undos:
            u()


def test_config_reload_restores_chip_state(caps):
    """config reload re-applies -> chip state restored. By default all registered devices have
    config_reload_safe=false (not verified per-device); once the cap is enabled this stub will be
    replaced by the full implementation: mark config -> save -> reload -> wait for services to
    re-stabilize -> assert chip state restored."""
    caps.require("config_reload_safe")
    pytest.fail("config_reload_safe declared but reload scenario not yet implemented "
                "for this device — implement the reload leg before enabling the cap")
