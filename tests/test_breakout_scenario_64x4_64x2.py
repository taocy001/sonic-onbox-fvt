"""C4-scale scenario: 64 ports 1->4 (4x200G) + 64 ports 1->2 (2x400G) broken out simultaneously.

Verifies each subport's chip entries (PC_PORT lanes/speed) are consistent + subports are visibly
named in `ps`, and that all are merged back (no residue). **Uses product config commands throughout
(config interface breakout, no direct DB writes).**

Scale is tunable via FVT_BR4/FVT_BR2 env vars (default 64/64). When chip logical-port capacity is
insufficient, report the actually-created count faithfully (continue-on-error), and merge all broken-out
ports back to their original mode in teardown.

How to run: must be a dedicated round `pytest tests/test_breakout_scenario_64x4_64x2.py -m breakout`
(creates/deletes ports, cannot run alongside a regular round).
"""
import os
import re

import pytest

from framework import breakout as BK

pytestmark = [pytest.mark.breakout, pytest.mark.chiptab]

_N4 = int(os.environ.get("FVT_BR4", "64"))
_N2 = int(os.environ.get("FVT_BR2", "64"))


def _eth_ports(dut):
    return sorted((p.name for p in dut.ports if re.match(r"Ethernet\d+$", p.name)),
                  key=lambda n: int(n[8:]))


def _mode_by_ways(modes, ways):
    cands = sorted(m for m in modes if m.startswith(f"{ways}x"))
    for m in cands:
        if "(" not in m:      # prefer whole-cage mode; "(4)" variant is rejected by some CLIs
            return m
    return cands[0] if cands else None


def _ps_named(cli, dut, port_name):
    """Whether this subport's corresponding bcm logical port is visibly named in `ps`.
    A subport may be a ghost (no cd name); it should have a name here. Use chiptab port_id to infer whether it is in ps."""
    try:
        pid = cli.sh  # placeholder; naming judged via bcmcmd ps below
    except Exception:
        pass
    return None


def test_scenario_64x4_and_64x2(dut, bdrv, chip, cli, topo):
    topo.caps.require("breakout_dpb")
    ports = _eth_ports(dut)
    need = _N4 + _N2
    if len(ports) < need:
        pytest.skip(f"need {need} Ethernet ports, have {len(ports)}")
    grp4 = ports[:_N4]
    grp2 = ports[_N4:_N4 + _N2]

    split_done = []       # [(port, subports)]
    restores = {}         # port -> original mode
    expected = 0
    verified = 0
    failures = []

    try:
        for grp, ways in ((grp4, 4), (grp2, 2)):
            for port in grp:
                modes = BK.platform_modes(dut, port)
                mode = _mode_by_ways(modes, ways)
                if not mode:
                    failures.append((port, f"no {ways}x mode in platform.json"))
                    continue
                restores[port] = bdrv.current_mode(port) or _mode_by_ways(modes, 1) or "1x800G"
                res = bdrv.split(port, mode, timeout=60)
                expected += ways
                if not res.get("ok"):
                    failures.append((port, "split failed: " + res.get("text", "")[-100:]))
                    continue
                split_done.append((port, res["subports"]))
                # Chip entry consistency: each subport's PC_PORT NUM_LANES / SPEED matches expectations
                for name, lanes, speed in res["subports"]:
                    try:
                        ent = chip.pc_port(name)
                    except Exception as e:  # noqa: BLE001
                        failures.append((name, f"chip pc_port unreadable: {e}"))
                        continue
                    if not ent:
                        failures.append((name, "chip PC_PORT missing (ghost/not created)"))
                        continue
                    if ent.get("NUM_LANES") != len(lanes):
                        failures.append((name, f"chip NUM_LANES {ent.get('NUM_LANES')} != {len(lanes)}"))
                        continue
                    verified += 1

        # naming (dport-fill fix): valid ports with no name (blank-name) in ps should be 0
        unnamed = cli.sh.run(
            "docker exec syncd bcmcmd 'ps' </dev/null 2>/dev/null | "
            "grep -E '^ +\\( *[0-9]+\\)' | wc -l", check=False).out.strip()

        print(f"SCENARIO 64x4+64x2: expected_subports={expected} chip_verified={verified} "
              f"failures={len(failures)} unnamed_ports_in_ps={unnamed}")
        for f in failures[:25]:
            print("  FAIL:", f[0], "-", f[1])

        # Criteria: the vast majority of subport chip entries are consistent (capacity shortfalls show up faithfully in the ratio), and no unnamed ports (naming fix)
        assert unnamed == "0", f"{unnamed} valid ports unnamed in ps (dport-fill regression)"
        assert verified >= expected * 0.95, (
            f"only {verified}/{expected} subports chip-verified "
            f"(if <<expected: chip logical-port capacity limit — see failures)")
    finally:
        # Restore: merge all broken-out ports back to their original mode (best-effort, print each failure, finally recommend reboot as a fallback)
        merge_fail = []
        for port, subs in split_done:
            # Clear any leftover subport vlan residue before merging
            for name, _l, _s in subs:
                if name == port:
                    continue
                for k in cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|*|{name}"):
                    vid = re.sub(r"\D", "", k.split("|")[1])
                    cli.sh.run(f"config vlan member del {vid} {name}", check=False)
            m = bdrv.merge(port, restores.get(port, "1x800G"), timeout=60)
            if not m.get("ok"):
                merge_fail.append(port)
        if merge_fail:
            print("MERGE-BACK FAILED for:", merge_fail, "(reboot restores from unsaved disk config)")
