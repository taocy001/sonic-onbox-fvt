"""Port physical-layer config behavior -- the full chain of speed / FEC / MTU / admin down to the chip PC_PORT.

Previously these had only `show ... doesn't crash`-level coverage (inventory); this file verifies each knob down
to CONFIG_DB -> ASIC_DB PORT attribute -> SDKLT PC_PORT field. Link-level behavior on a loopback bench (FEC
negotiation, autoneg interaction) is not testable -- verify only the programming layer and note it; paths the CLI
explicitly declares unsupported are honestly skipped.

Uses topo.misc_port(1) (h role, away from the traffic pair / L3 / L2 domains). All changes are restored in teardown.
"""
import time

import pytest

pytestmark = [pytest.mark.chiptab, pytest.mark.cli]


@pytest.fixture
def phys_port(topo):
    return topo.misc_port(1)


def _port_oid(cli, name):
    return cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {name}")


def _asic_port_key(asicdb, oid):
    for k in asicdb.objects("SAI_OBJECT_TYPE_PORT"):
        if k.endswith(oid):
            return k
    return None


def _wait_asic_attr(cli, key, attr, pred, timeout=15):
    end = time.time() + timeout
    val = None
    while time.time() < end:
        val = (cli.db_hgetall("ASIC_DB", key) or {}).get(attr)
        if val is not None and pred(str(val)):
            return True, val
        time.sleep(0.5)
    return False, val


def _unsupported(text):
    t = (text or "").lower()
    return "not support" in t or "unsupported" in t or "no such command" in t


def test_mtu_chain_to_chip_max_frame(cli, asicdb, chip, phys_port, config_guard):
    """MTU full chain, adding the chip layer: config mtu 9100 -> CONFIG_DB -> chip PC_PORT.MAX_FRAME_SIZE
    >= 9100 (the chip adds encapsulation headroom, so verify only the lower bound; existing MTU cases stop at the kernel netdev)."""
    chip.require()
    p = phys_port.name
    orig = (cli.db_hgetall("CONFIG_DB", f"PORT|{p}") or {}).get("mtu", "9216")
    rc, r = cli.config_raw(f"interface mtu {p} 9100")
    if rc != 0 and _unsupported((r.out or "") + (r.err or "")):
        pytest.skip(f"mtu CLI unavailable: {((r.out or '') + (r.err or ''))[-120:]}")
    assert rc == 0, f"config interface mtu rejected: {(r.out or '') + (r.err or '')}"
    config_guard.defer_undo(f"interface mtu {p} {orig}")
    assert (cli.db_hgetall("CONFIG_DB", f"PORT|{p}") or {}).get("mtu") == "9100", \
        "CONFIG_DB mtu not updated"
    # Fault localization: first prove the ASIC layer received the MTU, then look at the chip MAC (chip reads can
    # show an in-session transient of being empty for 20s straight -- the ASIC-layer assertion separates "orch
    # broke the chain" from "diagnostic-channel transient")
    oid = _port_oid(cli, p)
    key = _asic_port_key(asicdb, oid)
    assert key, f"no ASIC PORT object for {p}"
    okA, mval = _wait_asic_attr(cli, key, "SAI_PORT_ATTR_MTU",
                                lambda v: v.isdigit() and int(v) >= 9100, timeout=15)
    assert okA, f"ASIC SAI_PORT_ATTR_MTU never reached 9100 (last={mval})"
    ok, ent = chip.wait_field(lambda: chip.pc_port(p), "MAX_FRAME_SIZE",
                              lambda v: isinstance(v, int) and v >= 9100, timeout=40)
    assert ok, (
        f"chip PC_PORT.MAX_FRAME_SIZE for {p} never reached >=9100 (entry="
        f"{ {k: v for k, v in (ent or {}).items() if 'FRAME' in k} }); ASIC has the "
        f"MTU but chip MAC does not — SAI->SDK break (or lt-diag transient; retried 40s)")


def test_speed_chain_to_chip(cli, asicdb, chip, phys_port, config_guard):
    """speed full chain (previously zero coverage): pick a non-current rate from STATE/APPL supported_speeds,
    config speed -> CONFIG_DB -> ASIC SAI_PORT_ATTR_SPEED -> evidence of the rate on the chip PC_PORT."""
    chip.require()
    p = phys_port.name
    cur = (cli.db_hgetall("CONFIG_DB", f"PORT|{p}") or {}).get("speed")
    sup = (cli.db_hgetall("STATE_DB", f"PORT_TABLE|{p}") or {}).get("supported_speeds") \
        or (cli.db_hgetall("APPL_DB", f"PORT_TABLE:{p}") or {}).get("supported_speeds")
    if not sup:
        pytest.skip(f"no supported_speeds exposed for {p}; refusing to guess a speed")
    cands = [s for s in sup.split(",") if s.strip().isdigit() and s.strip() != cur]
    if not cands:
        pytest.skip(f"no alternative speed to switch to (supported={sup}, cur={cur})")
    target = sorted(cands, key=int)[-1]
    rc, r = cli.config_raw(f"interface speed {p} {target}")
    text = (r.out or "") + (r.err or "")
    if rc != 0 and _unsupported(text):
        pytest.skip(f"speed change declared unsupported by CLI: {text[-120:]}")
    assert rc == 0, f"config interface speed {target} rejected: {text[-200:]}"
    config_guard.defer_undo(f"interface speed {p} {cur}")
    assert (cli.db_hgetall("CONFIG_DB", f"PORT|{p}") or {}).get("speed") == target, \
        "CONFIG_DB speed not updated"
    oid = _port_oid(cli, p)
    key = _asic_port_key(asicdb, oid)
    assert key, f"no ASIC PORT object for {p}"
    okA, val = _wait_asic_attr(cli, key, "SAI_PORT_ATTR_SPEED",
                               lambda v: v == str(int(target) // 1000) or v == target,
                               timeout=20)
    assert okA, (
        f"ASIC SAI_PORT_ATTR_SPEED for {p} never became {target} (Mbps or units "
        f"variant; last={val}); speed accepted but not programmed")
    ent = chip.pc_port(p)
    hit = any((isinstance(v, int) and v in (int(target), int(target) // 1000))
              or (isinstance(v, str) and f"{int(target) // 1000}G" in v.upper())
              for f, v in (ent or {}).items() if "SPEED" in f)
    assert hit, (
        f"chip PC_PORT speed field for {p} does not reflect {target}: "
        f"{ {k: v for k, v in (ent or {}).items() if 'SPEED' in k} }")


def test_fec_chain_to_chip(cli, asicdb, chip, phys_port, config_guard):
    """FEC full chain (previously only show-doesn't-crash): rs -> none -> chip PC_PORT.FEC_MODE follows;
    a loopback bench has no peer, so FEC link-negotiation behavior is not testable (noted VERIFY-ON-HW); verify the programming layer."""
    chip.require()
    p = phys_port.name
    cur = (cli.db_hgetall("CONFIG_DB", f"PORT|{p}") or {}).get("fec", "rs")
    target = "none" if cur != "none" else "rs"
    rc, r = cli.config_raw(f"interface fec {p} {target}")
    text = (r.out or "") + (r.err or "")
    if rc != 0 and _unsupported(text):
        pytest.skip(f"fec CLI unavailable/unsupported: {text[-120:]}")
    if rc != 0 and "is not in" in text:
        # The platform declares this port supports only a single FEC (e.g. 800G forces RS) -- no alternative value to switch to, structural skip
        pytest.skip(f"platform allows a single FEC on {p} (no alternative to "
                    f"exercise): {text[-120:]}")
    assert rc == 0, f"config interface fec {target} rejected: {text[-200:]}"
    config_guard.defer_undo(f"interface fec {p} {cur}")
    ok, ent = chip.wait_field(
        lambda: chip.pc_port(p), "FEC_MODE",
        lambda v: (target == "none" and "NONE" in str(v).upper())
        or (target == "rs" and "RS" in str(v).upper()), timeout=20)
    assert ok, (
        f"chip PC_PORT.FEC_MODE for {p} did not become {target} "
        f"(entry FEC={ (ent or {}).get('FEC_MODE') }); FEC accepted but not programmed")


def test_admin_shutdown_chain_to_chip(cli, asicdb, chip, phys_port, config_guard):
    """admin shutdown/startup dedicated case (previously only indirect coverage): shutdown -> ASIC ADMIN_STATE
    false -> chip PC_PORT.ENABLE=0; startup does the reverse."""
    chip.require()
    p = phys_port.name
    oid = _port_oid(cli, p)
    key = _asic_port_key(asicdb, oid)
    assert key, f"no ASIC PORT object for {p}"
    rc, r = cli.config_raw(f"interface shutdown {p}")
    assert rc == 0, f"shutdown rejected: {(r.out or '') + (r.err or '')}"
    config_guard.defer_undo(f"interface startup {p}")
    okA, val = _wait_asic_attr(cli, key, "SAI_PORT_ATTR_ADMIN_STATE",
                               lambda v: v.lower() == "false", timeout=30)
    assert okA, f"ASIC ADMIN_STATE stayed {val} after shutdown"
    okC, ent = chip.wait_field(lambda: chip.pc_port(p), "ENABLE",
                               lambda v: v == 0, timeout=30)
    assert okC, f"chip PC_PORT.ENABLE stayed {(ent or {}).get('ENABLE')} after shutdown"
    rc, r = cli.config_raw(f"interface startup {p}")
    assert rc == 0, f"startup rejected: {(r.out or '') + (r.err or '')}"
    okA2, val2 = _wait_asic_attr(cli, key, "SAI_PORT_ATTR_ADMIN_STATE",
                                 lambda v: v.lower() == "true", timeout=30)
    assert okA2, f"ASIC ADMIN_STATE stayed {val2} after startup"
    okC2, ent2 = chip.wait_field(lambda: chip.pc_port(p), "ENABLE",
                                 lambda v: v == 1, timeout=30)
    assert okC2, f"chip PC_PORT.ENABLE stayed {(ent2 or {}).get('ENABLE')} after startup"


# ---------------------------------------------------------------------------
# FEC capability reporting supplement: STATE_DB supported_fecs sanity.
# ---------------------------------------------------------------------------
def test_supported_fecs_reported_sanely(cli, dut, statedb):
    """Every admin-up Ethernet port must report a **non-empty and valid** supported_fecs in STATE_DB.

    A malformed FEC capability set (e.g. declaring multiple modes that are all NONE) makes orchagent, after
    getting a capability that doesn't match the config, neither cache nor back off but repeatedly re-query,
    forming a query storm that slows convergence and floods the log. Capability reporting itself has no direct
    functional-plane symptom, so it must be watched specifically. The criterion is the loosest possible: non-empty,
    and not "all none" (that amounts to declaring the port supports no FEC at all, contradicting the fact that
    400G/800G force RS)."""
    import re as _re
    bad = []
    checked = 0
    for p in dut.ports:
        if not _re.match(r"Ethernet\d+$", p.name):
            continue
        cfg = cli.db_hgetall("CONFIG_DB", f"PORT|{p.name}") or {}
        if (cfg.get("admin_status") or "").lower() != "up":
            continue
        st = cli.db_hgetall("STATE_DB", f"PORT_TABLE|{p.name}") or {}
        if not st:
            continue
        checked += 1
        v = (st.get("supported_fecs") or "").strip()
        modes = [m.strip().lower() for m in v.split(",") if m.strip()]
        if not modes:
            bad.append(f"{p.name}=<empty>")
        elif set(modes) == {"none"}:
            bad.append(f"{p.name}={v}")
    if not checked:
        pytest.skip("no admin-up Ethernet port exposes STATE_DB PORT_TABLE")
    assert not bad, (
        f"{len(bad)}/{checked} ports report a degenerate FEC capability set: "
        f"{bad[:8]}. A capability answer that never matches the configured FEC "
        f"makes orchagent re-query without caching or backoff, flooding sairedis "
        f"and delaying buffer programming. Fix the SAI capability getter rather "
        f"than the symptom.")
