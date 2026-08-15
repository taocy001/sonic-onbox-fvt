"""SAI regression nails -- each one corresponds to a class of regression failure mode.

Common trait of these regressions: **no error log at all after the regression**, the config layer and ASIC_DB
look entirely correct, and only the chip tables or "send traffic after the event" can expose them. Ordinary cases
all "configure then send traffic" and cannot catch them.

| Case | Symptom after regression |
|------|-------------|
| LF1/LF2 | after a link flap the bridge port is a complete L2 black hole (learns no MAC, does not forward) |
| LF3     | after a routed port flaps it wrongly gets learn enabled, polluting the FDB |
| FX1     | after changing one subport's speed the **sibling subport** silently loses lossless/PFC |
| HS1     | the configured hash fields reach the DB but not the chip, ECMP/LAG all go through a single member |

Port usage: the LF group uses l2-role ports (e/f), the FX group uses ports at the tail of the port table (same
domain as the breakout group, so this file does not run in the same round as the breakout group), the HS group is read-only.
"""
import re
import time

import pytest

pytestmark = [pytest.mark.chiptab, pytest.mark.l2]

try:
    from scapy.all import Ether, IP, UDP, Raw, sendp  # noqa: F401
    _SCAPY = True
except Exception:  # noqa: BLE001
    _SCAPY = False

_N = 60


def _learn_bit(chip, port):
    """Chip port-level learning enable bit (PORT_LEARN.MAC_LEARN). Returns None if the table/field is missing."""
    if not chip.has_table("PORT_LEARN"):
        return None
    ent = chip.lookup("PORT_LEARN", PORT_ID=chip.port_id(port))
    return None if ent is None else ent.get("MAC_LEARN")


def _flap(cli, port, settle=6):
    cli.config_raw(f"interface shutdown {port}")
    time.sleep(2)
    cli.config_raw(f"interface startup {port}")
    time.sleep(settle)


# ============================ LF: learn replay after a link flap ============================
def test_lf1_bridge_port_learn_survives_link_flap(cli, chip, topo, l2_fwd_vlan):
    """LF1 (regression nail): after a bridge port goes through shutdown/startup, the chip port-level
    learning bit must return to the enabled state.

    On regression ASIC_DB still reports LEARNING_MODE_HW, admin=true, and only the chip PORT_LEARN.MAC_LEARN
    drops to 0 -- this is exactly the chip-level evidence of the "silent L2 black hole"."""
    chip.require()
    port = topo.l2_port(0).name
    cli.config_raw(f"vlan member add -u {l2_fwd_vlan} {port}")
    cli.config_raw(f"interface startup {port}")
    time.sleep(4)
    before = _learn_bit(chip, port)
    if before is None:
        pytest.skip("chip PORT_LEARN table/field unavailable on this device")
    if before != 1:
        pytest.skip(f"port {port} does not have learning enabled before the flap "
                    f"(MAC_LEARN={before}); not a valid starting point for this nail")
    try:
        _flap(cli, port)
        ok, ent = chip.wait_field(lambda: chip.lookup(
            "PORT_LEARN", PORT_ID=chip.port_id(port)), "MAC_LEARN",
            lambda v: v == 1, timeout=30)
        assert ok, (
            f"chip PORT_LEARN.MAC_LEARN for {port} stayed "
            f"{(ent or {}).get('MAC_LEARN')} after a link flap (was {before}); the "
            f"bridge-port learn intent was not replayed on link up -> this port is an "
            f"L2 black hole with no error logged anywhere")
    finally:
        cli.config_raw(f"vlan member del {l2_fwd_vlan} {port}")


@pytest.mark.traffic
def test_lf2_mac_learning_works_after_link_flap(cli, chip, traffic, l2_fwd_vlan):
    """LF2 (same as above, behavior level): send traffic again after the flap; the MAC must still be learnable and frames must still be forwarded.

    This is the class that "configure then send traffic" cannot catch: first prove learning works, then flap, then resend -- both must hold."""
    if not _SCAPY:
        pytest.skip("scapy unavailable")
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    src = "00:de:ad:be:ef:1f"
    pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=src)
           / IP(dst="2.2.2.2") / UDP() / Raw(b"LF2" + b"x" * 40))

    def _learned():
        out = cli.sh.run(f"show mac -v {l2_fwd_vlan}", check=False).out or ""
        return src.lower() in out.lower()

    cli.sh.run("sonic-clear fdb all", check=False)
    time.sleep(2)
    traffic.send(p_in, pkt, count=_N)
    time.sleep(3)
    if not _learned():
        pytest.skip(f"MAC not learned even before the flap (VLAN {l2_fwd_vlan}); "
                    "baseline learning path unavailable, nail cannot judge the flap")

    cli.sh.run("sonic-clear fdb all", check=False)
    _flap(cli, p_in.name)
    traffic.loop(p_in)          # the flap turned off loopback, re-enable it
    time.sleep(3)
    traffic.send(p_in, pkt, count=_N)
    got = False
    for _ in range(10):
        if _learned():
            got = True
            break
        time.sleep(1)
    assert got, (
        f"{src} was learned on {p_in.name} before the flap but not "
        f"after shutdown/startup; the port stopped learning silently (ASIC_DB still "
        f"reports LEARNING_MODE_HW) -- bridge-port learn intent not replayed on link "
        f"up")


def test_lf3_routed_port_stays_unlearned_after_flap(cli, chip, topo):
    """LF3 (negative nail): after a routed port flaps it **must not** get learning enabled -- baseline restore should only act on
    bridge ports. On regression the routed port starts learning MACs, polluting the FDB."""
    chip.require()
    port = topo.misc_port(1).name
    sub = topo.subnet("d")
    cli.config_raw(f"interface ip add {port} {sub['dut']}/{sub['prefix']}")
    time.sleep(4)
    try:
        before = _learn_bit(chip, port)
        if before is None:
            pytest.skip("chip PORT_LEARN unavailable")
        _flap(cli, port)
        after = None
        for _ in range(10):
            after = _learn_bit(chip, port)
            if after is not None:
                break
            time.sleep(2)
        assert after != 1 or before == 1, (
            f"routed port {port} had MAC_LEARN={before} before the flap "
            f"and {after} after it; the link-up learn baseline must not touch "
            f"non-bridge ports -- learning on a routed port pollutes the "
            f"FDB")
    finally:
        cli.config_raw(f"interface ip remove {port} {sub['dut']}/{sub['prefix']}")


# ============================ FX: sibling subport after a whole-core flex ============================
def _pg_snapshot(chip, ports, pgs=range(8)):
    snap = {}
    for p in ports:
        bits = {}
        for pg in pgs:
            ent = chip.pg_flags(p, pg)
            if ent:
                bits[pg] = (ent.get("LOSSLESS"), ent.get("PFC"))
        snap[p] = bits
    return snap


@pytest.mark.breakout
def test_fx1_sibling_pg_state_survives_per_core_flex(cli, chip, dut, bdrv, topo):
    """FX1 (regression nail): after changing the speed of **one** subport (triggering a whole-core flex),
    the **sibling subport's** PG lossless/PFC bits must stay unchanged.

    On regression only the port whose speed was changed is fine, and the sibling silently loses lossless and PFC -- the field
    symptom is "configured lossless but drops packets", appearing only on some subports."""
    chip.require()
    topo.caps.require("breakout_dpb")
    cands = [p for p in dut.ports if re.match(r"Ethernet\d+$", p.name)]
    base = cands[-1].name
    from framework import breakout as BK
    modes = BK.platform_modes(dut, base)
    mode2 = next((m for m in sorted(modes) if m.startswith("2x") and "(" not in m), None)
    if not mode2:
        pytest.skip(f"no 2x breakout mode for {base}: {sorted(modes)}")
    restore = bdrv.current_mode(base) or "1x800G"
    res = bdrv.split(base, mode2)
    if not res["ok"]:
        pytest.skip(f"cannot split {base} to set up the flex nail: {res['text']}")
    subs = [n for n, _, _ in res["subports"]]
    try:
        time.sleep(5)
        snap0 = _pg_snapshot(chip, subs)
        target, sibling = subs[0], subs[1]
        cur = (cli.db_hgetall("CONFIG_DB", f"PORT|{target}") or {}).get("speed")
        sup = ((cli.db_hgetall("STATE_DB", f"PORT_TABLE|{target}") or {})
               .get("supported_speeds") or "")
        alt = next((s for s in sup.split(",")
                    if s.strip().isdigit() and s.strip() != cur), None)
        if not alt:
            pytest.skip(f"no alternative speed on {target} (supported={sup!r}); "
                        "cannot trigger a per-core flex")
        rc, r = cli.config_raw(f"interface speed {target} {alt}")
        time.sleep(12)
        chip.invalidate()
        snap1 = _pg_snapshot(chip, subs)
        cli.config_raw(f"interface speed {target} {cur}")
        time.sleep(12)
        chip.invalidate()
        snap2 = _pg_snapshot(chip, subs)
        drift = {p: (snap0[p], snap1[p], snap2[p])
                 for p in subs
                 if not (snap0[p] == snap1[p] == snap2[p])}
        assert not drift, (
            f"PG lossless/PFC state changed across a per-core flex "
            f"(changed speed of {target} only). before/after/restored per port: "
            f"{drift}; sibling ports must keep their PG buffer + PFC state")
    finally:
        m = bdrv.merge(base, restore)
        assert m["ok"], (f"CLEANUP FAILURE: merge {base} back to {restore} failed: "
                         f"{m['text']}")


# ============================ HS: hash fields really reach the chip ============================
def test_hs1_default_hash_objects_exist(cli, chip, asicdb):
    """HS1 (regression nail): the default ECMP and LAG hash objects must exist, and the chip's
    hash-field selection tables must be programmed (not all-zero).

    Criterion notes:
    - If the image **lacks the `config switch-hash` CLI**, SONiC never sets SAI_SWITCH_ATTR_ECMP_HASH,
      so "the switch attribute exists" cannot be used as the criterion -- that would only misreport. The observable
      artifact is the **two SAI_OBJECT_TYPE_HASH objects** (default ECMP + default LAG), created at switch init.
    - The chip-side hash-field selection is spread across several LB_HASH_*_SELECTION tables; take the ones that exist
      and verify "at least one is programmed non-zero", i.e. the hash fields really reached the hardware.
    - On regression: the HASH object count is 0 and the chip selection tables are all-zero -> all ECMP/LAG traffic
      goes through a single member (symptom is uneven load, not an error)."""
    chip.require()
    hashes = asicdb.objects("SAI_OBJECT_TYPE_HASH")
    assert len(hashes) >= 2, (
        f"expected the default ECMP + LAG hash objects created at "
        f"switch init, found {len(hashes)} SAI_OBJECT_TYPE_HASH object(s): {hashes}; "
        f"without them the hash field list can never reach the chip")

    if cli.sh.run("config switch-hash --help", check=False).rc == 0:
        sw = asicdb.objects("SAI_OBJECT_TYPE_SWITCH")
        attrs = cli.db_hgetall("ASIC_DB", sw[0]) if sw else {}
        for a_name in ("SAI_SWITCH_ATTR_ECMP_HASH", "SAI_SWITCH_ATTR_LAG_HASH"):
            v = (attrs or {}).get(a_name)
            assert v and v != "oid:0x0", (
                f"image has a switch-hash CLI but {a_name} is {v!r}; the configured "
                f"hash never reached SAI")
    else:
        print("NOTE: no `config switch-hash` CLI, so SONiC never sets "
              "SAI_SWITCH_ATTR_ECMP_HASH/LAG_HASH; judging on the default hash "
              "objects and the chip selection tables instead")

    sel = [t for t in ("LB_HASH_IPV4_TCP_UDP_PORTS_EQUAL_FIELDS_SELECTION",
                       "LB_HASH_IPV6_TCP_UDP_FIELDS_SELECTION",
                       "LB_HASH_VXLAN_L3_PAYLOAD_FIELDS_SELECTION")
           if chip.has_table(t)]
    if not sel:
        print("NOTE: no LB_HASH_*_SELECTION table on this chip; ASIC-object evidence only")
        return
    programmed = {}
    for t in sel:
        ents = chip.traverse(t)
        programmed[t] = sum(
            1 for e in ents
            if any(isinstance(v, int) and v != 0
                   for f, v in e.items() if f != "OPERATIONAL_STATE"))
    assert any(programmed.values()), (
        f"every chip hash selection table is all-zero {programmed}; "
        f"no hash field selection is programmed although the default hash objects "
        f"exist -- ECMP/LAG would put every flow on one member")
    print(f"chip hash selection programmed rows: {programmed}")


def test_hs2_ecmp_hash_field_change_reaches_asic(cli, chip, asicdb):
    """HS2 (behavior nail): change the ECMP hash field set via the vendor CLI; the ASIC hash object's
    NATIVE_HASH_FIELD_LIST must follow, and restoring default must follow back too.

    The config channel is `config load-balance ecmp-hash-fields` (not the community `config switch-hash`).
    On regression the field set stays only in the CLI/DB layer and the ASIC object doesn't budge, so ECMP hashes on
    the old field set -- the load distribution doesn't match expectations without any error."""
    chip.require()
    if cli.sh.run("config load-balance ecmp-hash-fields --help",
                  check=False).rc != 0:
        pytest.skip("no `config load-balance ecmp-hash-fields`")

    def _lists():
        out = {}
        for k in asicdb.objects("SAI_OBJECT_TYPE_HASH"):
            v = (cli.db_hgetall("ASIC_DB", k) or {}).get(
                "SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST", "")
            if v:
                out[k] = v
        return out

    # The precondition only requires the hash **objects** to exist (handles created at switch init) -- it does **not
    # require them to already carry a field list right now**. In the default state the two HASH objects are empty
    # handles ({'NULL':'NULL'}); only after config is pushed does SAI fill in NATIVE_HASH_FIELD_LIST. The old
    # approach required "a field list before configuring", which necessarily fake-fails on a correct implementation.
    objs = asicdb.objects("SAI_OBJECT_TYPE_HASH")
    assert objs, (
        "no SAI_OBJECT_TYPE_HASH object exists at all; without the default "
        "ECMP/LAG hash handles the hash field config can never reach the chip")
    before = _lists()

    narrow = "src-ip,dest-ip,ip-pro"
    cli.config_raw(f"load-balance ecmp-hash-fields {narrow}")
    changed = {}
    for _ in range(10):
        changed = _lists()
        if any(v.startswith("3:") for v in changed.values()):
            break
        time.sleep(1)
    try:
        assert any(v.startswith("3:") for v in changed.values()), (
            f"after `ecmp-hash-fields {narrow}` no ASIC hash object "
            f"reports a 3-field list; before={before}, after={changed} -- the field "
            f"set stayed in the CLI/DB layer")
        for v in changed.values():
            if v.startswith("3:"):
                for f in ("SRC_IP", "DST_IP", "IP_PROTOCOL"):
                    assert f in v, f"field {f} missing from programmed list {v!r}"
                assert "L4_SRC_PORT" not in v, (
                    f"L4 ports should have been dropped from the hash but the ASIC "
                    f"list still has them: {v!r}")
    finally:
        cli.config_raw("load-balance ecmp-hash-fields default")
        restored = {}
        for _ in range(10):
            restored = _lists()
            if restored == before:
                break
            time.sleep(1)
        assert restored == before, (
            f"CLEANUP: hash field list did not return to the default: "
            f"before={before}, restored={restored}")


_TC_NAME_TO_NUM = {"BE": 0, "AF1": 1, "AF2": 2, "AF3": 3, "AF4": 4,
                   "EF": 5, "CS6": 6, "CS7": 7}


def test_dt1_default_tc_reaches_asic(cli, chip, asicdb, topo, config_guard):
    """DT1 (regression nail): `config port-qos-map update <port> -d <TC>` must write
    SAI_PORT_ATTR_QOS_DEFAULT_TC onto that port's ASIC object.

    The default TC decides which TC/queue a **packet with no classification basis** (an untagged non-IP frame: no
    DSCP to trust, no PCP to read) lands on. On regression untagged traffic always lands on TC0, and the config
    layer looks entirely normal.

    Note: the attribute is pushed **when the table entry is updated**; merely pre-seeding it in CONFIG_DB and then
    restarting swss does not re-push it, so the case always actively changes the value once."""
    chip.require()
    port = topo.misc_port(0).name
    poid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port}")
    assert poid, f"no COUNTERS oid for {port}"
    key = f"ASIC_STATE:SAI_OBJECT_TYPE_PORT:{poid}"
    orig = (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{port}") or {}).get("default_tc")
    want_name = "AF3" if orig != "AF3" else "AF4"
    want_num = _TC_NAME_TO_NUM[want_name]

    rc, r = cli.config_raw(f"port-qos-map update {port} -d {want_name}")
    text = ((r.out or "") + (r.err or "")).strip()
    if orig:
        config_guard.defer_undo(
            f"port-qos-map update {port} -d {orig}",
            verify=lambda: (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{port}") or {}
                            ).get("default_tc") == orig)
    landed = False
    for _ in range(8):
        if (cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{port}") or {}
                ).get("default_tc") == want_name:
            landed = True
            break
        time.sleep(1)
    assert landed, (
        f"`port-qos-map update {port} -d {want_name}` did not reach "
        f"CONFIG_DB. CLI said: {text[-160:]!r}")

    got = None
    deadline = time.time() + 20
    while time.time() < deadline:
        got = (cli.db_hgetall("ASIC_DB", key) or {}).get(
            "SAI_PORT_ATTR_QOS_DEFAULT_TC")
        if str(got) == str(want_num):
            return
        time.sleep(1)
    pytest.fail(
        f"default TC {want_name} is in CONFIG_DB but ASIC "
        f"SAI_PORT_ATTR_QOS_DEFAULT_TC for {port} is {got!r} (expected {want_num}); "
        f"untagged non-IP traffic will keep landing on TC0")
