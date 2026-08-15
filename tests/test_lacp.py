"""LACP / Port-Channel real-chip behavior: LAG/LAG_MEMBER into ASIC + lag-hash into the SAI HASH object.

Design principle (assert what the chip/orchagent actually did, not a CONFIG_DB echo):
  - Create PortChannel + add member -> assert **ASIC_DB SAI_OBJECT_TYPE_LAG / LAG_MEMBER** is programmed
    (teamd/teamsyncd/orchagent create these objects only when the SAI create succeeds).
  - lag-hash -> assert the NATIVE_HASH_FIELD_LIST of **ASIC_DB SAI_OBJECT_TYPE_HASH** carries the configured fields
    (switchorch pushes lag-hash into the SAI HASH object; this is evidence the chip really does LAG load-balancing on that field set).

Limits of single-device MAC loopback testing (empirically confirmed, see the root cause in test_lag_chip.py):
  min-links / fallback / fast-rate and other LACP protocol-layer knobs cannot be observed under a **single-DUT self-loop** --
  a member receives the LACPDU it sent itself (actor system == partner system), LACP correctly detects the self-loop and refuses to aggregate,
  the PortChannel stays oper-down forever, and the effects of these knobs (member selection / aggregation rate / fallback) cannot show up on the chip or the data plane.
  So these cases no longer fake-pass on a CONFIG_DB echo; they pytest.skip and honestly record "not testable on this bench".
  hash member sharing / MLAG behavior needs a traffic generator / two machines -- out of scope for this framework (single-box on-box), so no cases are written.

Print/assert/skip in English; comments/docstrings in English. Ports/VLANs come from topo, not hard-coded.
"""
import time

import pytest

pytestmark = [pytest.mark.lag]

PC = "PortChannel60"   # SONiC limits the suffix to 1-64 and rejects leading zeros (0080 raises Usage); 60 is valid on both images


def test_lacp_mode_and_members(cli, asicdb, topo, config_guard):
    """LAG + member really reach the chip: create PortChannel -> a SAI LAG object appears in ASIC_DB;
    add a physical port as a member -> a SAI LAG_MEMBER appears in ASIC_DB. Verifying only CONFIG_DB
    would fake-pass (teamd writes CONFIG_DB even on failure), so we assert the chip-side SAI objects are
    programmed before considering the LAG really in effect."""
    member = topo.misc_port(0).name
    dv = topo.default_vlan

    # --- create PortChannel -> ASIC LAG ---
    base_lag = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_LAG:*")
    rc, r = cli.config_raw(f"portchannel add {PC}")
    config_guard.defer_undo(f"portchannel del {PC}")
    assert rc == 0, f"failed to create PortChannel: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"PORTCHANNEL|{PC}"), "no PORTCHANNEL in CONFIG_DB"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_LAG:*", base_lag, timeout=10), \
        "PortChannel created in CONFIG_DB but no SAI_OBJECT_TYPE_LAG programmed to ASIC_DB " \
        "(LAG did not reach the chip)"

    # --- add member -> ASIC LAG_MEMBER (adding a member requires the member MTU to match the PC and the member not to be in a VLAN) ---
    pc_mtu = (cli.db_hgetall("CONFIG_DB", f"PORTCHANNEL|{PC}") or {}).get("mtu", "9100")
    port_mtu = (cli.db_hgetall("CONFIG_DB", f"PORT|{member}") or {}).get("mtu", "9100")
    if port_mtu != pc_mtu:
        cli.config_raw(f"interface mtu {member} {pc_mtu}")
        config_guard.defer_undo(f"interface mtu {member} {port_mtu}")
    cli.config_raw(f"vlan member del {dv} {member}")
    config_guard.defer_undo(f"vlan member add -u {dv} {member}")

    base_mem = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:*")
    rc, r = cli.config_raw(f"portchannel member add {PC} {member}")
    config_guard.defer_undo(f"portchannel member del {PC} {member}")
    assert rc == 0, f"failed to add member {member}: {r.err or r.out}"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:*", base_mem, timeout=10), \
        f"member {member} added in CONFIG_DB but no SAI_OBJECT_TYPE_LAG_MEMBER programmed to " \
        "ASIC_DB (member not bonded into the chip LAG)"
    # Identity-level assertion: the count growth could come from a leftover LAG / another lane -- there must
    # exist a LAG_MEMBER object whose PORT_ID == this member port's OID ("my port really got bonded into the
    # LAG", not "there is one more member somewhere in the world").
    port_oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {member}")
    assert port_oid, f"no COUNTERS_PORT_NAME_MAP oid for {member} (cannot identify member in ASIC)"
    found = False
    deadline = time.time() + 8
    while time.time() < deadline:
        if asicdb.find("SAI_OBJECT_TYPE_LAG_MEMBER", SAI_LAG_MEMBER_ATTR_PORT_ID=port_oid):
            found = True
            break
        time.sleep(0.5)
    assert found, (
        f"LAG_MEMBER count grew but none carries PORT_ID={port_oid} of {member} — "
        "our member was not bonded into the chip LAG")


def _hash_field_lists(cli, asicdb):
    """Read the NATIVE_HASH_FIELD_LIST text of all SAI HASH objects (e.g. '2:SAI_NATIVE_HASH_FIELD_SRC_IP,...')."""
    out = []
    for k in asicdb.objects("SAI_OBJECT_TYPE_HASH"):
        v = cli.db_hgetall("ASIC_DB", k).get("SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST", "")
        if v:
            out.append(str(v))
    return out


def test_lag_hash_config(cli, asicdb, config_guard):
    """LAG hash really reaches the chip and really changes: resolve the HASH object pointed to by
    SAI_SWITCH_ATTR_LAG_HASH, snapshot its baseline field set, configure a **different** set that includes L4
    ports, and assert the LAG hash object's NATIVE_HASH_FIELD_LIST really becomes the requested set
    (switchorch->SAI closed loop, not a CONFIG_DB echo and not a no-op that happens to hit the chip default set).

    teardown restores the global LAG hash to its original set, to avoid polluting later cases (changing the
    global hash without rolling back would alter every subsequent LAG/ECMP).
    The CLI checks against STATE_DB SWITCH_CAPABILITY.LAG_HASH_CAPABLE; skip if unsupported.
    """
    import re as _re
    sw = asicdb.objects("SAI_OBJECT_TYPE_SWITCH")
    lag_oid = cli.db_hgetall("ASIC_DB", sw[0]).get("SAI_SWITCH_ATTR_LAG_HASH") if sw else None

    def _lag_fields():
        # Prefer the LAG-hash-specific object; if it can't be resolved, fall back to scanning all HASH objects (union)
        if lag_oid and lag_oid != "oid:0x0":
            return cli.db_hgetall(
                "ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_HASH:{lag_oid}").get(
                "SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST", "")
        return " ".join(_hash_field_lists(cli, asicdb))

    base = _lag_fields()
    orig_tokens = _re.findall(r"SAI_NATIVE_HASH_FIELD_(\w+)", base)
    want = ["DST_IP", "SRC_IP", "L4_DST_PORT", "L4_SRC_PORT"]
    # Syntax adaptation: the vendor OS uses `config load-balance lag-hash-l3-pkt-fields
    # dest-ip,src-ip,dest-port,src-port`; the community image uses switch-hash.
    if cli.is_switchport_os():
        rc, r = cli.config_raw(
            "load-balance lag-hash-l3-pkt-fields dest-ip,src-ip,dest-port,src-port")
        if rc != 0:
            pytest.skip(f"load-balance lag-hash CLI rejected on this image: "
                        f"{(r.err or r.out)[:160]}")
        config_guard.defer_undo("load-balance lag-hash-l3-pkt-fields default")
    else:
        rc, r = cli.config_raw("switch-hash global lag-hash " + " ".join(want))
        if rc != 0:
            pytest.skip(f"switch-hash lag-hash not supported on this ASIC (LAG_HASH_CAPABLE): "
                        f"{(r.err or r.out)[:160]}")
        if orig_tokens:
            config_guard.defer_undo("switch-hash global lag-hash " + " ".join(orig_tokens))
    # Verify the requested field set really reaches the chip LAG hash object
    got = None
    for _ in range(20):
        f = _lag_fields()
        if all(f"SAI_NATIVE_HASH_FIELD_{x}" in f for x in want):
            got = f
            break
        time.sleep(0.5)
    assert got, ("lag-hash configured but the chip LAG hash object's NATIVE_HASH_FIELD_LIST does not "
                 "carry the requested fields (DST_IP/SRC_IP/L4_DST_PORT/L4_SRC_PORT); config did not reach chip")
    # Real change (not a no-op that hits the default set): when the specific LAG hash OID can be located, assert the field set actually changed
    if lag_oid and lag_oid != "oid:0x0":
        assert got != base, \
            f"LAG hash field list did not change after reconfig (config is a chip no-op): base={base!r}"
