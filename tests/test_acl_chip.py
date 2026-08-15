"""Comprehensive chip-level ACL verification (L3 IPv4 all-fields + MAC L2 all-fields + counter + DROP/FORWARD + dataplane drop).

Design goal (user emphasis: surface real defects, not inflate pass rate):
  The real value of ACL lies in **chip hardware classification match + action execution**. This
  suite verifies more than the CONFIG_DB contract: it asserts the **real ASIC_DB ACL_ENTRY is
  programmed** (syncd only creates that object when the SAI create succeeds), checks per-field that
  the corresponding SAI_ACL_ENTRY_ATTR_FIELD_* is set; the counter check validates the SAI
  ACL_COUNTER object + COUNTERS_DB mapping; the action check verifies DROP/FORWARD is pushed down;
  and it runs **real traffic** to verify the DROP rule intercepts matching frames in the dataplane
  (egress-port chip TX does not increment).

Legal input paths (never use bcmsh/bcmcmd to poke chip tables and force a pass):
  - L3 table: `config acl add table <name> L3 -s ingress -p <port>` (SONiC CLI; -s=stage, -p=port).
  - MAC/L2 table: CONFIG_DB ACL_TABLE_TYPE custom type + ACL_TABLE (legal CONFIG_DB write).
  - Rules: CONFIG_DB ACL_RULE write (consumed by aclorch -> SAI), i.e. the push-down path under test.
  - Dataplane: scapy injection via loopback (traffic / _lb fixture).
  - bcmcmd is only used elsewhere for read-only chip-state cross-checks; this file does not read the
    chip, it asserts ASIC_DB + chip port counters directly.

Prints/assert/skip in English; comments in English. Ports/VLAN taken from topo.
"""
import time

import pytest

from framework import acl

pytestmark = [pytest.mark.acl]

# Self-created object names (FVT prefix, fully cleaned in teardown, to avoid clashing with other ACL cases / system default tables)
_TBL_L3 = "FVT_CHIP_L3"
_TBL_MAC = "FVT_CHIP_MAC"
_MAC_TYPE = "FVT_CHIP_L2TYPE"


# ----------------------------- CONFIG_DB primitives -----------------------------
def _db_hset(cli, db, key, **fields):
    parts = " ".join(f"'{k}' '{v}'" for k, v in fields.items())
    return cli.sh.run(f"sonic-db-cli {db} HSET '{key}' {parts}", check=False)


def _db_del(cli, db, key):
    return cli.sh.run(f"sonic-db-cli {db} DEL '{key}'", check=False)


def _acl_entries(asicdb):
    return asicdb.objects("SAI_OBJECT_TYPE_ACL_ENTRY")


def _acl_entry_count(cli):
    return len(cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"))


_TBL_KEY_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:"


def _acl_table_keys(cli):
    """Current set of ASIC ACL_TABLE keys (sample as a baseline before table creation; the set difference locates this case's self-created table OID)."""
    return set(cli.db_keys("ASIC_DB", f"{_TBL_KEY_PREFIX}*"))


def _new_table_oids(cli, base_keys):
    """Pre-creation baseline set -> set difference yields this table's OID (form oid:0x..., used to reverse-look-up entry TABLE_ID ownership)."""
    return {k.split(_TBL_KEY_PREFIX, 1)[-1] for k in _acl_table_keys(cli) - base_keys}


def _sai_value_matches(cli, entry, sai_field, field, value):
    """Whether the entry's sai_field value carries the value **configured by this case** (not just that the field exists, but the value matches).

    For RANGE-class fields the entry value is a list of ACL_RANGE oids; reverse-look-up the SAI
    ACL_RANGE object's LIMIT interval and TYPE direction (two RANGE parameters map to the same SAI
    field, so only the interval value distinguishes this rule from a leftover entry)."""
    raw = str(entry.get(sai_field, ""))
    if not raw or "disable" in raw.lower():
        return False
    if field.endswith("_RANGE"):
        lo, hi = str(value).split("-")
        body = raw.split(":", 1)[-1] if raw[:1].isdigit() else raw   # "1:oid:0x.." -> "oid:0x.."
        for tok in body.split(","):
            tok = tok.strip()
            if not tok.startswith("oid:"):
                continue
            ro = cli.db_hgetall("ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_ACL_RANGE:{tok}")
            limit = str(ro.get("SAI_ACL_RANGE_ATTR_LIMIT", ""))
            rtyp = str(ro.get("SAI_ACL_RANGE_ATTR_TYPE", ""))
            if lo in limit and hi in limit and (not rtyp or field in rtyp):
                return True
        return False
    if field == "IP_TYPE":
        # Enum value: ipv4any -> SAI_ACL_IP_TYPE_IPV4ANY (strip underscores, case-insensitive containment)
        return str(value).replace("_", "").lower() in raw.replace("_", "").lower()
    head = raw.split("&")[0].strip()      # "10.1.1.0&mask:255.255.255.0" -> "10.1.1.0"
    want = str(value).split("/")[0]       # "10.1.1.0/24"->"10.1.1.0"; "0x10/0x10"->"0x10"
    if head.lower() == want.lower():
        return True
    try:
        return int(head, 0) == int(want, 0)   # numeric equivalence, e.g. 2048 == 0x800
    except ValueError:
        return False


def _entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value):
    """Among the ACL_ENTRY objects of **this case's self-created table** (SAI_ACL_ENTRY_ATTR_TABLE_ID
    in tbl_oids), find the one whose sai_field value matches the configured value. Returns the field
    dict or None.

    Fixes a false pass (following test_acl_egress_l2's table-OID set-difference method): without
    restricting the table domain and without checking field values, system-preset / leftover entries
    often carry same-named fields like IP_PROTOCOL/ETHER_TYPE/ACL_IP_TYPE/OUTER_VLAN_ID, so any hit
    falsely passes."""
    for e in _acl_entries(asicdb):
        d = cli.db_hgetall("ASIC_DB", e)
        if str(d.get("SAI_ACL_ENTRY_ATTR_TABLE_ID", "")) not in tbl_oids:
            continue
        if _sai_value_matches(cli, d, sai_field, field, value):
            return d
    return None


def _wait_entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value, tries=24, interval=0.5):
    for _ in range(tries):
        d = _entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value)
        if d:
            return d
        time.sleep(interval)
    return None


def _accum_tx_pkt(traffic, port, floor=None, window=3.0):
    """Poll and incrementally accumulate the port's chip TX delta, plus a confirmation read (same pattern as smoke_check).

    `show c` has "delta since last read" semantics: a single read after a fixed sleep can miss counts
    that land late via DMA, so a negative assertion (should not forward) reading 0 -> a non-effective
    ACL also passes falsely. When floor is given (positive control), converge early once the
    accumulation reaches the lower bound; on the negative side pass no floor, read the whole window +
    a confirmation read."""
    total = 0
    deadline = time.time() + window
    while time.time() < deadline:
        time.sleep(0.4)
        total += traffic.chip_counters(port).tx_pkt
        if floor is not None and total >= floor:
            break
    time.sleep(0.4)
    total += traffic.chip_counters(port).tx_pkt
    return total


# ----------------------------- table-binding warmup -----------------------------
def _wait_table_bound(cli, table, tries=40, interval=0.5):
    """Binding a table to the ASIC after creation is asynchronous: use a warmup rule and wait until a
    new ACL_ENTRY actually appears in the ASIC, then delete the warmup.
    Returns True=table is bound in hardware (later field cases can truly verify); False=table not bound
    (callers skip accordingly, to avoid misjudging field failures)."""
    base = _acl_entry_count(cli)
    # Rule goes through the image-adaptive channel (orchagent does not consume a bare HSET; the built-in acl-rule CLI is required)
    acl.add_l3_rule(cli, table, "WARMUP", priority="9999", action="DROP", SRC_IP="1.2.3.0/24")
    ok = False
    for _ in range(tries):
        if _acl_entry_count(cli) > base:
            ok = True
            break
        time.sleep(interval)
    acl.del_l3_rule(cli, table, "WARMUP")
    time.sleep(1.5)
    return ok


# ----------------------------- table fixtures -----------------------------
@pytest.fixture(scope="module")
def l3_table(cli, topo):
    """Create an ingress L3(IPv4) ACL table via legal CLI; wait until bound; teardown deletes the table + leftover rules.

    Note: in `config acl add table`, `-s` is the stage and `-p` is the port list. Earlier, mistakenly
    writing `-p ingress` treated "ingress" as a port name -> table creation errored out (the table was
    never created), masking the real defect. The correct form uses `-s ingress` to specify the stage
    and `-p <real port>` to bind the port, so the table enters CONFIG_DB normally, pinpointing failures
    to "table entered CONFIG_DB but was not bound to the ASIC"."""
    bind_port = topo.misc_port(0).name
    base_tbls = _acl_table_keys(cli)   # sample ASIC ACL_TABLE baseline before creation; set difference locates this table's OID
    cli.config_raw(f"acl add table {_TBL_L3} L3 -s ingress -p {bind_port}")
    time.sleep(2)
    bound = _wait_table_bound(cli, _TBL_L3)
    yield _TBL_L3, bound, _new_table_oids(cli, base_tbls)
    for k in cli.db_keys("CONFIG_DB", f"ACL_RULE|{_TBL_L3}|*"):
        acl.del_l3_rule(cli, _TBL_L3, k.split("|")[-1])
    cli.config_raw(f"acl remove table {_TBL_L3}")
    _db_del(cli, "CONFIG_DB", f"ACL_TABLE|{_TBL_L3}")
    time.sleep(1)


@pytest.fixture(scope="module")
def mac_table(cli, topo):
    """L2/MAC ACL table (image-adaptive); wait until bound; teardown deletes the table + type + leftover rules.

    The creation method is auto-selected by framework.acl per image: SONiC uses the built-in
    `config acl-table add -t L2`; the community build keeps the CONFIG_DB custom ACL_TABLE_TYPE path.
    The case side is oblivious to the difference."""
    bind_port = topo.misc_port(0).name
    base_tbls = _acl_table_keys(cli)   # sample baseline before creation; set difference locates this table's OID
    type_name = acl.add_mac_table(cli, _TBL_MAC, bind_port)
    time.sleep(2)
    bound = acl.wait_mac_table_bound(cli, _TBL_MAC)
    yield _TBL_MAC, bound, _new_table_oids(cli, base_tbls)
    acl.remove_mac_table(cli, _TBL_MAC, type_name)
    time.sleep(1)


# ----------------------------- field matrix -----------------------------
# L3(IPv4) table all match fields: (CONFIG_DB ACL_RULE field, value, expected SAI ACL_ENTRY field)
L3_FIELDS = [
    ("SRC_IP",            "10.1.1.0/24", "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP"),
    ("DST_IP",            "20.1.1.0/24", "SAI_ACL_ENTRY_ATTR_FIELD_DST_IP"),
    ("IP_PROTOCOL",       "6",           "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL"),
    ("L4_SRC_PORT",       "1234",        "SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT"),
    ("L4_DST_PORT",       "80",          "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT"),
    ("DSCP",              "46",          "SAI_ACL_ENTRY_ATTR_FIELD_DSCP"),
    ("TCP_FLAGS",         "0x10/0x10",   "SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS"),
    ("IP_TYPE",           "ipv4any",     "SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE"),
    ("L4_SRC_PORT_RANGE", "1000-2000",   "SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE"),
    ("L4_DST_PORT_RANGE", "3000-4000",   "SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE"),
]

# MAC(L2) table all match fields
MAC_FIELDS = [
    ("SRC_MAC",    "00:11:22:33:44:55", "SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC"),
    ("DST_MAC",    "00:aa:bb:cc:dd:ee", "SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC"),
    ("ETHER_TYPE", "2048",              "SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE"),
    ("VLAN_ID",    "100",               "SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID"),
    ("PCP",        "3",                 "SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI"),
]


def _rule_field_check(cli, asicdb, table, bound, tbl_oids, field, value, sai_field):
    """Create a rule matching field, assert **this table's** ASIC ACL_ENTRY truly carries sai_field with the configured value. Delete the rule afterward."""
    if not bound:
        # The table is not bound in the ASIC at all (the warmup rule was not pushed down) -> field cases are moot.
        # Do not hide with skip; fail instead, making "table/rule not reaching hardware" visible.
        pytest.fail(f"ACL table {table} not bound in ASIC (warmup rule never produced ACL_ENTRY) "
                    f"-> user ACL not programmed to hardware")
    if not acl.l3_rule_expressible(cli, field):
        pytest.skip(f"field {field} not expressible via this image's acl-rule CLI "
                    "(no such option; structural, not a defect)")
    if not acl.add_l3_rule(cli, table, f"R_{field}", priority="9000", action="DROP", **{field: value}):
        pytest.skip(f"device declares field {field} unsupported via its acl-rule CLI "
                    "('does not support'; structural capability gate, not a silent defect)")
    try:
        got = _wait_entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value)
        assert got, (f"ACL field {field}={value} not programmed to ASIC "
                     f"(no ACL_ENTRY under this test's table carries {sai_field}={value}); "
                     f"user ACL rule did not reach hardware")
    finally:
        acl.del_l3_rule(cli, table, f"R_{field}")
        time.sleep(0.5)


@pytest.mark.parametrize("field,value,sai_field", L3_FIELDS, ids=[f[0] for f in L3_FIELDS])
def test_acl_l3_field_in_asic(cli, asicdb, l3_table, field, value, sai_field):
    """L3(IPv4) ACL per-field chip programming: create a rule matching the field, verify the real ASIC ACL_ENTRY carries the corresponding SAI field."""
    table, bound, tbl_oids = l3_table
    _rule_field_check(cli, asicdb, table, bound, tbl_oids, field, value, sai_field)


def _mac_rule_field_check(cli, asicdb, table, bound, tbl_oids, field, value, sai_field):
    """MAC rule per-field chip-programming check: add the rule via framework.acl per image (SONiC uses
    the built-in `config acl-rule add`, the community build uses CONFIG_DB HSET), assert **this
    table's** ASIC ACL_ENTRY truly carries sai_field with the configured value."""
    if not bound:
        pytest.fail(f"ACL table {table} not bound in ASIC (warmup rule never produced ACL_ENTRY) "
                    f"-> user MAC ACL not programmed to hardware")
    rule = f"R_{field}"
    acl.add_mac_rule(cli, table, rule, priority="9000", action="DROP", **{field: value})
    try:
        got = _wait_entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value)
        assert got, (f"ACL field {field}={value} not programmed to ASIC "
                     f"(no ACL_ENTRY under this test's table carries {sai_field}={value}); "
                     f"user MAC ACL rule did not reach hardware")
    finally:
        acl.del_mac_rule(cli, table, rule)
        time.sleep(0.5)


@pytest.mark.parametrize("field,value,sai_field", MAC_FIELDS, ids=[f[0] for f in MAC_FIELDS])
def test_acl_mac_field_in_asic(cli, asicdb, mac_table, field, value, sai_field):
    """MAC(L2) ACL per-field chip programming: create a rule matching an L2 field, verify the ASIC ACL_ENTRY carries the corresponding SAI field.
    On SONiC the built-in L2 table + acl-rule CLI should genuinely push it down."""
    table, bound, tbl_oids = mac_table
    _mac_rule_field_check(cli, asicdb, table, bound, tbl_oids, field, value, sai_field)


# ----------------------------- counter coverage -----------------------------
def test_acl_rule_counter_object_in_asic(cli, asicdb, l3_table):
    """Rule with counter: ASIC ACL_ENTRY.ACTION_COUNTER points to an **existing** SAI ACL_COUNTER object.

    Fixes a false pass: no longer scan for "any entry with a counter" (system default groups / leftover
    entries commonly carry ACTION_COUNTER, so this counter failing to be created would still pass) --
    first locate the entry for R_CNT by this table's TABLE_ID + SRC_IP=11.0.0.0, then read **that
    entry's** ACTION_COUNTER, and verify the ACL_COUNTER object's TABLE_ID also points to this table."""
    table, bound, tbl_oids = l3_table
    if not bound:
        pytest.fail(f"ACL table {table} not bound in ASIC -> user ACL not programmed")
    acl.add_l3_rule(cli, table, "R_CNT", priority="8000", action="DROP", SRC_IP="11.0.0.0/8")
    try:
        ent = _wait_entry_with_field(cli, asicdb, tbl_oids,
                                     "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP", "SRC_IP", "11.0.0.0/8")
        assert ent, ("rule R_CNT (SRC_IP=11.0.0.0/8) not found under this test's table in ASIC "
                     "-- user ACL rule not programmed")
        c = str(ent.get("SAI_ACL_ENTRY_ATTR_ACTION_COUNTER", ""))
        assert "oid:" in c and "oid:0x0" not in c, (
            "ACL rule R_CNT entry has no valid SAI_ACL_ENTRY_ATTR_ACTION_COUNTER "
            f"(got {c!r}) -- rule counter not bound in ASIC")
        coid = c[c.find("oid:"):]
        ck = f"ASIC_STATE:SAI_OBJECT_TYPE_ACL_COUNTER:{coid}"
        ch = cli.db_hgetall("ASIC_DB", ck)
        assert ch, f"referenced ACL_COUNTER object {coid} does not exist"
        assert str(ch.get("SAI_ACL_COUNTER_ATTR_TABLE_ID", "")) in tbl_oids, (
            f"ACL_COUNTER {coid} TABLE_ID does not point back to this test's table "
            f"(counter belongs to another table)")
    finally:
        acl.del_l3_rule(cli, table, "R_CNT")
        time.sleep(0.5)


def test_acl_counter_in_countersdb(cli, l3_table):
    """ACL counter enters COUNTERS_DB ACL_COUNTER_RULE_MAP (prerequisite for aclshow / statistics being readable)."""
    table, bound, _tbl_oids = l3_table
    if not bound:
        pytest.fail(f"ACL table {table} not bound in ASIC -> user ACL not programmed")
    acl.add_l3_rule(cli, table, "R_CNT2", priority="7999", action="DROP", SRC_IP="12.0.0.0/8")
    try:
        ok = False
        for _ in range(20):
            if cli.db_keys("COUNTERS_DB", "ACL_COUNTER_RULE_MAP"):
                m = cli.db_hgetall("COUNTERS_DB", "ACL_COUNTER_RULE_MAP")
                if any("R_CNT2" in k for k in m):
                    ok = True
                    break
            time.sleep(0.5)
        assert ok, ("ACL rule counter not in COUNTERS_DB ACL_COUNTER_RULE_MAP "
                    "(statistics unreadable) -- user ACL counter not programmed")
    finally:
        acl.del_l3_rule(cli, table, "R_CNT2")
        time.sleep(0.5)


# ----------------------------- action coverage -----------------------------
@pytest.mark.parametrize("action,sai_action", [
    ("DROP",    "SAI_PACKET_ACTION_DROP"),
    ("FORWARD", "SAI_PACKET_ACTION_FORWARD"),
])
def test_acl_action_in_asic(cli, asicdb, l3_table, action, sai_action):
    """ACL action chip programming: DROP/FORWARD rules land in ASIC ACL_ENTRY with PACKET_ACTION at the expected value.

    Restrict to this table's TABLE_ID + DST_IP=30.0.0.0 value match to exclude leftover-entry false passes."""
    table, bound, tbl_oids = l3_table
    if not bound:
        pytest.fail(f"ACL table {table} not bound in ASIC -> user ACL not programmed")
    acl.add_l3_rule(cli, table, f"R_ACT_{action}", priority="6000", action=action,
                    DST_IP="30.0.0.0/8")
    try:
        match = None
        for _ in range(24):
            d = _entry_with_field(cli, asicdb, tbl_oids,
                                  "SAI_ACL_ENTRY_ATTR_FIELD_DST_IP", "DST_IP", "30.0.0.0/8")
            if d and sai_action in str(d.get("SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION", "")):
                match = d
                break
            time.sleep(0.5)
        assert match, (f"ACL action={action} rule not programmed to ASIC with "
                       f"{sai_action} (no entry under this test's table carries "
                       f"DST_IP=30.0.0.0 + {sai_action}) -- user ACL not reaching hardware")
    finally:
        acl.del_l3_rule(cli, table, f"R_ACT_{action}")
        time.sleep(0.5)


# ----------------------------- dataplane DROP hit -----------------------------
@pytest.mark.traffic
def test_acl_l3_drop_dataplane(cli, traffic, topo, l3_table, l2_fwd_vlan):
    """L3 DROP rule **dataplane** hit (real traffic, end-to-end):
      FDB unicasts the destination MAC to the egress port pout; the ACL creates a DROP UDP/dport=4444 rule at ingress.
      - matching frames (UDP/4444) should be DROPped by the chip -> pout chip TX **does not grow**;
      - non-matching frames (UDP/5555) should forward normally -> pout chip TX grows (control, proving the topology itself can forward);
      - after deleting the rule the same matching frame should resume forwarding (chip entry truly reclaimed, guarding against orch-delete-out-of-sync leftover DROP).
    Assert the difference among the three, proving the ACL truly intercepts in the hardware dataplane."""
    from scapy.all import Ether, IP, UDP, Raw
    _mod_table, bound, _tbl_oids = l3_table
    pin, pout = traffic.ports[0], traffic.ports[1]
    # As in test_acl_fields: the module table binds the misc port, so the ACL cannot see traffic injected from pin (bind-port mismatch).
    # Create a dedicated table bound to pin for dataplane verification.
    table = "FVT_ACL_DP2"
    cli.config_raw(f"acl add table {table} L3 -s ingress -p {pin.name}")
    time.sleep(2)
    dmac, smac = topo.mac("dst"), topo.mac("src")
    # Use the real test VLAN for L2 forwarding, dvlan = l2_fwd_vlan
    n = 100

    cli.fdb_static_add(dvlan, dmac, pout.name)
    # Match condition: L4_DST_PORT=4444 + IP_PROTOCOL=17(UDP), action DROP (image-adaptive channel)
    acl.add_l3_rule(cli, table, "R_DP", priority="5000", action="DROP",
                    IP_PROTOCOL="17", L4_DST_PORT="4444")
    time.sleep(3)
    traffic.loop(pout)
    try:
        if not bound:
            pytest.fail(f"ACL table {table} not bound in ASIC -> DROP rule cannot take effect "
                        f"in dataplane")
        # Control baseline: non-matching frames (UDP/5555) should forward normally to pout (proving FDB/topology can forward, ruling out environment issues)
        # Counting goes clear -> poll-accumulate + confirmation read (show c delta semantics); positive control adds a storm upper bound
        good = Ether(dst=dmac, src=smac) / IP() / UDP(dport=5555) / Raw(b"x" * 40)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, good, count=n)
        d_good = _accum_tx_pkt(traffic, pout, floor=n * 0.8)
        assert n * 0.8 <= d_good < n + 3000, (
            f"baseline non-matching traffic abnormal on {pout.name} "
            f"(TX+{d_good}, expected ~{n}); forwarding broken or storm, cannot judge ACL")

        # Matching frames (UDP/4444) should be ACL-DROPped -> pout TX essentially does not grow (negative side reads the full window, guarding against under-count false pass)
        match = Ether(dst=dmac, src=smac) / IP() / UDP(dport=4444) / Raw(b"x" * 40)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, match, count=n)
        d_match = _accum_tx_pkt(traffic, pout)
        assert d_match <= n * 0.1, (
            f"ACL DROP not enforced in dataplane: matching UDP/4444 traffic still forwarded "
            f"to {pout.name} (TX+{d_match} of {n}); user ACL DROP not programmed to hardware")

        # Third stage: after deleting the rule the same matching traffic should **resume forwarding** (verifying the chip DROP entry is truly reclaimed --
        # the out-of-sync defect where CONFIG_DB is deleted but orch-delete lags and leaves a hardware entry is exposed here)
        base_ent = _acl_entry_count(cli)
        acl.del_l3_rule(cli, table, "R_DP")
        end = time.time() + 12
        while time.time() < end and _acl_entry_count(cli) >= base_ent:
            time.sleep(0.5)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, match, count=n)
        d_restored = _accum_tx_pkt(traffic, pout, floor=n * 0.8)
        assert n * 0.8 <= d_restored < n + 3000, (
            f"forwarding did not recover after ACL rule deletion: matching UDP/4444 still "
            f"blocked to {pout.name} (TX+{d_restored} of {n}); stale DROP entry left on chip "
            f"(orch delete out of sync)")
    finally:
        traffic.unloop(pout)
        acl.del_l3_rule(cli, table, "R_DP")
        if cli._acl_table_cli():
            cli.config_raw(f"acl remove table {table}")
        cli.sh.run(f"sonic-db-cli CONFIG_DB DEL 'ACL_TABLE|{table}'", check=False)
        cli.fdb_static_del(dvlan, dmac)
