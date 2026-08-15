"""ACL field-level + counter + action coverage (per-field approach modeled on community sonic-mgmt acl/test_acl.py).

Test scope:
- **L3(IPv4) table**: build a rule per match field, verify the ASIC ACL_ENTRY really carries the corresponding SAI field (qset supports that field).
- **MAC(L2) table** (custom ACL_TABLE_TYPE): same, per L2 field.
- **Counters**: rule with a counter, verify SAI_ACL_ENTRY_ATTR_ACTION_COUNTER + a counter object in COUNTERS_DB.
- **action**: DROP/FORWARD programming.
- **Dataplane hit**: the loopback+CPU injection method is polluted for L3 (same as ip2me), so it is marked xfail rather than faking a pass.

The control plane / programming layer (ASIC really carries the field) is reliable: syncd only creates the ASIC object when SAI succeeds.
"""
import time

import pytest

from framework import acl

pytestmark = [pytest.mark.acl]

_TBL_L3 = "FVT_ACL_L3"
_TBL_MAC = "FVT_ACL_MAC"
_MAC_TYPE = "FVT_L2_TYPE"


def _db_hset(cli, db, key, **fields):
    parts = " ".join(f"'{k}' '{v}'" for k, v in fields.items())
    return cli.sh.run(f"sonic-db-cli {db} HSET '{key}' {parts}", check=False)


def _db_del(cli, db, key):
    return cli.sh.run(f"sonic-db-cli {db} DEL '{key}'", check=False)


def _acl_entries(asicdb):
    return asicdb.objects("SAI_OBJECT_TYPE_ACL_ENTRY")


_TBL_KEY_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:"


def _acl_table_keys(cli):
    """Current set of ASIC ACL_TABLE keys (sample a baseline before table creation; the diff locates the OID of this test's own table)."""
    return set(cli.db_keys("ASIC_DB", f"{_TBL_KEY_PREFIX}*"))


def _new_table_oids(cli, base_keys):
    """Pre-creation baseline set -> diff yields this table's OID (form oid:0x..., used to reverse-lookup an entry's TABLE_ID ownership)."""
    return {k.split(_TBL_KEY_PREFIX, 1)[-1] for k in _acl_table_keys(cli) - base_keys}


def _sai_value_matches(cli, entry, sai_field, field, value):
    """Whether the entry's sai_field value carries **the value configured by this test** (not just field presence, but a value match).

    For RANGE-type fields the entry value is a list of ACL_RANGE oids; reverse-lookup the SAI ACL_RANGE object's LIMIT range and
    TYPE direction (both RANGE parameters map to the same SAI field, only the range value distinguishes this rule from a leftover entry)."""
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
        # enum value: ipv4any -> SAI_ACL_IP_TYPE_IPV4ANY (strip underscores, case-insensitive containment)
        return str(value).replace("_", "").lower() in raw.replace("_", "").lower()
    head = raw.split("&")[0].strip()      # "10.1.1.0&mask:255.255.255.0" -> "10.1.1.0"
    want = str(value).split("/")[0]       # "10.1.1.0/24"->"10.1.1.0"; "0x10/0x10"->"0x10"
    if head.lower() == want.lower():
        return True
    try:
        return int(head, 0) == int(want, 0)   # numeric equivalence such as 2048 == 0x800
    except ValueError:
        return False


def _entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value):
    """Among the ACL_ENTRYs of **this test's own table** (SAI_ACL_ENTRY_ATTR_TABLE_ID in tbl_oids), find the one
    whose sai_field value matches the configured value. Returns the field dict or None.

    Fixes false passes (following test_acl_egress_l2's table-OID diff method): without scoping to the table and
    validating the field value, system-preset/leftover entries commonly carry same-named fields like
    IP_PROTOCOL/ETHER_TYPE/ACL_IP_TYPE/OUTER_VLAN_ID, and any hit becomes a false pass."""
    for e in _acl_entries(asicdb):
        d = cli.db_hgetall("ASIC_DB", e)
        if str(d.get("SAI_ACL_ENTRY_ATTR_TABLE_ID", "")) not in tbl_oids:
            continue
        if _sai_value_matches(cli, d, sai_field, field, value):
            return d
    return None


# ---- L3(IPv4) fields: CONFIG_DB ACL_RULE field -> value -> expected SAI ACL_ENTRY field ----
L3_FIELDS = [
    ("SRC_IP",            "10.1.1.0/24", "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP"),
    ("DST_IP",            "20.1.1.0/24", "SAI_ACL_ENTRY_ATTR_FIELD_DST_IP"),
    ("IP_PROTOCOL",       "6",           "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL"),
    ("L4_SRC_PORT",       "1234",        "SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT"),
    ("L4_DST_PORT",       "80",          "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT"),
    ("DSCP",              "10",          "SAI_ACL_ENTRY_ATTR_FIELD_DSCP"),
    ("TCP_FLAGS",         "0x10/0x10",   "SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS"),
    ("IP_TYPE",           "ipv4any",     "SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE"),
    ("L4_SRC_PORT_RANGE", "1000-2000",   "SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE"),
    ("L4_DST_PORT_RANGE", "3000-4000",   "SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE"),
]

# ---- MAC(L2) fields ----
MAC_FIELDS = [
    ("SRC_MAC",    "00:11:22:33:44:55", "SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC"),
    ("DST_MAC",    "00:aa:bb:cc:dd:ee", "SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC"),
    ("ETHER_TYPE", "2048",              "SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE"),
    ("VLAN_ID",    "100",               "SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID"),
    ("PCP",        "3",                 "SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_PRI"),
]


def _acl_entry_count(cli):
    return len(cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"))


def test_acl_user_table_programs_to_asic(cli, topo):
    """After building a user L3 ACL table via a valid CLI + programming one rule through CONFIG_DB, the ASIC's ACL_ENTRY count should grow.

    Note: for `config acl add table`, `-s` is the stage and `-p` is the port. Previously writing `-p ingress`
    treated "ingress" as a port name -> table creation errored (the table was never created). Use `-s ingress` + a real port."""
    base = _acl_entry_count(cli)
    cli.config_raw(f"acl add table {_TBL_L3} L3 -s ingress -p {topo.misc_port(0).name}")
    time.sleep(2)
    # The rule must go through the image-adaptive path acl.add_l3_rule: SONiC's orchagent does not consume
    # a raw HSET ACL_RULE, and a raw HSET would make the assertion text misdiagnose it as a chip defect
    # (device differences must be absorbed in the adaptation layer, not reach the verdict).
    acl.add_l3_rule(cli, _TBL_L3, "PROG", priority="9000", action="DROP", SRC_IP="10.1.1.0/24")
    grew = False
    for _ in range(30):
        if _acl_entry_count(cli) > base:
            grew = True
            break
        time.sleep(0.5)
    acl.del_l3_rule(cli, _TBL_L3, "PROG")
    if cli._acl_table_cli():
        cli.config_raw(f"acl remove table {_TBL_L3}")   # _fixup -> acl-table del
    _db_del(cli, "CONFIG_DB", f"ACL_TABLE|{_TBL_L3}")
    assert grew, "user ACL rule not programmed to ASIC (ACL_ENTRY did not grow)"



def _wait_table_bound(cli, table):
    """Table binding to the ASIC lags table creation: use a warmup rule to wait until the ASIC really shows an ACL_ENTRY, then delete warmup.
    Otherwise early field cases build rules while the table is not yet bound, the entry is not programmed, and they misjudge as failures."""
    base = _acl_entry_count(cli)
    # Rule programming goes through the image-adaptive path: SONiC's orchagent does not consume a raw HSET ACL_RULE,
    # it must use its built-in `config acl-rule add`; the community version keeps CONFIG_DB HSET (the path under test itself).
    acl.add_l3_rule(cli, table, "WARMUP", priority="9999", action="DROP",
                    SRC_IP="1.2.3.0/24")
    ok = False
    for _ in range(40):
        if _acl_entry_count(cli) > base:
            ok = True
            break
        time.sleep(0.5)
    acl.del_l3_rule(cli, table, "WARMUP")
    time.sleep(1.5)
    return ok


@pytest.fixture(scope="module")
def l3_table(cli, topo):
    """Build an ingress L3(IPv4) ACL table; probe whether it binds to the ASIC; delete the table on teardown.

    The fixture only builds/probes/cleans up and **never fails** (failing inside a fixture makes dependent cases
    report ERROR instead of a clean FAILED). Returns (table_name, bound_bool), leaving the "is it bound" defect assertion to the case body.

    Note: `-s` is the stage and `-p` is the port; previously writing `-p ingress` treated "ingress" as a port name -> table
    creation errored and the table was never created, masking a real defect. Use `-s ingress` + a real port."""
    base_tbls = _acl_table_keys(cli)   # sample the ASIC ACL_TABLE baseline before creation; diff locates this table's OID
    cli.config_raw(f"acl add table {_TBL_L3} L3 -s ingress -p {topo.misc_port(0).name}")
    time.sleep(2)
    bound = _wait_table_bound(cli, _TBL_L3)
    yield (_TBL_L3, bound, _new_table_oids(cli, base_tbls))
    # Clear leftover rules first (image-adaptive path), then delete the table: SONiC's tables/rules must be cleared via its CLI so orchagent syncs
    for rk in cli.db_keys("CONFIG_DB", f"ACL_RULE|{_TBL_L3}|*"):
        acl.del_l3_rule(cli, _TBL_L3, rk.split("|")[-1])
    if cli._acl_table_cli():
        cli.config_raw(f"acl remove table {_TBL_L3}")   # _fixup -> acl-table del
    _db_del(cli, "CONFIG_DB", f"ACL_TABLE|{_TBL_L3}")
    time.sleep(1)


@pytest.fixture(scope="module")
def mac_table(cli, topo):
    """Build an L2/MAC ACL table (image-adaptive); probe binding; delete table + type on teardown.

    The creation method is chosen automatically by framework.acl per image: SONiC uses the built-in `config acl-table add -t L2`
    (a community custom ACL_TABLE_TYPE fails to parse on its orchagent and the table never reaches the ASIC); the community
    version keeps the CONFIG_DB custom ACL_TABLE_TYPE path. Like l3_table: the fixture does not fail, returns
    (table_name, bound_bool), with the defect assertion moved into the case body."""
    bind_port = topo.misc_port(0).name
    base_tbls = _acl_table_keys(cli)   # sample the baseline before creation; diff locates this table's OID
    type_name = acl.add_mac_table(cli, _TBL_MAC, bind_port)
    time.sleep(2)
    bound = acl.wait_mac_table_bound(cli, _TBL_MAC)
    yield (_TBL_MAC, bound, _new_table_oids(cli, base_tbls))
    acl.remove_mac_table(cli, _TBL_MAC, type_name)
    time.sleep(1)


def _rule_field_check(cli, asicdb, table, tbl_oids, field, value, sai_field):
    """Build a rule matching field, verify **this table's** ASIC ACL_ENTRY really carries sai_field with the configured value.
    Delete the rule afterward. Scoping to the table + value doubly excludes false passes from system-preset/leftover entries."""
    rule = f"R_{field}"
    if not acl.l3_rule_expressible(cli, field):
        pytest.skip(f"field {field} not expressible via this image's acl-rule CLI "
                    "(no such option; structural, not a defect)")
    if not acl.add_l3_rule(cli, table, rule, priority="9000", action="DROP", **{field: value}):
        pytest.skip(f"device declares field {field} unsupported via its acl-rule CLI "
                    "('does not support'; structural capability gate, not a silent defect)")
    try:
        got = None
        for _ in range(12):
            got = _entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value)
            if got:
                break
            time.sleep(0.5)
        assert got, (f"ACL field {field}={value} not programmed to ASIC (no ACL_ENTRY under "
                     f"this test's table carries {sai_field}={value}) -- field unsupported")
    finally:
        acl.del_l3_rule(cli, table, rule)
        time.sleep(0.5)


@pytest.mark.parametrize("field,value,sai_field", L3_FIELDS, ids=[f[0] for f in L3_FIELDS])
def test_acl_l3_field(cli, asicdb, l3_table, field, value, sai_field):
    """L3(IPv4) ACL per field: build a rule matching that field, verify the ASIC ACL_ENTRY really carries the corresponding SAI field."""
    table, bound, tbl_oids = l3_table
    assert bound, (f"DEVICE DEFECT: L3 ACL table {table} not bound on ASIC "
                   f"(warmup rule not programmed to hardware)")
    _rule_field_check(cli, asicdb, table, tbl_oids, field, value, sai_field)


def _mac_rule_field_check(cli, asicdb, table, tbl_oids, field, value, sai_field):
    """MAC rule per-field check: add the rule via framework.acl per image (SONiC uses the built-in `config acl-rule add`,
    community uses CONFIG_DB HSET), verify **this table's** ASIC ACL_ENTRY really carries sai_field with the configured value."""
    rule = f"R_{field}"
    acl.add_mac_rule(cli, table, rule, priority="9000", action="DROP", **{field: value})
    try:
        got = None
        for _ in range(12):
            got = _entry_with_field(cli, asicdb, tbl_oids, sai_field, field, value)
            if got:
                break
            time.sleep(0.5)
        assert got, (f"ACL field {field}={value} not programmed to ASIC (no ACL_ENTRY under "
                     f"this test's table carries {sai_field}={value}) -- field unsupported")
    finally:
        acl.del_mac_rule(cli, table, rule)
        time.sleep(0.5)


@pytest.mark.parametrize("field,value,sai_field", MAC_FIELDS, ids=[f[0] for f in MAC_FIELDS])
def test_acl_mac_field(cli, asicdb, mac_table, field, value, sai_field):
    """MAC(L2) ACL per field: build a rule matching that field, verify the ASIC ACL_ENTRY really carries the corresponding SAI field."""
    table, bound, tbl_oids = mac_table
    assert bound, (f"DEVICE DEFECT: MAC ACL table {table} not bound on ASIC "
                   f"(user MAC ACL not programmed to hardware)")
    _mac_rule_field_check(cli, asicdb, table, tbl_oids, field, value, sai_field)


# ---- counter/statistics coverage ----

def test_acl_rule_has_counter(cli, asicdb, l3_table):
    """After programming, a rule with a counter: the ASIC ACL_ENTRY has ACTION_COUNTER + points to an existing ACL_COUNTER object.

    Fixes false passes: no longer scan "any entry with a counter" (default groups/leftover entries commonly carry ACTION_COUNTER) --
    first locate the R_CNT entry by this table's TABLE_ID + SRC_IP=11.0.0.0, then read that entry's ACTION_COUNTER,
    and verify the ACL_COUNTER object's TABLE_ID also points to this table."""
    table, bound, tbl_oids = l3_table
    assert bound, (f"DEVICE DEFECT: L3 ACL table {table} not bound on ASIC "
                   f"(warmup rule not programmed to hardware)")
    acl.add_l3_rule(cli, table, "R_CNT", priority="8000", action="DROP", SRC_IP="11.0.0.0/8")
    try:
        ent = None
        for _ in range(12):
            ent = _entry_with_field(cli, asicdb, tbl_oids,
                                    "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP", "SRC_IP", "11.0.0.0/8")
            if ent:
                break
            time.sleep(0.5)
        assert ent, ("rule R_CNT (SRC_IP=11.0.0.0/8) not found under this test's table in ASIC "
                     "-- rule not programmed")
        c = str(ent.get("SAI_ACL_ENTRY_ATTR_ACTION_COUNTER", ""))
        assert "oid:" in c and "oid:0x0" not in c, (
            f"ACL rule R_CNT entry has no valid SAI_ACL_ENTRY_ATTR_ACTION_COUNTER (got {c!r})")
        coid = c[c.find("oid:"):]
        ck = f"ASIC_STATE:SAI_OBJECT_TYPE_ACL_COUNTER:{coid}"
        ch = cli.db_hgetall("ASIC_DB", ck)
        assert ch, f"ACL_COUNTER object {coid} does not exist"
        assert str(ch.get("SAI_ACL_COUNTER_ATTR_TABLE_ID", "")) in tbl_oids, (
            f"ACL_COUNTER {coid} TABLE_ID does not point back to this test's table "
            f"(counter belongs to another table)")
    finally:
        acl.del_l3_rule(cli, table, "R_CNT")
        time.sleep(0.5)


def test_acl_counter_in_countersdb(cli, l3_table):
    """ACL counter reaches COUNTERS_DB ACL_COUNTER_RULE_MAP (aclshow/stats readable)."""
    table, bound, _tbl_oids = l3_table
    assert bound, (f"DEVICE DEFECT: L3 ACL table {table} not bound on ASIC "
                   f"(warmup rule not programmed to hardware)")
    acl.add_l3_rule(cli, table, "R_CNT2", priority="7999", action="DROP", SRC_IP="12.0.0.0/8")
    try:
        ok = False
        for _ in range(14):
            if cli.db_keys("COUNTERS_DB", "ACL_COUNTER_RULE_MAP"):
                m = cli.db_hgetall("COUNTERS_DB", "ACL_COUNTER_RULE_MAP")
                if any("R_CNT2" in k for k in m):
                    ok = True
                    break
            time.sleep(0.5)
        assert ok, "ACL rule counter not in COUNTERS_DB ACL_COUNTER_RULE_MAP (stats unreadable)"
    finally:
        acl.del_l3_rule(cli, table, "R_CNT2")
        time.sleep(0.5)


# ---- action coverage ----

@pytest.mark.parametrize("action,sai_action", [
    ("DROP",    "SAI_PACKET_ACTION_DROP"),
    ("FORWARD", "SAI_PACKET_ACTION_FORWARD"),
])
def test_acl_action(cli, asicdb, l3_table, action, sai_action):
    """ACL action programming with **action-value verification**: DROP/FORWARD rules land in an ASIC ACL_ENTRY, and that entry's
    SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION exactly equals the parametrized expected action.

    Before the upgrade it only asserted "some entry carries the DST_IP field" and never verified the action value (a wrong DROP/FORWARD
    would still pass). Now it scopes to this table's TABLE_ID + a DST_IP=30.0.0.0 value match, then reads that entry's action attribute and
    compares it against the parametrized SAI_PACKET_ACTION_* (excluding leftover-entry false passes)."""
    table, bound, tbl_oids = l3_table
    assert bound, (f"DEVICE DEFECT: L3 ACL table {table} not bound on ASIC "
                   f"(warmup rule not programmed to hardware)")
    acl.add_l3_rule(cli, table, f"R_ACT_{action}", priority="6000", action=action,
                    DST_IP="30.0.0.0/8")
    try:
        match = None
        for _ in range(12):
            # the entry must belong to this table, carry this rule's DST_IP=30.0.0.0, and have PACKET_ACTION equal to the expected action
            d = _entry_with_field(cli, asicdb, tbl_oids,
                                  "SAI_ACL_ENTRY_ATTR_FIELD_DST_IP", "DST_IP", "30.0.0.0/8")
            if d and sai_action in str(d.get("SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION", "")):
                match = d
                break
            time.sleep(0.5)
        assert match, (f"ACL action={action} rule not programmed to ASIC with {sai_action} "
                       f"(no ACL_ENTRY under this test's table carries DST_IP=30.0.0.0 + "
                       f"ACTION_PACKET_ACTION={sai_action})")
    finally:
        acl.del_l3_rule(cli, table, f"R_ACT_{action}")
        time.sleep(0.5)


# ---- dataplane hit (method-limited, honestly recorded as xfail) ----

@pytest.mark.traffic
def test_acl_l3_drop_dataplane(cli, l3_table, _lb, dut):
    """L3 DROP rule dataplane hit (inject a matching packet -> aclshow drop count grows).

    Unlike ip2me: ACL is pure ingress FP matching, independent of myStation/CPU-on-VPP,
    so loopback injection can test it reliably."""
    from scapy.all import Ether, IP, UDP, sendp
    table, bound, _tbl_oids = l3_table
    assert bound, (f"DEVICE DEFECT: L3 ACL table {table} not bound on ASIC "
                   f"(warmup rule not programmed to hardware)")
    p = dut.pick_test_ports(1)[0]
    # A dataplane hit requires **binding the injection port into the table**: module-level l3_table only binds the misc port, so when
    # traffic is injected from p the ACL cannot see it at all (a mis-bound port once had this case on both units testing a nonexistent
    # path). SONiC does not support rebinding after table creation, and an in-ports-equivalent (adding IN_PORTS to the rule) is not
    # feasible (community field), so just build a separate dedicated table bound to p.
    dp_tbl = "FVT_ACL_DP"
    cli.config_raw(f"acl add table {dp_tbl} L3 -s ingress -p {p.name}")
    time.sleep(2)
    table = dp_tbl
    acl.add_l3_rule(cli, table, "R_DP", priority="5000", action="DROP", SRC_IP="10.9.9.0/24")
    time.sleep(3)
    try:
        _lb.enable(p)
        time.sleep(1)
        sendp(Ether(dst="02:11:22:33:44:55") / IP(src="10.9.9.9", dst="8.8.8.8") / UDP(),
              iface=p.name, count=30, verbose=0)
        # Hit-count observation is image-adaptive: aclshow or a direct COUNTERS_DB read (SONiC's aclshow does not render CLI rules).
        # The ACL flex counter collection period is 10s (counterpoll) -- first poll up to the lower bound, then wait one collection
        # period to let the count **settle** (otherwise a late positive count pollutes the negative-control delta below).
        hit = 0
        for _ in range(10):
            time.sleep(2)
            hit = acl.rule_hit_count(cli, table, "R_DP") or 0
            if hit >= 27:
                break
        time.sleep(12)
        hit = acl.rule_hit_count(cli, table, "R_DP") or 0
        # Tightened lower bound + upper bound: 30 frames match deterministically, asserting only >0 would let 29 dropped frames slip; without an upper bound, duplicated counting / storms go unseen
        assert 27 <= hit <= 45, (
            f"ACL DROP rule R_DP hit count {hit} outside expected band [27,45] for 30 matching "
            f"frames (0/low: dataplane DROP not enforced or counter not collected; "
            f"high: duplicated counting / storm)")
        # Negative control: inject 30 frames with a non-matching src (10.8.8.8 not in 10.9.9.0/24), wait one collection period,
        # the hit count should not grow further (otherwise the match field was programmed as a wildcard / the counter is over-counting)
        sendp(Ether(dst="02:11:22:33:44:55") / IP(src="10.8.8.8", dst="8.8.8.8") / UDP(),
              iface=p.name, count=30, verbose=0)
        time.sleep(12)
        hit2 = acl.rule_hit_count(cli, table, "R_DP") or 0
        assert hit2 - hit <= 2, (
            f"non-matching traffic (src 10.8.8.8 outside 10.9.9.0/24) also increased rule "
            f"hit count (+{hit2 - hit}); ACL match is not selective (field programmed as "
            f"wildcard?)")
    finally:
        _lb.disable(p)
        acl.del_l3_rule(cli, table, "R_DP")
        if cli._acl_table_cli():
            cli.config_raw(f"acl remove table {dp_tbl}")
        cli.sh.run(f"sonic-db-cli CONFIG_DB DEL 'ACL_TABLE|{dp_tbl}'", check=False)
