"""egress ACL chip-programming verification (the ingress L3 + L2/MAC dimensions are covered by test_acl_chip.py).

Design trade-offs:
- test_acl_chip.py already makes full ASIC_DB assertions for ingress L3(IPv4) per-field + custom
  L2/MAC per-field + action + counter + dataplane DROP. This file does not repeat the ingress/L2
  dimensions and focuses on the egress stage that test_acl_chip does not cover: whether egress L3
  tables/rules are truly programmed into the ASIC (SAI_ACL_TABLE / SAI_ACL_ENTRY).
- The old version pinned the egress/L2 tests' "deepest verifiable layer" at CONFIG_DB (read back what
  you wrote, always passes = fake pass); that has been removed and replaced with direct assertions on
  real ASIC object growth.
- Ingress L3 user-ACL hardware programming is already covered by test_acl_chip; whether the egress
  stage programs likewise is not yet confirmed, so the egress tests are honestly annotated with
  `@pytest.mark.xfail(strict=False)`: programmed -> xpass, not programmed -> xfail, never a hiding
  skip and never weakening the assertion into a CONFIG_DB echo.
- L2/MAC ACL ASIC programming -> see test_acl_chip.py::test_acl_mac_field_in_asic (custom
  ACL_TABLE_TYPE asserting every MAC field one by one); not repeated here.

Prints / assert / xfail text and comments in English; ports come from topo (dynamically
assigned per device, not hard-coded EthernetX).
"""
import time

import pytest

from framework import acl

pytestmark = [pytest.mark.acl]

_TBL_PAT = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:*"
_ENT_PAT = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"


def _db_hset(cli, key, **fields):
    parts = " ".join(f"'{k}' '{v}'" for k, v in fields.items())
    return cli.sh.run(f"sonic-db-cli CONFIG_DB HSET '{key}' {parts}", check=False)


def _db_del(cli, key):
    return cli.sh.run(f"sonic-db-cli CONFIG_DB DEL '{key}'", check=False)


def _cleanup_table(cli, table):
    """Delete the table + leftover rules (acl remove table does not cascade-delete rules; orphan ACL_RULEs break GCU whole-tree validation)."""
    for k in cli.db_keys("CONFIG_DB", f"ACL_RULE|{table}|*"):
        _db_del(cli, k)
    cli.config_raw(f"acl remove table {table}")
    _db_del(cli, f"ACL_TABLE|{table}")


# ============================ egress capability precondition fact ============================

def test_acl_egress_capability_present(cli, statedb):
    """STATE_DB exposes egress capability (action_list=PACKET_ACTION) -- the hardware precondition for egress ACL to be viable.

    This is a device-self-reported capability (not a test's own write-then-readback), and is the
    precondition for the subsequent egress programming tests."""
    cap = cli.db_hgetall("STATE_DB", "ACL_STAGE_CAPABILITY_TABLE|EGRESS")
    assert cap, ("STATE_DB ACL_STAGE_CAPABILITY_TABLE|EGRESS absent "
                 "(egress ACL stage capability not exposed)")
    assert "PACKET_ACTION" in str(cap.get("action_list", "")), \
        f"egress ACL action capability missing PACKET_ACTION: {cap}"


# ============================ egress L3 table -> ASIC ============================

def test_acl_egress_table_in_asic(cli, asicdb, topo, config_guard):
    """egress L3 table + rule -> assert ASIC SAI_ACL_TABLE truly grows (egress-stage chip programming)."""
    table = "ACLT_EGR_ASIC"
    port = topo.l3_port(0).name
    base_tbl = asicdb.count(_TBL_PAT)
    rc, r = cli.config_raw(f"acl add table {table} L3 -s egress -p {port}")
    config_guard.defer_undo(f"acl remove table {table}")
    assert rc == 0, f"egress ACL table creation failed: {r.err or r.out}"
    acl.add_l3_rule(cli, table, "R_EGR", priority="9000", action="DROP", SRC_IP="10.7.7.0/24")
    try:
        assert asicdb.wait_count_gt(_TBL_PAT, base_tbl, timeout=12), \
            "egress ACL L3 table did not create SAI_OBJECT_TYPE_ACL_TABLE in ASIC_DB"
    finally:
        acl.del_l3_rule(cli, table, "R_EGR")
        _cleanup_table(cli, table)


# ============================ egress L3 rule -> ASIC ENTRY ============================

def test_acl_egress_l3_rule_in_asic(cli, asicdb, topo, config_guard):
    """egress L3 rule (IP_PROTOCOL/L4_DST_PORT + DROP) -> assert an ASIC SAI_ACL_ENTRY appears carrying
    the matching fields + DROP action (the egress rule is truly programmed into the chip classifier)."""
    table = "ACLT_EGR_RULE"
    rule = "R_EGR_DP"
    port = topo.l3_port(0).name
    # Record the existing ACL_TABLE OID set before creating the table; the one added afterward is this test's own table OID
    base_tbls = set(asicdb.objects("SAI_OBJECT_TYPE_ACL_TABLE"))
    rc, r = cli.config_raw(f"acl add table {table} L3 -s egress -p {port}")
    config_guard.defer_undo(f"acl remove table {table}")
    assert rc == 0, f"egress ACL table creation failed: {r.err or r.out}"
    # This test's own SAI_ACL_TABLE OID (extract the key's trailing oid:0x.. segment, used to trace ACL_ENTRY ownership)
    my_tbl_oids = {k.split("SAI_OBJECT_TYPE_ACL_TABLE:", 1)[-1]
                   for k in (set(asicdb.objects("SAI_OBJECT_TYPE_ACL_TABLE")) - base_tbls)}
    base_ent = asicdb.count(_ENT_PAT)
    acl.add_l3_rule(cli, table, rule, priority="8888", action="DROP",
                    IP_PROTOCOL="17", L4_DST_PORT="7777")
    try:
        assert asicdb.wait_count_gt(_ENT_PAT, base_ent, timeout=12), \
            "egress ACL rule did not create SAI_OBJECT_TYPE_ACL_ENTRY in ASIC_DB"
        # Scope the field/action scan precisely to this test's newly created entry: it must satisfy all of
        #   (1) TABLE_ID traces back to this test's own table OID (excludes a fake xpass from a system-preset entry)
        #   (2) L4_DST_PORT truly carries 7777 (not merely the field's presence)
        #   (3) DROP action
        hit = None
        for _ in range(16):
            for e in asicdb.objects("SAI_OBJECT_TYPE_ACL_ENTRY"):
                d = cli.db_hgetall("ASIC_DB", e)
                tid = str(d.get("SAI_ACL_ENTRY_ATTR_TABLE_ID", ""))
                l4 = str(d.get("SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT", ""))
                if tid in my_tbl_oids and "7777" in l4 and \
                        "DROP" in str(d.get("SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION", "")):
                    hit = d
                    break
            if hit:
                break
            time.sleep(0.5)
        assert hit, \
            "no ACL_ENTRY under this test's egress table OID carries L4_DST_PORT=7777 + DROP " \
            "(egress rule not programmed on chip for this table; not a pre-existing system entry)"
    finally:
        acl.del_l3_rule(cli, table, rule)
        _cleanup_table(cli, table)


# ============================ egress DROP dataplane hit ============================

def _accum_tx_pkt(traffic, port, floor=None, window=3.0):
    """Poll and accumulate the port's chip TX delta step by step with a confirmation read (same pattern as smoke_check).

    show c has "change since last read" semantics: a single read after a fixed sleep misses counts
    that land via DMA late, so a negative assertion (should not forward) reading 0 -> ACL not in
    effect also fake-passes. When floor is given (positive control), converge early once the total
    reaches the lower bound; on the negative side pass no floor and read the full window + confirm."""
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



@pytest.mark.traffic
def test_acl_egress_drop_dataplane(cli, traffic, topo, config_guard, l2_fwd_vlan):
    """egress L3 DROP rule dataplane hit (real end-to-end traffic, mirroring
    test_acl_chip::test_acl_l3_drop_dataplane but acting on the egress port's egress stage):
      the table binds to the egress stage of the egress port pout(=traffic.ports[1]); FDB makes the
      destination MAC unicast-forward to pout; the egress ACL adds a DROP UDP/dport=7777 rule at egress.
      - non-matching frames (UDP/5555) egress pout normally -> pout chip TX grows (control, proving the
        topology itself can forward);
      - matching frames (UDP/7777) should be egress-ACL DROPped at the egress -> pout chip TX does not grow.
    Assert the difference between the two, proving the egress ACL truly intercepts in the hardware dataplane."""
    from scapy.all import Ether, IP, UDP, Raw
    table = "ACLT_EGR_DP"
    pin, pout = traffic.ports[0], traffic.ports[1]
    dmac, smac = topo.mac("dst"), topo.mac("src")
    # On an l2_home_forwarding=false platform use the real forwarding VLAN (the parking Vlan1 does not forward), dvlan = l2_fwd_vlan
    n = 100

    # Bind the egress ACL to the egress port (frames are classified/matched in the egress stage as they leave pout)
    rc, r = cli.config_raw(f"acl add table {table} L3 -s egress -p {pout.name}")
    config_guard.defer_undo(f"acl remove table {table}")
    assert rc == 0, f"egress ACL table creation failed: {r.err or r.out}"
    cli.fdb_static_add(dvlan, dmac, pout.name)
    acl.add_l3_rule(cli, table, "R_EGR_DP", priority="5000", action="DROP",
                    IP_PROTOCOL="17", L4_DST_PORT="7777")
    time.sleep(3)
    traffic.loop(pout)
    try:
        # Control baseline: non-matching frames (UDP/5555) should forward normally to pout (proving
        # FDB/topology can forward, ruling out environment issues)
        # Counting uses clear -> polled accumulation + confirmation read (show c delta semantics); add a storm upper bound to the positive control
        good = Ether(dst=dmac, src=smac) / IP() / UDP(dport=5555) / Raw(b"x" * 40)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, good, count=n)
        d_good = _accum_tx_pkt(traffic, pout, floor=n * 0.8)
        assert n * 0.8 <= d_good < n + 3000, (
            f"baseline non-matching traffic abnormal on {pout.name} "
            f"(TX+{d_good}, expected ~{n}); forwarding broken or storm, cannot judge egress ACL")

        # Matching frames (UDP/7777) should be egress-ACL DROPped -> pout chip TX essentially does not grow
        # (the negative side reads the full window + confirmation, guarding against a fake pass from late-landing counts)
        match = Ether(dst=dmac, src=smac) / IP() / UDP(dport=7777) / Raw(b"x" * 40)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, match, count=n)
        d_match = _accum_tx_pkt(traffic, pout)
        assert d_match <= n * 0.1, (
            f"egress ACL DROP not enforced in dataplane: matching UDP/7777 traffic still egresses "
            f"{pout.name} (TX+{d_match} of {n}); egress user ACL DROP not programmed to hardware")
    finally:
        traffic.unloop(pout)
        acl.del_l3_rule(cli, table, "R_EGR_DP")
        cli.fdb_static_del(dvlan, dmac)
        _cleanup_table(cli, table)
