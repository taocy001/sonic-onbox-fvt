"""ACL: chip-programming verification of table create / show / remove (CLI -> aclorch -> ASIC SAI_ACL_TABLE/ACL_ENTRY).

On-device evidence (DUT 10.0.20.158, nos): L3 user ACLs now reach hardware -- after
creating a table + writing a rule, ASIC_DB shows new SAI_OBJECT_TYPE_ACL_TABLE /
SAI_OBJECT_TYPE_ACL_ENTRY objects (syncd only creates objects when the SAI create
succeeds). So this file asserts real chip programming / real reclaim, not a read-only
CONFIG_DB echo. Per-field / action / dataplane DROP coverage is in test_acl_chip.py.
"""
import time

import pytest

from framework import acl

pytestmark = [pytest.mark.acl]

TABLE = "DUTTEST_ACL"
_TBL_PAT = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:*"
_ENT_PAT = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"


def _db_hset(cli, key, **fields):
    parts = " ".join(f"'{k}' '{v}'" for k, v in fields.items())
    return cli.sh.run(f"sonic-db-cli CONFIG_DB HSET '{key}' {parts}", check=False)


def _db_del(cli, key):
    return cli.sh.run(f"sonic-db-cli CONFIG_DB DEL '{key}'", check=False)


def _add_rule_and_wait_asic(cli, asicdb, table, base_tbl, timeout=12):
    """Write one L3 rule to the table, then wait for ASIC to really show new ACL_TABLE / ACL_ENTRY.

    Write CONFIG_DB ACL_RULE directly (the very programming path aclorch consumes, same as
    test_acl_chip). base_tbl must be the ACL_TABLE baseline the caller sampled *before*
    `config acl add table`: table creation asynchronously builds a SAI_ACL_TABLE on the
    chip, and if the baseline is sampled after the create returns, the baseline already
    includes this table's object, so wait_count_gt never sees growth -> false failure. The
    ACL_ENTRY baseline is sampled here, before writing the rule.
    Returns (table_grew, entry_grew, rule_key); the caller is responsible for deleting the rule."""
    base_ent = asicdb.count(_ENT_PAT)
    rk = f"ACL_RULE|{table}|R_FVT"
    # rule goes through the image-adaptive channel (orchagent does not consume a bare HSET; use the CONFIG_DB HSET programming path)
    acl.add_l3_rule(cli, table, "R_FVT", priority="9000", action="DROP", SRC_IP="10.7.7.0/24")
    tbl_grew = asicdb.wait_count_gt(_TBL_PAT, base_tbl, timeout=timeout)
    ent_grew = asicdb.wait_count_gt(_ENT_PAT, base_ent, timeout=timeout)
    return tbl_grew, ent_grew, rk


def test_acl_table_create(cli, asicdb, topo, config_guard):
    """L3 ACL table create + rule -> assert ASIC SAI_ACL_TABLE and SAI_ACL_ENTRY really grow (chip programming).

    The old version read CONFIG_DB type/ports/stage only (read back what you wrote, always
    passes = false pass); this now asserts syncd really built ACL_TABLE/ACL_ENTRY objects in
    hardware. On nos, L3 is programmed, so this should pass; if not programmed, it fails honestly."""
    port = topo.misc_port(0).name
    base_tbl = asicdb.count(_TBL_PAT)   # must sample the baseline before table creation (see helper docstring)
    rc, r = cli.config_raw(f"acl add table {TABLE} L3 -p {port}")
    config_guard.defer_undo(f"acl remove table {TABLE}")
    assert rc == 0, f"Failed to create ACL table: {r.err or r.out}"
    tbl_grew, ent_grew, rk = _add_rule_and_wait_asic(cli, asicdb, TABLE, base_tbl)
    try:
        assert tbl_grew, \
            "ACL L3 table not programmed to ASIC (no new SAI_OBJECT_TYPE_ACL_TABLE) -- " \
            "user ACL did not reach hardware"
        assert ent_grew, \
            "ACL L3 rule not programmed to ASIC (no new SAI_OBJECT_TYPE_ACL_ENTRY) -- " \
            "rule did not reach hardware"
    finally:
        acl.del_l3_rule(cli, TABLE, "R_FVT")


def test_acl_table_show(cli, asicdb, topo, config_guard):
    """Build an L3 table + rule so it really programs to ASIC, then assert `show acl table` renders that (hardware-programmed) table.

    Ties CLI rendering to the *real chip state*: not "shows up because it's in CONFIG_DB",
    but the table is genuinely programmed to ASIC."""
    port = topo.misc_port(0).name
    base_tbl = asicdb.count(_TBL_PAT)   # must sample the baseline before table creation (see helper docstring)
    cli.config_raw(f"acl add table {TABLE} L3 -p {port}")
    config_guard.defer_undo(f"acl remove table {TABLE}")
    tbl_grew, _ent, rk = _add_rule_and_wait_asic(cli, asicdb, TABLE, base_tbl)
    try:
        assert tbl_grew, \
            "ACL table not programmed to ASIC; `show acl table` would render a hardware-absent table"
        # the show command name differs across images: community `show acl table`, SONiC
        # `show acl-table` (the former may be No such command). Decided by the same probe
        # as the table-create CLI.
        out = cli.show("acl-table" if cli._acl_table_cli() else "acl table")
        assert TABLE in out, "acl table show output missing the programmed table"
    finally:
        acl.del_l3_rule(cli, TABLE, "R_FVT")


def test_acl_table_remove(cli, asicdb, topo):
    """Positive-control then remove: first build a table + rule so ASIC shows a SAI_ACL_TABLE
    (proving there is really something to remove), then `acl remove table` and assert ASIC
    SAI_ACL_TABLE is reclaimed back to baseline (real chip delete, not just CONFIG_DB clear)."""
    port = topo.misc_port(0).name
    base = asicdb.count(_TBL_PAT)   # pre-create baseline, also reused as the helper's ACL_TABLE baseline
    cli.config_raw(f"acl add table {TABLE} L3 -p {port}")
    tbl_grew, _ent, rk = _add_rule_and_wait_asic(cli, asicdb, TABLE, base)
    try:
        assert tbl_grew, \
            "positive control failed: ACL table never programmed to ASIC, removal is meaningless"
    finally:
        # delete the rule (acl remove table does not cascade-delete rules; a leftover orphan breaks GCU whole-tree validation) then delete the table
        acl.del_l3_rule(cli, TABLE, "R_FVT")
        for k in cli.db_keys("CONFIG_DB", f"ACL_RULE|{TABLE}|*"):
            _db_del(cli, k)
        cli.config_raw(f"acl remove table {TABLE}")
    # after removing the table, ASIC SAI_ACL_TABLE should return to baseline
    end = time.time() + 12
    while time.time() < end:
        if asicdb.count(_TBL_PAT) <= base:
            break
        time.sleep(0.5)
    assert asicdb.count(_TBL_PAT) <= base, \
        f"ACL table not removed from ASIC after `acl remove table` (SAI_ACL_TABLE stayed above base {base})"
    assert not cli.db_keys("CONFIG_DB", f"ACL_TABLE|{TABLE}"), \
        "Table still in CONFIG_DB after removal"
