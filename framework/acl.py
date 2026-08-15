"""Cross-image helper for MAC (L2) ACL table/rule creation.

Background:
- The community edition declares L2 match fields via a custom CONFIG_DB
  ACL_TABLE_TYPE and pushes rules by CONFIG_DB ACL_RULE HSET (community edition
  has no per-rule `config acl-rule` command).
- On some images the orchagent does not support the community custom
  ACL_TABLE_TYPE mechanism (the table never reaches the ASIC), but its built-in
  `config acl-table add -t L2` can create an L2 table and
  `config acl-rule add ... -sm ... -a DROP` can push SRC_MAC+DROP to the ASIC.

This module auto-selects the table/rule creation path per image (via the
cli._acl_table_cli() probe) so MAC-ACL cases are agnostic to the difference:
on both image classes it asserts that a real
ACL_TABLE/ACL_ENTRY/FIELD_SRC_MAC/PACKET_ACTION_DROP reaches the ASIC, without
weakening the check.
"""
import time

# Match-field set for the community edition's custom L2 type
_MAC_MATCHES = "SRC_MAC,DST_MAC,ETHER_TYPE,OUTER_VLAN_ID,OUTER_VLAN_PRI,IN_PORTS"

# Community CONFIG_DB ACL_RULE field name -> SONiC `config acl-rule add` option
_MAC_FIELD_CLI = {
    "SRC_MAC":    "-sm",
    "DST_MAC":    "-dm",
    "ETHER_TYPE": "-et",
    "VLAN_ID":    "-vid",
    "PCP":        "-vp",
}

# L3 (IPv4/v6) field mapping. The SONiC CLI has **no** IP_TYPE option -- that
# field is structurally inexpressible on its CLI (caller should skip).
_L3_FIELD_CLI = {
    "SRC_IP":            "-si",
    "DST_IP":            "-di",
    "SRC_IPV6":          "-si6",
    "DST_IPV6":          "-di6",
    "IP_PROTOCOL":       "-ip",
    "L4_SRC_PORT":       "-sp",
    "L4_DST_PORT":       "-dp",
    "L4_SRC_PORT_RANGE": "-spr",
    "L4_DST_PORT_RANGE": "-dpr",
    "DSCP":              "-d",
    "ETHER_TYPE":        "-et",
    "ICMP_TYPE":         "-ict",
    "ICMP_CODE":         "-icc",
    "TCP_FLAGS":         "-tf",
}

# TCP flag bits -> SONiC `-tf` names (community CONFIG_DB value looks like "0x10/0x10")
_TCP_FLAG_NAMES = ((0x01, "TCP_FIN"), (0x02, "TCP_SYN"), (0x04, "TCP_RST"),
                   (0x08, "TCP_PSH"), (0x10, "TCP_ACK"), (0x20, "TCP_URG"))


def _tcp_flags_cli(value):
    """"0x10/0x10" -> "TCP_ACK" (SONiC -tf takes a name list). Returns None if unparsable."""
    try:
        bits = int(str(value).split("/")[0], 0)
    except ValueError:
        return None
    names = [n for b, n in _TCP_FLAG_NAMES if bits & b]
    return ",".join(names) if names else None


def _db_hset(cli, db, key, **fields):
    parts = " ".join(f"'{k}' '{v}'" for k, v in fields.items())
    return cli.sh.run(f"sonic-db-cli {db} HSET '{key}' {parts}", check=False)


def _db_del(cli, db, key):
    return cli.sh.run(f"sonic-db-cli {db} DEL '{key}'", check=False)


def _acl_entry_count(cli):
    return len(cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"))


def _ethertype_cli(value):
    """Community rules use decimal ETHER_TYPE (2048=IPv4); SONiC CLI `-et` wants 0xXXXX form."""
    try:
        return f"0x{int(str(value), 0):04X}"
    except ValueError:
        return str(value)


def add_mac_table(cli, name, port):
    """Create an L2/MAC ACL table (image-adaptive). Returns the custom type name
    actually used this time (for teardown):
    - SONiC: built-in `acl add table <name> L2 -p <port>` (transparently rewritten
      by cli._fixup to `acl-table add <name> -s ingress -t L2 -p <port>`). Returns
      None (no custom type to clean up).
    - Community edition: writes a custom CONFIG_DB ACL_TABLE_TYPE + ACL_TABLE.
      Returns the type name.
    """
    if cli._acl_table_cli():
        cli.config_raw(f"acl add table {name} L2 -p {port}")
        return None
    type_name = f"{name}_TYPE"
    _db_hset(cli, "CONFIG_DB", f"ACL_TABLE_TYPE|{type_name}",
             MATCHES=_MAC_MATCHES, BIND_POINTS="PORT", ACTIONS="PACKET_ACTION,COUNTER")
    time.sleep(1)
    _db_hset(cli, "CONFIG_DB", f"ACL_TABLE|{name}",
             policy_desc="fvt-mac", type=type_name, stage="ingress", ports=port)
    return type_name


def remove_mac_table(cli, name, type_name):
    """Delete a MAC ACL table (image-adaptive), clearing leftover rules first.
    type_name is the value returned by add_mac_table."""
    if cli._acl_table_cli():
        # SONiC: tables/rules created via the built-in CLI are cleared via the
        # built-in CLI (to avoid stale orchagent state)
        for rk in cli.db_keys("CONFIG_DB", f"ACL_RULE|{name}|*"):
            rule = rk.split("|")[-1]
            cli.config_raw(f"acl-rule del {name} {rule}")
        cli.config_raw(f"acl remove table {name}")   # _fixup -> acl-table del
    else:
        for rk in cli.db_keys("CONFIG_DB", f"ACL_RULE|{name}|*"):
            _db_del(cli, "CONFIG_DB", rk)
    _db_del(cli, "CONFIG_DB", f"ACL_TABLE|{name}")
    if type_name:
        _db_del(cli, "CONFIG_DB", f"ACL_TABLE_TYPE|{type_name}")


def add_mac_rule(cli, table, rule, priority="9000", action="DROP", **fields):
    """Add one rule to a MAC table (image-adaptive). fields use community field
    names (SRC_MAC/DST_MAC/ETHER_TYPE/VLAN_ID/PCP):
    - SONiC: uses the built-in `config acl-rule add <table> <rule> -p <pri> -a
      <action> <field options>` (`acl-rule` is not rewritten by _fixup, pushed as-is).
    - Community edition: CONFIG_DB ACL_RULE HSET (the community edition's own
      push path under test).
    """
    if cli._acl_table_cli():
        cmd = f"acl-rule add {table} {rule} -p {priority} -a {action}"
        for k, v in fields.items():
            flag = _MAC_FIELD_CLI.get(k)
            if not flag:
                continue
            if k == "ETHER_TYPE":
                v = _ethertype_cli(v)
            cmd += f" {flag} {v}"
        cli.config_raw(cmd)
    else:
        _db_hset(cli, "CONFIG_DB", f"ACL_RULE|{table}|{rule}",
                 PRIORITY=priority, PACKET_ACTION=action, **fields)


def l3_rule_expressible(cli, *fields):
    """Whether these L3 fields are expressible on this image's rule push channel.
    Community edition (HSET arbitrary fields) is always True; SONiC is limited by
    its acl-rule CLI option set (e.g. no IP_TYPE). Inexpressible = structural skip."""
    if not cli._acl_table_cli():
        return True
    for f in fields:
        if f not in _L3_FIELD_CLI:
            return False
        if f == "TCP_FLAGS":
            continue
    return True


def add_l3_rule(cli, table, rule, priority="9000", action="DROP", **fields):
    """Add one rule to an L3 table (image-adaptive). fields use community
    CONFIG_DB field names.

    - SONiC: built-in `config acl-rule add` (a bare HSET is not consumed by its
      orchagent).
    - Community edition: CONFIG_DB ACL_RULE HSET (the community edition's own push
      path under test).
    Returns False if some field is inexpressible on this image's CLI (caller
    should skip), True = pushed."""
    if cli._acl_table_cli():
        cmd = f"acl-rule add {table} {rule} -p {priority} -a {action}"
        for k, v in fields.items():
            flag = _L3_FIELD_CLI.get(k)
            if not flag:
                return False
            if k == "TCP_FLAGS":
                v = _tcp_flags_cli(v)
                if not v:
                    return False
            elif k == "ETHER_TYPE":
                v = _ethertype_cli(v)
            cmd += f" {flag} {v}"
        _rc, r = cli.config_raw(cmd)
        # Product capability gate: CLI explicitly declares this device does not
        # support the field -> structurally unsupported, caller should skip.
        if "does not support" in f"{r.out or ''}{r.err or ''}":
            return False
    else:
        _db_hset(cli, "CONFIG_DB", f"ACL_RULE|{table}|{rule}",
                 PRIORITY=priority, PACKET_ACTION=action, **fields)
    return True


def ensure_acl_counterpoll(cli):
    """Ensure the ACL flex counter is polling (factory default may be disabled ->
    hit counts stay 0 / never update). Idempotent."""
    if getattr(cli, "_aclpoll_on", False):
        return
    out = cli.sh.run("counterpoll show", check=False).out or ""
    for line in out.splitlines():
        if line.split()[:1] == ["ACL"] and "disable" in line:
            cli.sh.run("counterpoll acl enable", check=False)
            import time as _t
            _t.sleep(2)
            break
    cli._aclpoll_on = True


def rule_hit_count(cli, table, rule):
    """Rule hit packet count (image-adaptive observation channel).

    Prefers `aclshow -a`; SONiC's aclshow does not render rules created via its
    CLI (the counters are actually being polled) -- falls back to COUNTERS_DB:
    reverse-look up the counter oid via ACL_COUNTER_RULE_MAP, then read
    SAI_ACL_COUNTER_ATTR_PACKETS/Packets from COUNTERS:oid directly. Returns None
    if neither path yields a value."""
    ensure_acl_counterpoll(cli)
    out = cli.sh.run("aclshow -a", check=False).out or ""
    for line in out.splitlines():
        toks = line.split()
        if rule in toks and len(toks) >= 5 and toks[-2].isdigit():
            return int(toks[-2])
    m = cli.db_hgetall("COUNTERS_DB", "ACL_COUNTER_RULE_MAP") or {}
    for k, oid in m.items():
        if rule in k and table in k:
            h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}") or {}
            for f in ("SAI_ACL_COUNTER_ATTR_PACKETS", "Packets", "packets"):
                v = h.get(f)
                if v is not None and str(v).isdigit():
                    return int(v)
    return None


def del_l3_rule(cli, table, rule):
    """Delete one L3 rule (image-adaptive)."""
    if cli._acl_table_cli():
        cli.config_raw(f"acl-rule del {table} {rule}")
    else:
        _db_del(cli, "CONFIG_DB", f"ACL_RULE|{table}|{rule}")


def del_mac_rule(cli, table, rule):
    """Delete one MAC rule (image-adaptive)."""
    if cli._acl_table_cli():
        cli.config_raw(f"acl-rule del {table} {rule}")
    else:
        _db_del(cli, "CONFIG_DB", f"ACL_RULE|{table}|{rule}")


def wait_mac_table_bound(cli, table, tries=40, interval=0.5):
    """A MAC table binds to the ASIC asynchronously after creation: this pushes a
    SRC_MAC warmup rule, waits until a new ACL_ENTRY actually appears in the ASIC,
    then deletes the warmup. The warmup for a MAC table must use SRC_MAC (not L3's
    SRC_IP) -- otherwise the warmup field mismatches the table type, the rule is
    not pushed, and an already-bound table is misjudged as unbound. Returns True =
    the table is bound in hardware."""
    base = _acl_entry_count(cli)
    add_mac_rule(cli, table, "WARMUP", priority="9999", action="DROP",
                 SRC_MAC="00:de:ad:be:ef:01")
    ok = False
    for _ in range(tries):
        if _acl_entry_count(cli) > base:
            ok = True
            break
        time.sleep(interval)
    del_mac_rule(cli, table, "WARMUP")
    time.sleep(1.5)
    return ok
