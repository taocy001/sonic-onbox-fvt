"""CoPP all trap types: HOSTIF_TRAP present + CoPP config + punt of generatable trap traffic.

Traps are installed at ASIC init; verify HOSTIF_TRAP exists. Generatable protocols (LLDP/ARP/etc.)
verify punt; the rest (bgp/bfd/dhcp/lacp/udld/ip2me...) verify trap installation + CoPP rate-limit config.
"""
import time

import pytest

from framework import profile as _profile

pytestmark = [pytest.mark.trap]

# CoPP-supported trap types (aligned with spec)
TRAP_TYPES = [
    "arp_req", "arp_resp", "neigh_discovery", "lldp", "dhcp", "dhcpv6",
    "udld", "bgp", "bgpv6", "lacp", "ip2me", "bfd", "bfdv6", "ttl_error",
    "ssh", "snmp", "sample_packet",
]

# CoPP trap name -> the SAI_HOSTIF_TRAP_TYPE_* expected to be programmed to the ASIC (any hit means
# the trap is ready on the chip side).
# Route-type traps (bgp/bgpv6/ip2me) are produced by the L3 lookup result; some devices do not model
# them as HOSTIF_TRAP, so the mapping is left empty -> the test gives them a justified skip.
_TRAP_TO_SAI = {
    "arp_req":         ["SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST"],
    "arp_resp":        ["SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE"],
    "neigh_discovery": ["SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY"],
    "lldp":            ["SAI_HOSTIF_TRAP_TYPE_LLDP"],
    "dhcp":            ["SAI_HOSTIF_TRAP_TYPE_DHCP"],
    "dhcpv6":          ["SAI_HOSTIF_TRAP_TYPE_DHCPV6"],
    "udld":            ["SAI_HOSTIF_TRAP_TYPE_UDLD"],
    "lacp":            ["SAI_HOSTIF_TRAP_TYPE_LACP"],
    "bfd":             ["SAI_HOSTIF_TRAP_TYPE_BFD"],
    "bfdv6":           ["SAI_HOSTIF_TRAP_TYPE_BFDV6"],
    "ttl_error":       ["SAI_HOSTIF_TRAP_TYPE_TTL_ERROR"],
    "ssh":             ["SAI_HOSTIF_TRAP_TYPE_SSH"],
    "snmp":            ["SAI_HOSTIF_TRAP_TYPE_SNMP"],
    "sample_packet":   ["SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET"],
    # Route-type traps: L3 lookup products, not modeled as HOSTIF_TRAP
    "bgp": [], "bgpv6": [], "ip2me": [],
}


# ===== Device-specific CoPP expectations: read from the copp section of topology/profiles.yaml (device-agnostic) =====
# During collection (parametrize decoration phase) there is no dut fixture yet, so probe the current
# device via machine.conf/DUT_PLATFORM and load its profile, same source as dut.profile / topology.
# Each device section declares its own trap set and expectations; tests no longer hardcode device values.
# Unmatched devices (build-machine dry-run) fall back to the reference set to keep collection working.
_COPP = _profile.load_current().get("copp", {})

# Reference fallback (dry-run / unmatched devices only; real devices are overridden by their profile copp section)
_FALLBACK_ENABLED_TRAP_IDS = ["arp", "arp_req", "arp_resp", "neigh_discovery", "lldp",
                              "lacp", "udld", "bgp", "bgpv6", "ip2me", "neighbor_miss", "ttl_error"]
_FALLBACK_ROUTE_TYPE = ["bgp", "bgpv6", "ip2me", "neighbor_miss"]
_FALLBACK_TRAP_ID_SAI = {
    "arp": ["ARP_REQUEST", "ARP_RESPONSE"], "arp_req": ["ARP_REQUEST"], "arp_resp": ["ARP_RESPONSE"],
    "neigh_discovery": ["IPV6_NEIGHBOR_DISCOVERY"], "lldp": ["LLDP"], "lacp": ["LACP"],
    "udld": ["UDLD"], "ttl_error": ["TTL_ERROR"], "bgp": [], "bgpv6": [], "ip2me": [], "neighbor_miss": [],
}
_FALLBACK_RATE_TIERS = [[4, 6000], [4, 600], [4, 100], [1, 200], [1, 6000], [0, 600]]

# Full set of device-enabled trap-ids (STATE_DB COPP_TRAP_TABLE) -- parametrization source, no longer hardcoded.
ENABLED_TRAP_IDS = list(_COPP.get("enabled_trap_ids", _FALLBACK_ENABLED_TRAP_IDS))
# Route-type trap-ids (L3 lookup products, not modeled as ASIC HOSTIF_TRAP) -- device-specific (some devices have them, some empty).
ROUTE_TYPE_TRAP_IDS = set(_COPP.get("route_type_trap_ids", _FALLBACK_ROUTE_TYPE))
# Lower bound on non-default trap-group count (structural integrity).
MIN_TRAP_GROUPS = int(_COPP.get("min_trap_groups", 6))
# trap-id -> the SAI_HOSTIF_TRAP_TYPE_* expected to be programmed to the ASIC (profile omits the prefix, filled in here); empty list = route-type.
_TRAP_ID_TO_SAI = {
    tid: ["SAI_HOSTIF_TRAP_TYPE_" + t for t in sais]
    for tid, sais in _COPP.get("trap_id_sai", _FALLBACK_TRAP_ID_SAI).items()
}
# Full set of SAI types this device declares as expected-to-be-programmed to the ASIC (used by the generic TRAP_TYPES test to decide strict assert vs graceful skip).
EXPECTED_SAI_TYPES = {s for sais in _TRAP_ID_TO_SAI.values() for s in sais}
# (queue, CIR) rate-tier baseline: if declared, compare strictly (regression); if not declared (empty), degrade to structural validation.
EXPECTED_RATE_TIERS = {tuple(t) for t in _COPP.get("expected_rate_tiers", _FALLBACK_RATE_TIERS)}

# Valid SAI packet actions (for structural validation): TRAP/COPY/DROP are punt/drop class; FORWARD/DENY/LOG
# etc. are also valid SAI actions -- assert action is a known valid value, just catch empty/dangling,
# don't misjudge a device's legitimate non-punt action as a defect.
_VALID_TRAP_ACTIONS = {"TRAP", "COPY", "DROP", "FORWARD", "DENY", "LOG", "TRANSIT", "COPY_CANCEL"}


def _asic_trap_types(asicdb):
    """Collect the set of SAI_HOSTIF_TRAP_TYPE_* already programmed in the ASIC."""
    return {asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE")
            for t in asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP")}


def test_hostif_trap_objects_present(asicdb):
    """ASIC should install a batch of HOSTIF_TRAP (CoPP traps)."""
    n = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF_TRAP:*")
    assert n >= 5, f"Too few HOSTIF_TRAP ({n}), CoPP traps not properly installed"


def test_hostif_trap_group_present(asicdb):
    n = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP:*")
    assert n > 0, "No HOSTIF_TRAP_GROUP (CoPP group missing)"


def test_copp_config_present(cli, asicdb):
    """CoPP truly takes effect **to the chip**: STATE_DB COPP_TRAP_TABLE/CONFIG_DB has trap config (coppmgrd applied),
    and these traps are programmed as ASIC SAI_OBJECT_TYPE_HOSTIF_TRAP (control plane -> chip), and show copp doesn't crash.

    Before the upgrade this only checked STATE/CONFIG_DB keys + show not crashing (pure config side); now it additionally asserts the ASIC really has HOSTIF_TRAP objects.
    """
    installed = cli.db_keys("STATE_DB", "COPP_TRAP_TABLE|*")
    cfg = cli.db_keys("CONFIG_DB", "COPP_TRAP|*") or cli.db_keys("CONFIG_DB", "COPP_GROUP|*")
    assert installed or cfg, "no CoPP trap installed in STATE_DB nor configured in CONFIG_DB"
    traps = asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP")
    assert traps, ("CoPP configured (STATE/CONFIG_DB) but 0 SAI_OBJECT_TYPE_HOSTIF_TRAP in ASIC -- "
                   "traps not programmed to chip")
    out = cli.run("show copp configuration detailed").out
    assert "Traceback" not in out, "show copp crashed"


@pytest.mark.parametrize("trap", TRAP_TYPES)
def test_copp_trap_type_known(asicdb, trap):
    """Each generic trap type: if **this device's profile declares it expected**, assert it is truly programmed as an ASIC HOSTIF_TRAP
    (exact match to the chip by SAI trap-type); otherwise handle gracefully per device design.

    Device-agnostic: whether to assert strictly is decided by the union of the profile's copp.trap_id_sai (EXPECTED_SAI_TYPES),
    no longer by hardcoded ENABLED_TRAP_IDS naming.
    - Route-type (bgp/bgpv6/ip2me, an L3 lookup product from the generic viewpoint): a known route-type is correct behavior, PASS.
    - Not declared enabled by this device's profile (e.g. udld, or dhcp/bfd/ssh/snmp/sample_packet not enabled): honest skip.
    - Declared expected but not programmed to the chip: expose the defect (don't skip to hide it).
    """
    want = _TRAP_TO_SAI.get(trap)   # generic trap name -> SAI_HOSTIF_TRAP_TYPE_*
    if not want:
        # by-design: route-type traps (bgp/bgpv6/ip2me) are, from the generic viewpoint, L3 lookup results and
        # correctly not modeled as ASIC HOSTIF_TRAP (some devices do model them as traps, covered strictly by test_copp_trap_id_installed).
        assert trap in ("bgp", "bgpv6", "ip2me"), \
            f"trap '{trap}' has empty SAI mapping but is not a known route-type trap"
        return
    # Only assert programming to the ASIC strictly when this device's profile declares this trap expected (its SAI type is in the copp.trap_id_sai union);
    # undeclared traps (device by-design does not enable) get an honest skip rather than being misjudged as a defect.
    if not any(w in EXPECTED_SAI_TYPES for w in want):
        pytest.skip(
            f"trap '{trap}' ({want}) not declared enabled on this device "
            f"(not in profile copp.trap_id_sai); by design, no defect")
    installed = _asic_trap_types(asicdb)
    # A hit proves this trap is truly programmed to the chip (checked by SAI type, not a pure-STATE_DB false pass).
    assert any(w in installed for w in want), \
        f"DEVICE DEFECT (uncertain): trap '{trap}' ({want}) not programmed as ASIC HOSTIF_TRAP " \
        f"(have {sorted(installed)}); device profile declares it enabled but chip lacks it"


# ===== Extension: all trap-group / all trap-id coverage =====

def _oid(key):
    """ASIC_STATE:SAI_OBJECT_TYPE_X:oid:0x.. -> oid:0x.."""
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def test_all_trap_groups_have_policer(asicdb):
    """Every (non-default) trap-group is bound to a policer -- CoPP rate limiting is in effect for all user groups (covers all trap-groups).

    Excludes the SAI default trap-group (a pre-built group with no queue/no policer, legitimately unlimited, device-dependent) -- see framework
    hostif_trap_groups(exclude_default=True).
    """
    groups = asicdb.hostif_trap_groups(exclude_default=True)
    assert groups, "no user HOSTIF_TRAP_GROUP installed (excluding SAI default group)"
    unbound = [_oid(g) for g in groups
               if (asicdb.field(g, "SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER") or "oid:0x0") == "oid:0x0"]
    assert not unbound, f"{len(unbound)}/{len(groups)} trap-groups without policer: {unbound}"


def test_all_copp_policers_valid_rate(asicdb):
    """Every CoPP policer has a valid CIR (real rate limit, non-zero)."""
    pols = asicdb.objects("SAI_OBJECT_TYPE_POLICER")
    assert pols, "no POLICER installed"
    bad = []
    for p in pols:
        cir = asicdb.field(p, "SAI_POLICER_ATTR_CIR") or "0"
        if not cir.isdigit() or int(cir) <= 0:
            bad.append((_oid(p), cir))
    assert not bad, f"policers with invalid/zero CIR: {bad}"


def test_all_traps_mapped_to_group(asicdb):
    """Every trap-id maps to an existing trap-group + has a packet action (covers all trap-ids, no dangling)."""
    traps = asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP")
    assert traps, "no HOSTIF_TRAP installed"
    gset = set(_oid(g) for g in asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP"))
    bad = []
    for t in traps:
        grp = asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP")
        act = asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION")
        ttype = asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE")
        if not grp or grp not in gset or not act:
            bad.append((ttype, grp, act))
    assert not bad, f"traps with missing/dangling group or action: {bad}"


def test_statedb_traps_reflected_in_asic(cli, asicdb):
    """**Every** trap installed in STATE_DB COPP_TRAP_TABLE maps one-by-one to an ASIC HOSTIF_TRAP (control plane -> data plane,
    checked exactly by SAI trap-type).

    Before the upgrade this only asserted n_asic>=1 (too loose with many traps: skipping most could still pass); now it reuses the
    _TRAP_ID_TO_SAI mapping from sibling test test_copp_trap_id_installed, mapping each STATE_DB trap-id -> SAI_HOSTIF_TRAP_TYPE_*,
    requiring every FP-match class trap to find its corresponding type in an ASIC HOSTIF_TRAP. Route-type traps (bgp/bgpv6/ip2me/neighbor_miss)
    are produced by the L3 lookup and not modeled as HOSTIF_TRAP, honestly recorded as skipped one-by-one (not counted as missing)."""
    installed = [k.split("|")[-1] for k in cli.db_keys("STATE_DB", "COPP_TRAP_TABLE|*")
                 if "CAPABILITY" not in k]
    assert installed, "no COPP_TRAP_TABLE installed in STATE_DB"
    asic_types = _asic_trap_types(asicdb)
    assert asic_types, f"STATE_DB has {len(installed)} traps but ASIC has 0 HOSTIF_TRAP"

    route_type = []   # route-type traps: not modeled as HOSTIF_TRAP, honestly skipped (not missing)
    unmapped = []     # trap-ids not in the mapping table: cannot check by SAI type, skipped
    matched = []      # FP-match class traps successfully mapped one-by-one to an ASIC HOSTIF_TRAP
    missing = []      # FP-match class trap but no corresponding HOSTIF_TRAP found in the ASIC (real defect)
    for trap in installed:
        want = _TRAP_ID_TO_SAI.get(trap)
        if want is None:
            unmapped.append(trap)
        elif not want:
            route_type.append(trap)
        elif any(w in asic_types for w in want):
            matched.append(trap)
        else:
            missing.append((trap, want))

    # The device should install FP-match class HOSTIF_TRAPs (arp/lldp/lacp/udld/ttl_error etc.); if not a single one
    # is verified, expose the defect (no longer skip to hide it).
    assert matched, (f"DEVICE DEFECT: no FP-match trap mapped to ASIC HOSTIF_TRAP "
                     f"(route={route_type}, unmapped={unmapped}); device should install FP-match HOSTIF_TRAPs")
    assert not missing, (f"STATE_DB traps not reflected as ASIC HOSTIF_TRAP: {missing} "
                         f"(ASIC trap types: {sorted(t for t in asic_types if t)})")


# ===== Extension 2: per-trap-id + per-trap-group + rate-tier coverage (device-agnostic: expected values from profile.copp) =====
# ENABLED_TRAP_IDS / _TRAP_ID_TO_SAI / ROUTE_TYPE_TRAP_IDS / EXPECTED_RATE_TIERS / MIN_TRAP_GROUPS
# are all loaded at the top of the file from the copp section of topology/profiles.yaml for the current device
# (no longer hardcoding ASIC_TRAP_SPEC exact queue/priority numbers; topology switched to structural assertions, see test_copp_asic_trap_topology).


def _grp_queue(asicdb, grp):
    """trap-group OID (\"oid:0x..\") -> queue number (int) or None."""
    q = asicdb.field("ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP:" + grp,
                     "SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE")
    return int(q) if q and q.isdigit() else None


def _grp_policer_attr(asicdb, grp, attr):
    """A given attribute (int) of the policer bound to the trap-group, or None."""
    pol = asicdb.field("ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP:" + grp,
                       "SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER")
    if not pol or pol == "oid:0x0":
        return None
    v = asicdb.field("ASIC_STATE:SAI_OBJECT_TYPE_POLICER:" + pol, attr)
    return int(v) if v and v.isdigit() else None


@pytest.mark.parametrize("trap_id", ENABLED_TRAP_IDS)
def test_copp_trap_id_installed(cli, asicdb, trap_id):
    """Every enabled trap-id is installed into STATE_DB COPP_TRAP_TABLE (coppmgrd applied),
    and FP-match class traps are further programmed as ASIC HOSTIF_TRAP (control plane -> chip, checked by SAI type).

    Before the upgrade this only checked STATE_DB (weak); now it keeps the STATE_DB installation assertion and adds the ASIC HOSTIF_TRAP mapping check.
    Route-type traps (bgp/bgpv6/ip2me/neighbor_miss) are not modeled as HOSTIF_TRAP, so only STATE_DB installation is validated.
    """
    keys = [k.split("|")[-1] for k in cli.db_keys("STATE_DB", "COPP_TRAP_TABLE|*")
            if "CAPABILITY" not in k]
    assert trap_id in keys, \
        f"trap-id '{trap_id}' not installed in STATE_DB COPP_TRAP_TABLE (have {sorted(keys)})"
    want = _TRAP_ID_TO_SAI.get(trap_id)
    if not want:
        # by-design: route-type traps are L3 lookup results, correctly not modeled as ASIC HOSTIF_TRAP; STATE_DB installation
        # is already asserted above -> asserting it is in this device's profile-declared route-type set is correct behavior PASS (device-specific: some have it, some don't).
        assert trap_id in ROUTE_TYPE_TRAP_IDS, \
            f"trap-id '{trap_id}' has empty SAI mapping but is not a declared route-type trap " \
            f"(profile copp.route_type_trap_ids={sorted(ROUTE_TYPE_TRAP_IDS)})"
        return
    installed = _asic_trap_types(asicdb)
    assert any(w in installed for w in want), \
        f"trap-id '{trap_id}' expected one of {want} in ASIC HOSTIF_TRAP (have {sorted(installed)})"


def test_copp_asic_trap_topology(asicdb):
    """Every installed ASIC HOSTIF_TRAP is **structurally** correct in topology (device-agnostic):
    a valid trap-group, valid packet action, the group's bound queue (0-7) exists, and the group has a valid CIR>0 rate limit.

    No longer asserts exact queue/priority numbers (q3 vs q4, prio2 vs prio4 are legitimate device differences, should not fail) --
    exact tier regression is protected per-device by test_copp_rate_tiers against the profile-declared expected_rate_tiers.
    """
    traps = asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP")
    assert traps, "no HOSTIF_TRAP installed"
    gset = set(_oid(g) for g in asicdb.objects("SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP"))
    bad = []
    for t in traps:
        ttype = (asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE") or "").replace("SAI_HOSTIF_TRAP_TYPE_", "")
        grp = asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP")
        act = (asicdb.field(t, "SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION") or "").replace("SAI_PACKET_ACTION_", "")
        # 1) valid and existing trap-group
        if not grp or grp == "oid:0x0" or grp not in gset:
            bad.append((ttype, f"bad trap-group {grp}"))
            continue
        # 2) valid packet action (TRAP/COPY/DROP are punt/drop class; FORWARD etc. also valid, see _VALID_TRAP_ACTIONS)
        if act not in _VALID_TRAP_ACTIONS:
            bad.append((ttype, f"invalid action {act!r}"))
            continue
        # 3) group's bound queue exists and is valid (0-7)
        q = _grp_queue(asicdb, grp)
        if q is None or not (0 <= q <= 7):
            bad.append((ttype, f"bad queue {q}"))
            continue
        # 4) group has a valid CIR>0 rate limit
        cir = _grp_policer_attr(asicdb, grp, "SAI_POLICER_ATTR_CIR")
        if not cir or cir <= 0:
            bad.append((ttype, f"no valid CIR ({cir})"))
    assert not bad, f"HOSTIF_TRAP topology structurally invalid: {bad}"


def test_copp_trap_groups_complete(asicdb):
    """All (non-default) trap-groups are structurally complete: valid queue (0-7) + bound policer + CIR>0 + CBS>0 (covers all groups).

    Excludes the SAI default group (a pre-built group with no queue/no policer, legitimately unlimited); the group-count lower bound is declared per-device by profile.copp.min_trap_groups.
    """
    groups = asicdb.hostif_trap_groups(exclude_default=True)
    assert len(groups) >= MIN_TRAP_GROUPS, \
        f"user trap-group count={len(groups)}, expected >={MIN_TRAP_GROUPS} (excluding SAI default group)"
    bad = []
    for g in groups:
        grp = _oid(g)
        q = _grp_queue(asicdb, grp)
        cir = _grp_policer_attr(asicdb, grp, "SAI_POLICER_ATTR_CIR")
        cbs = _grp_policer_attr(asicdb, grp, "SAI_POLICER_ATTR_CBS")
        if q is None or not (0 <= q <= 7) or not cir or cir <= 0 or not cbs or cbs <= 0:
            bad.append((grp, q, cir, cbs))
    assert not bad, f"trap-group queue/cir/cbs invalid: {bad}"


def test_copp_rate_tiers(asicdb):
    """Validates the (queue, CIR) rate tiers of each (non-default) CoPP trap-group.

    Device-agnostic: if profile.copp declares expected_rate_tiers, **compare strictly** against this device's baseline
    (rate-limit regression protection, each device by its own legitimate tiers); if not declared, degrade to structural validation (each tier: valid queue + CIR>0).
    """
    tiers = set()
    for g in asicdb.hostif_trap_groups(exclude_default=True):
        grp = _oid(g)
        q = _grp_queue(asicdb, grp)
        cir = _grp_policer_attr(asicdb, grp, "SAI_POLICER_ATTR_CIR")
        if q is not None and cir:
            tiers.add((q, cir))
    assert tiers, "no CoPP rate tiers found on any user trap-group"
    if EXPECTED_RATE_TIERS:
        assert tiers == EXPECTED_RATE_TIERS, \
            f"CoPP rate tiers changed (device baseline regression): measured {sorted(tiers)}, baseline {sorted(EXPECTED_RATE_TIERS)}"
    else:
        # No device baseline declared: structural validation (no exact numeric regression, to avoid misjudging legitimate device differences as regressions)
        invalid = [(q, c) for (q, c) in tiers if not (0 <= q <= 7) or c <= 0]
        assert not invalid, f"invalid rate tiers (queue out of 0-7 or CIR<=0): {invalid}"


# ---- Data plane: verify FP-match class traps punt to CPU one-by-one (loopback + src MAC to distinguish) ----
_SMAC = {"lldp": "02:00:00:c0:00:01", "lacp": "02:00:00:c0:00:02", "udld": "02:00:00:c0:00:03",
         "arp_req": "02:00:00:c0:00:04", "arp_resp": "02:00:00:c0:00:05",
         "nd_ns": "02:00:00:c0:00:06", "nd_na": "02:00:00:c0:00:07",
         "dhcp": "02:00:00:c0:00:08", "dhcpv6": "02:00:00:c0:00:09"}

# Data-plane trap name -> corresponding SAI_HOSTIF_TRAP_TYPE_* (decides whether this device declares the trap enabled; if not, skip gracefully).
_SMAC_TO_SAI = {
    "lldp": "SAI_HOSTIF_TRAP_TYPE_LLDP", "lacp": "SAI_HOSTIF_TRAP_TYPE_LACP",
    "udld": "SAI_HOSTIF_TRAP_TYPE_UDLD", "arp_req": "SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST",
    "arp_resp": "SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE",
    "nd_ns": "SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY",
    "nd_na": "SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY",
    "dhcp": "SAI_HOSTIF_TRAP_TYPE_DHCP",
    "dhcpv6": "SAI_HOSTIF_TRAP_TYPE_DHCPV6",
}


def _trap_pkt(name, smac):
    from scapy.all import (ARP, BOOTP, DHCP, DHCP6_Solicit, Ether, ICMPv6ND_NA,
                           ICMPv6ND_NS, IP, IPv6, Raw, UDP)
    if name == "lldp":
        return Ether(dst="01:80:c2:00:00:0e", src=smac, type=0x88cc) / Raw(b"\x02\x07\x04" + b"x" * 40), "ether proto 0x88cc"
    if name == "lacp":
        return Ether(dst="01:80:c2:00:00:02", src=smac, type=0x8809) / Raw(b"\x01\x01" + b"x" * 40), "ether proto 0x8809"
    if name == "udld":
        return Ether(dst="01:00:0c:cc:cc:cc", src=smac) / Raw(b"x" * 50), "ether dst 01:00:0c:cc:cc:cc"
    if name == "arp_req":
        return Ether(dst="ff:ff:ff:ff:ff:ff", src=smac) / ARP(op=1, pdst="1.2.3.4"), "arp"
    if name == "arp_resp":
        return Ether(dst="ff:ff:ff:ff:ff:ff", src=smac) / ARP(op=2, pdst="1.2.3.4", psrc="1.2.3.5"), "arp"
    if name == "nd_ns":
        return Ether(dst="33:33:ff:00:00:01", src=smac) / IPv6(dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="fe80::1"), "icmp6"
    if name == "nd_na":
        return Ether(dst="33:33:00:00:00:01", src=smac) / IPv6(dst="ff02::1") / ICMPv6ND_NA(tgt="fe80::2"), "icmp6"
    if name == "dhcp":
        # Standard DHCP discover: UDP 68->67 broadcast (FP-match trap, reliably testable over loopback)
        chaddr = bytes(int(b, 16) for b in smac.split(":")) + b"\x00" * 10
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=smac) /
                IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
                BOOTP(chaddr=chaddr, xid=0xc0de) /
                DHCP(options=[("message-type", "discover"), "end"]), "udp port 67")
    if name == "dhcpv6":
        # Standard DHCPv6 Solicit: UDP 546->547 to ff02::1:2 (All_DHCP_Relay_Agents_and_Servers)
        return (Ether(dst="33:33:00:01:00:02", src=smac) /
                IPv6(src="fe80::2", dst="ff02::1:2") / UDP(sport=546, dport=547) /
                DHCP6_Solicit(trid=0xc0de), "udp port 547")
    raise ValueError(name)


# Injection-context matrix semantics correction:
# - slow protocol (link-local, no class qualification): must punt in both L2-port and L3 contexts, dual parametrization;
# - protocol-class trap (ARP/ND/DHCP, IFP entry with L3_IIF class qualification): should only punt in the L3 context,
#   not disturbing the CPU with a pure-L2-port packet is the correct semantics.
# l2 param first: copp_l3_ctx is module-level; once established at the first l3 param, the port is in the SVI VLAN, so order is sensitive
# (getfixturevalue is fetched dynamically inside the test to stop pytest from regrouping/reordering by fixture).
_SLOW_PROTOS = ["lldp", "lacp", "udld"]
_L3_PROTOS = ["arp_req", "arp_resp", "nd_ns", "nd_na", "dhcp", "dhcpv6"]
_CTX_PARAMS = ([(n, "l2") for n in _SLOW_PROTOS] +
               [(n, "l3") for n in _SLOW_PROTOS] +
               [(n, "l3") for n in _L3_PROTOS])


@pytest.mark.traffic
@pytest.mark.parametrize("name,ctx", _CTX_PARAMS, ids=[f"{n}-{c}" for n, c in _CTX_PARAMS])
def test_trap_to_cpu(traffic, request, name, ctx):
    """FP-match class trap data plane: inject protocol packet -> loopback re-ingress -> hit trap -> punt to CPU (matched by unique src MAC).

    Injection context is dispatched by trap semantics (see _CTX_PARAMS comment): slow protocol in both contexts, protocol-class trap only
    in the L3 context (SVI VLAN, conftest.copp_l3_ctx) -- a pure L2 port not punting protocol packets is correct behavior, not tested.

    Device-agnostic: if this device's profile does not declare the trap enabled (e.g. some devices lack udld/dhcp),
    skip gracefully rather than hard-asserting it must exist.
    (Bounds review): send 10 receive 1 tolerates 90% loss and masks a half-dead punt queue -- 10 frames are well below the lowest CIR tier,
    so a healthy punt should be nearly lossless; the lower bound is raised to 8 (leaving 2 frames for sniffer start/stop races); under a unique
    src MAC, exceeding the send count = loopback replication anomaly, so add an upper bound of 10.
    """
    if _SMAC_TO_SAI.get(name) not in EXPECTED_SAI_TYPES:
        pytest.skip(f"trap '{name}' not declared enabled on this device (profile copp); by design")
    if ctx == "l3":
        request.getfixturevalue("copp_l3_ctx")
    smac = _SMAC[name]
    pkt, bpf = _trap_pkt(name, smac)
    p = traffic.ports[0]
    with traffic.capture(p, bpf=bpf, inbound=True) as cap:
        traffic.send(p, pkt, count=10)
        time.sleep(0.6)
    got = cap.match(lambda x: getattr(x, "src", None) == smac)
    assert len(got) >= 8, \
        f"trap '{name}' ({ctx} ctx) punt lossy/dead: captured {len(got)}/10 inbound pkt with src {smac}"
    assert len(got) <= 10, \
        f"trap '{name}' ({ctx} ctx) punt duplicated: captured {len(got)} > 10 injected (loopback replication?)"
