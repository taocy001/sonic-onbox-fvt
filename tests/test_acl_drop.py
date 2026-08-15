"""End-to-end scenario: ACL DROP rule blocks matching traffic (rules pushed via acl-loader + chip counter verification).

Matching traffic is DROPped (egress port TX does not grow), non-matching traffic forwards normally.
# VERIFY-ON-HW: acl-loader json fields, binding, and counter behavior need on-hardware confirmation.
"""
import json
import time

import pytest

pytestmark = [pytest.mark.scenario, pytest.mark.acl, pytest.mark.traffic]

TABLE = "SCEN_ACL"

RULES = {
    "acl": {
        "acl-sets": {
            "acl-set": {
                TABLE: {
                    "acl-entries": {
                        "acl-entry": {
                            "1": {
                                "config": {"sequence-id": 1},
                                "ip": {"config": {"protocol": 17}},
                                "transport": {"config": {"destination-port": 4444}},
                                "actions": {"config": {"forwarding-action": "DROP"}},
                            }
                        }
                    }
                }
            }
        }
    }
}


def _accum_tx_pkt(traffic, port, floor=None, window=3.0):
    """Poll and accumulate the chip TX delta for port with a confirmation read (same pattern as smoke_check).

    `show c` has "delta since last read" semantics: a single read after a fixed sleep misses counts
    that land late via DMA, so a negative assertion (should not forward) reads 0 -> ACL not in effect
    also falsely passes. When floor is given (positive control), converge early once the accumulated
    total reaches the lower bound; on the negative side no floor is passed, so read the full window +
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


def test_acl_drop_matching_traffic(cli, dut, traffic, config_guard, topo, l2_fwd_vlan):
    from scapy.all import Ether, IP, UDP, Raw

    pin, pout = traffic.ports[0], traffic.ports[1]
    dmac = topo.mac("dst")
    # On some platforms the parking VLAN does not forward, so a real test VLAN must be used, otherwise
    # baseline forwarding silently fails on the parking port and the ACL cannot be judged.
    # On regular devices l2_fwd_vlan==default_vlan, so behavior is unchanged.
    dvlan = l2_fwd_vlan

    # FDB makes dmac unicast-forward to pout
    cli.fdb_static_add(dvlan, dmac, pout.name)
    # Bind ACL table to the ingress port + DROP UDP/4444 rule
    cli.config_raw(f"acl add table {TABLE} L3 -p {pin.name}")
    config_guard.defer_undo(f"acl remove table {TABLE}")
    rules_path = "/tmp/scen_acl.json"
    cli.sh.run(f"cat > {rules_path} <<'EOF'\n{json.dumps(RULES)}\nEOF", check=False)
    r = cli.sh.run(f"acl-loader update full {rules_path}", check=False)
    if r.rc != 0 or "Error" in (r.out + r.err) or "Traceback" in (r.out + r.err):
        cli.fdb_static_del(dvlan, dmac)
        pytest.fail(f"acl-loader failed to program ACL rules: {(r.out + r.err)[-200:]}")
    traffic.loop(pout)
    time.sleep(2)
    try:
        # Matching traffic (UDP/4444) should be DROPped -> pout TX does not grow
        # Counting goes clear -> poll-accumulate + confirmation read (show c delta semantics);
        # on the negative side read the full window to avoid a false pass from missed counts
        match = Ether(dst=dmac, src=topo.mac("src")) / IP() / UDP(dport=4444) / Raw(b"x" * 40)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, match, count=100)
        dmatch = _accum_tx_pkt(traffic, pout)
        assert dmatch <= 5, f"ACL DROP not working: matching traffic still forwarded {dmatch} frames"

        # Non-matching traffic (UDP/5555) should forward normally -> pout TX grows (positive control with a storm upper bound)
        good = Ether(dst=dmac, src=topo.mac("src")) / IP() / UDP(dport=5555) / Raw(b"x" * 40)
        traffic.clear_chip_counters()
        time.sleep(0.3)
        traffic.send(pin, good, count=100)
        dgood = _accum_tx_pkt(traffic, pout, floor=90)
        assert 90 <= dgood < 100 + 3000, \
            f"Non-matching traffic not forwarded normally (or storm): TX+{dgood}"
    finally:
        traffic.unloop(pout)
        cli.fdb_static_del(dvlan, dmac)
        # Clear the rules pushed by acl-loader: `acl remove table` does not cascade-delete rules ->
        # leftover orphan ACL_RULE breaks GCU whole-tree YANG validation (test_gcu all fail).
        # Explicitly delete all rules of this table.
        for k in cli.db_keys("CONFIG_DB", f"ACL_RULE|{TABLE}|*"):
            cli.sh.run(f"sonic-db-cli CONFIG_DB DEL '{k}'", check=False)
