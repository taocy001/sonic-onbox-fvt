"""Productized routing-policy CLI (prefix-list / route-map / BGP instance) -- config-plane ground-truth verification.

Background: routing configuration on the modified OS always goes through the sonic `config` product commands
(vtysh does not carry configuration on this product). These are must-have switch features, previously skipped due to
"missing community tooling" -- testing shows the product command groups `config prefix / route-map / bgp` all exist, so
add real coverage on that basis: CLI programs -> CONFIG_DB ground truth -> show rendering consistent -> clean deletion.

Images without these command groups (community images lack these product extension groups) skip after probing (structural, justified).
Print/assert/skip in English; comments/docstrings in English. Added behavior-level coverage: test_route_policy_filters_bgp_routes reuses
test_bgp.py's NetnsBgpPeer/VirtualLink infrastructure to verify prefix-list/route-map really block/pass BGP routes (at RIB/ASIC level).
"""
import time

import pytest

pytestmark = [pytest.mark.l3]


# (The old _has_group was removed: dead code with no callers anywhere in the repo, plus an and/or
#  precedence bug that wrongly returned True when rc!=0 as long as the output contained "Usage". For boolean probing reuse _require_group's criteria.)
def _require_group(cli, group):
    r = cli.sh.run(f"config {group} --help", check=False)
    if r.rc != 0 or ("add" not in (r.out or "")):
        pytest.skip(f"`config {group}` command group not shipped on this image (structural)")


def test_prefix_list_product_cli(cli, config_guard):
    """prefix-list: add -> CONFIG_DB PREFIX table ground truth -> `show ip prefix-list` rendering -> clean del."""
    _require_group(cli, "prefix")
    name, seq, pfx = "FVT_PL1", "10", "10.99.0.0/16"
    rc, r = cli.config_raw(f"prefix add {name} {seq} {pfx} -mr exact -a permit")
    assert rc == 0, f"config prefix add failed: {r.err or r.out}"
    config_guard.defer_undo(f"prefix del {name} {seq} {pfx} -mr exact -a permit")

    keys = [k for k in cli.db_keys("CONFIG_DB", "PREFIX*") if name in k]
    assert keys, f"prefix-list {name} not written to CONFIG_DB (no PREFIX* key contains it)"
    vals = " ".join(str(v) for k in keys for v in cli.db_hgetall("CONFIG_DB", k).values())
    assert pfx in vals or pfx in " ".join(keys), \
        f"prefix {pfx} not present in CONFIG_DB entries {keys}"

    out = cli.run("show ip prefix-list").out or ""
    assert name in out and pfx in out, \
        f"`show ip prefix-list` does not render {name}/{pfx}:\n{out[:400]}"


def test_route_map_product_cli(cli, config_guard):
    """route-map: add (permit + set next-hop) -> CONFIG_DB ROUTE_MAP ground truth -> show rendering -> del."""
    _require_group(cli, "route-map")
    name, stmt, nh = "FVT_RM1", "10", "10.99.1.1"
    rc, r = cli.config_raw(f"route-map add {name} {stmt} -o permit -N {nh}")
    assert rc == 0, f"config route-map add failed: {r.err or r.out}"
    config_guard.defer_undo(f"route-map del {name} {stmt}")

    attrs = (cli.db_hgetall("CONFIG_DB", f"ROUTE_MAP|{name}|{stmt}")
             or cli.db_hgetall("CONFIG_DB", f"ROUTE_MAP|{name}"))
    assert attrs, f"ROUTE_MAP|{name}|{stmt} not written to CONFIG_DB"
    vals = " ".join(str(v) for v in attrs.values())
    assert nh in vals, f"set next-hop {nh} not in CONFIG_DB route-map entry: {attrs}"

    out = cli.run("show route-map all").out or ""
    assert name in out, f"`show route-map all` does not render {name}:\n{out[:400]}"


def test_bgp_instance_product_cli(cli, config_guard):
    """BGP instance: `config bgp add default -a <asn> -r <router-id>` -> CONFIG_DB BGP_GLOBALS
    ground truth (asn/router-id) -> `show bgp summary` does not crash and reflects the instance -> key disappears after del.

    A single node can verify the closed loop (create/query/delete); neighbor session-level behavior needs a peer and is out of scope for this case."""
    _require_group(cli, "bgp")
    asn, rid = "65001", "10.9.9.9"
    rc, r = cli.config_raw(f"bgp add default -a {asn} -r {rid}")
    assert rc == 0, f"config bgp add failed: {r.err or r.out}"
    config_guard.defer_undo("bgp del default")
    try:
        attrs = {}
        for _ in range(10):
            attrs = (cli.db_hgetall("CONFIG_DB", "BGP_GLOBALS|default") or {})
            if attrs:
                break
            time.sleep(0.5)
        assert attrs, "BGP_GLOBALS|default not written to CONFIG_DB after config bgp add"
        vals = " ".join(str(v) for v in attrs.values())
        assert asn in vals, f"local ASN {asn} not in BGP_GLOBALS: {attrs}"
        assert rid in vals, f"router-id {rid} not in BGP_GLOBALS: {attrs}"
        # Content check: config must really reach FRR bgpd. With no neighbors, `show bgp summary` only prints
        # "No BGP neighbors found" and does not echo the local AS (FRR has already run `router bgp 65001`
        # but summary does not show the ASN when there are no neighbors) -- so the assertion instead checks FRR
        # running-config's `router bgp <asn>` (end-to-end real evidence), with summary only verified not to crash.
        # FRR sync has a seconds-level delay, so poll until it lands.
        run = ""
        for _ in range(20):
            assert "Traceback" not in (cli.run("show bgp summary").out or ""), "`show bgp summary` crashed"
            run = (cli.run("show runningconfiguration bgp").out or "")
            if f"router bgp {asn}" in run:
                break
            time.sleep(0.5)
        assert f"router bgp {asn}" in run, \
            f"configured ASN {asn} did not reach FRR bgpd (`show runningconfiguration bgp`):\n{run[:400]}"
    finally:
        cli.config_raw("bgp del default")
        for _ in range(10):
            if not cli.db_hgetall("CONFIG_DB", "BGP_GLOBALS|default"):
                break
            time.sleep(0.5)
        assert not cli.db_hgetall("CONFIG_DB", "BGP_GLOBALS|default"), \
            "BGP_GLOBALS|default still present after `config bgp del default` (cleanup broken)"


def test_static_arp_product_cli(cli, topo, l3up, config_guard):
    """Static ARP product CLI: `config arp static add <ip> <mac> <intf>` -> CONFIG_DB NEIGH table +
    ASIC NEIGHBOR_ENTRY -> `config arp static del <intf> <ip>` (note del argument order is reversed from add)
    deletes cleanly. This is dedicated coverage for the product static ARP -- the test scaffolding still uses
    kernel ip neigh (this product's static ARP is tightly-coupled config: attaching it to an interface changes
    interface ip add semantics, unsuitable as scaffolding)."""
    _require_group(cli, "arp static")
    sub = topo.subnet("c")
    port = topo.l3_port(0)
    l3up(port.name, f"{sub['dut']}/{sub['prefix']}")
    ip, mac = sub["peer"], "00:aa:bb:cc:dd:c9"
    rc, r = cli.config_raw(f"arp static add {ip} {mac} {port.name}")
    assert rc == 0, f"config arp static add failed: {r.err or r.out}"
    # del argument order = <intf> <ip> (reversed from add; register a belt-and-suspenders undo within the case)
    config_guard.defer_undo(f"arp static del {port.name} {ip}")
    try:
        keys = []
        for _ in range(10):
            keys = cli.db_keys("CONFIG_DB", f"NEIGH|{port.name}|{ip}")
            if keys:
                break
            time.sleep(0.5)
        assert keys, f"NEIGH|{port.name}|{ip} not written to CONFIG_DB after arp static add"
        found = False
        for _ in range(16):
            for k in cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:*"):
                if ip in k:
                    found = True
                    break
            if found:
                break
            time.sleep(0.5)
        assert found, (f"static ARP {ip} in CONFIG_DB but no ASIC NEIGHBOR_ENTRY programmed "
                       "(config->chip neighbor path broken)")
    finally:
        cli.config_raw(f"arp static del {port.name} {ip}")
        for _ in range(10):
            if not cli.db_keys("CONFIG_DB", f"NEIGH|{port.name}|{ip}"):
                break
            time.sleep(0.5)
        assert not cli.db_keys("CONFIG_DB", f"NEIGH|{port.name}|{ip}"), \
            "NEIGH entry still present after arp static del (cleanup broken; would block ip add)"


# ---------------------------------------------------------------------------
# Behavior-level: prefix-list/route-map really filter BGP routes (high-scrutiny: previously the whole file stopped
# at CONFIG_DB echo + show rendering, with zero coverage of the "block/pass route" policy behavior)
# ---------------------------------------------------------------------------
def _wait(pred, timeout=30, interval=1.0):
    """Poll pred() for truth, returning whether it was met (borrowed from test_bgp.py)."""
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    return False


def _vtysh(cli, args):
    """vtysh read-only query (configuration always goes through the product config commands; vtysh only reads FRR state)."""
    r = cli.run(f"vtysh -c '{args}'")
    return (r.out or "") + "\n" + (r.err or "")


@pytest.mark.bgp
def test_route_policy_filters_bgp_routes(cli, dut, _lb, asicdb, topo, config_guard):
    """Real behavior of inbound routing policy: a software peer (NetnsBgpPeer) advertises two prefixes, the DUT
    attaches an inbound route-map (match prefix-list permits only B) -- B is programmed end-to-end into ASIC
    ROUTE_ENTRY (positive), A enters neither the BGP RIB nor the ASIC (negative control, route-map implicit deny);
    then rebind to permit-all and re-advertise, and A is added into the ASIC (proving the earlier absence was
    caused by policy, not a session/link failure).

    Infrastructure reused from test_bgp.py: VirtualLink (front-panel port RIF + static neighbor + MAC loopback, so
    nexthop can be programmed to ASIC) + NetnsBgpPeer (a real eBGP peer in a netns). If the product CLI groups are
    absent (community image), the probe gates a skip.
    """
    _require_group(cli, "prefix")
    _require_group(cli, "route-map")
    _require_group(cli, "bgp")
    topo.caps.require("loopback")   # front-panel port needs loopback to bring oper-up, so the nexthop resolves and programs to ASIC

    from topo.netns_peer import NetnsBgpPeer
    from topo.virtual_link import VirtualLink

    sess = topo.subnet("bgp")          # session subnet (veth+netns)
    dp = topo.subnet("c")              # nexthop subnet (front-panel port)
    dut_as, peer_as = sess["dut_as"], sess["peer_as"]
    sess_dut, sess_peer = sess["dut"], sess["peer"]
    nh_ip = dp["peer"]
    route_a, route_b = topo.route("a"), topo.route("b")   # A denied by policy, B permitted
    port = dut.pick_test_ports(1)[0]

    pl, rm_in, rm_all = "FVT_PL_B", "FVT_RM_IN", "FVT_RM_ALL"
    # prefix-list permits only B (exact); route-map stmt10 permit matches that prefix-set,
    # and a miss (A) falls to the route-map implicit deny -- verifying prefix-list matching and route-map permit/deny semantics together
    rc, r = cli.config_raw(f"prefix add {pl} 10 {route_b} -mr exact -a permit")
    assert rc == 0, f"config prefix add failed: {r.err or r.out}"
    config_guard.defer_undo(f"prefix del {pl} 10 {route_b} -mr exact -a permit")
    rc, r = cli.config_raw(f"route-map add {rm_in} 10 -o permit -r {pl}")
    assert rc == 0, f"config route-map add failed: {r.err or r.out}"
    config_guard.defer_undo(f"route-map del {rm_in} 10")

    vl = VirtualLink(cli, dut, _lb, port, dp["dut"], nh_ip,
                     prefix=dp["prefix"], peer_mac=topo.mac("peer_a"),
                     vlan=topo.default_vlan)
    peer = NetnsBgpPeer(cli, sess_dut, sess_peer, peer_as=peer_as,
                        prefix=sess["prefix"],
                        advertise=[(route_a, nh_ip), (route_b, nh_ip)])
    try:
        vl.setup()
        peer.setup()
        rc, r = cli.config_raw(f"bgp add default -a {dut_as} -r {sess_dut} -g disable")
        assert rc == 0, f"config bgp add failed: {r.err or r.out}"
        # Attach the inbound route-map at neighbor creation (-i/--route_map_in product CLI option)
        rc, r = cli.config_raw(
            f"bgp neighbor add default {sess_peer} -a {peer_as} -p external "
            f"-A ipv4-unicast -S activate -i {rm_in}")
        assert rc == 0, f"config bgp neighbor add (route-map in) failed: {r.err or r.out}"

        assert peer.start_speaker(established_timeout=25), \
            "BGP speaker failed to reach Established (handshake)"
        assert _wait(lambda: "Established" in _vtysh(cli, f"show bgp neighbor {sess_peer}"),
                     timeout=20), "FRR neighbor not Established after speaker connected"

        # Positive: permitted prefix B is programmed end-to-end into the ASIC (also proving the session/advertise/programming pipeline is alive -- only then is A's absence meaningful)
        assert asicdb.has_route(route_b, timeout=40), \
            f"permitted prefix {route_b} not programmed to ASIC ROUTE_ENTRY"
        # Negative control: denied prefix A must not be in the BGP RIB (inbound filtering drops it), and certainly must not be programmed to ASIC
        out_a = _vtysh(cli, f"show bgp ipv4 unicast {route_a}")
        assert "Paths:" not in out_a, (
            f"denied prefix {route_a} present in BGP RIB despite inbound route-map deny:\n"
            f"{out_a[:300]}")
        assert not asicdb.has_route(route_a, timeout=3), \
            f"denied prefix {route_a} programmed to ASIC despite inbound route-map deny"

        # Causal confirmation: after rebinding permit-all and re-advertising A -> A should be added into the ASIC (ruling out the "session simply not working" explanation)
        rc, r = cli.config_raw(f"route-map add {rm_all} 10 -o permit")
        assert rc == 0, f"config route-map add (permit-all) failed: {r.err or r.out}"
        config_guard.defer_undo(f"route-map del {rm_all} 10")
        rc, r = cli.config_raw(
            f"bgp neighbor update default {sess_peer} -A ipv4-unicast -i {rm_all}")
        assert rc == 0, f"config bgp neighbor update (rebind route-map) failed: {r.err or r.out}"
        time.sleep(2)   # wait for the FRR-side policy rebind to land
        got_a = False
        for _ in range(3):   # the software peer does not support route-refresh, so rely on re-advertising to trigger an UPDATE carrying the new policy
            peer.announce(route_a, nh_ip)
            if asicdb.has_route(route_a, timeout=10):
                got_a = True
                break
        assert got_a, (
            f"prefix {route_a} still absent from ASIC after rebinding permit-all route-map "
            "and re-announcing -- inbound policy change not effective")
    finally:
        cli.config_raw(f"bgp neighbor del default {sess_peer}")
        cli.config_raw("bgp del default")
        peer.teardown()
        vl.teardown()
