"""GCU (generic_config_updater) ported cases (adapted from sonic-mgmt generic_config_updater/).

Tests SONiC's **JSON-patch incremental config entry point**: a valid patch is accepted and takes effect (CONFIG_DB/show),
an invalid patch is rejected (negative), and rollback returns to baseline. Pure config+DB, no traffic needed.

Isolation: the gcu fixture checkpoints before the case and rolls back + deletes the checkpoint after, guaranteeing no pollution downstream.
All values come from topo, none hardcoded.
"""
import re
import time

import pytest

pytestmark = pytest.mark.gcu



def _table_modeled(cli, table):
    """Whether this CONFIG_DB table has a YANG model in this image (GCU can only manage modeled tables; in-process cache).
    apply-patch on a table with no YANG model reports
    'changes to tables without YANG models' -- a structural limitation, not a GCU defect."""
    cache = getattr(cli, "_yang_tbl", None)
    if cache is None:
        cache = cli._yang_tbl = {}
    if table not in cache:
        r = cli.sh.run(f"grep -rl '{table}' /usr/local/yang-models/ 2>/dev/null | head -1",
                       check=False)
        cache[table] = bool((r.out or "").strip())
    return cache[table]

# ---------- static route (key must be vrf-qualified default|<prefix>, YANG requires vrf_name) ----------
def test_gcu_static_route_crud(gcu, cli, topo, l3up):
    """patch adds a static route -> verify it lands in CONFIG_DB + **the route is really installed in the FRR RIB** (show ip route), then patch removes it -> verify it disappears.
    On a single box FRR only installs static routes whose nexthop is reachable: first use l3up to bring up the directly-connected subnet the nexthop lives in + a static neighbor to resolve the nexthop,
    only then is the static route active (otherwise it stays unresolved and never enters the RIB -- the original case failed here every time)."""
    if not _table_modeled(cli, "STATIC_ROUTE"):
        pytest.skip("STATIC_ROUTE has no YANG model; GCU cannot manage it "
                    "(structural; GCU itself is exercised by other modeled-table cases)")
    net = topo.subnet("a")
    prefix = topo.route("a")                       # e.g. 10.251.0.0/24
    nexthop = net["peer"]                           # e.g. 10.80.1.2, must be in the connected subnet and resolvable
    port = topo.port_name("c")
    l3up(port, f"{net['dut']}/{net['prefix']}")     # bring up the connected subnet -> nexthop on-link
    cli.neigh_set(nexthop, topo.mac('peer_a'), port)
    rkey = f"default|{prefix}"                      # STATIC_ROUTE YANG key = vrf|prefix
    key = f"STATIC_ROUTE|{rkey}"
    gcu.apply_patch_ok(gcu.add_entry("STATIC_ROUTE", rkey, {"nexthop": nexthop}))
    assert cli.db_keys("CONFIG_DB", key), f"STATIC_ROUTE not in CONFIG_DB after patch: {key}"
    # behavior: nexthop reachable -> FRR installs the static route into the RIB (poll for the async install)
    shown = ""
    for _ in range(10):
        shown = cli.run("show ip route").out
        if prefix.split("/")[0] in shown:
            break
        time.sleep(1)
    assert prefix.split("/")[0] in shown, "static route not installed in 'show ip route' (nexthop unresolved?)"
    # `show ip route` also shows static routes with an unresolved nexthop (inactive) -- "really installed into the FIB" is judged by the kernel:
    # zebra only pushes installed routes to the kernel. Also verify the nexthop content is correct (not just any line with the same prefix matching).
    kern = ""
    for _ in range(10):
        kern = (cli.sh.run(f"ip route show {prefix}", check=False).out or "").strip()
        if kern:
            break
        time.sleep(1)
    assert kern, f"static route {prefix} not installed into kernel FIB (zebra kept it inactive)"
    assert nexthop in kern, \
        f"kernel FIB entry for {prefix} has wrong nexthop: {kern!r} (expected via {nexthop})"
    gcu.apply_patch_ok(gcu.remove_entry("STATIC_ROUTE", rkey))
    assert not cli.db_keys("CONFIG_DB", key), "STATIC_ROUTE still in CONFIG_DB after remove patch"
    # the delete side previously only verified CONFIG_DB -- a residual FRR/kernel route would be a false pass; poll until the FIB is truly cleared
    for _ in range(10):
        kern = (cli.sh.run(f"ip route show {prefix}", check=False).out or "").strip()
        if not kern:
            break
        time.sleep(1)
    assert not kern, f"static route {prefix} still in kernel FIB after remove patch: {kern!r}"


def test_gcu_static_route_invalid_rejected(gcu):
    """A patch with an invalid prefix should be rejected by GCU (the NOS does not accept invalid config -- negative verification)."""
    gcu.apply_patch_fail(gcu.add_entry("STATIC_ROUTE", "default|999.999.0.0/24", {"nexthop": "1.1.1.1"}))


# ---------- syslog server ----------
def test_gcu_syslog_server_crud(gcu, cli, topo):
    """patch adds a SYSLOG_SERVER -> verify it lands in CONFIG_DB + **rsyslog really renders it** (the server's forwarding target IP appears in /etc/rsyslog.conf or
    /etc/rsyslog.d/), then patch removes it -> verify it is cleared from CONFIG_DB."""
    if not _table_modeled(cli, "SYSLOG_SERVER"):
        pytest.skip("SYSLOG_SERVER has no YANG model; GCU cannot manage it "
                    "(structural)")
    ip = topo.server("sflow_collector")           # reuse a test IP
    key = f"SYSLOG_SERVER|{ip}"
    gcu.apply_patch_ok(gcu.add_entry("SYSLOG_SERVER", ip, {}))
    assert cli.db_keys("CONFIG_DB", key), f"SYSLOG_SERVER not in CONFIG_DB: {key}"
    # behavior: syslog config rendering should write this server into the rsyslog config (omfwd Target / `@@?<ip>` forwarding target)
    rendered = ""
    for _ in range(15):
        rendered = cli.sh.run(
            "grep -rh . /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null", check=False).out
        if ip in rendered:
            break
        time.sleep(1)
    # SYSLOG_SERVER landed in the DB but not rendered into the rsyslog config = rendering did not take effect
    assert ip in rendered, (
        f"SYSLOG_SERVER {ip} in CONFIG_DB but not rendered as an rsyslog forwarding "
        f"target in /etc/rsyslog.* (syslog rendering inactive)")
    gcu.apply_patch_ok(gcu.remove_entry("SYSLOG_SERVER", ip))
    assert not cli.db_keys("CONFIG_DB", key), "SYSLOG_SERVER still present after remove"


# ---------- DNS nameserver ----------
def test_gcu_dns_nameserver_crud(gcu, cli, topo):
    """patch adds/removes DNS_NAMESERVER -> verify CONFIG_DB + /etc/resolv.conf take effect."""
    ip = topo.server("dhcp_server")               # reuse a test IP as the DNS server
    key = f"DNS_NAMESERVER|{ip}"
    r = gcu.apply_patch(gcu.add_entry("DNS_NAMESERVER", ip, {}))
    # GCU should support incremental config of DNS_NAMESERVER; if the patch is rejected, FAIL to expose it
    assert r.rc == 0, f"DNS_NAMESERVER GCU not accepted: {r.out or r.err}"
    assert cli.db_keys("CONFIG_DB", key), f"DNS_NAMESERVER not in CONFIG_DB: {key}"
    # behavior: dns config rendering should really write this nameserver into /etc/resolv.conf (poll for the render)
    pat = re.compile(rf"^\s*nameserver\s+{re.escape(ip)}\b", re.M)
    resolv = ""
    for _ in range(15):
        resolv = cli.sh.run("cat /etc/resolv.conf 2>/dev/null", check=False).out
        if pat.search(resolv):
            break
        time.sleep(1)
    # DNS_NAMESERVER landed in the DB but not rendered into /etc/resolv.conf = rendering did not take effect
    assert pat.search(resolv), (
        f"DNS_NAMESERVER {ip} in CONFIG_DB but not rendered into /etc/resolv.conf "
        f"(resolvconf rendering inactive)")
    gcu.apply_patch_ok(gcu.remove_entry("DNS_NAMESERVER", ip))
    assert not cli.db_keys("CONFIG_DB", key), "DNS_NAMESERVER still present after remove"


# ---------- Loopback interface IP replacement ----------
def test_gcu_loopback_ip_add(gcu, cli, topo):
    """patch adds an IP to Loopback0 -> verify it appears in show ip interfaces; rollback restores it (the fixture handles it).

    This device's CONFIG_DB has **no Loopback0** by default -- adding an IP directly to a nonexistent interface is correctly rejected by GCU/YANG
    (leafref / interface object does not exist). So the patch **creates the Loopback0 base interface + its IP together** (YANG requires the interface object
    to exist first before an IP can be attached). Assemble the patch based on whether the LOOPBACK_INTERFACE table / Loopback0 already exist, avoiding hardcoded assumptions."""
    ip = topo.loopback("a").split("/")[0]          # e.g. 10.10.10.10
    cidr = topo.loopback("a")
    ip_key = f"LOOPBACK_INTERFACE|Loopback0|{cidr}"
    have_table = bool(cli.db_keys("CONFIG_DB", "LOOPBACK_INTERFACE|*"))
    have_base = bool(cli.db_keys("CONFIG_DB", "LOOPBACK_INTERFACE|Loopback0"))
    if have_table:
        # table exists: add the base interface if needed (only when missing) + add the IP entry
        patch = []
        if not have_base:
            patch.append({"op": "add",
                          "path": gcu.path("LOOPBACK_INTERFACE", "Loopback0"), "value": {}})
        patch.append({"op": "add",
                      "path": gcu.path("LOOPBACK_INTERFACE", f"Loopback0|{cidr}"), "value": {}})
    else:
        # table does not exist: create the whole table with the base interface + IP entry together (a key containing '/' is a plain string key in the whole-table value dict, not escaped)
        patch = [{"op": "add", "path": gcu.path("LOOPBACK_INTERFACE"),
                  "value": {"Loopback0": {}, f"Loopback0|{cidr}": {}}}]
    r = gcu.apply_patch(patch)
    # GCU should accept incremental config of the Loopback base interface + IP; if the patch is rejected, FAIL to expose it
    assert r.rc == 0, f"LOOPBACK_INTERFACE GCU add not accepted: {r.out or r.err}"
    assert cli.db_keys("CONFIG_DB", ip_key), f"Loopback IP not in CONFIG_DB: {ip_key}"
    assert ip in cli.run("show ip interfaces").out, "loopback IP not shown in 'show ip interfaces'"


# ---------- rollback to baseline ----------
def test_gcu_rollback_restores_baseline(gcu, cli, topo):
    """Add a route then immediately rollback, verifying CONFIG_DB is restored to the checkpoint baseline (isolation correctness)."""
    # choose the table by model probing: on images where STATIC_ROUTE has no model, use the modeled DNS_NAMESERVER instead;
    # the rollback semantics (restore the checkpoint baseline) are equivalent for both.
    if _table_modeled(cli, "STATIC_ROUTE"):
        prefix = topo.route("b")
        rkey = f"default|{prefix}"
        table = "STATIC_ROUTE"
        val = {"nexthop": topo.subnet("b")["peer"]}
    else:
        table, rkey, val = "DNS_NAMESERVER", "192.0.2.53", {}
        if not _table_modeled(cli, table):
            pytest.skip("no YANG-modeled table available for GCU rollback exercise")
    key = f"{table}|{rkey}"
    gcu.apply_patch_ok(gcu.add_entry(table, rkey, val))
    assert cli.db_keys("CONFIG_DB", key), "entry not added before rollback"
    gcu.rollback()                                 # return to the checkpoint taken when this case entered
    assert not cli.db_keys("CONFIG_DB", key), "rollback did not remove the entry (baseline not restored)"
    gcu.checkpoint()                               # rebuild the checkpoint for the fixture teardown's rollback
