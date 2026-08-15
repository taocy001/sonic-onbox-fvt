"""VRF: L3 port bound to VRF / loopback bound to VRF / route-leaking / mgmt-VRF."""
import re
import time

import pytest

pytestmark = [pytest.mark.l3]

VRF = "Vrf-test"


def _bare_oid(key):
    """Full ASIC key (ASIC_STATE:SAI_OBJECT_TYPE_X:oid:0x..) -> bare oid:0x...
    The VIRTUAL_ROUTER_ID in RIF attributes is a bare oid, whereas objects() returns the full
    key, so they must be normalized before comparison."""
    i = key.find("oid:")
    return key[i:] if i >= 0 else key


def _wait_new_vr(asicdb, before, timeout=8.0):
    """Wait for a new VIRTUAL_ROUTER oid to appear (VRF -> SAI VR mapping), returning its bare
    oid (or None if none appears)."""
    end = time.time() + timeout
    while time.time() < end:
        new = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER")) - before
        if new:
            return _bare_oid(next(iter(new)))
        time.sleep(0.4)
    return None


def test_vrf_create(cli, asicdb, config_guard):
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*")
    rc, r = cli.config_raw(f"vrf add {VRF}")
    config_guard.defer_undo(f"vrf del {VRF}")
    # Was: skip on CLI failure; vrf add is an existing command, so failure is a real defect
    # -> assert it succeeds
    assert rc == 0, f"config vrf add failed: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"VRF|{VRF}"), "no VRF in CONFIG_DB"
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*", base,
                                timeout=8), "VRF did not generate VIRTUAL_ROUTER"


def test_vrf_delete_recycles_asic_vr(cli, asicdb, config_guard):
    """VRF **deletion path**: after vrf del, its SAI_OBJECT_TYPE_VIRTUAL_ROUTER must leave
    ASIC_DB.

    Until now the whole suite only best-effort deleted VRFs in teardown and never asserted
    reclamation — an orchagent removal-chain leak (object left behind after undo) was entirely
    invisible. This case closes the loop with a dependency-free VRF (no port binding, no
    routes): add -> VR appears -> del -> VR reclaimed. Pure ASIC_DB assertions, zero storm
    risk."""
    name = "Vrf-delchk"
    before = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER"))
    rc, r = cli.config_raw(f"vrf add {name}")
    config_guard.defer_undo(f"vrf del {name}")   # idempotent safety net
    assert rc == 0, f"config vrf add failed: {r.err or r.out}"
    new_vr = _wait_new_vr(asicdb, before)
    assert new_vr, ("DEVICE DEFECT: VRF created but no new SAI_OBJECT_TYPE_VIRTUAL_ROUTER "
                    "appeared in ASIC (VRF not programmed into hardware)")
    rc, r = cli.config_raw(f"vrf del {name}")
    assert rc == 0, f"config vrf del failed: {r.err or r.out}"
    gone = False
    end = time.time() + 15
    while time.time() < end:
        oids = {_bare_oid(k) for k in asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER")}
        if new_vr not in oids:
            gone = True
            break
        time.sleep(0.5)
    assert gone, (f"DEVICE ISSUE: VIRTUAL_ROUTER {new_vr} still present in ASIC_DB 15s after "
                  f"vrf del (orchagent removal leak — stale ASIC object)")
    assert not cli.db_keys("CONFIG_DB", f"VRF|{name}"), \
        f"VRF|{name} still in CONFIG_DB after vrf del"


def test_bind_interface_to_vrf(cli, asicdb, topo, config_guard):
    """L3 port bound to VRF -> ASIC RIF reprogrammed under that VRF's virtual_router (chip-level
    proof the binding actually took effect).

    Beyond checking CONFIG_DB INTERFACE.vrf_name (a write-then-read-your-own anti-pattern),
    this asserts that orchagent points the port's SAI_ROUTER_INTERFACE VIRTUAL_ROUTER_ID at
    the SAI_OBJECT_TYPE_VIRTUAL_ROUTER of the newly created VRF (not the default VR) — i.e. the
    chip really moved the interface into this VRF.

    Data-plane VRF isolation (no cross-VRF leakage) is covered by test_vrf_chip.py; this case
    focuses on the ASIC reprogramming of a single-port binding."""
    port = topo.l3_port(0)
    dv = topo.default_vlan
    sub = topo.subnet("c")
    cidr = f"{sub['dut']}/{sub['prefix']}"

    # 1) Create the VRF, note the virtual_router oid it newly adds in the ASIC
    before_vr = set(asicdb.objects("SAI_OBJECT_TYPE_VIRTUAL_ROUTER"))
    rc, r = cli.config_raw(f"vrf add {VRF}")
    config_guard.defer_undo(f"vrf del {VRF}")
    # Was: skip on CLI failure; vrf add is an existing command, so failure is a real defect
    # -> assert it succeeds
    assert rc == 0, f"config vrf add failed: {r.err or r.out}"
    new_vr = _wait_new_vr(asicdb, before_vr)
    # Was: skip if no new VR; a VRF that produces no chip VIRTUAL_ROUTER = VRF not in hardware,
    # a device defect -> FAIL
    assert new_vr, (
        "DEVICE DEFECT: VRF created but no new SAI_OBJECT_TYPE_VIRTUAL_ROUTER appeared in ASIC "
        "(VRF not programmed into hardware)")

    # 2) Move the port out of the default VLAN -> bind VRF -> configure IP (the RIF should be
    #    created directly under this VRF's VR)
    cli.config_raw(f"vlan member del {dv} {port.name}")
    config_guard.defer_undo(f"vlan member add -u {dv} {port.name}")
    rc, r = cli.config_raw(f"interface vrf bind {port.name} {VRF}")
    config_guard.defer_undo(f"interface vrf unbind {port.name}")
    # Was: skip on CLI failure; interface vrf bind is an existing command, so failure is a real
    # defect -> assert it succeeds
    assert rc == 0, f"interface vrf bind failed: {r.err or r.out}"
    cli.config_raw(f"interface ip add {port.name} {cidr}")
    config_guard.defer_undo(f"interface ip remove {port.name} {cidr}")
    cli.intf_startup(port.name)

    # 3) CONFIG_DB reflects the binding (intermediate-state check)
    time.sleep(1)
    attrs = cli.db_hgetall("CONFIG_DB", f"INTERFACE|{port.name}")
    assert attrs.get("vrf_name") == VRF, f"interface not bound to VRF in CONFIG_DB: {attrs}"

    # 4) Chip: some RIF has VIRTUAL_ROUTER_ID == the new VRF's VR oid (RIF really moved into
    #    this VRF)
    found = []
    end = time.time() + 10
    while time.time() < end:
        found = asicdb.find("SAI_OBJECT_TYPE_ROUTER_INTERFACE",
                            SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID=new_vr)
        if found:
            break
        time.sleep(0.5)
    assert found, (
        f"interface bound to VRF in CONFIG_DB but no SAI_ROUTER_INTERFACE programmed under the "
        f"VRF's virtual_router {new_vr} in ASIC (RIF not rebound to the new VRF on chip)")


def _mgmt_vrf_table(cli):
    """Whether mgmt is a genuine type-vrf netdev; if so return its kernel routing-table id
    ('vrf table N'), otherwise None."""
    r = cli.sh.run("ip -d link show mgmt", check=False)
    if r.rc != 0 or "vrf" not in (r.out or "").lower():
        return None
    m = re.search(r"vrf table (\d+)", r.out or "")
    return m.group(1) if m else None


def _mgmt_enslaved_ifaces(cli):
    """Return the list of NIC names enslaved to the mgmt VRF (master mgmt) — discovered
    dynamically, not hard-coded to eth0."""
    out = cli.sh.run("ip -o link show", check=False).out or ""
    ifaces = []
    for line in out.splitlines():
        if "master mgmt" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                ifaces.append(parts[1].strip().split("@")[0])
    return ifaces


def test_mgmt_vrf(cli, asicdb, config_guard):
    """Management VRF: `vrf add mgmt` is a **Linux-only** construct not pushed to the ASIC:
    after the mgmt VRF comes up the ASIC SAI_OBJECT_TYPE_VIRTUAL_ROUTER count does not grow
    (still just the default VR=1), and the management port (eth0) is physically not on the
    data-plane ASIC, so the mgmt VRF is implemented purely by the kernel L3 VRF. Thus this
    case does **not** assert on the ASIC VR, but rather on the real **mgmt VRF routing
    isolation behavior** in the kernel:

      1) mgmt is a genuine type-vrf master device with its own **dedicated kernel routing
         table** ('vrf table N');
      2) the management port is enslaved to mgmt (master mgmt), and its connected/default
         routes **move into that VRF table** — `ip route show vrf mgmt` contains
         `dev <mgmt-iface>` routes;
      3) cross-VRF isolation: those `dev <mgmt-iface>` routes are **not** in the main
         (default-VRF) routing table — i.e. the management port's L3 reachability is isolated
         into the mgmt VRF table, and default-VRF processes cannot use management-port routes
         (real management/data-plane isolation).
      4) corroborating Linux-only: the ASIC VIRTUAL_ROUTER count does not grow before/after
         enablement.

    A pure write-then-read of CONFIG_DB.mgmtVrfEnabled only proves the config was written to
    the DB — here CONFIG_DB serves only as an intermediate-state check, while the real
    assertions land on vrfmgrd/kernel artifacts (dedicated routing table + route isolation).
    If the CLI syntax is unsupported, skip faithfully."""
    vr_before = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*")
    rc, r = cli.config_raw("vrf add mgmt")
    config_guard.defer_undo("vrf del mgmt")
    # Was: skip on CLI failure; vrf add mgmt is an existing command, so failure is a real
    # defect -> assert it succeeds
    assert rc == 0, f"mgmt VRF config failed: {r.err or r.out}"
    # Intermediate state: CONFIG_DB reflects enablement (vrf_add_management_vrf writes
    # mgmtVrfEnabled=true)
    time.sleep(1)
    attrs = cli.db_hgetall("CONFIG_DB", "MGMT_VRF_CONFIG|vrf_global")
    assert attrs.get("mgmtVrfEnabled") == "true", f"mgmt VRF not enabled in CONFIG_DB: {attrs}"

    # Real assertion 1: vrfmgrd/kernel has instantiated mgmt as a type-vrf device with a
    # dedicated routing table, and the management port is enslaved (poll for async)
    table, ifaces = None, []
    end = time.time() + 12
    while time.time() < end:
        table = _mgmt_vrf_table(cli)
        ifaces = _mgmt_enslaved_ifaces(cli)
        if table and ifaces:
            break
        time.sleep(0.5)
    assert table, (
        "mgmt VRF enabled in CONFIG_DB but vrfmgrd did not instantiate a 'mgmt' type-vrf netdev "
        "with a dedicated kernel routing table in the kernel")
    assert ifaces, (
        "mgmt VRF instantiated but no interface is enslaved to it (no 'master mgmt'); "
        "management port not bound into the mgmt VRF")

    # Real assertions 2 and 3: management-port routes move into the mgmt VRF table and are
    # **not** in the main table (proof of cross-VRF route isolation). On fresh enablement the
    # kernel migrates routes asynchronously, so poll until "the port's route appears in the VRF
    # table" before the isolation assertion, to avoid misjudging mid-migration.
    vrf_routes = main_routes = ""
    end = time.time() + 10
    while time.time() < end:
        vrf_routes = cli.sh.run("ip route show vrf mgmt", check=False).out or ""
        main_routes = cli.sh.run("ip route show", check=False).out or ""
        if any(f"dev {ifc}" in vrf_routes for ifc in ifaces):
            break
        time.sleep(0.5)
    isolated = False
    for ifc in ifaces:
        in_vrf = f"dev {ifc}" in vrf_routes
        in_main = f"dev {ifc}" in main_routes
        # isolation = the port's route is in the mgmt VRF table but not in the default-VRF
        # main table
        assert not in_main, (
            f"mgmt-enslaved iface {ifc} still has routes in the main (default-VRF) table; "
            f"mgmt VRF did not isolate its L3 reachability:\n{main_routes}")
        isolated = isolated or in_vrf
    assert isolated, (
        f"no route via any mgmt-enslaved iface {ifaces} found in the mgmt VRF table "
        f"(routing not actually moved into the mgmt VRF):\n{vrf_routes}")

    # Corroborating: the mgmt VRF is Linux-only and produces no ASIC virtual router (count does
    # not grow)
    vr_after = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*")
    assert vr_after <= vr_before, (
        f"mgmt VRF unexpectedly created an ASIC SAI_OBJECT_TYPE_VIRTUAL_ROUTER "
        f"(before={vr_before}, after={vr_after}); mgmt VRF is expected to be kernel-only")


def test_vrf_64(cli, asicdb, config_guard):
    """VRF scale (>=64): bulk-create 64 VRFs, verify all land in CONFIG_DB, and that the ASIC
    VIRTUAL_ROUTER count grows accordingly (one VR per VRF). Doable on a single box but slow
    with per-VRF config vrf add — no longer skipped; makes a real scale assertion.

    Cleanup is per-VRF `vrf del` via config_guard, idempotent."""
    n = 64
    base_vr = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*")
    names = [f"Vrf-scale-{i}" for i in range(n)]
    created = []
    for name in names:
        rc, r = cli.config_raw(f"vrf add {name}")
        if rc != 0:
            # vrf add is an existing command; a failure here = scale is limited, a real defect
            # -> FAIL (report how many were created)
            pytest.fail(f"config vrf add {name} failed at {len(created)}/{n} VRFs: {r.err or r.out}")
        config_guard.defer_undo(f"vrf del {name}")
        created.append(name)
    # CONFIG_DB: all 64 VRFs landed in the DB
    missing = [name for name in names if not cli.db_keys("CONFIG_DB", f"VRF|{name}")]
    assert not missing, f"{len(missing)} VRFs not written to CONFIG_DB: {missing[:5]}..."
    # ASIC: VIRTUAL_ROUTER count should grow to >= base+n (async programming, allow a longer
    # poll window)
    ok = asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*",
                              base_vr + n - 1, timeout=30)
    now_vr = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:*")
    assert ok, (
        f"DEVICE DEFECT: {n} VRFs created in CONFIG_DB but ASIC VIRTUAL_ROUTER only grew by "
        f"{now_vr - base_vr} (< {n}); VRF scale not fully programmed to hardware")
