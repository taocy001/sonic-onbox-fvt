"""QoS full set: classification (dot1p/dscp/acl) + scheduling (SP/WRR/DWRR) + shaping + WRED + remark + DCB (PFC/ECN).

After config qos reload, verify ASIC QoS objects; scheduling ratio / PFC deadlock need a traffic
generator -- out of this framework's scope, no cases defined.
"""
import pytest

from framework import qos

pytestmark = [pytest.mark.qos]

# POLICER is not parametrized here: the qos_loaded baseline never creates a policer, and on these
# images the ASIC POLICER actually comes from CoPP -- asserting its existence under the QoS baseline
# name would wrongly blame a CoPP-domain defect on the QoS baseline (policer existence is the copp
# suite's responsibility, see test_copp_policer.py).
# BUFFER_POOL is merged in from the original test_qos.py (that file was retired; the existence
# dimension is kept only once here).
QOS_OBJ_TYPES = [
    "SAI_OBJECT_TYPE_QOS_MAP",
    "SAI_OBJECT_TYPE_SCHEDULER",
    "SAI_OBJECT_TYPE_WRED",
    "SAI_OBJECT_TYPE_BUFFER_PROFILE",
    "SAI_OBJECT_TYPE_BUFFER_POOL",
]


@pytest.fixture(scope="module")
def qos_loaded(cli, topo):
    """Community image: template reload; SONiC (product-CLI config model): **never run reload** (on that
    image it only clears without building, and a dangling PORT_QOS_MAP reference would break config
    validation, mechanism see the test_qos.py module docstring); instead build the map/scheduler/WRED/
    buffer-profile baseline directly via the product CLI, cleaned up at module end."""
    import time
    if not qos.has_qos_cli(cli):
        cli.sh.run("config qos reload", check=False, timeout=90)
        time.sleep(5)
    undos = []
    if qos.has_qos_cli(cli):
        port = topo.misc_port(0).name
        if not cli.db_keys("CONFIG_DB", "DSCP_TO_TC_MAP|*"):   # the ASIC has a default dot1p map, so look at CONFIG_DB
            u = qos.build_baseline(cli, port)
            if u:
                undos.append(u)
        if not cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:*"):
            u = qos.build_sched_baseline(cli, port)
            if u:
                undos.append(u)
        if not cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:*"):
            cli.config_raw("buffer profile add FVTQF_BUF --dynamic-th 3")
            undos.append(lambda: cli.config_raw("buffer profile del FVTQF_BUF"))
    yield
    for u in reversed(undos):
        u()


@pytest.mark.parametrize("sai_type", QOS_OBJ_TYPES, ids=[t.split("TYPE_")[1] for t in QOS_OBJ_TYPES])
def test_qos_object_programmed(cli, asicdb, qos_loaded, sai_type):
    n = asicdb.count(f"ASIC_STATE:{sai_type}:*")
    if n == 0 and sai_type == "SAI_OBJECT_TYPE_BUFFER_POOL" and qos.has_qos_cli(cli):
        # On product-CLI config-model images the buffer uses its own model with no default SAI pool object (same judgment as original test_qos.py)
        pytest.skip("this image manages buffers via its own CLI model without default "
                    "SAI buffer pools (structural)")
    assert n > 0, (f"{sai_type} not programmed to ASIC (community image: qos reload constrained "
                   f"by missing hwsku templates; CLI-model image: baseline build did not produce it)")


_PFC_SEPARATE = "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE"


def _ports_with_separate_pfc(asicdb):
    """Return the set of PORT object keys in the ASIC whose PFC mode is SEPARATE (ports with asymmetric PFC programmed)."""
    out = set()
    for k in asicdb.objects("SAI_OBJECT_TYPE_PORT"):
        if asicdb.field(k, "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE") == _PFC_SEPARATE:
            out.add(k)
    return out


def test_pfc_config(cli, asicdb, topo, config_guard):
    """PFC asymmetric on -> ASIC port SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE changes from COMBINED to SEPARATE
    (config->chip loop: orchagent really pushes pfc_asym=on into the port PFC-mode attribute), not just checking the CONFIG_DB write.

    There is no direct port-name -> SAI PORT oid mapping, so use a before/after set difference: after enabling asymmetric,
    one port object should **newly** have PFC mode SEPARATE."""
    import time
    port = topo.misc_port(0).name
    before = _ports_with_separate_pfc(asicdb)
    rc, r = cli.config_raw(f"interface pfc asymmetric {port} on")
    if "does not support" in ((r.out or "") + (r.err or "")):
        # Product capability gate ("The device does not support this configuration")
        pytest.skip("device declares asymmetric PFC unsupported "
                    "('does not support this configuration'; structural capability gate)")
    out = r.out + r.err
    assert "Traceback" not in out, f"config interface pfc asymmetric crashed: {out[:200]}"
    if rc != 0:
        pytest.fail("DEVICE DEFECT: PFC asymmetric config rejected on this image "
                    f"(image should support `config interface pfc asymmetric`): {out.strip()[:160]}")
    config_guard.defer_undo(f"interface pfc asymmetric {port} off")
    # CONFIG_DB write precondition confirmation (start of the programming path)
    val = None
    for _ in range(10):
        val = cli.db_hgetall("CONFIG_DB", f"PORT|{port}").get("pfc_asym")
        if val == "on":
            break
        time.sleep(0.3)
    assert val == "on", f"pfc_asym not written to CONFIG_DB PORT|{port}: got {val!r}"
    # Poll the ASIC: one more port should have PFC mode changed to SEPARATE (config->chip really took effect)
    grown, after = False, before
    for _ in range(20):
        after = _ports_with_separate_pfc(asicdb)
        if len(after - before) >= 1:
            grown = True
            break
        time.sleep(0.5)
    assert grown, (
        f"enabled pfc_asym on {port} but no ASIC PORT changed "
        f"SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE to SEPARATE "
        f"(config->ASIC PFC mode programming broken)")


def test_ecn_config(cli, asicdb, qos_loaded):
    """ECN marking really programmed into the chip: the ASIC should have a SAI_OBJECT_TYPE_WRED object carrying a valid
    SAI_WRED_ATTR_ECN_MARK_MODE enum (proving the ECN/WRED policy is pushed to hardware), not merely `show ecn` not crashing.

    If the image lacks buffers.json.j2, `config qos reload` does not push WRED -> honestly exposed (visible, no false pass)."""
    r = cli.run("show ecn")
    assert "Traceback" not in (r.out + r.err), "show ecn crashed"
    wreds = asicdb.objects("SAI_OBJECT_TYPE_WRED")
    if not wreds:
        pytest.fail("DEVICE DEFECT: no SAI_OBJECT_TYPE_WRED programmed to ASIC "
                    "(ECN/WRED policy not programmed to hardware)")
    modes = [m for m in (asicdb.field(w, "SAI_WRED_ATTR_ECN_MARK_MODE") for w in wreds) if m]
    if not modes:
        pytest.fail("DEVICE DEFECT: WRED objects exist but none carry SAI_WRED_ATTR_ECN_MARK_MODE")
    bad = [m for m in modes if not m.startswith("SAI_ECN_MARK_MODE_")]
    assert not bad, f"WRED objects with invalid SAI_WRED_ATTR_ECN_MARK_MODE enum: {bad}"


def test_running_config_round_trips_qos_section(cli, asicdb, topo):
    """Program a known QoS config item (SCHEDULER) into CONFIG_DB -> it must both round-trip into
    `show runningconfiguration all` (running-config serialization truly reflects the newly written QoS section) and be
    **really programmed to ASIC SAI_OBJECT_TYPE_SCHEDULER** via QosOrch (type=DWRR, weight=that value) -- swss qosorch.cpp's
    handleSchedulerTable calls create_scheduler directly on a SCHEDULER-table SET, so writing a new SCHEDULER should add one
    matching scheduler object in the ASIC (config->chip loop, bypassing the qos reload limitation of missing buffers.json.j2).

    The write channel adapts to the image config model (same as test_qos_sched_chip::test_scheduler_weight_change_reflects_asic):
    SONiC's orch **does not consume a bare HSET**, it must go through the product `config scheduler add`, and its scheduler
    object **is only programmed to the ASIC when referenced by a port-queue** (see framework/qos.build_sched_baseline)
    -- so the CLI channel additionally binds queue2 (0/1 are reserved for the scheduling baseline). The bare HSET is used only for
    community images (schedulerorch listens on CONFIG_DB). If QosOrch does not push an ASIC object -> honest FAIL, never PASS by
    only checking CONFIG_DB."""
    import time
    name = "FVT_RC_SCHED"
    key = f"SCHEDULER|{name}"
    weight = 7
    use_cli = qos.has_qos_cli(cli)
    port = topo.misc_port(0).name
    # Idempotent: clear leftovers first, then write the known QoS section (SCHEDULER is a real subtable of the running-config serialization)
    if use_cli:
        cli.config_raw(f"port-queue del {port} 2")   # best-effort clear of leftover binding
        cli.config_raw(f"scheduler del {name}")
    else:
        cli.db("CONFIG_DB", f"DEL '{key}'")
    # Snapshot existing ASIC SCHEDULER oids before writing, to identify the one this case creates (distinct from existing schedulers)
    before = set(asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER"))
    if use_cli:
        rc, r = cli.config_raw(f"scheduler add {name} -t DWRR -w {weight}")
        assert rc == 0, (f"DEVICE DEFECT: `config scheduler add` rejected a legal DWRR scheduler: "
                         f"{(r.out + r.err).strip()[:160]}")
        rc, r = cli.config_raw(f"port-queue add {port} 2 -s {name}")
        assert rc == 0, (f"DEVICE DEFECT: `config port-queue add` rejected binding scheduler "
                         f"{name} to {port} queue2: {(r.out + r.err).strip()[:160]}")
    else:
        cli.db("CONFIG_DB", f"HSET '{key}' type DWRR weight {weight}")
    try:
        rolled, out = False, ""
        for _ in range(10):
            r = cli.run("show runningconfiguration all")
            out = r.out
            assert "Traceback" not in (r.out + r.err), "show runningconfiguration all crashed"
            if name in out:
                rolled = True
                break
            time.sleep(0.5)
        assert rolled, (
            f"wrote CONFIG_DB {key} but it did not round-trip into "
            f"`show runningconfiguration all` (running config serialization broken)")
        assert "SCHEDULER" in out, \
            "running config missing SCHEDULER section after programming a scheduler"
        # === Chip loop: poll the ASIC; it should add one DWRR + weight=7 SAI_OBJECT_TYPE_SCHEDULER ===
        hit = False
        for _ in range(20):
            for s in set(asicdb.objects("SAI_OBJECT_TYPE_SCHEDULER")) - before:
                if (asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE") == "SAI_SCHEDULING_TYPE_DWRR"
                        and asicdb.field(s, "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT") == str(weight)):
                    hit = True
                    break
            if hit:
                break
            time.sleep(0.5)
        if not hit:
            # Config round-trip holds but QosOrch did not create_scheduler an ASIC object from this entry
            # -> honest FAIL, exposing the broken config->chip link, never masking the defect
            pytest.fail("DEVICE DEFECT: programmed SCHEDULER (via the image's supported channel) and it "
                        "round-trips into running config, but QosOrch did not program a matching "
                        "SAI_OBJECT_TYPE_SCHEDULER (DWRR/weight=7) to ASIC "
                        "(config->chip programming did not complete)")
    finally:
        if use_cli:
            # Unbind before deleting (deleting a referenced scheduler would be rejected)
            cli.config_raw(f"port-queue del {port} 2")
            cli.config_raw(f"scheduler del {name}")
        else:
            cli.db("CONFIG_DB", f"DEL '{key}'")
        time.sleep(1)
