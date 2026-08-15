"""QoS config **referential integrity**: dangling references must be refused at the CLI layer and must not exist in the DB.

Background: dangling references are dangerous. If a `BUFFER_PROFILE` references a
`BUFFER_POOL` that does not exist in the config, BufferOrch waits forever for a pool
object that never appears and never drains its task queue, presenting as a **silent
permanent hang** rather than an error; likewise, a mapping table the platform does not
model can make orchagent fail during processing so the config never converges.

The product CLI should reject these dangling references at push time. So this file does
two things:
  RI1-RI7: guard the CLI's validation layer (the day it loosens, the storm has a way in);
  RI8-RI9: read-only DB scan confirming no dangling reference / unmodelled table slipped
  in (the JSON channel bypasses the CLI).

RI1-RI7 only issue commands **expected to fail** and leave no config behind; RI8/RI9 are
pure read-only. The whole file can run alongside any round.
"""
import pytest

pytestmark = [pytest.mark.qos, pytest.mark.cli]

_MISSING = "FVTNOEXIST"          # an object name guaranteed not to exist


def _run(cli, cmd):
    """config_raw returns (rc, Result); rc is not trustworthy (a refused command can still
    return 0), so we only take the text for error context and always judge by reading
    CONFIG_DB back."""
    _rc, r = cli.config_raw(cmd)
    return ((r.out or "") + (r.err or "")).strip()


def _refused(cli, cmd, key, table="CONFIG_DB"):
    """The verdict ignores rc (a refused SONiC CLI command still returns 0); it only checks
    **whether anything was left behind in the DB**."""
    text = _run(cli, cmd)
    left = cli.db_hgetall(table, key) or {}
    return left, text


@pytest.fixture(scope="module")
def probe_port(topo):
    return topo.misc_port(0).name


# ==================== RI1-RI7 CLI must refuse dangling references ====================
def test_ri1_pg_bind_to_missing_profile_refused(cli, probe_port):
    """RI1: binding a lossless PG to a non-existent profile must be refused and not persisted.

    This is the easiest one to slip on (one wrong letter in the profile name), and exactly
    the class of dangling reference that can create a permanent hang."""
    left, text = _refused(
        cli, f"interface buffer priority-group lossless add {probe_port} 3 {_MISSING}",
        f"BUFFER_PG|{probe_port}|3")
    assert not left, (
        f"CLI accepted a BUFFER_PG bound to a non-existent profile {_MISSING!r}: "
        f"CONFIG_DB now holds {left}. BufferOrch will wait forever for an object "
        f"that will never exist — no error, no log, and the box never converges "
        f"after the next reboot. CLI output was: {text[:200]}")


def test_ri2_port_qos_map_missing_map_refused(cli, probe_port):
    """RI2: a port-qos-map referencing a non-existent mapping table must be refused."""
    before = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{probe_port}") or {}
    text = _run(cli, f"port-qos-map update {probe_port} "
                     f"-dscpt {_MISSING} -tq {_MISSING}2")
    after = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{probe_port}") or {}
    assert after.get("dscp_to_tc_map") != _MISSING, (
        f"CLI wrote a dangling dscp_to_tc_map={_MISSING!r} into "
        f"PORT_QOS_MAP|{probe_port} (before={before}, after={after}); output={text[:200]}")
    assert after.get("tc_to_queue_map") != f"{_MISSING}2", (
        f"CLI wrote a dangling tc_to_queue_map into PORT_QOS_MAP|{probe_port} "
        f"(after={after}); output={text[:200]}")


def test_ri3_port_queue_missing_scheduler_refused(cli, probe_port):
    """RI3: a port-queue referencing a non-existent scheduler / wred must be refused."""
    left, text = _refused(cli, f"port-queue add {probe_port} 3 -s {_MISSING} -w {_MISSING}2",
                          f"QUEUE|{probe_port}|3")
    assert left.get("scheduler") != _MISSING, (
        f"CLI accepted a QUEUE bound to a non-existent scheduler: {left}; "
        f"output={text[:200]}")


def test_ri4_port_qos_map_missing_scheduler_refused(cli, probe_port):
    """RI4: the port-level scheduler reference in port-qos-map must be validated too."""
    text = _run(cli, f"port-qos-map update {probe_port} -s {_MISSING}")
    after = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{probe_port}") or {}
    assert after.get("scheduler") != _MISSING, (
        f"CLI wrote a dangling port-level scheduler reference: {after}; "
        f"output={text[:200]}")


def test_ri5_delete_referenced_profile_refused(cli, probe_port):
    """RI5: deleting a profile still referenced by a PG must be refused -- otherwise a single
    delete conjures a dangling reference out of nothing.

    This one actually creates a profile and binds it, so it self-rolls back."""
    prof = "FVTRI5"
    _run(cli, f"buffer profile add {prof} --headroom 184800 --dynamic-th 0 --min-th 1680")
    if not (cli.db_hgetall("CONFIG_DB", f"BUFFER_PROFILE|{prof}") or {}):
        pytest.skip("cannot create a buffer profile on this image; "
                    "referenced-delete protection untestable here")
    bound = False
    try:
        _run(cli, f"interface buffer priority-group lossless add {probe_port} 3 {prof}")
        bound = bool(cli.db_hgetall("CONFIG_DB", f"BUFFER_PG|{probe_port}|3") or {})
        if not bound:
            pytest.skip("buffer PG binding channel unavailable; nothing to protect")
        text = _run(cli, f"buffer profile del {prof}")
        still = cli.db_hgetall("CONFIG_DB", f"BUFFER_PROFILE|{prof}") or {}
        pg = cli.db_hgetall("CONFIG_DB", f"BUFFER_PG|{probe_port}|3") or {}
        assert still or not pg, (
            f"CLI deleted profile {prof!r} while BUFFER_PG|{probe_port}|3 still "
            f"references it ({pg}) — that is exactly the dangling reference that "
            f"hangs BufferOrch forever. output={text[:200]}")
    finally:
        if bound:
            _run(cli, f"interface buffer priority-group lossless del {probe_port} 3")
        _run(cli, f"buffer profile del {prof}")


def test_ri6_buffer_profile_has_no_pool_option(cli):
    """RI6: `buffer profile add` should not offer `--pool` -- that option would hand the
    operator the ability to "point at an arbitrary pool name", with no feedback when the
    pool name is wrong.

    On both platforms measured this is `no such option: --pool`. This is a capability-surface
    guard, not a behavioral one."""
    text = _run(cli, "buffer profile add FVTRI6 --pool FVTNOPOOL --headroom 184800 "
                     "--dynamic-th 0 --min-th 1680")
    left = cli.db_hgetall("CONFIG_DB", "BUFFER_PROFILE|FVTRI6") or {}
    try:
        assert (left.get("pool") or "").strip("[]").split("|")[-1] != "FVTNOPOOL", (
            f"CLI accepted --pool pointing at a non-existent pool: {left}; "
            f"output={text[:200]}")
    finally:
        if left:
            _run(cli, "buffer profile del FVTRI6")


def test_ri7_no_cli_to_delete_a_referenced_pool(cli):
    """RI7: there should be no CLI that can delete an in-use buffer pool -- the moment the
    pool is gone, every profile referencing it instantly becomes a dangling reference.

    `config buffer` only has the `profile` subcommand."""
    pools = cli.db_keys("CONFIG_DB", "BUFFER_POOL|*") or []
    if not pools:
        pytest.skip("no BUFFER_POOL in CONFIG_DB on this platform (pool lives in the "
                    "SAI yml); there is nothing a CLI could strand")
    name = pools[0].split("|", 1)[1]
    text = _run(cli, f"buffer pool del {name}")
    still = cli.db_hgetall("CONFIG_DB", f"BUFFER_POOL|{name}") or {}
    assert still, (
        f"CLI removed BUFFER_POOL|{name} that profiles still reference; every "
        f"profile pointing at it is now a dangling reference. output={text[:200]}")


# ================ RI8-RI9 no dangling / unmodelled content allowed in the DB ================
def test_ri8_no_dangling_pool_reference_in_config(cli):
    """RI8 **read-only guard**: every `BUFFER_PROFILE.pool` must point at a `BUFFER_POOL`
    that is defined in this DB and carries a `size`.

    The JSON channel (`config load` / `sonic-cfggen -j` / `apply-patch`) bypasses CLI
    validation, so RI1-RI7 cannot stop a dangling reference that came in from a config
    file -- this test scans the DB. The `size` check matters too: a pool entry with no
    size is rejected by SAI with MANDATORY_ATTRIBUTE_MISSING, which is equivalent to it
    not existing."""
    pools = {}
    for k in cli.db_keys("CONFIG_DB", "BUFFER_POOL|*") or []:
        pools[k.split("|", 1)[1]] = cli.db_hgetall("CONFIG_DB", k) or {}
    bad = []
    for k in cli.db_keys("CONFIG_DB", "BUFFER_PROFILE|*") or []:
        name = k.split("|", 1)[1]
        ref = (cli.db_hgetall("CONFIG_DB", k) or {}).get("pool")
        if not ref:
            continue
        ref = ref.strip("[]").split("|")[-1]
        if ref not in pools:
            bad.append((name, ref, "pool not defined"))
        elif not str(pools[ref].get("size") or "").strip().isdigit():
            bad.append((name, ref, f"pool has no numeric size: {pools[ref]}"))
    assert not bad, (
        f"dangling buffer pool reference(s) in CONFIG_DB: {bad}. BufferOrch waits "
        f"for an object that will never be created — silently, with no log line — "
        f"and the switch never finishes applying QoS after the next reboot "
        f"(measured: >517s with queue counters stuck at 0, versus 286s once the "
        f"reference is removed). Defined pools: {sorted(pools)}")


def test_ri9_no_unmodelled_qos_map_tables(cli, caps):
    """RI9 **read-only guard**: a QoS mapping table the platform does not model must not
    appear in the DB.

    Once an unmodelled mapping table enters the DB, orchagent may fail and exit during
    processing, swss restarts repeatedly, and the config never finishes replaying. The
    chip's ING_PRI->PG is already an identity mapping, so this table does **not** need to
    be pushed. The platform profile records this capability as `caps.tc_to_pg_map_usable`."""
    if caps.has("tc_to_pg_map_usable"):
        pytest.skip("this platform models TC_TO_PRIORITY_GROUP_MAP; guard not applicable")
    present = cli.db_keys("CONFIG_DB", "TC_TO_PRIORITY_GROUP_MAP|*") or []
    assert not present, (
        f"CONFIG_DB carries {present}, which this platform does not model. "
        f"orchagent can fail on these keys and swss may restart into the same failure "
        f"on replay, so configuration never finishes applying. The chip maps ING_PRI "
        f"to PG identically already — the table is not needed. Remove it from whatever "
        f"config file introduced it.")
