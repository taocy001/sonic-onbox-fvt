"""WRED profile lifecycle: enable toggling and disabled-state threshold semantics.

Background: when a queue-bound profile goes `-en false` then `-en true`, if disable destroys the stored thresholds in place,
the re-sent MAX combined with the poisoned min forms min>max, and SAI reports a per-color reapply error. A correct
implementation keeps the user thresholds on disable and substitutes an unreachable value at apply time.

Cases (all verdicts settled by read-back):
  WL1 enable toggle: zero SAI reapply errors throughout, and after re-enable the ASIC thresholds == user values;
  WL2 disabled-state threshold update: while disabled the hardware holds the "min==max device-max" signature (WRED off),
      and after re-enable the new thresholds apply in one shot -- before the fix this scenario's behavior depends on
      field-write ordering and is unpredictable.
  WL3 created disabled: build a profile already red-disabled then bind it to a queue,
      the chip red lands the "min==max device-max" unreachable signature while green/yellow keep user values; toggling
      enable alone (without re-sending thresholds) makes the user values take effect in one shot;
  WL4 per-color toggle: green/yellow/red each run 3 rounds of disable->enable, each round zero SAI errors
      and ASIC read-back == user values;
  WL5 explicit ECN thresholds are unaffected by the disable substitution -- the current harness cannot express explicit
      ECN thresholds (the CLI has only the ecn mode enum, and YANG has no ecn threshold leaf), so the case honestly skips.

Per-color enable channel note: SONiC `config wred-profile` only exposes the global -en (verified by walking the click tree),
so wred_<color>_enable can only be written to the CONFIG_DB WRED_PROFILE field -- orchagent subscribes to that table
directly, a data-plane channel equivalent to the CLI (queue binding in this file already goes through db_hset, same rule).

Cleanup iron rule: first delete the QUEUE binding and wait for the ASIC WRED_PROFILE_ID to return to oid:0x0, then delete
the profile; in the reverse order orchagent reports -17 and then **drops the task outright** (no retry), leaking the ASIC WRED object.
"""
import time
from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.qos]

_PROF = "FVTWRD"
_PROF_D = "FVTWRDD"   # WL3-only: the created-red-disabled profile variant
_Q = 1
_GMIN, _GMAX = 1000000, 2000000
_GMIN2, _GMAX2 = 600000, 900000
# stable fingerprint of a SAI reapply failure (syslog keyword)
_ERR_PAT = "Apply queue config failed"


def _err_count(cli):
    r = cli.sh.run(f"grep -ac '{_ERR_PAT}' /var/log/syslog", check=False)
    out = (r.out or "").strip()
    return int(out) if out.isdigit() else 0


def _wait(pred, timeout=10.0, interval=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(interval)
    return pred()


def _asic_queue_wred(cli, qoid):
    h = cli.db_hgetall("ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:{qoid}") or {}
    return h.get("SAI_QUEUE_ATTR_WRED_PROFILE_ID")


def _asic_wred(cli, woid):
    return cli.db_hgetall("ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_WRED:{woid}") or {}


def _update(cli, args):
    rc, r = cli.config_raw(f"wred-profile update {_PROF} {args}")
    text = ((r.out or "") + (r.err or "")).strip()
    assert rc == 0 and "Error" not in text, \
        f"DEVICE DEFECT: legal wred-profile update rejected: {text[-160:]}"


def _curve_rows(chip, port, q, color="GREEN"):
    """Per-pipe rows of (min, max) cells for the given color of the queue curve profile; returns None if lt is unavailable."""
    ent = chip.wred_uc_q(port, q)
    pid = ent and ent.get("TM_WRED_DROP_CURVE_SET_PROFILE_ID")
    if not pid:
        return None
    table = next((t for t in ("TM_WRED_DROP_CURVE_SET_PIPE_PROFILE",
                              "TM_WRED_DROP_CURVE_SET_PROFILE")
                  if chip.has_table(t)), None)
    if table is None:
        return None
    rows = []
    for e in chip.traverse(table):
        if e.get("TM_WRED_DROP_CURVE_SET_PROFILE_ID") != pid:
            continue
        cmin = next((v for k, v in e.items()
                     if k.endswith(f"{color}_DROP_MIN_THD_CELLS")
                     and not k.startswith("NON_")), None)
        cmax = next((v for k, v in e.items()
                     if k.endswith(f"{color}_DROP_MAX_THD_CELLS")
                     and not k.startswith("NON_")), None)
        if cmin is not None and cmax is not None:
            rows.append((cmin, cmax))
    return rows or None


def _wredq_impl(cli, topo, prof, red_disabled):
    """Shared implementation for wredq/wredqdis: build a profile (all colors 1M/2M, ecn_all, enable) and bind it to q1 of
    a port with no leftover QUEUE config. When red_disabled=True, set wred_red_enable to false before binding the queue
    (the "created disabled" variant): SONiC CLI has only the global -en, so per-color enable can only be written to
    CONFIG_DB (see module docstring); the sleep lets orchagent land RED_ENABLE=false to SAI before binding, ensuring the
    profile is already red-disabled at bind time."""
    rc, r = cli.config_raw("wred-profile --help")
    if rc != 0 or "add" not in ((r.out or "") + (r.err or "")):
        pytest.skip("no `config wred-profile` CLI on this image")
    port = None
    for role in ("e", "f", "g", "h"):
        try:
            p = topo.port(role).name
        except KeyError:
            continue
        if not cli.db_hgetall("CONFIG_DB", f"QUEUE|{p}|{_Q}"):
            port = p
            break
    if port is None:
        pytest.skip(f"no candidate port free of QUEUE|<p>|{_Q} config")

    cli.config_raw(f"wred-profile del {prof}")   # clean up any leftover from a previous round
    err0 = _err_count(cli) if red_disabled else None   # WL3 must cover reapply errors in the bind window
    rc, r = cli.config_raw(
        f"wred-profile add {prof} -ecn ecn_all -en true "
        f"-gmin {_GMIN} -gmax {_GMAX} -gdrop 5 -ymin {_GMIN} -ymax {_GMAX} -ydrop 5 "
        f"-rmin {_GMIN} -rmax {_GMAX} -rdrop 5")
    assert cli.db_hgetall("CONFIG_DB", f"WRED_PROFILE|{prof}"), \
        f"DEVICE DEFECT: wred-profile add not landed: {((r.out or '') + (r.err or ''))[-160:]}"
    if red_disabled:
        cli.db_hset("CONFIG_DB", f"WRED_PROFILE|{prof}", "wred_red_enable", "false")
        time.sleep(2)

    qmap = cli.db_hgetall("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP") or {}
    qoid = qmap.get(f"{port}:{_Q}")
    assert qoid, f"COUNTERS_QUEUE_NAME_MAP has no {port}:{_Q}"
    cli.db_hset("CONFIG_DB", f"QUEUE|{port}|{_Q}", "wred_profile", prof)
    woid = _wait(lambda: (lambda v: v if v and v != "oid:0x0" else None)
                 (_asic_queue_wred(cli, qoid)), timeout=15)
    assert woid, (f"QUEUE|{port}|{_Q} wred_profile={prof} not programmed to ASIC "
                  f"(SAI_QUEUE_ATTR_WRED_PROFILE_ID stays absent/oid:0x0)")
    yield SimpleNamespace(port=port, qoid=qoid, woid=woid, err0=err0)
    # cleanup: unbind -> wait for oid:0x0 to land -> delete profile (order cannot be reversed, see module docstring)
    cli.db("CONFIG_DB", f'DEL "QUEUE|{port}|{_Q}"')
    unbound = _wait(lambda: _asic_queue_wred(cli, qoid) in (None, "oid:0x0"), timeout=15)
    cli.config_raw(f"wred-profile del {prof}")
    if not (unbound and not cli.db_hgetall("CONFIG_DB", f"WRED_PROFILE|{prof}")):
        print(f"CLEANUP WARNING: wred unbind/del incomplete on {port} "
              f"(unbound={unbound}); ASIC may leak a WRED object until syncd restart")


@pytest.fixture(scope="module")
def wredq(cli, topo):
    """Build FVTWRD (all colors 1M/2M, ecn_all, enable) and bind it to q1 of a port with no leftover QUEUE config.
    If this NOS-private `config wred-profile` CLI is missing, skip the whole module."""
    yield from _wredq_impl(cli, topo, _PROF, red_disabled=False)


@pytest.fixture(scope="module")
def wredqdis(cli, topo):
    """WL3-only: build FVTWRDD (red created disabled, the other two colors same as wredq) and bind it to q1 of another
    port with no leftover QUEUE config (the port already taken by wredq is auto-skipped because QUEUE|<p>|1 exists)."""
    yield from _wredq_impl(cli, topo, _PROF_D, red_disabled=True)


def test_wl1_enable_toggle_no_sai_error(wredq, cli, chip):
    """WL1: `-en false` -> `-en true`, zero SAI reapply errors, and after re-enable the ASIC thresholds == user values.
    Under a buggy implementation each toggle flushes one reapply error per green/yellow/red, and if thresholds are not
    re-sent WRED silently fails (thresholds stuck at the device max)."""
    base = _err_count(cli)
    _update(cli, "-en false")
    assert _wait(lambda: _asic_wred(cli, wredq.woid)
                 .get("SAI_WRED_ATTR_GREEN_ENABLE") == "false"), \
        "GREEN_ENABLE=false never reached ASIC"
    _update(cli, "-en true")
    assert _wait(lambda: _asic_wred(cli, wredq.woid)
                 .get("SAI_WRED_ATTR_GREEN_ENABLE") == "true"), \
        "GREEN_ENABLE=true never reached ASIC"
    time.sleep(1)   # let trailing attributes/reapply finish before the post-mortem
    got = _err_count(cli)
    assert got == base, (
        f"SAI reapply errors during enable toggle: +{got - base} `{_ERR_PAT}` in syslog "
        f"(disable clobbered stored thresholds, re-sent MAX pairs "
        f"with poisoned min as min>max)")
    attrs = _asic_wred(cli, wredq.woid)
    assert attrs.get("SAI_WRED_ATTR_GREEN_MIN_THRESHOLD") == str(_GMIN) and \
        attrs.get("SAI_WRED_ATTR_GREEN_MAX_THRESHOLD") == str(_GMAX), (
        f"user thresholds not restored after re-enable: "
        f"min={attrs.get('SAI_WRED_ATTR_GREEN_MIN_THRESHOLD')} "
        f"max={attrs.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD')} (want {_GMIN}/{_GMAX})")
    if chip.available():
        rows = _curve_rows(chip, wredq.port, _Q)
        if rows and chip.cell_size():
            want = chip.cells(_GMIN)
            assert any(abs(mn - want) <= 2 for mn, _ in rows), (
                f"chip curve has no pipe row with green_min≈{want} cells "
                f"(profile rows={rows}); re-enable not programmed to chip")


def test_wl2_disabled_threshold_update_stays_off(wredq, cli, chip):
    """WL2: update thresholds while disabled; the hardware must hold "min==max device-max" (WRED off); after re-enable the new values take effect.
    Under a buggy implementation the cache is alternately overwritten by new/poison values per write order, and the chip's final state is a matter of luck."""
    base = _err_count(cli)
    _update(cli, "-en false")
    assert _wait(lambda: _asic_wred(cli, wredq.woid)
                 .get("SAI_WRED_ATTR_GREEN_ENABLE") == "false"), \
        "GREEN_ENABLE=false never reached ASIC"
    time.sleep(1)
    if chip.available():
        rows = _curve_rows(chip, wredq.port, _Q)
        if rows:
            assert all(mn == mx for mn, mx in rows), (
                f"disabled color must sit at min==max device-max signature, "
                f"chip rows={rows}")
    _update(cli, f"-gmin {_GMIN2} -gmax {_GMAX2} -ymin {_GMIN2} -ymax {_GMAX2} "
                 f"-rmin {_GMIN2} -rmax {_GMAX2}")
    time.sleep(2)   # window for setting every field one by one + reapply
    if chip.available():
        rows = _curve_rows(chip, wredq.port, _Q)
        if rows:
            assert all(mn == mx for mn, mx in rows), (
                f"threshold update while disabled leaked into chip (rows={rows}); "
                f"WRED partially re-armed although wred_enable=false")
    _update(cli, "-en true")
    assert _wait(lambda: _asic_wred(cli, wredq.woid)
                 .get("SAI_WRED_ATTR_GREEN_MIN_THRESHOLD") == str(_GMIN2)), \
        f"new thresholds not applied after re-enable (want green_min={_GMIN2})"
    time.sleep(1)
    got = _err_count(cli)
    assert got == base, (
        f"SAI reapply errors during disabled-state update: +{got - base} in syslog")
    if chip.available():
        rows = _curve_rows(chip, wredq.port, _Q)
        if rows and chip.cell_size():
            want = chip.cells(_GMIN2)
            assert any(abs(mn - want) <= 2 for mn, _ in rows), (
                f"chip curve has no pipe row with green_min≈{want} cells after "
                f"re-enable (rows={rows})")


def test_wl3_created_disabled_unreachable_then_enable(wredqdis, cli, chip):
    """WL3: profile created red-disabled (wred_red_enable=false before binding the queue) -- the chip red must land the
    "min==max device-max" unreachable signature while green/yellow keep user values; then toggling wred_red_enable=true
    alone (without re-sending thresholds) must make the user thresholds take effect in one shot.
    Under a buggy implementation: disable overwrites the stored thresholds in place, and with no re-send on enable the chip stays at the unreachable value forever.
    The err0 baseline is snapshotted by the fixture before the profile is built, so the zero-error assertion below covers the **bind window**."""
    base = wredqdis.err0 if wredqdis.err0 is not None else _err_count(cli)
    assert _wait(lambda: _asic_wred(cli, wredqdis.woid)
                 .get("SAI_WRED_ATTR_RED_ENABLE") == "false"), \
        "RED_ENABLE=false never reached ASIC"
    attrs = _asic_wred(cli, wredqdis.woid)
    # the storage layer must keep the user thresholds (core of the fix: disable no longer overwrites stored values, only substitutes an unreachable value on the write path)
    assert attrs.get("SAI_WRED_ATTR_RED_MIN_THRESHOLD") == str(_GMIN) and \
        attrs.get("SAI_WRED_ATTR_RED_MAX_THRESHOLD") == str(_GMAX), (
        f"stored red thresholds clobbered at create-disabled: "
        f"min={attrs.get('SAI_WRED_ATTR_RED_MIN_THRESHOLD')} "
        f"max={attrs.get('SAI_WRED_ATTR_RED_MAX_THRESHOLD')} (want {_GMIN}/{_GMAX})")
    if chip.available():
        rows_r = _curve_rows(chip, wredqdis.port, _Q, "RED")
        if rows_r:
            assert all(mn == mx for mn, mx in rows_r), (
                f"created-disabled red must sit at min==max device-max signature, "
                f"chip rows={rows_r}")
        if chip.cell_size():
            want = chip.cells(_GMIN)
            for cname in ("GREEN", "YELLOW"):
                rows = _curve_rows(chip, wredqdis.port, _Q, cname)
                if rows:
                    assert any(abs(mn - want) <= 2 for mn, _ in rows), (
                        f"enabled color {cname} lost user thresholds on a "
                        f"created-disabled profile: no pipe row with min≈{want} "
                        f"cells (rows={rows})")
    # toggle enable only, do not re-send thresholds -- recovery must come from the preserved stored values
    cli.db_hset("CONFIG_DB", f"WRED_PROFILE|{_PROF_D}", "wred_red_enable", "true")
    assert _wait(lambda: _asic_wred(cli, wredqdis.woid)
                 .get("SAI_WRED_ATTR_RED_ENABLE") == "true"), \
        "RED_ENABLE=true never reached ASIC"
    assert _wait(lambda: _asic_wred(cli, wredqdis.woid)
                 .get("SAI_WRED_ATTR_RED_MIN_THRESHOLD") == str(_GMIN)), \
        f"user red thresholds not restored by bare re-enable (want red_min={_GMIN})"
    time.sleep(1)   # let reapply finish before the post-mortem
    got = _err_count(cli)
    assert got == base, (
        f"SAI reapply errors on a created-disabled color (bind + bare re-enable): "
        f"+{got - base} `{_ERR_PAT}` in syslog")
    if chip.available():
        rows_r = _curve_rows(chip, wredqdis.port, _Q, "RED")
        if rows_r and chip.cell_size():
            want = chip.cells(_GMIN)
            assert any(abs(mn - want) <= 2 for mn, _ in rows_r), (
                f"chip curve has no pipe row with red_min≈{want} cells after "
                f"bare re-enable (rows={rows_r}); user thresholds never programmed")


@pytest.mark.parametrize("color", ("green", "yellow", "red"))
def test_wl4_enable_toggle_per_color_loops(wredq, cli, chip, color):
    """WL4: per color, 3 rounds of disable->enable, each round zero SAI errors and ASIC read-back == user values.
    Expected values are read back from CONFIG_DB (WL2 already changed thresholds to the second set, not hardcoded)."""
    del chip   # this case only checks the ASIC layer; chip curves are already covered by WL1/WL2/WL3
    field = f"wred_{color}_enable"
    attr = f"SAI_WRED_ATTR_{color.upper()}_ENABLE"
    prof = cli.db_hgetall("CONFIG_DB", f"WRED_PROFILE|{_PROF}") or {}
    want_min, want_max = (prof.get(f"{color}_min_threshold"),
                          prof.get(f"{color}_max_threshold"))
    assert want_min and want_max, \
        f"WRED_PROFILE|{_PROF} missing {color} thresholds in CONFIG_DB"
    for rnd in range(3):
        base = _err_count(cli)
        cli.db_hset("CONFIG_DB", f"WRED_PROFILE|{_PROF}", field, "false")
        assert _wait(lambda: _asic_wred(cli, wredq.woid).get(attr) == "false"), \
            f"{attr}=false never reached ASIC (round {rnd})"
        cli.db_hset("CONFIG_DB", f"WRED_PROFILE|{_PROF}", field, "true")
        assert _wait(lambda: _asic_wred(cli, wredq.woid).get(attr) == "true"), \
            f"{attr}=true never reached ASIC (round {rnd})"
        time.sleep(1)   # let trailing attributes/reapply finish before the post-mortem
        got = _err_count(cli)
        assert got == base, (
            f"SAI reapply errors in {color} toggle round {rnd}: "
            f"+{got - base} `{_ERR_PAT}` in syslog")
        attrs = _asic_wred(cli, wredq.woid)
        assert attrs.get(f"SAI_WRED_ATTR_{color.upper()}_MIN_THRESHOLD") == want_min and \
            attrs.get(f"SAI_WRED_ATTR_{color.upper()}_MAX_THRESHOLD") == want_max, (
            f"{color} thresholds not restored after round {rnd} re-enable: "
            f"min={attrs.get(f'SAI_WRED_ATTR_{color.upper()}_MIN_THRESHOLD')} "
            f"max={attrs.get(f'SAI_WRED_ATTR_{color.upper()}_MAX_THRESHOLD')} "
            f"(want {want_min}/{want_max})")


def test_wl5_ecn_thresholds_unaffected_by_color_disable():
    """WL5: explicit ECN thresholds should not be polluted by the color-disable unreachable substitution -- the current
    harness cannot express explicit ECN thresholds: SONiC `config wred-profile` exposes only the ecn mode enum (ecn_none/
    ecn_all/..., verified via the click tree to have no ecn min/max flags), and the WRED_PROFILE YANG model has no ecn
    threshold leaf either (ecn thresholds are derived from drop thresholds, whose chip curve rows are already covered
    indirectly by WL1/WL2/WL3). Honestly skip; do not request any fixture -- an unconditional skip should not build and
    bind a whole profile for nothing."""
    pytest.skip("harness cannot express explicit ECN thresholds: `config wred-profile` "
                "has only the ecn mode enum and WRED_PROFILE YANG carries no ecn "
                "min/max threshold leaves (derived from drop thresholds, covered "
                "indirectly by WL1/WL2 chip curve rows)")
