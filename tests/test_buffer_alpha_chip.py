"""Chip-level alpha (dynamic threshold coefficient) semantics for lossless PGs.

The framework has always just written `--dynamic-th` down and never had any test
read back what the chip understood it to mean. Yet this number means **different
things** on different SAI semantic lines:

| alpha semantics | `dynamic_th=1` actually is |
|---|---|
| alpha = 2^th (standard) | alpha = 2 |
| alpha = 2^(th-6)        | alpha = **1/32** |

In other words, the same test code running on DUTs with different semantics gives
the lossless PG a share of the shared pool that differs by **64x**, and no assertion
would ever fire about it — `lossless.build_lossless`'s default happens to be exactly
`dynamic_th=1`. A too-small alpha means the PG stops early at a tiny shared quota, PFC
backpressure triggers prematurely, and throughput cannot ramp; a too-large alpha lets
a handful of ports drain the shared pool. Neither leaves any trace at the config layer.

Source of truth: `chip.alpha_offset()` reads the profile's `chip.alpha_exponent_offset`
(calibrated from the correspondence between `--dynamic-th` and the chip enum: e.g. at
offset=-6, `--dynamic-th 2` -> `ALPHA_1_16`; at offset=0, th=0 -> ALPHA_1, th=3 -> ALPHA_8).
**Undeclared platforms are skipped rather than assumed to use standard semantics** —
guessing the wrong direction is a 64x error.

AL1/AL2 are read-only; AL3 provisions a profile with a known th as a closed loop and rolls back.
"""
import pytest

from framework import lossless
from framework.gcu import Gcu

pytestmark = [pytest.mark.qos, pytest.mark.chiptab, pytest.mark.roce]

_ALPHA_FIELD = "SHARED_LIMIT_DYNAMIC"
_PROBE_TH = 0          # dynamic_th provisioned by the closed-loop test: maps differently on both platforms, so it discriminates best


def _profiles(cli):
    out = {}
    for k in cli.db_keys("CONFIG_DB", "BUFFER_PROFILE|*") or []:
        out[k.split("|", 1)[1]] = cli.db_hgetall("CONFIG_DB", k) or {}
    return out


def _lossless_pg_bindings(cli):
    """[(port, pg, profile_name, dynamic_th)], only for profiles that explicitly set dynamic_th."""
    profs = _profiles(cli)
    rows = []
    for k in cli.db_keys("CONFIG_DB", "BUFFER_PG|*") or []:
        parts = k.split("|")
        if len(parts) < 3 or "-" in parts[2]:      # skip range indices; per-PG reconciliation is what matters
            continue
        h = cli.db_hgetall("CONFIG_DB", k) or {}
        pname = (h.get("profile") or "").strip("[]").split("|")[-1]
        th = (profs.get(pname) or {}).get("dynamic_th")
        if pname and th is not None and str(th).strip().lstrip("-").isdigit():
            rows.append((parts[1], parts[2], pname, int(th)))
    return rows


@pytest.fixture(scope="module")
def alpha_off(chip):
    chip.require()
    off = chip.alpha_offset()
    if off is None:
        pytest.skip("chip.alpha_exponent_offset not declared for this platform; "
                    "refusing to assume the standard alpha=2^dynamic_th mapping — "
                    "guessing wrong is a 64x error (see module docstring). Calibrate "
                    "once with `config buffer profile add ... --dynamic-th 2` and read "
                    "TM_ING_THD_PORT_PRI_GRP.SHARED_LIMIT_DYNAMIC back, then declare it.")
    return int(off)


# ============================ AL1 platform on file ============================
def test_al1_alpha_semantics_declared_and_sane(chip, alpha_off):
    """AL1: platform must declare its alpha exponent offset, and the mapping must yield a valid enum name.

    This one does not touch the device; it guards against "someone onboarding a new
    platform blindly reuses standard semantics" — some SAI semantic lines are shifted
    a full 6 exponent bits, and standard semantics are not universal."""
    assert -8 <= alpha_off <= 0, (
        f"chip.alpha_exponent_offset={alpha_off} is outside any observed range "
        f"[-8, 0]; either the profile has a typo or this platform uses a mapping "
        f"nobody has characterised — do not let tests run on a guess")
    for th in (0, 1, 3):
        name = chip.alpha_enum(th + alpha_off)
        assert name.startswith("ALPHA_"), (
            f"alpha_enum({th}+{alpha_off}) produced {name!r}, not a chip enum name")


# ============================ AL2 per-binding reconciliation of existing bindings ============================
def test_al2_bound_pg_alpha_matches_configured_dynamic_th(cli, chip, alpha_off):
    """AL2 **read-only reconciliation**: for every bound lossless PG, the chip's
    `SHARED_LIMIT_DYNAMIC` must equal the enum that the profile's `dynamic_th` maps to
    under this platform's semantics.

    A mismatch has two possible causes, both serious: either SAI translated th under
    different semantics (invisible at the config layer), or the binding never reached
    the chip and the PG is still at the SDK default — the latter, when
    `HEADROOM_LIMIT_CELLS` was also never written, shows up as "claims lossless but has
    zero headroom"."""
    rows = _lossless_pg_bindings(cli)
    if not rows:
        pytest.skip("no BUFFER_PG bound to a profile carrying dynamic_th; "
                    "alpha semantics not exercised in this configuration")
    bad, checked = [], 0
    for port, pg, pname, th in rows:
        ent = chip.pg_thd(port, pg)
        if not ent or _ALPHA_FIELD not in ent:
            continue
        checked += 1
        want = chip.alpha_enum(th + alpha_off)
        got = str(ent.get(_ALPHA_FIELD))
        if got != want:
            bad.append((port, pg, pname, th, want, got))
    if not checked:
        pytest.skip(f"chip returned no {_ALPHA_FIELD} for any bound PG "
                    f"({len(rows)} bindings tried); table/field absent on this chip")
    assert not bad, (
        f"alpha mismatch on {len(bad)}/{checked} bound lossless PGs. Expected enum "
        f"is alpha_enum(dynamic_th + {alpha_off}) for this platform. A wrong alpha "
        f"silently changes how much shared pool the PG may take — too small starves "
        f"throughput and triggers PFC early, too large lets a few ports eat the pool. "
        f"If the chip shows the SDK default instead, the binding never reached "
        f"hardware. sample={bad[:4]}")


# ============================ AL3 provisioning closed loop ============================
def test_al3_configured_dynamic_th_lands_as_expected_alpha(cli, chip, topo, alpha_off):
    """AL3 **closed-loop self-calibration**: provision a known `dynamic_th` on a test
    port and read the chip enum back to check it.

    This is the active version of AL2 — existing config may not have a single profile
    carrying dynamic_th, in which case AL2 can only skip. This test builds one itself,
    so any platform can produce an empirically measured conclusion about "what this
    box's alpha semantics actually are". th=0 is used because it differs across the two
    semantic lines (standard -> ALPHA_1, offset semantics -> ALPHA_1_64), which best
    exposes a misconfigured platform profile."""
    p, why = lossless.pick_pfc_port(cli, topo)
    if p is None:
        pytest.skip("no candidate port for PFC/lossless tests")
    if why == "all-blocked":
        pytest.fail(
            "every candidate port carries a stale PFC_WD entry, so lossless "
            "provisioning is refused there while the CLI still returns rc=0. "
            "Clear it with the top-level `pfcwd stop <port>` and rerun.")
    b = lossless.build_lossless(cli, Gcu(cli), p.name, dynamic_th=_PROBE_TH)
    try:
        if not any(s[0] == "bind_pg" and s[1] for s in b.steps):
            pytest.skip(f"buffer provisioning channel unavailable on this image "
                        f"(steps={b.steps}); alpha round-trip untestable here")
        want = chip.alpha_enum(_PROBE_TH + alpha_off)
        ok, ent = chip.wait_field(
            lambda: chip.pg_thd(b.port, b.pg), _ALPHA_FIELD,
            lambda v: str(v) == want, timeout=30)
        assert ok, (
            f"configured dynamic_th={_PROBE_TH} on {b.port} PG{b.pg} but chip "
            f"{_ALPHA_FIELD} is {(ent or {}).get(_ALPHA_FIELD)!r}, expected {want!r} "
            f"for alpha_exponent_offset={alpha_off}. Either this platform's alpha "
            f"semantics differ from the profile (recalibrate the offset — every "
            f"lossless test on this DUT is running at the wrong alpha until you do) "
            f"or the profile never reached the chip. entry={ent}")
    finally:
        b.undo()
