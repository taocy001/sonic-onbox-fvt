"""Buffer pool **chip-level budget and programming** verification (chiptab provides
ing_service_pools()/headroom_pools() read capabilities; this module consumes them for budget reconciliation).

Core approach:

- **When a pool is misconfigured, CONFIG_DB and ASIC_DB may both look green; only the chip tables reveal it.** If the headroom
  pool is smaller than the sum required by all bound lossless PGs, the lossless guarantee fails under a PFC storm, while the
  configuration plane shows nothing abnormal. BP2 is the probe for this.
- **The chip shared pool is not equal to the configured size**:
  `shared = floor(size/cell) - floor(xoff/cell) - sum(bound-object profile.size) - reserve`.
  The reserve usually depends on port count: `base + per_port x port_count`. When the platform declares base/per_port,
  BP3 uses an exact equality, otherwise it falls back to a tolerance-window criterion.
- **Pools are programmed lazily**: create does not touch hardware, the first BUFFER_PG attach does. With no PG bound at all
  the chip stays at the SDK default, and "a pool was configured" equals nothing configured -- BP3 covers this state.

All cases are **read-only** on CONFIG_DB and the chip tables, change no configuration, and can run alongside other cases.
"""
import pytest

pytestmark = [pytest.mark.qos, pytest.mark.chiptab]

# Fallback window when the platform declares no reserve model: can only judge "whether this set of config values is in use"
# (stopping at the SDK default is off by tens of percent), it cannot judge whether the config itself is correct. Platforms that
# declare chip.pool_reserve_* use the exact equality, see BP3.
_SHARED_TOLERANCE = 0.08


def _pool_cfg(cli):
    """BUFFER_POOL in CONFIG_DB: {name: {type,mode,size,xoff}}."""
    out = {}
    for k in cli.db_keys("CONFIG_DB", "BUFFER_POOL|*") or []:
        name = k.split("|", 1)[1]
        out[name] = cli.db_hgetall("CONFIG_DB", k) or {}
    return out


def _profiles(cli):
    out = {}
    for k in cli.db_keys("CONFIG_DB", "BUFFER_PROFILE|*") or []:
        out[k.split("|", 1)[1]] = cli.db_hgetall("CONFIG_DB", k) or {}
    return out


def _bindings(cli, table):
    """BUFFER_PG / BUFFER_QUEUE bindings: [(port, index_expr, profile_name)].
    The profile value may carry the [] reference form (BUFFER_PROFILE|x); strip it uniformly to the bare name."""
    rows = []
    for k in cli.db_keys("CONFIG_DB", f"{table}|*") or []:
        parts = k.split("|")
        if len(parts) < 3:
            continue
        h = cli.db_hgetall("CONFIG_DB", k) or {}
        prof = (h.get("profile") or "").strip("[]").split("|")[-1]
        if prof:
            rows.append((parts[1], parts[2], prof))
    return rows


def _idx_count(expr):
    """The binding key's index segment may be "3" or "0-2" (a range); return the number of objects it covers."""
    s = str(expr)
    if "-" in s:
        a, _, b = s.partition("-")
        if a.strip().isdigit() and b.strip().isdigit():
            return max(0, int(b) - int(a) + 1)
        return 0
    return 1 if s.strip().isdigit() else 0


def _int0(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def _device_cells(chip):
    """The chip's self-reported total MMU cell count (TM_DEVICE_INFO.NUM_CELLS). No hard-coded constant --
    it follows automatically across SKU/chip changes."""
    ents = chip.traverse("TM_DEVICE_INFO")
    if not ents:
        return None
    return ents[0].get("NUM_CELLS")


def _shared_cells(chip):
    """SHARED_LIMIT_CELLS of each ingress service pool (prefer OPER -- it is the effective value)."""
    out = {}
    for e in chip.ing_service_pools():
        pid = e.get("TM_ING_SERVICE_POOL_ID")
        if pid is None:
            continue
        v = e.get("SHARED_LIMIT_CELLS_OPER")
        if v is None:
            v = e.get("SHARED_LIMIT_CELLS")
        out[pid] = _int0(v)
    return out


def _headroom_cells(chip):
    out = {}
    for e in chip.headroom_pools():
        pid = e.get("TM_HEADROOM_POOL_ID")
        if pid is None:
            continue
        v = e.get("LIMIT_CELLS_OPER")
        if v is None:
            v = e.get("LIMIT_CELLS")
        out[pid] = _int0(v)
    return out


@pytest.fixture(scope="module")
def pools(chip):
    chip.require()
    if not chip.has_table("TM_ING_THD_SERVICE_POOL"):
        pytest.skip("TM_ING_THD_SERVICE_POOL absent on this chip family "
                    "(pool accounting model differs; nothing to assert)")
    return {"shared": _shared_cells(chip), "headroom": _headroom_cells(chip)}


# ============================ BP1 budget not oversubscribed ============================
def test_bp1_pool_budget_within_device_cells(chip, pools):
    """BP1 chip self-consistency: the sum of all ingress shared pools + all headroom pools must not exceed the total MMU cell count.

    Exceeding it means the two ledgers together are larger than physical buffer -- under congestion the thresholds on either side
    are meaningless. Configuring past the limit in one shot is rejected outright by the SDK (e.g. `INCORRECT_SHARED_LIMIT`), but
    reaching the "each legal, together over" state in two steps is caught by no one."""
    total = _device_cells(chip)
    if not total:
        pytest.skip("TM_DEVICE_INFO.NUM_CELLS unreadable; refusing to guess MMU size")
    used = sum(pools["shared"].values()) + sum(pools["headroom"].values())
    assert used <= total, (
        f"buffer budget oversubscribed on chip: shared pools {pools['shared']} + "
        f"headroom pools {pools['headroom']} = {used} cells > device NUM_CELLS "
        f"{total}; both ledgers together exceed physical MMU — thresholds on at "
        f"least one side cannot be honoured")


# ============================ BP2 headroom oversubscription probe ============================
def test_bp2_headroom_pool_covers_bound_lossless_pgs(cli, chip, pools):
    """BP2 **headroom oversubscription probe**: headroom pool capacity must be >=
    the sum of headroom required by all bound lossless PGs.

    Every PG bound to a profile with xoff requests `xoff/cell` cells from the headroom pool during a PFC pause. When the pool
    is smaller than total demand, the configuration plane/ASIC_DB are all green and each port's PG HEADROOM_LIMIT_CELLS is
    individually correct, but when multiple ports back-pressure at once the later ones get no buffer --
    "lossless" fails exactly when it is needed most. This kind of defect is only visible by summing and reconciling both sides."""
    profs = _profiles(cli)
    need = 0
    detail = []
    for port, idx, pname in _bindings(cli, "BUFFER_PG"):
        xoff = _int0((profs.get(pname) or {}).get("xoff"))
        if xoff <= 0:
            continue
        n = _idx_count(idx)
        cells = chip.cells(xoff) * n
        need += cells
        detail.append((port, idx, pname, cells))
    if not need:
        pytest.skip("no lossless BUFFER_PG binding (profile with xoff) present; "
                    "headroom accounting not exercised in this configuration")
    have = sum(pools["headroom"].values())
    ratio = (need / have) if have else float("inf")
    assert have >= need, (
        f"headroom pool OVERSUBSCRIBED {ratio:.1f}x: {len(detail)} lossless PG "
        f"bindings need {need} cells total, chip headroom pools hold {have} "
        f"({pools['headroom']}). Under a multi-port PFC storm the later ports get "
        f"no headroom and drop — 'lossless' silently stops being lossless. "
        f"Raise BUFFER_POOL.xoff or bind fewer "
        f"lossless PGs. sample={detail[:4]}")


# ============================ BP3 shared pool really programmed per config ============================
def test_bp3_shared_pool_matches_configured_size(cli, chip, pools):
    """BP3 the shared pool programmed value must come from CONFIG_DB's pool config, not the SDK default.

    Pools are programmed lazily: create does not push, the first BUFFER_PG attach does. So this case only has a criterion when
    **a PG is already bound** (otherwise the chip staying at the SDK default is expected, and it skips with an explanation).

    The criterion uses a range rather than equality: chip shared pool = size - xoff - sum(bound-object min) - fixed term,
    where the fixed term varies by platform. Landing within [balance x (1-tol), balance] is taken as "this set of config values is in use";
    stopping at the SDK default is off by tens of percent and stands out at a glance."""
    cfg = _pool_cfg(cli)
    if not cfg:
        pytest.skip("no BUFFER_POOL in CONFIG_DB on this image")
    pg_rows = _bindings(cli, "BUFFER_PG")
    if not pg_rows:
        pytest.skip("no BUFFER_PG binding: pool programming is lazy on this SAI "
                    "(create does not touch hardware), so the chip legitimately "
                    "still shows the SDK default — nothing to compare")
    # Single-pool model (this platform's sole whole_pool): with multiple pools, take the largest-size one as the main-ledger
    # reference, and include the full set in the message to avoid misjudgment.
    name, main = max(cfg.items(), key=lambda kv: _int0(kv[1].get("size")))
    size_b = _int0(main.get("size"))
    if size_b <= 0:
        pytest.skip(f"BUFFER_POOL|{name} has no numeric size ({main}); "
                    "vendor-managed pool, nothing to verify")
    size_c = size_b // chip.cell_size()
    xoff_c = _int0(main.get("xoff")) // chip.cell_size()

    profs = _profiles(cli)
    # Which pool the min (profile.size) is deducted from depends on the pool type: a BOTH-type pool shares one ledger for
    # ingress and egress, so both PG and queue mins are charged to it; a pure ingress pool only deducts the PG part,
    # and counting queue in as well over-deducts and pushes the result below the window's lower edge.
    tables = ("BUFFER_PG",) if (main.get("type") or "").lower() == "ingress" \
        else ("BUFFER_PG", "BUFFER_QUEUE")
    min_c = 0
    for table in tables:
        for _p, idx, pname in _bindings(cli, table):
            sz = _int0((profs.get(pname) or {}).get("size"))
            if sz > 0:
                min_c += chip.cells(sz) * _idx_count(idx)

    balance = size_c - xoff_c - min_c
    got = sum(pools["shared"].values())

    # Platform declares a reserve model -> exact equality (an order of magnitude more sensitive than the window)
    base = chip.chip_cfg("pool_reserve_base_cells")
    per_port = chip.chip_cfg("pool_reserve_per_port_cells")
    if base is not None and per_port is not None:
        nports = len(cli.db_keys("CONFIG_DB", "PORT|Ethernet*") or [])
        reserve = int(base) + int(per_port) * nports
        want = balance - reserve
        assert got == want, (
            f"chip shared pool is {got} cells, model predicts exactly {want}: "
            f"size {size_c}c − xoff {xoff_c}c − bound mins {min_c}c − reserve "
            f"({base} + {per_port}×{nports} ports = {reserve}). Delta {got - want} "
            f"cells. A mismatch means one of: the pool was programmed from different "
            f"values than CONFIG_DB now holds (sticky/lazy pool — it only reaches "
            f"hardware on the first BUFFER_PG attach), the port count changed since "
            f"the pool was programmed, or this SKU reserves differently and the "
            f"profile needs recalibrating. config={cfg}, all pools={pools['shared']}")
        return

    lo = int(balance * (1 - _SHARED_TOLERANCE))
    assert lo <= got <= balance, (
        f"chip shared pool {got} cells is outside the budget window "
        f"[{lo}, {balance}] derived from CONFIG_DB BUFFER_POOL|{name} "
        f"(size={size_b}B={size_c}c, xoff={xoff_c}c, bound mins={min_c}c). "
        + ("ABOVE the window means the pool is oversubscribed or still at the SDK "
           "default (pool never programmed — check that a BUFFER_PG attach "
           "happened after the pool was created). "
           if got > balance else
           "BELOW the window means the chip was programmed from different values "
           "than CONFIG_DB holds — stale/sticky pool state, or the pool was "
           "re-created from an older config. ")
        + f"all pools={pools['shared']}, config={cfg}")


# ============================ BP4 pool type consistent with config ============================
def test_bp4_pool_type_consistent_config_to_asic(cli, asicdb):
    """BP4 the pool type declared in CONFIG_DB must match the one actually created in ASIC_DB.

    Background: when CONFIG_DB writes `type: ingress` but the pool is created as `SAI_BUFFER_POOL_TYPE_BOTH`,
    some SAI implementations reject attribute SETs on a BOTH-type pool, so the pool size cannot be changed at runtime, and the
    symptom is "configured but nothing happens". The type mismatch is the head of this chain, and reconciling it here is easiest.

    Note: if the config itself writes `type: both` (a value fixed only at create and never SET at runtime, precisely
    bypassing that restriction), it is consistent and not judged a failure."""
    cfg = _pool_cfg(cli)
    if not cfg:
        pytest.skip("no BUFFER_POOL in CONFIG_DB")
    keys = asicdb.objects("SAI_OBJECT_TYPE_BUFFER_POOL")
    if not keys:
        pytest.skip("no SAI_OBJECT_TYPE_BUFFER_POOL in ASIC_DB")
    asic_types = []
    for k in keys:
        attrs = cli.db_hgetall("ASIC_DB", k) or {}
        t = (attrs.get("SAI_BUFFER_POOL_ATTR_TYPE") or "").rsplit("_", 1)[-1].lower()
        if t:
            asic_types.append(t)
    if not asic_types:
        pytest.skip("ASIC_DB buffer pools carry no TYPE attribute")
    cfg_types = sorted({(v.get("type") or "").lower() for v in cfg.values() if v.get("type")})
    got = sorted(set(asic_types))
    assert got == cfg_types, (
        f"buffer pool type mismatch: CONFIG_DB declares {cfg_types} but ASIC_DB "
        f"has {got}. A pool created as BOTH may reject attribute SETs in some "
        f"SAI implementations, so its size can never be changed at "
        f"runtime — the symptom is 'pool resize silently does nothing' plus a "
        f"flood of failed SETs. config={cfg}")
