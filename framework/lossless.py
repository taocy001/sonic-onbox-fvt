"""Lossless (RoCE/PFC) configuration driver -- programmatic form of the AIDC RoCE config template (~/aidc-roce-config-template.md).

Goal: push the full chain "DSCP->TC->queue/PG same number + TC_TO_PG + PFC enable + lossless buffer(pool/profile/PG)"
via the SONiC blessed path, and return structured expected values for the final chiptab chip-table check
(true-lossless criteria: PC_PFC enabled AND TM_ING_PORT_PRI_GRP.LOSSLESS=1 AND headroom>0).

Channel selection (all via the SONiC blessed path, never writing the chip directly):
- Map tables/schedulers: SONiC product CLI (probe --help); tables without a CLI go through GCU apply-patch (YANG-validated).
- BUFFER_PG binding: always GCU apply-patch (the template-validated channel; `config interface buffer`
  is incomplete in both image families).
- CLI trap: the `port-queue add` YANG plugin forces the scheduler to carry cir+cbs (a pure-software gate,
  the chip does not need it). Adaptive: try bare config first, and on a "cir and cbs" error retry with cir=0/cbs=0
  (cir=0 chip semantics = no minimum guarantee; MAX unset = no rate limit).
"""
import re
import time

from . import log
from .qos import _unbind_port_qos, has_qos_cli, tc_name  # noqa: F401

_log = log.get("lossless")


def _help_flags(cli, cmd):
    """Return the `config <cmd> --help` text (to probe the flag set); returns "" if the command does not exist."""
    r = cli.sh.run(f"config {cmd} --help", check=False)
    return (r.out or "") if r.rc == 0 else ""


class LosslessBuild:
    """Product of one lossless build: expected values + undo."""

    def __init__(self, port, pg, queue, dscp, tc):
        self.port, self.pg, self.queue, self.dscp, self.tc = port, pg, queue, dscp, tc
        self.pool = None            # (name, size_bytes, xoff_bytes) the ingress pool actually used
        self.pool_created = False
        self.profile = None         # profile name
        self.xoff = None            # expected headroom bytes (BUFFER_PROFILE.xoff)
        self.size = None            # PG min bytes
        self.maps = []              # maps created [(table, name)]
        self.steps = []             # for post-mortem review
        self._undo = []

    def defer(self, fn):
        self._undo.append(fn)

    def undo(self):
        for fn in reversed(self._undo):
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                _log.warning("lossless undo step failed: %s", e)


def _pfc_enabled_set(cli, port):
    """The port's current pfc_enable set (PORT_QOS_MAP.pfc_enable, comma-separated)."""
    h = cli.db_hgetall("CONFIG_DB", f"PORT_QOS_MAP|{port}") or {}
    raw = h.get("pfc_enable", "") or ""
    return {int(x) for x in raw.split(",") if x.strip().isdigit()}


def pfcwd_blocked(cli, port):
    """Whether the port has a PFC_WD entry: if so, `config interface pfc priority` is rejected
    but still returns rc=0. Clear it with the **top-level** `pfcwd stop <port>` -- note that
    `config pfcwd stop` takes no port argument, and passing one errors out while also returning rc=0."""
    return bool(cli.db_hgetall("CONFIG_DB", f"PFC_WD|{port}"))


def pick_pfc_port(cli, topo, roles=("g", "h", "e", "f")):
    """Pick a test port with no leftover PFC_WD, avoiding whole-round pollution caused by stale PFC_WD.
    If all are occupied, return the first candidate and let the test case expose it honestly."""
    cands = []
    for r in roles:
        try:
            cands.append(topo.port(r))
        except KeyError:
            continue
    for p in cands:
        if not pfcwd_blocked(cli, p.name):
            return p, "clean"
    return (cands[0], "all-blocked") if cands else (None, "no-candidate")


def pick_pg(cli, port, prefer):
    """Pick a PG that can be made lossless. On SONiC, if BUFFER_PG|port|pg already exists
    but that pg is not pfc-enabled, `pfc priority on` is rejected with "PFC/PG buffer cannot coexist".
    Rules: pg already PFC-enabled -> use it directly (existing mode, ideally with an existing BUFFER_PG);
    otherwise pick a pg with "no existing BUFFER_PG"; if all conflict, use prefer and let the failure surface honestly."""
    enabled = _pfc_enabled_set(cli, port)
    cands = [prefer] + [p for p in (3, 4, 2, 1, 5) if p != prefer]
    for p in cands:
        if p in enabled:
            return p, "existing-pfc"
    for p in cands:
        if not cli.db_hgetall("CONFIG_DB", f"BUFFER_PG|{port}|{p}"):
            return p, "fresh"
    return prefer, "conflicted"


def build_lossless(cli, gcu, port, *, dscp=26, pg=3,
                   headroom_bytes=203200, min_bytes=4318, static_th_bytes=None,
                   dynamic_th=1, xon_offset=131072, prefix="FVTLL", **_legacy):
    """Build a "single lossless PG" on port. Returns a LosslessBuild (with undo).

    **Entirely via product CLI, creating no QoS map tables**:
    - DSCP->TC and TC->queue use the image's built-in default maps (each port's PORT_QOS_MAP
      is already bound; the default maps take DSCP 26 -> AF3, AF3 -> queue 3), which is how production uses it too;
    - TC->PG relies on the chip's identity mapping (correct mapping with no TC_TO_PG table);
      this framework no longer creates that table -- it both deviates from production reality and its only entry point, apply-patch, is unstable;
    - buffer: `config buffer profile add` + `config interface buffer priority-group
      lossless add <port> <pg> <profile>`;
    - PFC: `config interface pfc priority <port> <pg> on`, and **read back PORT_QOS_MAP.pfc_enable
      as the verdict** (the CLI still returns rc=0 when it rejects).

    The gcu parameter is kept only for compatibility with the existing call signature; this function no longer uses it.
    """
    b = LosslessBuild(port, pg, pg, dscp, tc_name(pg))
    pg, pg_mode = pick_pg(cli, port, pg)
    b.pg = b.queue = pg
    b.tc = tc_name(pg)
    b.steps.append(("pick_pg", True, f"pg={pg} mode={pg_mode}"))

    # 1) Classification chain: just verify the default maps really carry dscp to tc=pg (no config, read-only assertion material)
    dflt = cli.db_hgetall("CONFIG_DB", "DSCP_TO_TC_MAP|default") or {}
    got_tc = dflt.get(str(dscp))
    b.steps.append(("default_dscp_to_tc", got_tc == tc_name(pg),
                    f"dscp {dscp} -> {got_tc} (want {tc_name(pg)})"))
    dq = cli.db_hgetall("CONFIG_DB", "TC_TO_QUEUE_MAP|default") or {}
    got_q = dq.get(tc_name(pg))
    b.steps.append(("default_tc_to_queue", str(got_q) == str(pg),
                    f"{tc_name(pg)} -> q{got_q} (want q{pg})"))

    # 2) Lossless config: the product blessed path is **a single command**
    #    `config interface buffer priority-group lossless add <port> <pg> <profile>`
    #    -- it creates BUFFER_PG, sets PORT_QOS_MAP.pfc_enable, and programs the ASIC PFC bitmap all at once.
    #    **Do not** additionally run `pfc priority on`: this NOS explicitly rejects
    #    "PFC, PG buffer and ASY configurations cannot coexist".
    existing = cli.db_hgetall("CONFIG_DB", f"BUFFER_PG|{port}|{pg}") or {}
    if existing:
        prof = (existing.get("profile", "") or "").strip("[]").split("|")[-1]
        ph = cli.db_hgetall("CONFIG_DB", f"BUFFER_PROFILE|{prof}") or {}
        b.profile = prof
        b.xoff = _int0(ph.get("xoff")) or _int0(ph.get("headroom"))
        b.size = _int0(ph.get("size")) or _int0(ph.get("min_th"))
        b.steps.append(("bind_pg", True,
                        f"existing profile={prof} xoff={b.xoff} size={b.size}"))
        b.steps.append(("pfc_on", pg in _pfc_enabled_set(cli, port), "implied by BUFFER_PG"))
        return b

    prof = f"{prefix}_prof"
    th = (f"--static-th {static_th_bytes}" if static_th_bytes and dynamic_th is None
          else f"--dynamic-th {1 if dynamic_th is None else dynamic_th}")
    rc, r = cli.config_raw(
        f"buffer profile add {prof} --headroom {headroom_bytes} "
        f"--xon-offset {xon_offset} --min-th {min_bytes} {th}")
    ok_prof = bool(cli.db_hgetall("CONFIG_DB", f"BUFFER_PROFILE|{prof}"))
    b.steps.append(("create_profile", ok_prof, ((r.out or "") + (r.err or ""))[-160:]))
    if not ok_prof:
        return b
    b.defer(lambda: cli.config_raw(f"buffer profile del {prof}"))
    ph = cli.db_hgetall("CONFIG_DB", f"BUFFER_PROFILE|{prof}") or {}
    b.profile = prof
    b.xoff = _int0(ph.get("xoff")) or _int0(ph.get("headroom")) or headroom_bytes
    b.size = _int0(ph.get("size")) or _int0(ph.get("min_th")) or min_bytes

    rc, r = cli.config_raw(
        f"interface buffer priority-group lossless add {port} {pg} {prof}")
    text = ((r.out or "") + (r.err or "")).strip()
    landed = False
    for _ in range(8):     # rc is unreliable; always read back CONFIG_DB for the verdict
        if cli.db_hgetall("CONFIG_DB", f"BUFFER_PG|{port}|{pg}"):
            landed = True
            break
        time.sleep(1)
    b.steps.append(("bind_pg", landed, text[-160:]))
    if landed:
        b.defer(lambda: cli.config_raw(
            f"interface buffer priority-group lossless del {port} {pg}"))
    # PFC is implicitly enabled by the command above; read back to verify (no separate push)
    pfc_ok = False
    for _ in range(6):
        if pg in _pfc_enabled_set(cli, port):
            pfc_ok = True
            break
        time.sleep(1)
    b.steps.append(("pfc_on", pfc_ok,
                    "implied by lossless PG bind" if pfc_ok
                    else "lossless PG bind did not enable PFC"))
    time.sleep(3)
    _log.info("lossless build on %s: %s", port, b.steps)
    return b


def make_scheduler(cli, name, mode="DWRR", weight=None, pir=None, pbs=None):
    """Create a scheduler, adapting to the forced cir/cbs gate. Returns (ok, undo_fn).

    Units: the SONiC CLI's -pr/--pir is in **Kbps** (IntRange 0~1e8);
    when the CLI lands it in CONFIG_DB it converts to **bytes/s** (-pr 10000000 -> pir=1250000000). The caller
    passes pir in CLI units; expected values are always read back from CONFIG_DB and converted, never trusting the argument. When any rate knob is set,
    -m bytes is auto-appended (a missing meter-type causes Aborted)."""
    # A previous run aborted abnormally may leave a same-named object ("already exists"); clean up idempotently first
    if cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{name}"):
        cli.config_raw(f"scheduler del {name}")
        time.sleep(1)
    base = f"scheduler add {name} -t {mode}"
    if weight is not None:
        base += f" -w {weight}"
    h = _help_flags(cli, "scheduler add")
    def flag(f):
        for cand in (f"--{f}", f"-{f}"):
            if re.search(rf"(^|\s){re.escape(cand)}(\s|,)", h):
                return cand
        return None
    extra = ""
    if pir is not None and flag("pir"):
        extra += f" {flag('pir')} {pir}"
    if pir is not None and pbs is None:
        pbs = 8192          # the CLI requires pir/pbs as a pair (a missing pbs reports "Missing pbs")
    if pbs is not None and flag("pbs"):
        extra += f" {flag('pbs')} {pbs}"
    if extra and flag("meter-type"):
        extra += f" {flag('meter-type')} bytes"
    rc, r = cli.config_raw(base + extra)
    text = ((r.out or "") + (r.err or "")).strip()
    if rc != 0 and "cir" in text.lower() and flag("cir"):
        # YANG gate: forces cir+cbs to be present as a pair. cir=0 chip semantics = no minimum guarantee.
        retry = base + f" {flag('cir')} 0"
        if flag("cbs"):
            retry += f" {flag('cbs')} 0"
        retry += extra
        rc, r = cli.config_raw(retry)
        text = ((r.out or "") + (r.err or "")).strip()
    # rc is unreliable: the verdict comes from reading back CONFIG_DB
    if not cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{name}"):
        _log.warning("scheduler add did not land: cmd=%r text=%r",
                     base + extra, text[-300:])
        return False, lambda: None, text[-300:] or f"rc={rc}, no CLI output"

    def _del_sched():
        # **retry + read-back confirm**: the caller's reverse-order undo first unbinds port-qos-map/port-queue, but that
        # unbind is asynchronous on SONiC -- the immediately following `scheduler del` often fails within the "still referenced" window (its rc is ignored),
        # and a leftover scheduler = the port is rate-limited to pir, polluting all subsequent traffic cases. The retry loop gives the unbind time to settle.
        for _ in range(8):
            if not cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{name}"):
                return
            cli.config_raw(f"scheduler del {name}")
            time.sleep(0.5)
        _log.warning("scheduler %s still in CONFIG_DB after retried del (still bound?)", name)

    return True, _del_sched, ""


def bind_queue(cli, port, q, sched=None, wred=None):
    """port-queue binding. Returns (ok, undo_fn).

    Some builds have a new CLI gate: `port-queue add -s` requires the scheduler to carry the
    **full set** cir/cbs/pir/pbs, otherwise "The device requires cir and cbs ...
    Aborted!" (and cir requires pir as a pair, with 0 treated as unset -- a pure-scheduling profile cannot bind). When this gate is hit, the
    profile is auto-augmented with cir=1/cbs=8192/pir=1e8(=CLI ceiling 100Gbps)/pbs=8192 and retried once.
    WARNING side effect: any scheduled queue on that build is forced to carry a <=100G implicit rate cap (an 800G port = actually capped),
    exposed by the test_bound_queue_shapers_meet_linerate_lint / cir_zero cases."""
    cmd = f"port-queue add {port} {q}"
    if sched:
        cmd += f" -s {sched}"
    if wred:
        cmd += f" -w {wred}"
    rc, r = cli.config_raw(cmd)
    text = ((r.out or "") + (r.err or ""))[-200:]
    landed = False
    for _ in range(5):      # rc is unreliable: read back QUEUE|<port>|<q> for the verdict
        if cli.db_hgetall("CONFIG_DB", f"QUEUE|{port}|{q}"):
            landed = True
            break
        time.sleep(1)
    if not landed and sched and "requires cir and cbs" in text:
        _log.warning("bind_queue hit the cir/cbs/pir/pbs CLI gate; recreating "
                     "%s with cir=1/pir=100Gbps (forced implicit queue cap on >100G ports) "
                     "and retrying", sched)
        # `scheduler update` does not accept -m and always blows up with "Error: 'cir'" when carrying a rate --
        # the only path is to delete and rebuild with the original type/weight plus the full meter parameter set.
        h = cli.db_hgetall("CONFIG_DB", f"SCHEDULER|{sched}") or {}
        rebuild = f"scheduler add {sched}"
        if h.get("type"):
            rebuild += f" -t {h['type']}"
        if str(h.get("weight", "")).isdigit():
            rebuild += f" -w {h['weight']}"
        rebuild += " -m bytes -cr 1 -cs 8192 -pr 100000000 -ps 8192"
        cli.config_raw(f"scheduler del {sched}")
        time.sleep(1)
        cli.config_raw(rebuild)
        rc, r = cli.config_raw(cmd)
        text = ((r.out or "") + (r.err or ""))[-200:]
        for _ in range(5):
            if cli.db_hgetall("CONFIG_DB", f"QUEUE|{port}|{q}"):
                landed = True
                break
            time.sleep(1)
    if not landed:
        _log.info("bind_queue did not land: %s", text)
        return False, lambda: None
    return True, lambda: cli.config_raw(f"port-queue del {port} {q}")


# ---- internal ----

def _int0(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _pick_ingress_pool(cli):
    for k in cli.db_keys("CONFIG_DB", "BUFFER_POOL|*"):
        h = cli.db_hgetall("CONFIG_DB", k) or {}
        if h.get("type", "ingress") in ("ingress", "both"):
            return k.split("|", 1)[1]
    return None


def _cli_map(cli, b, cmd, table, name):
    rc, r = cli.config_raw(cmd)
    b.steps.append((f"map:{table}", rc == 0, ((r.out or "") + (r.err or ""))[-160:]))
    if rc == 0:
        b.maps.append((table, name))
        grp = cmd.split()[0]
        b.defer(lambda: cli.config_raw(f"{grp} del {name}"))


