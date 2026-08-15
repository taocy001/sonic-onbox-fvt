"""Cross-test contamination sentinel (goal #1 diagnostic).

Enabled when FVT_SENTINEL=1: **after every test's teardown has fully run** (after the yield in the
pytest_runtest_teardown hookwrapper), it takes a fingerprint of device state and compares it against
the "last quiet baseline". Any net change is attributed precisely to the test that just ran --
turning "order-dependent flaky failures that only reproduce on a full run" into a deterministic leak
map: `test X left behind CONFIG_DB keys [...] / dynamic FDB grew by N / port stuck down`.

Three fingerprint elements (all cheap, single redis KEYS):
  1) CONFIG_DB full key set -- catches every config leak in one shot: VLAN members / INTERFACE(RIF) /
     ACL / MIRROR / static FDB / QoS.buffer.policer / PFC / AAA / SNMP / sFlow, etc.;
  2) ASIC_DB dynamic FDB_ENTRY count -- learn-state leak / flooding-storm indicator;
  3) ASIC_DB NEIGHBOR_ENTRY count -- neighbor-learning leak indicator.

CONFIG_DB uses a "rolling baseline": after net additions/removals are attributed to the test that
produced them, the baseline is advanced to the current state -- so a persistent leak is attributed
only once (pinpointing its source) and does not repeatedly blame later tests. FDB/neighbor are
dynamic quantities, compared against the original baseline and reported only over threshold (not
rolling).
"""
import json
import os

_ON = os.environ.get("FVT_SENTINEL", "") not in ("", "0", "false", "no")
_REPORT = os.environ.get("FVT_SENTINEL_REPORT", "/tmp/fvt_sentinel.jsonl")
# Alert threshold for dynamic quantities: only this much above baseline counts as a "suspected leak/storm" (background LLDP/protocol learning has normal jitter)
_FDB_DELTA = 4
_NEIGH_DELTA = 4
# CONFIG_DB key prefixes that are "known benign residue / background rewrites" and unrelated to test contamination, excluded from the fingerprint:
#  - MGMT_VRF_CONFIG|vrf_global: after `config vrf del mgmt`, SONiC keeps this key but sets mgmtVrfEnabled=false
#    (= disabled state, functionally equivalent to the baseline's "no such key", affects no later test; no CLI to delete the key, and we do not write the DB directly).
_VOLATILE_PREFIXES = ("MGMT_VRF_CONFIG|vrf_global",)

_STATE = {"sh": None, "clean_cfg": None, "base_fdb": 0, "base_neigh": 0,
          "records": [], "heals": []}


def enabled():
    return _ON


def _keys(sh, db, pat):
    r = sh.run(f"sonic-db-cli {db} KEYS '{pat}'", check=False)
    return {l for l in (r.out or "").splitlines() if l
            and not any(l.startswith(p) for p in _VOLATILE_PREFIXES)}


# High-blast-radius singleton keys under field-level watch: these keys **persist** (the key-set
# fingerprint cannot see changes to their internals), but a single field written badly can fail the
# whole-database YANG validation -> collaterally breaking every full-validation config path like
# scheduler/bgp. HGETALL of these few keys per test is cheap.
_WATCHED_KEYS = ("NTP|global", "STP|GLOBAL", "DEVICE_METADATA|localhost",
                 "MGMT_VRF_CONFIG|vrf_global", "AAA|authentication")


def _watched(sh):
    out = {}
    for k in _WATCHED_KEYS:
        r = sh.run(f"sonic-db-cli CONFIG_DB HGETALL '{k}'", check=False)
        out[k] = (r.out or "").strip()
    return out


def _snapshot(sh):
    return {
        "cfg": _keys(sh, "CONFIG_DB", "*"),
        "fdb": len(_keys(sh, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*")),
        "neigh": len(_keys(sh, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:*")),
        "watched": _watched(sh),
    }


def capture_baseline(sh):
    """Session baseline: call once at the end of _suite_baseline's setup (after everything is settled, before any test)."""
    if not _ON:
        return
    snap = _snapshot(sh)
    _STATE["sh"] = sh
    _STATE["clean_cfg"] = snap["cfg"]
    _STATE["base_fdb"] = snap["fdb"]
    _STATE["base_neigh"] = snap["neigh"]
    _STATE["watch"] = snap["watched"]
    try:
        with open(_REPORT, "w") as f:
            f.write(json.dumps({"event": "baseline", "cfg_keys": len(snap["cfg"]),
                                "fdb": snap["fdb"], "neigh": snap["neigh"]}) + "\n")
    except OSError:
        pass


def check_after_test(nodeid):
    """Call after every test's teardown has fully run: compare -> attribute -> record -> roll the baseline forward."""
    if not _ON or _STATE["clean_cfg"] is None or _STATE["sh"] is None:
        return
    cur = _snapshot(_STATE["sh"])
    added = sorted(cur["cfg"] - _STATE["clean_cfg"])
    removed = sorted(_STATE["clean_cfg"] - cur["cfg"])
    dfdb = cur["fdb"] - _STATE["base_fdb"]
    dneigh = cur["neigh"] - _STATE["base_neigh"]
    # Field-level: watched key content differs from the previous baseline -> record the diff (roll forward, attribute the source once)
    prev_w = _STATE.get("watch") or {}
    wchanged = {k: {"was": prev_w.get(k, ""), "now": v}
                for k, v in cur["watched"].items() if v != prev_w.get(k, v)}
    _STATE["watch"] = cur["watched"]
    dirty = (bool(added or removed) or dfdb > _FDB_DELTA or dneigh > _NEIGH_DELTA
             or bool(wchanged))
    if dirty:
        rec = {"nodeid": nodeid, "added": added, "removed": removed,
               "fdb": cur["fdb"], "dfdb": dfdb, "neigh": cur["neigh"], "dneigh": dneigh}
        if wchanged:
            rec["watched_changed"] = wchanged
        _STATE["records"].append(rec)
        try:
            with open(_REPORT, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass
    # CONFIG_DB roll forward: a persistent leak is attributed to its source only once, not blamed on later tests
    _STATE["clean_cfg"] = cur["cfg"]


def record_heal(nodeid, ports):
    """The self-heal guard (_port_l2_baseline_guard) registers once each time it restores a batch of drifted ports -- both cleaning up and leaving a diagnostic
    ("which test left which ports in routed state"). Not gated by the FVT_SENTINEL switch: the guard
    itself is always active, and the healed record is always written (useful for tallying long-tail
    leak points after a full run)."""
    rec = {"event": "heal", "nodeid": nodeid, "ports": list(ports)}
    _STATE["heals"].append(rec)
    try:
        with open(_REPORT, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def summary_lines():
    """Brief report for pytest_terminal_summary."""
    out = []
    heals = _STATE["heals"]
    if heals:
        out.append(f"[sentinel] self-heal guard restored drifted ports in {len(heals)} test(s):")
        for h in heals:
            out.append(f"  {h['nodeid']}  ::  reset->L2 {h['ports']}")
    if not _ON:
        return out
    recs = _STATE["records"]
    if not recs:
        out.append("[sentinel] no cross-test state leaks detected (CONFIG_DB / dynamic FDB / neigh clean)")
        return out
    out.append(f"[sentinel] {len(recs)} test(s) left residual state (see {_REPORT}):")
    for r in recs:
        bits = []
        if r["added"]:
            bits.append(f"+cfg{r['added']}")
        if r["removed"]:
            bits.append(f"-cfg{r['removed']}")
        if r["dfdb"] > _FDB_DELTA:
            bits.append(f"fdb+{r['dfdb']}")
        if r["dneigh"] > _NEIGH_DELTA:
            bits.append(f"neigh+{r['dneigh']}")
        out.append(f"  {r['nodeid']}  ::  {'; '.join(bits)}")
    return out
