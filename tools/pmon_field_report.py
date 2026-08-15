#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""On-device pmon fault field-test report generator (runs on the DUT itself).

For each scenario reproducible on real hardware:
  1) record the pre-injection baseline (the three show commands + daemon states + cache age);
  2) inject the fault via the mock BMC, sampling repeatedly at T+30s / T+60s / T+300s;
  3) revoke the injection, sample again at T+30s / T+60s / T+300s, and from that decide [whether it
     auto-recovers] (recovered = back to baseline without restarting pmon; otherwise record "pmon restart required");
  4) capture the raw show output at every point for manual review.

Produces /tmp/PMON_FIELD_REPORT_<host>.md. Because the real BMC is slow and SSH/daemon timing adds up,
a full run takes a while; use --only to pick scenarios and --quick to shorten observation points for a smoke test.

Usage (on the DUT, as root):
    sudo python3 tools/pmon_field_report.py                 # all reproducible scenarios
    sudo python3 tools/pmon_field_report.py --only b2,s5    # specific scenarios
    sudo python3 tools/pmon_field_report.py --quick         # observation points only 30/60s
"""
import argparse
import datetime
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework import shell                                  # noqa: E402
from framework.pmon_fault import (BmcRedirect, PmonCtl, PlatformState,  # noqa: E402
                                  SYNC_UNIT, PMON_DAEMONS)
from servers.mock_bmc import MockBmc                          # noqa: E402

OBSERVE = [("T+30s", 30), ("T+60s", 60), ("T+300s", 300)]
OBSERVE_QUICK = [("T+30s", 30), ("T+60s", 60)]


class Ctx:
    def __init__(self, quick=False):
        self.sh = shell.Shell(dry_run=False)
        self.ctl = PmonCtl(self.sh)
        self.state = PlatformState(self.sh)
        self.mock = MockBmc()
        self.redirect = BmcRedirect(self.sh, self.mock.port)
        self.observe = OBSERVE_QUICK if quick else OBSERVE
        self.baselined = False

    def ensure_mock(self):
        if not self.baselined:
            ok = (self.mock.snapshot_from_cache(self.state.read_cache())
                  or self.mock.snapshot_from_real())
            if not ok:
                return False
            self.mock.start()
            self.redirect.mock_port = self.mock.port
            self.baselined = True
        return True


# ------------------------- observation -------------------------

def snapshot(ctx):
    """A complete observation at one point in time (user view + internal state)."""
    states = ctx.ctl.supervisor_states()
    age = ctx.state.cache_age_s() if ctx.state.has_cache_arch() else None
    return {
        "clock": datetime.datetime.now().strftime("%H:%M:%S"),
        "daemons": " ".join("%s=%s" % (d, states.get(d, "?"))
                            for d in PMON_DAEMONS),
        "cache_age": age,
        "sync_alive": ctx.ctl.sync_proc_alive(),
        "psustatus": ctx.state.show("psustatus"),
        "fan": ctx.state.show("fan"),
        "temperature": ctx.state.show("temperature"),
        "psu_blank": ctx.state.psu_detail_blank(),
    }


def observe_series(ctx, points):
    """Starting from now, sample once at each given observation point (cumulative wait relative to the start)."""
    series = {}
    start = time.time()
    for label, t in points:
        wait = t - (time.time() - start)
        if wait > 0:
            time.sleep(wait)
        series[label] = snapshot(ctx)
    return series


def recovered(base, snap):
    """Whether the current observation is back to baseline health (daemons equally alive, cache fresh, no fallback blanks)."""
    if snap["psu_blank"] and not base["psu_blank"]:
        return False
    if snap["cache_age"] is not None and snap["cache_age"] > 120:
        return False
    if not snap["sync_alive"] and base["sync_alive"]:
        return False
    base_dead = {d for d in PMON_DAEMONS if "=FATAL" in base["daemons"]
                 and d in base["daemons"]}
    for d in PMON_DAEMONS:
        if ("%s=FATAL" % d in snap["daemons"] or "%s=EXITED" % d in snap["daemons"]) \
                and ("%s=FATAL" % d not in base["daemons"]):
            return False
    return True


# ------------------------- scenarios -------------------------

def sc_baseline(ctx):
    """Baseline: the device's current real state (no injection). Directly reflects whether the field device is already in a defective state."""
    base = snapshot(ctx)
    return {"inject": None, "base": base, "inject_series": {},
            "recover_series": {}, "auto_recover": None,
            "note": "field baseline snapshot (no injection)"}


def _run_bmc_behavior(ctx, mode_setter, desc):
    """Group B: BMC behavior fault -> observe sync daemon survival and cache supply cutoff, then recovery after revocation."""
    ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    ctx.state.wait_cache_fresh()
    base = snapshot(ctx)
    mode_setter()
    ctx.redirect.to_mock()
    inj = observe_series(ctx, ctx.observe)
    # revoke
    ctx.mock.reset()
    ctx.redirect.restore()
    ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    rec = observe_series(ctx, ctx.observe)
    auto = recovered(base, rec[ctx.observe[-1][0]])
    return {"inject": desc, "base": base, "inject_series": inj,
            "recover_series": rec, "auto_recover": auto,
            "note": "whether it auto-recovers after revoking the injection and restarting the sync daemon"}


def sc_b1_refuse(ctx):
    def setter():
        ctx.redirect.refuse()
    ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    ctx.state.wait_cache_fresh()
    base = snapshot(ctx)
    setter()
    inj = observe_series(ctx, ctx.observe)
    ctx.redirect.restore()
    ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    rec = observe_series(ctx, ctx.observe)
    auto = recovered(base, rec[ctx.observe[-1][0]])
    return {"inject": "BMC connection refused (iptables REJECT 240.1.1.1:8080)",
            "base": base, "inject_series": inj, "recover_series": rec,
            "auto_recover": auto,
            "note": "whether the sync daemon survives BMC connection refusal, and self-heals after revocation"}


def sc_b2_malformed(ctx):
    if not ctx.ensure_mock():
        return {"skip": "cannot baseline mock BMC"}
    return _run_bmc_behavior(ctx, lambda: ctx.mock.set_mode("malformed"),
                             "BMC returns bad JSON (mock malformed)")


def sc_s5_sentinel(ctx):
    if not ctx.ensure_mock():
        return {"skip": "cannot baseline mock BMC"}
    if ctx.state.psu_detail_blank():
        return {"skip": "psud is already in the 1.0 fallback state (pre-existing field defect); cannot isolate the sentinel injection"}
    base = snapshot(ctx)
    ctx.mock.set_psu_field("PSU1", ["Outputs", "Voltage", "Value"], -99999)
    ctx.redirect.to_mock()
    inj = observe_series(ctx, ctx.observe)
    ctx.mock.reset()
    ctx.redirect.restore()
    ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    rec = observe_series(ctx, ctx.observe)
    auto = recovered(base, rec[ctx.observe[-1][0]])
    return {"inject": "PSU1 voltage sentinel -99999 (mock)", "base": base,
            "inject_series": inj, "recover_series": rec, "auto_recover": auto,
            "note": "whether the sentinel value displays as 0.0 (should be N/A), and self-heals after revocation"}


def sc_s9_sensor_vanish(ctx):
    if not ctx.ensure_mock():
        return {"skip": "cannot baseline mock BMC"}
    if "thermalctld=FATAL" in snapshot(ctx)["daemons"]:
        return {"skip": "thermalctld is already FATAL (pre-existing field defect); cannot isolate the runtime key-drop injection"}
    base = snapshot(ctx)
    ctx.mock.drop_sensor("OcmBoard")
    ctx.redirect.to_mock()
    inj = observe_series(ctx, ctx.observe)
    ctx.mock.reset()
    ctx.redirect.restore()
    ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)
    rec = observe_series(ctx, ctx.observe)
    auto = recovered(base, rec[ctx.observe[-1][0]])
    return {"inject": "stop reporting the OcmBoard sensor at runtime (mock)", "base": base,
            "inject_series": inj, "recover_series": rec, "auto_recover": auto,
            "note": "whether that temperature row freezes into stale data, and self-heals after revocation"}


SCENARIOS = [
    ("baseline", "field baseline (no injection)", sc_baseline),
    ("b1", "BMC connection refused -> sync daemon survival", sc_b1_refuse),
    ("b2", "BMC bad JSON -> sync daemon survival", sc_b2_malformed),
    ("s5", "PSU sentinel voltage -> displays 0.0 vs N/A", sc_s5_sentinel),
    ("s9", "runtime sensor key-drop -> temperature row freezes", sc_s9_sensor_vanish),
]


# ------------------------- rendering -------------------------

def fence(snap):
    return ("```\n$ show platform psustatus\n%s\n\n"
            "$ show platform fan\n%s\n\n"
            "$ show platform temperature\n%s\n```"
            % (snap["psustatus"].rstrip(), snap["fan"].rstrip(),
               snap["temperature"].rstrip()))


def status_line(snap):
    return ("daemons: %s | sync daemon alive: %s | cache age: %ss | PSU detail blank: %s"
            % (snap["daemons"], "yes" if snap["sync_alive"] else "no",
               snap["cache_age"], snap["psu_blank"] or "none"))


def render(host, results):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = ["# pmon fault device field-test report (%s)\n" % host,
           "> Generated: %s | Method: `sudo python3 tools/pmon_field_report.py`\n"
           "> Scope: on-device real mock BMC injection -> real sync daemon -> real cache -> real psud/"
           "thermalctld -> real `show platform`. Each scenario is sampled repeatedly at "
           "T+30s/T+60s/T+300s after injection and after revocation; the last sample decides whether it can "
           "**auto-recover** (back to baseline without restarting pmon).\n" % now]
    for key, title, _fn in SCENARIOS:
        r = results.get(key)
        if r is None:
            continue
        out.append("## %s\n" % title)
        if r.get("skip"):
            out.append("- **Result**: skipped -- %s\n" % r["skip"])
            continue
        if r.get("inject"):
            out.append("- **Injection method**: %s" % r["inject"])
        if r.get("note"):
            out.append("- **Observation goal**: %s" % r["note"])
        if r.get("auto_recover") is not None:
            out.append("- **Auto-recovers**: %s"
                       % ("✅ yes (back to baseline without restarting pmon after revocation)"
                          if r["auto_recover"]
                          else "🔴 no (still not back to baseline after revocation, pmon restart required)"))
        out.append("")
        if r.get("base"):
            out.append("### Baseline (pre-injection)\n")
            out.append("- %s\n" % status_line(r["base"]))
            out.append(fence(r["base"]) + "\n")
        order = [lbl for lbl, _t in OBSERVE]
        for phase, series in (("After injection", r.get("inject_series") or {}),
                              ("After revocation", r.get("recover_series") or {})):
            for label in sorted(series, key=lambda l: order.index(l)
                                if l in order else 99):
                s = series[label]
                out.append("### %s %s (%s)\n" % (phase, label, s["clock"]))
                out.append("- %s\n" % status_line(s))
                out.append(fence(s) + "\n")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    ctx = Ctx(quick=args.quick)
    only = set(x.strip() for x in args.only.split(",") if x.strip())
    host = socket.gethostname()

    results = {}
    entry = ctx.state.baseline_problems()
    print("entry baseline problems: %s" % entry)
    try:
        for key, title, fn in SCENARIOS:
            if only and key not in only:
                continue
            print("=== scenario %s ..." % key)
            try:
                results[key] = fn(ctx)
            except Exception as e:  # noqa: BLE001
                results[key] = {"skip": "execution error: %r" % e}
            # after each scenario, make sure the redirect is undone
            try:
                ctx.redirect.restore()
            except Exception:  # noqa: BLE001
                pass
    finally:
        try:
            ctx.mock.stop()
        except Exception:  # noqa: BLE001
            pass
        ctx.sh.run("sudo systemctl restart %s" % SYNC_UNIT)

    path = "/tmp/PMON_FIELD_REPORT_%s.md" % host
    with open(path, "w") as f:
        f.write(render(host, results))
    print("written: %s" % path)
    left = [p for p in ctx.state.baseline_problems() if p not in entry]
    print("exit baseline delta: %s" % (left or "none (device not left worse)"))


if __name__ == "__main__":
    main()
