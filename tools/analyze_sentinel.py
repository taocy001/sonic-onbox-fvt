#!/usr/bin/env python3
"""Parse the contamination-sentinel jsonl -> classify leaks. Usage: analyze_sentinel.py <fvt_sentinel.jsonl>

Three categories:
  TRUE-LEAK    a CONFIG_DB key is added and never removed until the whole run ends
               persistent contamination that must be fixed (a test/fixture teardown did not
               clean up).
  CROSS-MODULE a key is added in module A but only removed in module B  the resource
               survives across modules, and tests outside its boundary run carrying it;
               this is implicit contamination (a module fixture leaking beyond its scope).
  BENIGN       added and removed within the same test_*.py file  a module-level fixture's
               normal lifecycle, harmless.

Also lists STORM: tests where dfdb / dneigh exceed a threshold (dynamic-learning-state leak /
suspected flood storm).
"""
import json
import sys
from collections import defaultdict


def _mod(nodeid):
    return nodeid.split("::", 1)[0]


def main(path):
    outstanding = {}          # key -> (creator_nodeid)
    events = []               # (nodeid, added[], removed[])
    storms = []
    order = []                # order in which keys first appear
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("event") == "baseline":
            print(f"baseline: {rec['cfg_keys']} cfg keys, fdb={rec['fdb']}, neigh={rec['neigh']}")
            continue
        nid = rec["nodeid"]
        added, removed = rec.get("added", []), rec.get("removed", [])
        events.append((nid, added, removed))
        for k in added:
            if k not in outstanding:
                outstanding[k] = nid
                order.append(k)
        if rec.get("dfdb", 0) > 4 or rec.get("dneigh", 0) > 4:
            storms.append((nid, rec.get("dfdb", 0), rec.get("dneigh", 0), rec.get("fdb"), rec.get("neigh")))

    # Replay, deciding whether each removal is benign (same module) or cross-module
    outstanding2 = {}
    cross = []
    benign = []
    for nid, added, removed in events:
        for k in added:
            outstanding2[k] = nid
        for k in removed:
            creator = outstanding2.pop(k, None)
            if creator is None:
                # Removed a key that existed in the baseline (a test deleted something not its own)  also counts as an anomaly
                cross.append((k, "<baseline-or-unknown>", nid, "removed-baseline-key"))
            elif _mod(creator) == _mod(nid):
                benign.append((k, creator, nid))
            else:
                cross.append((k, creator, nid, "cross-module"))
    true_leak = [(k, c) for k, c in outstanding2.items()]

    print(f"\n=== TRUE-LEAK (added, never removed until end) : {len(true_leak)} ===")
    for k, creator in sorted(true_leak, key=lambda x: x[1]):
        print(f"  {k:45s}  created by  {creator}")

    print(f"\n=== CROSS-MODULE (added in A, removed in B) : {len(cross)} ===")
    for row in cross:
        if len(row) == 4 and row[3] == "cross-module":
            k, c, r, _ = row
            print(f"  {k:40s}  {_mod(c)}  ->removed in->  {_mod(r)}")
        else:
            k, c, r, why = row
            print(f"  {k:40s}  {why}: removed by {r}")

    print(f"\n=== STORM (dfdb/dneigh > 4) : {len(storms)} ===")
    for nid, df, dn, f, n in storms:
        print(f"  {nid}  dfdb=+{df} (fdb={f})  dneigh=+{dn} (neigh={n})")

    print(f"\n=== BENIGN module-scoped churn : {len(benign)} keys (created+removed same file) ===")
    from collections import Counter
    for mod, cnt in Counter(_mod(c) for _, c, _ in benign).most_common():
        print(f"  {mod}: {cnt}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fvt_sentinel.jsonl")
