"""Feature coverage report: read features.yaml, aggregate implemented/planned status by domain, print a matrix.

Usage: python3 -m catalog.coverage
"""
import os
from collections import defaultdict

import yaml

HERE = os.path.dirname(__file__)
CATALOG = os.path.join(HERE, "features.yaml")
ROOT = os.path.dirname(HERE)


def load():
    with open(CATALOG) as f:
        return yaml.safe_load(f)


def report():
    data = load()
    feats = data["features"]
    by_domain = defaultdict(list)
    for ft in feats:
        by_domain[ft["domain"]].append(ft)

    total = len(feats)
    impl = sum(1 for f in feats if f["status"] in ("implemented", "passing"))
    traffic = sum(1 for f in feats if f.get("traffic"))

    lines = []
    lines.append("=" * 72)
    lines.append(f"SONiC feature coverage matrix  (hwsku={data['meta']['hwsku']})")
    lines.append("=" * 72)
    for dom in sorted(by_domain):
        items = by_domain[dom]
        di = sum(1 for f in items if f["status"] in ("implemented", "passing"))
        lines.append(f"\n[{dom}]  {di}/{len(items)} implemented")
        for f in items:
            mark = {"implemented": "✓", "passing": "✓✓", "planned": "·",
                    "skipped": "s"}.get(f["status"], "?")
            pat = f.get("pattern") or "-"
            tr = "T" if f.get("traffic") else " "
            exists = "M" if os.path.exists(os.path.join(ROOT, f["module"])) else "-"
            lines.append(f"  {mark} [{tr}{exists} {pat:>1}] {f['id']:<28} {f['desc']}")
    lines.append("\n" + "-" * 72)
    lines.append(f"Total: {total} features | {impl} implemented | {traffic} traffic-involving | "
                 f"coverage {impl*100//total}%")
    lines.append("Legend: ✓=implemented ·=planned | T=traffic-involving M=module exists | A/B/C=verification mode")
    out = "\n".join(lines)
    print(out)
    with open(os.path.join(ROOT, "coverage_matrix.txt"), "w") as f:
        f.write(out + "\n")
    return out


if __name__ == "__main__":
    report()
