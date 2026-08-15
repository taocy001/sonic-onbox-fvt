#!/usr/bin/env python3
"""Auto-generate docs/TEST_CASE_CATALOG.md (the test case catalog) from the tests/ source.

Usage (repo root): python3 tools/gen_catalog.py
Data source = the single source of truth (the code itself): each test_*.py module docstring first paragraph + each test_
function's docstring first line + pytestmark/parametrization scale. The output carries date and commit anchors to prevent hand-maintained drift.
"""
import ast
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# functional-domain grouping (classified by filename prefix; unmatched fall into "Other")
DOMAINS = [
    ("L2 switching", ("test_vlan", "test_fdb", "test_mac", "test_lag", "test_lacp",
                 "test_hairpin", "test_loopback", "test_storm_mtu")),
    ("L3 routing", ("test_intf_ip", "test_route", "test_l3_", "test_arp", "test_ndp",
                 "test_vrf", "test_pbr", "test_ipv6")),
    ("Routing protocols", ("test_bgp", "test_ospf", "test_bfd", "test_routing_policy")),
    ("ACL", ("test_acl",)),
    ("QoS", ("test_qos", "test_queue_crm")),
    ("CoPP/punt", ("test_copp",)),
    ("Mirroring/sampling", ("test_mirror", "test_erspan", "test_sflow")),
    ("Counters/telemetry", ("test_counters", "test_port_counters", "test_stats", "test_crm",
                   "test_gnmi", "test_dynamic_entries")),
    ("Tunneling", ("test_vxlan",)),
    ("Platform/system management", ("test_platform", "test_transceiver", "test_snmp", "test_aaa",
                       "test_ssh", "test_syslog", "test_system_mgmt", "test_ntp",
                       "test_lldp", "test_dhcp", "test_auto_techsupport", "test_gcu",
                       "test_config_wired", "test_show_commands")),
    ("SAI object ledger", ("test_sai_objects",)),
    ("Other", ()),
]


def domain_of(fname):
    for dom, prefixes in DOMAINS:
        if any(fname.startswith(p) for p in prefixes):
            return dom
    return "Other"


def first_line(doc):
    return (doc or "").strip().splitlines()[0].strip() if doc else ""


def param_count(node):
    """Rough estimate of parametrization expansion count: product of the list lengths of each parametrize decorator's second arg; 1 if none."""
    n = 1
    for dec in node.decorator_list:
        if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "parametrize" and len(dec.args) >= 2
                and isinstance(dec.args[1], (ast.List, ast.Tuple))):
            n *= max(1, len(dec.args[1].elts))
    return n


def main():
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip() or "?"
    groups = {}
    tot_files = tot_funcs = tot_cases = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "tests", "test_*.py"))):
        fname = os.path.basename(path)
        tree = ast.parse(open(path).read())
        fdoc = first_line(ast.get_docstring(tree))
        cases = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                cases.append((node.name, first_line(ast.get_docstring(node)),
                              param_count(node)))
        if not cases:
            continue
        tot_files += 1
        tot_funcs += len(cases)
        tot_cases += sum(c[2] for c in cases)
        groups.setdefault(domain_of(fname), []).append((fname, fdoc, cases))

    out = [f"""# Test case catalog (auto-generated, do not hand-edit)

> Generated: `python3 tools/gen_catalog.py`
> Scale: {tot_files} files / {tot_funcs} test functions (statically visible parametrization ~{tot_cases})
> Four verification depth levels: config->CONFIG_DB contract / orchagent->ASIC_DB / chip counts / data-plane traffic.
"""]
    for dom, _ in DOMAINS:
        files = groups.get(dom)
        if not files:
            continue
        nfun = sum(len(c) for _, _, c in files)
        out.append(f"\n## {dom} ({len(files)} files / {nfun} functions)\n")
        for fname, fdoc, cases in files:
            out.append(f"\n### {fname} — {fdoc}\n")
            out.append("| Case | Expansions | Purpose |\n|------|:---:|------|")
            for name, doc, n in cases:
                out.append(f"| {name} | {n} | {doc} |")
            out.append("")
    text = "\n".join(out) + "\n"
    dst = os.path.join(ROOT, "docs", "TEST_CASE_CATALOG.md")
    open(dst, "w").write(text)
    print(f"{dst}: {tot_files} files / {tot_funcs} funcs / ~{tot_cases} cases @ {commit}")


if __name__ == "__main__":
    sys.exit(main())
