"""OSPF: v2/v3 + areas + redistribution (FRR vtysh config + show verification).

Adjacency/convergence verify config takes effect and the process accepts it; a real
adjacency (Full) needs a peer.

Why a single box cannot reach a real OSPF adjacency -> ASIC:
  1) On this image ospfd/ospf6d are not started by default (supervisor only runs
     bgpd/zebra/staticd/fpmsyncd); vtysh `router ospf` => "ospfd is not running".
  2) The peer must be a real OSPF speaker. Even with NET_ADMIN/SYS_ADMIN, the bgp
     container (where FRR lives, host-net) still fails `ip netns add`
     (mount --make-shared /run/netns: Permission denied, propagation is blocked),
     so a second isolated FRR cannot run inside the container as a peer; and the host
     side has no FRR binary => there is nowhere to put a peer.
  3) Even if the control plane brought up an adjacency over a veth, the OSPF route
     nexthop would land on the veth (not a SONiC front-panel RIF), orchagent cannot
     resolve it => nothing is programmed to the ASIC. (BGP works because NEXT_HOP is a
     decoupled attribute that can point at a real RIF; an OSPF nexthop is derived from
     SPF/the adjacency interface and cannot be decoupled.)
  4) Going through a front-panel port + MAC loopback => the DUT receives its own hello
     (router-id self-conflict) => the adjacency cannot come up either.
  So real-adjacency tests honestly skip on this single-box image (not "pending
  integration" — it is structurally unreachable).
"""
import time

import pytest

pytestmark = [pytest.mark.bgp]   # reuse the routing-protocol group; add an ospf marker if needed


def _poll_ospf_instance(cli, vtysh_show, product_show, rid, want, timeout=15):
    """Poll OSPF instance state: prefer a read-only vtysh query to FRR (authoritative;
    the framework allows vtysh to read state); when the host has no vtysh, fall back to
    content-checking the product show. want=True waits for the router-id to appear
    (config actually reached the daemon), want=False waits for it to disappear (the
    delete chain took effect). Returns (achieved, last output)."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        pr = cli.sh.run(f'vtysh -c "{vtysh_show}"', check=False)
        last = (pr.out or "") + (pr.err or "")
        if pr.rc == 127 or "not found" in last.lower():
            # no vtysh on the host side -> fall back to the instance content rendered by the product show
            last = (cli.run(f"show {product_show}").out or "")
            present = rid in last
        else:
            present = ("is not running" not in last) and (rid in last)
        if present == want:
            return True, last
        time.sleep(1.0)
    return False, last


def _ospf_daemon_up(cli, vtysh_show):
    """Probe whether ospfd/ospf6d is running: a vtysh show echoing `... is not running`
    means the daemon is down (note: SONiC has no top-level `show ip ospf` command; you
    must query FRR through vtysh)."""
    r = cli.sh.run(f'vtysh -c "{vtysh_show}"', check=False)
    return "is not running" not in (r.out + r.err)


def test_ospfv2_enable(cli, config_guard):
    """OSPFv2: verify FRR **actually accepts and renders** the config (running-config contains `router ospf` + network/area).

    On this image the supervisor only brings up bgpd/zebra/staticd/fpmsyncd, so
    **ospfd is not started by default** (`show ip ospf` => "ospfd is not running"); and
    in SONiC OSPF has no CONFIG_DB config entry point (it can only go through vtysh to
    ospfd), so with the daemon down it can neither be configured nor rendered —
    **there is no verifiable behavior that does not depend on the daemon**. ospfd being
    off by default is standard SONiC by-design (not a defect); a real adjacency/
    convergence needs a peer besides (see module docstring). So this single-box image
    honestly skips (structurally untestable, not a false pass and not a device defect)."""
    if cli.is_switchport_os():
        # Product path (user guidance): `config ospfv2 add <vrf> -ri <id>` + area network
        # -> real CONFIG_DB OSPFV2_ROUTER* values -> `show ospfv2` renders -> del cleanly.
        rc, r = cli.config_raw("ospfv2 add default -ri 10.9.9.2")
        if rc != 0:
            pytest.fail(f"product ospfv2 add rejected: {(r.err or r.out)[:200]}")
        config_guard.defer_undo("ospfv2 del default")
        keys = cli.db_keys("CONFIG_DB", "OSPFV2*")
        assert keys, "OSPFV2_ROUTER not written to CONFIG_DB after config ospfv2 add"
        out = (cli.run("show ospfv2").out or "")
        assert "Traceback" not in out, "`show ospfv2` crashed"
        # Upgrade: config must actually reach ospfd (content check: the instance carries
        # this test's router-id), not merely a CONFIG_DB echo + a non-crashing show — a
        # CONFIG_DB write does not mean the ospfmgr->ospfd programming chain is alive.
        ok, last = _poll_ospf_instance(cli, "show ip ospf", "ospfv2", "10.9.9.2", want=True)
        assert ok, ("config ospfv2 accepted (CONFIG_DB written) but router-id 10.9.9.2 never "
                    f"appeared in ospfd/`show ospfv2` — programming chain broken: {last[-300:]}")
        # Negative closed loop: after del the instance disappears (guard's repeated del is an idempotent cleanup)
        cli.config_raw("ospfv2 del default")
        ok, last = _poll_ospf_instance(cli, "show ip ospf", "ospfv2", "10.9.9.2", want=False)
        assert ok, f"ospfv2 instance still present after `config ospfv2 del`: {last[-300:]}"
        return
    if not _ospf_daemon_up(cli, "show ip ospf"):
        pytest.skip("ospfd not running (SONiC default; OSPF has no CONFIG_DB-only "
                    "path) — nothing verifiable without the daemon; adjacency needs a peer")
    # if ospfd is running, actually verify config rendering (keep the original verification path for images with ospfd enabled)
    cli.vtysh("configure terminal\nrouter ospf\n network 10.90.0.0/16 area 0\n", config=False)
    try:
        rc = cli.run("show ip ospf")
        assert "Traceback" not in (rc.out + rc.err), "show ip ospf crashed"
        run = cli.vtysh("show running-config", config=False)
        body = run if isinstance(run, str) else (getattr(run, "out", "") or "")
        assert "router ospf" in body, \
            f"FRR did not render 'router ospf': {body[:200]}"
        assert "10.90.0.0/16 area 0" in body or "area 0" in body, \
            f"FRR did not render configured network/area: {body[:300]}"
    finally:
        cli.vtysh("configure terminal\nno router ospf", config=False)


def test_ospfv3_enable(cli, config_guard):
    """OSPFv3: verify FRR actually accepts and renders `router ospf6`.

    Same as v2: on this image **ospf6d is not started by default** (`show ipv6 ospf6` =>
    "ospf6d is not running"), OSPFv3 has no CONFIG_DB config entry point, and with the
    daemon down there is no verifiable behavior -> honest skip (structurally untestable)."""
    if cli.is_switchport_os():
        rc, r = cli.config_raw("ospfv3 add default -ri 10.9.9.3")
        if rc != 0:
            pytest.fail(f"product ospfv3 add rejected: {(r.err or r.out)[:200]}")
        config_guard.defer_undo("ospfv3 del default")
        keys = cli.db_keys("CONFIG_DB", "OSPFV3*")
        assert keys, "OSPFV3 router not written to CONFIG_DB after config ospfv3 add"
        out = (cli.run("show ospfv3").out or "")
        assert "Traceback" not in out, "`show ospfv3` crashed"
        # Same as v2: config must actually reach ospf6d (router-id content check) + del negative closed loop
        ok, last = _poll_ospf_instance(cli, "show ipv6 ospf6", "ospfv3", "10.9.9.3", want=True)
        assert ok, ("config ospfv3 accepted (CONFIG_DB written) but router-id 10.9.9.3 never "
                    f"appeared in ospf6d/`show ospfv3` — programming chain broken: {last[-300:]}")
        cli.config_raw("ospfv3 del default")
        ok, last = _poll_ospf_instance(cli, "show ipv6 ospf6", "ospfv3", "10.9.9.3", want=False)
        assert ok, f"ospfv3 instance still present after `config ospfv3 del`: {last[-300:]}"
        return
    if not _ospf_daemon_up(cli, "show ipv6 ospf6"):
        pytest.skip("ospf6d not running (SONiC default; OSPFv3 has no CONFIG_DB-only "
                    "path) — nothing verifiable without the daemon; adjacency needs a peer")
    cli.vtysh("configure terminal\nrouter ospf6\n", config=False)
    try:
        r = cli.run("show ipv6 ospf6")
        assert "Traceback" not in (r.out + r.err), "show ipv6 ospf6 crashed"
        run = cli.vtysh("show running-config", config=False)
        body = run if isinstance(run, str) else (getattr(run, "out", "") or "")
        assert "router ospf6" in body, \
            f"FRR did not render 'router ospf6': {body[:200]}"
    finally:
        cli.vtysh("configure terminal\nno router ospf6", config=False)
