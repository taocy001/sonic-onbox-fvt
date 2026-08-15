"""BFD / VRRP: session/instance config programming. Session establishment/failover behavior needs a peer -> local loopback peer pending integration."""
import time

import pytest

pytestmark = [pytest.mark.scenario]


PEER = "10.91.1.2"


def test_bfd_static_peer_config(cli, config_guard, topo):
    """BFD peer config (FRR/bfdd): after configuring, the peer must actually register into FRR (`show bfd peers` lists it).

    In SONiC a static BFD peer can only go through bfdd via vtysh; there is no CONFIG_DB-only
    config entry. bfdd is off by default (standard SONiC by-design), so when the daemon is not
    running there is nothing to configure and no verifiable behavior, and session establishment
    needs a peer anyway. Hence honestly skip when the daemon is down (structurally untestable)."""
    if cli.is_switchport_os():
        # Product path: config always goes through the config command: `config bfd-peer-single-hop add
        # <dest> <interface> <vrf> -n <name> -s null` -> real CONFIG_DB value -> `show bfd peers`
        # renders -> del cleanly. Session Up needs a real peer; this case only verifies the config chain.
        port = topo.port_name("c")
        rc, r = cli.config_raw(
            f"bfd-peer-single-hop add {PEER} {port} default -n FVT_BFD1 -s null")
        if rc != 0:
            pytest.fail(f"DEVICE DEFECT: product BFD peer config rejected: "
                        f"{(r.err or r.out)[:200]}")
        config_guard.defer_undo(f"bfd-peer-single-hop del {PEER} {port} default")
        keys = [k for k in cli.db_keys("CONFIG_DB", "BFD_PEER_SINGLE_HOP*") if PEER in k]
        assert keys, f"BFD peer {PEER} not written to CONFIG_DB BFD_PEER_SINGLE_HOP"
        # Same strength as the community path: the peer must actually register into bfdd
        # (`show bfd peers` lists it). With no peer, a Down/AdminDown state is the *correct*
        # state -- its presence is a content check, one level stronger than "show didn't crash".
        out = ""
        deadline = time.time() + 10
        while time.time() < deadline:
            out = (cli.run("show bfd peers").out or "")
            assert "Traceback" not in out, "`show bfd peers` crashed"
            if PEER in out:
                break
            time.sleep(1.0)
        assert PEER in out, (
            f"BFD peer {PEER} written to CONFIG_DB but never registered in bfdd "
            f"(`show bfd peers` lacks it — programming chain broken): {out[-300:]}")
        # Negative closure: after an explicit del the peer should disappear from show output
        # (the guard's repeated del is an idempotent cleanup).
        cli.config_raw(f"bfd-peer-single-hop del {PEER} {port} default")
        deadline = time.time() + 10
        while time.time() < deadline:
            out = (cli.run("show bfd peers").out or "")
            if PEER not in out:
                break
            time.sleep(1.0)
        assert PEER not in out, \
            f"BFD peer {PEER} still present in `show bfd peers` after del (removal chain broken)"
        return

    _pre = cli.run("vtysh -c 'show bfd peers'")
    if "bfdd is not running" in (_pre.out + _pre.err):
        pytest.skip("bfdd not running (SONiC default; BFD has no CONFIG_DB-only path) "
                    "— nothing verifiable without the daemon; session establishment needs a peer")
    try:
        cli.vtysh(f"configure terminal\nbfd\n peer {PEER}\n", config=False)
    except Exception as e:  # noqa: BLE001
        # BFD config should have been accepted but errored -> fail to expose it
        pytest.fail(f"BFD config restricted: {e}")
    try:
        r = cli.run("vtysh -c 'show bfd peers'")
        out = r.out + r.err
        assert "Traceback" not in out, "show bfd peers crashed"
        # Verify the peer actually registered into bfdd (not just that show didn't crash)
        assert PEER in out, f"BFD peer {PEER} not registered in FRR: {out[-300:]}"
    finally:
        cli.vtysh(f"configure terminal\nbfd\n no peer {PEER}\n", config=False)

# test_vrrp_instance_config: removed per user instruction.

