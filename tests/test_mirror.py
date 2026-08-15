"""Mirror: SPAN / ERSPAN session creation -> CONFIG_DB / ASIC_DB.

span add positional args are <session_name> <dst_port> (source/direction are optional).
"""
import pytest

pytestmark = [pytest.mark.mirror]

SPAN = "span_dut"
ERSPAN = "erspan_dut"


def test_span_session_create(cli, asicdb, topo, config_guard):
    """Local SPAN session: config-plane contract (CONFIG_DB) + **data-plane check: programmed into ASIC SAI_MIRROR_SESSION**.

    SPAN is local port mirroring and can be programmed into the ASIC (unlike ACL-based ERSPAN). Verifies the config
    is accepted + orchagent->SAI actually programs a mirror session object. Capturing the mirrored copy content
    (egress frames to the dst port) is deferred to batch-2 traffic generation."""
    dst = topo.port_name("c")
    vid = topo.default_vlan
    # The destination port cannot be a VLAN member. On the modified OS (SONiC): the mirror destination port must be in
    # **route mode** — when an access/bridge port is used as dst the session is not programmed into the ASIC (and an
    # access port forbids vlan member del to leave Vlan1), so use restore_port_l3 to switch to route; community mirror
    # just moves it out of the VLAN.
    if cli.is_switchport_os():
        cli.restore_port_l3(dst)
    else:
        cli.config_raw(f"vlan member del {vid} {dst}")
        config_guard.defer_undo(f"vlan member add -u {vid} {dst}")
    base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*")
    rc, r = cli.config_raw(f"mirror_session span add {SPAN} {dst}")
    config_guard.defer_undo(f"mirror_session remove {SPAN}")
    assert rc == 0, f"failed to create SPAN: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"MIRROR_SESSION|{SPAN}"), "no MIRROR_SESSION in CONFIG_DB"
    # data-plane: local SPAN should actually be programmed into the ASIC (SAI_MIRROR_SESSION count grows)
    assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*", base, timeout=8), \
        "local SPAN session not programmed to ASIC (no new SAI_MIRROR_SESSION)"


def test_erspan_session_create(cli, asicdb, config_guard, topo):
    """ERSPAN: encapsulate to remote <name> <src_ip> <dst_ip> <dscp> <ttl> <gre> <queue>.

    Real data-plane check: ERSPAN should create a mirror session in the ASIC (with GRE/tunnel) to actually encapsulate.
    orchagent only attaches the session to the ASIC when the collector (dst_ip) **route is resolvable** — otherwise the
    session stays "inactive" in CONFIG_DB and the ASIC never produces the object (not a device defect, just a missing
    prerequisite route/neighbor). So first, following test_erspan_traffic's LocalPeerIP recipe, make the collector IP
    locally reachable (dummy interface + static neighbor), then assert the ASIC session is programmed. If it takes the
    ACL path and is not programmed into the ASIC -> the ASIC assertion truly fails -> FAIL (binary exposure, not masked
    with xfail)."""
    from topo.virtual_link import LocalPeerIP

    net = topo.subnet("erspan")
    src_ip, collector_ip = net["dut"], net["peer"]
    # prerequisite: make the collector IP locally reachable so orchagent can resolve the nexthop and attach the session to the ASIC
    if not cli.has_erspan_cli():
        pytest.skip("ERSPAN session CLI not shipped on this image "
                    "(config mirror_session has only span/del) — structurally untestable")
    peer = LocalPeerIP(cli, collector_ip)
    peer.setup()
    try:
        base = asicdb.count("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*")
        rc, r = cli.config_raw(
            f"mirror_session erspan add {ERSPAN} {src_ip} {collector_ip} 8 100 0 0")
        config_guard.defer_undo(f"mirror_session remove {ERSPAN}")
        assert rc == 0, f"failed to create ERSPAN: {r.err or r.out}"
        assert cli.db_keys("CONFIG_DB", f"MIRROR_SESSION|{ERSPAN}"), "no MIRROR_SESSION in CONFIG_DB"
        # data-plane: ERSPAN must be programmed into the ASIC to actually encapsulate (truly FAILs and exposes if not programmed)
        assert asicdb.wait_count_gt("ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*", base, timeout=8), \
            "ERSPAN session not programmed to ASIC (ACL-based ERSPAN not programmed)"
    finally:
        peer.teardown()
