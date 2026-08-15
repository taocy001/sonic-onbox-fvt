"""LAG / PortChannel **chip-behavior + data-plane** cases (distinct from test_lag.py, which
only verifies CONFIG_DB/ASIC_DB programming).

Mechanism (reuses the L3 loopback traffic paradigm of test_l3_forward_traffic, no storm):
  - Create a PortChannel, add two physical ports as members (members enable MAC loopback to
    pull them up and make the chip TX counters readable).
  - Configure an L3 IP on the PortChannel + one static route (next hop in the PC subnet) + a
    static neighbor.
  - From a separate ingress port p_in (MAC loopback enabled), inject IP traffic "destined for
    the remote network, outer DMAC = router MAC"; the DUT routes it to the PortChannel -> the
    chip spreads different flows across different member ports by LAG hash.
  - Each member port's chip MIB_TPKT (TX) reflects the traffic share landing on that member.
  Note: with member MAC loopback on, the egress frame to the neighbor MAC (≠ router MAC)
  re-enters and is dropped at the L3 port, so there is no storm.

Real chip behavior verified:
  1) Members really enter the ASIC LAG (ASIC_DB LAG_MEMBER count grows + both members
     oper-up).
  2) Hash load-sharing: injecting many varying flows (varying L4 port / source IP) -> both
     member ports' chip TX are >0 (traffic truly spread across >1 member), summing to ≈ N with
     no storm.
  3) Single-flow affinity: one fixed-5-tuple flow should land on **only** one member (same
     hash bucket) -> only one member's TX grows.
  4) Member-down failover: after shutting one member, all traffic shifts to the surviving
     member (shut member TX≈0, surviving member TX≈N) == the LAG really did a data-plane
     failover redistribution.

Single-device limitation: MAC loopback cannot get LACP PortChannel members selected — a
member receives its own emitted LACPDU (actor system == partner system), and LACP correctly
judges it a self-loop and refuses to aggregate (selected=false) -> PC oper-down. **The three
data-plane cases hash/affinity/failover are a "single-box bench physical limitation" (need a
real LACP peer / traffic generator) and were deleted by test-scope decision, out of this
framework's capability**; this file keeps only the ASIC LAG member programming verification
test_lag_members_up_in_asic (unaffected by LACP selection).

Cleanup: teardown removes members / removes the PC, restores VLAN membership and MTU, disables
all loopbacks, and restores any shut ports.
"""
import time

import pytest

from framework.counters import ChipCounters

pytestmark = [pytest.mark.lag, pytest.mark.traffic]

PC = "PortChannel63"  # <=64: SONiC limits PortChannel suffix to 1-64, so this number is valid
_NH = "10.86.9.2"                 # next-hop IP (within the PC subnet)
_NH_MAC = "00:11:22:33:44:c1"     # next-hop neighbor MAC (egress DMAC rewrite target, ≠ router MAC -> re-entry dropped)
_PC_CIDR = "10.86.9.1/24"
_DST_NET = "10.249.0.0/24"
_DST_IP = "10.249.0.5"
@pytest.fixture
def lag_setup(cli, dut, _lb, topo):
    """Create PortChannel + two members (loopback on) + L3 IP/route/neighbor + ingress port.
    Returns a context dict. Members/ingress use the misc/L3 roles to avoid colliding with the
    traffic fixture's (a,b) traffic pair. Teardown reclaims everything."""
    topo.caps.require("loopback")
    dv = topo.default_vlan
    p_in = topo.l3_port(0)                          # ingress port (separate L3 domain)
    m1, m2 = topo.misc_port(0), topo.misc_port(1)   # two LAG members (misc domains g,h)
    members = [m1, m2]
    undo = []

    # --- ingress port: clear residue -> configure IP -> startup -> enable loopback ---
    from framework import hygiene
    hygiene.reset_port_to_l2(cli, _lb, dut, p_in, dv)
    cli.config_raw(f"vlan member del {dv} {p_in.name}")
    for _ in range(20):
        if not cli.db_keys("CONFIG_DB", f"VLAN_MEMBER|Vlan{dv}|{p_in.name}"):
            break
        time.sleep(0.3)
    cli.config_raw(f"interface ip add {p_in.name} 10.86.1.1/24")
    undo.append(f"interface ip remove {p_in.name} 10.86.1.1/24")
    cli.intf_startup(p_in.name)
    _lb.enable(p_in)

    # --- PortChannel ---
    cli.config_raw(f"portchannel add {PC}")
    undo.append(f"portchannel del {PC}")
    pc_mtu = (cli.db_hgetall("CONFIG_DB", f"PORTCHANNEL|{PC}") or {}).get("mtu", "9100")

    # --- members: match MTU -> move out of default VLAN -> join PC -> startup -> enable
    #     loopback to pull up ---
    for m in members:
        port_mtu = (cli.db_hgetall("CONFIG_DB", f"PORT|{m.name}") or {}).get("mtu", "9100")
        if port_mtu != pc_mtu:
            cli.config_raw(f"interface mtu {m.name} {pc_mtu}")
            undo.append(f"interface mtu {m.name} {port_mtu}")
        cli.config_raw(f"vlan member del {dv} {m.name}")
        undo.append(f"vlan member add -u {dv} {m.name}")
        rc, r = cli.config_raw(f"portchannel member add {PC} {m.name}")
        undo.append(f"portchannel member del {PC} {m.name}")
        if rc != 0:
            for c in reversed(undo):
                cli.config_raw(c)
            for p in [p_in] + members:
                _lb.disable(p)
            # Single-device capability: adding a physical port to a PortChannel should
            # succeed; failure is a config/programming defect -> surface as FAIL
            pytest.fail(f"DEVICE DEFECT: cannot add member {m.name} to {PC}: {r.err or r.out}")
        cli.intf_startup(m.name)
        _lb.enable(m)

    # --- PC L3 interface + route + neighbor (via SONiC/kernel) ---
    cli.config_raw(f"interface ip add {PC} {_PC_CIDR}")
    undo.append(f"interface ip remove {PC} {_PC_CIDR}")
    cli.intf_startup(PC)
    cli.neigh_set(_NH, _NH_MAC, PC)
    cli.sh.run(f"ip route replace {_DST_NET} via {_NH}", check=False)

    ctx = {"p_in": p_in, "members": members, "pc": PC}
    yield ctx

    # --- teardown ---
    cli.sh.run(f"ip route del {_DST_NET}", check=False)
    cli.neigh_del(_NH, PC)
    # safety net: restore any members shut by this class
    for m in members:
        cli.config_raw(f"interface startup {m.name}")
    for c in reversed(undo):
        cli.config_raw(c)
    for p in [p_in] + members:
        try:
            _lb.disable(p)
        except Exception:  # noqa: BLE001
            pass
    # reset the ingress port back to L2, leaving no RIF for the next case
    try:
        hygiene.reset_port_to_l2(cli, _lb, dut, p_in, dv)
    except Exception:  # noqa: BLE001
        pass


def _router_mac(cli):
    return cli.db_hgetall("CONFIG_DB", "DEVICE_METADATA|localhost").get("mac")


# ---------------------------------------------------------------------------

def test_lag_members_up_in_asic(cli, asicdb, dut, lag_setup):
    """Members really enter the ASIC LAG: **identity-level** assertion — each member port's
    port OID appears in some LAG_MEMBER's PORT_ID attribute, both members' LAG_ID point to the
    same LAG, and both member physical ports are oper-up. A global count >=2 can be falsely
    satisfied by a LAG left over from an earlier case, so we must verify "my ports are bonded
    into my LAG"."""
    members = lag_setup["members"]
    # ASIC_DB: LAG object exists
    assert asicdb.exists("ASIC_STATE:SAI_OBJECT_TYPE_LAG:*", timeout=10), \
        "LAG object not programmed to ASIC_DB"
    # Identity-level: find each member port's LAG_MEMBER by its port OID, and record which LAG
    # OID it belongs to
    port_oids = {}
    for m in members:
        oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {m.name}")
        assert oid, f"no COUNTERS_PORT_NAME_MAP oid for {m.name} (cannot identify member in ASIC)"
        port_oids[m.name] = oid
    lag_of = {}
    deadline = time.time() + 10
    while time.time() < deadline and len(lag_of) < len(members):
        for name, oid in port_oids.items():
            if name in lag_of:
                continue
            hits = asicdb.find("SAI_OBJECT_TYPE_LAG_MEMBER", SAI_LAG_MEMBER_ATTR_PORT_ID=oid)
            if hits:
                lag_of[name] = cli.db_hgetall("ASIC_DB", hits[0]).get("SAI_LAG_MEMBER_ATTR_LAG_ID")
        if len(lag_of) < len(members):
            time.sleep(0.5)
    missing = [m.name for m in members if m.name not in lag_of]
    assert not missing, \
        f"no LAG_MEMBER carries PORT_ID of {missing} in ASIC_DB (members not bonded in chip)"
    assert len(set(lag_of.values())) == 1, \
        f"members bonded into different chip LAGs (expected one PortChannel): {lag_of}"
    # both member physical ports oper-up (pulled up by loopback), so the LAG will select them
    # to egress traffic
    for m in members:
        up = False
        for _ in range(20):
            st = cli.db_hgetall("APPL_DB", f"PORT_TABLE:{m.name}").get("oper_status", "")
            if st == "up":
                up = True
                break
            time.sleep(0.5)
        assert up, f"LAG member {m.name} not oper-up; LAG cannot egress on it"
