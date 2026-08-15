"""Positively trigger the _BP_DELETED path.
Dynamically learn a MAC on a bridge port, then convert that port to routed (config interface link-mode route) -- SAI deleting the bridge port
flushes that port's FDB, and the FDB delete events from the flush arrive when the port's bdg_port==_BP_DELETED, hitting the suppression path.
Verify that syncd produces no "bug?" error logs under the suppression path.
"""
import time
import pytest

try:
    from scapy.all import Ether, IP, UDP, Raw  # noqa: F401
except ImportError:
    pass

pytestmark = [pytest.mark.l2, pytest.mark.traffic]

_SMAC = "00:de:ad:c3:00:01"
_DST = "00:aa:bb:c3:00:02"


def _asic_has_mac(cli, needle, timeout=10):
    end = time.time() + timeout
    nd = needle.replace(":", "").upper()
    while time.time() < end:
        for k in cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*"):
            if nd in k.upper() or needle.upper() in k.upper():
                return True
        time.sleep(1)
    return False


def test_c3_bp_deleted_suppress(cli, traffic, dut, _lb, topo, l2_fwd_vlan):
    p_in, p_out = traffic.ports[0], traffic.ports[1]
    vlan = l2_fwd_vlan
    # 1) dynamically learn _SMAC on p_in (real traffic)
    cli.fdb_static_add(vlan, _DST, p_out.name)
    learned = False
    try:
        pkt = Ether(dst=_DST, src=_SMAC) / IP() / UDP() / Raw(b"x" * 40)
        traffic.send(p_in, pkt, count=40)
        learned = _asic_has_mac(cli, _SMAC, timeout=12)
    finally:
        cli.fdb_static_del(vlan, _DST)
    if not learned:
        pytest.skip("could not dynamically learn seed MAC — cannot set up _BP_DELETED trigger")

    # 2) record baseline + mark syslog
    base_bug = int(cli.sh.run("grep -c 'bug?' /var/log/syslog", check=False).out.strip() or "0")
    cli.sh.run("logger CLAUDE_C3_BPDEL_START", check=False)

    # 3) convert p_in to routed -- delete bridge port -> flush that port's FDB -> delete events hit the _BP_DELETED suppression path
    cli.config_raw(f"interface link-mode {p_in.name} route")
    time.sleep(4)

    # 4) collect
    seg = cli.sh.run("awk '/CLAUDE_C3_BPDEL_START/{f=1} f' /var/log/syslog", check=False).out
    suppressed = "suppress notify for mac" in seg or "no bridge port/router vlan" in seg
    now_bug = int(cli.sh.run("grep -c 'bug?' /var/log/syslog", check=False).out.strip() or "0")
    new_bug = now_bug - base_bug

    print(f"C3 _BP_DELETED: seed_learned={learned} suppress_log={suppressed} new_bug?={new_bug}")
    # restore p_in back to bridge (the fixture also does this on teardown, belt and suspenders)
    cli.config_raw(f"interface link-mode {p_in.name} bridge")

    # the suppression path should produce no new "bug?" errors. A visible suppress_log is positive evidence.
    assert new_bug == 0, (
        f"syncd should suppress routed-port(_BP_DELETED) FDB delete events, but {new_bug} "
        f"'bug?' errors appeared in syncd — suppression not effective")
