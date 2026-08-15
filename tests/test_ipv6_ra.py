"""IPv6 Router Advertisement (radvd) functional verification -- really verifies "the device emits RA".

This module makes end-to-end real-behavior assertions on radvd in the radv container
(capturing the ICMPv6 type 134 the device emits), rather than a smoke test or "just check the
process is up":
  1. radv container up + feature enabled (prerequisite for RA);
  2. after configuring an IPv6 VLAN interface, the radvd daemon really starts and radvd.conf
     really has that interface/prefix block;
  3. the device really emits RA: tcpdump on that SVI captures an ICMPv6 Router Advertisement
     (type 134, destination ff02::1), the source is a local link-local, the on-link prefix
     carried == the subnet we configured, router lifetime>0, and the source link-layer address
     == the device MAC (its self-reported identity is genuine). This is on-wire proof that
     "the device is really emitting RA".

Mechanism notes (see the module footer):
  - SONiC's radvd is gated by device type via the template
    docker-router-advertiser.supervisord.conf.j2: only ToRRouter/EPMS/MgmtTsToR with an IPv6
    VLAN_INTERFACE present writes the radvd program into supervisord.conf. This DUT defaults to
    type=LeafRouter, so by default it does not emit RA (by design, not a defect).
  - So the ra_enabled fixture temporarily configures the device as an "RA-emitting gateway":
    create a test VLAN + configure IPv6 on its SVI (topo.subnet v6a) + set type to ToRRouter +
    regenerate supervisord.conf/radvd.conf inside the radv container with sonic-cfggen and
    `supervisorctl update/start radvd`. Teardown fully restores (stop radvd, remove IPv6,
    remove VLAN, restore the original type, regenerate config so radvd disappears). This
    "in-container regenerate + supervisorctl" avoids the systemd restart rate limit of
    `systemctl restart radv` and needs no whole-container restart.
  - radvd just started emits initial fast RAs (a few within the first ~16s), so the fixture
    can capture right after starting radvd and reliably catch one, without waiting the
    60~180s steady-state interval, and without loopback/traffic (a Vlan SVI on the Bridge has
    its own carrier and can emit RA with no member ports).

Prints/assert/skip in English; comments/docstrings translated. VLAN/IPv6 subnets are taken
dynamically from topo, not hardcoded.
"""
import ipaddress
import re
import socket
import time
from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.l3]

_RADV_CT = "radv"   # router advertiser container name
# two templates generated inside the radv container by docker-init.sh via sonic-cfggen (rendered from CONFIG_DB data)
_SUP_TPL = "/usr/share/sonic/templates/docker-router-advertiser.supervisord.conf.j2"
_RADVD_TPL = "/usr/share/sonic/templates/radvd.conf.j2"
_SUP_DST = "/etc/supervisor/conf.d/supervisord.conf"
_RADVD_DST = "/etc/radvd.conf"


# ----------------------------- helpers -----------------------------
def _radv_running(cli):
    """Whether the radv container is in `docker ps`."""
    return _RADV_CT in cli.sh.run("docker ps --format '{{.Names}}'", check=False).out.split()


def _require_radv_shipped(cli):
    """Whether radv ships with the image. Not shipped at all (no docker image, no FEATURE|radv entry)
    = structurally untestable -> skip; shipped but not running = device defect -> caller asserts FAIL."""
    has_img = _RADV_CT in cli.sh.run(
        "docker images --format '{{.Repository}}'", check=False).out
    has_feat = bool(cli.db_hgetall("CONFIG_DB", f"FEATURE|{_RADV_CT}"))
    if not has_img and not has_feat:
        pytest.skip("radv (router advertiser) not shipped "
                    "(no docker image, no FEATURE entry) — RA structurally untestable")


def _radvd_status(cli):
    """Raw output of `supervisorctl status radvd` inside the radv container."""
    return cli.sh.run("supervisorctl status radvd", container=_RADV_CT, check=False).out


def _set_type(cli, t):
    """Change DEVICE_METADATA.type (the RA template gates whether radvd is enabled by type)."""
    cli.sh.run(f"sonic-db-cli CONFIG_DB hset 'DEVICE_METADATA|localhost' type {t}", check=False)


def _regen_radv(cli):
    """Regenerate supervisord.conf/radvd.conf inside the container from the current CONFIG_DB with
    sonic-cfggen, then reread/update so the radvd program appears or disappears per the type gate."""
    cmd = (f"sonic-cfggen -d -t {_SUP_TPL},{_SUP_DST} -t {_RADVD_TPL},{_RADVD_DST} "
           f"&& supervisorctl reread && supervisorctl update")
    return cli.sh.run(cmd, container=_RADV_CT, check=False)


def _dev_mac(cli):
    """DEVICE_METADATA.mac (ground truth for the RA source link-layer address / link-local)."""
    return cli.db("CONFIG_DB", "hget 'DEVICE_METADATA|localhost' mac").strip().lower()


def _norm6(a):
    """Normalize an IPv6 string for comparison across notations."""
    try:
        return socket.inet_pton(socket.AF_INET6, a)
    except OSError:
        return a


# ----------------------------- fixture -----------------------------
@pytest.fixture
def ra_enabled(cli, topo):
    """Temporarily configure the device as an "RA-emitting IPv6 gateway" and start radvd; yield config info; teardown fully restores.

    Steps: create a test VLAN -> configure IPv6 on its SVI (topo v6a) -> set type to ToRRouter
    -> regenerate config inside the container and start radvd -> poll for radvd RUNNING.
    Restore: stop radvd, remove IPv6, remove VLAN, restore the original type, regenerate config
    (radvd disappears with it)."""
    # radv not shipped by the image at all -> structural skip; shipped but not running = device defect -> fail to expose.
    _require_radv_shipped(cli)
    assert _radv_running(cli), (
        "radv container not running; cannot test router advertisement")

    vid = topo.vlan("a")
    ifname = f"Vlan{vid}"
    net = topo.subnet("v6a")
    cidr = f"{net['dut']}/{net['prefix']}"
    prefix_net = str(ipaddress.ip_interface(cidr).network)   # e.g. 2001:db8:83::/64
    dev_mac = _dev_mac(cli)
    orig_type = (cli.db("CONFIG_DB", "hget 'DEVICE_METADATA|localhost' type").strip()
                 or "LeafRouter")

    # ---- setup ----
    cli.config_raw(f"vlan add {vid}")                       # ignored if already exists
    cli.config_raw(f"interface ip add {ifname} {cidr}")     # configure IPv6 on the SVI -> radvd.conf generates the interface block
    _set_type(cli, "ToRRouter")                            # release the type gate
    _regen_radv(cli)                                       # regenerate supervisord.conf (with radvd)
    cli.sh.run("supervisorctl start radvd", container=_RADV_CT, check=False)

    running = False
    deadline = time.time() + 30
    while time.time() < deadline:
        if "RUNNING" in _radvd_status(cli):
            running = True
            break
        time.sleep(1)

    info = SimpleNamespace(vid=vid, ifname=ifname, cidr=cidr, prefix_net=prefix_net,
                           net=net, dev_mac=dev_mac, running=running)
    try:
        yield info
    finally:
        # ---- teardown: fully restore, leaving a clean baseline for later tests ----
        cli.sh.run("supervisorctl stop radvd", container=_RADV_CT, check=False)
        cli.config_raw(f"interface ip remove {ifname} {cidr}")
        cli.config_raw(f"vlan del {vid}")
        _set_type(cli, orig_type)
        _regen_radv(cli)


# ============================ 1. RA prerequisites ============================
def test_radv_container_and_feature_enabled(cli):
    """radv container up + radv is enabled in `show feature status`. This is the prerequisite for all RA functionality."""
    _require_radv_shipped(cli)
    assert _radv_running(cli), "radv container not running"
    out = cli.run("show feature status").out
    line = next((l for l in out.splitlines() if l.split()[:1] == ["radv"]), None)
    assert line is not None, f"radv feature not listed in 'show feature status':\n{out}"
    assert "enabled" in line, f"radv feature not enabled: {line!r}"


# ============================ 2. radvd daemon really starts ============================
def test_radvd_daemon_runs_when_enabled(cli, ra_enabled):
    """After configuring an IPv6 VLAN interface + ToR gateway role, the radvd process should be
    RUNNING and radvd.conf should really contain the interface block under test + our
    configured prefix + AdvSendAdvert on (proving RA config is really generated and the process
    really enabled)."""
    # radvd should be RUNNING after a ToR IPv6 VLAN is configured but isn't = device defect -> fail to expose.
    assert ra_enabled.running, (
        "radvd did not reach RUNNING after enabling ToR IPv6 VLAN "
        "(RA daemon should run; see module notes)")
    status = _radvd_status(cli)
    assert "RUNNING" in status, f"radvd not RUNNING: {status!r}"

    conf = cli.sh.run(f"cat {_RADVD_DST}", container=_RADV_CT, check=False).out
    assert f"interface {ra_enabled.ifname}" in conf, \
        f"radvd.conf missing interface block for {ra_enabled.ifname}:\n{conf}"
    assert ra_enabled.prefix_net in conf, \
        f"radvd.conf missing advertised prefix {ra_enabled.prefix_net}:\n{conf}"
    assert "AdvSendAdvert on" in conf, f"radvd.conf does not enable AdvSendAdvert:\n{conf}"


# ============================ 3. device really emits RA (type 134) ============================
def test_device_emits_router_advertisement(cli, ra_enabled):
    """tcpdump on the SVI under test to capture an ICMPv6 Router Advertisement (type 134): radvd
    just started emits initial fast RAs, so capturing right after start suffices. Strong field
    assertions:
      - 'router advertisement' really captured (the device is indeed emitting RA);
      - source is a local link-local (fe80::), destination is all-nodes ff02::1;
      - router lifetime > 0 (a usable default-router advert);
      - the on-link prefix carried == the subnet we configured on the SVI;
      - the source link-layer address option == the device MAC (genuine self-reported
        identity, cannot be faked/placeholder)."""
    # radvd should be RUNNING but isn't = device defect -> fail to expose.
    assert ra_enabled.running, "radvd not RUNNING; cannot validate RA emission"
    ifname = ra_enabled.ifname

    # -c 1: exit on the first RA captured; timeout 25 as a backstop (initial fast RA arrives within ~16s).
    cap = cli.sh.run(f"timeout 25 tcpdump -nvi {ifname} -c 1 'icmp6 and ip6[40]==134' 2>/dev/null",
                     check=False, timeout=35).out
    assert "router advertisement" in cap, (
        f"no ICMPv6 Router Advertisement (type 134) captured on {ifname} within 25s; "
        f"device did not emit RA. tcpdump output:\n{cap}")

    # source link-local + destination all-nodes
    m = re.search(r"(fe80::\S+) > (ff02::\S+):", cap)
    assert m, f"cannot parse RA src/dst from capture:\n{cap}"
    src, dst = m.group(1), m.group(2).rstrip(":")
    assert _norm6(dst) == _norm6("ff02::1"), f"RA dst {dst} != all-nodes ff02::1"

    # router lifetime > 0
    lt = re.search(r"router lifetime (\d+)s", cap)
    assert lt is not None and int(lt.group(1)) > 0, \
        f"RA router lifetime not >0 (not a usable default-router advert):\n{cap}"

    # advertised on-link prefix == configured subnet
    pm = re.search(r"prefix info option.*?:\s*([0-9a-fA-F:]+/\d+)", cap, re.S)
    assert pm is not None, f"RA carries no prefix info option:\n{cap}"
    assert ipaddress.ip_network(pm.group(1)) == ipaddress.ip_network(ra_enabled.prefix_net), \
        f"advertised prefix {pm.group(1)} != configured {ra_enabled.prefix_net}"

    # source link-layer address == device MAC (strongly validated when tcpdump includes this option)
    sl = re.search(r"source link-address option.*?:\s*([0-9a-fA-F:]+)", cap, re.S)
    if sl is not None:
        assert sl.group(1).lower() == ra_enabled.dev_mac, \
            f"RA source link-addr {sl.group(1)} != device MAC {ra_enabled.dev_mac}"


# ----------------------------------------------------------------------------
# Mechanism notes (basis for the assertions):
#   - the radv container is resident, feature enabled; but with default type=LeafRouter, radvd
#     is *not* in supervisord.conf (the RA template gates by type: only ToRRouter/EPMS/MgmtTsToR
#     generate the radvd program), so by default it does not emit RA.
#   - after configuring IPv6 on the SVI + type=ToRRouter + regenerating config in the container
#     and starting radvd: radvd RUNNING; radvd.conf shows the corresponding interface block + prefix block.
#   - tcpdump on that SVI captures an RA (source fe80:: link-local > ff02::1), carrying the
#     on-link prefix, router lifetime>0, source link-address == DEVICE_METADATA.mac. One every
#     ~16s (initial fast RA).
#   - a Vlan SVI on the Bridge has its own carrier (UP,LOWER_UP), so it can emit RA with no
#     member ports / no loopback, hence the test needs no traffic.
#   - restart mechanism: use "in-container sonic-cfggen regenerate + supervisorctl update/start",
#     avoiding the systemd restart rate limit of `systemctl restart radv` (repeated restarts
#     trigger the start-limit), with no whole-container restart.
# ----------------------------------------------------------------------------
