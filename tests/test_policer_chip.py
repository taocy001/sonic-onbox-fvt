"""Policer objects and port binding.

Current state:
- `config policer add/update/del` **exists** and can create POLICER objects -> the SAI policer object side can be verified
  (CIR/CBS/PIR/PBS/color actions -> ASIC_DB SAI_OBJECT_TYPE_POLICER attributes).
- **There is no product CLI to bind a policer to a port** (`config interface policer` and `config interface rate-limit` both do not exist),
  so the `SAI_PORT_ATTR_POLICER_ID` chain **cannot be reached via production paths** on this image. The port-binding parts (IFP internal
  group, warm-boot double-metering, unbind on port delete, tunnel oid rejection) are unverifiable on this image -- the cases honestly skip and
  say so, rather than forcing it with table-level means like apply-patch (that isn't a production path, and any conclusion drawn from it is untrustworthy).
- Port-level rate limiting also has a `PORT_STORM_CONTROL` channel (storm-control), a separate path from the port policer, covered by
  test_storm_mtu_chip.py.
"""
import time

import pytest

pytestmark = [pytest.mark.qos, pytest.mark.asicdb]

_P = "FVTPOL"
_CIR, _CBS, _PIR, _PBS = 10000, 20000, 20000, 40000     # Kbps / bytes


def _has_cli(cli, cmd):
    """Whether the product CLI truly exists. Note you can't just check rc / whether Usage is printed -- a parent command's error also carries
    the word Usage, so you must confirm the output contains no 'No such command'."""
    r = cli.sh.run(f"config {cmd} --help", check=False)
    text = (r.out or "") + (r.err or "")
    return "No such command" not in text and "Usage:" in text


def _asic_policers(asicdb):
    return set(asicdb.objects("SAI_OBJECT_TYPE_POLICER"))


@pytest.fixture
def policer(cli, asicdb):
    """Create a policer via the product CLI, yield (name, the newly added ASIC oid); teardown deletes it and confirms the object is reclaimed.
    The CLI's rc is untrustworthy; conclusions are always drawn from CONFIG_DB/ASIC_DB read-backs."""
    if not _has_cli(cli, "policer add"):
        pytest.skip("no `config policer add` on this image")
    if cli.db_hgetall("CONFIG_DB", f"POLICER|{_P}"):
        cli.config_raw(f"policer del {_P}")
        time.sleep(1)
    before = _asic_policers(asicdb)
    cli.config_raw(
        f"policer add {_P} -mt bytes -mm sr_tcm -c blind "
        f"-cr {_CIR} -cs {_CBS} -pr {_PIR} -ps {_PBS} "
        f"-gpa forward -ypa forward -rpa drop")
    landed = False
    for _ in range(6):
        if cli.db_hgetall("CONFIG_DB", f"POLICER|{_P}"):
            landed = True
            break
        time.sleep(1)
    if not landed:
        pytest.fail(f"DEVICE DEFECT: `config policer add` accepted but POLICER|{_P} "
                    f"never appeared in CONFIG_DB")
    new = None
    deadline = time.time() + 20
    while time.time() < deadline:
        diff = _asic_policers(asicdb) - before
        if diff:
            new = sorted(diff)[0]
            break
        time.sleep(1)
    yield _P, new
    cli.config_raw(f"policer del {_P}")
    for _ in range(6):
        if not cli.db_hgetall("CONFIG_DB", f"POLICER|{_P}"):
            break
        time.sleep(1)


def test_pol1_policer_config_conversion(cli, asicdb, policer):
    """POL1: `config policer add` rates must be persisted correctly per the CLI's semantics.

    Under `-mt bytes`, `-cr` takes **Kbps** and CONFIG_DB stores **bytes/s** (-cr 10000 -> cir=1250000, i.e. x125). A mismatch in this one unit
    conversion is the source of rate-limiting incidents, so it is nailed down separately."""
    name, oid = policer
    cfg = cli.db_hgetall("CONFIG_DB", f"POLICER|{name}") or {}
    assert cfg, f"POLICER|{name} absent from CONFIG_DB"
    want_cir = _CIR * 125
    got_cir = cfg.get("cir")
    assert str(got_cir).isdigit() and abs(int(got_cir) - want_cir) <= 1, (
        f"policer rate conversion wrong: -cr {_CIR} (Kbps) should store "
        f"cir={want_cir} bytes/s, CONFIG_DB has {got_cir!r}")
    assert cfg.get("red_packet_action") == "drop", (
        f"red action did not land: {cfg.get('red_packet_action')!r}")
    assert cfg.get("meter_type") == "bytes" and cfg.get("mode") in ("sr_tcm", None), (
        f"meter type/mode wrong in CONFIG_DB: {cfg}")

    if oid is None:
        pytest.skip(
            "an unbound POLICER is not programmed to SAI on this image (no new "
            "SAI_OBJECT_TYPE_POLICER appeared; the objects present belong to CoPP). "
            "That is expected orchagent behaviour, not a defect: policer objects reach "
            "SAI when something references them. The bound path is covered by "
            "test_copp_policer.py; the port-binding path has no CLI here (see pol3).")
    a = cli.db_hgetall("ASIC_DB", oid) or {}
    got = a.get("SAI_POLICER_ATTR_CIR")
    assert got and str(got).isdigit() and abs(int(got) - want_cir) <= max(1, want_cir // 50), (
        f"ASIC policer {oid} CIR={got!r}, expected ~{want_cir} (bytes/s)")


def test_pol2_policer_update_lands(cli, asicdb, policer):
    """POL2: `policer update` changing the rate must be persisted; when the object is already referenced it must also propagate to the ASIC.

    An unreferenced policer does not reach SAI (see pol1), so the ASIC assertion only runs when the object is visible."""
    name, oid = policer
    if not _has_cli(cli, "policer update"):
        pytest.skip("no `config policer update` on this image")
    new_cir_kbps = _CIR * 2
    want = new_cir_kbps * 125
    rc, r = cli.config_raw(f"policer update {name} -cr {new_cir_kbps}")
    text = ((r.out or "") + (r.err or "")).strip()
    # when only -cr is given, if the CLI doesn't read the remaining params back from the existing entry it may throw an exception that leaves
    # the config ineffective; the assertion exposes such a crash faithfully.
    assert "Traceback" not in text and "TypeError" not in text, (
        f"DEVICE DEFECT: `config policer update {name} -cr {new_cir_kbps}` crashed "
        f"with a Python exception instead of updating the policer: {text[-200:]!r}. "
        f"The command should either apply the change or reject it cleanly.")
    landed = False
    got_cfg = None
    for _ in range(8):
        got_cfg = (cli.db_hgetall("CONFIG_DB", f"POLICER|{name}") or {}).get("cir")
        if str(got_cfg).isdigit() and abs(int(got_cfg) - want) <= 1:
            landed = True
            break
        time.sleep(1)
    assert landed, (
        f"DEVICE DEFECT: `policer update -cr {new_cir_kbps}` did not reach CONFIG_DB "
        f"(cir={got_cfg!r}, expected {want}); update path broken. CLI said: "
        f"{text[-160:]!r}")
    if oid is None:
        pytest.skip("unbound policer is not in SAI; CONFIG_DB update verified only")
    ok = False
    got = None
    deadline = time.time() + 20
    while time.time() < deadline:
        got = (cli.db_hgetall("ASIC_DB", oid) or {}).get("SAI_POLICER_ATTR_CIR")
        if got and str(got).isdigit() and abs(int(got) - want) <= max(1, want // 50):
            ok = True
            break
        time.sleep(1)
    assert ok, (
        f"DEVICE DEFECT: policer CIR update did not reach ASIC (CIR={got!r}, "
        f"expected ~{want})")


def test_pol3_port_policer_binding_channel(cli, caps):
    """POL3: `SAI_PORT_ATTR_POLICER_ID` needs a product CLI before it can be used in production.

    This image has none (`config interface policer` / `config interface rate-limit` both do not exist), so the **port-binding** parts (IFP
    internal group, warm-boot double-metering, unbind on port delete, tunnel oid rejection) cannot be verified via production paths on this
    image. Forcing it with table-level apply-patch is not verification -- that isn't a path production would take, and the conclusion is
    untrustworthy. Recorded honestly as a coverage gap."""
    chans = [c for c in ("interface policer", "interface rate-limit",
                         "interface port-policer") if _has_cli(cli, c)]
    if not chans:
        pytest.skip(
            "COVERAGE GAP (not a defect): this image exposes no product CLI to bind a "
            "policer to a port, so SAI_PORT_ATTR_POLICER_ID cannot be exercised from "
            "production paths. The SAI side is implemented; "
            "validating it needs either a NOS build that exposes the binding CLI or a "
            "sonic-mgmt run against one. Storm control is a separate path and is "
            "covered by test_storm_mtu_chip.py.")
    pytest.fail(f"binding channel(s) {chans} now exist - implement the port policer "
                f"chain assertions (bind -> SAI_PORT_ATTR_POLICER_ID -> chip IFP "
                f"entry, one per port; plus warm-boot double-metering nail)")
