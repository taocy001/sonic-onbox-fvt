"""AAA: TACACS+ / RADIUS server config + client-reachability verification.

Full login authentication (PAM-triggered) requires on-hardware integration with a
real tac_plus/freeradius (VERIFY-ON-HW); here we verify the config lands in CONFIG_DB
and (when a mock server is present) that the client can reach the server.
"""
import pytest

pytestmark = [pytest.mark.mgmt]

# RFC5737 TEST-NET unreachable address: cannot use 127.0.0.1 -- the customized OS (SONiC)
# rejects a loopback address as an AAA server ("Loopback ip is not valid"), yet rc is still
# 0 (false success) and nothing lands in CONFIG_DB. A TEST-NET address is accepted by both
# image types and is unreachable (never sends a real auth request, never disrupts the
# current SSH session).
SRV = "192.0.2.11"


def _tacacs_del_cmd(cli):
    """Delete subcommand differs across images (probe + cache)."""
    if getattr(cli, "_aaa_del", None) is None:
        r = cli.sh.run("config tacacs del --help", check=False)
        cli._aaa_del = "del" if r.rc == 0 else "delete"
    return cli._aaa_del


def _rendered(cli, *paths):
    """Read the config files rendered by hostcfgd (evidence the daemon actually consumed the config). Returns (merged text, list of hit paths)."""
    body, hit = "", []
    for p in paths:
        r = cli.sh.run(f"cat {p} 2>/dev/null", check=False)
        if r.rc == 0 and r.out.strip():
            body += r.out
            hit.append(p)
    return body, hit


def test_tacacs_config(cli, config_guard):
    """TACACS+: lands in CONFIG_DB + **hostcfgd actually renders** to NSS/PAM (/etc/tacplus_nss.conf), proving the daemon consumed the
    config rather than only checking "written into CONFIG_DB". Full login authentication needs a real tac_plus (VERIFY-ON-HW)."""
    rc, r = cli.config_raw(f"tacacs add {SRV}")
    config_guard.defer_undo(f"tacacs {_tacacs_del_cmd(cli)} {SRV}")
    # C: the CLI should succeed; a mismatched subcommand FAILs to surface it
    assert rc == 0, f"config tacacs add subcommand differs from expected: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"TACPLUS_SERVER|{SRV}"), "No TACACS server in CONFIG_DB"
    import time
    time.sleep(2)  # give hostcfgd time to render
    body, hit = _rendered(cli, "/etc/tacplus_nss.conf", "/etc/pam.d/common-auth-sonic")
    # A: hostcfgd should render the TACACS config into the NSS/PAM files but rendered none = device defect
    assert hit, ("hostcfgd TACACS render files absent "
                 "(config landed in CONFIG_DB but daemon did not render NSS/PAM)")
    assert SRV in body, f"hostcfgd did not render TACACS server {SRV} into {hit}: {body[:200]}"


def test_radius_config(cli, config_guard):
    """RADIUS: lands in CONFIG_DB + **hostcfgd actually renders** to /etc/pam_radius_auth.conf (evidence the daemon consumed it)."""
    rc, r = cli.config_raw(f"radius add {SRV}")
    config_guard.defer_undo(f"radius {_tacacs_del_cmd(cli)} {SRV}")
    # C: the CLI should succeed; a mismatched subcommand FAILs to surface it
    assert rc == 0, f"config radius add subcommand differs from expected: {r.err or r.out}"
    assert cli.db_keys("CONFIG_DB", f"RADIUS_SERVER|{SRV}"), "No RADIUS server in CONFIG_DB"
    import time
    time.sleep(2)
    body, hit = _rendered(cli, "/etc/pam_radius_auth.conf", "/etc/pam.d/common-auth-sonic")
    if SRV not in body:
        # hostcfgd only renders the server into PAM when the aaa login method includes radius
        # (as a pam_radius_auth.so conf=/etc/pam_radius_auth.d/<ip>_1812.conf line).
        # Putting local first keeps the current SSH from stalling on the unreachable server
        # (same safety posture as the TACACS case).
        cli.config_raw("aaa authentication login local radius")
        config_guard.defer_undo("aaa authentication login local")
        for _ in range(6):
            time.sleep(2)
            body, hit = _rendered(cli, "/etc/pam_radius_auth.conf",
                                  "/etc/pam.d/common-auth-sonic",
                                  f"/etc/pam_radius_auth.d/{SRV}_1812.conf")
            if SRV in body:
                break
    # A: hostcfgd should render the RADIUS config into the PAM files but rendered none = device defect
    assert hit, ("hostcfgd RADIUS render files absent "
                 "(config landed in CONFIG_DB but daemon did not render PAM)")
    assert SRV in body, f"hostcfgd did not render RADIUS server {SRV} into {hit}: {body[:200]}"


def test_aaa_authentication_order(cli, config_guard):
    """AAA authentication order: CONFIG_DB AAA table + **hostcfgd actually renders** PAM (/etc/pam.d/common-auth-sonic contains tacplus)."""
    # **local first** (not tacacs+ first): the TACACS server is unreachable on the bench; if tacacs
    # were first, every login of the current SSH session would first stall on the TACACS timeout
    # (5-10s) before falling back to local -> the management SSH gets interrupted/timed out during
    # that window (a device with only SSH and no serial console would go unreachable).
    # With local first, local succeeds immediately and never touches TACACS, yet the order still
    # contains tacacs and PAM still renders tacplus, so the assertions hold without cutting SSH.
    # Add a TACACS server first (RFC5737 TEST-NET unreachable address): hostcfgd only renders the
    # tacplus line into PAM when a TACACS server **exists** (correctly rendering nothing otherwise);
    # setting only the order without adding a server would cause a false "PAM has no tacplus" failure.
    # order=local first, so an SSH login hits local first and succeeds immediately, never touching
    # this unreachable server.
    cli.config_raw("tacacs add 192.0.2.10")
    config_guard.defer_undo(f"tacacs {_tacacs_del_cmd(cli)} 192.0.2.10")
    rc, r = cli.config_raw("aaa authentication login local tacacs+")
    config_guard.defer_undo("aaa authentication login local")
    # C: the CLI should succeed; a mismatched subcommand FAILs to surface it
    assert rc == 0, f"config aaa subcommand differs from expected: {r.err or r.out}"
    attrs = cli.db_hgetall("CONFIG_DB", "AAA|authentication")
    assert "tacacs" in str(attrs.get("login", "")), f"AAA authentication order not applied: {attrs}"
    import time
    time.sleep(2)
    body, hit = _rendered(cli, "/etc/pam.d/common-auth-sonic", "/etc/pam.d/sshd")
    # A: hostcfgd should render the auth order into the PAM file but did not = device defect
    assert hit, ("PAM render file absent "
                 "(auth order landed in CONFIG_DB but daemon did not render PAM)")
    assert any(k in body.lower() for k in ("tacplus", "tacacs")), \
        f"hostcfgd did not render tacplus into PAM after setting auth order: {hit} {body[:200]}"
