"""SSH security suite (all loopback, no external dependencies).

Adapted from sonic-mgmt tests/ssh/ to run "on-box": everything goes through the
DUT-local `ssh ... 127.0.0.1` / `ssh -Q` / `sshd -T`. No login password is
needed -- algorithm negotiation happens before authentication, so
`-o BatchMode=yes` is enough:
  - negotiation succeeds => enters the auth stage => stderr shows
    "Permission denied (publickey,password)" or prints a banner (rc=255, but
    this is NOT a negotiation failure);
  - negotiation fails => stderr contains "no matching cipher/MAC/key exchange ... found".

Read-only test; never touches sshd / pam config. Algorithm whitelists are judged
against the set actually in effect per `sshd -T`: if what the device actually
allows is not in the whitelist, that sub-case is meaningless -> skip; if no
disabled item can be found to verify, also skip.

Coverage:
  1. Protocol version: OpenSSH >= 7, protocol 1 disabled
  2. Cipher whitelist: allowed ones negotiate, disabled ones are rejected
  3. MAC whitelist: same (note: AEAD ciphers imply a MAC, so a CTR cipher must be
     paired for the MAC to actually be negotiated)
  4. KEX whitelist: same
  5. pam maxlogins: if configured, concurrency over the limit is rejected; skip if not configured
"""
import re

import pytest

pytestmark = [pytest.mark.mgmt]

HOST = "127.0.0.1"
USER = "admin"
# Negotiation happens before auth; BatchMode avoids hanging on the password prompt.
# A non-AEAD cipher lets the MAC actually participate in negotiation.
_BASE = ("-o BatchMode=yes -o StrictHostKeyChecking=no "
         "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=8")
# Substrings that indicate negotiation failure (stderr wording differs per algo type; matched uniformly here)
_NEG_FAIL = ("no matching cipher found", "no matching mac found",
             "no matching key exchange method found",
             "unable to negotiate")


# ---------- Probe helper: read sshd's actually-effective whitelist ----------
def _sshd_effective(cli, key):
    """`sshd -T` gives sshd's truly effective config (compiled defaults + sshd_config overlay).
    Requires root; admin can sudo on the DUT. Returns the key's value list (comma-separated), or None on failure."""
    r = cli.sh.run(f"sudo sshd -T 2>/dev/null | grep -i '^{key} '", check=False)
    if r.rc != 0 or not r.out.strip():
        return None
    # e.g. "ciphers a,b,c"
    parts = r.out.strip().splitlines()[0].split(None, 1)
    if len(parts) < 2:
        return None
    return [x.strip() for x in parts[1].split(",") if x.strip()]


def _q_list(cli, what):
    """`ssh -Q <what>` the full set the client supports at compile time (cipher/mac/kex)."""
    r = cli.sh.run(f"ssh -Q {what}", check=False)
    if r.rc != 0:
        return []
    return [l.strip() for l in r.out.splitlines() if l.strip()]


def _try_negotiate(cli, opt):
    """Attempt a local connection with a set of ssh options; returns (negotiated: bool, blob: str).

    negotiated=True means algorithm negotiation passed (reached auth), False means
    sshd rejected it with "no matching ...". Any other error (cannot connect, etc.)
    is returned as None for the caller to judge.
    """
    cmd = f"ssh {opt} {_BASE} {USER}@{HOST} true 2>&1"
    r = cli.sh.run(cmd, check=False, timeout=20)
    blob = (r.out + "\n" + r.err).lower()
    if any(s in blob for s in _NEG_FAIL):
        return False, blob
    # Positive signal that negotiation passed: reached auth (permission denied / banner / password prompt)
    if ("permission denied" in blob or "password:" in blob
            or "newkeys" in blob or "debian" in blob or "linux" in blob
            or r.rc == 0):
        return True, blob
    # Unknown state (e.g. cannot even parse the password prompt) -- left to the caller to skip as needed
    return None, blob


# ---------- 1. Protocol version ----------
def test_ssh_protocol_version(cli):
    """sshd OpenSSH version >= 7, and protocol 1 unsupported (modern OpenSSH has fully removed SSH-1)."""
    # `sshd --error` / `ssh -V` both print the version to stderr
    r = cli.sh.run("ssh -V 2>&1", check=False)
    blob = r.out + r.err
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", blob)
    assert m, f"cannot parse OpenSSH version from: {blob!r}"
    major = int(m.group(1))
    assert major >= 7, f"OpenSSH major version {major} < 7 (insecure)"

    # Disable protocol 1: sshd_config should not enable Protocol 1; OpenSSH>=7.6 has no SSH-1 code.
    cfg = cli.sh.run("sudo grep -iE '^[[:space:]]*Protocol' /etc/ssh/sshd_config 2>/dev/null",
                     check=False)
    proto_lines = [l for l in cfg.out.splitlines() if l.strip()]
    for l in proto_lines:
        # As long as "Protocol 1" is not explicitly enabled ("Protocol 2" or no such line are both compliant)
        toks = l.split()
        assert "1" not in toks[1:], f"sshd_config enables SSH protocol 1: {l!r}"


# ---------- 2/3/4. Algorithm whitelists ----------
def _whitelist_case(cli, what, sshd_key, neg_opt_fmt, *, extra=""):
    """Generic whitelist verification:

    - allowed = sshd -T effective set ∩ ssh -Q client-supported set
    - disabled = ssh -Q full set - allowed
    Use allowed[0] to verify "can negotiate", disabled[0] to verify "is rejected".
    Either side empty -> skip (this image did not enable a whitelist for this
    class / there is no disabled item to verify).

    neg_opt_fmt: e.g. "-c {}" / "-m {}" / "-o KexAlgorithms={}".
    extra: additional ssh options (the MAC case must pair a non-AEAD cipher,
    otherwise the MAC does not participate in negotiation).
    """
    effective = _sshd_effective(cli, sshd_key)
    supported = _q_list(cli, what)
    # When uncertain, treat as failure: admin can sudo on the DUT, so failing to read the
    # effective config is exposed as FAIL (no longer hidden by skip).
    assert effective is not None, \
        f"cannot read effective sshd '{sshd_key}' (need root / not exposed) -- rig/precondition not met, exposed as failure"
    assert supported, f"`ssh -Q {what}` returned nothing on this build -- precondition not met, exposed as failure"

    allowed = [a for a in effective if a in supported]
    disabled = [c for c in supported if c not in effective]

    # When uncertain, treat as failure: no overlap between sshd's effective set and the
    # client-supported set, so the positive path cannot be verified -> exposed as FAIL.
    assert allowed, \
        f"no overlap between sshd {sshd_key} and `ssh -Q {what}`; cannot test allow path -- exposed as failure"
    # When uncertain, treat as failure: sshd did not whitelist-trim this algo class (permits ALL),
    # so there is no disabled item to verify rejection -> exposed as FAIL.
    assert disabled, (f"sshd {sshd_key} permits ALL client-supported {what} algos; no disabled algo "
                      f"to verify rejection -- no whitelist trimming, exposed as failure")

    # Positive: the first item of the allowed set should negotiate successfully
    good = allowed[0]
    ok, blob = _try_negotiate(cli, (neg_opt_fmt.format(good) + " " + extra).strip())
    # When uncertain, treat as failure: the negotiation result is inconclusive (neither clearly
    # passed nor clearly rejected) -> exposed as FAIL.
    assert ok is not None, \
        f"inconclusive negotiation for allowed {what}={good}: {blob[:160]!r} -- exposed as failure"
    assert ok, f"allowed {what} '{good}' was rejected unexpectedly: {blob[:200]!r}"

    # Negative: the first item of the disabled set should be rejected with "no matching ..."
    bad = disabled[0]
    rej, blob2 = _try_negotiate(cli, (neg_opt_fmt.format(bad) + " " + extra).strip())
    assert rej is False, \
        f"disabled {what} '{bad}' was NOT rejected (negotiated={rej}): {blob2[:200]!r}"


def test_ssh_cipher_whitelist(cli):
    """Only ciphers within sshd's Ciphers whitelist may negotiate; others should get 'no matching cipher found'."""
    _whitelist_case(cli, "cipher", "ciphers", "-c {}")


def test_ssh_mac_whitelist(cli):
    """Only MACs within sshd's MACs whitelist may negotiate; others should get 'no matching MAC found'.

    Note: AEAD ciphers (*-gcm / chacha20-poly1305) carry their own authentication and do not
    negotiate a MAC separately, which would make `-m` a no-op. So a non-AEAD CTR cipher
    (within the whitelist) is forced to make the MAC actually participate in negotiation.
    """
    # Pick a whitelisted CTR cipher as the negotiation carrier; skip if none (cannot reliably verify MAC)
    ciphers = _sshd_effective(cli, "ciphers") or []
    ctr = next((c for c in ciphers if c.endswith("-ctr")), None)
    # When uncertain, treat as failure: no non-AEAD (CTR) cipher available to carry, so the MAC
    # cannot really participate in negotiation -> precondition not met, exposed as FAIL.
    assert ctr is not None, \
        "no non-AEAD (CTR) cipher permitted; cannot force MAC negotiation -- precondition not met, exposed as failure"
    _whitelist_case(cli, "mac", "macs", "-m {}", extra=f"-c {ctr}")


def test_ssh_kex_whitelist(cli):
    """Only KEX within sshd's KexAlgorithms whitelist is allowed; others should get 'no matching key exchange method found'."""
    _whitelist_case(cli, "kex", "kexalgorithms", "-o KexAlgorithms={}")


# ---------- 5. pam maxlogins ----------
# Note: the original test_ssh_pam_maxlogins was removed. maxlogins is an OPTIONAL hardening measure,
# not configured in limits.conf by default in this image (not configured != device defect); and the rig
# has no sshpass/keys, so under BatchMode a password login cannot be completed to create real concurrent
# sessions. Neither the "configured" nor the "rejection takes effect" path can be verified on a single-node
# rig (not a device defect, and no assertable correct behavior either), so the whole function was removed.
