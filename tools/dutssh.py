#!/usr/bin/env python3
"""Dev-time use: run commands on the DUT from the build host via system ssh + pexpect (password login).

paramiko 2.6 can't negotiate host key algorithms with this SONiC, so use the system ssh client.
Only for me (the orchestrator) to deploy/diagnose the DUT; not part of the on-DUT framework.

Usage:
    python3 tools/dutssh.py 'show version'
    python3 tools/dutssh.py --sudo 'systemctl restart swss'
    python3 tools/dutssh.py --put <local> <remote>   # scp upload
"""
import os
import sys

import pexpect

# target DUT switchable via environment variables: DUT_HOST / DUT_USER(S) / DUT_PASS
# DUT_USERS supports a comma-separated list of candidates; no longer includes the built-in
# "adimn" (a historical typo fallback: after occasional admin jitter it would land on an invalid
# user, guaranteed to fail and inflate the sshd failure count, amplified into intermittent auth failed).
HOST = os.environ.get("DUT_HOST", "10.0.20.158")
USERS = os.environ.get("DUT_USERS", os.environ.get("DUT_USER", "admin")).split(",")
PASSWORD = os.environ.get("DUT_PASS", "admin")

SSH_OPTS = (
    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "-o PreferredAuthentications=password -o PubkeyAuthentication=no "
    "-o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=10 -o LogLevel=ERROR"
)


def run(cmd, sudo=False, timeout=180, attempts=4):
    """attempts>1 applies only to idempotent commands (reads / repeatable config). Process-starting
    commands must use --once (attempts=1) -- a timeout retry would launch multiple copies of the
    same process (observed run_lanes being started repeatedly)."""
    if sudo:
        cmd = "echo %s | sudo -S bash -lc %s" % (PASSWORD, _q(cmd))
    # mitigate sshd rate limiting: retry the whole thing a few times
    for _try in range(attempts):
        try:
            return _run_once(cmd, timeout)
        except SystemExit as e:
            last = e
            import time as _t
            _t.sleep(3 + _try * 2)
    raise last


def _run_once(cmd, timeout):
    last_err = ""
    for user in USERS:
        full = f"ssh {SSH_OPTS} {user}@{HOST} {_q(cmd)}"
        child = pexpect.spawn("/bin/bash", ["-lc", full], encoding="utf-8", timeout=timeout)
        child.logfile_read = None
        sent_pw = 0
        while True:
            # match the password prompt only during authentication; "permission denied" in command output is not treated as an auth failure
            i = child.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT])
            if i == 0:
                if sent_pw >= 2:        # still asking for a password twice in a row = auth failure
                    last_err = "auth failed"
                    child.close()
                    break
                child.sendline(PASSWORD)
                sent_pw += 1
            elif i == 1:
                out = child.before
                child.close()
                return child.exitstatus or 0, out, user
            else:
                child.close()
                last_err = "timeout"
                break
    raise SystemExit(f"SSH connection failed ({last_err})")


def put(local, remote):
    for user in USERS:
        full = f"scp {SSH_OPTS} {_q(local)} {user}@{HOST}:{_q(remote)}"
        child = pexpect.spawn("/bin/bash", ["-lc", full], encoding="utf-8", timeout=300)
        while True:
            i = child.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT])
            if i == 0:
                child.sendline(PASSWORD)
            elif i == 1:
                child.close()
                if child.exitstatus == 0:
                    return 0, user
                break
            else:
                child.close()
                break
    raise SystemExit("scp failed")


def get(remote, local):
    for user in USERS:
        full = f"scp {SSH_OPTS} {user}@{HOST}:{_q(remote)} {_q(local)}"
        child = pexpect.spawn("/bin/bash", ["-lc", full], encoding="utf-8", timeout=300)
        while True:
            i = child.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT])
            if i == 0:
                child.sendline(PASSWORD)
            elif i == 1:
                child.close()
                if child.exitstatus == 0:
                    return 0, user
                break
            else:
                child.close()
                break
    raise SystemExit("scp failed")


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--put":
        rc, user = put(args[1], args[2])
        sys.stderr.write(f"[scp via {user} rc={rc}]\n")
        sys.exit(rc)
    if args and args[0] == "--get":
        rc, user = get(args[1], args[2])
        sys.stderr.write(f"[scp-get via {user} rc={rc}]\n")
        sys.exit(rc)
    sudo = False
    attempts = 4
    while args and args[0] in ("--sudo", "--once"):
        if args[0] == "--sudo":
            sudo = True
        else:               # --once: no timeout retry for non-idempotent commands (process starts, etc.)
            attempts = 1
        args = args[1:]
    timeout = int(os.environ.get("DUT_TIMEOUT", "180"))
    rc, out, user = run(" ".join(args), sudo=sudo, timeout=timeout, attempts=attempts)
    sys.stderr.write(f"[{user}@{HOST} rc={rc}]\n")
    sys.stdout.write(out)
    sys.exit(rc or 0)
