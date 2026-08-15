#!/usr/bin/env python3
"""On the DUT, drive syncd's bcmsh via a PTY to run SDKLT/diag commands and return the output.

Background: on some devices (some platforms) bcmcmd command output does not come back on stdout;
bcmsh can connect but socat needs a PTY + a "Press Enter" handshake. This script uses the stdlib pty
to launch `docker exec -i syncd bcmsh`, feeds Enter to get the prompt, and sends commands one by one
collecting the output. Pure stdlib, no pexpect required.

Usage: python3 bcmsh_run.py "lt PC_PORT update PORT_ID=1 LOOPBACK_MODE=PC_LBMODE_MAC"
"""
import os
import pty
import select
import sys
import time

SYNCD = os.environ.get("DUT_SYNCD", "syncd")


def _read(fd, timeout=1.5):
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            end = time.time() + 0.5   # keep waiting while more data arrives
    return out.decode(errors="replace")


def run(cmds, settle=2.0):
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execvp("docker", ["docker", "exec", "-it", SYNCD, "bcmsh"])
        os._exit(1)
    transcript = []
    try:
        time.sleep(settle)
        banner = _read(fd, 2.0)        # "Press Enter to show prompt."
        transcript.append(banner)
        os.write(fd, b"\r")            # Enter to bring up the prompt
        transcript.append(_read(fd, 1.5))
        for c in cmds:
            os.write(fd, c.encode() + b"\r")
            transcript.append(_read(fd, 2.0))
        os.write(fd, b"exit\r")
        _read(fd, 0.5)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    return "".join(transcript)


if __name__ == "__main__":
    cmds = sys.argv[1:] or ["version"]
    sys.stdout.write(run(cmds))
