#!/usr/bin/env python3
"""Clean Vendor-X diag unix-socket client (for devices where dsserve only exposes a unix socket).

Background: on some devices (SDK6), dsserve only serves diagnostics on
/var/run/sswsyncd/sswsyncd.socket; bcmcmd over TCP cannot connect, and socat readline needs a
PTY. But connecting with a plain blocking socket, sending commands, and reading up to the
prompt just works -- the key is that the socket backlog is only 2, so each connection must be
closed as soon as it is done, never leaving stale connections (otherwise the backlog fills up
and everything blocks).

Usage (run inside the syncd container): python3 bcm_sock.py "ps" "port cd0 lb=mac"
"""
import socket
import sys
import time

SOCK = "/var/run/sswsyncd/sswsyncd.socket"
PROMPTS = (b"BCM.0>", b"drivshell>", b"BCMLT.0>")


def run(cmds, timeout=5.0):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.setblocking(True)
    s.settimeout(timeout)
    s.connect(SOCK)
    out = []
    try:
        for c in cmds:
            s.sendall(c.encode() + b"\n")
            buf = b""
            end = time.time() + timeout
            while time.time() < end:
                try:
                    chunk = s.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                if any(p in buf for p in PROMPTS):   # prompt reached means the command is done
                    break
            out.append(buf.decode(errors="replace"))
    finally:
        s.close()   # must close, otherwise it occupies the backlog
    return "\n".join(out)


if __name__ == "__main__":
    sys.stdout.write(run(sys.argv[1:] or ["version"]))
