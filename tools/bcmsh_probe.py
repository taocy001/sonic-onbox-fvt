#!/usr/bin/env python3
"""Build-host interactive probe: ssh -tt to the DUT, docker exec -it bcmsh, mimic a real interactive session to see whether diag echoes back."""
import sys

import pexpect

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.0.63.32"
USER, PW = "admin", "sonic"
CMD = sys.argv[2] if len(sys.argv) > 2 else "version"

opts = ("-tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o PreferredAuthentications=password -o PubkeyAuthentication=no "
        "-o HostKeyAlgorithms=+ssh-rsa -o LogLevel=ERROR")
child = pexpect.spawn(f"ssh {opts} {USER}@{HOST}", encoding="utf-8", timeout=25)
child.expect("[Pp]assword:")
child.sendline(PW)
child.expect([r"\$", r"#", r">"], timeout=15)
# Clear leftover socat, then enter bcmsh
child.sendline("echo sonic | sudo -S docker exec syncd bash -c 'pkill -9 socat' 2>/dev/null; sleep 2")
child.expect([r"\$", r"#"], timeout=10)
child.sendline("echo sonic | sudo -S docker exec -it syncd bcmsh")
import time
time.sleep(3)
child.send("\r")                      # Press Enter to show prompt
time.sleep(2)
child.send(CMD + "\r")
time.sleep(3)
try:
    out = child.read_nonblocking(size=8000, timeout=3)
except Exception:
    out = child.before or ""
print("=== TRANSCRIPT ===")
print(out)
child.sendcontrol("c")
child.close()
