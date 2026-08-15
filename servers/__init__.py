"""On-DUT mock servers: run on the DUT host (localhost / local interface IP) for the DUT's own clients to connect to.

Why on-DUT: DUT<->server traffic goes through the kernel local stack (control plane) or chip+loopback (data plane),
requiring no cross-host orchestration while sidestepping the redirect-to-CPU problem in the "DUT->peer" direction, with chip programming still verified via ASIC_DB.

- Lightweight protocols use a Python threaded socket mock (base.ThreadServer): portable, no package install.
- Connection-oriented/complex protocols use a real daemon subprocess (base.ProcessServer, e.g. exabgp, installed from an offline wheel).
"""
