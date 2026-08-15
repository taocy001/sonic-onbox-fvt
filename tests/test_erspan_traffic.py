"""The ERSPAN data-plane encapsulation test has been merged into tests/test_mirror_chip.py::test_erspan_gre_encap_to_collector.

The original test_erspan_encap_to_collector and the chip version share identical session
parameters (`erspan add <name> <src> <dst> 8 100 ... <port> rx` + LocalPeerIP +
ErspanCollector), stimulus, and assertions; a multi-expert review judged them a pure runtime
duplicate, and per that conclusion the test in this file was deleted while the chip version
was kept and upgraded (the merge added real verification of the outer encapsulation header:
outer IP DSCP/TTL programmed per session parameters + GRE protocol==0x88be ERSPAN type II).
This file is kept as a stub to prevent old references / collection paths from dangling.
"""
