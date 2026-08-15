"""CoPP L3-result trap data plane (ip2me/bgp/ttl_error/neighbor_miss) — bench limitation, tests removed.

Category D (bench / measurement-method limitation, not a pass and not a device defect
that is currently on-box decidable):

Mechanism (design note): the reason for an L3-result trap is a product of the LPP L3
lookup — DMAC=myStation sets MyStationHit, DIP=local IP sets DstClassL3=IP2ME_CLASS, and
the VPP trap FP reads these two flags. An L3-result trap's myStation is added per-port
(src_port=a specific physical port) (sai_xgs_ltsw_l2_stn.c). When a MAC-loopback CPU-
injected packet re-ingresses, its src_port is reported as the CPU port, not the physical
port -> the per-port myStation does not match -> the L3 lookup does not trigger -> cpu0 RPKT=0.

So the loopback + CPU-injection on-box test method gives a **false negative** for
L3-result traps: cpu0=0 could mean the trap really does not work, or it could just be the
method's false negative (aux4 count pollution + re-ingress src_port != physical port
breaking the per-port myStation), and current on-box means cannot distinguish the two.
Deciding this requires a **real external ingress** (traffic generator / physical peer
port), which this bench does not have.

Accordingly, rather than hiding it with xfail, the original test_l3_trap_to_cpu and its
fixtures/helpers are removed entirely, and this is explicitly recorded as a bench
limitation. The chip-programming side (RIF/route -> CPU port/myStation, LPP
MyStationHit+DstClassL3 flag) is already checked read-only via code + ASIC_DB; loopback
data-plane coverage of L2/protocol traps is in test_copp_full.py /
test_copp_dataplane_chip.py (Part 1).
"""
