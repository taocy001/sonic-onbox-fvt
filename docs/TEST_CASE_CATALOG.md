# Test case catalog (auto-generated, do not hand-edit)

> Generated: `python3 tools/gen_catalog.py`
> Scale: 120 files / 544 test functions (statically visible parametrization ~561)
> Four verification depth levels: config->CONFIG_DB contract / orchagent->ASIC_DB / chip counts / data-plane traffic.


## L2 switching (12 files / 39 functions)


### test_fdb.py — L2 FDB functionality: static entry programming + known unicast forwarded per FDB.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_static_fdb_forwarding | 1 |  |


### test_fdb_chip.py — L2 FDB chip-behavior-level verification (dynamic learning / known-unicast directed vs unknown-unicast flood / MAC move / static / flush / aging).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dynamic_learning_chip_and_directed_unicast | 1 | [1] Dynamic MAC learning + known-unicast **directed** forwarding: |
| test_unknown_unicast_floods_all_members | 1 | [2] Unknown unicast **floods to all other members** (**dedicated test VLAN** + flood-safe loopback, zero storm/zero degradation on a single device): |
| test_broadcast_floods_all_members | 1 | [7] Broadcast dst=ff:ff:ff:ff:ff:ff **floods to all other members** (dedicated test VLAN + flood-safe loopback). |
| test_mac_move_relearn_on_new_port | 1 | [3] MAC move (relearn on a new port, **dedicated test VLAN**, storm-safe): the same src is first |
| test_static_fdb_chip_and_dataplane | 1 | [4] Static FDB: install a dmac->p_out static entry via swssconfig. |
| test_static_fdb_immune_to_station_move | 1 | [8] Static entry resists moving (station-move immunity, dedicated test VLAN): after a chip static FDB |
| test_fdb_flush_clears_chip_and_reverts_to_flood | 1 | [5] flush (**dedicated test VLAN**, flood domain shrunk to 4 ports to prevent degradation): first learn a |
| test_dynamic_fdb_flush_on_link_down | 1 | [9] link-down triggers **per-port** dynamic FDB flush (production Vlan1000): first learn a dynamic MAC |
| test_fdb_aging_removes_dynamic_entry | 1 | [6] aging (stays on production Vlan1000): learn a dynamic MAC (confirmed in chip + ASIC_DB), then after |


### test_hairpin_validate.py — Validate the asymmetric VLAN hairpin topology: dual-port loopback but structurally loop-broken (no storm) + correct forwarding + return frames capturable.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_hairpin_no_storm_and_forward | 1 | CPU->p_in(A)->forward to p_out->p_out loopback->VLAN B (dead end/SVI). Validate: |
| test_hairpin_capture_forwarded | 1 | Pattern C: capture the forwarded frame **after p_out egress processing** (validates the forwarding |


### test_lacp.py — LACP / Port-Channel real-chip behavior: LAG/LAG_MEMBER into ASIC + lag-hash into the SAI HASH object.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_lacp_mode_and_members | 1 | LAG + member really reach the chip: create PortChannel -> a SAI LAG object appears in ASIC_DB; |
| test_lag_hash_config | 1 | LAG hash really reaches the chip and really changes: resolve the HASH object pointed to by |


### test_lag_chip.py — LAG / PortChannel **chip-behavior + data-plane** cases (distinct from test_lag.py, which

| Case | Expansions | Purpose |
|------|:---:|------|
| test_lag_members_up_in_asic | 1 | Members really enter the ASIC LAG: **identity-level** assertion — each member port's |


### test_loopback_smoke.py — On-DUT smoke self-check: does hairpin loopback really send frames back into the pipeline (using chip counters, not packet capture).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_loopback_reingress_counter | 1 | ports[0] has loopback enabled: send N known-unicast frames, chip RX_PKT should be +~N (real loopback re-ingress), and the |
| test_negative_no_loopback_no_reingress | 1 | Control: after disabling loopback, frames cannot be sent out / do not re-ingress, RX_PKT should be ~0. |


### test_mac.py — L2 MAC full feature set: static/dynamic/aging/move/flush (chip behavior level, not DB echo).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_static_mac_crud | 1 | Static FDB CRUD (default VLAN, swssconfig path) + **storm-safe directed dataplane** (dedicated test VLAN). |
| test_mac_aging_time_config | 1 | MAC aging: set fdb_aging_time to a short value, learn a dynamic MAC (confirmed into ASIC), stop |
| test_mac_flush | 1 | flush: first learn a dynamic MAC and **confirm it into ASIC (positive control)**, then |
| test_mac_move | 1 | MAC move (relearn on the new port): the same source MAC is first learned on the old port, then |


### test_storm_mtu_chip.py — Storm-control (BUM rate-limit) + port MTU oversized-frame drop -- real-traffic / chip-behavior verification.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_storm_control_rate_limits_bum | 1 | storm-control rate-limits broadcast/unknown-unicast/unknown-multicast: |
| test_storm_control_show_and_db | 1 | storm-control config plane: after provisioning, `show storm-control` reflects the rate + |
| test_port_mtu_oversized_frame_dropped | 1 | Port MTU oversized-frame drop (data plane, **egress semantics**): set p_out MTU=1500, |


### test_vlan.py — L2 VLAN: create/member/ASIC_DB programming + delete lifecycle (negative). The command behavior is the object under test.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vlan_create_in_asicdb | 1 | config vlan add -> a new SAI_VLAN object appears in ASIC_DB. |
| test_vlan_show_brief | 1 | Pure CLI: after creation, show vlan brief shows it, and it's idempotent. |
| test_vlan_member_add | 1 | Member join -> the member appears in CONFIG_DB + ASIC VLAN_MEMBER really programmed (orchagent->SAI chain). |
| test_vlan_member_del_lifecycle | 1 | vlan/member DELETE really reaches the chip + forwarding plane (negative lifecycle). Existing |


### test_vlan_chip.py — VLAN chip-behavior (data plane + read-only chip state) verification -- covers access/trunk member

| Case | Expansions | Purpose |
|------|:---:|------|
| test_flood_scoped_to_vlan_member | 1 | Broadcast flooding reaches only **same-VLAN members** (**dedicated test VLAN**, flood domain shrunk |
| test_flood_not_crossing_vlan | 1 | Cross-VLAN isolation (dual chip-side evidence; **dedicated flood VLAN** shrinks the flood domain to |
| test_known_unicast_forwarded_within_vlan | 1 | Same-VLAN known unicast hits the member port **directed** by FDB (dedicated test VLAN + silent control |
| test_access_port_pvid_on_chip | 1 | PVID ingress semantics of an access (untagged) member: after an untagged member joins VLAN-d, the |
| test_trunk_member_in_chip_vlan | 1 | A trunk (tagged) member actually enters the chip VLAN member table: add ports[1] as a tagged member of |
| test_tagged_ingress_classification_and_filtering | 1 | Two core trunk-ingress data-plane behaviors (egress-tag **content capture** is untestable and |


### test_vlan_full.py — VLAN full feature set: member modes/native/range/tagged/VLAN-IF MTU/QinQ/PVLAN/translation/BUM.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vlan_range_high_id | 1 | VLAN range 2-4094: create high-numbered VLAN 4094 and verify it is actually programmed to ASIC (SAI_VLAN count grows). |
| test_vlan_tagged_member | 1 | trunk(tagged) member actually programmed to chip: add a tagged member -> a new SAI_VLAN_MEMBER appears in ASIC |
| test_vlan_untagged_pvid | 1 | access(untagged) member actually programmed to chip: add a port untagged into VLAN-b -> the VLAN's SAI_VLAN_MEMBER |


### test_vlan_scenarios.py — Integrated scenarios: VLAN isolation / inter-VLAN L3 routing (chip-counter verified, hairpin loopback).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vlan_isolation | 1 | Different VLANs are isolated from each other (positive control + chip-side |
| test_inter_vlan_routing | 1 | Inter-VLAN L3 routing (real traffic): p_in@VLAN-a SVI injects an IP packet with "dest |


## L3 routing (16 files / 62 functions)


### test_arp_full.py — ARP full feature set: static/dynamic/aging/GARP/proxy/arp-to-host. Ports come from topo.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_static_arp | 1 | Static ARP/neighbor: (1) ASIC NEIGHBOR_ENTRY programming + (2) **real traffic**: after configuring a static neighbor, inject packets routed to that next-hop |
| test_dynamic_arp_learning | 1 |  |
| test_arp_aging_config | 1 | ARP aging (real behavior): first learn a dynamic neighbor via ArpResponder and confirm it is programmed into the ASIC (positive control), |
| test_gratuitous_arp_send | 1 | Gratuitous ARP: after configuring an IP, the DUT should proactively send a GARP (the peer receives it). |
| test_arp_reply_for_interface_ip | 1 | arp-to-host: as an L3 interface, the DUT must reply on its own behalf to an ARP request of **who-has <its own interface IP>** |
| test_arp_proxy_config | 1 | ARP proxy (real behavior): enable proxy_arp on the ingress port p_in, with a target address in another subnet (reachable via a connected route on p_out); |


### test_intf_ip.py — L3 interface IP: assign IP -> RIF + connected route programmed into ASIC_DB. Ports reference topo.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_intf_ip_creates_rif | 1 |  |


### test_ipv6_ra.py — IPv6 Router Advertisement (radvd) functional verification -- really verifies "the device emits RA".

| Case | Expansions | Purpose |
|------|:---:|------|
| test_radv_container_and_feature_enabled | 1 | radv container up + radv is enabled in `show feature status`. This is the prerequisite for all RA functionality. |
| test_radvd_daemon_runs_when_enabled | 1 | After configuring an IPv6 VLAN interface + ToR gateway role, the radvd process should be |
| test_device_emits_router_advertisement | 1 | tcpdump on the SVI under test to capture an ICMPv6 Router Advertisement (type 134): radvd |


### test_l3_forward_traffic.py — L3 forwarding real-traffic end-to-end cases (template) -- not just verifying ASIC_DB programming, but **driving real traffic to verify forwarding behavior**.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_l3_ipv4_unicast_forwarding | 1 | L3 IPv4 unicast forwarding, real traffic: inject IP packets at p_in -> route to p_out -> verify p_out chip TX +~N. |
| test_l3_ipv6_unicast_forwarding | 1 | L3 IPv6 unicast forwarding, real traffic: inject IPv6 packets at p_in -> route to p_out -> verify p_out chip TX +~N. |
| test_l3_forward_content_rewrite | 1 | L3 forwarding **content check** (egress-mirror to CPU to capture the real frame): inject an IP packet routed to p_out, mirror p_out's |
| test_l3_ttl_expired_not_forwarded | 1 | L3 TTL-expired negative real traffic: inject TTL=1 packets; the DUT decrements to 0 and should **drop, not forward**, verify p_out chip |
| test_l3_ecmp_member_failure_rebalances | 1 | L3 ECMP **member-failure rebalancing** (the old "both ports >0" distribution case is now strictly covered by test_l3_route_chip's |


### test_l3_neighbor_chip.py — L3 neighbor (ARP/ND) chip-behavior cases -- not just verifying NEIGHBOR_ENTRY in ASIC_DB, but

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ipv4_arp_neighbor_programs_asic | 1 | IPv4 ARP neighbor resolution programs the chip: config `ip neigh` (NEIGH) on an L3 port -> ASIC_DB NEIGHBOR_ENTRY appears, |
| test_ipv6_nd_neighbor_programs_asic | 1 | IPv6 ND neighbor resolution programs the chip: config IPv6 `ip neigh` on an L3 port -> ASIC_DB NEIGHBOR_ENTRY appears, |
| test_ipv4_forward_to_resolved_neighbor | 1 | IPv4 forward to resolved neighbor (real traffic): after neighbor+route programming, inject an IP packet -> routed to p_out -> p_out chip TX +≈N, |
| test_ipv6_forward_to_resolved_neighbor | 1 | IPv6 forward to resolved neighbor (real traffic): after ND neighbor+route programming, inject an IPv6 packet -> routed to p_out -> p_out chip TX +≈N |
| test_ipv4_unresolved_neighbor_not_forwarded | 1 | IPv4 unresolved neighbor (neighbor_miss) negative (real traffic): the route points at a next hop with **no neighbor entry**, inject the same packet, |
| test_ipv6_unresolved_neighbor_not_forwarded | 1 | IPv6 unresolved neighbor (neighbor_miss) negative (real traffic): the IPv6 route points at a next hop with no ND entry, inject an IPv6 packet, |


### test_l3_route_chip.py — L3 routing **path-selection** chip-behavior test suite -- verifies LPM longest-prefix

| Case | Expansions | Purpose |
|------|:---:|------|
| test_host_route_preferred_over_lpm | 1 | Host route (/32) preferred over the LPM route covering it: the same destination |
| test_lpm_longest_prefix_selection | 1 | Longest-prefix match: a /16 overlaps a more-specific /24, pointing to egress-1 / |
| test_lpm_longest_prefix_selection_v6 | 1 | IPv6 longest-prefix match (v6 twin of test_lpm_longest_prefix_selection): v6 LPM uses |
| test_default_route_catchall | 1 | Default-route catch-all: for a destination address not covered by any specific |
| test_connected_route_forward_and_rewrite | 1 | Connected-route forward + L3 rewrite: the dest IP falls in an egress port's |
| test_ecmp_hash_distributes_5tuple | 1 | ECMP 5-tuple hash distribution: one route with two next-hops (on two egress ports), |


### test_ndp.py — NDP (IPv6) full feature set: ND/neighbor/RA/DAD/proxy/RA-Guard. Ports referenced from topo. Capacity/rate needs a traffic generator -- out of this framework's scope, no case provided.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ipv6_address_and_rif | 1 | IPv6 config -> connected route programmed (proves RIF + route, more robust to port reuse than the RIF-count method). |
| test_static_neighbor_v6 | 1 | Static IPv6 neighbor: (1) ASIC NEIGHBOR/route programming + (2) **real traffic**: after configuring a static v6 neighbor, inject an IPv6 packet routed to that next hop, |
| test_ipv6_connected_route_teardown | 1 | connected route **teardown direction** (distinct from the setup direction of test_ipv6_address_and_rif -- |
| test_dynamic_nd_learning | 1 | Dynamic ND learning (the v6 counterpart of test_dynamic_arp_learning, previously missing): a real NS->NA exchange |
| test_dad_duplicate_address | 1 | DAD duplicate address detection (real behavior): enable MAC loopback on the ingress port and start |


### test_pbr.py — PBR policy routing: redirect entries truly programmed to the ASIC + policy-driven data-plane rerouting.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_pbr_v4_configurable | 1 | PBR (v4) truly programmed: redirect rule -> a SAI_ACL_ENTRY appears **in this table** carrying an SRC_IP |
| test_pbr_bind_and_forward | 1 | PBR end-to-end data-plane: matched traffic is redirected by policy to the policy egress port (not the route egress port). |


### test_route_full.py — Basic routing full feature set: v4/v6 static/default/floating/Null0/distance. Ports reference topo.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ipv4_static_route | 1 | IPv4 static route: configure the route via SONiC CLI -> (1) ASIC has_route (programmed) + (2) **real traffic**: inject |
| test_default_route | 1 | Default route: configure 0.0.0.0/0 -> inject a packet whose "destination is in no connected subnet", verifying it is |
| test_null0_blackhole_route | 1 | Null0 blackhole route: verify dropping with **real traffic**. Under the same p_out egress, compare: (1) a normal route's |
| test_route_withdraw_stops_forwarding | 1 | Route deletion really withdraws hardware forwarding (the whole suite previously only tested the add direction, del was only |
| test_floating_static_route_distance | 1 | Floating static route: distance really affects **FIB selection + hardware forwarding** (not just appearing in FRR RIB/APPL_DB). |


### test_routed_default_vlan.py — Routed-port default-VLAN fix verification -- the minimal sufficient set.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_t1_routed_port_config_chip_and_l3_traffic | 1 | T1 no breakout, routed port: config + chip triple + L3 forwarding. |
| test_t2_bridged_port_config_chip_and_l2_traffic | 1 | T2 no breakout, bridged port: RIF removed then re-added -- config + chip triple + L2 flood forwarding. |
| test_t3_t4_breakout_subport_and_merged_base | 1 | T3 breakout subport + T4 merged base port: each verifies config + chip triple + L3 forwarding. |


### test_routed_default_vlan_ops.py — Routed-port default-VLAN fix -- supplementary validation of production ops flows.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_e1_subinterface_does_not_detach_parent | 1 | E1 [C1-n1] creating a subif while the parent is an L2 port: the parent **must not** be |
| test_e2_routed_lag_member_lifecycle | 1 | E2 [C3+C4+C5+C2] routed LAG: member add/remove / member leave-rejoin / RIF delete rejoins in-place members. |
| test_e3_ingress_disabled_member_keeps_discard | 1 | E3 [C2-b1] an LACP standby (ingress-disabled) member must keep discard=All after LAG RIF delete. |
| test_e4_port_flap_keeps_state | 1 | E4 port shutdown/startup round trips: the routed-port triple must not drift (link flap is an unavoidable production event). |
| test_e5_bulk_linkmode_switch | 1 | E5 bulk link-mode: switching many ports back to back, each port's final state must be correct with no cross-contamination. |
| test_e6_user_vlan_interaction | 1 | E6 user-VLAN interaction: a port that joins a user VLAN (not vlan1) then becomes routed -- |
| test_e7_vrf_bind_rebuilds_rif | 1 | E7 VRF bind/unbind rebuilds the RIF -- after the rebuild the port triple must still be correct. |


### test_routed_default_vlan_stress.py — Long-stability cases for routed-port default VLAN (skipped by default, enabled with FVT_STRESS=1, rounds via FVT_STRESS_ROUNDS).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ss1_breakout_cycles | 1 | SS1 split/merge xN: each round, neither the post-split subports nor the post-merge base port may stay in vlan1; resource counts must not grow. |
| test_ss2_linkmode_cycles | 1 | SS2 route<->bridge xN: each round the triple is correct in both states with no residue; on the last round send real traffic to confirm functionality wasn't worn down. |


### test_vrf.py — VRF: L3 port bound to VRF / loopback bound to VRF / route-leaking / mgmt-VRF.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vrf_create | 1 |  |
| test_vrf_delete_recycles_asic_vr | 1 | VRF **deletion path**: after vrf del, its SAI_OBJECT_TYPE_VIRTUAL_ROUTER must leave |
| test_bind_interface_to_vrf | 1 | L3 port bound to VRF -> ASIC RIF reprogrammed under that VRF's virtual_router (chip-level |
| test_mgmt_vrf | 1 | Management VRF: `vrf add mgmt` is a **Linux-only** construct not pushed to the ASIC: |
| test_vrf_64 | 1 | VRF scale (>=64): bulk-create 64 VRFs, verify all land in CONFIG_DB, and that the ASIC |


### test_vrf_bgp_chip.py — BGP-in-VRF: build a real eBGP session inside a VRF, learn the route into that VRF's RIB/FIB/ASIC, and forward data-plane traffic per the VRF route.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_bgp_in_vrf_session_route_and_dataplane | 1 | eBGP session inside a VRF -> route into that VRF's RIB/FIB/ASIC (vr matches that VRF) -> |


### test_vrf_chip.py — VRF chip behavior / data-plane isolation cases -- verify not just CONFIG_DB/ASIC object existence but **real isolation**.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vrf_same_ip_two_vrfs_distinct_vr | 1 | The same prefix adds one route in each of two VRFs -> the ASIC should show **two** ROUTE_ENTRY with **different** vr oids, |
| test_vrf_dataplane_isolation_no_cross_leak | 1 | Data-plane isolation: the route is added **only** in Vrf-A. Inject a flow to the Vrf-A ingress port -> should be forwarded to the Vrf-A egress (chip TX +~N); |
| test_vrf_same_ip_independent_forwarding | 1 | The same destination IP has a route in each of two VRFs, pointing at **different** egress ports: inject a flow to the Vrf-A ingress -> only to A's egress; |


### test_vrf_route_leak_chip.py — VRF cross-table route leaking (positive) + selective leaking -- dataplane proof.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vrf_route_leak_forwards_dataplane | 1 | Cross-VRF leak, positive: install a route in Vrf-A whose nexthop lands on the Vrf-B egress port -> |
| test_vrf_route_leak_is_selective | 1 | Selective leaking: within Vrf-B the egress port has routes to **both** prefixes P1/P2 (both reachable); |


## Routing protocols (5 files / 16 functions)


### test_bfd_vrrp.py — BFD / VRRP: session/instance config programming. Session establishment/failover behavior needs a peer -> local loopback peer pending integration.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_bfd_static_peer_config | 1 | BFD peer config (FRR/bfdd): after configuring, the peer must actually register into FRR (`show bfd peers` lists it). |


### test_bgp.py — BGP: a stdlib-only on-box software peer builds a **real eBGP session** and announces routes -> DUT learns them -> programmed to ASIC.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_bgp_session_and_route_to_asic | 1 | Software peer builds a real eBGP session -> announce a route -> programmed end-to-end to ASIC -> withdraw removes it. |


### test_bgp_frr_state.py — BGP / FRR state test cases (pure config + real FRR/DB state verification, no live BGP peer needed).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_prefix_list_suppress_cli_renders_to_frr | 1 | SUPPRESS_PREFIX: CLI add -> CONFIG_DB PREFIX_LIST key (verifiable behavior not |
| test_prefix_list_unknown_type_rejected | 1 | Negative: an unknown PREFIX_TYPE is rejected by the CLI, not written to CONFIG_DB, and bgpcfgd doesn't crash |
| test_prefix_list_malformed_prefix_not_rendered | 1 | Negative: a malformed prefix is either rejected by the CLI (CONFIG_DB clean) or accepted but not rendered by FRR, and bgpcfgd doesn't crash |
| test_frr_zebra_runs_as_frr_uid | 1 | zebra runs as the frr user (uid 300) (adapted from test_bgp_port_disable.py::test_zebra_uid). |
| test_frr_daemon_ports_local_only | 1 | FRR daemon ports are locally reachable only: zebra/fpmsyncd listen on 127.0.0.1, restricted ports not exposed |
| test_frr_iptables_port_hardening | 1 | caclmgrd iptables OUTPUT owner-uid hardening rules for 2601/2620 |
| test_frr_config_files_in_running_config | 1 | Every meaningful line in /etc/sonic/frr/*.conf should appear in `vtysh show running-config` |


### test_ospf.py — OSPF: v2/v3 + areas + redistribution (FRR vtysh config + show verification).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ospfv2_enable | 1 | OSPFv2: verify FRR **actually accepts and renders** the config (running-config contains `router ospf` + network/area). |
| test_ospfv3_enable | 1 | OSPFv3: verify FRR actually accepts and renders `router ospf6`. |


### test_routing_policy_cli.py — Productized routing-policy CLI (prefix-list / route-map / BGP instance) -- config-plane ground-truth verification.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_prefix_list_product_cli | 1 | prefix-list: add -> CONFIG_DB PREFIX table ground truth -> `show ip prefix-list` rendering -> clean del. |
| test_route_map_product_cli | 1 | route-map: add (permit + set next-hop) -> CONFIG_DB ROUTE_MAP ground truth -> show rendering -> del. |
| test_bgp_instance_product_cli | 1 | BGP instance: `config bgp add default -a <asn> -r <router-id>` -> CONFIG_DB BGP_GLOBALS |
| test_static_arp_product_cli | 1 | Static ARP product CLI: `config arp static add <ip> <mac> <intf>` -> CONFIG_DB NEIGH table + |
| test_route_policy_filters_bgp_routes | 1 | Real behavior of inbound routing policy: a software peer (NetnsBgpPeer) advertises two prefixes, the DUT |


## ACL (6 files / 23 functions)


### test_acl_basic.py — ACL: chip-programming verification of table create / show / remove (CLI -> aclorch -> ASIC SAI_ACL_TABLE/ACL_ENTRY).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_acl_table_create | 1 | L3 ACL table create + rule -> assert ASIC SAI_ACL_TABLE and SAI_ACL_ENTRY really grow (chip programming). |
| test_acl_table_show | 1 | Build an L3 table + rule so it really programs to ASIC, then assert `show acl table` renders that (hardware-programmed) table. |
| test_acl_table_remove | 1 | Positive-control then remove: first build a table + rule so ASIC shows a SAI_ACL_TABLE |


### test_acl_chip.py — Comprehensive chip-level ACL verification (L3 IPv4 all-fields + MAC L2 all-fields + counter + DROP/FORWARD + dataplane drop).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_acl_l3_field_in_asic | 1 | L3(IPv4) ACL per-field chip programming: create a rule matching the field, verify the real ASIC ACL_ENTRY carries the corresponding SAI field. |
| test_acl_mac_field_in_asic | 1 | MAC(L2) ACL per-field chip programming: create a rule matching an L2 field, verify the ASIC ACL_ENTRY carries the corresponding SAI field. |
| test_acl_rule_counter_object_in_asic | 1 | Rule with counter: ASIC ACL_ENTRY.ACTION_COUNTER points to an **existing** SAI ACL_COUNTER object. |
| test_acl_counter_in_countersdb | 1 | ACL counter enters COUNTERS_DB ACL_COUNTER_RULE_MAP (prerequisite for aclshow / statistics being readable). |
| test_acl_action_in_asic | 2 | ACL action chip programming: DROP/FORWARD rules land in ASIC ACL_ENTRY with PACKET_ACTION at the expected value. |
| test_acl_l3_drop_dataplane | 1 | L3 DROP rule **dataplane** hit (real traffic, end-to-end): |


### test_acl_drop.py — End-to-end scenario: ACL DROP rule blocks matching traffic (rules pushed via acl-loader + chip counter verification).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_acl_drop_matching_traffic | 1 |  |


### test_acl_egress_l2.py — egress ACL chip-programming verification (the ingress L3 + L2/MAC dimensions are covered by test_acl_chip.py).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_acl_egress_capability_present | 1 | STATE_DB exposes egress capability (action_list=PACKET_ACTION) -- the hardware precondition for egress ACL to be viable. |
| test_acl_egress_table_in_asic | 1 | egress L3 table + rule -> assert ASIC SAI_ACL_TABLE truly grows (egress-stage chip programming). |
| test_acl_egress_l3_rule_in_asic | 1 | egress L3 rule (IP_PROTOCOL/L4_DST_PORT + DROP) -> assert an ASIC SAI_ACL_ENTRY appears carrying |
| test_acl_egress_drop_dataplane | 1 | egress L3 DROP rule dataplane hit (real end-to-end traffic, mirroring |


### test_acl_fields.py — ACL field-level + counter + action coverage (per-field approach modeled on community sonic-mgmt acl/test_acl.py).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_acl_user_table_programs_to_asic | 1 | After building a user L3 ACL table via a valid CLI + programming one rule through CONFIG_DB, the ASIC's ACL_ENTRY count should grow. |
| test_acl_l3_field | 1 | L3(IPv4) ACL per field: build a rule matching that field, verify the ASIC ACL_ENTRY really carries the corresponding SAI field. |
| test_acl_mac_field | 1 | MAC(L2) ACL per field: build a rule matching that field, verify the ASIC ACL_ENTRY really carries the corresponding SAI field. |
| test_acl_rule_has_counter | 1 | After programming, a rule with a counter: the ASIC ACL_ENTRY has ACTION_COUNTER + points to an existing ACL_COUNTER object. |
| test_acl_counter_in_countersdb | 1 | ACL counter reaches COUNTERS_DB ACL_COUNTER_RULE_MAP (aclshow/stats readable). |
| test_acl_action | 2 | ACL action programming with **action-value verification**: DROP/FORWARD rules land in an ASIC ACL_ENTRY, and that entry's |
| test_acl_l3_drop_dataplane | 1 | L3 DROP rule dataplane hit (inject a matching packet -> aclshow drop count grows). |


### test_acl_full.py — ACL full suite: table type -> ASIC programming + aclshow rendering (bound to real chip state).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_acl_table_type | 1 | Each ACL table type: create + warmup rule -> assert ASIC SAI_ACL_TABLE truly grows (chip programming). |
| test_acl_table_and_aclshow_contract | 1 | L3 table + rule truly programmed to the ASIC (chip-proven), then assert `aclshow` can render that (hardware-programmed) rule. |


## QoS (8 files / 60 functions)


### test_qos_config.py — config->DB contract checks for QoS / buffer / PFCWD / ecnconfig (config + DB only, no traffic).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dscp_to_tc_map_content | 1 | DSCP->TC map programmed exactly into the chip: the map_to_value_list of the ASIC type=DSCP_TO_TC SAI_QOS_MAP must |
| test_dot1p_to_tc_map_content | 1 | dot1p->TC map programmed exactly into the chip: the map_to_value_list of the ASIC type=DOT1P_TO_TC SAI_QOS_MAP must |
| test_tc_to_queue_map_content | 1 | TC->queue map programmed exactly into the chip: the map_to_value_list of the ASIC type=TC_TO_QUEUE SAI_QOS_MAP must |
| test_port_qos_map_references_valid | 1 | Port QoS binding really programmed into the chip: at least one ASIC PORT's SAI_PORT_ATTR_QOS_*_MAP points to a truly |
| test_buffer_pool_content | 1 | Buffer pool really programmed into the chip: the main assertion cross-checks the ASIC SAI_OBJECT_TYPE_BUFFER_POOL's |
| test_buffer_profile_content_and_pool_ref | 1 | Buffer profile really programmed into the chip: the main assertion checks the ASIC SAI_OBJECT_TYPE_BUFFER_PROFILE's |
| test_buffer_pg_and_queue_profile_ref | 1 | PG/queue buffer binding really programmed into the chip: the main assertion checks that the ASIC INGRESS_PRIORITY_GROUP's |
| test_pfcwd_legal_start_accepted | 1 | Legal `config pfcwd start --action drop <port> <detect> --restoration-time <restore>` is accepted |
| test_pfcwd_illegal_rejected | 5 | Illegal PFCWD config must be rejected by the NOS: CLI non-zero rc or CONFIG_DB PFC_WD|<port> not written with bad values, |
| test_ecnconfig_list_profiles | 1 | WRED/ECN profile list really programmed into the chip: every WRED_PROFILE listed by `ecnconfig -l` must be reflected as a |
| test_ecnconfig_legal_modify_updates_db | 1 | Legal `ecnconfig -p <profile> -gmin <v> -gmax <v>` changes WRED params -> CONFIG_DB WRED_PROFILE updates, |
| test_ecnconfig_illegal_value_rejected | 1 | Illegal WRED params (non-numeric threshold) must be rejected: ecnconfig non-zero rc or CONFIG_DB unchanged, and no traceback. |
| test_buffer_profile_illegal_size_rejected | 1 | Configuring an illegal size (non-numeric) on a BUFFER_PROFILE -> must be rejected by the NOS (CLI non-zero rc or CONFIG_DB |


### test_qos_full.py — QoS full set: classification (dot1p/dscp/acl) + scheduling (SP/WRR/DWRR) + shaping + WRED + remark + DCB (PFC/ECN).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_qos_object_programmed | 1 |  |
| test_pfc_config | 1 | PFC asymmetric on -> ASIC port SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE changes from COMBINED to SEPARATE |
| test_ecn_config | 1 | ECN marking really programmed into the chip: the ASIC should have a SAI_OBJECT_TYPE_WRED object carrying a valid |
| test_running_config_round_trips_qos_section | 1 | Program a known QoS config item (SCHEDULER) into CONFIG_DB -> it must both round-trip into |


### test_qos_pfcmaps_chip.py — Programming-chain verification of the three core lossless maps -- TC_TO_PRIORITY_GROUP /

| Case | Expansions | Purpose |
|------|:---:|------|
| test_tc_to_pg_map_content_to_asic | 1 | Pair-by-pair programming of the TC->PG map: create {TC3->PG3}, and the ASIC must |
| test_pfc_prio_to_queue_map_content_to_asic | 1 | Pair-by-pair programming of the PFC priority->queue map: {prio3->queue3}. |
| test_pfc_prio_to_pg_map_content_to_asic | 1 | Pair-by-pair programming of the PFC priority->PG map: {prio3->pg3}. Precondition as above (not applicable when no product CLI). |
| test_port_qos_binding_attrs_not_dangling | 1 | Upgraded port QoS binding-attribute integrity check: every non-empty QOS_*_MAP |


### test_qos_referential_integrity.py — QoS config **referential integrity**: dangling references must be refused at the CLI layer and must not exist in the DB.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ri1_pg_bind_to_missing_profile_refused | 1 | RI1: binding a lossless PG to a non-existent profile must be refused and not persisted. |
| test_ri2_port_qos_map_missing_map_refused | 1 | RI2: a port-qos-map referencing a non-existent mapping table must be refused. |
| test_ri3_port_queue_missing_scheduler_refused | 1 | RI3: a port-queue referencing a non-existent scheduler / wred must be refused. |
| test_ri4_port_qos_map_missing_scheduler_refused | 1 | RI4: the port-level scheduler reference in port-qos-map must be validated too. |
| test_ri5_delete_referenced_profile_refused | 1 | RI5: deleting a profile still referenced by a PG must be refused -- otherwise a single |
| test_ri6_buffer_profile_has_no_pool_option | 1 | RI6: `buffer profile add` should not offer `--pool` -- that option would hand the |
| test_ri7_no_cli_to_delete_a_referenced_pool | 1 | RI7: there should be no CLI that can delete an in-use buffer pool -- the moment the |
| test_ri8_no_dangling_pool_reference_in_config | 1 | RI8 **read-only guard**: every `BUFFER_PROFILE.pool` must point at a `BUFFER_POOL` |
| test_ri9_no_unmodelled_qos_map_tables | 1 | RI9 **read-only guard**: a QoS mapping table the platform does not model must not |


### test_qos_remark_chip.py — QoS classification/remark chip-behavior verification -- not just verifying CONFIG_DB/ASIC maps exist, but sending real traffic to verify queue selection + egress marking.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dscp_to_tc_map_programmed_to_asic | 1 | ASIC should have a type=DSCP_TO_TC SAI_QOS_MAP whose map_to_value_list maps at least one DSCP to a non-zero TC |
| test_tc_to_queue_map_programmed_to_asic | 1 | ASIC should have a type=TC_TO_QUEUE SAI_QOS_MAP (proving TC->queue assignment really programmed into the chip). |
| test_traffic_enters_an_egress_queue | 1 | Dataplane sanity: inject a plain IP packet, verify some egress queue's SAI_QUEUE_STAT_PACKETS on ports[0] really increments >=0.5N. |
| test_dscp_selects_distinct_egress_queue | 1 | DSCP queue selection: inject DSCP=0 and DSCP=ef traffic separately, verify they land on |
| test_dscp_steers_to_nonzero_queue | 1 | Per-DSCP queue-steering verification: inject high-priority DSCP traffic, verify its main |
| test_pcp_selects_distinct_egress_queue | 1 | PCP queue selection: inject PCP=0 and PCP=7 802.1Q tagged frames, verify they land on |
| test_dscp_preserved_on_l2_forward_egress | 1 | DSCP egress content check: inject a frame with DSCP, forward it out ports[0] (re-enter then |


### test_qos_sched_chip.py — Chip-level attribute correctness of QoS scheduling/buffering (filling gaps left by test_qos*/test_stats_full).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_scheduler_attrs_valid | 1 | Each ASIC SCHEDULER's scheduling_type must be a valid enum (STRICT/DWRR/WRR); weighted types |
| test_scheduler_has_strict_and_weighted | 1 | A typical SONiC QoS profile programs both strict (SP) and weighted (WRR/DWRR) schedulers -- verifies |
| test_queue_attrs_valid | 1 | Each ASIC QUEUE has a valid type (UCAST/MCAST/ALL), index in [0,15], and PORT pointing to a real existing port object. |
| test_frontpanel_multicast_queue_structure | 1 | Front-panel port multicast-queue modeling coverage: each front-panel port should have unicast queues (index 0..k-1) + |
| test_queue_bound_to_scheduler | 1 | Queues bound to schedulers: at least some QUEUE objects' SCHEDULER_PROFILE_ID points to a real existing |
| test_wred_profile_attrs_valid | 1 | Each ASIC WRED: at least one color enabled; for that color max_threshold>min_threshold (>0); |
| test_buffer_pool_attrs_valid | 1 | Each ASIC BUFFER_POOL: type in {ingress,egress,both}, size>0, valid threshold_mode enum. |
| test_buffer_profile_attrs_and_pool_ref | 1 | Each ASIC BUFFER_PROFILE: POOL_ID points to a real existing BUFFER_POOL (not dangling); buffer_size is a non-negative integer; |
| test_ingress_pg_bound_to_buffer_profile | 1 | Ingress priority groups (IPG) bound to a buffer profile: at least some INGRESS_PRIORITY_GROUP objects' |
| test_pfc_priority_enable_programs_asic | 1 | Enable several PFC priorities on a port -> the ASIC port object's SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL |
| test_scheduler_weight_change_reflects_asic | 1 | Change a CONFIG_DB SCHEDULER's weight -> orchagent programs the new weight to the ASIC SCHEDULER's |
| test_egress_queue_counter_increments | 1 | Loopback traffic -> some SAI_QUEUE_STAT_PACKETS on the injection port ports[0]'s own egress queue |


### test_qos_shaper_chip.py — Scheduler/shaper value-chain validation -- CONFIG_DB -> ASIC_DB -> SDKLT TM chip table (layer 4).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_scheduler_weight_chain_to_chip | 1 | DWRR weight full chain: CONFIG(weight=77) -> ASIC SCHEDULING_WEIGHT=77 -> |
| test_shaper_pir_chain_units_to_chip | 1 | shaper value+unit full chain (the incident's root-cause dimension, previously zero |
| test_shaper_cir_zero_means_no_cap | 1 | cir=0 / no-pir semantics: chip MIN/MAX_BANDWIDTH_KBPS both 0 = no rate limit (locking |
| test_bound_queue_shapers_meet_linerate_lint | 1 | Incident detector (read-only lint, changes no config): walk the SCHEDULER bound to each |
| test_sp_wrr_whole_port_pattern_to_chip | 1 | Whole-port scheduling template full chain ("q7 SP, q0~6 WRR each weighted" pattern): |
| test_wrr_vs_dwrr_port_mode_flag_to_chip | 1 | WRR/DRR distinguishing bit full chain: bind DWRR to a queue -> port WRR flag=0 (WERR |
| test_shaper_only_rebind_replaces_sp_on_chip | 1 | "pure shaping profile clobbers SP" semantics lock-in (a common human root cause of "SP |
| test_chip_threshold_mode_visible | 1 | Global TM threshold mode readability + valid domain (LOSSY / LOSSY_AND_LOSSLESS). In a |


### test_queue_crm.py — Queue/PG/buffer-pool watermark and drop-reason counters -- real-traffic driven, verifying true chip values increment.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_queue_counters_show | 1 | Queue counters increment with real traffic: inject N known unicast frames on the already-looped |
| test_pg_watermark_moves_on_traffic | 1 | PG watermark moves with real traffic: after injecting N frames, some PG on the injection port |
| test_dropcounters_reason_delta | 1 | drop-reason counters increment with malformed frames: install a PORT_INGRESS_DROPS=SMAC_EQUALS_DMAC |


## CoPP/punt (4 files / 25 functions)


### test_copp.py — Trap / CoPP: protocol packets punted to CPU.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_lldp_trap_to_cpu | 2 | LLDP multicast frames should be punted to CPU, captured inbound on the ingress port netdev. |
| test_arp_request_trap | 1 | Broadcast ARP requests should be punted to CPU (for ARP learning/response). |


### test_copp_dataplane_chip.py — CoPP dataplane + chip behavior: drive real protocol packets per trap type, verifying it truly punts to the CPU.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_l2_trap_to_cpu | 1 | L2/protocol trap dataplane + chip-programming dual evidence (should PASS): |
| test_l2_traps_share_one_loopback_no_storm | 1 | Smoke protection: L2 trap cases share a single-port loopback path; injecting N broadcast ARP frames |
| test_non_trap_not_punted | 1 | Negative-control review: across the CoPP dataplane suite there was only "what should arrive arrives", |


### test_copp_full.py — CoPP all trap types: HOSTIF_TRAP present + CoPP config + punt of generatable trap traffic.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_hostif_trap_objects_present | 1 | ASIC should install a batch of HOSTIF_TRAP (CoPP traps). |
| test_hostif_trap_group_present | 1 |  |
| test_copp_config_present | 1 | CoPP truly takes effect **to the chip**: STATE_DB COPP_TRAP_TABLE/CONFIG_DB has trap config (coppmgrd applied), |
| test_copp_trap_type_known | 1 | Each generic trap type: if **this device's profile declares it expected**, assert it is truly programmed as an ASIC HOSTIF_TRAP |
| test_all_trap_groups_have_policer | 1 | Every (non-default) trap-group is bound to a policer -- CoPP rate limiting is in effect for all user groups (covers all trap-groups). |
| test_all_copp_policers_valid_rate | 1 | Every CoPP policer has a valid CIR (real rate limit, non-zero). |
| test_all_traps_mapped_to_group | 1 | Every trap-id maps to an existing trap-group + has a packet action (covers all trap-ids, no dangling). |
| test_statedb_traps_reflected_in_asic | 1 | **Every** trap installed in STATE_DB COPP_TRAP_TABLE maps one-by-one to an ASIC HOSTIF_TRAP (control plane -> data plane, |
| test_copp_trap_id_installed | 1 | Every enabled trap-id is installed into STATE_DB COPP_TRAP_TABLE (coppmgrd applied), |
| test_copp_asic_trap_topology | 1 | Every installed ASIC HOSTIF_TRAP is **structurally** correct in topology (device-agnostic): |
| test_copp_trap_groups_complete | 1 | All (non-default) trap-groups are structurally complete: valid queue (0-7) + bound policer + CIR>0 + CBS>0 (covers all groups). |
| test_copp_rate_tiers | 1 | Validates the (queue, CIR) rate tiers of each (non-default) CoPP trap-group. |
| test_trap_to_cpu | 1 | FP-match class trap data plane: inject protocol packet -> loopback re-ingress -> hit trap -> punt to CPU (matched by unique src MAC). |


### test_copp_policer.py — CoPP rate-limiting (policer) + supplementary statistics coverage: config -> ASIC POLICER object/attributes, actual rate-limiting (optional traffic), per-trap stats.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_copp_policer_config_wellformed | 1 | A CoPP group's rate-limit value with cir should **really land on an ASIC POLICER object**: config-side cir/cbs are well-formed, |
| test_copp_policer_asic_object | 1 | CoPP's cir/cbs should be instantiated by orchagent into an ASIC SAI_OBJECT_TYPE_POLICER object (verified to the chip). |
| test_copp_policer_asic_cir_cbs_attrs | 1 | Every ASIC POLICER object should carry SAI_POLICER_ATTR_CIR/CBS (rate-limit params really reached the chip). |
| test_copp_trap_group_bound_to_policer | 1 | A CoPP trap_group should bind to a POLICER via SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER. |
| test_copp_policer_rate_enforced | 1 | CoPP policer dataplane rate-limiting really takes effect (the dataplane regression at this suite's core purpose): |
| test_copp_per_trap_counters_exposed | 1 | Verify the **content** exposed by per-trap stats: every COUNTERS:<oid> really carries SAI_COUNTER_STAT_PACKETS/BYTES |
| test_copp_per_trap_counter_increments | 1 | After sending ARP to CPU, the **arp-specific** per-trap count should increment by the injected amount (exact attribution). |


## Mirroring/sampling (5 files / 15 functions)


### test_mirror.py — Mirror: SPAN / ERSPAN session creation -> CONFIG_DB / ASIC_DB.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_span_session_create | 1 | Local SPAN session: config-plane contract (CONFIG_DB) + **data-plane check: programmed into ASIC SAI_MIRROR_SESSION**. |
| test_erspan_session_create | 1 | ERSPAN: encapsulate to remote <name> <src_ip> <dst_ip> <dscp> <ttl> <gre> <queue>. |


### test_mirror_chip.py — Mirror chip-behavior verification: local SPAN (ingress/egress) mirror copies + ERSPAN GRE encap + truncation length.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_span_ingress_copies_to_destination | 1 | SPAN ingress (rx): inject N frames on the monitored source port -> the chip should mirror a full copy to the destination port. |
| test_span_egress_copies_to_destination | 1 | SPAN egress (tx): the egress frames of the monitored source port should be mirrored to the destination port. |
| test_span_remove_stops_copies | 1 | Negative control: after `mirror_session remove`, mirror copies must stop. |
| test_erspan_gre_encap_to_collector | 1 | ERSPAN: the session points at a locally-reachable collector IP, and monitored-port traffic should be GRE/ERSPAN-encapsulated and sent to the collector. |
| test_span_truncation_shortens_copy | 1 | Mirror truncation length: configure truncate_size on the SPAN session, inject a large |


### test_sflow.py — sFlow: global/interface enable -> CONFIG_DB; sampling punt is Pattern A (add traffic once the collector is ready).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_sflow_enable | 1 | config sflow enable -> CONFIG_DB write **and sflowmgrd propagates the state to APPL_DB**. |
| test_sflow_show | 1 | config sflow enable -> CONFIG_DB admin_state=up, and the sflow service must really be running for sFlow to be effective. |


### test_sflow_chip.py — **Chip-level** verification of sFlow sampling (distinct from test_sflow.py which only

| Case | Expansions | Purpose |
|------|:---:|------|
| test_sflow_chip_samplepacket_programmed | 1 | Global + interface enable sFlow + set sample rate -> ASIC_DB actually shows a SAI_SAMPLEPACKET whose SAMPLE_RATE matches config. |
| test_sflow_chip_port_ingress_bound | 1 | An enabled interface's SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE is bound to a valid SAMPLEPACKET OID. |
| test_sflow_samplepacket_trap_present | 1 | The sample_packet HOSTIF_TRAP should be installed on the ASIC -- the hardware trap path that punts sampled copies to the CPU is present. |
| test_sflow_chip_rate_update_and_disable | 1 | Change the rate at runtime -> the bound session's SAI SAMPLE_RATE follows; interface disable -> the port unbinds back to oid:0x0. |
| test_sflow_chip_sample_rate_dataplane | 1 | Inject a fixed burst on a looped-back port and verify the chip really produces ~burst/rate samples at the configured low rate (1/256). |


### test_sflow_traffic.py — sFlow: sample data-plane traffic -> the local collector receives a flow sample with the probe signature.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_sflow_samples_to_collector | 1 | Low-rate sampling + a fixed known-unicast injection -> the collector (lo) receives flow samples of the same order of magnitude as the rate. |


## Counters/telemetry (9 files / 40 functions)


### test_counters_chip.py — Counter **accuracy** test set -- not "count > 0 passes" but "send N packets, count is exactly +N".

| Case | Expansions | Purpose |
|------|:---:|------|
| test_port_tx_counter_exact | 1 | Port TX exact counting: send N frames on the looped ports[0]; chip MAC TX (MIB_TPKT) should be **exactly +N** |
| test_port_rx_counter_exact | 1 | Port RX exact counting: send N frames that re-enter via MAC loopback; chip MAC RX (MIB_RPKT) should be **exactly +N**. |
| test_port_rx_scales_with_count | 1 | Counter linearity: send two batches N1, N2 in a row; RX deltas should be exactly ~N1, ~N2 respectively (counter is linear with injected amount, no saturation, no duplication). |
| test_sai_port_counter_exact | 1 | SAI COUNTERS_DB port count accuracy: send N unicast frames, expect SAI |
| test_per_queue_counter_exact | 1 | Per-queue exact counting: N frames with the same dot1p/TC egress ports[0], all landing in the same egress queue -> |
| test_drop_reason_counter_exact | 1 | drop-reason exact attribution counting: install a PORT_INGRESS_DROPS=SMAC_EQUALS_DMAC counter, inject N |


### test_crm.py — CRM resource usage: batch-drive N real resources → CRM used actually grows ~N + ASIC_DB SAI objects grow ~N in sync.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_crm_ipv4_route_used_grows_with_n_routes | 1 | Batch routes drive CRM ipv4_route used linear growth: install one resolved next hop on an |
| test_crm_ipv4_neighbor_used_grows_with_n_neighbors | 1 | Batch neighbors drive CRM ipv4_neighbor used linear growth: configure N static neighbors |
| test_crm_fdb_used_grows_with_n_entries | 1 | Batch static FDB drives CRM fdb_entry used linear growth: write N static FDB entries with |


### test_crm_chip.py — Consistency closed loop between CRM resource counts and **actual chip occupancy**.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_crm_used_plus_available_is_capacity | 3 | CRM resource-accounting invariant + real-occupancy accounting: after injecting one real resource, used **really +1**, capacity (used+available) unchanged. |
| test_crm_route_used_matches_asic_route_count | 1 | ipv4_route: add one static route -> CRM used +1 and ASIC_DB ROUTE_ENTRY count +1 (consistent), |
| test_crm_neighbor_used_matches_asic_neighbor_count | 1 | ipv4_neighbor: add one static neighbor -> CRM used +1 and ASIC_DB NEIGHBOR_ENTRY count +1 (consistent), |
| test_crm_nexthop_used_matches_asic_nexthop_count | 1 | ipv4_nexthop: a neighbor + a route through it makes a nexthop land -> CRM used +1 and ASIC_DB NEXT_HOP count +1, |
| test_crm_fdb_used_matches_asic_fdb_count | 1 | fdb_entry: write one static FDB (swssconfig -> APPL_DB -> fdborch -> ASIC) -> CRM used +1 and |
| test_crm_route_threshold_crossing_raises_state | 1 | Threshold crossing: add a route so used really grows (ASIC ROUTE_ENTRY growing in sync proves real occupancy), straddle the |


### test_crm_thresholds.py — CRM increment driving + threshold-alarm closed loop (adapted from sonic-mgmt tests/crm/).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_crm_ipv4_route_threshold_closed_loop | 1 | ipv4_route full closed loop: ip route add -> used+1 -> threshold EXCEEDED/CLEAR -> route del -> used falls back. |
| test_crm_ipv4_neighbor_threshold_closed_loop | 1 | ipv4_neighbor full closed loop: ip neigh replace -> used+1 -> threshold EXCEEDED/CLEAR -> neigh del -> fall back. |
| test_crm_ipv4_nexthop_increment | 1 | ipv4_nexthop increment: neighbor+route lands one nexthop -> used+1 -> delete -> fall back. |
| test_crm_nexthop_group_increment | 1 | nexthop_group increment: one ECMP route (two neighbors) -> forms a nexthop group -> used+1 -> delete -> fall back. |


### test_dynamic_entries.py — Chip entry coverage (part 3): traffic/protocol-driven dynamic entry programming.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dynamic_fdb_learning | 1 | Source MAC learning (**real-traffic driven**): after sending real frames, the ASIC shows a dynamic |
| test_dynamic_arp_neighbor | 1 | ArpResponder emulates the peer -> DUT ping triggers ARP -> dynamic neighbor NEIGHBOR_ENTRY learned. |


### test_gnmi.py — gNMI / telemetry: Capabilities RPC + container present + sampling period really effective (COUNTERS_DB advances over time).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_gnmi_get_capabilities | 1 | gNMI Capabilities RPC really effective: issue one Capabilities to the running gNMI server and assert a structured |
| test_telemetry_container_running | 1 | telemetry/gnmi daemon really effective: container/process/port present (precondition), then issue a **real gNMI Get RPC** |
| test_flex_counter_polls_and_disable_freezes | 1 | flex counter polling really effective + the switch really consumed (the old name interval_configurable was a misnomer -- |
| test_gnmi_streaming_subscribe | 1 | gNMI STREAM subscribe really effective: issue a short-duration (~8s) STREAM/SAMPLE subscribe to the running gNMI server |


### test_port_counters.py — Port counters: chip and SAI counts grow with real traffic (Pattern B fast smoke layer).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_chip_counter_increments | 1 | Chip RX count grows with loopback traffic: clear -> inject N -> polled accumulate + |
| test_sai_counter_tracks_loopback | 1 | SAI COUNTERS_DB count grows with loopback traffic: send N frames, SAI RX(total) falls |


### test_port_counters_full.py — Full port traffic counter set: RX/TX_OK, ERR, DRP, broadcast/multicast/unicast classification, frame-length buckets, utilization.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_show_interfaces_counters_columns | 1 | `show interfaces counters` column headers exist + real traffic reaches the chip (binary assertion, no xfail). |
| test_counters_db_sai_fields_exist | 1 | COUNTERS_DB port counters: verify each SAI field exists + SAI IF_IN_UCAST_PKTS delta truly follows the injected volume. |
| test_broadcast_counter_increments | 1 | Broadcast frames grow the broadcast classification counter (SAI_PORT_STAT_IF_IN_BROADCAST_PKTS) -- not just total RX. |
| test_clear_counters | 1 | `sonic-clear counters` resets the show-interfaces-counters display baseline (true reset semantics). |


### test_stats_full.py — End-to-end coverage of statistics (counters): configure/send traffic -> verify real chip values, not just that commands don't crash.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_queue_name_map_present | 1 | COUNTERS_QUEUE_NAME_MAP is non-empty and its keys look like `<port>:<q>`, values are queue oids (true readiness marker). |
| test_queue_counters_db_fields_exist | 1 | Some port's queue0 COUNTERS hash contains SAI_QUEUE_STAT_* fields (proving queue counters are actually collected). |
| test_queue_packets_increment_on_traffic | 1 | Loopback traffic: inject known unicast on the already-looped ports[0]. The CPU-injected frame **egresses |
| test_pg_name_map_present | 1 | COUNTERS_PG_NAME_MAP is non-empty and its values are PG oids (PG watermark flex counter readiness marker). |
| test_pg_watermark_headroom_show_numeric | 1 | `show priority-group watermark headroom` emits a parseable numeric table (each PG column is an integer), |
| test_dropcounters_capabilities_numeric | 1 | `show dropcounters capabilities` emits real numbers (supported drop counter types and available slot count > 0), |
| test_debug_drop_counter_install_and_program | 1 | After configuring a debug drop counter, verify it lands in the DB + inject **malformed frames** to verify the |
| test_rif_counters_registered_for_l3_interface | 1 | RIF stats **registration**: after configuring an IP on a port (creating a RIF), COUNTERS_RIF_NAME_MAP must |
| test_rif_counters_advance_on_l3_traffic | 1 | RIF stats **measured with traffic**: send L3 traffic on a real layer-3 port, |


## Tunneling (2 files / 5 functions)


### test_vxlan_chip.py — VXLAN chip-behavior verification: VTEP + VNI<->VLAN map really program to ASIC, and the dataplane really encaps/decaps.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vtep_programs_asic_tunnel | 1 | VTEP creation -> ASIC_DB shows SAI_OBJECT_TYPE_TUNNEL (the tunnel object really programs to the chip). |
| test_vlan_vni_map_programs_asic_tunnel_map | 1 | VLAN<->VNI map -> ASIC_DB shows SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY (the VNI mapping really programs to the chip). |
| test_vxlan_encap_to_remote_vtep | 1 | Dataplane ENCAP: a VLAN member port's overlay frame -> DUT encaps it as VXLAN/UDP(4789) to the remote VTEP. |
| test_vxlan_decap_to_local_member | 1 | Dataplane DECAP: inject a VXLAN frame with dst=local VTEP IP -> DUT decapsulates -> the inner frame goes to the VNI's VLAN local member port. |


### test_vxlan_full.py — VXLAN full set: L3VNI (VRF<->VNI) ASIC mapping + encap/decap data-plane localization.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vrf_vni_mapping | 1 | L3VNI: VRF<->VNI mapping -> an **attribute-exact-match** SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY appears in ASIC_DB. |


## Platform/system management (17 files / 98 functions)


### test_aaa.py — AAA: TACACS+ / RADIUS server config + client-reachability verification.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_tacacs_config | 1 | TACACS+: lands in CONFIG_DB + **hostcfgd actually renders** to NSS/PAM (/etc/tacplus_nss.conf), proving the daemon consumed the |
| test_radius_config | 1 | RADIUS: lands in CONFIG_DB + **hostcfgd actually renders** to /etc/pam_radius_auth.conf (evidence the daemon consumed it). |
| test_aaa_authentication_order | 1 | AAA authentication order: CONFIG_DB AAA table + **hostcfgd actually renders** PAM (/etc/pam.d/common-auth-sonic contains tacplus). |


### test_auto_techsupport.py — AUTO_TECHSUPPORT feature tests: global/per-feature config <-> show consistency, enable/disable toggle really takes effect, and end-to-end verification of the trigger mechanism (core_pattern pipe + coredump_gen_handler consuming state + dump package structure).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_global_config_matches_show | 1 | `show auto-techsupport global` columns == corresponding CONFIG_DB AUTO_TECHSUPPORT|GLOBAL fields, compared field by field. |
| test_feature_config_matches_show | 1 | Each `show auto-techsupport-feature` row == CONFIG_DB AUTO_TECHSUPPORT_FEATURE|<name> fields, compared feature by feature. |
| test_global_state_toggle | 1 | `config auto-techsupport global state <enabled|disabled>` truly changes CONFIG_DB state and show tracks it, |
| test_coredump_trigger_wiring | 1 | End-to-end real verification of the auto-techsupport trigger path (the old implementation |
| test_existing_dump_structure | 1 | techsupport-generated package has a sane structure (containing dump/ + log/ + CONFIG_DB.json). |
| test_history_matches_state_db | 1 | `show auto-techsupport history` <-> STATE_DB AUTO_TECHSUPPORT* records match one by one. |


### test_config_wired.py — CLI coverage: `--help` for every `config` command that *actually exists* on this image must work (command is wired), without actually changing config.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_config_wired | 1 |  |


### test_dhcp_relay.py — DHCP relay: client broadcasts DISCOVER -> DUT relay adds option-82/giaddr and forwards to a local mock server.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dhcp_relay_option82 | 1 |  |


### test_gcu.py — GCU (generic_config_updater) ported cases (adapted from sonic-mgmt generic_config_updater/).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_gcu_static_route_crud | 1 | patch adds a static route -> verify it lands in CONFIG_DB + **the route is really installed in the FRR RIB** (show ip route), then patch removes it -> verify it disappears. |
| test_gcu_static_route_invalid_rejected | 1 | A patch with an invalid prefix should be rejected by GCU (the NOS does not accept invalid config -- negative verification). |
| test_gcu_syslog_server_crud | 1 | patch adds a SYSLOG_SERVER -> verify it lands in CONFIG_DB + **rsyslog really renders it** (the server's forwarding target IP appears in /etc/rsyslog.conf or |
| test_gcu_dns_nameserver_crud | 1 | patch adds/removes DNS_NAMESERVER -> verify CONFIG_DB + /etc/resolv.conf take effect. |
| test_gcu_loopback_ip_add | 1 | patch adds an IP to Loopback0 -> verify it appears in show ip interfaces; rollback restores it (the fixture handles it). |
| test_gcu_rollback_restores_baseline | 1 | Add a route then immediately rollback, verifying CONFIG_DB is restored to the checkpoint baseline (isolation correctness). |


### test_lldp.py — LLDP functional verification -- filling the "zero functional coverage" gap (previously only SNMP LLDP-MIB OID corroboration).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_lldpd_daemon_healthy | 1 | lldp container is up + both lldpd and lldpmgrd are RUNNING under supervisorctl. |
| test_local_chassis_matches_device | 1 | The local ChassisID reported by lldpcli is a stable, unique MAC on the device, and SysName == hostname. |
| test_local_ports_exposed | 1 | The physical ports under test (taken dynamically from dut) appear in lldpd's interface list. |
| test_self_loop_neighbor_discovery | 1 | Single-box self-loop trick to verify "PDU actually transmitted + neighbor discovery": the traffic fixture has already |
| test_lldp_tx_counter_increments | 1 | LLDP should transmit periodically on the looped-back (oper-up) port: sample TX -> wait one tx-interval -> sample again, |


### test_platform_pmon_chain.py — Full-chain platform fault injection (mock BMC -> real sync daemon -> real cache

| Case | Expansions | Purpose |
|------|:---:|------|
| test_s5_sentinel_voltage_not_zero | 1 | Dead-sensor sentinel -99999 must be reported as N/A, not 0.0 (0.0 trips a psud |
| test_s9_sensor_vanish_row_must_not_freeze | 1 | When the BMC stops reporting OcmBoard at runtime, the row must update to N/A rather than freezing forever as stale/dead data (value and timestamp). |
| test_s7_fan_key_vanish_must_not_kill_thermalctld | 1 | The BMC dropping the FAN1 key at runtime must not kill the whole thermalctld. |
| test_s6_fan_zero_maxspeed_not_reported_faulty | 1 | With SpeedMax=0, a spinning fan must not be silently reported as 0%/Not OK (otherwise a false fault, amber LED, and an inflated faulty count). |
| test_s1_sync_crash_must_be_restarted | 1 | After the sync daemon crashes, systemd must bring it back up (Restart=on-failure). |
| test_b1_sync_survives_bmc_refused | 1 | When the BMC refuses connections, the sync daemon should skip the cycle rather than crash out. |
| test_b2_sync_survives_malformed_json | 1 | The sync daemon should survive the BMC returning malformed JSON. |
| test_w1_setspeed_reaches_bmc_bounded | 1 | Fan set-speed is pushed to the BMC through the platform API -- verify the request |
| test_s8_partial_sensor_boot_must_not_kill_daemons | 1 | Booting while the BMC is missing the single OcmBoard key must not kill pmon daemons at startup. |
| test_s2_corrupt_cache_boot_must_not_kill_daemons | 1 | Booting onto a power-loss-corrupted cache (truncated JSON) must not kill daemons at startup; the sync daemon rewrites a good cache within 10s. |
| test_s4_minmax_not_poisoned_by_empty_boot_window | 1 | A pmon started during a cache-empty window must recover real temperature readings once the BMC/cache are ready. |


### test_platform_pmon_health.py — Platform pmon health checks (read-only, no injection): detect field signatures of "a defect happening on this device".

| Case | Expansions | Purpose |
|------|:---:|------|
| test_pmon_daemons_alive | 1 | Critical pmon daemons must not be in FATAL/EXITED/STOPPED (field signature of the startup-death family). |
| test_sync_unit_not_zombie | 1 | The sync daemon unit must not "play dead": active(exited) with no live process = crashed and never restarted. |
| test_bmc_cache_fresh | 1 | The cache file must be fresh: both mtime and content timestamp should be within 6x the sync period (10s). |
| test_temperature_rows_fresh_not_frozen | 1 | Temperature rows must be updating and not all N/A: all-N/A + a stalled timestamp is treated as a fault. |
| test_psu_detail_fields_present | 1 | PSU rows with presence=true must carry detail fields: missing model/voltage = psud has fallen back to 1.0. |
| test_configured_thermal_sensors_all_reported | 1 | Every sensor declared in the platform thermal config should have a TEMPERATURE_INFO row (missing-key detection). |
| test_fan_rows_not_collapsed_by_duplicate_names | 1 | FAN_INFO row count must not collapse due to duplicate fan names. |


### test_platform_sensors.py — Platform fan / PSU (pmon) sensor read-only cases ([A] pure show ↔ STATE_DB consistency, no traffic; cli domain).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_fan_presence_status_matches_db | 1 | Each FAN_INFO's presence/status matches its corresponding `show platform fan` row item by item. |
| test_fan_speed_reasonable_and_matches_db | 1 | `show platform fan` speed compared with STATE_DB FAN_INFO.speed (tolerance) and within a reasonable range (>0 and < upper limit). |
| test_psu_presence_status_matches_db | 1 | Each PSU_INFO's presence/status matches its corresponding `show platform psustatus` row. |
| test_psu_electrical_values | 1 | PSU voltage/current/power compared with STATE_DB (tolerance) and within a reasonable range. |
| test_voltage_current_sensors | 1 | If VOLTAGE_INFO/CURRENT_INFO sensors exist: values are valid numbers within threshold range, and compared with show where possible. |
| test_sensor_data_freshness | 1 | pmon sensor data must keep refreshing: FAN/PSU/TEMPERATURE_INFO timestamps should advance |


### test_show_commands.py — CLI coverage: run every `show` command on the DUT, asserting it doesn't crash (no Python Traceback).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_show_no_crash | 1 |  |


### test_snmp_mibs.py — SNMP MIBs: v2c/v3, RFC1213, IF-MIB, ifXTable, Q-BRIDGE, LLDP-MIB, ENTITY, HOST-RES.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_snmp_v2c_reachable | 1 | snmpd really in effect: compare sysDescr against DB ground truth (CONFIG_DB hwsku / build version), not just checking that output contains STRING. |
| test_snmp_mib_oid | 1 | Each OID: first verify it can be walked (presence), then compare against DB ground truth via _VALIDATORS. |
| test_snmp_v3_user_config | 1 | SNMP v3 user: written to CONFIG_DB + snmpd really serves v3 authentication (an authNoPriv snmpget with that user succeeds), |


### test_snmp_mibs_full.py — SNMP MIB value-vs-DB broad coverage (drawn from sonic-mgmt tests/snmp/ + snmp_facts.py DefineOid).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_snmpv2_sysDescr_contains_hwsku_kernel | 1 | sysDescr should contain HwSku / Kernel / version substrings (vs CONFIG_DB hwsku + uname -r). |
| test_snmpv2_sysName_vs_hostname | 1 | sysName should equal hostname (CONFIG_DB DEVICE_METADATA.hostname / `hostname`). |
| test_snmpv2_sysObjectId_is_oid | 1 | sysObjectId should be an OID under the enterprises subtree, compared against known |
| test_snmpv2_sysUpTime_positive_and_grows | 1 | sysUpTime should be a positive TimeTicks and grow monotonically between two samples (proving the agent is really running). |
| test_snmpv2_sysContact_and_sysLocation_present | 1 | sysContact / sysLocation should have values (SONiC defaults injected by snmp.yml; vs CONFIG_DB if configured). |
| test_ifmib_ifNumber_matches_port_count | 1 | ifNumber should **exactly equal** the real IF-MIB ifTable entry count (walk ifDescr and |
| test_ifmib_ifDescr_vs_config_alias | 1 | ifDescr[ifIndex] should equal the port's CONFIG_DB alias (SONiC uses alias as ifDescr/ifName). |
| test_ifmib_ifMtu_vs_db | 1 | ifMtu[ifIndex] should equal the STATE_DB (preferred) or CONFIG_DB mtu (default 9100). |
| test_ifmib_ifAdminStatus_vs_db | 1 | ifAdminStatus[ifIndex] (1=up,2=down) should match CONFIG_DB admin_status. |
| test_ifmib_ifOperStatus_vs_state_db | 1 | ifOperStatus[ifIndex] (1=up,2=down) should match STATE_DB oper (netdev_oper_status/oper_status). |
| test_ifmib_ifSpeed_consistent_with_highspeed | 1 | ifSpeed(bps, saturable) and ifHighSpeed(Mbps) should be self-consistent: when not saturated, ifSpeed == ifHighSpeed*1e6. |
| test_ifxtable_ifHighSpeed_vs_config_speed | 1 | ifHighSpeed(Mbps) should equal CONFIG_DB speed(Kbps)/1000. |
| test_ifxtable_ifName_vs_config_alias | 1 | ifName[ifIndex] should equal CONFIG_DB alias (same source as ifDescr). |
| test_ifxtable_ifAlias_vs_config_description | 1 | ifAlias[ifIndex] should equal CONFIG_DB PORT.description; empty here when no description is configured -> skip. |
| test_ifxtable_ifHCInOctets_is_counter | 1 | ifHCInOctets[ifIndex] should grow with **real traffic** (a Counter64 high-capacity byte counter really being sampled, not just checked non-negative). |
| test_ucd_memory_vs_meminfo | 5 | UCD memory counts(kB) vs /proc/meminfo: Total/Swap exact, Free/Buff with tolerance (sampling drift). |
| test_ipforward_default_route | 1 | The ipCidrRouteStatus subtree should contain the default route 0.0.0.0; skip if this image does not expose the MIB. |
| test_entity_chassis_present | 1 | The entPhysicalClass subtree should contain chassis(=3), and entPhysicalName.1 should contain 'chassis'. |
| test_entity_serial_matches_db | 1 | If STATE_DB has a platform EEPROM serial, entPhysicalSerialNum should match; skip if there is no real serial. |
| test_entity_sensor_values_vs_state_db | 1 | entPhySensorValue (scaled to actual temperature by Scale/Precision) should match some |
| test_cisco_fru_psu_status_vs_state_db | 1 | cefcFRUPowerOperStatus should reflect STATE_DB PSU_INFO: not only PSU **count** matching, |
| test_lldp_locChassisId_vs_device_mac | 1 | lldpLocChassisId should be a stable, unique MAC on the device (chassis-id subtype=mac). |
| test_lldp_locSysName_vs_hostname | 1 | lldpLocSysName should equal hostname. |


### test_snmp_ntp.py — SNMP / NTP: config provisioning + reachability verification.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_snmp_community_config | 1 | SNMP community: persisted to CONFIG_DB + **snmpd actually serves the community** |
| test_snmpget_localhost | 1 | When snmpd is present, a local snmpget of sysDescr should be compared against the |
| test_ntp_server_config | 1 | NTP server: persisted to CONFIG_DB + **the NTP daemon actually consumes it** (the |


### test_ssh.py — SSH security suite (all loopback, no external dependencies).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ssh_protocol_version | 1 | sshd OpenSSH version >= 7, and protocol 1 unsupported (modern OpenSSH has fully removed SSH-1). |
| test_ssh_cipher_whitelist | 1 | Only ciphers within sshd's Ciphers whitelist may negotiate; others should get 'no matching cipher found'. |
| test_ssh_mac_whitelist | 1 | Only MACs within sshd's MACs whitelist may negotiate; others should get 'no matching MAC found'. |
| test_ssh_kex_whitelist | 1 | Only KEX within sshd's KexAlgorithms whitelist is allowed; others should get 'no matching key exchange method found'. |


### test_syslog.py — Remote syslog: config syslog pointing at the local collector -> generate a log -> collector receives it (end-to-end).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_remote_syslog_forwarding | 1 |  |
| test_syslog_config_in_db | 1 | config syslog add: (1) CONFIG_DB SYSLOG_SERVER key + (2) **rsyslog really renders a forwarding rule** |


### test_system_mgmt.py — System management: hostname/banner/user/time/config persistence/ping/traceroute/SCP/reboot-cause.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_hostname_config | 1 | hostname: written to CONFIG_DB + **hostcfgd actually applies it to the kernel** (/etc/hostname |
| test_banner_config | 1 | banner: written to CONFIG_DB + **hostcfgd actually renders** the login banner to /etc/issue(.net), |
| test_config_persistence | 1 | Change a specific config value -> `config save` -> the saved json can be **grepped for that value**, |
| test_ping_loopback | 1 |  |
| test_traceroute_available | 1 |  |
| test_reboot_cause | 1 | show reboot-cause vs. **row-by-row comparison against the STATE_DB REBOOT_CAUSE table**: the cause |
| test_user_management_config | 1 | Create a test user -> the user truly appears in /etc/passwd (getent), proving system user management works -> delete to restore. |


### test_transceiver_db.py — Transceiver / SFP read-only tests ([A] pure show <-> STATE_DB consistency, no traffic; cli domain).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_transceiver_info_fields_in_db | 1 | For every port with an optic, STATE_DB TRANSCEIVER_INFO|EthernetX has the key fields. |
| test_transceiver_dom_sensor_values | 1 | For every port with an optic, STATE_DB TRANSCEIVER_DOM_SENSOR|EthernetX has valid numeric sensors. |
| test_show_presence_matches_db | 1 | The Present port set from `show interfaces transceiver presence` agrees with STATE_DB TRANSCEIVER_INFO. |
| test_show_eeprom_matches_db | 1 | `show interfaces transceiver eeprom` yields EEPROM (not 'Not detected') for module-bearing |
| test_show_status_matches_db | 1 | The status fields of `show interfaces transceiver status` agree with the corresponding values in STATE_DB TRANSCEIVER_STATUS. |
| test_platform_temperature_matches_db | 1 | `show platform temperature` sensor readings vs STATE_DB TEMPERATURE_INFO temperature, **compared per sensor**. |
| test_sfputil_show_presence_readonly | 1 | `sfputil show presence` is read-only and does not crash, and its Present set agrees with STATE_DB. |
| test_sfputil_show_eeprom_readonly | 1 | `sfputil show eeprom` is read-only and does not crash, and for module-bearing ports its EEPROM |
| test_sfpshow_eeprom_readonly | 1 | `sfpshow eeprom` is read-only and does not crash, and for module-bearing ports its EEPROM |


## SAI object ledger (2 files / 7 functions)


### test_sai_objects_present.py — Chip table coverage (part 1): core SAI objects programmed at switch init, verified present (>0) in ASIC_DB.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_core_sai_object_present | 1 |  |


### test_sai_objects_triggered.py — Chip table coverage (part 2): SAI objects newly programmed after config/traffic/protocol triggers, verifying the **orchagent->SAI programming chain** actually takes effect (the corresponding object appears in ASIC_DB).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_router_interface_created | 1 | Verify the **connected route** is programmed after configuring an IP (proving the RIF was created). Shares the l3net base: base setup already configures p_in as L3 (IP + loopback held), so this directly verifies its connected route is in the ASIC == the RIF is programmed (if not programmed, the connected route would not be issued). |
| test_neighbor_and_nexthop_created | 1 |  |
| test_route_entry_created | 1 |  |
| test_ecmp_nexthop_group_created | 1 | Dual-nexthop static route -> NEXTHOP_GROUP + member. Shares l3net's two L3 ports p_in/p_out. |
| test_fdb_entry_created | 1 |  |
| test_lag_objects_created | 1 | LAG programming lifecycle: create/program + **delete/reclaim** (the strong create |


## Other (34 files / 154 functions)


### test_breakout_chip.py — DPB dynamic port breakout (1-to-2 / 1-to-4) full-chain verification -- previously zero coverage across the suite.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_br1_split2_full_chain | 1 | BR1 1-to-2 full chain (victim B independent up/down): CONFIG lanes split/speed -> APPL -> |
| test_br2_split4_subports_chain | 1 | BR2 1-to-4: per-subport CONFIG/chip check for the 4 subports (shared base). |
| test_br3_subport_qos_tree_present | 1 | BR3 QoS queue-tree completeness per subport: count that subport's queues via |
| test_br5_subport_l2_forward_traffic | 1 | BR5 subport real forwarding (traffic): two subports with lt loopback + test VLAN + static FDB |
| test_br8_merge_recycles_objects_no_leak | 1 | BR8 merge with no leak (victim B independent up/down): after one split->merge cycle the ASIC |
| test_br9_split_config_persists_to_save | 1 | BR9 persistence: config save the split state to a standalone file (leaving |
| test_br10_invalid_mode_rejected | 1 | BR10 negative: an invalid mode must be rejected and leave config untouched. |
| test_br11_force_flag_matches_help_text | 1 | BR11 `-f` semantic pin: help text says -f = 'Clear all dependencies internally first', so a |
| test_br12_current_mode_truth | 1 | BR12 show current-mode truth value + chip base verification: show output matches BREAKOUT_CFG, |


### test_breakout_scenario_64x4_64x2.py — C4-scale scenario: 64 ports 1->4 (4x200G) + 64 ports 1->2 (2x400G) broken out simultaneously.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_scenario_64x4_and_64x2 | 1 |  |


### test_buffer_alpha_chip.py — Chip-level alpha (dynamic threshold coefficient) semantics for lossless PGs.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_al1_alpha_semantics_declared_and_sane | 1 | AL1: platform must declare its alpha exponent offset, and the mapping must yield a valid enum name. |
| test_al2_bound_pg_alpha_matches_configured_dynamic_th | 1 | AL2 **read-only reconciliation**: for every bound lossless PG, the chip's |
| test_al3_configured_dynamic_th_lands_as_expected_alpha | 1 | AL3 **closed-loop self-calibration**: provision a known `dynamic_th` on a test |


### test_buffer_pool_chip.py — Buffer pool **chip-level budget and programming** verification (chiptab provides

| Case | Expansions | Purpose |
|------|:---:|------|
| test_bp1_pool_budget_within_device_cells | 1 | BP1 chip self-consistency: the sum of all ingress shared pools + all headroom pools must not exceed the total MMU cell count. |
| test_bp2_headroom_pool_covers_bound_lossless_pgs | 1 | BP2 **headroom oversubscription probe**: headroom pool capacity must be >= |
| test_bp3_shared_pool_matches_configured_size | 1 | BP3 the shared pool programmed value must come from CONFIG_DB's pool config, not the SDK default. |
| test_bp4_pool_type_consistent_config_to_asic | 1 | BP4 the pool type declared in CONFIG_DB must match the one actually created in ASIC_DB. |


### test_buffer_stats_traffic.py — **Live-traffic testing** of PG (ingress priority group) and buffer pool statistics -- filling a spot in the

| Case | Expansions | Purpose |
|------|:---:|------|
| test_bs1_pg_packet_and_byte_counters_advance | 1 | BS1 PG **throughput** statistics increment with real traffic: after injecting N frames, the sum of |
| test_bs2_pool_counter_fields_exposed | 1 | BS2 buffer pool counter **field exposure** (read-only, no traffic): the registered buffer pool counter rows |


### test_c3_bpdel.py — Positively trigger the _BP_DELETED path.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_c3_bp_deleted_suppress | 1 |  |


### test_command_coverage.py — Onbox klish command-coverage.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_command_coverage | 1 |  |


### test_config_persist_chip.py — Config persistence x chip state -- save file contents + chip state restored after reload (gated).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_saved_config_carries_chip_verified_state | 1 | Create scheduler(w=66), bind queue -> chip WEIGHT=66 confirms it took effect -> config save to a separate file |
| test_config_reload_restores_chip_state | 1 | config reload re-applies -> chip state restored. By default all registered devices have |


### test_congestion_chip.py — Low-rate congestion bench -- use a shaper to push the service rate below the CPU injection

| Case | Expansions | Purpose |
|------|:---:|------|
| test_cg1_queue_shaper_caps_egress_rate | 1 | CG1 shaper rate-cap behavior: q0 pushed to 2Mbps, inject a ~8Mbps-equivalent burst; within the |
| test_cg2_dwrr_ratio_under_congestion | 1 | CG2 DWRR service ratio: two queues with 80/20 weights + whole-egress-port rate cap to create a |
| test_cg5_sp_dominates_weighted_under_congestion | 1 | CG5 strict-priority behavior (CG2 only verified the DWRR ratio; SP's **service behavior** has |
| test_cg3_wred_ecn_marks_under_congestion | 1 | CG3 ECN marking behavior: q0 rate cap + small-threshold WRED(ECN) + ECT(0) traffic burst -> |
| test_cg4_pfc_tx_generated_on_pg_congestion | 1 | CG4 PFC generation (PFC TX verification without a traffic generator): ingress-port lossless |
| test_cg6_wred_drops_counted_for_non_ect | 1 | CG6 WRED drop counting: the same congestion bench as CG3 (q0 rate cap + small-threshold |
| test_cg7_tail_drop_counted_deterministically | 1 | CG7 queue tail-drop counting (deterministic congestion bench): |
| test_cg8_dwrr_weight_hot_change_flips_ratio | 1 | CG8 **behavioral** closed loop for hot scheduler-weight change (test_qos_sched_chip only |
| test_cg9_congestion_drops_land_on_egress_not_ingress | 1 | CG9 under egress congestion, drops must be counted on the **egress queue** ledger, not the |
| test_cg10_pg_and_pool_stats_move_under_congestion | 1 | CG10 under real congestion the ingress-side stats must move: PG shared watermark rises, and the |


### test_counter_classes_traffic.py — Statistics inventory gap-fill: **live-traffic testing** of three counter classes -- frame-size/anomalous-frame distribution, derived rates, and protocol traps. An objective inventory of "which SAI_*_STAT_* fields the whole suite has ever asserted on" found that, beyond the basic queue/port counters, six counter classes have **zero coverage** (grep across the whole repo finds no reference):

| Case | Expansions | Purpose |
|------|:---:|------|
| test_cc1_frame_size_buckets_count_the_right_bucket | 1 | CC1 frame-size distribution counters count the **right bucket**: send frames of a given length, and only the matching length bucket should advance. |
| test_cc2_oversize_frames_are_counted | 1 | CC2 oversize frames must be counted in the anomalous-frame statistics (`ETHER_STATS_OVERSIZE_PKTS` or RX_ERR). |
| test_cc3_rate_table_populated_under_sustained_traffic | 1 | CC3 `RATES:PORT` derived rates must be non-zero under sustained traffic. |
| test_cc4_trap_counters_advance_on_protocol_traffic | 1 | CC4 protocol-punt counters (FLOW_CNT_TRAP) increment with real protocol packets. |


### test_counter_infra.py — Counter **infrastructure liveness** -- the pre-flight checkup for every statistics case. A possible failure mode:

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ci1_enabled_counter_groups_have_name_map | 1 | CI1 every enabled flex counter group must have a non-empty NAME_MAP. |
| test_ci2_queue_and_pg_maps_cover_every_port | 1 | CI2 coverage: the queue/PG NAME_MAP must cover **every** Ethernet port, not just some of them. |
| test_ci3_registered_oids_have_counter_rows | 1 | CI3 registered is not enough, it must actually be collected: each oid in a NAME_MAP must have a `COUNTERS:<oid>` row, |
| test_ci4_port_counters_advance_on_traffic | 1 | CI4 **traffic measurement**: after injecting real traffic, the SAI port counters on the injection port must advance. |


### test_default_tc_untagged.py — Real-traffic verification: SAI_PORT_ATTR_QOS_DEFAULT_TC makes **untagged** traffic land in the egress queue corresponding to the default TC.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_untagged_lands_in_default_tc_queue | 1 | Untagged non-IP frame -> lands in the egress queue corresponding to default_tc (=6). |
| test_dscp_ip_not_overridden_by_default_tc | 1 | Scope regression: an untagged IP frame with DSCP=46 (EF->TC5->queue5) on a trust_dscp port is |


### test_dlb_chip.py — Standalone DLB (Dynamic Load Balancing) ECMP chip-behaviour suite (vendor-x-sai).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dlb_group_create_and_free | 1 | All three DLB group types create, produce an L1 group, and return every chip resource after delete. |
| test_dlb_two_level_group_shape | 1 | Standalone DLB's two-level shape: L1 OVERLAY(MAX_PATHS=1) single member = L2 UNDERLAY, with both members on the L2. |
| test_dlb_members_are_not_forced_down | 1 | A DLB member must not be forced down after it joins. |
| test_dlb_member_survives_neighbour_relearn | 1 | After a neighbour ages out and is re-learned, the member is still in the group and not forced down. |
| test_dlb_quality_tracks_load_and_queue_depth | 1 | The quality quantisation map a DLB member port uses must be driven by both port loading and TM queue depth. |
| test_dlb_pfc_filter_mode_enabled | 1 | The DLB engine's PFC filter mode must be on (Idle semantics). |
| test_dlb_watched_queues_match_lossless_config | 1 | The 4 unicast queues the engine watches must match the device's actual lossless config, not the SDK default 0-3. |
| test_dlb_watched_queues_follow_pfc_change | 1 | Change the lossless config at runtime and the watched queues must follow; after reverting they must return to the original. |
| test_dlb_watched_queues_follow_qos_map_content | 1 | Rewrite the content of an **already bound** PFC-priority->queue map and the watched queues must follow. |
| test_dlb_coexists_with_regular_ecmp | 1 | A plain ECMP group and a DLB group coexist: each is created, they do not interfere, and the plain group is intact after the DLB group is deleted. |
| test_dlb_group_grows_past_the_allocation_increment | 1 | A DLB group's MAX_PATHS is the **allocation increment**, not a member ceiling — it must grow past the increment. |
| test_plain_ecmp_hashing_survives_dlb | 1 | **DLB's impact on plain ECMP**: the plain ECMP data-plane hash spread must keep working while a DLB group is present and after it is torn down. |
| test_dlb_physical_port_ceiling | 1 | **How many physical egress ports one DLB group can hold** — the real spec of a DLB load-sharing group. |
| test_dlb_group_churn_leaves_no_residue | 1 | Repeated create/delete (with members) leaks no chip resources and does not kill syncd. |
| test_dlb_member_release_frees_next_hop | 1 | After a member is deleted it must release its reference to the next hop, or that next hop can never be deleted. |
| test_dlb_left_no_damage | 1 | Closing health check: after the DLB suite there are no **new** cores, no syncd/orchagent errors, and port counters are intact. |


### test_dlb_ecmp_mode_cli.py — Standalone DLB **product-path** verification -- `config load-balance ecmp-mode`.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ecmp_mode_dynamic_submodes | 3 | All three dynamic submodes must take effect through the product command and land as a DLB group on the chip. |
| test_dlb_member_survives_port_flap | 1 | After a member port link flap, the DLB group and member state must recover; a member must not be permanently kicked out. |
| test_dlb_single_flow_stays_on_one_member | 1 | **One flow must always take one path.** This is the entire value of DLB over per-packet hashing. |
| test_dlb_attributes_survive_member_growth | 1 | **When adding members grows the group, the DLB attributes must be preserved as-is.** |
| test_ecmp_mode_dynamic_takes_effect_at_runtime | 1 | After switching to `dynamic eligible`, an ECMP route must become a DLB group -- and clarify whether a restart is needed. |


### test_dlb_flowset_degrade_chip.py — DLB flowset exhaustion degrade -- on-hardware verdict suite.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_dlb_flowset_exhaustion_degrades_to_plain_ecmp | 1 | **A2 core verdict: once the whole table is filled by the 32768 group, an injected DLB group must degrade to plain ECMP.** |
| test_dlb_degraded_group_member_add_remove | 1 | **A3: while degraded, member add/remove lands directly on L1, without error and without reviving L2.** |
| test_dlb_degraded_group_upgrades_after_flowset_freed | 1 | **A4: after deleting the 32k group frees the flowset, a single member add triggers an automatic upgrade to the two-level DLB shape.** |
| test_dlb_degraded_group_delete_leaves_no_residue | 1 | **A5: deleting a group while degraded must be clean: L1 emptied, no added engine rows, next hop references returned.** |
| test_dlb_invalid_flowset_size_fails_loudly | 1 | **A6: an illegal flowset size (3333) is not a resource error and must fail loudly, leaving no group.** |
| test_dlb_degrade_upgrade_cycle_no_bitmap_leak | 1 | **A7 (slow): fill -> degrade -> release -> upgrade cycled 5 times, with zero flowset-bitmap leak.** |
| test_dlb_upgraded_group_takes_member_immediately | 1 | **D1: adding another member right after a successful upgrade keeps the group healthy and the flowset window intact.** |


### test_dlb_flowset_reseed_chip.py — Standalone DLB flowset re-seed (member join) chip behavior -- the adjudicating case set.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_join_moves_only_new_member_slots | 1 | **Core adjudication: a member join only rewrites the slots ceded to it; all other slots are byte-for-byte unchanged.** |
| test_inservice_bounce_readds_member_in_place | 1 | **In-service fast flap: remove/add a member in place on the same group, partial re-seed touches only the new member's stripe.** |
| test_resize_then_flap_stress_full_table | 1 | **32768 large table: in-place resize regression + full-table RMW stress.** |
| test_resize_denied_with_two_groups_keeps_both | 1 | **A failed resize must be loud and lossless.** Push -s 8 with two groups coexisting (a 128 contiguous block is unavailable): |
| test_traffic_spread_and_aging_cabled_only | 1 | Pending on a cabled bench (loopback infeasible): |
| test_breakout_subport_member_cabled_only | 1 | Pending on a dedicated bench: config interface breakout to 4x, configure L3 on subports and join the DLB group, |


### test_dlb_join_edges_chip.py — Boundary cases for DLB member-join reseed / partial reseed.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_damping_knobs_stay_zero | 1 | **REASSIGNMENT_PROBABILITY_THRESHOLD / QUALITY_DELTA stay 0/0 after all write points.** |
| test_replace_reindex_falls_back_to_full_reseed | 1 | **Member index re-order (REPLACE) marks all members -> must fall back to a full DMA reseed.** |
| test_join_and_resize_same_update | 1 | **Size change (stacked with a member join) -> reallocate base, update size, full round-robin.** |
| test_flowset_instances_pipes_consistent | 1 | **After a partial reseed, the same row must have identical contents across 4 table instances x 8 pipes.** |
| test_no_member_change_zero_disturbance | 1 | **Without member changes, the flowset must have zero disturbance.** |
| test_join_with_alternate_path | 1 | **Alternate member join (pending a supporting bench): primary port_id unchanged -> no partial mark -> full reseed.** |


### test_drop_packets.py — Malformed-packet drop test suite -- adapted from sonic-mgmt tests/drop_packets/.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_multicast_smac_drop | 1 | [2] Multicast SMAC: a frame whose source MAC is a multicast address (01:00:5e:..) should be |
| test_not_expected_vlan_tag_drop | 1 | [3] Tagged frame with an unconfigured VID: an 802.1Q tagged frame carrying an unconfigured |
| test_broken_ip_header_version | 1 | [10a] Bad IP header version=1: an illegal IP version field should be dropped at **L3** |
| test_broken_ip_header_ihl | 1 | [10c] Bad IP header ihl=1: an illegal IP header-length field should be dropped at **L3** |
| test_ip_pkt_with_expired_ttl | 1 | [9] TTL expired: a packet whose TTL decrements to 0 on the routing path should be dropped |
| test_ip_pkt_with_exceeded_mtu | 1 | [13] Exceeds egress MTU: a routed packet whose whole frame exceeds the L3 egress interface MTU |


### test_ecmp_breakout_combo.py — Load balancing x port breakout: whether breakout subports can really participate in ECMP / DLB load balancing.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_ecmp_over_breakout_subports | 1 | The 4 breakout subports as 4 next hops of plain ECMP: the NHG must really have 4 members. |
| test_dlb_group_over_breakout_subports | 1 | 4 subports form one DLB group: 4 mutually distinct PORT_IDs must appear in the group. |
| test_dlb_group_survives_subport_merge | 1 | Merge a subport back while it's still a DLB group member: the group must shrink cleanly, leaving no residual group and not collapsing the device. |


### test_ecmp_vlanif_combo.py — **Load balancing across a physical L3 port / VLANIF mix**: one route with next hops on both a physical L3 port and a VLAN interface.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_vlanif_nexthop_forwards | 1 | Control: with the SVI as the only next hop, traffic must egress the SVI's member port. |
| test_ecmp_mixes_physical_port_and_vlanif | 1 | Physical L3 port + VLANIF mixed as plain ECMP: both paths must get a share of traffic. |
| test_dlb_over_mixed_physical_and_vlanif | 1 | The same mixed topology switched to dynamic: record what the DLB group is built as and what PORT_ID holds. |
| test_mixed_ecmp_converges_when_vlanif_member_goes_down | 1 | Bring the SVI's only member port down: the SVI path must converge, the physical path must carry on as usual. |


### test_env_sanity.py — On-box preflight health check: **are you actually measuring what you think you are?**

| Case | Expansions | Purpose |
|------|:---:|------|
| test_es1_sai_library_is_the_one_you_installed | 1 | ES1: `libsai.so.1` must be a symlink pointing at `libsai.so.1.0`, and its content must |
| test_es2_ports_finished_initialising | 1 | ES2: APPL_DB must have `PORT_TABLE:PortInitDone`, and `PORT_TABLE_KEY_SET` must be drained. |
| test_es3_bst_tracking_actually_enabled | 1 | ES3: to assert on watermarks, first confirm the chip's BST is genuinely tracking. |


### test_mtu_logical.py — MTU and logical interfaces: port/PC/VLAN-IF MTU, jumbo, loopback, oversize-MTU egress routed-forwarding drop.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_port_mtu | 1 | Port MTU: CONFIG_DB persisted + **the kernel interface MTU actually takes effect** (portmgrd applies it to the netdev), not just a |
| test_jumbo_frame_mtu | 1 | Jumbo MTU (9216) triple evidence: ASIC port MTU attribute + ~9000B real-traffic forwarding + kernel netdev actually takes effect. |
| test_egress_mtu_routed_drop | 1 | Egress MTU dataplane enforcement (**routed-forwarding** path, storm-free): egress p_out MTU=1500, an injected >1500B routed frame should |
| test_loopback_interface | 1 | Loopback logical interface, independent of any physical port. |


### test_pattern_c_content.py — Pattern C content check: use a hairpin topology to capture forwarded frames **after p_out egress

| Case | Expansions | Purpose |
|------|:---:|------|
| test_forward_preserves_content | 1 | L2 forwarding content invariants (single hairpin, one frame carrying all fields, **every** matching frame |


### test_pfc_rx_priority_chip.py — Data-plane verification of PFC Rx per-priority narrowing.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_pfc_baseline_dscp_reaches_expected_queues | 1 | Baseline sanity: with no XOFF, DSCP 24/10 land on queue 3/1 respectively. |
| test_pfc_configured_priority_pauses_its_queue | 1 | Positive control: p_out is configured with priority 3, so while priority-3 XOFF is flooded continuously queue 3 must be paused. |
| test_pfc_unconfigured_priority_does_not_pause | 1 | Core case: p_out is configured with only priority 3, so while **unconfigured** priority-1 XOFF is flooded continuously, |


### test_pfcwd_storm_chip.py — PFCWD storm full cycle and chip DLR mode -- DEBUG_STORM driven, no real XOFF source needed.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_pw1_storm_restore_cycle | 1 | PW1: DEBUG_STORM set -> queue declared storm; HDEL -> restored to operational. |
| test_pw2_dlr_mode_programming | 1 | PW2 (DLR mode only): MANUAL_RECOVERY already programmed by create_switch; |
| test_pw3_unarmed_priority_no_timer_rebuild | 1 | PW3 (DLR mode only): after an armed priority completes storm->restore (DLR_INIT true->false), |
| test_pw4_multi_port_multi_priority | 1 | PW4 (slow): 2 ports x 2 lossless priorities concurrent storm -> restore full cycle. |


### test_policer_chip.py — Policer objects and port binding.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_pol1_policer_config_conversion | 1 | POL1: `config policer add` rates must be persisted correctly per the CLI's semantics. |
| test_pol2_policer_update_lands | 1 | POL2: `policer update` changing the rate must be persisted; when the object is already referenced it must also propagate to the ASIC. |
| test_pol3_port_policer_binding_channel | 1 | POL3: `SAI_PORT_ATTR_POLICER_ID` needs a product CLI before it can be used in production. |


### test_port_phys_chip.py — Port physical-layer config behavior -- the full chain of speed / FEC / MTU / admin down to the chip PC_PORT.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_mtu_chain_to_chip_max_frame | 1 | MTU full chain, adding the chip layer: config mtu 9100 -> CONFIG_DB -> chip PC_PORT.MAX_FRAME_SIZE |
| test_speed_chain_to_chip | 1 | speed full chain (previously zero coverage): pick a non-current rate from STATE/APPL supported_speeds, |
| test_fec_chain_to_chip | 1 | FEC full chain (previously only show-doesn't-crash): rs -> none -> chip PC_PORT.FEC_MODE follows; |
| test_admin_shutdown_chain_to_chip | 1 | admin shutdown/startup dedicated case (previously only indirect coverage): shutdown -> ASIC ADMIN_STATE |
| test_supported_fecs_reported_sanely | 1 | Every admin-up Ethernet port must report a **non-empty and valid** supported_fecs in STATE_DB. |


### test_queue_stats_fields.py — Guard for the **counter-field completeness** of queue stats / ECN stats (a regression lock for the ECN capability defect).

| Case | Expansions | Purpose |
|------|:---:|------|
| test_qsf1_uc_queue_counter_fields_complete | 1 | QSF1 UC queue counter-field completeness: not one of the drop family or ECN family may be missing, and values must parse as integers. |
| test_qsf2_mc_queue_counter_row_intact_with_ecn | 1 | QSF2 MC queue row intact + ECN fields present. Two bad shapes attributed separately: |


### test_rate_pkt_len_chip.py — Which **packet length** rate limiting / shaping bills against — line length (L1) vs L2 frame.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_rpl1_shaper_and_meter_account_wire_length | 1 | RPL1: front-panel port shaper and meter must both add 20 bytes of wire overhead on |
| test_rpl2_port_byte_counters_stay_l2 | 1 | RPL2: the port byte-counter compensation must **stay at the baseline**, and must not |
| test_rpl3_shaper_serves_by_wire_length | 1 | RPL3 behavioral: squeeze the **port** shaper well below the CPU injection rate, flood |
| test_rpl4_ingress_policer_traffic_path_unreachable | 1 | RPL4: the ingress policer's **behavioral face** cannot be verified via a production |


### test_roce_lossless_chip.py — End-to-end RoCE lossless verification -- config provisioned the proper way + SDKLT chip-table final check + PFC-frame / RoCE-packet traffic.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_rc1_lossless_chain_chip_final | 1 | RC1 chip final check: PG3's PFC bit and LOSSLESS bit + headroom>0. A defect can |
| test_rc2_buffer_values_cells_to_chip | 1 | RC2 buffer value conversion: BUFFER_PROFILE.xoff/size(bytes) -> chip cells (±2 cells). |
| test_rc3_lossless_classification_effective | 1 | RC3 classification-chain **effectiveness** (no longer requires a custom map object |
| test_rc4_buffer_profile_programmed_to_asic | 1 | RC4 buffer profile reaches ASIC: the configured headroom (xoff) must appear on some |
| test_rc5_port_pfc_bitmap_in_asic | 1 | RC5 port PFC bitmap: ASIC PORT.PRIORITY_FLOW_CONTROL contains bit3 (cross-checks |
| test_rc6_pfcwd_config_chain | 1 | RC6 PFCWD config chain: start -> real CONFIG_DB PFC_WD table field values -> stop |
| test_rc7_pfc_pause_frame_rx_counter | 1 | RC7 PFC-frame data plane (no traffic generator needed): build an 802.1Qbb pause frame |
| test_rc8_rocev2_classified_to_lossless_queue | 1 | RC8 RoCE packet classification and enqueue (traffic): inject RoCEv2(BTH/UDP4791, |
| test_rc9_non_lossless_pgs_stay_lossy | 1 | RC9 **reverse criterion**: only the PG that was configured with PFC may have |


### test_sai_regression_chip.py — SAI regression nails -- each one corresponds to a class of regression failure mode.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_lf1_bridge_port_learn_survives_link_flap | 1 | LF1 (regression nail): after a bridge port goes through shutdown/startup, the chip port-level |
| test_lf2_mac_learning_works_after_link_flap | 1 | LF2 (same as above, behavior level): send traffic again after the flap; the MAC must still be learnable and frames must still be forwarded. |
| test_lf3_routed_port_stays_unlearned_after_flap | 1 | LF3 (negative nail): after a routed port flaps it **must not** get learning enabled -- baseline restore should only act on |
| test_fx1_sibling_pg_state_survives_per_core_flex | 1 | FX1 (regression nail): after changing the speed of **one** subport (triggering a whole-core flex), |
| test_hs1_default_hash_objects_exist | 1 | HS1 (regression nail): the default ECMP and LAG hash objects must exist, and the chip's |
| test_hs2_ecmp_hash_field_change_reaches_asic | 1 | HS2 (behavior nail): change the ECMP hash field set via the vendor CLI; the ASIC hash object's |
| test_dt1_default_tc_reaches_asic | 1 | DT1 (regression nail): `config port-qos-map update <port> -d <TC>` must write |


### test_scale_consistency_chip.py — Full-scale config: **per-port reconciliation of config plane vs chip plane** -- "CONFIG_DB complete != chip complete".

| Case | Expansions | Purpose |
|------|:---:|------|
| test_sc1_all_bound_pgs_programmed | 1 | SC1 every lossless BUFFER_PG binding must land in TM_ING_THD_PORT_PRI_GRP, and the headroom |
| test_sc2_all_bound_queues_programmed | 1 | SC2 every BUFFER_QUEUE binding must take effect in TM_THD_UC_Q (static_th or min). |
| test_sc3_all_queue_schedulers_programmed | 1 | SC3 **queue scheduler landing regression lock**: every QUEUE's scheduler binding must land in |
| test_sc4_all_wred_bindings_programmed | 1 | SC4 every queue's wred_profile binding must take effect in TM_WRED_UC_Q. Missing one port means |
| test_sc5_all_pfc_enables_programmed | 1 | SC5 for every port that declares pfc_enable, both TX and RX in PC_PFC must be enabled. Missing one port = |


### test_scenario_fullscale_roce.py — Full-scale RoCE provisioning scenario: configure lossless + scheduling + ECN + PFC on

| Case | Expansions | Purpose |
|------|:---:|------|
| test_fs1_every_port_accepted_the_config | 1 | FS1 the config plane itself must be clean first: no per-port command may fail. |
| test_fs2_all_ports_resolve_to_chip | 1 | FS2 every port must resolve to a chip PORT_ID. A port that cannot resolve is skipped in |
| test_fs3_chip_matches_config_at_scale | 1 | FS3 **full-scale reconciliation**: every binding just configured must land on the chip. |


### test_wred_lifecycle_chip.py — WRED profile lifecycle: enable toggling and disabled-state threshold semantics.

| Case | Expansions | Purpose |
|------|:---:|------|
| test_wl1_enable_toggle_no_sai_error | 1 | WL1: `-en false` -> `-en true`, zero SAI reapply errors, and after re-enable the ASIC thresholds == user values. |
| test_wl2_disabled_threshold_update_stays_off | 1 | WL2: update thresholds while disabled; the hardware must hold "min==max device-max" (WRED off); after re-enable the new values take effect. |
| test_wl3_created_disabled_unreachable_then_enable | 1 | WL3: profile created red-disabled (wred_red_enable=false before binding the queue) -- the chip red must land the |
| test_wl4_enable_toggle_per_color_loops | 3 | WL4: per color, 3 rounds of disable->enable, each round zero SAI errors and ASIC read-back == user values. |
| test_wl5_ecn_thresholds_unaffected_by_color_disable | 1 | WL5: explicit ECN thresholds should not be polluted by the color-disable unreachable substitution -- the current |

