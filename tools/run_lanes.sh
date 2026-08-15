#!/bin/bash
# Multi-lane parallel runner (runs on the DUT). Phase3 version:
#   P phase (parallel): traffic worker1 + traffic worker2 (FVT_WORKER=1/2, disjoint port blocks / resource views)
#                 + observation lane (FVT_LANE=safe, zero global side effects)
#   S phase (serial tail): global-singleton files (save/qos reload/GCU/counterpoll/CoPP/CRM/AAA/service restarts)
#                 -- they touch box-wide shared state, can't be split into lanes, and run single-process at the tail (semantics match traditional serial execution).
# Usage: tools/run_lanes.sh
# See the README "parallel lanes" section for the lane mechanism; worker resource-offset rules are in framework/worker.py.
set -u
cd "$(dirname "$0")/.."

# ---- Observation lane (static audit: zero port/VLAN touches; ospf/sflow excluded here due to FRR / global-switch conflicts) ----
SAFE_FILES="tests/test_show_commands.py tests/test_snmp_mibs.py tests/test_transceiver_db.py \
tests/test_platform_sensors.py tests/test_ssh.py tests/test_syslog.py \
tests/test_sai_objects_present.py tests/test_auto_techsupport.py \
tests/test_vxlan.py tests/test_vxlan_full.py tests/test_vlan_tag_content.py"

# ---- Serial tail (true global singletons: config save/reload, config qos reload (158 actually run), GCU checkpoint,
#      counterpoll interval, CoPP trap/policer global tables, CRM global config, AAA, service-restart class) ----
SERIAL_FILES="tests/test_aaa.py tests/test_bgp_frr_state.py tests/test_system_mgmt.py \
tests/test_gcu.py tests/test_ipv6_ra.py tests/test_acl_fields.py \
tests/test_qos.py tests/test_qos_config.py tests/test_qos_full.py \
tests/test_qos_remark_chip.py tests/test_qos_sched_chip.py tests/test_queue_crm.py \
tests/test_copp.py tests/test_copp_full.py tests/test_copp_policer.py \
tests/test_copp_dataplane_chip.py tests/test_copp_l3_traps.py \
tests/test_crm.py tests/test_crm_chip.py tests/test_crm_thresholds.py"

# ---- worker1 (affinity group: dynamic FDB/learning/aging class -- its targeted FDB cleanup and global aging changes only affect this lane;
#      ACL cluster / mirror cluster on the same worker, so table/session names don't collide across lanes) ----
W1_FILES="tests/test_fdb.py tests/test_fdb_chip.py tests/test_mac.py \
tests/test_vlan.py tests/test_vlan_chip.py tests/test_vlan_scenarios.py tests/test_vlan_full.py \
tests/test_dynamic_entries.py tests/test_hairpin_validate.py tests/test_pattern_c_content.py \
tests/test_loopback_smoke.py tests/test_storm_mtu_chip.py \
tests/test_acl_basic.py tests/test_acl_full.py tests/test_acl_chip.py tests/test_acl_drop.py \
tests/test_acl_egress_l2.py tests/test_mirror.py tests/test_mirror_chip.py \
tests/test_erspan_traffic.py tests/test_lag_chip.py tests/test_lacp.py \
tests/test_counters_chip.py tests/test_port_counters.py tests/test_port_counters_full.py \
tests/test_stats_full.py"

# ---- worker2 = everything else (L3/protocol/config class; new files land here by default) ----
IGNORES=""
for f in $SAFE_FILES $SERIAL_FILES $W1_FILES; do IGNORES="$IGNORES --ignore=$f"; done

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p /tmp/fvt-lanes
echo "[lanes] phase-0 global init $TS"
# One-time global sanity (worker processes no longer each do this when parallel, see conftest._suite_baseline):
# turn off all loopbacks / clear dynamic FDB / AAA=local / clean up FRR orphan route-maps
python3 - <<'PYEOF'
import sys; sys.path.insert(0, ".")
from framework import shell, dut as D, cli as C, hygiene
sh = shell.Shell()
dut = D.discover(sh)
cli = C.Cli(sh, dut.syncd)
from framework.loopback import BcmShell
BcmShell(sh, dut).cmd("port all lb=none")
cli.sh.run("sonic-clear fdb all", check=False)
cli.sh.run("config aaa authentication login local", check=False)
try:
    hygiene.clean_frr_orphan_routemaps(cli)
except Exception as e:
    print(f"[lanes-init] FRR orphan cleanup skipped: {e}")
print("[lanes-init] done")
PYEOF

echo "[lanes] phase-P parallel: worker1 + worker2 + safe"
FVT_WORKER=1 python3 -m pytest $W1_FILES -q -p no:cacheprovider -p no:warnings \
    > /tmp/fvt-lanes/w1-$TS.log 2>&1 &
PID_1=$!
FVT_WORKER=2 python3 -m pytest tests $IGNORES -q -p no:cacheprovider -p no:warnings \
    > /tmp/fvt-lanes/w2-$TS.log 2>&1 &
PID_2=$!
FVT_LANE=safe python3 -m pytest $SAFE_FILES -q -p no:cacheprovider -p no:warnings \
    > /tmp/fvt-lanes/safe-$TS.log 2>&1 &
PID_S=$!
wait $PID_S; RC_S=$?
wait $PID_1; RC_1=$?
wait $PID_2; RC_2=$?

echo "[lanes] phase-S serial tail (global singletons)"
python3 -m pytest $SERIAL_FILES -q -p no:cacheprovider -p no:warnings \
    > /tmp/fvt-lanes/serial-$TS.log 2>&1
RC_T=$?

echo "[lanes] rc: w1=$RC_1 w2=$RC_2 safe=$RC_S serial=$RC_T"
for L in w1 w2 safe serial; do
    echo "== $L =="; tail -2 /tmp/fvt-lanes/$L-$TS.log
done
M=$RC_1; for r in $RC_2 $RC_S $RC_T; do [ $r -gt $M ] && M=$r; done
exit $M
