"""(Retired) QoS object-existence checks merged into test_qos_full.py; this file no longer contains cases.

Retirement rationale (reviewed): this file's two cases were a strict subset / redundant --
  - test_qos_maps_in_asicdb (QOS_MAP count>0) is a subset of
    test_qos_full.py::test_qos_object_programmed[QOS_MAP], and test_qos_config.py has a far
    stronger per-pair content comparison;
  - test_buffer_pool_in_asicdb (BUFFER_POOL count>0 + product-CLI-image structural skip) was
    migrated verbatim to test_qos_full.py::test_qos_object_programmed[BUFFER_POOL] (with the
    same structural skip).
Each module's module-scoped QoS setup fixture (~30s each) thus runs one fewer round, and the
existence dimension is now in one place with a single setup.

Important historical lesson (kept for reference; the mechanism is synced into each qos module fixture):
  WARNING: on a product-CLI-configured image, **never run `config qos reload`** -- on such
  images this command **only clears, never builds**: it first empties the QoS tables (deleting
  the read-only default maps TC_TO_QUEUE_MAP/DSCP_TO_TC_MAP injected by the product runtime),
  then exits with an error for the missing hwsku template. The consequence = PORT_QOS_MAP
  dangling references -> whole-DB YANG validation fails -> every command that goes through
  whole-DB validation (GCU/acl-table/mirror/bgp, even the map add used to repair it) fails in
  a chain, the CLI cannot self-heal (the read-only defaults refuse to be rebuilt), and only a
  direct redis write / restart resolves it. This image's QoS provisioning is handled by the
  product-CLI baseline (framework/qos.build_baseline).
"""
