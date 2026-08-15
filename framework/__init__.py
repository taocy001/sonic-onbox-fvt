"""SONiC on-DUT test framework core layer.

Layers (bottom-up):
  shell      subprocess/container command execution (supports dry-run)
  log        unified logging
  ports      port abstraction (EthernetX <-> bcm logical port number)
  dut        device discovery (platform/asic/syncd/sdk/port inventory)
  cli        SONiC CLI wrapper (config/show/sonic-db-cli/vtysh) + parsing
  loopback   bcmsh per-port internal MAC loopback management (SDK-pluggable)
  collector  copy-to-CPU collector (return-path capture in capture-first mode)
  counters   port/queue counter reads and deltas
  traffic    CPU tx (scapy) / rx (AsyncSniffer) / counter verification
  verify     DB/ASIC/STATE assertions + packet matching
  config_guard  config snapshot/restore, ensuring test isolation
"""

__all__ = [
    "shell", "log", "ports", "dut", "cli", "loopback",
    "collector", "counters", "traffic", "verify", "config_guard",
]
