"""Device profile loading: merge the defaults and device sections of topology/profiles.yaml by platform/hwsku.

A single source of truth, shared by dut (sdk/bcm mapping) and topology (port roles/vlan/subnet/caps).
"""
import copy
import os

import yaml

from . import log

_log = log.get("profile")
_PATH = os.path.join(os.path.dirname(__file__), "..", "topology", "profiles.yaml")


def _deep_merge(base, over):
    for k, v in (over or {}).items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load(platform=None, hwsku=None):
    """Return the merged profile (defaults + the matching device section)."""
    with open(_PATH) as f:
        data = yaml.safe_load(f)
    prof = copy.deepcopy(data.get("defaults", {}))
    devs = data.get("devices", {})
    dev = devs.get(platform) or devs.get(hwsku)
    if dev:
        _deep_merge(prof, dev)
        _log.info("profile matched device section: %s", platform or hwsku)
    else:
        _log.warning("no matching device profile (%s / %s), using defaults", platform, hwsku)
    return prof


def _detect_platform():
    """Detect the current device platform at collection time (no dut fixture): prefer DUT_PLATFORM, then /host/machine.conf."""
    p = os.environ.get("DUT_PLATFORM")
    if p and p != "unknown-platform":
        return p
    try:
        with open("/host/machine.conf") as f:
            for line in f:
                if line.startswith("onie_platform="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def load_current():
    """Load the profile for the current device (machine.conf / DUT_PLATFORM, DUT_HWSKU env vars).

    Lets test cases read device expectations at **collection time** (the pytest.mark.parametrize
    decoration stage, when no dut fixture exists yet), from the same source as dut.profile / topology.
    The build machine (no machine.conf) falls back to defaults.
    """
    return load(_detect_platform(), os.environ.get("DUT_HWSKU"))
