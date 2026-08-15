"""Test topology: feeds ports/VLANs/IPs/capabilities to test cases so cases only reference them, never hardcode.

Usage (inside a test case):
    def test_x(topo, ...):
        p = topo.port("a")            # dynamically allocated physical port (not a hardcoded EthernetX)
        vid = topo.vlan("a")          # test VLAN
        net = topo.subnet("a")        # {dut, peer, prefix}
        if not topo.caps.has("loopback"): pytest.skip(...)
"""
from . import log, profile
from .ports import Port

_log = log.get("topo")


class Caps:
    def __init__(self, d):
        self._d = d or {}

    def has(self, name):
        return bool(self._d.get(name, False))

    def require(self, name):
        """pytest.skip when the capability is unavailable (device-specific handling: unsupported means skip, not fail)."""
        if not self.has(name):
            import pytest
            pytest.skip(f"device capability not available: {name} (see topology/profiles.yaml)")

    def __repr__(self):
        return f"Caps({self._d})"


class Topology:
    def __init__(self, dut):
        from . import worker as W
        self.dut = dut
        prof = profile.load(dut.platform, dut.hwsku)
        # ---- worker resource view (Phase3 lane split; identity for non-parallel/w1, transparent to cases) ----
        # Two worker processes share one device: VLANs/subnets/routes/loopbacks/hairpin params are offset per worker,
        # guaranteeing the two resource sets are statically disjoint (offset rules and auditing live in framework/worker.py).
        self._vlans = {k: W.remap_vid(v) for k, v in prof.get("vlans", {}).items()}
        self._subnets = {
            role: {k: (W.remap_asn(v) if str(k).endswith("_as")
                       else W.remap_cidr(v) if k in ("dut", "peer", "peer2") else v)
                   for k, v in sub.items()}
            for role, sub in prof.get("subnets", {}).items()}
        self._macs = prof.get("macs", {})        # MACs are not offset: FDB keys are already isolated by VLAN
        self._dscp = prof.get("dscp", {})
        self._routes = {k: W.remap_cidr(v) for k, v in prof.get("routes", {}).items()}
        self._servers = {k: W.remap_cidr(v) for k, v in prof.get("servers", {}).items()}
        self._loopbacks = {k: W.remap_cidr(v) for k, v in prof.get("loopbacks", {}).items()}
        # base_default_vlan = the device's real default VLAN (used by w2 for session baseline migration/restore); default_vlan =
        # this worker's flooding domain (private VLAN for w2+ -- if two bare loopback ports across processes share a VLAN, any kernel noise multicast becomes a permanent storm).
        self.base_default_vlan = prof.get("default_vlan", 1000)
        self.default_vlan = W.remap_default_vlan(self.base_default_vlan)
        hp = dict(prof.get("hairpin", {}))                   # hairpin topology params (worker view)
        if hp:
            hp["vlan_a"] = W.remap_vid(hp.get("vlan_a", 110))
            hp["vlan_b"] = W.remap_vid(hp.get("vlan_b", 120))
            if hp.get("svi"):
                hp["svi"] = W.remap_cidr(hp["svi"])
        self._hairpin = hp
        self.caps = Caps(prof.get("caps", {}))
        roles = prof.get("port_roles", ["a", "b"])
        # Dynamically allocate physical ports to roles (no hardcoding). Placeholder ports for dry-run/no-device;
        # port-selection failure in parallel mode never falls back silently (placeholder ports would mask worker-block config errors).
        try:
            ports = dut.pick_test_ports(len(roles))
        except Exception:  # noqa: BLE001
            if W.is_parallel():
                raise
            ports = [Port(name=f"Ethernet{i}") for i in range(len(roles))]
        self._ports = dict(zip(roles, ports))
        _log.info("topology: ports=%s vlans=%s caps=%s",
                  {r: p.name for r, p in self._ports.items()}, self._vlans, self.caps)

    # ---- reference interface ----
    def port(self, role):
        return self._ports[role]

    def port_name(self, role):
        return self._ports[role].name

    # ---- port role domains (isolation: L3 and L2 use different ports, so stale RIFs left by L3 don't break L2 cases) ----
    # a,b = traffic pair (hairpin/smoke); c,d = L3 domain (route/arp/ndp/vrf/intf-ip); e,f = L2 domain (fdb/mac/vlan/stp);
    # g,h = misc (lag/mirror/qos, etc.). Cases in each domain use only that domain's ports.
    _L3_ROLES = ("c", "d")
    _L2_ROLES = ("e", "f")
    _MISC_ROLES = ("g", "h")

    def l3_port(self, i=0):
        """L3 domain port (for route/arp/ndp/vrf/intf-ip)."""
        return self._ports[self._L3_ROLES[i]]

    def l2_port(self, i=0):
        """L2 domain port (for fdb/mac/vlan/stp) -- separate from the L3 domain, not polluted by RIFs."""
        return self._ports[self._L2_ROLES[i]]

    def misc_port(self, i=0):
        """Misc domain port (lag/mirror/qos/counters, etc.)."""
        return self._ports[self._MISC_ROLES[i]]

    def vlan(self, role):
        return self._vlans[role]

    def subnet(self, role):
        return self._subnets[role]

    def mac(self, role):
        return self._macs.get(role, "00:de:ad:be:ef:01")

    def dscp(self, name):
        """DSCP name -> value (e.g. topo.dscp("ef")=46). Cases don't hardcode numbers."""
        return self._dscp[name]

    def route(self, role):
        """Route prefix under test (e.g. topo.route("a")="10.251.0.0/24")."""
        return self._routes[role]

    def server(self, name):
        """External/integration server address (e.g. topo.server("sflow_collector"))."""
        return self._servers[name]

    def loopback(self, role):
        """Logical loopback interface address CIDR (e.g. topo.loopback("a")="10.10.10.10/32")."""
        return self._loopbacks[role]

    # ---- hairpin topology params (no hardcoding) ----
    @property
    def hp_vlan_a(self):
        return self._hairpin.get("vlan_a", 110)

    @property
    def hp_vlan_b(self):
        return self._hairpin.get("vlan_b", 120)

    @property
    def hp_svi(self):
        return self._hairpin.get("svi")

    @property
    def hp_probe_dst(self):
        return self._hairpin.get("probe_dst", "00:11:22:33:44:55")
