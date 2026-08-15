"""Mock BMC REST service: impersonate the OpenBMC HTTP interface on the DUT itself.

Used together with the iptables REDIRECT in framework/pmon_fault.py to form a full-chain
injection:
    mock sensor data returned → real bmc2cpu_cache_sync → real bmc_cache
      → real sonic_platform read side → real psud/thermalctld → STATE_DB → real show

Baseline data is preferably snapshotted live from the real BMC (snapshot_from_real) so the
shape matches the local firmware; scenarios are injected onto the baseline via mutation
methods (drop_sensor / set_psu_field / set_mode ...).
POST (e.g. /api/hw/rawcmd fan-speed writes) is only recorded, never executed -- writes during
the redirect never reach the real BMC.
"""
import copy
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from framework import log

_log = log.get("mock_bmc")

DEFAULT_PORT = 18080
REAL_BMC_BASE = "http://240.1.1.1:8080"
ENDPOINTS = ("sensor/info", "fan/info", "psu/info", "psu/number",
             "firmware/cpldversion")


class MockBmc:
    """Scenario-controllable fake OpenBMC. Threaded HTTP; start()/stop() lifecycle follows the servers convention."""

    def __init__(self, port=DEFAULT_PORT):
        self.port = port
        self.data = {ep: {} for ep in ENDPOINTS}
        self._baseline = None
        self.mode = "ok"        # ok | malformed | status_error | empty_data
        self.delay_s = 0.0
        self.posts = []         # [(path, body_dict)] W-group criterion
        self.requests = []      # [(method, path)]
        self._httpd = None
        self._thread = None

    # ------------------------- baseline -------------------------

    def snapshot_from_real(self, base=REAL_BMC_BASE, timeout=30, retries=3):
        """Snapshot the five endpoints from the real BMC as baseline (fallback: real BMC latency jitters, so retry per endpoint)."""
        snap = {}
        for ep in ENDPOINTS:
            for attempt in range(retries):
                try:
                    body = urllib.request.urlopen(
                        "%s/api/%s" % (base, ep), timeout=timeout).read()
                    j = json.loads(body.decode())
                    if j.get("status") != "OK":
                        raise ValueError("status=%s" % j.get("status"))
                    snap[ep] = j.get("data") or {}
                    break
                except Exception as e:  # noqa: BLE001
                    _log.info("snapshot %s try%d: %s", ep, attempt + 1, e)
            else:
                return False
        self.data = snap
        self._baseline = copy.deepcopy(snap)
        return True

    def snapshot_from_cache(self, cache_dict):
        """Derive the baseline from the on-disk bmc_cache (preferred: produced by the real sync
        daemon, so the shape is authentic and does not depend on live BMC latency/jitter).
        cache key → endpoint:
            thermal_info→sensor/info  fan_info→fan/info  psu_info→psu/info
            fan_cpld_info→firmware/cpldversion  psu/number derived by counting PSU* keys.
        """
        if not cache_dict:
            return False
        psu = cache_dict.get("psu_info") or {}
        n = len([k for k in psu if k.startswith("PSU")])
        snap = {
            "sensor/info": cache_dict.get("thermal_info") or {},
            "fan/info": cache_dict.get("fan_info") or {},
            "psu/info": psu,
            "firmware/cpldversion": cache_dict.get("fan_cpld_info") or {},
            "psu/number": {"Number": n},
        }
        if not snap["psu/info"] and not snap["sensor/info"]:
            return False
        self.data = snap
        self._baseline = copy.deepcopy(snap)
        return True

    def load_profile(self, profile):
        """Offline baseline (dict: endpoint -> data), a self-provided shape for when the real BMC is unreachable."""
        self.data = copy.deepcopy(profile)
        self._baseline = copy.deepcopy(profile)

    def reset(self):
        """Restore baseline data and behavior mode (must be called in each case's finally)."""
        if self._baseline is not None:
            self.data = copy.deepcopy(self._baseline)
        self.mode = "ok"
        self.delay_s = 0.0

    # ------------------------- scenario mutation -------------------------

    def drop_sensor(self, name):
        self.data["sensor/info"].pop(name, None)

    def keep_only_sensors(self, names):
        self.data["sensor/info"] = {
            k: v for k, v in self.data["sensor/info"].items() if k in names}

    def drop_fan(self, name):
        self.data["fan/info"].pop(name, None)

    def set_psu_field(self, psu, path, value):
        """psu='PSU1', path=['Outputs','Voltage','Value']."""
        node = self.data["psu/info"][psu]
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    def set_fan_field(self, fan, path, value):
        node = self.data["fan/info"][fan]
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    def set_mode(self, mode):
        assert mode in ("ok", "malformed", "status_error", "empty_data")
        self.mode = mode

    def set_delay(self, seconds):
        self.delay_s = float(seconds)

    # ------------------------- HTTP -------------------------

    def _make_handler(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):   # silence the default access log
                _log.debug("mock_bmc %s", fmt % args)

            def _reply(self, payload_bytes, code=200):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload_bytes)))
                self.end_headers()
                self.wfile.write(payload_bytes)

            def do_GET(self):
                import time as _t
                mock.requests.append(("GET", self.path))
                if mock.delay_s:
                    _t.sleep(mock.delay_s)
                ep = self.path.lstrip("/")
                ep = ep[4:] if ep.startswith("api/") else ep
                if mock.mode == "malformed":
                    return self._reply(b"{not json !!")
                if mock.mode == "status_error":
                    return self._reply(json.dumps(
                        {"status": "ERROR", "data": {}}).encode())
                if mock.mode == "empty_data":
                    return self._reply(json.dumps({"status": "OK"}).encode())
                data = mock.data.get(ep, {})
                return self._reply(json.dumps(
                    {"status": "OK", "data": data}).encode())

            def do_POST(self):
                mock.requests.append(("POST", self.path))
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode() or "{}")
                except ValueError:
                    body = {"_raw": raw.decode(errors="replace")}
                mock.posts.append((self.path, body))
                return self._reply(json.dumps(
                    {"status": "OK", "data": {}}).encode())

        return Handler

    def start(self):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port),
                                          self._make_handler())
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        _log.info("MockBmc started on 127.0.0.1:%d", self.port)
        return self

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        _log.info("MockBmc stopped")
