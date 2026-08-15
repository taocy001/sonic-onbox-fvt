"""gNMI / telemetry: Capabilities RPC + container present + sampling period really effective (COUNTERS_DB advances over time).

Design principle (emphasized by the user: assert real behavior, not "command did not error" /
CONFIG_DB echo):
  - Capabilities: issue one **Capabilities RPC** to the actually running gNMI server, and assert a
    structured capability response (gNMI version + supported encodings + models). Without a gNMI
    client -> honestly skip (untestable, no false pass).
  - Sampling period: instead of only reading the CONFIG_DB FLEX_COUNTER_STATUS=enable echo, **sample
    COUNTERS_DB twice** within the sampling period and assert the count really advances over time
    (the flex counter poll is indeed flushing chip counts into COUNTERS_DB).

Prints/asserts/skips in English; comments/docstrings translated.
"""
import ast
import json
import time

import pytest

pytestmark = [pytest.mark.mgmt]


def _gnmi_container(cli):
    """Return the name of the running gnmi/telemetry container (None if absent)."""
    names = cli.run("docker ps --format '{{.Names}}'").out.split()
    for c in ("gnmi", "telemetry"):
        if c in names:
            return c
    return None


def _gnmi_port(cli, cname):
    """Probe the gNMI listening port via ss inside the container (telemetry defaults to 8080; also covers 50051/9339)."""
    ss = cli.run(f"docker exec {cname} ss -tlnp").out
    for p in ("8080", "50051", "9339"):
        if f":{p}" in ss:
            return p
    return None


def _gnmi_client_in(cli, cname):
    """A gNMI client available inside the container. Prefer gnmic (cleanest Capabilities response), fall back to gnmi_cli."""
    for tool in ("gnmic", "gnmi_cli"):
        if cli.run(f"docker exec {cname} which {tool}").rc == 0:
            return tool
    return None


def _server_is_notls(cli, cname):
    """Whether telemetry started in plaintext (noTLS): a process with --noTLS/--insecure means a plaintext endpoint."""
    ps = cli.run(f"docker exec {cname} ps aux").out.lower()
    return "--notls" in ps or "-notls" in ps or "--insecure" in ps


def test_gnmi_get_capabilities(cli):
    """gNMI Capabilities RPC really effective: issue one Capabilities to the running gNMI server and assert a structured
    capability response (gNMI version / supported encodings / models). The "-h did not error" kind is a false pass; here we
    issue a real RPC.

    If telemetry started in **noTLS (plaintext h2c)** and the only client inside the container supporting the Capabilities
    subcommand is `gnmi_cli` (TLS-only, no -notls/plaintext option), hitting a plaintext server hangs on the TLS handshake
    (rc=124); while the plaintext-capable `gnmi_get -notls` has no Capabilities subcommand. When gnmic (whose plaintext
    --insecure can issue Capabilities) is absent, **there is no noTLS-compatible Capabilities client** -> honestly skip
    (a client limitation, not a server defect, not a false pass). If gnmic is installed, use gnmic to really issue Capabilities."""
    cname = _gnmi_container(cli)
    # telemetry/gnmi container should be running but is not = device defect
    if not cname:
        pytest.fail("DEVICE DEFECT: telemetry/gnmi container not running; cannot issue a real "
                    "Capabilities RPC")
    port = _gnmi_port(cli, cname) or "8080"
    client = _gnmi_client_in(cli, cname)
    # the gNMI client that should exist inside the telemetry container is missing = device defect
    if not client:
        pytest.fail("DEVICE DEFECT: no gNMI client (gnmi_cli/gnmic) inside the telemetry container "
                    "to issue a Capabilities RPC; client bring-up pending")

    if client == "gnmic":
        # gnmic's --insecure = plaintext (no TLS), can really issue Capabilities to a noTLS server
        cmd = (f"docker exec {cname} gnmic -a localhost:{port} --insecure "
               f"-u admin -p admin capabilities")
    else:
        # the only Capabilities client gnmi_cli is TLS-only; with a plaintext server it cannot reliably issue Capabilities -> skip
        if _server_is_notls(cli, cname):
            pytest.skip("no noTLS-capable Capabilities client on this image: gnmi_cli is TLS-only "
                        "(no -notls) and clashes with the plaintext telemetry endpoint; gnmi_get "
                        "cannot issue Capabilities; gnmic absent")
        # gnmi_cli (google) supports -capabilities; --insecure does TLS-skip-verify (when the server has TLS)
        cmd = (f"docker exec {cname} gnmi_cli -capabilities -address localhost:{port} "
               f"-insecure -logtostderr")
    r = cli.run(cmd, timeout=25)
    out = (r.out + "\n" + r.err)
    low = out.lower()

    # When a client does not support the Capabilities subcommand it spits usage/help (treating capabilities as an unknown
    # command) -- this is "untestable", honestly skip; do not let 'encoding' appearing in a help text count as a false pass.
    help_markers = ("usage:", "available commands", "unknown command", "command not found",
                    "flag provided but not defined", "see '")
    # the gNMI client inside the container has no usable Capabilities subcommand = client not ready = device defect
    if r.rc != 0 and any(m in low for m in help_markers):
        pytest.fail(f"DEVICE DEFECT: {client} lacks a Capabilities RPC subcommand (returned "
                    f"usage/help, not a capability response); gNMI client bring-up pending: "
                    f"{out[-300:]}")

    # Server unreachable / RPC timeout (rc=124 means the client was killed by timeout, or connection refused/DeadlineExceeded) --
    # this is a bench/image-level environment limitation: on this image the telemetry endpoint won't come up or can't be reached,
    # recorded as an untestable skip, not a real switch-chip defect and not a false pass. The real RPC was still issued, only the
    # unreachable outcome is converted to skip.
    unreachable_markers = ("deadline exceeded", "context deadline", "connection refused",
                           "connection reset", "transport is closing", "unavailable",
                           "rpc error", "timed out", "timeout", "no route to host",
                           "i/o timeout", "dial tcp")
    # telemetry endpoint should be up and reachable but can't connect/times out = gNMI server unusable on this image = device defect
    if r.rc == 124 or (r.rc != 0 and any(m in low for m in unreachable_markers)):
        pytest.fail(
            f"DEVICE DEFECT: gNMI Capabilities RPC timed out / telemetry endpoint not reachable on "
            f"this image (rc={r.rc}) at {cname}:{port}; gNMI server/client not usable on this "
            f"build: {out[-300:]}")

    # If a real RPC was issued and the server is reachable, it must return successfully
    assert r.rc == 0, (
        f"gNMI Capabilities RPC failed (rc={r.rc}) on {cname}:{port}: {out[-400:]}")

    # Look for real response tokens only in "non-usage / non-flag-description" lines: a description like
    # `-encoding string ...` in help text is not a structured capability and must be excluded, to avoid the 'encoding'
    # substring being misjudged as a pass.
    resp = "\n".join(
        l for l in out.splitlines()
        if l.strip()
        and "usage" not in l.lower()
        and not l.lstrip().startswith("-")
    ).lower()
    # Supported encodings: gnmic prints `supported encodings:` + JSON_IETF; gnmi_cli prints `supported_encodings:`/JSON_IETF.
    # These are Capabilities-response-specific tokens that never appear in the body of usage text.
    has_encoding = ("supported_encodings" in resp or "supported encodings" in resp
                    or "json_ietf" in resp or "proto" in resp)
    # gNMI version / supported-models list: another piece of evidence of a structured response.
    has_version = ("gnmi_version" in resp or "gnmi version" in resp
                   or "supported_models" in resp or "supported models" in resp)
    assert has_encoding and has_version, (
        f"gNMI Capabilities RPC did not return a structured capability response "
        f"(supported encodings + gNMI version on a non-usage line) from {cname}:{port}: "
        f"{out[-400:]}")


def _get_client_in(cli, cname):
    """A gNMI **Get** client available inside the container (gnmi_get is the most direct; gnmi_cli is the fallback)."""
    for tool in ("gnmi_get", "gnmi_cli"):
        if cli.run(f"docker exec {cname} which {tool}").rc == 0:
            return tool
    return None


def _extract_json_ietf(out):
    """Extract json_ietf_val from gnmi_get's proto-text response and parse it into a dict (None if absent).
    In the response this field is a single-line escaped string: json_ietf_val: "{\\"k\\":\\"v\\",...}"."""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("json_ietf_val:"):
            q = s[len("json_ietf_val:"):].strip()
            try:
                inner = ast.literal_eval(q)          # unquote/unescape -> JSON string
                return json.loads(inner)
            except (ValueError, SyntaxError, TypeError):
                return None
    return None


def test_telemetry_container_running(cli):
    """telemetry/gnmi daemon really effective: container/process/port present (precondition), then issue a **real gNMI Get RPC**
    fetching COUNTERS_DB's COUNTERS_PORT_NAME_MAP, asserting the returned structured value matches the local DB (not just
    checking the process is up).

    No gNMI Get client / endpoint unreachable -> honestly skip (bench/image untestable, no false pass)."""
    r = cli.run("docker ps --format '{{.Names}}'")
    cname = "gnmi" if "gnmi" in r.out else ("telemetry" if "telemetry" in r.out else None)
    # telemetry/gnmi container should be running but is not = device defect
    if not cname:
        pytest.fail("DEVICE DEFECT: telemetry/gnmi container not running")
    # Precondition: process present (the telemetry binary is launched by supervisor) + gNMI port listening
    ps = cli.run(f"docker exec {cname} ps aux")
    assert "telemetry" in ps.out, f"telemetry process not running in {cname}: {ps.out[-200:]}"
    port = _gnmi_port(cli, cname) or "8080"
    ss = cli.run(f"docker exec {cname} ss -tlnp")
    assert f":{port}" in ss.out or ":50051" in ss.out or ":9339" in ss.out, \
        f"gNMI/telemetry not listening on a known port: {ss.out[-200:]}"

    # Real Get RPC: if the client is missing, honestly skip (no false pass)
    client = _get_client_in(cli, cname)
    # the gnmi_get client that should exist inside the telemetry container is missing = device defect
    if client != "gnmi_get":
        pytest.fail(f"DEVICE DEFECT: no gnmi_get client inside {cname} to issue a real gNMI Get RPC "
                    f"(found={client}); Get client bring-up pending")

    # Local DB ground truth: port-name -> counter-oid map (telemetry goes through the SONiC DB, should return it verbatim)
    # flex counter should flush the port-name map into COUNTERS_DB but it is empty = device defect
    db_map = cli.db_hgetall("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP")
    assert db_map, ("DEVICE DEFECT: COUNTERS_PORT_NAME_MAP empty in COUNTERS_DB; flex counter did "
                    "not populate port name map")

    cmd = (f"docker exec {cname} gnmi_get -target_addr localhost:{port} -notls "
           f"-xpath_target COUNTERS_DB -xpath COUNTERS_PORT_NAME_MAP -encoding JSON_IETF")
    res = cli.run(cmd, timeout=25)
    out = (res.out or "") + "\n" + (res.err or "")
    low = out.lower()

    # Endpoint unreachable / RPC timeout -> bench environment limitation, recorded as an untestable skip (not a switch-chip defect, no false pass)
    unreachable = ("deadline exceeded", "context deadline", "connection refused",
                   "connection reset", "transport is closing", "unavailable", "rpc error",
                   "timed out", "timeout", "no route to host", "i/o timeout", "dial tcp")
    # telemetry endpoint should be up and reachable but can't connect/times out = device defect
    if res.rc == 124 or (res.rc != 0 and any(m in low for m in unreachable)):
        pytest.fail(f"DEVICE DEFECT: gNMI Get RPC timed out / telemetry endpoint not reachable on "
                    f"this image (rc={res.rc}) at {cname}:{port}: {out[-300:]}")
    assert res.rc == 0, f"gNMI Get RPC failed (rc={res.rc}) on {cname}:{port}: {out[-400:]}"

    # Parse the returned structured value and compare with the DB (proving Get really fetched the DB's value, not some arbitrary text)
    gnmi_map = _extract_json_ietf(out)
    assert isinstance(gnmi_map, dict) and gnmi_map, (
        f"gNMI Get did not return a structured JSON_IETF value for COUNTERS_PORT_NAME_MAP: {out[-400:]}")
    common = set(gnmi_map) & set(db_map)
    assert common, (
        f"gNMI Get response shares no port with COUNTERS_DB (got {len(gnmi_map)} ports, "
        f"db has {len(db_map)}); value does not match DB")
    mismatch = [k for k in common if str(gnmi_map[k]) != str(db_map[k])]
    assert not mismatch, (
        f"gNMI Get value disagrees with COUNTERS_DB for {len(mismatch)} ports "
        f"(e.g. {mismatch[:3]}): gNMI vs DB oid mismatch")


def _port_octets(cli, port_name):
    """Single-port COUNTERS_DB IN+OUT octet total (observation narrowed to the injection port itself); return None if no readable field."""
    oid = cli.db("COUNTERS_DB", f"HGET COUNTERS_PORT_NAME_MAP {port_name}")
    if not oid:
        return None
    h = cli.db_hgetall("COUNTERS_DB", f"COUNTERS:{oid}")
    total, seen = 0, False
    for f in ("SAI_PORT_STAT_IF_IN_OCTETS", "SAI_PORT_STAT_IF_OUT_OCTETS"):
        v = h.get(f)
        if v is not None and str(v).isdigit():
            total += int(v)
            seen = True
    return total if seen else None


def test_flex_counter_polls_and_disable_freezes(cli, traffic, topo):
    """flex counter polling really effective + the switch really consumed (the old name interval_configurable was a misnomer --
    POLL_INTERVAL was never changed, so it has been renamed):

    (1) Positive: the injection port's **own** COUNTERS octet delta >= injected bytes * 0.9 -- an all-port total + t1>t0 would be
        satisfied by any background noise; narrowing to this port + a quantified lower bound is what allows attribution to this injection.
    (2) Negative: after setting FLEX_COUNTER_TABLE|PORT to disable, inject the same traffic and wait 2 periods, and this port's
        octets freeze; after restoring enable it advances again -- proving the switch is really consumed by the flex counter, not a CONFIG_DB echo."""
    h = cli.db_hgetall("CONFIG_DB", "FLEX_COUNTER_TABLE|PORT")
    assert h, "FLEX_COUNTER_TABLE|PORT does not exist"
    assert h.get("FLEX_COUNTER_STATUS") == "enable", \
        f"PORT flex counter not enabled (counter export inactive): {h}"

    # Sampling period: take the PORT group's POLL_INTERVAL (ms), sleep for >=2 periods plus margin
    pi_ms = h.get("POLL_INTERVAL", "")
    poll_s = (int(pi_ms) / 1000.0) if str(pi_ms).isdigit() and int(pi_ms) > 0 else 1.0
    wait_s = min(max(poll_s * 2 + 3.0, 5.0), 15.0)

    try:
        from scapy.all import Ether, IP, UDP, Raw
    except Exception:  # noqa: BLE001
        pytest.skip("scapy unavailable (dry-run/build host); cannot inject the attributable flow")
    port = traffic.ports[0]
    base = _port_octets(cli, port.name)
    # flex counter should export octet counts for this port but does not = device defect
    assert base is not None, (
        f"DEVICE DEFECT: no octet counters for {port.name} in COUNTERS_DB (flex counter not "
        "exporting this port)")
    pkt = (Ether(dst=topo.mac("dst"), src=topo.mac("src")) / IP() / UDP() / Raw(b"g" * 40))
    frame_len = len(pkt) + 4
    lower = int(100 * frame_len * 0.9)     # loopback port counts IN/OUT both ways, single-direction sampling still meets the lower bound

    # (1) Positive: this port's octets must advance at the injected-byte magnitude
    traffic.send(port, pkt, count=100)
    delta = 0
    deadline = time.time() + wait_s
    while time.time() < deadline:
        time.sleep(1)
        cur = _port_octets(cli, port.name)
        delta = (cur - base) if cur is not None else delta
        if delta >= lower:
            break
    assert delta >= lower, (
        f"COUNTERS_DB octets on {port.name} advanced only +{delta}B over {wait_s:.0f}s for "
        f"100 x {frame_len}B injected frames (expected >= {lower}B); flex-counter polling is "
        "not refreshing this port's chip counters (sampling defect)")

    # (2) Negative: after disable the count freezes (the switch is really consumed), after enable it resumes advancing.
    # **Parallel-unsafe**: FLEX_COUNTER_TABLE|PORT is a device-global key (one CONFIG_DB / one flexcounterorch /
    # one ASIC); disable freezes flex sampling on **all ports, all parallel lanes** for several seconds -- cases that
    # concurrently read octets on an observation lane (e.g. snmp ifHCInOctets) would falsely fail (blocking per independent review).
    # So run this negative leg only in **single-process mode** (no FVT_WORKER/FVT_LANE, no concurrent lanes); in parallel
    # mode the positive leg already sufficiently proves polling works.
    from framework import worker as _W
    import os as _os
    if _W.is_parallel() or _os.environ.get("FVT_LANE"):
        return
    try:
        cli.db("CONFIG_DB", "HSET 'FLEX_COUNTER_TABLE|PORT' FLEX_COUNTER_STATUS disable")
        time.sleep(poll_s + 1.5)           # wait for orch to consume the switch + in-flight sampling to write out
        frozen0 = _port_octets(cli, port.name)
        traffic.send(port, pkt, count=100)
        time.sleep(wait_s)
        frozen1 = _port_octets(cli, port.name)
        assert frozen1 == frozen0, (
            f"FLEX_COUNTER_STATUS=disable written but {port.name} octets still advanced "
            f"(+{frozen1 - frozen0}B): the switch is not consumed by flex counter (echo only)")
    finally:
        # Restore enable no matter what, never leave the device in a sampling-disabled state
        cli.db("CONFIG_DB", "HSET 'FLEX_COUNTER_TABLE|PORT' FLEX_COUNTER_STATUS enable")
    traffic.send(port, pkt, count=100)
    resumed = False
    deadline = time.time() + wait_s
    while time.time() < deadline:
        time.sleep(1)
        cur = _port_octets(cli, port.name)
        if cur is not None and frozen1 is not None and cur > frozen1:
            resumed = True
            break
    assert resumed, (
        f"flex counter did not resume refreshing {port.name} octets after re-enable "
        "(polling stuck after disable/enable cycle)")


def test_gnmi_streaming_subscribe(cli):
    """gNMI STREAM subscribe really effective: issue a short-duration (~8s) STREAM/SAMPLE subscribe to the running gNMI server
    for COUNTERS_DB/COUNTERS_PORT_NAME_MAP, asserting at least 1 update is received in the window.
    Reuses this file's existing container/client discovery logic. No container / no client / endpoint unreachable -> device-defect
    fail (telemetry should be able to stream-subscribe but cannot). Kept binary."""
    cname = _gnmi_container(cli)
    # telemetry/gnmi container should be running but is not = device defect
    if not cname:
        pytest.fail("DEVICE DEFECT: telemetry/gnmi container not running; cannot issue a STREAM "
                    "subscribe")
    port = _gnmi_port(cli, cname) or "8080"
    # Subscribe client: gnmic's subscribe is the cleanest, gnmi_cli is the fallback
    client = _gnmi_client_in(cli, cname)
    # the gNMI client that should exist inside the telemetry container is missing = device defect
    if not client:
        pytest.fail("DEVICE DEFECT: no gNMI client (gnmic/gnmi_cli) inside the telemetry container "
                    "to issue a STREAM subscribe")

    # Same cause as Capabilities: the only subscribe client gnmi_cli is TLS-only and cannot build a stream against a plaintext
    # telemetry endpoint; gnmi_get has no subscribe subcommand; gnmic (plaintext-subscribe-capable) absent -> no noTLS-compatible subscribe client, honestly skip.
    if client != "gnmic" and _server_is_notls(cli, cname):
        pytest.skip("no noTLS-capable STREAM subscribe client on this image: gnmi_cli is TLS-only "
                    "(no -notls) and clashes with the plaintext telemetry endpoint; gnmic absent")

    if client == "gnmic":
        cmd = (f"docker exec {cname} timeout 8 gnmic -a localhost:{port} --insecure "
               f"-u admin -p admin subscribe --mode stream --stream-mode sample "
               f"--sample-interval 2s --target COUNTERS_DB "
               f"--path COUNTERS_PORT_NAME_MAP")
    else:
        cmd = (f"docker exec {cname} timeout 8 gnmi_cli -address localhost:{port} -insecure "
               f"-query_type streaming -streaming_type SAMPLE -streaming_sample_interval 2 "
               f"-target COUNTERS_DB -query COUNTERS_PORT_NAME_MAP -logtostderr")
    r = cli.run(cmd, timeout=25)
    out = (r.out or "") + "\n" + (r.err or "")
    low = out.lower()

    # A STREAM subscribe is a long-lived connection; being killed by `timeout` (rc=124) is a normal wrap-up, not a failure; the criterion is whether an update was received in the window.
    got_update = any(m in low for m in (
        "counters_port_name_map", "json_ietf_val", '"updates"', "update:", "update {",
        "sync_response", "timestamp:"))
    # Endpoint can't connect (connection refused/unavailable/RPC error) and no update received = telemetry streaming service unusable = device defect
    unreachable = ("connection refused", "connection reset", "transport is closing", "unavailable",
                   "no route to host", "i/o timeout", "dial tcp", "rpc error", "permission denied")
    if not got_update and any(m in low for m in unreachable):
        pytest.fail(f"DEVICE DEFECT: gNMI STREAM subscribe could not reach telemetry endpoint on "
                    f"{cname}:{port}: {out[-300:]}")
    assert got_update, (
        f"DEVICE DEFECT: gNMI STREAM subscribe to {cname}:{port} returned no update in the window "
        f"(telemetry streaming not delivering data): {out[-300:]}")
