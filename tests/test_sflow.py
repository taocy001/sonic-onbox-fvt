"""sFlow: global/interface enable -> CONFIG_DB; sampling punt is Pattern A (add traffic once the collector is ready)."""
import time

import pytest

pytestmark = [pytest.mark.counters]


def test_sflow_enable(cli, config_guard, topo):
    """config sflow enable -> CONFIG_DB write **and sflowmgrd propagates the state to APPL_DB**.

    Differentiated layering from test_sflow_show (review: low, the original case was a strict subset of the show case):
    this case observes the next hop of the programming chain -- after sflowmgrd consumes CONFIG_DB SFLOW| it must write APPL_DB
    SFLOW_TABLE:global; checking only CONFIG_DB is config-plumbing, and a broken propagation would still show false green.
    """
    topo.caps.require("sflow")   # if the device self-declares unsupported, structurally skip
    rc, r = cli.config_raw("sflow enable")
    config_guard.defer_undo("sflow disable")
    assert rc == 0, f"failed to enable sFlow: {r.err or r.out}"
    attrs = cli.db_hgetall("CONFIG_DB", "SFLOW|global")
    assert attrs.get("admin_state") == "up", f"sFlow not enabled: {attrs}"
    # Chain next hop: sflowmgrd consumes asynchronously -> APPL_DB SFLOW_TABLE:global admin_state=up (poll-wait to settle)
    app, deadline = {}, time.time() + 8
    while time.time() < deadline:
        app = cli.db_hgetall("APPL_DB", "SFLOW_TABLE:global")
        if app.get("admin_state") == "up":
            break
        time.sleep(0.5)
    assert app.get("admin_state") == "up", (
        f"sFlow enable not propagated to APPL_DB SFLOW_TABLE:global (got {app}); "
        f"sflowmgrd propagation broken despite CONFIG_DB write")


def test_sflow_show(cli, config_guard, topo):
    """config sflow enable -> CONFIG_DB admin_state=up, and the sflow service must really be running for sFlow to be effective.

    Previously only checking CONFIG_DB + show-not-crashing was config-plumbing false green on images where sflow.service is masked --
    masking the real defect of "the service won't start and sFlow doesn't actually work" (the sibling case test_sflow_enable also FAILs outright to expose it).
    Now add an sflow service-liveness assertion: when masked this FAILs honestly (binary exposure, no xfail masking).
    """
    topo.caps.require("sflow")   # if the device self-declares unsupported, structurally skip
    rc, r = cli.config_raw("sflow enable")
    config_guard.defer_undo("sflow disable")
    assert rc == 0, f"config sflow enable failed: {r.err or r.out}"
    attrs = cli.db_hgetall("CONFIG_DB", "SFLOW|global")
    assert attrs.get("admin_state") == "up", f"sFlow admin_state not written to CONFIG_DB: {attrs}"
    out = cli.run("show sflow").out
    assert "Traceback" not in out, "show sflow crashed"
    # Real functionality requires the sflow service to be running; service masked -> is-active != active -> assertion FAILs (binary exposure)
    st = cli.sh.run("systemctl is-active sflow", check=False).out.strip()
    assert st == "active", \
        f"sflow.service not active (is-active={st!r}); sFlow non-functional despite CONFIG_DB enable"
