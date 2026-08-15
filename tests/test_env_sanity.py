"""On-box preflight health check: **are you actually measuring what you think you are?**

Three checks, each guarding against a class of "the whole round's conclusions are void" trap:

- **ES1 SAI library identity**: if `/usr/lib/libsai.so.1` is not a symlink but a standalone
  old file entity, the freshly installed `libsai.so.1.0` is **never loaded**. Any batch of
  anomalies recorded against the "new library" (PFC counters not collected, subport LOSSLESS
  bit, pfc/buffer mutual exclusion...) is really measuring the old one, and vanishes once the
  symlink is restored. A single `md5sum` can head off this loss.
- **ES2 port init complete**: if orchagent is stuck re-entering `initPortSupportedFecModes`,
  APPL_DB has only `PortConfigDone` and no `PortInitDone` => `allPortsReady()` is always false =>
  no QoS is programmed at all, `SAI_OBJECT_TYPE_QOS_MAP` is 0, COUNTERS has only one oid.
  QoS cases run empty here, and the failure reasons look wildly random.
- **ES3 BST validity**: `counterpoll show` shows watermark enabled, but when the chip's
  `TM_BST_TRACKING_STATE` has all 8 bits at 0 and there is not a single `CTR_ING_TM_BST_*`,
  the watermark numbers the upper layers read are all 0, and any assertion built on them only
  "appears to pass".

All read-only, sub-second. Put first in the smoke round -- if these three fail, nothing that follows can be trusted.
"""
import pytest

pytestmark = [pytest.mark.smoke]

_SAI_LIB = "/usr/lib/libsai.so.1"


def _syncd(cli, cmd):
    return cli.sh.run(f"docker exec syncd sh -c \"{cmd}\"", check=False)


# ============================ ES1 SAI library identity ============================
def test_es1_sai_library_is_the_one_you_installed(cli):
    """ES1: `libsai.so.1` must be a symlink pointing at `libsai.so.1.0`, and its content must
    not equal any `.orig*` / `.bak*` backup.

    The standard way to install the library is `dpkg -i` or replacing `.so.1.0` directly,
    taking effect through the `libsai.so.1` symlink. Once it becomes a standalone file (the
    product of some past manual cp/mv), the new library never loads, and **there is no sign of
    it** -- version strings, timestamps and dpkg records all point at the new library."""
    r = _syncd(cli, "ls -la /usr/lib/libsai.so*; echo ---; md5sum /usr/lib/libsai.so* 2>/dev/null")
    out = (r.out or "") + (r.err or "")
    if "libsai.so" not in out:
        pytest.skip(f"cannot inspect {_SAI_LIB} inside syncd (output={out[:160]}); "
                    "vendor SAI layout differs")
    listing = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith("/usr/lib/libsai.so"):
            listing[parts[1]] = parts[0]
    is_link = f"{_SAI_LIB} ->" in out or f"libsai.so.1 ->" in out
    assert is_link, (
        f"{_SAI_LIB} is a standalone file, not a symlink to libsai.so.1.0. Whatever "
        f"you installed is NOT what syncd loaded, and nothing else in the system will "
        f"tell you so — version strings, timestamps and dpkg all describe the new "
        f"library. Fix with `ln -sf libsai.so.1.0 libsai.so.1` and restart swss, then "
        f"re-run everything you thought you had measured. listing:\n{out[:400]}")
    live = listing.get(_SAI_LIB)
    stale = {p: m for p, m in listing.items()
             if p != _SAI_LIB and (".orig" in p or ".bak" in p)}
    if live and stale:
        same = [p for p, m in stale.items() if m == live]
        assert not same, (
            f"{_SAI_LIB} has the same md5 ({live}) as backup(s) {same} — the running "
            f"SAI is a pre-upgrade copy. Every defect you attribute to the new build "
            f"is being measured against the old one.")


# ============================ ES2 port init complete ============================
def test_es2_ports_finished_initialising(cli):
    """ES2: APPL_DB must have `PORT_TABLE:PortInitDone`, and `PORT_TABLE_KEY_SET` must be drained.

    Without PortInitDone, orchagent's `allPortsReady()` is always false, so **no QoS
    configuration is programmed at all**; a backlogged KEY_SET means port tasks are still
    churning in the queue (port tasks re-entering repeatedly, per-port cache not taking effect).
    Running functional cases in either state only yields a pile of inexplicable failures."""
    keys = cli.db_keys("APPL_DB", "PORT_TABLE:Port*") or []
    assert any("PortInitDone" in k for k in keys), (
        f"APPL_DB has no PORT_TABLE:PortInitDone (found {keys}). orchagent's "
        f"allPortsReady() is false, so no QoS configuration is programmed at all — "
        f"any functional result from this box right now is meaningless. Check whether "
        f"orchagent is stuck re-entering initPortSupportedFecModes.")
    r = cli.sh.run("sonic-db-cli APPL_DB scard PORT_TABLE_KEY_SET", check=False)
    txt = (r.out or "").strip().splitlines()
    backlog = int(txt[-1]) if txt and txt[-1].strip().lstrip("-").isdigit() else 0
    assert backlog == 0, (
        f"APPL_DB PORT_TABLE_KEY_SET still holds {backlog} pending port tasks; "
        f"port programming has not settled. Counters and QoS objects will be "
        f"incomplete while this drains.")


# ============================ ES3 BST validity ============================
def test_es3_bst_tracking_actually_enabled(cli, chip):
    """ES3: to assert on watermarks, first confirm the chip's BST is genuinely tracking.

    `counterpoll show` showing enabled **does not mean** BST is running: watermark may all be
    enabled yet the chip's `TM_BST_TRACKING_STATE` has all 8 bits at 0 and `CTR_ING_TM_BST_PORT_PRI_GRP`
    has zero entries -- the upper layers read all 0s, and assertions built on them "pass". This
    case only judges when watermark polling is on, otherwise it skips."""
    chip.require()
    if not chip.has_table("TM_BST_TRACKING_STATE"):
        pytest.skip("TM_BST_TRACKING_STATE absent on this chip family")
    r = cli.sh.run("counterpoll show", check=False)
    if "WATERMARK" not in (r.out or "").upper():
        pytest.skip("no watermark counter polling enabled; BST not required")
    # On a bare box with zero buffer bindings, SAI never reaches BST enable at all,
    # so all-zero BST here is expected, not a defect -- "watermarks should have numbers" only
    # makes sense once bindings exist.
    if not (cli.db_keys("CONFIG_DB", "BUFFER_PG|*") or
            cli.db_keys("CONFIG_DB", "BUFFER_QUEUE|*")):
        pytest.skip("no BUFFER_PG/BUFFER_QUEUE binding on this box, so SAI never "
                    "enables BST — all-zero tracking is expected here, not a defect")
    ents = chip.traverse("TM_BST_TRACKING_STATE")
    if not ents:
        pytest.skip("TM_BST_TRACKING_STATE readable but empty; cannot judge")
    tracking = [e for e in ents
                if any(isinstance(v, int) and v for k, v in e.items() if k != "PIPE")]
    assert tracking, (
        f"watermark polling is enabled but the chip tracks nothing: every "
        f"TM_BST_TRACKING_STATE bit is 0 ({ents[:2]}). Every watermark value the "
        f"upper layers report is a constant zero, so any assertion built on them "
        f"passes without measuring anything. BST needs "
        f"`CTR_TM_BST_STATS_SYNC_CONTROL update CLASS=ALL STATE=START` and a "
        f"configuration that actually binds PGs/queues.")
