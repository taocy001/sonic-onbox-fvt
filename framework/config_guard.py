"""Config snapshot / restore keeping each test isolated and free of cross-test contamination.

Strategy:
  1) Before a test runs, `config save` to a temp file to take a snapshot;
  2) During the test, record the "undo commands" that were issued and replay them in
     reverse order at teardown (targeted rollback, fast);
  3) If targeted rollback errors out or the test crashes, fall back to
     `config reload <snapshot> -y` (full restore, slow but reliable).
"""
import os

from . import log

_log = log.get("config_guard")

# Snapshot path is keyed by lane/worker: under multiprocess parallelism (FVT_LANE=safe
# observation lane / FVT_WORKER=N traffic lanes), each config save avoids overwriting the others
_SNAP = ("/tmp/dut_test_snapshot-safe.json" if os.environ.get("FVT_LANE") == "safe"
         else f"/tmp/dut_test_snapshot-w{os.environ['FVT_WORKER']}.json"
         if os.environ.get("FVT_WORKER") else "/tmp/dut_test_snapshot.json")


class ConfigGuard:
    def __init__(self, cli):
        self.cli = cli
        self._undo = []

    def __enter__(self):
        self.cli.sh.run(f"config save -y {_SNAP}", check=False)
        return self

    def defer_undo(self, cmd, verify=None):
        """Register an undo command. When verify is callable, rollback success is judged by
        verify()  the SONiC CLI can return rc=0 even on error, so rc alone cannot judge
        rollback success."""
        self._undo.append((cmd, verify))

    # Idempotency errors from the CLI when the undo target state is already reached
    # (semantically equivalent to rollback success  no warning, no retry)
    _IDEMPOTENT = ("already a member", "already exist", "is not a member",
                   "does not exist", "doesn't exist", "not configured")

    @classmethod
    def _benign(cls, r):
        s = f"{r.err or ''}\n{r.out or ''}".lower()
        # 'No such command' = the command itself is wrong (a real problem, e.g.
        # mirror_session remove vs del)  must never be swallowed as idempotent; it has
        # to warn and be surfaced for the adapter layer to fix.
        if "no such command" in s:
            return False
        return any(t.lower() in s for t in cls._IDEMPOTENT)

    def __exit__(self, exc_type, *exc):
        # Roll back one command at a time; failures are only logged, we do **not** run
        # config reload (reload would restart swss/syncd, interrupt the whole test suite,
        # and wipe loopbacks). When a full restore is needed, run `config reload <snapshot>`
        # manually.
        #
        # **Second-pass retry fallback**: undo commands may have dependencies (e.g.
        # `vlan member add` run before `interface ip remove` fails with "is a router
        # interface"  when a test's registration order is not ideal, reverse order is not
        # always topological order). A single failed undo can permanently drop a port's
        # default VLAN membership and cascade failures into subsequent L2 tests.
        # So commands that failed on the first pass are retried once after the whole pass
        # completes (by then the command blocking them has most likely run).
        # Idempotency errors ("already a member"/"does not exist" etc. = target state already
        # reached) are treated as success.
        # Judgement priority: verify() > idempotent text > rc. **rc alone is insufficient to
        # judge success**  the SONiC CLI can still return 0 when it rejects a command, so
        # looking only at rc records a failed rollback as success, leaving residual config
        # that contaminates the rest of the run.
        def _run_undo(item):
            cmd, verify = item
            rc, r = self.cli.config_raw(cmd)
            if verify is not None:
                try:
                    return bool(verify()), r
                except Exception as e:  # noqa: BLE001
                    _log.warning("undo verify raised for %r: %s", cmd, e)
                    return False, r
            return (rc == 0 or self._benign(r)), r

        failed = []
        for item in reversed(self._undo):
            if item is None or item[0] is None:
                continue
            ok, r = _run_undo(item)
            if not ok:
                failed.append(item)
                _log.warning("undo failed (will retry after full pass): config %s | %s",
                             item[0], r.err)
        for item in failed:
            ok, r = _run_undo(item)
            if not ok:
                _log.warning("undo retry failed (skipped, no reload triggered): config %s | %s",
                             item[0], r.err)
        self._undo.clear()
        return False  # do not swallow exceptions

    @staticmethod
    def manual_full_restore(cli):
        """Call manually when needed: full restore to the entry snapshot (restarts services)."""
        cli.sh.run(f"config reload {_SNAP} -y -f", check=False, timeout=180)
