"""GCU (generic_config_updater) helper: incremental CONFIG_DB edits via JSON-patch + checkpoint/rollback.

Derived from sonic-mgmt tests/common/gu_utils.py, adapted for the on-DUT framework (cli.sh.run
runs directly on the DUT). It verifies the **NOS GCU config entry point**: patches correctly
accepted/rejected (apply_patch_ok/fail) + show/DB content takes effect + rollback returns to baseline.
JSON-patch format (RFC6902): [{"op":"add"/"remove"/"replace","path":"/TABLE/key","value":{...}}].

A "/" appearing in the path (e.g. route prefix 10.0.0.0/24 used as key) must be escaped as "~1" --
use Gcu.path() to build it.
"""
import json

from . import log

_log = log.get("gcu")

_PATCH_FILE = "/tmp/gcu_patch.json"


class Gcu:
    """GCU operation wrapper. cli.sh.run returns Result(rc/out/err)."""

    def __init__(self, cli):
        self.cli = cli

    def apply_patch(self, json_data):
        """Write patch to a DUT temp file + config apply-patch, return Result (no assertion)."""
        content = json.dumps(json_data, indent=2)
        self.cli.sh.run(f"cat > {_PATCH_FILE}", stdin=content)
        _log.info("apply-patch: %s", content)
        return self.cli.sh.run(f"config apply-patch {_PATCH_FILE}", timeout=120)

    def apply_patch_ok(self, json_data):
        """Push the patch and assert it is accepted (NOS correctly applies a valid incremental config)."""
        r = self.apply_patch(json_data)
        assert r.rc == 0 and "Patch applied successfully" in r.out, \
            f"apply-patch should succeed: rc={r.rc} out={r.out!r} err={r.err!r}"
        return r

    def apply_patch_fail(self, json_data, absent_keys=()):
        """Push an illegal patch and assert it is rejected (negative verification).

        rc is untrustworthy (SONiC CLI may still return 0 on error), so the criterion is that the
        **output does not contain the success marker**; the caller may also pass absent_keys (a list
        of CONFIG_DB keys) to assert those illegal configs really did not land in the DB."""
        r = self.apply_patch(json_data)
        text = (r.out or "") + (r.err or "")
        assert "Patch applied successfully" not in text, (
            f"apply-patch should be rejected but reported success: {text[-200:]!r}")
        for k in absent_keys:
            assert not self.cli.db_hgetall("CONFIG_DB", k), (
                f"rejected patch still landed in CONFIG_DB: {k}")
        return r

    def checkpoint(self, cp="gcu_cp"):
        r = self.cli.sh.run(f"config checkpoint {cp}")
        assert r.rc == 0 and "Checkpoint created successfully" in r.out, \
            f"checkpoint failed: {r.out!r} {r.err!r}"
        return cp

    def rollback(self, cp="gcu_cp"):
        return self.cli.sh.run(f"config rollback {cp}", timeout=120)

    def delete_checkpoint(self, cp="gcu_cp"):
        return self.cli.sh.run(f"config delete-checkpoint {cp}", check=False)

    @staticmethod
    def path(*tokens):
        """Build a JSON-pointer path, escaping ~->~0 and /->~1 (order: ~ first, then /).
        E.g. path("STATIC_ROUTE", "10.0.0.0/24") -> "/STATIC_ROUTE/10.0.0.0~124"."""
        out = ""
        for t in tokens:
            out += "/" + str(t).replace("~", "~0").replace("/", "~1")
        return out

    def add_entry(self, table, key, value):
        """Build a patch that "adds one table entry", handling whether the parent table exists:
        - table already has entries -> add to /TABLE/key (GCU requires the parent table to exist,
          otherwise it reports member not found);
        - table does not exist -> add the whole /TABLE with this entry (adding to a nonexistent path
          creates it).
        A key containing '/' (e.g. a route prefix) is escaped in path; as a plain string key inside
        the whole-table value dict it is not escaped."""
        if self.cli.db_keys("CONFIG_DB", f"{table}|*"):
            return [{"op": "add", "path": self.path(table, key), "value": value}]
        return [{"op": "add", "path": self.path(table), "value": {key: value}}]

    def remove_entry(self, table, key):
        """Build a patch that "removes one table entry"; if it is the last entry in the table,
        remove the whole table (GCU does not allow empty tables in ConfigDb, so removing the last
        entry must remove the table along with it)."""
        if len(self.cli.db_keys("CONFIG_DB", f"{table}|*")) <= 1:
            return [{"op": "remove", "path": self.path(table)}]
        return [{"op": "remove", "path": self.path(table, key)}]
