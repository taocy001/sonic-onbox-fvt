"""Subprocess / container command execution wrapper.

- host commands: direct bash -lc
- container commands (e.g. bcmcmd inside syncd): docker exec
- dry-run: with DUT_DRY_RUN=1 only print, don't execute, for build-host self-checks
"""
import os
import subprocess

from . import log

_log = log.get("shell")


class ShellError(RuntimeError):
    def __init__(self, cmd, result):
        self.cmd, self.result = cmd, result
        super().__init__(f"command failed rc={result.rc}: {cmd}\n--- stderr ---\n{result.err}")


class Result:
    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out.rstrip("\n"), err.rstrip("\n")

    @property
    def ok(self):
        return self.rc == 0

    def __repr__(self):
        return f"Result(rc={self.rc}, out={self.out!r})"


class Shell:
    def __init__(self, dry_run=None, cli_flavor=None):
        if dry_run is None:
            dry_run = os.environ.get("DUT_DRY_RUN", "") not in ("", "0", "false")
        self.dry_run = dry_run
        # "klish" routes every host config/show through the klish (Cisco-style) CLI
        # translator in the private plugins/klish_xlate.  Off by default -> native
        # behavior unchanged.  Set via KLISH_FLAVOR env or profiles.yaml caps
        # (propagated by the dut fixture).  Only affects devices explicitly opted in.
        self.cli_flavor = cli_flavor or os.environ.get("KLISH_FLAVOR") or None

    def _klish_rewrite(self, cmd):
        """Rewrite a native config/show host command into a klish CLI invocation
        (private plugins/klish_xlate).  Returns (new_cmd, err_result): new_cmd None
        means run as-is; err_result set means a config/show we own could not be
        translated -> surface, no fallback.  If the klish plugin is absent, returns
        (None, None) -> native passthrough."""
        try:
            from plugins import klish_xlate as X
        except ImportError:
            return None, None
        try:
            new = X.get().rewrite_shell_cmd(cmd)
            return new, None
        except (X.UntranslatedCommand, ValueError) as e:
            return None, Result(2, "", "klish: untranslated command %r (%s)"
                                % (cmd, e))

    def run(self, cmd, container=None, check=False, timeout=30, stdin=None):
        """Execute a command. If container is non-empty, run it inside that container."""
        if self.cli_flavor == "klish" and container is None:
            new, err = self._klish_rewrite(cmd)
            if err is not None:
                if check:
                    raise ShellError(cmd, err)
                return err
            if new is not None:
                _log.debug("klish xlate: %s  ==>  %s", cmd, new)
                cmd = new
        if container:
            argv = ["docker", "exec", "-i", container, "bash", "-lc", cmd]
        else:
            argv = ["bash", "-lc", cmd]
        tag = f"[{container}] " if container else ""
        _log.debug("RUN %s%s", tag, cmd)
        if self.dry_run:
            _log.info("[dry-run] %s%s", tag, cmd)
            return Result(0, "", "")
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, input=stdin
            )
        except subprocess.TimeoutExpired as e:
            r = Result(124, (e.stdout or "") if isinstance(e.stdout, str) else "",
                       f"timeout after {timeout}s")
            if check:
                raise ShellError(cmd, r)
            return r  # check=False: return a timeout as non-crash (rc=124), don't raise
        r = Result(p.returncode, p.stdout, p.stderr)
        if check and not r.ok:
            raise ShellError(cmd, r)
        return r
