#!/bin/bash
# Runs on the build machine: run pytest on the DUT to produce allure results -> pull them back -> render an interactive report with the allure CLI.
# Usage: tools/allure_report.sh [pytest args...]    e.g.: tools/allure_report.sh tests/test_lag.py -q
# Prerequisites: DUT has allure-pytest installed (offline wheel, see docs/DEPLOY.md); build machine has Java + the allure CLI.
#   The allure CLI path defaults to ~/allure-cli/bin/allure and can be overridden via the ALLURE_BIN env var.
# Output: ~/test-reports/allure-<timestamp>/ (a multi-file directory; view with `allure open <dir>`, richer than pytest-html).
#
# WARNING: pytest runs on the DUT **in the background via nohup + polling** (not over a 30min synchronous SSH connection --
#    a long connection dropping gets retried into multiple runs that interfere and hammer the device; a known pitfall). Each poll is a short SSH, resilient to drops.
set -e
cd "$(dirname "$0")/.."
ARGS="${*:-tests/}"
ALLURE="${ALLURE_BIN:-$HOME/allure-cli/bin/allure}"

# Deploy
tar czf /tmp/sonic-onbox-fvt.tgz --exclude=.git --exclude=__pycache__ --exclude='*.pyc' --exclude='tools/__pycache__' .
python3 tools/dutssh.py --put /tmp/sonic-onbox-fvt.tgz /tmp/sonic-onbox-fvt.tgz >/dev/null
python3 tools/dutssh.py --sudo 'rm -rf /home/admin/sonic-onbox-fvt && mkdir -p /home/admin/sonic-onbox-fvt && tar xzf /tmp/sonic-onbox-fvt.tgz -C /home/admin/sonic-onbox-fvt 2>/dev/null && echo deployed' | tail -1

# Run pytest on the DUT in the background via nohup to produce allure results. **Key to preventing multiple runs** (a known pitfall: on SSH auth failure dutssh
# retries the whole command -> repeatedly spawning concurrent runs that clobber each other; once ended up with 9 runs and 122 stray report entries):
#   (1) Split cleanup and launch into **two separate dutssh calls** -- the cleanup call is idempotent (kill pytest + rm locks/markers/results);
#   (2) The launch call **uses a pure mkdir atomic lock with no rm at all** -- on retry mkdir fails and is skipped, so there is only one run.
#      (A pgrep guard doesn't work: it matches the command's own command line; rm-then-mkdir doesn't work either: on retry the rm destroys the lock.)
#   (3) The launched pytest rmdir's the lock itself after it finishes.
# ---- Cleanup call (idempotent, harmless to retry) ----
python3 tools/dutssh.py --sudo 'for i in 1 2 3; do pkill -9 -f "m pytest .*alluredir" 2>/dev/null; sleep 1; done
rm -rf /tmp/allure.lock /tmp/.allure_done /tmp/allure-results /tmp/allure_run.log; echo cleaned' | tail -1
# ---- Launch call (pure mkdir lock, retry-safe; contains no rm) ----
python3 tools/dutssh.py --sudo "if mkdir /tmp/allure.lock 2>/dev/null; then cd /home/admin/sonic-onbox-fvt && nohup bash -c 'python3 -m pytest $ARGS -p no:cacheprovider -p no:warnings --alluredir=/tmp/allure-results; touch /tmp/.allure_done; rmdir /tmp/allure.lock' >/tmp/allure_run.log 2>&1 & echo launched; else echo locked-skip; fi" | tail -1

# Poll for completion (a short SSH every 30s, up to ~3h)
echo -n "running pytest on DUT (background)"
for _ in $(seq 1 360); do
    if python3 tools/dutssh.py --sudo 'test -f /tmp/.allure_done && echo DONE' 2>/dev/null | grep -q DONE; then
        echo " done"; break
    fi
    echo -n "."; sleep 30
done
python3 tools/dutssh.py --sudo 'grep -aoE "[0-9]+ (passed|failed|skipped|xfailed|xpassed)" /tmp/allure_run.log | tail -5 | tr "\n" " "; echo' | tail -1

# Package results + pull back + render
python3 tools/dutssh.py --sudo 'cd /tmp && tar czf /home/admin/allure-results.tgz allure-results && chmod 644 /home/admin/allure-results.tgz' >/dev/null
python3 tools/dutssh.py --get /home/admin/allure-results.tgz /tmp/allure-results.tgz >/dev/null
rm -rf /tmp/allure-results && tar xzf /tmp/allure-results.tgz -C /tmp
OUT="$HOME/test-reports/allure-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$HOME/test-reports"
"$ALLURE" generate /tmp/allure-results -o "$OUT" --clean
echo "[allure report] $OUT"
echo "  view: $ALLURE open '$OUT'   (starts a local server, browser opens automatically; opening index.html directly fails to load data over file://)"
