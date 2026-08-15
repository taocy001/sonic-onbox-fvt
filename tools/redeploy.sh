#!/bin/bash
# Runs on the build machine: package -> upload -> extract -> run pytest on the DUT -> generate and pull back an HTML report
# Usage: tools/redeploy.sh [pytest args...]   e.g.: tools/redeploy.sh -m smoke -v
# Report: if pytest-html is installed on the DUT, /tmp/report.html is generated automatically and pulled back to ~/test-reports/ (NO_REPORT=1 skips)
set -e
cd "$(dirname "$0")/.."
tar czf /tmp/sonic-onbox-fvt.tgz --exclude=.git --exclude=__pycache__ --exclude='*.pyc' --exclude='tools/__pycache__' .
python3 tools/dutssh.py --put /tmp/sonic-onbox-fvt.tgz /tmp/sonic-onbox-fvt.tgz >/dev/null
# Clean up with sudo (__pycache__ may be root-owned) + extract
python3 tools/dutssh.py --sudo 'rm -rf /home/admin/sonic-onbox-fvt && mkdir -p /home/admin/sonic-onbox-fvt && tar xzf /tmp/sonic-onbox-fvt.tgz -C /home/admin/sonic-onbox-fvt 2>/dev/null && echo deployed' | tail -1

# If pytest-html is present on the DUT, add --html (self-contained single-file report)
HTML_ARG=""
if [ "${NO_REPORT:-0}" != "1" ] && \
   python3 tools/dutssh.py 'python3 -c "import pytest_html" 2>/dev/null && echo yes' 2>/dev/null | grep -q yes; then
    HTML_ARG="--html=/tmp/report.html --self-contained-html"
fi

ARGS="${*:-tests/smoke -v}"
python3 tools/dutssh.py --sudo "cd /home/admin/sonic-onbox-fvt && python3 -m pytest $ARGS -p no:cacheprovider $HTML_ARG 2>&1 | grep -vE 'Deprecation|cipher=algorithms|Blowfish|CAST5|warnings.warn|import cgi' | tail -45"

# Pull the report back to the build machine (timestamped name)
if [ -n "$HTML_ARG" ]; then
    mkdir -p ~/test-reports
    LOCAL=~/test-reports/report-$(date +%Y%m%d-%H%M%S).html
    python3 tools/dutssh.py --sudo 'cp /tmp/report.html /home/admin/report.html && chmod 644 /home/admin/report.html' >/dev/null 2>&1 || true
    if python3 tools/dutssh.py --get /home/admin/report.html "$LOCAL" >/dev/null 2>&1; then
        echo "[report] $LOCAL"
    fi
fi
