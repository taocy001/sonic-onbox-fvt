#!/bin/bash
# Run the full suite on the DUT and generate a self-contained HTML report. Usage (on the DUT): bash tools/run_report.sh [pytest_args...]
# Requires pytest-html installed offline first (see docs/DEPLOY.md). Report output: /tmp/report.html.
cd "$(dirname "$0")/.." || exit 1
python3 -m pytest "${@:-tests/}" -p no:cacheprovider -p no:warnings \
  --html=/tmp/report.html --self-contained-html
echo "report: /tmp/report.html"
