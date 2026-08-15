# Build-machine self-check + on-device run entry points
PY ?= python3

.PHONY: check collect dryrun coverage run smoke install

# Build machine: pure syntax compile, no scapy/hardware needed
check:
	$(PY) -m compileall -q framework conftest.py tests catalog && echo "OK: compileall passed"

# Build machine: can pytest collect all cases (without running)? Requires scapy importable or STUB-guarded
collect:
	$(PY) -m pytest --collect-only -q || true

# Build machine: dry-run, print the commands that would be issued, without connecting to a device
dryrun:
	DUT_DRY_RUN=1 $(PY) -m pytest -q -m "cli" || true

# Emit the feature coverage matrix (reads catalog/features.yaml + actually-observed cases)
coverage:
	$(PY) -m catalog.coverage

install:
	$(PY) -m pip install -r requirements.txt

# On device: smoke self-check (first confirm the loopback hairpin link is up)
smoke:
	$(PY) -m pytest -m smoke -v

# On device: run everything (or make run M="l2 and traffic")
M ?=
run:
	$(PY) -m pytest $(if $(M),-m "$(M)",) -v
