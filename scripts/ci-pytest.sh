#!/usr/bin/env bash
#
# ci-pytest.sh: the integration test run, in one place.
#
# This is the run that is supposed to prove tenant isolation, row locks and the
# database-backed APIs — everything tests/conftest.py skips when there is no
# OCTO_POSTGRES_URL. Its exit code alone never proved that: a suite skipped
# wholesale exits 0 exactly like a suite that passed. So the script declares the
# infrastructure available (OCTO_REQUIRE_INTEGRATION=1) and tests/conftest.py
# then refuses to let the session end green if the Postgres or NATS suites were
# skipped anyway, or if suspiciously few of them ran.
#
# Report paths differ between the two pipelines (Jenkins archives one file per
# Python version, GitHub Actions uploads a single coverage.xml), so they come in
# through the environment rather than being hard-coded twice.
#
#   JUNIT_XML         JUnit report path; empty (default) writes none.
#   COVERAGE_XML      Cobertura report path. Default: coverage.xml
#   COV_FAIL_UNDER    Coverage gate. Default: 74 (docs/development.md).
#   OCTO_REQUIRE_INTEGRATION
#                     Set to 0 for a deliberately infrastructure-less run.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

JUNIT_XML="${JUNIT_XML:-}"
COVERAGE_XML="${COVERAGE_XML:-coverage.xml}"
COV_FAIL_UNDER="${COV_FAIL_UNDER:-74}"
export OCTO_REQUIRE_INTEGRATION="${OCTO_REQUIRE_INTEGRATION:-1}"

args=(-q)
if [[ -n "${JUNIT_XML}" ]]; then
  args+=("--junitxml=${JUNIT_XML}")
fi
args+=(
  --cov=api
  --cov=scanner
  "--cov-report=xml:${COVERAGE_XML}"
  --cov-report=term-missing
  "--cov-fail-under=${COV_FAIL_UNDER}"
)
# Anything the caller adds (a -k selection while debugging a stage) lands after
# the defaults, where pytest lets it win.
args+=("$@")

echo "[pytest] integration gate: OCTO_REQUIRE_INTEGRATION=${OCTO_REQUIRE_INTEGRATION}"
exec python -m pytest "${args[@]}"
