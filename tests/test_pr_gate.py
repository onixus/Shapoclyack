"""Contract for the lightweight GitHub pull-request gate (#345).

The full workflow intentionally remains manual because it builds images, runs
live integration services, SAST, e2e, load tests, Trivy and SBOM generation.
This file protects the cheap gate that every pull request must receive instead
of merely trusting comments in YAML to stay uncommented forever.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PR_GATE = (REPO_ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
FULL_CI = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")


def test_pr_gate_runs_for_pull_requests_and_merge_queue():
    assert "\n  pull_request:\n" in PR_GATE
    assert "branches: [main]" in PR_GATE
    assert "\n  merge_group:\n" in PR_GATE
    assert "\n  workflow_dispatch:\n" in PR_GATE


def test_pr_gate_is_read_only_and_infrastructure_free():
    assert "contents: read" in PR_GATE
    assert "contents: write" not in PR_GATE
    assert "postgres:" not in PR_GATE
    assert "OCTO_POSTGRES_URL" not in PR_GATE
    assert "OCTO_NATS_URL" not in PR_GATE
    assert "docker run" not in PR_GATE


def test_pr_gate_uses_the_shared_lint_and_runs_unit_tests():
    assert "./scripts/ci-lint.sh" in PR_GATE
    assert "python -m compileall scanner api tests agent" in PR_GATE
    assert 'OCTO_REQUIRE_INTEGRATION: "0"' in PR_GATE
    assert "python -m pytest -q --maxfail=1" in PR_GATE


def test_expensive_full_ci_stays_manual():
    assert "\n  workflow_dispatch:\n" in FULL_CI
    assert "\n  # pull_request:\n" in FULL_CI
