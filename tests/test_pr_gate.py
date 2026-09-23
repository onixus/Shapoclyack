"""Contract for the lightweight GitHub pull-request gate (#345).

The full workflow intentionally remains manual because it builds images, runs
live integration services, SAST, e2e, load tests, Trivy and SBOM generation.
This file protects the cheap gate that every pull request must receive instead
of merely trusting comments in YAML to stay uncommented forever.

The workflow is parsed, not grepped. The first version asserted substrings, and
every one of them survived the edits that actually neuter a gate: `|| true`
after the test command, `continue-on-error: true` on a step, `if: false`, or
`permissions: write-all` next to the untouched `contents: read`. So the parts
that decide what a green check means are compared whole, and anything not on
the expected list — a key, a step, a job — is a failure rather than a pass.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PR_GATE = yaml.safe_load((REPO_ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8"))
FULL_CI = yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

# The gate's commands, in order. Changing one is a decision about what the
# required check proves, so it has to be made here too.
EXPECTED_RUNS = [
    "python -m pip install -r requirements-dev.txt",
    "./scripts/ci-lint.sh",
    "python -m compileall scanner api tests agent",
    "./scripts/ci-pytest.sh --maxfail=1",
]
EXPECTED_USES = ["actions/checkout@v4", "actions/setup-python@v5"]

# Keys a step may carry. `continue-on-error`, `if`, `shell` and
# `working-directory` are absent on purpose: each can turn a failing step into
# a green check without touching the command itself.
STEP_KEYS = {"name", "uses", "with", "run", "env"}
JOB_KEYS = {"name", "runs-on", "timeout-minutes", "steps"}


def _triggers(workflow: dict) -> dict:
    # YAML 1.1 reads a bare `on` key as boolean True; PyYAML follows it.
    return workflow.get("on", workflow.get(True))


def _steps() -> list[dict]:
    return PR_GATE["jobs"]["python"]["steps"]


def test_pr_gate_runs_for_pull_requests_and_merge_queue():
    assert _triggers(PR_GATE) == {
        "pull_request": {"branches": ["main"]},
        "merge_group": None,
        "workflow_dispatch": None,
    }


def test_pr_gate_is_read_only():
    # pull_request_target runs with the base repository's secrets and a
    # writable token on code from a fork; the trigger equality above already
    # excludes it, and the permissions must not widen anywhere below.
    assert "pull_request_target" not in _triggers(PR_GATE)
    assert PR_GATE["permissions"] == {"contents": "read"}
    for name, job in PR_GATE["jobs"].items():
        assert "permissions" not in job, f"job {name} widens the token"


def test_pr_gate_is_a_single_infrastructure_free_job():
    assert set(PR_GATE) <= {"name", "on", True, "permissions", "concurrency", "jobs"}
    assert list(PR_GATE["jobs"]) == ["python"]
    job = PR_GATE["jobs"]["python"]
    # No `services:` (PostgreSQL/NATS), no `container:`, no job-level
    # `continue-on-error`, `if` or `env`.
    assert set(job) <= JOB_KEYS, f"unexpected job keys: {set(job) - JOB_KEYS}"


def test_no_step_can_fail_green():
    for step in _steps():
        label = step.get("name") or step.get("uses")
        assert set(step) <= STEP_KEYS, f"{label}: unexpected keys {set(step) - STEP_KEYS}"


def test_pr_gate_runs_exactly_the_shared_scripts():
    assert [s["uses"] for s in _steps() if "uses" in s] == EXPECTED_USES
    assert [s["run"].strip() for s in _steps() if "run" in s] == EXPECTED_RUNS


def test_only_the_test_step_relaxes_the_integration_gate():
    envs = {s["run"].strip(): s.get("env") for s in _steps() if "run" in s}
    assert envs.pop("./scripts/ci-pytest.sh --maxfail=1") == {
        "OCTO_REQUIRE_INTEGRATION": "0",
        "COV_FAIL_UNDER": "0",
    }
    assert all(env is None for env in envs.values()), envs


def test_expensive_full_ci_stays_manual():
    assert _triggers(FULL_CI) == {"workflow_dispatch": None}
