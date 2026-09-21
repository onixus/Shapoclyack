"""The shared CI scripts and the integration gate that makes a green run mean something.

Two classes of claim live here, both of which used to be checked by nobody:

* the gate in ``tests/conftest.py`` — with the infrastructure declared
  available, a session that skipped the Postgres/NATS suites anyway must not
  exit 0. The arithmetic is tested through ``integration_gate_problems`` rather
  than a nested pytest session: the hooks around it are three lines each, the
  thresholds are the part that can be wrong.
* the two pipelines call the *same* scripts. Spelled out in both files, the
  checks drifted — different Ruff pins, and `agent/` linted by neither.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from tests.conftest import INTEGRATION_SUITES, integration_gate_problems, requires_postgres

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
JENKINSFILE = (REPO_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
CI_WORKFLOW = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

# The packages every lint call has to cover. `agent` is the one that was
# missing: the sensor worker is production code the test matrix compiles.
LINTED_PACKAGES = ["scanner", "api", "tests", "agent"]


# --- integration gate ------------------------------------------------------


def _counts(postgres: tuple[int, int], nats: tuple[int, int]) -> dict[str, tuple[int, int]]:
    """``(collected, skipped)`` per suite, in the shape the gate takes."""
    return {"postgres": postgres, "nats": nats}


def test_a_fully_executed_run_passes_the_gate():
    assert integration_gate_problems(_counts((1232, 0), (5, 0))) == []


def test_a_skipped_postgres_suite_fails_the_gate():
    problems = integration_gate_problems(_counts((1232, 1232), (5, 0)))
    assert problems, "a wholly skipped Postgres suite must not pass"
    assert any("OCTO_POSTGRES_URL" in problem for problem in problems)


def test_a_single_skipped_test_fails_the_gate():
    # Not a threshold on skips: with the database declared available, one
    # skipped row-lock test is one claim the run did not make.
    problems = integration_gate_problems(_counts((1232, 1), (5, 0)))
    assert any("1 of 1232" in problem for problem in problems)


def test_an_empty_collection_fails_the_gate_on_the_floor():
    # The case the skip count alone cannot catch: a conftest change stops
    # applying the mark, nothing is collected, nothing is skipped.
    problems = integration_gate_problems(_counts((0, 0), (0, 0)))
    assert any("floor" in problem for problem in problems)
    assert any("OCTO_NATS_URL" in problem for problem in problems)


@pytest.mark.parametrize("suite", sorted(INTEGRATION_SUITES))
def test_every_gated_suite_names_a_variable_and_a_floor(suite: str):
    var, floor = INTEGRATION_SUITES[suite]
    assert var.startswith("OCTO_")
    assert floor > 0, "a floor of zero passes on an empty collection"


def test_the_gate_recognises_the_suites_by_the_wording_of_their_skip_reasons():
    """The collection hook matches on the skip reason, so the wording is API.

    Rewording ``requires_postgres`` without touching ``INTEGRATION_SUITES``
    would leave the gate counting nothing and passing on the floor check only
    — which is the failure mode the floors exist to catch, one level up.
    """
    postgres_var = INTEGRATION_SUITES["postgres"][0]
    assert postgres_var in requires_postgres.kwargs["reason"]

    nats_var = INTEGRATION_SUITES["nats"][0]
    nats_source = (REPO_ROOT / "tests/test_nats_live.py").read_text(encoding="utf-8")
    assert nats_var in nats_source


# --- shared CI scripts -----------------------------------------------------


@pytest.mark.parametrize(
    "name", ["ci-lint.sh", "ci-pytest.sh", "ci-web.sh", "ci-semgrep.sh"]
)
def test_the_shared_scripts_are_executable(name: str):
    # Both pipelines invoke them as `scripts/<name>` rather than `bash …`, so
    # a lost mode bit is a broken stage, not a style detail.
    mode = (SCRIPTS / name).stat().st_mode
    assert mode & stat.S_IXUSR, f"scripts/{name} is not executable"


def test_the_lint_script_checks_every_package_including_agent(tmp_path: Path):
    """Run the script against a stub ``ruff`` and read back the argv it built.

    A stub rather than the real thing: what is under test is the package list
    and the pin, not whether the tree currently lints.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    argv_file = tmp_path / "argv.txt"
    stub = bindir / "ruff"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$1" == "--version" ]]; then echo "ruff 0.0.0-stub"; exit 0; fi\n'
        f'printf "%s\\n" "$@" > "{argv_file}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)

    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    result = subprocess.run(
        [str(SCRIPTS / "ci-lint.sh")],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    assert argv_file.read_text(encoding="utf-8").split() == ["check", *LINTED_PACKAGES]

    pin = next(
        line.strip()
        for line in (REPO_ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("ruff==")
    )
    assert f"[lint] pinned: {pin}" in result.stdout


@pytest.mark.parametrize("pipeline", ["Jenkinsfile", ".github/workflows/ci.yml"])
def test_no_pipeline_pins_ruff_of_its_own(pipeline: str):
    # requirements-dev.txt is the single pin; scripts/ci-lint.sh reads it. The
    # drift this replaces was 0.15.22 in the Jenkinsfile against 0.15.20 here.
    text = JENKINSFILE if pipeline == "Jenkinsfile" else CI_WORKFLOW
    assert "ruff==" not in text, f"{pipeline} pins Ruff itself"
    assert "ruff check" not in text, f"{pipeline} calls ruff directly, bypassing scripts/ci-lint.sh"


@pytest.mark.parametrize(
    "script", ["ci-lint.sh", "ci-pytest.sh", "ci-web.sh", "ci-semgrep.sh"]
)
def test_both_pipelines_call_the_same_scripts(script: str):
    assert f"scripts/{script}" in JENKINSFILE, f"Jenkinsfile does not call {script}"
    assert f"scripts/{script}" in CI_WORKFLOW, f"ci.yml does not call {script}"


def test_both_pipelines_validate_the_prometheus_rules():
    # The Kustomize stage ran two scripts in Jenkins and one in the workflow.
    for name, text in (("Jenkinsfile", JENKINSFILE), ("ci.yml", CI_WORKFLOW)):
        assert "validate-prometheus-rules.sh" in text, f"{name} skips the Prometheus rules"


def test_the_pytest_script_declares_the_integration_infrastructure():
    body = (SCRIPTS / "ci-pytest.sh").read_text(encoding="utf-8")
    assert "OCTO_REQUIRE_INTEGRATION" in body
    assert "--cov-fail-under" in body
