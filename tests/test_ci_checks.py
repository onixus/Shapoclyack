"""The shared CI scripts and the integration gate that makes a green run mean something.

Two classes of claim live here, both of which used to be checked by nobody:

* the gate in ``tests/integration_gate.py`` — with the infrastructure declared
  available, a session that skipped or deselected the Postgres/NATS suites must
  not exit 0. The hooks are driven through real pytest sessions in a throwaway
  suite (``_run_gate``) rather than by handing the arithmetic tuples: the first
  version of these tests only ever called ``integration_gate_problems`` and
  stayed green when every hook body was deleted, including the one that had the
  bug — ``pytest -k something`` counted the whole suite as having run.
* the two pipelines call the *same* scripts. Spelled out in both files, the
  checks drifted — different Ruff pins, and `agent/` linted by neither.
"""

from __future__ import annotations

import importlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests import integration_gate
from tests.conftest import requires_postgres
from tests.integration_gate import (
    INTEGRATION_SUITES,
    integration_gate_problems,
    suite_for_reason,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
JENKINSFILE = (REPO_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
CI_WORKFLOW = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
PR_GATE_WORKFLOW = (REPO_ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")


# --- the gate, driven through real sessions --------------------------------

_GATED_SUITE = """\
import os

import pytest

pytestmark = pytest.mark.skipif(
    {condition},
    reason={reason!r},
)

{tests}
"""


def _write_gated_suite(
    directory: Path,
    *,
    postgres_reason: str = "OCTO_POSTGRES_URL not set (throwaway suite)",
    nats_reason: str = "OCTO_NATS_URL not set (throwaway suite)",
    postgres_condition: str = 'not os.environ.get("OCTO_POSTGRES_URL")',
) -> None:
    """A miniature stand-in for the repository's gated suites.

    Three Postgres-gated tests and two NATS-gated ones, marked the way the real
    ones are: a module-level ``skipif`` whose reason names the variable. The
    conftest imports the gate module itself, so what runs here is the code that
    runs in CI, hooks included.
    """
    (directory / "conftest.py").write_text(
        "from tests.integration_gate import (\n"
        "    pytest_collection_modifyitems,\n"
        "    pytest_configure,\n"
        "    pytest_runtest_logreport,\n"
        "    pytest_sessionfinish,\n"
        "    pytest_terminal_summary,\n"
        ")\n",
        encoding="utf-8",
    )
    (directory / "test_gated_postgres.py").write_text(
        _GATED_SUITE.format(
            condition=postgres_condition,
            reason=postgres_reason,
            tests="\n".join(f"def test_pg_{n}():\n    pass\n" for n in range(3)),
        ),
        encoding="utf-8",
    )
    (directory / "test_gated_nats.py").write_text(
        _GATED_SUITE.format(
            condition='not os.environ.get("OCTO_NATS_URL")',
            reason=nats_reason,
            tests="\n".join(f"def test_nats_{n}():\n    pass\n" for n in range(2)),
        ),
        encoding="utf-8",
    )


def _run_gate(
    directory: Path, *args: str, env: dict[str, str | None] | None = None, **kwargs
) -> subprocess.CompletedProcess[str]:
    """Run pytest over the throwaway suite and return the finished process."""
    _write_gated_suite(directory, **kwargs)
    child_env = dict(
        os.environ,
        PYTHONPATH=str(REPO_ROOT),
        OCTO_REQUIRE_INTEGRATION="1",
        OCTO_POSTGRES_URL="postgresql://gate.invalid/none",
        OCTO_NATS_URL="nats://gate.invalid:4222",
    )
    for key, value in (env or {}).items():
        if value is None:
            child_env.pop(key, None)
        else:
            child_env[key] = value
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:randomly", "-p", "no:cacheprovider", *args],
        cwd=directory,
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_fully_executed_run_passes_the_gate(tmp_path: Path):
    result = _run_gate(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "postgres: 3 ran, 0 skipped, 0 never ran, 3 collected" in result.stdout
    assert "nats: 2 ran, 0 skipped, 0 never ran, 2 collected" in result.stdout


def test_a_selection_that_runs_two_tests_cannot_pass_as_the_whole_suite(tmp_path: Path):
    """The hole this gate had: ``-k`` deselects after the collection hook counted.

    ``scripts/ci-pytest.sh`` passes the caller's arguments through, so a stage
    added as `COV_FAIL_UNDER=0 scripts/ci-pytest.sh -k "not slow"` used to print
    "postgres: 1232 ran" and exit 0 with two tests executed.
    """
    result = _run_gate(tmp_path, "-k", "test_pg_0 or test_nats_0")
    assert result.returncode != 0, result.stdout
    assert "postgres: 1 ran, 0 skipped, 2 never ran, 3 collected" in result.stdout
    assert "2 of 3 tests never ran" in result.stdout


def test_a_suite_skipped_with_its_variable_set_fails_the_gate(tmp_path: Path):
    # The reachability case: the URL is there, the suite skips anyway. Nothing
    # in the current marks can do this, which is why it is worth a test — the
    # next gate that probes the database rather than the variable will.
    result = _run_gate(tmp_path, postgres_condition="True")
    assert result.returncode != 0, result.stdout
    assert "3 of 3 tests skipped although OCTO_POSTGRES_URL is declared available" in result.stdout


def test_a_reworded_skip_reason_fails_the_gate_instead_of_emptying_it(tmp_path: Path):
    # The gate matches suites by the variable named in the skip reason. Reword
    # the reason and the suite stops being recognised — which has to be red, not
    # an empty set passing quietly.
    result = _run_gate(tmp_path, nats_reason="live broker not configured")
    assert result.returncode != 0, result.stdout
    assert "no tests recognised as gated on OCTO_NATS_URL" in result.stdout


def test_a_missing_url_fails_before_collection(tmp_path: Path):
    result = _run_gate(tmp_path, env={"OCTO_POSTGRES_URL": None})
    assert result.returncode != 0
    assert "OCTO_POSTGRES_URL is unset" in result.stderr + result.stdout
    assert "collected" not in result.stdout, "the run must not reach collection"


def test_without_the_flag_nothing_changes(tmp_path: Path):
    # Skipping stays the right default on a laptop: no flag, no gate, not even
    # the summary section.
    result = _run_gate(tmp_path, "-k", "test_pg_0", env={"OCTO_REQUIRE_INTEGRATION": "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "integration gate" not in result.stdout


def test_the_repository_conftest_registers_the_gate_hooks():
    """tests/conftest.py is what makes the hooks apply to the real suite.

    The sessions above import the gate module directly, so they would stay green
    if the import in conftest were dropped or a hook redefined there.
    """
    conftest = importlib.import_module("tests.conftest")
    hooks = [
        "pytest_configure",
        "pytest_collection_modifyitems",
        "pytest_runtest_logreport",
        "pytest_terminal_summary",
        "pytest_sessionfinish",
    ]
    for hook in hooks:
        assert getattr(conftest, hook, None) is getattr(integration_gate, hook), (
            f"tests/conftest.py does not register the gate's {hook}"
        )


# --- the gate's arithmetic, read directly ----------------------------------


def _counts(
    postgres: tuple[int, int, int], nats: tuple[int, int, int]
) -> dict[str, tuple[int, int, int]]:
    """``(collected, executed, skipped)`` per suite, in the shape the gate takes."""
    return {"postgres": postgres, "nats": nats}


def test_a_single_skipped_test_fails_the_gate():
    # Not a threshold on skips: with the database declared available, one
    # skipped row-lock test is one claim the run did not make.
    problems = integration_gate_problems(_counts((1232, 1231, 1), (5, 5, 0)))
    assert any("1 of 1232" in problem for problem in problems)


def test_an_empty_collection_fails_the_gate():
    # A conftest change stops applying the mark: nothing collected, nothing
    # skipped, nothing deselected. There is no floor to catch this any more, and
    # none is needed — zero recognised tests is the condition itself.
    problems = integration_gate_problems(_counts((0, 0, 0), (0, 0, 0)))
    assert any("no tests recognised as gated on OCTO_NATS_URL" in p for p in problems)


@pytest.mark.parametrize("suite", sorted(INTEGRATION_SUITES))
def test_every_gated_suite_names_a_variable(suite: str):
    assert INTEGRATION_SUITES[suite].startswith("OCTO_")


def test_the_gate_recognises_the_postgres_suite_by_the_wording_of_its_skip_reason():
    """The collection hook matches on the skip reason, so the wording is API.

    Asserted against the mark itself, not by grepping the file: ``OCTO_POSTGRES_URL``
    also appears in an ``os.environ.get`` call and a docstring two lines away, so
    a file-wide search stays green through exactly the rewording it is meant to
    catch.
    """
    assert suite_for_reason(requires_postgres.kwargs["reason"]) == "postgres"


def test_the_gate_recognises_the_nats_suite_by_the_wording_of_its_skip_reason():
    module = importlib.import_module("tests.test_nats_live")
    assert suite_for_reason(module.pytestmark.kwargs["reason"]) == "nats"


# --- shared CI scripts -----------------------------------------------------


@pytest.mark.parametrize("name", ["ci-lint.sh", "ci-pytest.sh", "ci-web.sh", "ci-semgrep.sh"])
def test_the_shared_scripts_are_executable(name: str):
    # Both pipelines invoke them as `scripts/<name>` rather than `bash …`, so
    # a lost mode bit is a broken stage, not a style detail.
    mode = (SCRIPTS / name).stat().st_mode
    assert mode & stat.S_IXUSR, f"scripts/{name} is not executable"


# Directories ruff itself never descends into (build output, caches, vendored
# trees). Everything else is walked, so a `.py` in a new top-level directory
# counts against the lint scope the moment it appears.
_WALK_PRUNE = frozenset(
    {
        "node_modules",
        "__pycache__",
        "venv",
        "dist",
        "build",
        "target",
        "htmlcov",
    }
)


def _python_files_in_tree() -> list[str]:
    """Every .py under the repository root, as forward-slash relative paths."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [
            name for name in dirnames if name not in _WALK_PRUNE and not name.startswith(".")
        ]
        for filename in filenames:
            if filename.endswith(".py"):
                found.append(str(Path(dirpath, filename).relative_to(REPO_ROOT)))
    return sorted(found)


def _ruff_pin() -> str:
    return next(
        line.strip()
        for line in (REPO_ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("ruff==")
    )


def _run_lint_with_stub_ruff(
    tmp_path: Path, *, version: str | None = None, env: dict[str, str] | None = None
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run scripts/ci-lint.sh against a stub ``ruff`` that records its argv.

    A stub rather than the real thing: what is under test is the scope and the
    pin check, not whether the tree currently lints.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    argv_file = tmp_path / "argv.txt"
    stub = bindir / "ruff"
    reported = version if version is not None else _ruff_pin().removeprefix("ruff==")
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'if [[ "$1" == "--version" ]]; then echo "ruff {reported}"; exit 0; fi\n'
        f'printf "%s\\n" "$@" > "{argv_file}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)

    child_env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", **(env or {}))
    result = subprocess.run(
        [str(SCRIPTS / "ci-lint.sh")],
        cwd=REPO_ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, argv_file


def test_the_lint_scope_leaves_no_tracked_python_file_out(tmp_path: Path):
    """The scope has to cover every tracked .py, not a package list that ages.

    The list it replaces was `scanner api tests agent`, which missed the seven
    .py files under scripts/ and k8s/scripts/ — including the ones this very
    branch adds to.
    """
    result, argv_file = _run_lint_with_stub_ruff(tmp_path)
    assert result.returncode == 0, result.stderr

    argv = argv_file.read_text(encoding="utf-8").split()
    assert argv[0] == "check"
    targets = [Path(target) for target in argv[1:]]
    assert targets, "ci-lint.sh passed ruff no targets"

    present = _python_files_in_tree()
    # Not `git ls-files`: this test has to run in the same containers the suite
    # runs in, and the one Jenkins uses for the Tests stage has no usable git
    # (the first version of it died there with returncode 255). A check that
    # quietly skips wherever its tooling is missing is the exact defect this
    # branch is about, so it walks the tree itself instead.
    assert any(path.startswith("scripts/") for path in present), (
        "the walk found no scripts/*.py — _WALK_PRUNE is pruning too much"
    )
    uncovered = [
        path
        for path in present
        if not any(target == Path(".") or Path(path).is_relative_to(target) for target in targets)
    ]
    assert not uncovered, f"outside the lint scope {argv[1:]}: {uncovered}"

    assert f"[lint] pinned: {_ruff_pin()}" in result.stdout


def test_the_lint_refuses_a_ruff_that_is_not_the_pin(tmp_path: Path):
    # docs/development.md promises that a local pass means the CI lint passes.
    # It only does while the two versions agree, so the script says so.
    result, _ = _run_lint_with_stub_ruff(tmp_path, version="0.0.0-not-the-pin")
    assert result.returncode == 1
    assert "is not the pinned" in result.stderr
    assert _ruff_pin() in result.stderr, "the message has to name the install command"


def test_the_lint_can_be_told_to_accept_a_different_ruff(tmp_path: Path):
    result, argv_file = _run_lint_with_stub_ruff(
        tmp_path, version="0.0.0-not-the-pin", env={"OCTO_LINT_ALLOW_RUFF_DRIFT": "1"}
    )
    assert result.returncode == 0, result.stderr
    assert "warning" in result.stderr
    assert argv_file.exists(), "the check must still run"


def _run_semgrep_with_stub_docker(
    tmp_path: Path, *args: str, mount_holds_repo: bool = True
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run scripts/ci-semgrep.sh against a stub ``docker`` that logs its argv."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker.log"
    stub = bindir / "docker"
    probe_status = 0 if mount_holds_repo else 1
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        f'if [[ "$*" == *"test -f"* ]]; then exit {probe_status}; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)

    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    result = subprocess.run(
        [str(SCRIPTS / "ci-semgrep.sh"), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def test_the_sast_scan_refuses_a_mount_that_does_not_hold_the_repository(tmp_path: Path):
    """`docker run -v X:/src` is resolved by the host daemon.

    Wrap this stage in `docker { image … }` and X becomes a path inside that
    container, which on the host is some other directory or none. Semgrep only
    catches the "none" half itself; a directory that exists and is not this
    repository it scans happily and exits 0. The probe turns that silent green
    into a red build.
    """
    result, calls = _run_semgrep_with_stub_docker(tmp_path, mount_holds_repo=False)
    assert result.returncode != 0
    assert "requirements-dev.txt" in result.stderr
    assert not any("semgrep scan" in call for call in calls), "scanned despite an empty mount"


def test_the_sast_scan_mounts_the_root_it_is_given(tmp_path: Path):
    result, calls = _run_semgrep_with_stub_docker(tmp_path, "/host/workspace")
    assert result.returncode == 0, result.stderr
    assert calls, "the script ran no docker command"
    assert all("-v /host/workspace:/src" in call for call in calls)
    assert sum("semgrep scan" in call for call in calls) == 2, "both passes have to run"


_PIPELINES = {
    "Jenkinsfile": JENKINSFILE,
    ".github/workflows/ci.yml": CI_WORKFLOW,
    ".github/workflows/pr-gate.yml": PR_GATE_WORKFLOW,
}


@pytest.mark.parametrize("pipeline", sorted(_PIPELINES))
def test_no_pipeline_pins_ruff_of_its_own(pipeline: str):
    # requirements-dev.txt is the single pin; scripts/ci-lint.sh reads it. The
    # drift this replaces was 0.15.22 in the Jenkinsfile against 0.15.20 here.
    text = _PIPELINES[pipeline]
    assert "ruff==" not in text, f"{pipeline} pins Ruff itself"
    assert "ruff check" not in text, f"{pipeline} calls ruff directly, bypassing scripts/ci-lint.sh"


@pytest.mark.parametrize("doc", ["README.md", "README.ru.md", "docs/development.md"])
def test_the_docs_send_developers_to_the_same_lint(doc: str):
    # The README told developers `ruff check .` while docs/development.md told
    # them scripts/ci-lint.sh, which linted four packages — two scopes and one
    # of them narrower than CI's.
    text = (REPO_ROOT / doc).read_text(encoding="utf-8")
    assert "scripts/ci-lint.sh" in text, f"{doc} does not name the lint script"
    assert "ruff check" not in text, f"{doc} spells out a ruff invocation of its own"


@pytest.mark.parametrize("script", ["ci-lint.sh", "ci-pytest.sh", "ci-web.sh", "ci-semgrep.sh"])
def test_both_pipelines_call_the_same_scripts(script: str):
    assert f"scripts/{script}" in JENKINSFILE, f"Jenkinsfile does not call {script}"
    assert f"scripts/{script}" in CI_WORKFLOW, f"ci.yml does not call {script}"


@pytest.mark.parametrize("script", ["ci-lint.sh", "ci-pytest.sh"])
def test_the_pr_gate_calls_the_same_scripts(script: str):
    # The PR gate is the Python half only (no web, Semgrep or manifests), but
    # that half goes through the same scripts, not a pytest line of its own.
    assert f"scripts/{script}" in PR_GATE_WORKFLOW, f"pr-gate.yml does not call {script}"
    assert "python -m pytest" not in PR_GATE_WORKFLOW, "pr-gate.yml calls pytest directly"


def test_ruff_targets_the_oldest_python_the_matrix_runs():
    # The PR gate runs 3.12 only and leans on Ruff to reject 3.12-only syntax;
    # with no target-version Ruff parses against its newest grammar and does not.
    matrix = re.search(r"for \(PY in \[([^\]]*)\]\)", JENKINSFILE)
    assert matrix, "the Jenkinsfile Python matrix moved; update this test"
    versions = re.findall(r"'3\.(\d+)'", matrix.group(1))
    oldest = min(int(minor) for minor in versions)
    ruff_toml = (REPO_ROOT / "ruff.toml").read_text(encoding="utf-8")
    assert re.search(rf'^target-version = "py3{oldest}"$', ruff_toml, re.MULTILINE), (
        f"ruff.toml must target py3{oldest}, the oldest Python the Jenkinsfile tests"
    )


def test_both_pipelines_validate_the_prometheus_rules():
    # The Kustomize stage ran two scripts in Jenkins and one in the workflow.
    for name, text in (("Jenkinsfile", JENKINSFILE), ("ci.yml", CI_WORKFLOW)):
        assert "validate-prometheus-rules.sh" in text, f"{name} skips the Prometheus rules"


def test_the_pytest_script_declares_the_integration_infrastructure():
    body = (SCRIPTS / "ci-pytest.sh").read_text(encoding="utf-8")
    assert "OCTO_REQUIRE_INTEGRATION" in body
    assert "--cov-fail-under" in body


# ---------------------------------------------------------------------------
# The Kubernetes contract has to run where CI says it ran (#338 review)
# ---------------------------------------------------------------------------


def _jenkins_stage(name: str) -> str:
    start = JENKINSFILE.index(f"stage('{name}')")
    following = JENKINSFILE.find("\n    stage('", start + 1)
    return JENKINSFILE[start : following if following != -1 else len(JENKINSFILE)]


def test_the_jenkins_test_containers_are_handed_the_rendered_manifests():
    """The Tests stage runs pytest in python:slim, which has no kubectl, so
    79 of the Kubernetes contract tests skipped on every build while the
    stage reported green. The Jenkins node has kubectl (the Kustomize stage
    uses it): render there, hand the directory in."""
    stage = _jenkins_stage("Tests")
    render = stage.index("validate-kustomize.sh")
    assert render < stage.index('docker.image("python:${PY}-slim")'), (
        "the render has to happen on the node, before the python container starts"
    )
    assert "'OCTO_K8S_RENDER_DIR=" in stage, "the directory is not passed into the container"


def _contract_run(tmp_path: Path, require: str) -> subprocess.CompletedProcess[str]:
    # No kubectl, no kustomize, no render directory: an empty PATH is the
    # python:slim container as far as shutil.which is concerned.
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("OCTO_K8S_RENDER_DIR", "PATH")
    }
    env.update(
        PATH=str(tmp_path),
        OCTO_REQUIRE_INTEGRATION=require,
        OCTO_POSTGRES_URL=env.get("OCTO_POSTGRES_URL") or "postgresql+psycopg://unused@127.0.0.1:1/x",
        OCTO_NATS_URL=env.get("OCTO_NATS_URL") or "nats://127.0.0.1:1",
    )
    return subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            "-rs",
            "tests/test_k8s_pod_security.py::test_every_exception_is_still_needed",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_the_k8s_contract_fails_rather_than_skips_when_ci_declares_its_infrastructure(tmp_path):
    result = _contract_run(tmp_path, "1")
    assert "1 failed" in result.stdout, result.stdout[-2000:]
    assert "OCTO_K8S_RENDER_DIR" in result.stdout


def test_the_k8s_contract_still_skips_on_a_laptop_without_kubectl(tmp_path):
    result = _contract_run(tmp_path, "0")
    assert result.returncode == 0, result.stdout[-2000:]
    assert "1 skipped" in result.stdout
