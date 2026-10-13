"""Shared CI script behavior and pipeline wiring contracts."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
JENKINSFILE = (REPO_ROOT / "Jenkinsfile").read_text(encoding="utf-8")
CI_WORKFLOW = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
PR_GATE_WORKFLOW = (REPO_ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")


# --- shared CI scripts -----------------------------------------------------


@pytest.mark.parametrize("name", ["ci-lint.sh", "ci-pytest.sh", "ci-web.sh", "ci-semgrep.sh", "ci-jenkins-tests.sh"])
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
    assert f"scripts/{script}" in JENKINSFILE + (SCRIPTS / "ci-jenkins-tests.sh").read_text(), f"Jenkinsfile does not call {script}"
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


@pytest.mark.parametrize("failure", ["unraisable", "thread"])
def test_ci_fails_when_passing_assertions_hide_unhandled_errors(tmp_path, failure):
    """Execute the shared script: checking its text would not prove the gate."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "ci-pytest.sh"
    script.write_text((SCRIPTS / script.name).read_text(encoding="utf-8"))
    source = (
        "def test_unraisable():\n"
        "    class Broken:\n"
        "        def __del__(self):\n"
        "            raise RuntimeError('shutdown regression')\n"
        "    obj = Broken()\n"
        "    del obj\n"
        "    assert True\n"
        if failure == "unraisable" else
        "import threading\n"
        "def test_thread():\n"
        "    def broken():\n"
        "        raise RuntimeError('shutdown regression')\n"
        "    thread = threading.Thread(target=broken)\n"
        "    thread.start()\n"
        "    thread.join()\n"
        "    assert True\n"
    )
    (tmp_path / "test_failure.py").write_text(source, encoding="utf-8")
    env = dict(os.environ, OCTO_REQUIRE_INTEGRATION="0")
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env['PATH']}"
    result = subprocess.run(
        ["bash", str(script), "--no-cov", "test_failure.py"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "shutdown regression" in result.stdout + result.stderr
    assert "1 passed" not in result.stdout
