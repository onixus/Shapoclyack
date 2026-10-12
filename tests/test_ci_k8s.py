"""CI must execute Kubernetes contracts when infrastructure is declared available."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JENKINSFILE = (REPO_ROOT / "Jenkinsfile").read_text(encoding="utf-8")


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
    assert render < stage.index('docker.image(PYTHON_IMAGES[PY])'), (
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
