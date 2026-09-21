"""Architecture guards for the split job subsystem.

These tests are intentionally static. The point is to stop the compatibility
facade from becoming the dependency hub again while behavior tests exercise
the individual workflows.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "api" / "services"

JOB_IMPLEMENTATION_MODULES = (
    "scan_admission.py",
    "job_submission.py",
    "job_repository.py",
    "job_store.py",
    "job_control.py",
    "job_leases.py",
    "job_reaper.py",
    "job_results.py",
    "job_inputs.py",
    "job_dispatch.py",
    "local_scan_executor.py",
    "local_job_runner.py",
    "run_completion.py",
    "run_ids.py",
    "run_publisher.py",
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports_job_facade(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "api.services.jobs" for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "api.services.jobs":
                return True
            if node.module == "api.services" and any(
                alias.name == "jobs" for alias in node.names
            ):
                return True
    return False


@pytest.mark.parametrize("name", JOB_IMPLEMENTATION_MODULES)
def test_job_implementation_does_not_import_compatibility_facade(name: str):
    tree = _tree(SERVICES / name)
    assert not _imports_job_facade(tree), (
        f"{name} imports api.services.jobs; depend on the owning job service "
        "instead or the monolith dependency cycle returns"
    )


def test_jobs_facade_does_not_take_persistence_or_process_dependencies():
    tree = _tree(SERVICES / "jobs.py")
    forbidden = {"sqlalchemy", "subprocess"}

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(
                alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])

    assert not (imported & forbidden), (
        "jobs.py is a compatibility facade; persistence and process lifecycle "
        "belong in job_repository/job_store and local_scan_executor"
    )
