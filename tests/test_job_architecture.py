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


def _imported_names(tree: ast.Module) -> set[str]:
    """Every name the module could reach: dotted paths and bound aliases both.

    ``from api.services import quotas`` binds ``quotas`` while its ``module``
    is ``api.services``, so looking only at ``node.module`` — as the first
    version of this guard did — misses exactly the imports worth forbidding.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                names.add(alias.name.split(".", 1)[0])
                names.add(alias.asname or alias.name.split(".")[-1])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".", 1)[0])
            for alias in node.names:
                names.add(f"{node.module}.{alias.name}")
                names.add(alias.asname or alias.name)
    return names


# Anything that would make the facade a decision-maker again rather than a
# forwarding table: persistence, process lifecycle, the broker, the filesystem,
# and every admission policy the split moved into scan_admission.
FORBIDDEN_FACADE_IMPORTS = {
    "sqlalchemy",
    "subprocess",
    "os",
    "shutil",
    "signal",
    "json",
    "uuid",
    "quotas",
    "maintenance",
    "scan_policy",
    "scan_scopes",
    "scan_intents",
    "scan_surface",
    "promoted_domains",
    "agent_groups",
    "agents",
    "results_ingest",
    "nats_bus",
    "artifact_store",
    "metrics",
    "workflow_events",
    "get_session",
    "models",
}


def test_jobs_facade_does_not_take_persistence_or_process_dependencies():
    offenders = _imported_names(_tree(SERVICES / "jobs.py")) & FORBIDDEN_FACADE_IMPORTS
    assert not offenders, (
        f"jobs.py imports {sorted(offenders)}; it is a compatibility facade. "
        "Persistence belongs in job_repository/job_store, process lifecycle in "
        "local_scan_executor, and admission policy in scan_admission"
    )


# ``_now`` is a two-line naive-UTC clock the older tests read their timestamps
# from. It decides nothing, so it is the one function here that is allowed not
# to forward.
FACADE_NOT_DELEGATING = {"_now"}


def test_jobs_facade_functions_only_forward():
    """The import guard above is necessary but not sufficient.

    Re-adding a quota check to the facade needs no new import if the module it
    calls is already there, and re-adding a branch ("skip the offer when the
    group is empty") needs no import at all. So this asserts the shape instead:
    every function in jobs.py is a docstring plus exactly one call into an
    owning service, which leaves nowhere for a decision to live.
    """
    tree = _tree(SERVICES / "jobs.py")
    owners = {name[: -len(".py")] for name in JOB_IMPLEMENTATION_MODULES}
    owners.add("pagination")

    offenders: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name in FACADE_NOT_DELEGATING:
            continue
        body = [
            stmt
            for stmt in node.body
            if not (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            )
        ]
        if len(body) != 1:
            offenders.append(f"{node.name}: {len(body)} statements, expected 1")
            continue
        stmt = body[0]
        call = stmt.value if isinstance(stmt, ast.Return | ast.Expr) else None
        if not isinstance(call, ast.Call):
            offenders.append(f"{node.name}: body is not a single call")
            continue
        func = call.func
        if (
            not isinstance(func, ast.Attribute)
            or not isinstance(func.value, ast.Name)
            or func.value.id not in owners
        ):
            offenders.append(f"{node.name}: does not forward to an owning service")

    assert not offenders, (
        "jobs.py must stay a forwarding table; put the logic in the owning "
        "service instead: " + "; ".join(offenders)
    )
