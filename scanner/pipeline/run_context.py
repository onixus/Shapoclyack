from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .config_schema import RuntimeConfig


@dataclass(frozen=True)
class RunPaths:
    run_id: str
    output_dir: Path
    state_dir: Path
    logs_dir: Path


def _new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _latest_run_pointer(state_base: Path) -> Path:
    return state_base / "latest_run.json"


def _read_latest_run_id(state_base: Path) -> str | None:
    pointer = _latest_run_pointer(state_base)
    if not pointer.exists():
        return None
    data = json.loads(pointer.read_text(encoding="utf-8"))
    run_id = data.get("run_id")
    return str(run_id) if run_id else None


def _write_latest_run_id(state_base: Path, run_id: str) -> None:
    state_base.mkdir(parents=True, exist_ok=True)
    _latest_run_pointer(state_base).write_text(
        json.dumps({"run_id": run_id}, indent=2) + "\n",
        encoding="utf-8",
    )


def resolve_run_paths(
    runtime: RuntimeConfig,
    *,
    run_id: str | None,
    resume: bool,
) -> RunPaths:
    """Resolve per-run output/state/log directories."""
    output_base = Path(runtime.output_dir)
    state_base = Path(runtime.state_dir)

    if not runtime.per_run_output:
        logs = Path(runtime.logs_dir) if runtime.logs_dir else output_base / "logs"
        rid = run_id or "default"
        return RunPaths(run_id=rid, output_dir=output_base, state_dir=state_base, logs_dir=logs)

    if resume:
        resolved_id = run_id or _read_latest_run_id(state_base)
        if not resolved_id:
            raise ValueError(
                "resume requires --run-id or a previous run recorded in "
                f"{_latest_run_pointer(state_base)}"
            )
    else:
        resolved_id = run_id or _new_run_id()
        _write_latest_run_id(state_base, resolved_id)

    output_dir = output_base / "runs" / resolved_id
    state_dir = state_base / "runs" / resolved_id
    logs_dir = output_dir / "logs"
    return RunPaths(run_id=resolved_id, output_dir=output_dir, state_dir=state_dir, logs_dir=logs_dir)


def write_run_meta(paths: RunPaths, profile_name: str, config_path: str) -> None:
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "run_id": paths.run_id,
        "profile": profile_name,
        "config": config_path,
        "started_at": datetime.now(UTC).isoformat(),
    }
    (paths.output_dir / "run_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
