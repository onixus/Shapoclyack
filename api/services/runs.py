from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from api.schemas import RunDetail, RunSummary, VulnerabilityItem
from api.settings import Settings


def _load_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _run_dirs(settings: Settings) -> list[Path]:
    runs_root = settings.output_dir / "runs"
    if runs_root.is_dir():
        dirs = [path for path in runs_root.iterdir() if path.is_dir()]
        return sorted(dirs, key=lambda path: path.name, reverse=True)

    # Flat layout fallback (per_run_output=false)
    if (settings.output_dir / "summary.json").exists() or (settings.output_dir / "alive_ips.txt").exists():
        return [settings.output_dir]
    return []


def _run_id_for(path: Path, settings: Settings) -> str:
    if path == settings.output_dir:
        return "default"
    return path.name


def list_runs(settings: Settings) -> list[RunSummary]:
    results: list[RunSummary] = []
    for run_dir in _run_dirs(settings):
        run_id = _run_id_for(run_dir, settings)
        meta = _load_json(run_dir / "run_meta.json") or {}
        summary = _load_json(run_dir / "summary.json") or {}
        results.append(
            RunSummary(
                run_id=run_id,
                profile=meta.get("profile") if isinstance(meta, dict) else None,
                started_at=meta.get("started_at") if isinstance(meta, dict) else None,
                config=meta.get("config") if isinstance(meta, dict) else None,
                alive_hosts=summary.get("alive_hosts") if isinstance(summary, dict) else None,
                open_host_port_pairs=summary.get("open_host_port_pairs") if isinstance(summary, dict) else None,
                potential_vulnerabilities=(
                    summary.get("potential_vulnerabilities") if isinstance(summary, dict) else None
                ),
                vulnerable_hosts=summary.get("vulnerable_hosts") if isinstance(summary, dict) else None,
                has_diff=(run_dir / "diff.json").exists(),
                has_summary=(run_dir / "summary.json").exists(),
                path=str(run_dir),
            )
        )
    return results


def get_run_dir(settings: Settings, run_id: str) -> Path | None:
    if run_id == "default":
        candidate = settings.output_dir
        if candidate.is_dir():
            return candidate
        return None
    candidate = settings.output_dir / "runs" / run_id
    return candidate if candidate.is_dir() else None


def get_run_detail(settings: Settings, run_id: str) -> RunDetail | None:
    run_dir = get_run_dir(settings, run_id)
    if run_dir is None:
        return None
    artifacts = sorted(
        str(path.relative_to(run_dir))
        for path in run_dir.rglob("*")
        if path.is_file() and path.stat().st_size < 50_000_000
    )
    return RunDetail(
        run_id=run_id,
        meta=_load_json(run_dir / "run_meta.json") or {},
        summary=_load_json(run_dir / "summary.json"),
        diff=_load_json(run_dir / "diff.json"),
        artifacts=artifacts[:500],
    )


_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


def get_vulnerabilities(settings: Settings, run_id: str, *, limit: int = 5000) -> list[VulnerabilityItem] | None:
    run_dir = get_run_dir(settings, run_id)
    if run_dir is None:
        return None
    raw = _load_json(run_dir / "vulnerabilities.json")
    if raw is None:
        return []
    if not isinstance(raw, list):
        return []
    items: list[VulnerabilityItem] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        items.append(
            VulnerabilityItem(
                host=entry.get("host"),
                port=str(entry.get("port")) if entry.get("port") is not None else None,
                cve=entry.get("cve"),
                cvss=entry.get("cvss"),
                severity=entry.get("severity"),
                script_id=entry.get("script_id"),
            )
        )
    items.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.severity or "unknown").lower(), 4),
            -(float(item.cvss) if item.cvss is not None else -1.0),
            str(item.host or ""),
            str(item.cve or ""),
        )
    )
    return items[:limit]


def read_artifact_text(settings: Settings, run_id: str, relative: str, *, max_bytes: int = 1_000_000) -> str | None:
    run_dir = get_run_dir(settings, run_id)
    if run_dir is None:
        return None
    # Prevent path traversal (reject .. segments even if the HTTP layer normalizes URLs).
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    target = (run_dir / rel).resolve()
    try:
        target.relative_to(run_dir.resolve())
    except ValueError:
        return None
    if not target.is_file():
        return None
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")
