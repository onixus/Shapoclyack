from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.schemas import JobInfo, StartScanRequest
from api.services.targets import parse_target_payload
from api.settings import Settings

_LOCK = threading.Lock()
_JOBS: dict[str, dict[str, Any]] = {}


def _jobs_file(settings: Settings) -> Path:
    return settings.state_dir / "api_jobs.json"


def _persist(settings: Settings) -> None:
    path = _jobs_file(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(list(_JOBS.values()), indent=2) + "\n", encoding="utf-8")


def load_jobs(settings: Settings) -> None:
    path = _jobs_file(settings)
    if not path.exists():
        return
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    if not isinstance(raw, list):
        return
    with _LOCK:
        for item in raw:
            if isinstance(item, dict) and item.get("job_id"):
                _JOBS[str(item["job_id"])] = item


def list_jobs() -> list[JobInfo]:
    with _LOCK:
        items = sorted(_JOBS.values(), key=lambda item: item.get("started_at") or "", reverse=True)
    return [JobInfo.model_validate(item) for item in items]


def get_job(job_id: str) -> JobInfo | None:
    with _LOCK:
        item = _JOBS.get(job_id)
    return JobInfo.model_validate(item) if item else None


def _update_job(settings: Settings, job_id: str, **fields: Any) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job.update(fields)
        _persist(settings)


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    if body:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def _prepare_target_inputs(
    settings: Settings,
    job_id: str,
    request: StartScanRequest,
) -> tuple[Path | None, dict[str, int] | None, list[str]]:
    """Write per-job input files when overrides are provided.

    Returns (inputs_dir, target_counts, extra_cli_args).
    """
    parsed = parse_target_payload(
        ranges_text=request.ranges,
        domains_text=request.domains,
        ports_text=request.ports,
    )
    if parsed is None:
        return None, None, []

    inputs_dir = settings.state_dir / "job_inputs" / job_id
    inputs_dir.mkdir(parents=True, exist_ok=True)
    extra: list[str] = []
    counts: dict[str, int] = {}

    if parsed.ranges is not None and parsed.domains is not None:
        ranges_path = inputs_dir / "ranges.txt"
        domains_path = inputs_dir / "domains.txt"
        _write_lines(ranges_path, parsed.ranges)
        _write_lines(domains_path, parsed.domains)
        extra.extend(["--ranges", str(ranges_path), "--domains", str(domains_path)])
        counts["ranges"] = len(parsed.ranges)
        counts["domains"] = len(parsed.domains)

    if parsed.ports is not None:
        ports_path = inputs_dir / "ports.txt"
        _write_lines(ports_path, parsed.ports)
        extra.extend(["--ports-file", str(ports_path)])
        counts["ports"] = len(parsed.ports)

    return inputs_dir, counts or None, extra


def _run_job(settings: Settings, job_id: str, command: list[str]) -> None:
    _update_job(settings, job_id, status="running", started_at=datetime.now(UTC).isoformat())
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        # Best-effort: read latest_run.json after completion.
        run_id = None
        pointer = settings.state_dir / "latest_run.json"
        if pointer.exists():
            try:
                run_id = json.loads(pointer.read_text(encoding="utf-8")).get("run_id")
            except json.JSONDecodeError:
                run_id = None
        status = "succeeded" if completed.returncode == 0 else "failed"
        error = None
        if completed.returncode != 0:
            error = (completed.stderr or completed.stdout or f"exit {completed.returncode}")[:2000]
        _update_job(
            settings,
            job_id,
            status=status,
            finished_at=datetime.now(UTC).isoformat(),
            exit_code=completed.returncode,
            run_id=str(run_id) if run_id else None,
            error=error,
        )
    except Exception as exc:  # noqa: BLE001
        logging.exception("Scan job %s failed", job_id)
        _update_job(
            settings,
            job_id,
            status="failed",
            finished_at=datetime.now(UTC).isoformat(),
            error=str(exc)[:2000],
        )


def start_scan(settings: Settings, request: StartScanRequest, *, username: str) -> JobInfo:
    if not settings.allow_scan_start:
        raise RuntimeError("Scan start disabled by OCTO_ALLOW_SCAN_START")

    job_id = uuid.uuid4().hex[:12]
    _, target_counts, target_args = _prepare_target_inputs(settings, job_id, request)

    command = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        str(settings.config_path),
        "--mode",
        request.mode,
    ]
    if request.delta:
        command.append("--delta")
    if request.skip_nse:
        command.append("--skip-nse")
    if request.notify:
        command.append("--notify")
    if request.export_defectdojo:
        command.append("--export-defectdojo")
    if request.run_id:
        command.extend(["--run-id", request.run_id])
    command.extend(target_args)

    record = {
        "job_id": job_id,
        "status": "queued",
        "run_id": request.run_id,
        "mode": request.mode,
        "command": command,
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "error": None,
        "requested_by": username,
        "target_counts": target_counts,
    }
    with _LOCK:
        _JOBS[job_id] = record
        _persist(settings)

    thread = threading.Thread(target=_run_job, args=(settings, job_id, command), daemon=True)
    thread.start()
    return JobInfo.model_validate(record)
