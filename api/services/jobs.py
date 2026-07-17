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

from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import agents as agents_service
from api.services import nats_bus
from api.services import results_ingest
from api.services import tenants as tenants_service
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
        ports_udp_text=request.ports_udp,
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

    if parsed.ports_udp is not None:
        ports_udp_path = inputs_dir / "ports_udp.txt"
        _write_lines(ports_udp_path, parsed.ports_udp)
        extra.extend(["--ports-udp-file", str(ports_udp_path)])
        counts["ports_udp"] = len(parsed.ports_udp)

    return inputs_dir, counts or None, extra


def _build_command(
    settings: Settings,
    request: StartScanRequest,
    *,
    run_id: str | None,
    target_args: list[str],
) -> list[str]:
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
    if run_id:
        command.extend(["--run-id", run_id])
    command.extend(target_args)
    return command


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

    tenant_id = (request.tenant_id or tenants_service.DEFAULT_TENANT_ID).strip()
    tenant = tenants_service.get_tenant(tenant_id)
    if tenant is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")
    if tenant.get("status") != "active":
        raise ValueError(f"Tenant is not active: {tenant_id}")

    job_id = uuid.uuid4().hex[:12]
    execution = "agent" if settings.job_execution_mode == "agent" else "local"
    run_id = request.run_id
    if execution == "agent" and not run_id:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    _, target_counts, target_args = _prepare_target_inputs(settings, job_id, request)
    command = _build_command(settings, request, run_id=run_id, target_args=target_args)

    queued_at = datetime.now(UTC).isoformat()
    record: dict[str, Any] = {
        "job_id": job_id,
        "status": "queued",
        "run_id": run_id,
        "mode": request.mode,
        "command": command,
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "error": None,
        "requested_by": username,
        "target_counts": target_counts,
        "execution": execution,
        "assigned_agent_id": None,
        "queued_at": queued_at,
        "tenant_id": tenant_id,
        "scan_options": {
            "mode": request.mode,
            "delta": request.delta,
            "skip_nse": request.skip_nse,
            "notify": request.notify,
            "export_defectdojo": request.export_defectdojo,
        },
    }
    with _LOCK:
        _JOBS[job_id] = record
        _persist(settings)

    if execution == "local":
        thread = threading.Thread(target=_run_job, args=(settings, job_id, command), daemon=True)
        thread.start()
    elif execution == "agent" and settings.nats_url:
        _publish_job_offer(settings, job_id)

    return JobInfo.model_validate(record)


def _claim_payload(settings: Settings, job: dict[str, Any]) -> dict[str, Any]:
    job_id = str(job["job_id"])
    opts = dict(job.get("scan_options") or {})
    mode = str(job.get("mode") or opts.get("mode") or "balanced")
    run_id = str(job.get("run_id") or "")
    return {
        "job_id": job_id,
        "run_id": run_id,
        "mode": mode,
        "delta": bool(opts.get("delta", False)),
        "skip_nse": bool(opts.get("skip_nse", False)),
        "notify": bool(opts.get("notify", False)),
        "export_defectdojo": bool(opts.get("export_defectdojo", False)),
        "inputs": _read_job_inputs(settings, job_id),
        "tenant_id": str(job.get("tenant_id") or tenants_service.DEFAULT_TENANT_ID),
    }


def _publish_job_offer(settings: Settings, job_id: str) -> None:
    job = get_job(job_id)
    if job is None:
        return
    with _LOCK:
        raw = dict(_JOBS.get(job_id) or {})
    payload = _claim_payload(settings, raw)
    bus = nats_bus.get_bus(settings.nats_url)
    if bus is None:
        logging.getLogger(__name__).warning(
            "NATS configured but unavailable; job %s stays queued for HTTP claim",
            job_id,
        )
        return
    if bus.publish_job_offer(payload):
        logging.getLogger(__name__).info("Published jobs.scan offer for %s", job_id)
    else:
        logging.getLogger(__name__).warning(
            "Failed to publish jobs.scan for %s; HTTP claim still available",
            job_id,
        )


def _read_job_inputs(settings: Settings, job_id: str) -> dict[str, str]:
    inputs_dir = settings.state_dir / "job_inputs" / job_id
    if not inputs_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for name in ("ranges.txt", "domains.txt", "ports.txt", "ports_udp.txt"):
        path = inputs_dir / name
        if path.is_file():
            out[name] = path.read_text(encoding="utf-8")
    return out


def claim_job(
    settings: Settings,
    agent_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
) -> AgentClaimResponse | None:
    """Assign a queued agent job to ``agent_id``, or return None.

    When ``job_id`` is set (NATS pull path), assign that specific job if still queued.
    When ``tenant_id`` is set, only jobs for that tenant are eligible.
    """
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise LookupError("Unknown agent_id; register first")
    effective_tenant = tenant_id or agent.tenant_id

    with _LOCK:
        if job_id:
            job = _JOBS.get(job_id)
            if (
                job is None
                or job.get("execution") != "agent"
                or job.get("status") != "queued"
                or job.get("assigned_agent_id")
                or str(job.get("tenant_id") or "default") != effective_tenant
            ):
                return None
            candidates = [job]
        else:
            candidates = [
                job
                for job in _JOBS.values()
                if job.get("execution") == "agent"
                and job.get("status") == "queued"
                and not job.get("assigned_agent_id")
                and str(job.get("tenant_id") or "default") == effective_tenant
            ]
            candidates.sort(key=lambda item: str(item.get("queued_at") or item.get("job_id")))
        if not candidates:
            return None
        job = candidates[0]
        job["status"] = "running"
        job["assigned_agent_id"] = agent_id
        job["started_at"] = datetime.now(UTC).isoformat()
        _persist(settings)
        claimed_id = str(job["job_id"])
        run_id = str(job.get("run_id") or "")
        opts = dict(job.get("scan_options") or {})
        mode = str(job.get("mode") or opts.get("mode") or "balanced")
        job_tenant = str(job.get("tenant_id") or "default")

    if not run_id:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        _update_job(settings, claimed_id, run_id=run_id)

    agents_service.touch_job(agent_id, claimed_id, status="busy")
    return AgentClaimResponse(
        job_id=claimed_id,
        run_id=run_id,
        mode=mode,
        delta=bool(opts.get("delta", False)),
        skip_nse=bool(opts.get("skip_nse", False)),
        notify=bool(opts.get("notify", False)),
        export_defectdojo=bool(opts.get("export_defectdojo", False)),
        inputs=_read_job_inputs(settings, claimed_id),
        tenant_id=job_tenant,
    )


def complete_job(
    settings: Settings,
    job_id: str,
    *,
    agent_id: str,
    exit_code: int,
    error: str | None = None,
    run_id: str | None = None,
    archive_bytes: bytes | None = None,
    tenant_id: str | None = None,
) -> JobInfo:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            raise LookupError("Job not found")
        if job.get("execution") != "agent":
            raise ValueError("Job is not an agent job")
        if job.get("assigned_agent_id") != agent_id:
            raise PermissionError("Job is assigned to a different agent")
        job_tenant = str(job.get("tenant_id") or "default")
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")
        if job.get("status") not in {"running", "queued"}:
            raise ValueError(f"Job is already {job.get('status')}")
        resolved_run_id = run_id or job.get("run_id")

    if archive_bytes:
        if not resolved_run_id:
            raise ValueError("run_id required when uploading results")
        # Gateway: validate + publish to ingest.raw_results (idempotent Msg-Id).
        if settings.nats_url:
            try:
                results_ingest.publish_raw_results(
                    nats_url=settings.nats_url,
                    job_id=job_id,
                    run_id=str(resolved_run_id),
                    agent_id=agent_id,
                    exit_code=exit_code,
                    archive_bytes=archive_bytes,
                    error=error,
                    tenant_id=job_tenant,
                )
            except results_ingest.IngestError as exc:
                raise ValueError(str(exc)) from exc
        dest = settings.output_dir / "runs" / str(resolved_run_id)
        try:
            results_ingest.extract_run_archive(archive_bytes, dest)
            results_ingest.update_latest_run_pointer(settings.state_dir, str(resolved_run_id))
            (dest / "tenant.json").write_text(
                json.dumps({"tenant_id": job_tenant, "job_id": job_id}, indent=2) + "\n",
                encoding="utf-8",
            )
        except results_ingest.IngestError as exc:
            raise ValueError(str(exc)) from exc

    status = "succeeded" if exit_code == 0 else "failed"
    _update_job(
        settings,
        job_id,
        status=status,
        finished_at=datetime.now(UTC).isoformat(),
        exit_code=exit_code,
        run_id=str(resolved_run_id) if resolved_run_id else None,
        error=(error[:2000] if error else None),
    )
    agents_service.touch_job(agent_id, None, status="idle")
    result = get_job(job_id)
    assert result is not None
    return result
