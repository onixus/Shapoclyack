"""Unit tests for api.services.metrics wiring (ROADMAP P3.4)."""

from __future__ import annotations

import json
from pathlib import Path

from api.services import jobs as jobs_service
from api.services import metrics
from api.settings import Settings


def test_render_exposes_registered_metric_families():
    body, content_type = metrics.render()
    text = body.decode("utf-8")
    assert "text/plain" in content_type
    for name in (
        "octo_http_requests_total",
        "octo_http_request_duration_seconds",
        "octo_job_duration_seconds",
        "octo_jobs_queued",
        "octo_jobs_running",
        "octo_nats_consumer_pending",
        "octo_ch_ingest_batch_duration_seconds",
        "octo_ch_ingest_messages_total",
    ):
        assert name in text, f"{name} missing from /metrics output"


def test_job_terminal_transition_records_duration_and_gauges(tmp_path: Path):
    jobs_service._JOBS.clear()  # noqa: SLF001 -- isolate from other tests' global job state
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    job_id = "metrics-job-1"
    (state_dir / "api_jobs.json").write_text(
        json.dumps(
            [
                {
                    "job_id": job_id,
                    "status": "running",
                    "run_id": None,
                    "mode": "balanced",
                    "command": ["python", "-m", "scanner.main"],
                    "started_at": "2026-07-24T13:00:00+00:00",
                    "finished_at": None,
                    "exit_code": None,
                    "error": None,
                    "requested_by": "admin",
                    "execution": "agent",
                    "tenant_id": "default",
                }
            ]
        ),
        encoding="utf-8",
    )
    settings = Settings(state_dir=state_dir)
    # load_jobs reconciles orphaned *local* jobs to "failed" on startup; use
    # "agent" execution here so the fixture's "running" status survives load,
    # matching the terminal-transition path this test exercises.
    jobs_service.load_jobs(settings)

    before = metrics.JOB_DURATION_SECONDS.labels(status="succeeded", execution="agent")._sum.get()  # noqa: SLF001

    jobs_service._update_job(  # noqa: SLF001
        settings,
        job_id,
        status="succeeded",
        finished_at="2026-07-24T13:00:30+00:00",
        exit_code=0,
    )

    after = metrics.JOB_DURATION_SECONDS.labels(status="succeeded", execution="agent")._sum.get()  # noqa: SLF001
    assert after - before == 30.0
    assert metrics.JOBS_RUNNING._value.get() == 0  # noqa: SLF001
