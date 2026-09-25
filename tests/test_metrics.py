"""Unit tests for api.services.metrics wiring (ROADMAP P3.4)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from api.services import jobs as jobs_service
from api.services import metrics, metrics_sources
from api.services import tenants as tenants_service
from tests.conftest import configured_client, make_settings, requires_postgres


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
        "octo_endpoint_inventory_submissions_total",
        "octo_endpoint_inventory_ingest_duration_seconds",
        "octo_endpoint_inventory_software_items",
        "octo_endpoint_inventory_software_changes_total",
        "octo_endpoint_devices",
        "octo_endpoint_retention_deleted_total",
        "octo_endpoint_retention_run_duration_seconds",
    ):
        assert name in text, f"{name} missing from /metrics output"


@requires_postgres
def test_job_terminal_transition_records_duration_and_gauges(tmp_path: Path):
    settings = make_settings(tmp_path, state_dir=tmp_path / "state")
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()  # isolate from other tests' job rows
    tenants_service.load_tenants(settings)
    state_dir = settings.state_dir
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
    # load_jobs reconciles orphaned *local* jobs to "failed" on startup; use
    # "agent" execution here so the fixture's "running" status survives load,
    # matching the terminal-transition path this test exercises.
    jobs_service.load_jobs(settings)

    before = metrics.JOB_DURATION_SECONDS.labels(status="succeeded", execution="agent")._sum.get()  # noqa: SLF001

    jobs_service._update_job(  # noqa: SLF001
        settings,
        job_id,
        status="succeeded",
        finished_at=datetime(2026, 7, 24, 13, 0, 30),
        exit_code=0,
    )

    after = metrics.JOB_DURATION_SECONDS.labels(status="succeeded", execution="agent")._sum.get()  # noqa: SLF001
    assert after - before == 30.0
    # Read at scrape time since #334: the transition expired the snapshot.
    metrics_sources.configure(settings)
    running = [
        sample.value
        for family in metrics.CLUSTER_COLLECTOR.collect()
        for sample in family.samples
        if sample.name == "octo_jobs_running"
    ]
    assert running == [0]


def test_http_metric_labels_come_from_a_fixed_set():
    """The same guard without a database, so the infrastructure-free gate
    runs it too."""
    from starlette.requests import Request
    from starlette.routing import Route

    from api.app import UNMATCHED_PATH_LABEL, _http_metric_labels

    def request(method: str, path: str, route: Route | None = None) -> Request:
        scope = {"type": "http", "method": method, "path": path, "headers": []}
        if route is not None:
            scope["route"] = route
        return Request(scope)

    route = Route("/api/agents/{agent_id}", endpoint=lambda: None)
    assert _http_metric_labels(request("GET", "/api/agents/a-1", route)) == (
        "GET",
        "/api/agents/{agent_id}",
    )
    assert _http_metric_labels(request("GET", "/wp-login.php")) == ("GET", UNMATCHED_PATH_LABEL)
    assert _http_metric_labels(request("PROPFIND", "/x", route)) == ("OTHER", "/api/agents/{agent_id}")


@requires_postgres
def test_unrouted_requests_do_not_mint_a_series_each(tmp_path, monkeypatch):
    """``path`` is the route template, which is what bounds it — but a request
    no route matched has no template, and the raw URL used to stand in. That is
    every 404 on an API without the console build and every CORS preflight
    (answered by the middleware before routing), so each path a scanner probed
    became a series of its own, on every replica, until the process restarted
    (#334). ``method`` was copied through the same way."""
    client = configured_client(tmp_path, monkeypatch)
    probe = f"/probe-{uuid.uuid4().hex}"
    preflight = f"/preflight-{uuid.uuid4().hex}"
    assert client.get(probe).status_code == 404
    client.options(
        preflight,
        headers={"Origin": "https://console.example", "Access-Control-Request-Method": "GET"},
    )
    assert client.request("PROPFIND", "/api/health").status_code == 405

    body = client.get("/metrics").text
    assert probe not in body
    assert preflight not in body
    assert 'path="<unmatched>"' in body
    assert "PROPFIND" not in body
    assert 'method="OTHER",path="/api/health",status="405"' in body
    # A routed request keeps its template, which is the point of the label.
    assert 'method="GET",path="/metrics"' in client.get("/metrics").text


@requires_postgres
def test_console_assets_are_labelled_by_their_mount(tmp_path, monkeypatch):
    """The console's static files are served by Starlette ``Mount``s, which never
    set ``scope["route"]`` — so every served 200 of the console build landed in
    ``<unmatched>`` with the probes, and in the GET p95 of SLO 2 as an
    unattributable route (review of #334). A mount is a template too."""
    web = tmp_path / "web"
    (web / "_next" / "static" / "chunks").mkdir(parents=True)
    (web / "index.html").write_text("<html></html>", encoding="utf-8")
    (web / "_next" / "static" / "chunks" / "app.js").write_text("console.log(1)", encoding="utf-8")
    client = configured_client(tmp_path, monkeypatch, web_dist=web)
    assert client.get("/_next/static/chunks/app.js").status_code == 200
    assert client.get(f"/_next/static/{uuid.uuid4().hex}.js").status_code == 404
    body = client.get("/metrics").text
    served = [
        line
        for line in body.splitlines()
        if line.startswith("octo_http_requests_total{") and 'method="GET"' in line
    ]
    assert any('path="/_next/*",status="200"' in line for line in served), served
    assert any('path="/_next/*",status="404"' in line for line in served), served
    assert not any('path="<unmatched>"' in line and 'status="200"' in line for line in served), served
    assert "app.js" not in body


def test_a_mount_is_labelled_by_its_template_not_its_path():
    from starlette.requests import Request
    from starlette.routing import Mount

    from api.app import _http_metric_labels

    assets = Mount("/_next", app=lambda scope, receive, send: None)
    app = type("App", (), {"router": type("Router", (), {"routes": [assets]})()})()
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/_next/static/x.js",
        "headers": [],
        "app": app,
        "endpoint": assets.app,
    }
    assert _http_metric_labels(Request(scope)) == ("GET", "/_next/*")


def test_the_api_runs_one_worker_whatever_web_concurrency_says(monkeypatch):
    """Every series here is per process, and ``instance`` is how the dashboards
    tell processes apart. ``uvicorn.run`` honours WEB_CONCURRENCY when no
    ``workers`` is passed, and N workers behind one port would each answer a
    scrape with their own counters — different numbers on every scrape, with
    nothing to say so (review of #334)."""
    import api.__main__ as main_module

    seen = {}
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *args, **kwargs: seen.update(kwargs))
    monkeypatch.setattr(main_module, "configure_logging", lambda: ("text", 20))
    main_module.main()
    assert seen["workers"] == 1
