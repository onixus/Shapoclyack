from __future__ import annotations

import hmac
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api import __version__
from api.auth import get_settings
from api.db import engine as db_engine
from api.middleware import (
    BodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
    install_request_id_middleware,
)
from api.request_context import REQUEST_ID_HEADER
from api.routes import agents as agents_routes
from api.routes import audit as audit_routes
from api.routes import assets as assets_routes
from api.routes import auth as auth_routes
from api.routes import endpoint_inventory as endpoint_inventory_routes
from api.routes import jobs as jobs_routes
from api.routes import mfa as mfa_routes
from api.routes import promoted_domains as promoted_domains_routes
from api.routes import adoption as adoption_routes
from api.routes import usage as usage_routes
from api.routes import compliance as compliance_routes
from api.routes import config as config_routes
from api.routes import reports as reports_routes
from api.routes import runs as runs_routes
from api.routes import schedules as schedules_routes
from api.routes import service_tokens as service_tokens_routes
from api.routes import system as system_routes
from api.routes import users as users_routes
from api.routes import vulnerabilities as vulnerabilities_routes
from api.routes import webhooks as webhooks_routes
from api.routes import wordlists as wordlists_routes
from api.schemas import HealthResponse, SsoStatus
from api.services import agent_deployer
from api.services import agents as agents_service
from api.services import audit as audit_service
from api.services import auth_audit
from api.services import ch_ingest_worker
from api.services import endpoint_inventory as endpoint_inventory_service
from api.services import endpoint_retention
from api.services import health as health_service
from api.services import screenshot_retention
from api.services import software_match_worker
from api.services import risk_snapshots, run_retention
from api.services import job_reaper
from api.services.crypto import startup as crypto_startup
from api.services.integrations import ticket_sync_worker
from api.services.integrations import webhook_worker
from api.services.integrations import webhooks as webhooks_service
from api.services import jobs as jobs_service
from api.services import memberships as memberships_service
from api.services import metrics as metrics_service
from api.services import nats_bus
from api.services import oidc as oidc_service
from api.services import scan_schedules
from api.services.reports import dispatcher as report_dispatcher
from api.services import service_tokens as service_tokens_service
from api.services import schedule_dispatcher
from api.services import tracing as tracing_service
from api.services import tenants as tenants_service
from api.services import users as users_service
from api.services import wordlists as wordlists_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.nats_url:
        nats_bus.startup_bus(settings.nats_url)
    if settings.ch_ingest_enabled and settings.nats_url and settings.clickhouse_url:
        ch_ingest_worker.start_worker(
            nats_url=settings.nats_url,
            clickhouse_url=settings.clickhouse_url,
            settings=settings,
        )
    # Started in every replica, but dispatches only in the one holding the
    # advisory lock (ROADMAP P1.6).
    schedule_dispatcher.start_worker(settings)
    endpoint_retention.start_worker(settings)
    screenshot_retention.start_worker(settings)
    run_retention.start_worker(settings)
    risk_snapshots.start_worker(settings)
    # Leader-locked, unlike the retention sweeps above: it takes no
    # per-row claim, so a second replica would re-match the same devices
    # and write the same lifecycle events twice.
    software_match_worker.start_worker(settings)
    # Leader-locked like the scan dispatcher above, and for a stronger
    # reason: a duplicate scan is wasted work, a duplicate report is a
    # second PDF in a customer's inbox.
    report_dispatcher.start_worker(settings)
    # Needs no lock at all, unlike the dispatcher above: expiry is a property
    # of the row, and the sweep takes candidates with FOR UPDATE SKIP LOCKED.
    job_reaper.start_worker(settings)
    # Same reasoning as the reaper: due-ness is a property of the delivery row
    # and claims are taken with FOR UPDATE SKIP LOCKED, so every replica may
    # dispatch (ROADMAP Phase 10.3).
    webhook_worker.start_worker(settings)
    # Leader-locked, unlike the webhook dispatcher above: reading a tracker
    # back takes no per-row claim, so every replica would poll the same tenant's
    # tickets and write the same lifecycle events (#347).
    ticket_sync_worker.start_worker(settings)
    try:
        yield
    finally:
        ticket_sync_worker.stop_worker()
        webhook_worker.stop_worker()
        job_reaper.stop_worker()
        report_dispatcher.stop_worker()
        software_match_worker.stop_worker()
        risk_snapshots.stop_worker()
        run_retention.stop_worker()
        screenshot_retention.stop_worker()
        tracing_service.shutdown()
        endpoint_retention.stop_worker()
        schedule_dispatcher.stop_worker()
        ch_ingest_worker.stop_worker()
        nats_bus.shutdown_bus()


def _bearer_matches(request: Request, expected: str) -> bool:
    """Constant-time check of an ``Authorization: Bearer`` header.

    ``hmac.compare_digest`` rather than ``==``: the token is a fixed secret an
    unauthenticated caller may retry without limit, which is exactly the case a
    byte-by-byte comparison leaks a length-proportional signal in.
    """
    scheme, _, presented = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not presented:
        return False
    return hmac.compare_digest(presented.strip(), expected)


def _check_flag(report: health_service.Readiness, name: str) -> bool | None:
    """One readiness check as ``HealthResponse``'s tri-state field.

    None means "not configured here", which is what the field meant before the
    checks became real: False would read as an outage of something this
    installation does not run.
    """
    reported = report.checks.get(name)
    return None if reported is None else reported == health_service.STATUS_OK


def create_app() -> FastAPI:
    settings = get_settings()
    # Before the tenant store opens the first session: the engine is a lazy
    # singleton keyed by URL, so pool sizing that arrives after something has
    # already built it would apply to nobody (#335).
    db_engine.configure(settings)
    tenants_service.load_tenants(settings)
    # After the tenant store (it shares the session factory), and before any
    # router is mounted: a prod install with no console account refuses here
    # rather than serving a login form nobody can get through (#156).
    users_service.bootstrap(settings)
    # Same shape as the check above and for the same reason: only the database
    # can tell an installation that stores integration secrets — and so needs
    # OCTO_MASTER_KEY — from one that has none (#310).
    crypto_startup.bootstrap(settings)
    jobs_service.load_jobs(settings)
    agents_service.load_agents(settings)
    agent_deployer.configure(settings)
    scan_schedules.configure(settings)
    memberships_service.configure(settings)
    auth_audit.configure(settings)
    audit_service.configure(settings)
    service_tokens_service.configure(settings)
    endpoint_inventory_service.configure(settings)
    webhooks_service.configure(settings)
    wordlists_service.configure(settings)

    # Unmounted rather than authenticated when disabled (#319): FastAPI builds
    # the schema from the mounted routers, so the only way an installation can
    # be sure the map of its API is not served is for the routes not to exist.
    # With a console build present the catch-all below answers these paths with
    # the UI's own 404 page rather than 404 JSON — either way, no schema.
    docs_enabled = settings.api_docs_enabled
    app = FastAPI(
        title="Shapoclyack API",
        version=__version__,
        description="HTTP API for Shapoclyack scan runs, jobs, remote agents, and RBAC-protected access.",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    tracing_service.configure(app, settings)
    if settings.endpoint_inventory_enabled:
        # Runs before routing and body parsing: the cap is decided from the
        # request headers, never by buffering the payload first (S9). Added
        # before CORS so CORSMiddleware stays outside it and still annotates
        # the 413/411 responses this layer generates.
        app.add_middleware(
            BodySizeLimitMiddleware,
            max_bytes=settings.endpoint_inventory_max_body_bytes,
            paths=("/api/endpoint/inventory",),
        )
    # Same reasoning for the agent results upload (#222): the archive part is a
    # whole run directory, and the route buffered it in full before deciding
    # anything about it. Its own cap because the two contracts are different
    # sizes, and no endpoint-submission counter because those rejections are not
    # endpoint submissions.
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=settings.agent_results_max_body_bytes,
        path_patterns=(r"^/api/agent/jobs/[^/]+/results/?$",),
        count_endpoint_submissions=False,
    )
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.hsts_enabled)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        # Without this the console cannot read `X-Request-Id` off a cross-origin
        # response at all — a browser hides every response header that is not on
        # the CORS-safelist unless the server names it — and docs/operations.md
        # telling an operator to grep for "the id the console reported" would be
        # asking for an id nothing could report (#330).
        expose_headers=[REQUEST_ID_HEADER],
    )

    @app.middleware("http")
    async def _metrics_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        route = request.scope.get("route")
        path = route.path if route is not None else request.url.path
        metrics_service.HTTP_REQUESTS_TOTAL.labels(request.method, path, str(response.status_code)).inc()
        metrics_service.HTTP_REQUEST_DURATION_SECONDS.labels(request.method, path).observe(duration)
        return response

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint(request: Request) -> Response:
        # Open unless a token is configured: that is the Prometheus shape most
        # installations scrape with, and making the token mandatory would break
        # every existing ServiceMonitor on upgrade. Where it is set, the series
        # stop being readable by anyone who can reach the API — they name every
        # route, the queue depth and login outcomes (#319).
        expected = settings.metrics_token
        if expected and not _bearer_matches(request, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Metrics require a bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        body, content_type = metrics_service.render()
        return Response(content=body, media_type=content_type)

    @app.get("/livez", include_in_schema=False)
    def livez() -> dict[str, str]:
        # Deliberately dependency-free (#331): liveness answers "should the
        # kubelet restart this process", and restarting every replica is not how
        # an unreachable Postgres gets fixed — it is how a database outage
        # becomes a crash loop on top of itself. Readiness is the probe that is
        # allowed to know about dependencies.
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        report = health_service.check_readiness(get_settings())
        # The status code and the body answer different questions: 503 means
        # "take this replica out of the Service", which only a blocking
        # dependency earns, while "degraded" means "something configured here
        # is not answering". A replica with ClickHouse down is 200 degraded —
        # serving, and saying what is wrong (#335).
        return JSONResponse(
            status_code=200 if report.ready else 503,
            content={
                "status": "ok" if report.healthy else "degraded",
                "checks": report.checks,
            },
        )

    @app.get("/api/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        settings = get_settings()
        # The same sweep /readyz runs, reported in this endpoint's older shape:
        # the status used to be the literal "ok" whatever the dependencies were
        # doing, which made it a check on the process being able to serialize a
        # response (#331). Still always 200 — callers parse the body, and both
        # container HEALTHCHECKs are wired to this path.
        report = health_service.check_readiness(settings)
        return HealthResponse(
            status="ok" if report.healthy else "degraded",
            version=__version__,
            nats=_check_flag(report, "nats"),
            clickhouse=_check_flag(report, "clickhouse"),
            checks=report.checks,
            ch_ingest=ch_ingest_worker.worker_stats(),
            # The login form has to know whether to offer an SSO button before
            # anyone is authenticated, and this endpoint is already public.
            sso=SsoStatus.model_validate(oidc_service.public_config(settings)),
        )

    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(runs_routes.router, prefix="/api")
    app.include_router(jobs_routes.router, prefix="/api")
    app.include_router(agents_routes.router, prefix="/api")
    app.include_router(assets_routes.router, prefix="/api")
    app.include_router(system_routes.router, prefix="/api")
    app.include_router(config_routes.router, prefix="/api")
    app.include_router(schedules_routes.router, prefix="/api")
    app.include_router(wordlists_routes.router, prefix="/api")
    app.include_router(users_routes.router, prefix="/api")
    app.include_router(mfa_routes.router, prefix="/api")
    app.include_router(audit_routes.router, prefix="/api")
    if settings.service_tokens_enabled:
        app.include_router(service_tokens_routes.router, prefix="/api")
    app.include_router(vulnerabilities_routes.router, prefix="/api")
    app.include_router(compliance_routes.router, prefix="/api")
    app.include_router(adoption_routes.router, prefix="/api")
    app.include_router(usage_routes.router, prefix="/api")
    app.include_router(promoted_domains_routes.router, prefix="/api")
    if settings.reports_enabled:
        app.include_router(reports_routes.router, prefix="/api")
    if settings.webhooks_enabled:
        app.include_router(webhooks_routes.router, prefix="/api")
    if settings.endpoint_inventory_enabled:
        app.include_router(endpoint_inventory_routes.router, prefix="/api")

    web_dist = settings.web_dist
    if web_dist.is_dir() and (web_dist / "index.html").exists():
        next_static = web_dist / "_next"
        vite_assets = web_dist / "assets"
        # Next export uses `/_next/*` and also has an `/assets` app route — do not
        # mount Vite's `/assets` StaticFiles when serving a Next build.
        if next_static.is_dir():
            app.mount("/_next", StaticFiles(directory=next_static), name="next_static")
        elif vite_assets.is_dir():
            app.mount("/assets", StaticFiles(directory=vite_assets), name="assets")

        web_root = web_dist.resolve()

        def _contained_file(candidate: Path) -> Path | None:
            """Resolve ``candidate`` and keep it only if it stays under the web root.

            Same containment check as ``runs.resolve_artifact``: resolve, then
            require ``relative_to`` the root to succeed. ``full_path`` reaches the
            handler percent-decoded, so a ``%2e%2e%2f`` segment arrives here as a
            real ``..`` that no ASGI-level path normalization ever saw — and this
            route is unauthenticated, which made every file the API process can
            read, its environment included, readable to anyone
            (GHSA-cpcx-h7mr-24pc).
            """
            resolved = candidate.resolve()
            try:
                resolved.relative_to(web_root)
            except ValueError:
                return None
            return resolved if resolved.is_file() else None

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str) -> FileResponse:
            # Next `output: "export"` emits `runs.html` / `runs/view.html` (and optionally
            # directory `index.html`). Prefer explicit files before the SPA shell.
            if full_path:
                cleaned = full_path.rstrip("/")
                candidate = _contained_file(web_dist / cleaned)
                if candidate is not None:
                    return FileResponse(candidate)
                html_candidate = _contained_file(web_dist / f"{cleaned}.html")
                if html_candidate is not None:
                    return FileResponse(html_candidate)
                index_candidate = _contained_file(web_dist / cleaned / "index.html")
                if index_candidate is not None:
                    return FileResponse(index_candidate)
            # An escaping path lands here, on the SPA shell, exactly like any
            # other unknown route: the client-side router owns 404 rendering.
            return FileResponse(web_dist / "index.html")

    # Last, and deliberately not `add_middleware`: the correlation id has to be
    # bound before anything else can log — the body-size rejections that never
    # reach a route, the CORS preflight answers, and the 500 that Starlette's
    # own ServerErrorMiddleware writes from outside the user middleware stack
    # (#330). Nothing may add middleware after this point.
    install_request_id_middleware(app)
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> FastAPI:
    """Lazily build the module-level ``app`` singleton (PEP 562).

    Postgres is a hard dependency for create_app() (tenants_service.load_tenants
    fails fast without it — Phase 7). Building `app` eagerly at import time meant
    a bare `from api.app import create_app` — which every API test file does —
    executed create_app() as a side effect of importing the module, requiring a
    reachable Postgres just to collect tests that don't even touch tenants.
    Deferring construction to first access of the `app` attribute keeps
    `uvicorn.run("api.app:app", ...)` / `api.__main__` working identically
    (uvicorn imports the module then getattrs "app"), while plain imports and
    explicit create_app() calls (what tests already do) are unaffected.
    """
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
