from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api import __version__
from api.auth import get_settings
from api.routes import agents as agents_routes
from api.routes import assets as assets_routes
from api.routes import auth as auth_routes
from api.routes import jobs as jobs_routes
from api.routes import config as config_routes
from api.routes import runs as runs_routes
from api.routes import schedules as schedules_routes
from api.routes import system as system_routes
from api.schemas import HealthResponse
from api.services import agents as agents_service
from api.services import ch_ingest_worker
from api.services import clickhouse_client
from api.services import jobs as jobs_service
from api.services import nats_bus
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.services import tenants as tenants_service


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
    schedule_dispatcher.start_worker(settings)
    try:
        yield
    finally:
        schedule_dispatcher.stop_worker()
        ch_ingest_worker.stop_worker()
        nats_bus.shutdown_bus()


def create_app() -> FastAPI:
    settings = get_settings()
    tenants_service.load_tenants(settings)
    jobs_service.load_jobs(settings)
    agents_service.load_agents(settings)
    scan_schedules.configure(settings)

    app = FastAPI(
        title="Octo-man API",
        version=__version__,
        description="HTTP API for Octo-man scan runs, jobs, remote agents, and RBAC-protected access.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        settings = get_settings()
        nats_ok = None
        ch_ok = None
        if settings.nats_url:
            bus = nats_bus.get_bus(settings.nats_url)
            nats_ok = bus is not None and bus._started  # noqa: SLF001
        if settings.clickhouse_url:
            ch_ok = clickhouse_client.ping(settings.clickhouse_url)
        return HealthResponse(
            status="ok",
            version=__version__,
            nats=nats_ok,
            clickhouse=ch_ok,
            ch_ingest=ch_ingest_worker.worker_stats(),
        )

    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(runs_routes.router, prefix="/api")
    app.include_router(jobs_routes.router, prefix="/api")
    app.include_router(agents_routes.router, prefix="/api")
    app.include_router(assets_routes.router, prefix="/api")
    app.include_router(system_routes.router, prefix="/api")
    app.include_router(config_routes.router, prefix="/api")
    app.include_router(schedules_routes.router, prefix="/api")

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

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str) -> FileResponse:
            # Next `output: "export"` emits `runs.html` / `runs/view.html` (and optionally
            # directory `index.html`). Prefer explicit files before the SPA shell.
            if full_path:
                cleaned = full_path.rstrip("/")
                candidate = web_dist / cleaned
                if candidate.is_file():
                    return FileResponse(candidate)
                html_candidate = web_dist / f"{cleaned}.html"
                if html_candidate.is_file():
                    return FileResponse(html_candidate)
                index_candidate = candidate / "index.html"
                if index_candidate.is_file():
                    return FileResponse(index_candidate)
            return FileResponse(web_dist / "index.html")

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
