from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api import __version__
from api.auth import get_settings
from api.routes import auth as auth_routes
from api.routes import jobs as jobs_routes
from api.routes import runs as runs_routes
from api.schemas import HealthResponse
from api.services import jobs as jobs_service


def create_app() -> FastAPI:
    settings = get_settings()
    jobs_service.load_jobs(settings)

    app = FastAPI(
        title="Octo-man API",
        version=__version__,
        description="Phase 2 HTTP API for Octo-man scan runs, jobs, and RBAC-protected access.",
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
        return HealthResponse(status="ok", version=__version__)

    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(runs_routes.router, prefix="/api")
    app.include_router(jobs_routes.router, prefix="/api")

    web_dist = settings.web_dist
    if web_dist.is_dir() and (web_dist / "index.html").exists():
        assets = web_dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str) -> FileResponse:
            candidate = web_dist / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(web_dist / "index.html")

    return app


app = create_app()
