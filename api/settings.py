from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_USERS = [
    {
        "username": "admin",
        "password": "admin-change-me",
        "role": "admin",
    },
    {
        "username": "operator",
        "password": "operator-change-me",
        "role": "operator",
    },
    {
        "username": "viewer",
        "password": "viewer-change-me",
        "role": "viewer",
    },
]


@dataclass
class Settings:
    jwt_secret: str = "octo-man-dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    output_dir: Path = Path("scanner/output")
    state_dir: Path = Path("scanner/state")
    config_path: Path = Path("scanner/config/default.yaml")
    web_dist: Path = Path("web/dist")
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    users: list[dict[str, str]] = field(default_factory=lambda: list(DEFAULT_USERS))
    allow_scan_start: bool = True
    # local = API pod runs scanner in a thread; agent = remote workers claim jobs.
    job_execution_mode: str = "local"
    # Shared bearer token for remote agents (OCTO_AGENT_TOKEN). Empty disables legacy agent auth.
    agent_token: str = ""
    agent_stale_seconds: int = 120
    # Short-lived agent JWT lifetime after provisioning-key exchange (Phase 2).
    agent_jwt_expire_minutes: int = 60
    # NATS JetStream URL (e.g. nats://octo-man-nats-client:4222). Empty disables broker.
    nats_url: str = ""
    # ClickHouse HTTP URL (e.g. http://octo-man-clickhouse-client:8123). Empty disables CH.
    clickhouse_url: str = ""
    # Start NATS→ClickHouse ingest worker when both NATS and CH URLs are set.
    ch_ingest_enabled: bool = True
    # Optional risk-scoring overlays (read by RiskScoring.from_env):
    #   OCTO_EPSS_DATABASE (default scanner/data/epss/epss-overlay.json)
    #   OCTO_KEV_DATABASE  (default scanner/data/kev/kev-overlay.json)
    # get_scorer() hot-reloads these when they change on disk, re-checking mtimes
    # at most once per OCTO_ENRICHMENT_RELOAD_SECONDS (default 60) so a refresh
    # CronJob's new feeds reach every replica without a restart.
    # Postgres PRIMARY_DB (Phase 7 — asset inventory + tenants/provisioning keys).
    # UNLIKE nats_url/clickhouse_url, this is NOT an opt-in sidecar: the tenant
    # store lives here, so an empty value makes API startup fail fast (see
    # api/services/tenants.py:load_tenants) rather than silently disabling a
    # feature. Empty-string default is kept only for config-shape consistency.
    postgres_url: str = ""
    # Asset lifecycle: active assets not re-observed within this many days flip
    # to "stale" at the end of every ingest (api/services/assets.py).
    asset_stale_days: int = 14


def load_settings() -> Settings:
    users_raw = os.environ.get("OCTO_API_USERS", "").strip()
    users = DEFAULT_USERS
    if users_raw:
        parsed = json.loads(users_raw)
        if not isinstance(parsed, list) or not parsed:
            raise ValueError("OCTO_API_USERS must be a non-empty JSON list")
        users = parsed

    origins = os.environ.get("OCTO_API_CORS", "*").strip()
    cors = [part.strip() for part in origins.split(",") if part.strip()] or ["*"]

    mode = os.environ.get("OCTO_JOB_EXECUTION_MODE", "local").strip().lower()
    if mode not in {"local", "agent"}:
        mode = "local"

    return Settings(
        jwt_secret=os.environ.get("API_SECRET_KEY", "").strip()
        or os.environ.get("OCTO_JWT_SECRET", "octo-man-dev-secret-change-me"),
        jwt_expire_minutes=int(os.environ.get("OCTO_JWT_EXPIRE_MINUTES", "480")),
        output_dir=Path(os.environ.get("OCTO_OUTPUT_DIR", "scanner/output")),
        state_dir=Path(os.environ.get("OCTO_STATE_DIR", "scanner/state")),
        config_path=Path(os.environ.get("OCTO_CONFIG", "scanner/config/default.yaml")),
        web_dist=Path(os.environ.get("OCTO_WEB_DIST", "web/dist")),
        cors_origins=cors,
        users=users,
        allow_scan_start=os.environ.get("OCTO_ALLOW_SCAN_START", "true").lower()
        in {"1", "true", "yes"},
        job_execution_mode=mode,
        agent_token=os.environ.get("OCTO_AGENT_TOKEN", "").strip(),
        agent_stale_seconds=int(os.environ.get("OCTO_AGENT_STALE_SECONDS", "120")),
        agent_jwt_expire_minutes=int(os.environ.get("OCTO_AGENT_JWT_EXPIRE_MINUTES", "120")),
        nats_url=os.environ.get("OCTO_NATS_URL", "").strip(),
        clickhouse_url=os.environ.get("OCTO_CLICKHOUSE_URL", "").strip(),
        ch_ingest_enabled=os.environ.get("OCTO_CH_INGEST_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        postgres_url=os.environ.get("OCTO_POSTGRES_URL", "").strip() or "sqlite:///scanner/state/octo_man.db",
        asset_stale_days=int(os.environ.get("OCTO_ASSET_STALE_DAYS", "14")),
    )
