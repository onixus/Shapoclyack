from __future__ import annotations

import json
import os
import socket
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
    jwt_secret: str = "shapoclyack-dev-secret-change-me"
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
    # NATS JetStream URL (e.g. nats://shapoclyack-nats-client:4222). Empty disables broker.
    nats_url: str = ""
    # ClickHouse HTTP URL (e.g. http://shapoclyack-clickhouse-client:8123). Empty disables CH.
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
    # In-process per-tenant recurring-scan dispatcher (Phase 8.5). On by
    # default since postgres_url always resolves (sqlite fallback), unlike
    # the opt-in NATS/ClickHouse sidecars.
    scheduler_dispatch_enabled: bool = True
    # Lariska endpoint-inventory ingestion (Agent_plan.md S1-S7). Router is
    # only registered when this is true.
    endpoint_inventory_enabled: bool = True
    endpoint_inventory_max_software_items: int = 5000
    endpoint_inventory_max_identifiers: int = 16
    endpoint_inventory_max_labels: int = 32
    endpoint_inventory_max_string_length: int = 512
    endpoint_inventory_max_snapshot_age_seconds: int = 86400
    endpoint_inventory_max_future_skew_seconds: int = 300
    endpoint_inventory_rate_limit_per_hour: int = 12
    # Hard request-body cap enforced before JSON parsing (S9, decision 1).
    # 15 MiB covers the worst case allowed by the per-field limits above
    # (5000 items x ~6 bounded 512-byte strings).
    endpoint_inventory_max_body_bytes: int = 15 * 1024 * 1024
    # Server-side endpoint staleness (S9, decision 7). Mirrors the 48h value
    # the asset card already used client-side; a device whose last accepted
    # inventory is older than this reports status "stale".
    endpoint_stale_hours: int = 48
    # Retention (S9, decision 2): software rows of snapshots older than
    # snapshot_retention_days are pruned (summary row kept); change events are
    # kept for change_retention_days as audit history.
    endpoint_retention_enabled: bool = True
    endpoint_snapshot_retention_days: int = 90
    endpoint_change_retention_days: int = 365
    endpoint_retention_interval_seconds: int = 21600
    endpoint_retention_batch_size: int = 5000
    # Identity of this API process in the shared control plane (ROADMAP P1.2).
    # Local-mode jobs execute in a thread inside one specific replica, so the
    # jobs table records which one; on startup a replica only reconciles the
    # orphaned local jobs carrying its own id, instead of failing jobs another
    # replica is still running. Defaults to the hostname (the pod name under
    # Kubernetes). Jobs orphaned by a replica that never comes back under the
    # same id are the reaper's job — ROADMAP P1.4.
    instance_id: str = ""


# Legacy sqlite filename from when the product was called "octo-man". Kept as a
# fallback so an existing self-host keeps its data after the rename instead of
# silently starting against a fresh, empty database.
_LEGACY_SQLITE_NAME = "octo_man.db"
_SQLITE_NAME = "shapoclyack.db"


def _default_sqlite_url() -> str:
    state_dir = Path(os.environ.get("OCTO_STATE_DIR", "scanner/state"))
    current = state_dir / _SQLITE_NAME
    legacy = state_dir / _LEGACY_SQLITE_NAME
    if not current.exists() and legacy.exists():
        return f"sqlite:///{legacy}"
    return f"sqlite:///{current}"


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
        or os.environ.get("OCTO_JWT_SECRET", "shapoclyack-dev-secret-change-me"),
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
        postgres_url=os.environ.get("OCTO_POSTGRES_URL", "").strip() or _default_sqlite_url(),
        asset_stale_days=int(os.environ.get("OCTO_ASSET_STALE_DAYS", "14")),
        scheduler_dispatch_enabled=os.environ.get("OCTO_SCHEDULER_DISPATCH_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        endpoint_inventory_enabled=os.environ.get("OCTO_ENDPOINT_INVENTORY_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        endpoint_inventory_max_software_items=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_SOFTWARE_ITEMS", "5000")
        ),
        endpoint_inventory_max_identifiers=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_IDENTIFIERS", "16")
        ),
        endpoint_inventory_max_labels=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_LABELS", "32")
        ),
        endpoint_inventory_max_string_length=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_STRING_LENGTH", "512")
        ),
        endpoint_inventory_max_snapshot_age_seconds=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_SNAPSHOT_AGE_SECONDS", "86400")
        ),
        endpoint_inventory_max_future_skew_seconds=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_FUTURE_SKEW_SECONDS", "300")
        ),
        endpoint_inventory_rate_limit_per_hour=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_RATE_LIMIT_PER_HOUR", "12")
        ),
        endpoint_inventory_max_body_bytes=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES", str(15 * 1024 * 1024))
        ),
        endpoint_stale_hours=int(os.environ.get("OCTO_ENDPOINT_STALE_HOURS", "48")),
        endpoint_retention_enabled=os.environ.get("OCTO_ENDPOINT_RETENTION_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        endpoint_snapshot_retention_days=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS", "90")
        ),
        endpoint_change_retention_days=int(
            os.environ.get("OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS", "365")
        ),
        endpoint_retention_interval_seconds=int(
            os.environ.get("OCTO_ENDPOINT_RETENTION_INTERVAL_SECONDS", "21600")
        ),
        endpoint_retention_batch_size=int(
            os.environ.get("OCTO_ENDPOINT_RETENTION_BATCH_SIZE", "5000")
        ),
        instance_id=os.environ.get("OCTO_INSTANCE_ID", "").strip() or socket.gethostname(),
    )
