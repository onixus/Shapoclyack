from __future__ import annotations

import json
import logging
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path


logger = logging.getLogger(__name__)

# The environment the process believes it is running in. Defaults to "prod"
# because the failure modes are asymmetric: a dev box that has to set
# OCTO_ENV=dev loses a minute, while a production install that silently keeps
# built-in credentials is compromised by anyone who has read the repository.
ENV_PROD = "prod"
ENV_DEV = "dev"
VALID_ENVS = (ENV_DEV, ENV_PROD)

# Referenced by the dataclass default *and* the fail-closed check, so it lives
# here rather than being retyped in both places — a check comparing against a
# stale copy of the literal would pass while the insecure default stayed live.
DEFAULT_JWT_SECRET = "shapoclyack-dev-secret-change-me"


class InsecureConfigurationError(RuntimeError):
    """Startup refusal: ``OCTO_ENV=prod`` with built-in defaults still active.

    Raised from :func:`load_settings`, so it aborts process startup rather than
    surfacing on the first request — a half-started API that answers health
    checks with demo credentials active is the outcome this exists to prevent.
    """


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
    # "prod" (default) enforces the fail-closed checks in _validate_production;
    # "dev" allows the built-in secrets and demo accounts below. Only
    # load_settings() validates — Settings constructed directly (tests, tools)
    # are trusted, since whoever writes the field is stating the value.
    env: str = ENV_PROD
    jwt_secret: str = DEFAULT_JWT_SECRET
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
    # Publish Phase 10.1 asset events to events.asset.{tenant}.{kind} (Phase
    # 10.2). Requires nats_url — with no broker there is nowhere to publish and
    # the flag is inert. Kept separately switchable so an operator can silence
    # the event stream without also disabling job dispatch and result ingest,
    # which share the same broker.
    asset_events_enabled: bool = True
    # Per-run publish cap; the overflow is logged and counted, never silently
    # dropped, and diff.json always holds the full set.
    asset_events_max_per_run: int = 1000
    # Outbound webhooks for asset events (Phase 10.3). The fan-out consumer
    # needs nats_url (that is where the events are); the delivery loop does
    # not, so a disabled broker still lets an operator replay a dead delivery
    # from the DLQ. Flag is separate from asset_events_enabled: publishing the
    # stream and calling out to third parties are different blast radii.
    webhooks_enabled: bool = True
    # Whether *this* process runs the delivery loop. Separate from the feature
    # flag above so an installation can keep the API surface (subscriptions,
    # DLQ, audit trail) while confining outbound HTTP to selected replicas —
    # and so tests can exercise the endpoints without a thread POSTing in the
    # background.
    webhook_dispatch_enabled: bool = True
    # Attempts (including the first) before a delivery is dead-lettered.
    webhook_max_attempts: int = 6
    # Exponential backoff between attempts: base * 2**(attempts-1), capped.
    # 30s → 1m → 2m → 4m → 8m, so the six attempts span ~15 minutes.
    webhook_retry_base_seconds: int = 30
    webhook_retry_max_seconds: int = 3600
    # Per-request timeout. Short on purpose: a receiver that needs longer than
    # this is doing work in the request instead of queueing it, and the
    # dispatcher thread is shared by every tenant's deliveries.
    webhook_timeout_seconds: int = 10
    webhook_dispatch_interval_seconds: int = 5
    webhook_dispatch_batch_size: int = 50
    # Delivered/dead rows are pruned past this; the audit trail is bounded, not
    # infinite. 0 disables pruning.
    webhook_delivery_retention_days: int = 30
    # A webhook URL is operator-supplied and this service sits inside the
    # network it scans, so by default a target resolving to a loopback, private,
    # link-local or otherwise non-global address is refused: that is the SSRF
    # shape where the "integration" is really a probe of the cluster's own
    # internals. Set true for an on-cluster receiver reached by service DNS.
    webhook_allow_private_targets: bool = False
    # Bound on how much fan-out one event can cause per tenant.
    webhook_max_subscriptions_per_tenant: int = 20
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
    # Tenant-uploaded brute-force wordlists (Phase 8.2). The word cap mirrors
    # BruteForceSubdomainConfig.max_candidates' ceiling — a list longer than the
    # scanner would ever iterate is a mistake, not a feature. The byte cap is
    # enforced before the body is read into memory.
    wordlist_max_words: int = 50_000
    wordlist_max_body_bytes: int = 8 * 1024 * 1024
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
    # Job leases (ROADMAP P1.4). A claimed/running job carries a deadline that
    # its executor must keep pushing forward: agents on every heartbeat, local
    # jobs from a renewal thread beside the scan. Once it lapses the job is
    # provably unattended — the executor is gone, not slow — and the reaper
    # requeues it (agent jobs) or fails it (local jobs, whose only executor was
    # the dead process). The default is deliberately several times the agent's
    # heartbeat interval so an ordinary hiccup does not steal a live job.
    job_lease_seconds: int = 300
    # How many times a job may be handed out before the reaper stops requeueing
    # it and fails it instead. Counted per claim, so a target that reliably
    # kills its worker cannot cycle forever.
    job_max_attempts: int = 3
    job_reaper_enabled: bool = True
    job_reaper_interval_seconds: int = 60


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


def _resolve_env() -> str:
    raw = os.environ.get("OCTO_ENV", ENV_PROD).strip().lower()
    if raw not in VALID_ENVS:
        # An unrecognised value is a typo, and guessing either way is worse than
        # saying so: silently reading it as prod makes a dev box refuse to start
        # for reasons it never named, and reading it as dev would turn a
        # misspelled "prodution" into a disabled safety check.
        raise InsecureConfigurationError(
            f"OCTO_ENV must be one of {', '.join(VALID_ENVS)} (got an unrecognised value)."
        )
    return raw


def _validate_production(settings: Settings) -> None:
    """Refuse to start when prod configuration is still the published default.

    Every problem is reported at once: an operator fixing these one restart at a
    time learns about the next one only after redeploying, so the list is the
    whole checklist. Messages name the variable and how to fill it and never
    echo a configured value — this text reaches logs and terminals.

    Console accounts are **not** checked here. Since #156 they live in Postgres,
    so an unset ``OCTO_API_USERS`` is the normal steady state rather than a
    misconfiguration, and only the database can tell an installation with a real
    admin from one with none. That check is
    :func:`api.services.users.bootstrap`, which runs once the store is up.
    """
    problems: list[str] = []

    if not settings.jwt_secret or settings.jwt_secret == DEFAULT_JWT_SECRET:
        problems.append(
            "OCTO_JWT_SECRET (or API_SECRET_KEY) is unset or still the built-in default.\n"
            "    Anyone with the repository can mint a valid admin token.\n"
            "    Generate one with: openssl rand -hex 32\n"
            "    Every API replica must share the same value — a per-replica secret\n"
            "    invalidates the tokens issued by the others."
        )

    # Any "*" in the list, not just a bare ["*"]: the wildcard matches every
    # origin regardless of what else is listed beside it, so ["*", "https://x"]
    # is exactly as open as ["*"] while looking deliberate.
    if "*" in settings.cors_origins:
        problems.append(
            'OCTO_API_CORS allows any origin ("*", which is also the default when unset).\n'
            "    Name the exact origins the console is served from, comma-separated."
        )

    if not problems:
        return

    listed = "\n\n".join(f"  * {problem}" for problem in problems)
    raise InsecureConfigurationError(
        f"Refusing to start: OCTO_ENV={ENV_PROD} but the configuration still carries "
        f"built-in defaults.\n\n{listed}\n\n"
        f"  Set OCTO_ENV={ENV_DEV} to allow these defaults for local development only."
    )


def load_settings() -> Settings:
    env = _resolve_env()

    # Since #156 this is a one-time bootstrap input, not the account store:
    # api/services/users.py imports it into Postgres on a first start and stops
    # consulting it afterwards. The built-in list is kept as the marker for
    # "nothing was configured" — users_service refuses to import it.
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

    settings = Settings(
        env=env,
        jwt_secret=os.environ.get("API_SECRET_KEY", "").strip()
        or os.environ.get("OCTO_JWT_SECRET", DEFAULT_JWT_SECRET),
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
        asset_events_enabled=os.environ.get("OCTO_ASSET_EVENTS_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        asset_events_max_per_run=int(os.environ.get("OCTO_ASSET_EVENTS_MAX_PER_RUN", "1000")),
        webhooks_enabled=os.environ.get("OCTO_WEBHOOKS_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        webhook_dispatch_enabled=os.environ.get("OCTO_WEBHOOK_DISPATCH_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        webhook_max_attempts=max(1, int(os.environ.get("OCTO_WEBHOOK_MAX_ATTEMPTS", "6"))),
        webhook_retry_base_seconds=max(
            1, int(os.environ.get("OCTO_WEBHOOK_RETRY_BASE_SECONDS", "30"))
        ),
        webhook_retry_max_seconds=max(
            1, int(os.environ.get("OCTO_WEBHOOK_RETRY_MAX_SECONDS", "3600"))
        ),
        webhook_timeout_seconds=max(1, int(os.environ.get("OCTO_WEBHOOK_TIMEOUT_SECONDS", "10"))),
        # Floored like the reaper's interval: a mistyped 0 would turn the
        # dispatcher's Event.wait() into a busy loop against the database.
        webhook_dispatch_interval_seconds=max(
            1, int(os.environ.get("OCTO_WEBHOOK_DISPATCH_INTERVAL_SECONDS", "5"))
        ),
        webhook_dispatch_batch_size=max(
            1, int(os.environ.get("OCTO_WEBHOOK_DISPATCH_BATCH_SIZE", "50"))
        ),
        webhook_delivery_retention_days=max(
            0, int(os.environ.get("OCTO_WEBHOOK_DELIVERY_RETENTION_DAYS", "30"))
        ),
        webhook_allow_private_targets=os.environ.get(
            "OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS", "false"
        ).lower()
        in ("1", "true", "yes", "on"),
        webhook_max_subscriptions_per_tenant=max(
            1, int(os.environ.get("OCTO_WEBHOOK_MAX_SUBSCRIPTIONS_PER_TENANT", "20"))
        ),
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
        wordlist_max_words=int(os.environ.get("OCTO_WORDLIST_MAX_WORDS", "50000")),
        wordlist_max_body_bytes=int(
            os.environ.get("OCTO_WORDLIST_MAX_BODY_BYTES", str(8 * 1024 * 1024))
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
        job_lease_seconds=int(os.environ.get("OCTO_JOB_LEASE_SECONDS", "300")),
        job_max_attempts=int(os.environ.get("OCTO_JOB_MAX_ATTEMPTS", "3")),
        job_reaper_enabled=os.environ.get("OCTO_JOB_REAPER_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        # Floored: the reaper's tick is a locking query over the jobs table, so
        # a mistyped 0 or a negative value would turn Event.wait() into a busy
        # loop hammering the database rather than "sweep more often".
        job_reaper_interval_seconds=max(
            5, int(os.environ.get("OCTO_JOB_REAPER_INTERVAL_SECONDS", "60"))
        ),
    )

    if settings.env == ENV_PROD:
        _validate_production(settings)
        if settings.agent_token:
            # A warning, not a refusal: the legacy shared token still works and
            # maps to tenant_id=default (Phase 2), so refusing would break a
            # working install over a design preference rather than a published
            # credential. The provisioning-key exchange is the replacement.
            logger.warning(
                "OCTO_AGENT_TOKEN is set: every agent holding it authenticates as "
                "tenant_id=default and one leak covers the whole fleet. Prefer "
                "per-tenant provisioning keys (POST /api/auth/agent/token)."
            )

    return settings
