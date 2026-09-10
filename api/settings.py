from __future__ import annotations

import json
import logging
import os
import socket
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path


logger = logging.getLogger(__name__)

# The environment the process believes it is running in. Defaults to "prod"
# because the failure modes are asymmetric: a dev box that has to set
# OCTO_ENV=dev loses a minute, while a production install that silently keeps
# built-in credentials is compromised by anyone who has read the repository.
ENV_PROD = "prod"
ENV_DEV = "dev"
VALID_ENVS = (ENV_DEV, ENV_PROD)

# What ``OCTO_LOCAL_LOGIN`` may say about password login on an SSO
# installation (#315). Constants rather than literals because the login route,
# the settings loader and the console's SSO status all switch on them.
LOCAL_LOGIN_ENABLED = "enabled"
LOCAL_LOGIN_BREAK_GLASS = "break-glass"
LOCAL_LOGIN_DISABLED = "disabled"
VALID_LOCAL_LOGIN = (LOCAL_LOGIN_ENABLED, LOCAL_LOGIN_BREAK_GLASS, LOCAL_LOGIN_DISABLED)

# Referenced by the dataclass default *and* the fail-closed check, so it lives
# here rather than being retyped in both places — a check comparing against a
# stale copy of the literal would pass while the insecure default stayed live.
DEFAULT_JWT_SECRET = "shapoclyack-dev-secret-change-me"

# The only JWT algorithm this installation signs and verifies with. It is an
# allowlist rather than a free-text setting because the algorithm decides what
# a token's ``alg`` header can talk the decoder into: "none" and the RS/ES
# families are the two classic confusion attacks, and neither has key material
# here to make it work honestly. Widening this set is a key-management change
# (#312), not a configuration one.
ALLOWED_JWT_ALGORITHMS = ("HS256",)

# The other credentials k8s/shapoclyack/base/kustomization.yaml ships as
# literals. They are placeholders exactly like the JWT secret above, but they
# reach the process inside a connection URL rather than as a variable of their
# own, so the check below looks for the literal *within* whichever URL carries
# it. One list rather than a check per secret: #225 added ClickHouse and NATS to
# a base that had only Postgres, and a per-secret check is a per-secret chance
# to forget the next one.
DEFAULT_DATA_PLANE_SECRETS: tuple[str, ...] = (
    "shapoclyack-dev-postgres-change-me",
    "shapoclyack-dev-clickhouse-change-me",
    "shapoclyack-dev-nats-api-change-me",
    "shapoclyack-dev-nats-agent-change-me",
)

# End of the legacy shared agent token (#224). One OCTO_AGENT_TOKEN maps every
# agent holding it to tenant_id="default", so for an MSSP install the whole
# fleet lands in one tenant and the isolation the rest of the product enforces
# is not there. Until this date a prod start warns; from this date on it is a
# refusal, because "we will remove it eventually" has been the state since
# Phase 2 and a warning nobody reads is not a migration plan. The replacement
# is per-tenant provisioning keys (POST /api/auth/agent/token).
AGENT_TOKEN_SUNSET = date(2027, 3, 1)


class InsecureConfigurationError(RuntimeError):
    """Startup refusal: ``OCTO_ENV=prod`` with built-in defaults still active.

    Raised from :func:`load_settings`, so it aborts process startup rather than
    surfacing on the first request — a half-started API that answers health
    checks with demo credentials active is the outcome this exists to prevent.

    One check cannot be made at startup and raises from a request instead:
    storing an integration secret with no ``OCTO_MASTER_KEY`` configured
    (``api/services/integrations/webhooks.py``). Whether the installation has
    such a secret is a fact about the database that a later write changes, so
    the boot-time answer expires. It is the same refusal — the request fails
    as a server misconfiguration, which is what it is, and the message goes to
    the log rather than to the caller (#310).
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


def _csv_secrets(raw: str) -> list[str]:
    """Parse a comma-separated key list from the environment.

    Whitespace and empty entries are dropped rather than kept as keys: a
    trailing comma in a Secret is a typo, and an empty string would otherwise
    become a signing key that verifies an unsigned-looking token.
    """
    return _unique_secrets(raw.split(","))


def _unique_secrets(values: list[str]) -> list[str]:
    """Non-empty values in order, first occurrence wins."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = (value or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


@dataclass
class Settings:
    # "prod" (default) enforces the fail-closed checks in _validate_production;
    # "dev" allows the built-in secrets and demo accounts below. Only
    # load_settings() validates — Settings constructed directly (tests, tools)
    # are trusted, since whoever writes the field is stating the value.
    env: str = ENV_PROD
    jwt_secret: str = DEFAULT_JWT_SECRET
    jwt_algorithm: str = ALLOWED_JWT_ALGORITHMS[0]
    jwt_expire_minutes: int = 480
    # Keys this installation has retired but still verifies with, newest first
    # (OCTO_JWT_SECRET_PREVIOUS, comma-separated). Rotating a symmetric secret
    # without them is a fleet-wide logout at the moment of the rollout, because
    # every session token in every browser was signed with the old value; with
    # them the old tokens are accepted until they expire on their own and
    # nothing new is ever signed with them. Nothing here weakens verification:
    # a key is trusted only because an operator wrote it down as one that was
    # in use, and #314 gives every token a ``kid`` so the right one is tried
    # first. Empty is the normal state — a rotation adds one entry and a later
    # deploy removes it (docs/operations.md § Rotating the JWT signing key).
    jwt_secret_previous: list[str] = field(default_factory=list)
    # Signing key for agent JWTs (OCTO_AGENT_JWT_SECRET). Empty means "derive
    # one from jwt_secret" -- see agent_signing_secret() below.
    agent_jwt_secret: str = ""
    # The same rotation window for the agent key (OCTO_AGENT_JWT_SECRET_PREVIOUS).
    # Only consulted when agent_jwt_secret is set explicitly: when it is
    # derived, the previous *operator* keys derive the previous agent keys, so
    # naming them twice would be two lists to keep in step.
    agent_jwt_secret_previous: list[str] = field(default_factory=list)
    output_dir: Path = Path("scanner/output")
    state_dir: Path = Path("scanner/state")
    config_path: Path = Path("scanner/config/default.yaml")
    web_dist: Path = Path("web/dist")
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    # The URL this installation is reached at, from the outside
    # (OCTO_PUBLIC_BASE_URL). Everything that hands an operator or a target host
    # a link back to the API — the install one-liner, the container and
    # Kubernetes snippets, the OCTO_API_URL the SSH push writes into agent.env —
    # is built from this. It used to be derived from the request's own Host
    # header, which is client-controlled: whoever could reach the API decided
    # which host the next agent would fetch its installer from and report to.
    # Required under OCTO_ENV=prod; under dev the request URL is still used, so
    # a laptop needs no extra variable.
    public_base_url: str = ""
    # Strict-Transport-Security on every response (OCTO_HSTS_ENABLED). On in
    # prod, off in dev: the header pins a browser to HTTPS for a year, and a
    # developer who picks it up from http://localhost cannot clear it the way a
    # cookie is cleared (#224).
    hsts_enabled: bool = True
    # Mount the interactive schema (/docs, /redoc, /openapi.json) —
    # OCTO_API_DOCS. Off in prod, on in dev, for the same asymmetry as the
    # OCTO_ENV default itself: the schema names every route, its parameters and
    # every field an answer carries, which is a map of the installation handed
    # to anyone who can reach it, while a developer who wants it back sets one
    # variable (#319).
    api_docs_enabled: bool = False
    # Bearer token GET /metrics demands when set (OCTO_METRICS_TOKEN). Empty
    # leaves the endpoint open — standard Prometheus practice, and true only
    # while the scrape path stays inside the cluster; a prod start without it
    # warns rather than refuses, since a ServiceMonitor usually does scrape from
    # inside and breaking that on upgrade would be the worse outcome (#319).
    metrics_token: str = ""
    users: list[dict[str, str]] = field(default_factory=lambda: list(DEFAULT_USERS))
    allow_scan_start: bool = True
    # Resolve requested scan domains at admission and refuse the ones whose
    # current addresses land in a denied range (#226). Off leaves the name
    # checked as a string only — see docs/configuration.md.
    scan_scope_resolve_check: bool = True
    # local = API pod runs scanner in a thread; agent = remote workers claim jobs.
    job_execution_mode: str = "local"
    # Shared bearer token for remote agents (OCTO_AGENT_TOKEN). Empty disables legacy agent auth.
    agent_token: str = ""
    agent_stale_seconds: int = 120
    # Lowest agent version allowed to claim jobs (OCTO_AGENT_MIN_VERSION).
    # Empty = no floor, which is the default: a gate that refuses work by
    # default would strand every fleet on the upgrade that introduced it.
    agent_min_version: str = ""
    # TCP ports the SSH push deployer and its host-key probe may dial (#240).
    # The probe opens a connection to a host and port taken from the request
    # body and reports what answered, which over an open range is a port
    # scanner with a tidy response format. SSH is 22 nearly everywhere and 2222
    # where 22 is taken; a target on anything else is named here deliberately.
    # "*" restores the full range — see docs/configuration.md.
    agent_deploy_ssh_ports: str = "22,2222"
    # Whether a deployment target must sit *inside* the tenant's approved scan
    # scope (#226), not merely outside its denied ranges. Off by default:
    # where a tenant's agent lives is not the same question as what it is
    # approved to scan — an agent on a management host that scans a customer
    # range is the ordinary case — so only the prohibitions apply unless an
    # operator decides the two scopes are the same set.
    agent_deploy_enforce_scan_scope: bool = False
    # Short-lived agent JWT lifetime after provisioning-key exchange (Phase 2).
    agent_jwt_expire_minutes: int = 120
    # Days a newly minted provisioning key stays exchangeable (#308). 0 mints
    # perpetual keys, which is what every key predating the column already is.
    # 90 days is a rotation cadence, not a security boundary: the key is a
    # bootstrap credential the agent trades for a 2h JWT, so the cost of the
    # expiry is one operator action per quarter and the benefit is that a key
    # pasted into an install snippet stops being a fleet-wide door forever.
    provisioning_key_ttl_days: int = 90
    # Hard request-body cap on POST /api/agent/jobs/{job_id}/results, read from
    # Content-Length before the multipart body is buffered (#222). A run archive
    # is a tar.gz of one scan directory — single-digit MiB in practice, more with
    # screenshots; 128 MiB leaves room for an unusually large run while keeping a
    # compromised agent from streaming the API out of memory. An order of
    # magnitude above endpoint_inventory_max_body_bytes because, unlike a bounded
    # JSON document, the archive has no per-field ceiling to fall back on.
    agent_results_max_body_bytes: int = 128 * 1024 * 1024
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
    # store lives here. load_settings() still falls back to a local SQLite file
    # so dev and the test suite need no database, but under OCTO_ENV=prod that
    # fallback — and any explicit sqlite:// URL — is a startup refusal (#174):
    # a per-replica file means a per-replica control plane. Empty-string default
    # is kept only for config-shape consistency.
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
    # Whether *this* process runs the fan-out consumer (JetStream → delivery
    # rows). Separate from dispatch (#153): fan-out touches the broker and
    # Postgres only, dispatch is the half that opens connections to third
    # parties, and an installation that confines egress to a few replicas
    # should not have to confine the consumer with it — or the other way round.
    # Three shapes fall out of the pair: API-only (both off), fan-out worker
    # (fan-out on, dispatch off) and egress worker (dispatch on, fan-out off).
    webhook_fanout_enabled: bool = True
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
    # default since postgres_url always resolves — Postgres in prod, the SQLite
    # fallback in dev — unlike the opt-in NATS/ClickHouse sidecars.
    scheduler_dispatch_enabled: bool = True
    # Report factory (Sprint 4). ``reports_enabled`` gates the API surface;
    # ``report_dispatch_enabled`` gates whether *this* replica renders and
    # sends scheduled reports, the same split webhooks use — an installation
    # can keep the console's report pages while confining outbound mail to one
    # replica, and the test suite can exercise the endpoints without a thread
    # emailing customers in the background.
    reports_enabled: bool = True
    report_dispatch_enabled: bool = True
    report_dispatch_interval_seconds: int = 60
    # Generated reports are files on disk. 0 disables pruning; the default
    # keeps a year, because "the quarterly report we sent in March" is a thing
    # customers ask for and a scan-retention window would not cover.
    report_retention_days: int = 365
    # Per-tenant usage quotas (ROADMAP Track E, MSSP operations). These are the
    # platform *defaults*, applied to any tenant without a ``tenant_quotas``
    # row; 0 means unlimited, which is what an installation that never sold a
    # limit keeps getting. A per-tenant row overrides them in either direction,
    # including back to unlimited. Quotas are a commercial boundary, so they
    # fail open on upgrade — unlike the approved scan scope, which does not.
    quota_default_max_assets: int = 0
    quota_default_max_scans_per_month: int = 0
    # Enforcement is separable from metering on purpose: an MSSP typically
    # wants to see consumption against the number it sold for a billing period
    # or two before it starts refusing its customer's scans.
    quota_enforcement_enabled: bool = True
    # SMTP for report delivery. Separate from the scanner's alert SMTP
    # (scanner/pipeline/alerts.py): an alert goes to the operations channel and
    # a report goes to a customer, and one installation routinely needs
    # different relays or senders for the two.
    report_smtp_host: str = ""
    report_smtp_port: int = 25
    report_smtp_from: str = ""
    report_smtp_username: str = ""
    report_smtp_password: str = ""
    report_smtp_starttls: bool = True
    # Certificate verification for that STARTTLS session. smtplib's default
    # context verifies nothing, so this is the switch between "encrypted" and
    # "encrypted to whoever answered".
    report_smtp_verify_tls: bool = True
    report_smtp_timeout_seconds: int = 20
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
    # Phase S8: publish accepted endpoint inventory summary to NATS
    endpoint_nats_events_enabled: bool = True
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
    # Software→CVE matches folded into the vulnerability lifecycle (Track E,
    # M3). The worker re-matches devices whose latest snapshot moved since it
    # last looked, in batches; the interval is a ceiling on how stale a tracked
    # software finding may be, not a scan cadence.
    software_match_enabled: bool = True
    software_match_interval_seconds: int = 900
    software_match_batch_size: int = 100
    # How long a tick may spend draining. The tick takes batches until the
    # tenant has nothing due or this is spent, because one batch per tick made
    # the interval above a ceiling on nothing — the real one was
    # ``due_devices / batch_size × interval``.
    software_match_tick_budget_seconds: int = 60
    # Severity floor for creating a tracked finding, on top of the "must have a
    # published fix" rule. Empty means no floor. Raise it on an installation
    # whose SLA dashboard is drowning in low-severity backports.
    software_finding_min_severity: str = ""
    # P4.4: screenshot PNG retention. 0 disables the reaper (files stay until
    # the run directory is pruned). Default is short — these images can hold
    # personal data even after DOM redaction.
    screenshot_retention_enabled: bool = True
    screenshot_retention_days: int = 14
    screenshot_retention_interval_seconds: int = 3600
    # Run artifact retention (#187). Old scan run directories in output_dir/runs/*
    # are deleted past run_retention_days. 0 disables the reaper.
    run_retention_enabled: bool = True
    run_retention_days: int = 30
    run_retention_interval_seconds: int = 3600
    # Risk snapshot retention (#229). risk_score_snapshots gains a row per
    # tenant per finished run; migration 0023 landed after #187, so nothing
    # bounded it. 0 disables the sweep.
    risk_snapshot_retention_enabled: bool = True
    risk_snapshot_retention_days: int = 90
    risk_snapshot_retention_interval_seconds: int = 21600

    # OpenTelemetry (ROADMAP P3). Empty = no TracerProvider, no export.
    # The value is the OTLP HTTP traces URL, e.g. http://otel-collector:4318/v1/traces
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "shapoclyack-api"
    # Head sampling ratio, 0.0-1.0 (#330). 1.0 keeps every request span, which
    # is fine for a demo and expensive for an installation scanning all day:
    # the API's own traffic is the console polling run state. Sampling is
    # parent-based, so a trace started upstream keeps whatever the ingress
    # decided and only root spans are drawn against this ratio.
    otel_traces_sampler_ratio: float = 1.0
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
    # Login brute-force protection (#157). The counter is the auth_events table,
    # so the limit holds across replicas; see api/services/auth_audit.py.
    login_rate_limit_enabled: bool = True
    # Failures allowed per (username, client IP) inside the window. Five is a
    # typo budget, not a guessing budget: a human who has forgotten which of
    # their passwords this is has room, an attacker gets 5 per 15 minutes.
    login_rate_limit_max_failures: int = 5
    login_rate_limit_window_seconds: int = 900
    # The same window counted per IP across all usernames, which is what one
    # address walking a username list looks like. Deliberately much looser: a
    # NAT gateway or an office egress IP is many legitimate users.
    login_rate_limit_ip_max_failures: int = 50
    # Trusted reverse proxies (comma-separated IPs/CIDRs). X-Forwarded-For is
    # honoured **only** when the immediate peer is one of these — otherwise the
    # client picks its own limiter key by writing the header. Empty (default)
    # means the socket peer is always used. See api/core/client_ip.py.
    trusted_proxies: list[str] = field(default_factory=list)
    # Audit-trail retention. Pruned opportunistically on login (auth_audit);
    # 0 keeps events forever.
    auth_event_retention_days: int = 90
    # Administrative audit trail (#327). Longer than the login trail above,
    # because it is what a compliance review reads a year later, and pruned by
    # a privileged job rather than by the API — see
    # api/services/audit_retention.py. 0 keeps events forever.
    audit_event_retention_days: int = 365

    # --- Enterprise IAM: OIDC single sign-on (ROADMAP Track E) ----------------
    # SSO is off unless issuer, client id *and* client secret are all set; see
    # api/services/oidc.py:is_enabled. A half-configured provider is a
    # misconfiguration, not a partially-enabled feature, so it stays off rather
    # than failing at the first redirect.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # Where the provider sends the browser back. Empty derives
    # ``{public_base_url}/api/auth/oidc/callback``, which is why prod requires
    # OCTO_PUBLIC_BASE_URL: the redirect URI must never come from the request's
    # own Host header (same reasoning as the agent install one-liner).
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid email profile"
    # Claim carrying the console username. Falls back to ``email`` and then
    # ``sub`` when the configured claim is absent.
    oidc_username_claim: str = "preferred_username"
    # Just-in-time provisioning. **Off by default**: with it on, anyone the
    # identity provider will authenticate gets a console account.
    oidc_jit_provisioning: bool = False
    # Role given to a JIT-provisioned account when no claim maps to one. The
    # lowest privileged role on purpose — a default that grants more is a
    # default that grants it to everyone the IdP knows.
    oidc_default_role: str = "viewer"
    # Optional claim holding the caller's group/role values, and the map from
    # those values to console roles (JSON object, e.g.
    # {"vm-admins": "admin", "vm-ops": "operator"}). The *highest* matching
    # role wins; an unmapped value contributes nothing.
    oidc_role_claim: str = ""
    oidc_role_map: dict[str, str] = field(default_factory=dict)
    # Optional claim naming the tenant a provisioned user is granted membership
    # in, and the fallback when the claim is missing or unknown.
    oidc_tenant_claim: str = ""
    oidc_default_tenant: str = "default"
    # Discovery/JWKS cache lifetime. Rotation is also handled out of band: an
    # unknown ``kid`` forces one refresh before the token is refused.
    oidc_cache_ttl_seconds: int = 3600
    # How long an authorization request stays valid. Short: it only has to
    # cover a human typing a password at the provider. Since #321 it is also
    # the retention of ``oidc_pending_states``, which holds one row per login
    # in flight and is swept on expiry.
    oidc_state_ttl_seconds: int = 600
    oidc_http_timeout_seconds: int = 10
    # Where the callback sends the browser once the session exists. Empty makes
    # the callback answer with the token as JSON (same body as password login),
    # which is what an API-only install wants; a console install points this at
    # the UI, which reads the token out of the URL fragment.
    oidc_post_login_redirect: str = ""

    # --- Enterprise IAM: service tokens (ROADMAP Track E) --------------------
    # Non-interactive API credentials, admin-issued per tenant with a scope
    # list (api/services/service_tokens.py). The flag gates the routes only:
    # an already-issued token keeps authenticating until it is revoked, which
    # is what the revoke endpoint is for.
    service_tokens_enabled: bool = True
    # Default lifetime for a token whose creator named none. Bounded on
    # purpose — a credential with no expiry is one nobody ever rotates.
    service_token_default_ttl_days: int = 90
    service_token_max_ttl_days: int = 365
    # ``last_used_at`` is written at most this often per token, so a token
    # driving a busy integration does not turn every request into a write.
    service_token_last_used_interval_seconds: int = 300

    # --- Enterprise IAM: multi-factor authentication (#315) ------------------
    # Roles that must carry a second factor, e.g. ["admin"]. **Empty by
    # default**, which is the only setting that leaves an upgrade behaving
    # exactly as before: enrolment is available to everyone from the first
    # boot, and nobody is required to have done it. An account in a listed role
    # that has not enrolled still signs in, but its session carries
    # ``mfa_pending`` and can reach nothing but the MFA setup routes and logout
    # (api/auth.py), so the requirement is a guided enrolment rather than a
    # lockout.
    mfa_required_roles: list[str] = field(default_factory=list)
    # How recently the second factor must have been proved for an operation
    # that mints or revokes a credential — service tokens, provisioning keys —
    # and for approving a tenant's scanning scope. Fifteen minutes is long
    # enough to do a piece of administration without re-entering a code per
    # click, short enough that a session left open on a desk is not a standing
    # authority to issue credentials. Applies only to accounts that have MFA
    # enabled; an installation with no MFA is unchanged.
    mfa_stepup_minutes: int = 15
    # What local (password) login is for when SSO is configured:
    #   enabled      — the default and the pre-#315 behaviour;
    #   break-glass  — only the accounts in OCTO_BREAK_GLASS_USERS may use it,
    #                  and each such login is its own audit action and its own
    #                  metric, so using the emergency door is visible;
    #   disabled     — no password login at all; SSO is the only way in.
    # Ignored entirely when OIDC is not configured: an installation with no
    # identity provider that turned password login off would have no way in.
    local_login: str = LOCAL_LOGIN_ENABLED
    # Accounts allowed to log in with a password under ``break-glass``. Names,
    # not roles: the point of a break-glass account is that it is a specific,
    # named, closely watched credential rather than a property somebody can
    # acquire by being promoted.
    break_glass_users: list[str] = field(default_factory=list)

    def agent_signing_secret(self) -> str:
        """The key agent JWTs are signed and verified with (#312).

        Never ``jwt_secret``: an operator session and an agent token used to
        carry the same signature, so a console token with ``typ`` rewritten was
        a valid agent credential for any tenant the moment a ``typ`` check was
        missed anywhere. When ``OCTO_AGENT_JWT_SECRET`` is unset the key is
        derived from ``jwt_secret``, which keeps existing installs working
        across the upgrade while still giving the two audiences different key
        material.
        """
        from api.core.security import derive_agent_jwt_secret

        return self.agent_jwt_secret or derive_agent_jwt_secret(self.jwt_secret)

    def jwt_verification_secrets(self) -> list[str]:
        """Every key a console token may be verified against, signing key first.

        Signing still uses ``jwt_secret`` alone: this list exists so a rotation
        is a window rather than an outage (#314). Deduplicated and stripped of
        blanks, because an ``OCTO_JWT_SECRET_PREVIOUS`` that still names the
        current key would otherwise make the rotation look done when it is not.
        """
        secrets = [self.jwt_secret, *self.jwt_secret_previous]
        return _unique_secrets(secrets)

    def agent_signing_secrets(self) -> list[str]:
        """The agent counterpart of :meth:`jwt_verification_secrets`.

        When ``OCTO_AGENT_JWT_SECRET`` is unset the agent key is an HKDF of the
        operator key, so the retired operator keys derive the retired agent
        keys and one rotation covers both audiences. When it *is* set the two
        keys are independent and so are their rotation windows.
        """
        from api.core.security import derive_agent_jwt_secret

        if self.agent_jwt_secret:
            previous = list(self.agent_jwt_secret_previous)
        else:
            previous = [derive_agent_jwt_secret(key) for key in self.jwt_secret_previous]
        return _unique_secrets([self.agent_signing_secret(), *previous])


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


VALID_API_DOCS = ("enabled", "disabled")


def _api_docs_enabled(env: str) -> bool:
    """Whether ``OCTO_API_DOCS`` asks for the interactive schema to be mounted.

    An unrecognised value warns and reads as "disabled" instead of refusing the
    start, for the same reason :func:`_oidc_default_role` refuses to raise: the
    safe reading of a typo is the closed one, and no installation should be
    unable to boot over how its documentation was spelled.
    """
    default = "disabled" if env == ENV_PROD else "enabled"
    raw = os.environ.get("OCTO_API_DOCS", default).strip().lower() or default
    if raw not in VALID_API_DOCS:
        logger.warning(
            "OCTO_API_DOCS must be one of %s; keeping the interactive schema disabled.",
            ", ".join(VALID_API_DOCS),
        )
        return False
    return raw == "enabled"


VALID_CONSOLE_ROLES = ("viewer", "operator", "admin")


def _oidc_default_role() -> str:
    """Role for a JIT-provisioned SSO account. Anything unrecognised is a viewer.

    Not a startup refusal: a typo here must not take the whole API down, and
    falling *down* to the lowest role is the only safe reading of an
    unrecognised value — guessing upward would hand every SSO user whatever the
    operator meant to type.
    """
    raw = os.environ.get("OCTO_OIDC_DEFAULT_ROLE", "viewer").strip().lower() or "viewer"
    if raw not in VALID_CONSOLE_ROLES:
        logger.warning(
            "OCTO_OIDC_DEFAULT_ROLE is not one of %s; using 'viewer'.",
            ", ".join(VALID_CONSOLE_ROLES),
        )
        return "viewer"
    return raw


def _oidc_role_map() -> dict[str, str]:
    """``{claim value: console role}`` from ``OCTO_OIDC_ROLE_MAP`` (JSON object).

    Entries naming an unknown role are dropped rather than downgraded: a
    mapping that silently becomes "viewer" reads, in the admin's head, as a
    grant that worked.

    Malformed JSON is a warning and an empty mapping, not an exception, for the
    same reason :func:`_oidc_default_role` refuses to raise: this is parsed on
    every startup whether or not SSO is configured, so letting it propagate
    would let one stray environment variable take the entire API down —
    including for the tenants that never enabled SSO. Dropping the mapping only
    ever costs role *elevation*, so failing this way cannot over-grant.
    """
    raw = os.environ.get("OCTO_OIDC_ROLE_MAP", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        logger.warning("OCTO_OIDC_ROLE_MAP is not valid JSON (%s); ignoring it.", exc)
        return {}
    if not isinstance(parsed, dict):
        logger.warning(
            "OCTO_OIDC_ROLE_MAP must be a JSON object of {claim value: role}; ignoring it."
        )
        return {}
    mapping: dict[str, str] = {}
    for key, value in parsed.items():
        role = str(value).strip().lower()
        if role not in VALID_CONSOLE_ROLES:
            logger.warning("OCTO_OIDC_ROLE_MAP entry %r names an unknown role; ignoring it.", key)
            continue
        mapping[str(key)] = role
    return mapping


def _mfa_required_roles() -> list[str]:
    """Roles that must carry a second factor, from ``OCTO_MFA_REQUIRED_ROLES``.

    Comma-separated, and an unknown value is dropped with a warning rather than
    raising: the same reasoning as :func:`_oidc_role_map`. Dropping a role only
    ever *relaxes* the requirement, which is a state an operator can see in the
    console (an admin whose account says "MFA not required") — where raising
    would take the API down for every tenant over a typo.
    """
    raw = os.environ.get("OCTO_MFA_REQUIRED_ROLES", "").strip()
    if not raw:
        return []
    roles: list[str] = []
    for item in raw.split(","):
        role = item.strip().lower()
        if not role:
            continue
        if role not in VALID_CONSOLE_ROLES:
            logger.warning(
                "OCTO_MFA_REQUIRED_ROLES names an unknown role %r; ignoring it. "
                "Valid roles: %s.",
                role,
                ", ".join(VALID_CONSOLE_ROLES),
            )
            continue
        if role not in roles:
            roles.append(role)
    return roles


def _local_login() -> str:
    """``OCTO_LOCAL_LOGIN``, defaulting to the pre-#315 behaviour.

    An unrecognised value keeps password login *enabled* rather than closing
    it. That is the opposite of how the other unknown-value readers fail, and
    deliberately so: this one's closed direction locks every operator out of an
    installation whose SSO may itself be the thing that is broken, which is
    exactly the situation break-glass exists for.
    """
    raw = os.environ.get("OCTO_LOCAL_LOGIN", LOCAL_LOGIN_ENABLED).strip().lower()
    if raw not in VALID_LOCAL_LOGIN:
        logger.warning(
            "OCTO_LOCAL_LOGIN must be one of %s; keeping password login enabled.",
            ", ".join(VALID_LOCAL_LOGIN),
        )
        return LOCAL_LOGIN_ENABLED
    return raw


def _is_sqlite_url(url: str) -> bool:
    return url.strip().lower().startswith("sqlite")


def _float_env(name: str, default: float) -> float:
    """Float from the environment; an unparsable value warns and keeps the default.

    Deliberately not a refusal, unlike the credential checks above: this is the
    trace sampling ratio, and a typo in an observability knob should cost the
    operator a warning, not the API's ability to start.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number; using %s", name, raw, default)
        return default


def _today() -> date:
    """UTC date, indirected so the sunset check can be tested without freezing time."""
    return datetime.now(UTC).date()


def _shipped_data_plane_secrets(settings: Settings) -> list[str]:
    """Variables whose URL still carries a credential published in this repository.

    Returned sorted and de-duplicated: two NATS placeholders live in the same
    URL, and naming ``OCTO_NATS_URL`` twice would read as two problems.
    """
    urls = {
        "OCTO_POSTGRES_URL": settings.postgres_url,
        "OCTO_CLICKHOUSE_URL": settings.clickhouse_url,
        "OCTO_NATS_URL": settings.nats_url,
    }
    found = {
        variable
        for variable, url in urls.items()
        if url
        for literal in DEFAULT_DATA_PLANE_SECRETS
        if literal in url
    }
    return sorted(found)


def _validate_production(settings: Settings, *, postgres_url_env: str) -> None:
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

    Transport hardening is *warned* about rather than refused (#309). Unlike a
    published default credential, an unverified transport is not a value we can
    tell apart from a deliberate choice — a Postgres reachable only over a Unix
    socket or an operator-owned encrypted link is a legitimate install — and
    refusing would break every existing deployment on upgrade.
    """
    if not _is_sqlite_url(settings.postgres_url) and "sslmode=" not in (
        settings.postgres_url.lower()
    ):
        logger.warning(
            "OCTO_POSTGRES_URL carries no sslmode=, so libpq negotiates TLS opportunistically "
            "and accepts an unauthenticated server: the control plane's credentials, tokens and "
            "scan results are readable by anything on the path. Append ?sslmode=verify-full and "
            "point sslrootcert= at the cluster CA — see docs/operations.md "
            "§ Transport encryption."
        )
    if settings.report_smtp_host and settings.report_smtp_starttls:
        if not settings.report_smtp_verify_tls:
            logger.warning(
                "OCTO_REPORT_SMTP_VERIFY_TLS=false: report delivery encrypts to the relay "
                "without verifying its certificate, which stops a passive listener and nobody "
                "else. Trust the relay's CA system-wide instead of turning this off."
            )

    if settings.local_login == LOCAL_LOGIN_BREAK_GLASS and not settings.break_glass_users:
        # A warning and not a refusal: with no names, break-glass behaves as
        # ``disabled``, which is a legitimate destination — but it is almost
        # never the one an operator who typed "break-glass" meant, and finding
        # out during an SSO outage is the worst possible moment (#315).
        logger.warning(
            "OCTO_LOCAL_LOGIN=break-glass with an empty OCTO_BREAK_GLASS_USERS: no "
            "account may sign in with a password, so the emergency door this mode "
            "exists to keep open is shut. Name the break-glass accounts, or set "
            "OCTO_LOCAL_LOGIN=disabled to say so deliberately."
        )

    problems: list[str] = []

    if not settings.jwt_secret or settings.jwt_secret == DEFAULT_JWT_SECRET:
        problems.append(
            "OCTO_JWT_SECRET (or API_SECRET_KEY) is unset or still the built-in default.\n"
            "    Anyone with the repository can mint a valid admin token.\n"
            "    Generate one with: openssl rand -hex 32\n"
            "    Every API replica must share the same value — a per-replica secret\n"
            "    invalidates the tokens issued by the others."
        )

    # A retired key is trusted for as long as it is listed, so the two ways to
    # get this wrong are worth naming: the published development secret, which
    # would let anyone with the repository mint a token again, and the current
    # key, which makes a half-finished rotation look finished.
    if DEFAULT_JWT_SECRET in settings.jwt_secret_previous:
        problems.append(
            "OCTO_JWT_SECRET_PREVIOUS lists the built-in development secret.\n"
            "    A rotation window that trusts a published key is not a rotation.\n"
            "    Remove that entry; list only keys this installation actually used."
        )
    if settings.jwt_secret and settings.jwt_secret in settings.jwt_secret_previous:
        problems.append(
            "OCTO_JWT_SECRET_PREVIOUS repeats the current OCTO_JWT_SECRET.\n"
            "    List only the keys being retired — see docs/operations.md\n"
            "    § Rotating the JWT signing key."
        )

    # Any "*" in the list, not just a bare ["*"]: the wildcard matches every
    # origin regardless of what else is listed beside it, so ["*", "https://x"]
    # is exactly as open as ["*"] while looking deliberate.
    if "*" in settings.cors_origins:
        problems.append(
            'OCTO_API_CORS allows any origin ("*", which is also the default when unset).\n'
            "    Name the exact origins the console is served from, comma-separated."
        )

    # Postgres is a hard dependency, not an opt-in sidecar like NATS or
    # ClickHouse: tenants, users, assets, jobs, agents and webhook deliveries
    # all live there. The SQLite fallback below load_settings() is what makes
    # this check necessary — tenants_service.load_tenants() already refuses an
    # empty URL, but it never sees one, because the fallback has already
    # supplied a URL that resolves.
    if _is_sqlite_url(settings.postgres_url):
        unset = not postgres_url_env
        lead = (
            "OCTO_POSTGRES_URL is unset, so the API falls back to a local SQLite file."
            if unset
            else "OCTO_POSTGRES_URL points at SQLite."
        )
        problems.append(
            f"{lead}\n"
            "    SQLite cannot carry the control plane: each replica would open its\n"
            "    own file, so two replicas mean two disagreeing control planes, and\n"
            "    the guarantees P1 was built on — SELECT ... FOR UPDATE SKIP LOCKED\n"
            "    for job claims and leases, advisory locks for scheduler leader\n"
            "    election — quietly stop holding. The file also sits on the pod's\n"
            "    ephemeral disk and is lost on restart.\n"
            "    Set OCTO_POSTGRES_URL to the PostgreSQL instance, e.g.\n"
            "    postgresql+psycopg://user:password@postgres:5432/shapoclyack"
        )

    # The install snippets and the URL the SSH push writes into agent.env are
    # built from this. Deriving it from the request's Host header let whoever
    # reached the API choose where the next agent fetches its installer from
    # and reports to, so there has to be one configured answer.
    if not settings.public_base_url:
        problems.append(
            "OCTO_PUBLIC_BASE_URL is unset.\n"
            "    The agent install snippets and the SSH push would otherwise take the\n"
            "    server URL from the request's Host header, which the caller controls.\n"
            "    Set it to the URL operators and agents reach this API at, e.g.\n"
            "    https://shapoclyack.example.com"
        )
    elif not settings.public_base_url.lower().startswith(("http://", "https://")):
        problems.append(
            "OCTO_PUBLIC_BASE_URL is not an absolute http(s) URL.\n"
            "    It is embedded verbatim in installer commands run on target hosts,\n"
            "    so a bare hostname produces a command that cannot work.\n"
            "    Include the scheme, e.g. https://shapoclyack.example.com"
        )

    # Each of these is a credential printed in k8s/shapoclyack/base — an install
    # that overrode the JWT secret and stopped there used to start silently.
    for variable in _shipped_data_plane_secrets(settings):
        problems.append(
            f"{variable} still carries the placeholder credential shipped in\n"
            "    k8s/shapoclyack/base/kustomization.yaml.\n"
            "    Anyone with the repository can read the data plane it protects.\n"
            "    Generate one with: openssl rand -hex 32, put it in the matching\n"
            "    Secret, and see docs/operations.md § Data-plane credentials."
        )

    # A warning until the sunset date, a refusal after it — see AGENT_TOKEN_SUNSET.
    if settings.agent_token and _today() >= AGENT_TOKEN_SUNSET:
        problems.append(
            f"OCTO_AGENT_TOKEN is set and the legacy shared agent token was retired on "
            f"{AGENT_TOKEN_SUNSET.isoformat()}.\n"
            "    Every agent holding it authenticates as tenant_id=default, so one\n"
            "    token leak covers the whole fleet and no tenant is isolated from\n"
            "    another's agents.\n"
            "    Issue a per-tenant provisioning key instead\n"
            "    (POST /api/tenants/{tenant_id}/provisioning-keys), re-install the\n"
            "    agents with it, then unset this variable."
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

    # Kept separately from the resolved URL so the refusal below can tell
    # "forgot to set it" from "set it to the wrong thing" — the fallback erases
    # that difference the moment it is applied.
    postgres_url_env = os.environ.get("OCTO_POSTGRES_URL", "").strip()

    mode = os.environ.get("OCTO_JOB_EXECUTION_MODE", "local").strip().lower()
    if mode not in {"local", "agent"}:
        mode = "local"

    # Refused in every environment, not only prod: an algorithm this build
    # cannot honestly verify is never a local-development convenience, and the
    # variable used to be read by api.core.security alone while Settings pinned
    # HS256 regardless (#312).
    algorithm = os.environ.get("OCTO_JWT_ALGORITHM", ALLOWED_JWT_ALGORITHMS[0]).strip() or ALLOWED_JWT_ALGORITHMS[0]
    if algorithm not in ALLOWED_JWT_ALGORITHMS:
        raise InsecureConfigurationError(
            f"OCTO_JWT_ALGORITHM must be one of {', '.join(ALLOWED_JWT_ALGORITHMS)}.\n"
            "    Anything else is either unverifiable here or a token-forgery\n"
            "    surface: this installation holds one shared symmetric secret."
        )

    settings = Settings(
        env=env,
        jwt_secret=os.environ.get("API_SECRET_KEY", "").strip()
        or os.environ.get("OCTO_JWT_SECRET", DEFAULT_JWT_SECRET),
        jwt_algorithm=algorithm,
        jwt_expire_minutes=int(os.environ.get("OCTO_JWT_EXPIRE_MINUTES", "480")),
        jwt_secret_previous=_csv_secrets(os.environ.get("OCTO_JWT_SECRET_PREVIOUS", "")),
        output_dir=Path(os.environ.get("OCTO_OUTPUT_DIR", "scanner/output")),
        state_dir=Path(os.environ.get("OCTO_STATE_DIR", "scanner/state")),
        config_path=Path(os.environ.get("OCTO_CONFIG", "scanner/config/default.yaml")),
        web_dist=Path(os.environ.get("OCTO_WEB_DIST", "web/dist")),
        cors_origins=cors,
        public_base_url=os.environ.get("OCTO_PUBLIC_BASE_URL", "").strip().rstrip("/"),
        hsts_enabled=os.environ.get("OCTO_HSTS_ENABLED", "true" if env == ENV_PROD else "false").lower()
        in {"1", "true", "yes"},
        api_docs_enabled=_api_docs_enabled(env),
        metrics_token=os.environ.get("OCTO_METRICS_TOKEN", "").strip(),
        users=users,
        allow_scan_start=os.environ.get("OCTO_ALLOW_SCAN_START", "true").lower()
        in {"1", "true", "yes"},
        scan_scope_resolve_check=os.environ.get("OCTO_SCAN_SCOPE_RESOLVE_CHECK", "true").lower()
        in {"1", "true", "yes"},
        job_execution_mode=mode,
        agent_token=os.environ.get("OCTO_AGENT_TOKEN", "").strip(),
        agent_stale_seconds=int(os.environ.get("OCTO_AGENT_STALE_SECONDS", "120")),
        agent_min_version=os.environ.get("OCTO_AGENT_MIN_VERSION", "").strip(),
        agent_deploy_ssh_ports=os.environ.get("OCTO_AGENT_DEPLOY_SSH_PORTS", "22,2222").strip(),
        agent_deploy_enforce_scan_scope=os.environ.get(
            "OCTO_AGENT_DEPLOY_ENFORCE_SCAN_SCOPE", "false"
        ).lower()
        in {"1", "true", "yes"},
        agent_jwt_expire_minutes=int(os.environ.get("OCTO_AGENT_JWT_EXPIRE_MINUTES", "120")),
        provisioning_key_ttl_days=max(
            0, int(os.environ.get("OCTO_PROVISIONING_KEY_TTL_DAYS", "90") or 0)
        ),
        agent_jwt_secret=os.environ.get("OCTO_AGENT_JWT_SECRET", "").strip(),
        agent_jwt_secret_previous=_csv_secrets(
            os.environ.get("OCTO_AGENT_JWT_SECRET_PREVIOUS", "")
        ),
        agent_results_max_body_bytes=int(
            os.environ.get("OCTO_AGENT_RESULTS_MAX_BODY_BYTES", str(128 * 1024 * 1024))
        ),
        nats_url=os.environ.get("OCTO_NATS_URL", "").strip(),
        clickhouse_url=os.environ.get("OCTO_CLICKHOUSE_URL", "").strip(),
        ch_ingest_enabled=os.environ.get("OCTO_CH_INGEST_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        postgres_url=postgres_url_env or _default_sqlite_url(),
        asset_stale_days=int(os.environ.get("OCTO_ASSET_STALE_DAYS", "14")),
        asset_events_enabled=os.environ.get("OCTO_ASSET_EVENTS_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        asset_events_max_per_run=int(os.environ.get("OCTO_ASSET_EVENTS_MAX_PER_RUN", "1000")),
        webhooks_enabled=os.environ.get("OCTO_WEBHOOKS_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        webhook_dispatch_enabled=os.environ.get("OCTO_WEBHOOK_DISPATCH_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        webhook_fanout_enabled=os.environ.get("OCTO_WEBHOOK_FANOUT_ENABLED", "true").lower()
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
        reports_enabled=os.environ.get("OCTO_REPORTS_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        quota_default_max_assets=max(
            0, int(os.environ.get("OCTO_QUOTA_DEFAULT_MAX_ASSETS", "0"))
        ),
        quota_default_max_scans_per_month=max(
            0, int(os.environ.get("OCTO_QUOTA_DEFAULT_MAX_SCANS_PER_MONTH", "0"))
        ),
        quota_enforcement_enabled=os.environ.get(
            "OCTO_QUOTA_ENFORCEMENT_ENABLED", "true"
        ).lower()
        in {"1", "true", "yes"},
        report_dispatch_enabled=os.environ.get("OCTO_REPORT_DISPATCH_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        # Floored for the same reason as the webhook dispatcher's: a mistyped 0
        # turns the thread's Event.wait() into a busy loop against the database.
        report_dispatch_interval_seconds=max(
            5, int(os.environ.get("OCTO_REPORT_DISPATCH_INTERVAL_SECONDS", "60"))
        ),
        report_retention_days=max(0, int(os.environ.get("OCTO_REPORT_RETENTION_DAYS", "365"))),
        report_smtp_host=os.environ.get("OCTO_REPORT_SMTP_HOST", "").strip(),
        report_smtp_port=max(1, int(os.environ.get("OCTO_REPORT_SMTP_PORT", "25"))),
        report_smtp_from=os.environ.get("OCTO_REPORT_SMTP_FROM", "").strip(),
        report_smtp_username=os.environ.get("OCTO_REPORT_SMTP_USERNAME", "").strip(),
        report_smtp_password=os.environ.get("OCTO_REPORT_SMTP_PASSWORD", ""),
        report_smtp_starttls=os.environ.get("OCTO_REPORT_SMTP_STARTTLS", "true").lower()
        in {"1", "true", "yes"},
        report_smtp_verify_tls=os.environ.get("OCTO_REPORT_SMTP_VERIFY_TLS", "true").lower()
        in {"1", "true", "yes"},
        report_smtp_timeout_seconds=max(
            1, int(os.environ.get("OCTO_REPORT_SMTP_TIMEOUT_SECONDS", "20"))
        ),
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
        endpoint_nats_events_enabled=os.environ.get("OCTO_ENDPOINT_NATS_EVENTS_ENABLED", "true").lower()
        in {"1", "true", "yes"},
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
        software_match_enabled=os.environ.get("OCTO_SOFTWARE_MATCH_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        software_match_interval_seconds=int(
            os.environ.get("OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS", "900")
        ),
        software_match_batch_size=int(os.environ.get("OCTO_SOFTWARE_MATCH_BATCH_SIZE", "100")),
        software_match_tick_budget_seconds=max(
            1, int(os.environ.get("OCTO_SOFTWARE_MATCH_TICK_BUDGET_SECONDS", "60"))
        ),
        software_finding_min_severity=os.environ.get("OCTO_SOFTWARE_FINDING_MIN_SEVERITY", "")
        .strip()
        .lower(),
        screenshot_retention_enabled=os.environ.get("OCTO_SCREENSHOT_RETENTION_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        screenshot_retention_days=max(
            0, int(os.environ.get("OCTO_SCREENSHOT_RETENTION_DAYS", "14"))
        ),
        screenshot_retention_interval_seconds=max(
            60, int(os.environ.get("OCTO_SCREENSHOT_RETENTION_INTERVAL_SECONDS", "3600"))
        ),
        run_retention_enabled=os.environ.get("OCTO_RUN_RETENTION_ENABLED", "true").lower()
        in {"1", "true", "yes"},
        run_retention_days=max(
            0, int(os.environ.get("OCTO_RUN_RETENTION_DAYS", "30"))
        ),
        run_retention_interval_seconds=max(
            60, int(os.environ.get("OCTO_RUN_RETENTION_INTERVAL_SECONDS", "3600"))
        ),
        risk_snapshot_retention_enabled=os.environ.get(
            "OCTO_RISK_SNAPSHOT_RETENTION_ENABLED", "true"
        ).lower()
        in {"1", "true", "yes"},
        risk_snapshot_retention_days=max(
            0, int(os.environ.get("OCTO_RISK_SNAPSHOT_RETENTION_DAYS", "90"))
        ),
        risk_snapshot_retention_interval_seconds=max(
            60, int(os.environ.get("OCTO_RISK_SNAPSHOT_RETENTION_INTERVAL_SECONDS", "21600"))
        ),

        otel_exporter_otlp_endpoint=os.environ.get("OCTO_OTEL_EXPORTER_OTLP_ENDPOINT", "").strip(),
        otel_service_name=os.environ.get("OCTO_OTEL_SERVICE_NAME", "shapoclyack-api").strip()
        or "shapoclyack-api",
        # Clamped rather than validated: a ratio outside 0..1 has an obvious
        # intended meaning at either end, and refusing startup over a
        # observability knob would take the API down for a typo.
        otel_traces_sampler_ratio=min(
            1.0, max(0.0, _float_env("OCTO_OTEL_TRACES_SAMPLER_RATIO", 1.0))
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
        login_rate_limit_enabled=os.environ.get("OCTO_LOGIN_RATE_LIMIT_ENABLED", "true").lower()
        in {"1", "true", "yes", "on"},
        login_rate_limit_max_failures=max(
            1, int(os.environ.get("OCTO_LOGIN_RATE_LIMIT_MAX_FAILURES", "5"))
        ),
        login_rate_limit_window_seconds=max(
            1, int(os.environ.get("OCTO_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "900"))
        ),
        login_rate_limit_ip_max_failures=max(
            1, int(os.environ.get("OCTO_LOGIN_RATE_LIMIT_IP_MAX_FAILURES", "50"))
        ),
        trusted_proxies=[
            part.strip()
            for part in os.environ.get("OCTO_TRUSTED_PROXIES", "").split(",")
            if part.strip()
        ],
        auth_event_retention_days=max(
            0, int(os.environ.get("OCTO_AUTH_EVENT_RETENTION_DAYS", "90"))
        ),
        audit_event_retention_days=max(
            0, int(os.environ.get("OCTO_AUDIT_EVENT_RETENTION_DAYS", "365"))
        ),
        oidc_issuer=os.environ.get("OCTO_OIDC_ISSUER", "").strip().rstrip("/"),
        oidc_client_id=os.environ.get("OCTO_OIDC_CLIENT_ID", "").strip(),
        oidc_client_secret=os.environ.get("OCTO_OIDC_CLIENT_SECRET", "").strip(),
        oidc_redirect_uri=os.environ.get("OCTO_OIDC_REDIRECT_URI", "").strip(),
        oidc_scopes=os.environ.get("OCTO_OIDC_SCOPES", "openid email profile").strip()
        or "openid email profile",
        oidc_username_claim=os.environ.get("OCTO_OIDC_USERNAME_CLAIM", "preferred_username").strip()
        or "preferred_username",
        oidc_jit_provisioning=os.environ.get("OCTO_OIDC_JIT_PROVISIONING", "false").lower()
        in {"1", "true", "yes", "on"},
        oidc_default_role=_oidc_default_role(),
        oidc_role_claim=os.environ.get("OCTO_OIDC_ROLE_CLAIM", "").strip(),
        oidc_role_map=_oidc_role_map(),
        oidc_tenant_claim=os.environ.get("OCTO_OIDC_TENANT_CLAIM", "").strip(),
        oidc_default_tenant=os.environ.get("OCTO_OIDC_DEFAULT_TENANT", "default").strip()
        or "default",
        oidc_cache_ttl_seconds=max(60, int(os.environ.get("OCTO_OIDC_CACHE_TTL_SECONDS", "3600"))),
        oidc_state_ttl_seconds=max(30, int(os.environ.get("OCTO_OIDC_STATE_TTL_SECONDS", "600"))),
        oidc_http_timeout_seconds=max(1, int(os.environ.get("OCTO_OIDC_HTTP_TIMEOUT_SECONDS", "10"))),
        oidc_post_login_redirect=os.environ.get("OCTO_OIDC_POST_LOGIN_REDIRECT", "").strip(),
        service_tokens_enabled=os.environ.get("OCTO_SERVICE_TOKENS_ENABLED", "true").lower()
        in {"1", "true", "yes", "on"},
        service_token_default_ttl_days=max(
            1, int(os.environ.get("OCTO_SERVICE_TOKEN_DEFAULT_TTL_DAYS", "90"))
        ),
        service_token_max_ttl_days=max(
            1, int(os.environ.get("OCTO_SERVICE_TOKEN_MAX_TTL_DAYS", "365"))
        ),
        service_token_last_used_interval_seconds=max(
            0, int(os.environ.get("OCTO_SERVICE_TOKEN_LAST_USED_INTERVAL_SECONDS", "300"))
        ),
        mfa_required_roles=_mfa_required_roles(),
        # At least a minute: zero would demand a fresh code for every single
        # request in a burst of administration, which is a way of teaching
        # people to keep an authenticator open next to the console.
        mfa_stepup_minutes=max(1, int(os.environ.get("OCTO_MFA_STEPUP_MINUTES", "15"))),
        local_login=_local_login(),
        break_glass_users=[
            item.strip()
            for item in os.environ.get("OCTO_BREAK_GLASS_USERS", "").split(",")
            if item.strip()
        ],
    )

    if settings.env == ENV_PROD:
        _validate_production(settings, postgres_url_env=postgres_url_env)
        if not settings.metrics_token:
            # Not a refusal: most installations scrape /metrics from inside the
            # cluster, where the endpoint being open is the documented
            # Prometheus shape — but nothing here can tell that apart from a
            # /metrics reachable through the public Ingress, so it says so once.
            logger.warning(
                "OCTO_METRICS_TOKEN is not set: GET /metrics answers anyone who can "
                "reach the API, and it names every route, tenant-level queue depth "
                "and login outcome. Keep /metrics off the public Ingress, or set the "
                "token and give the scraper a bearerTokenSecret."
            )
        if settings.agent_token:
            # Still only a warning *before* the sunset date — after it,
            # _validate_production above has already refused the start. Breaking
            # a working install needs notice, which is what the date is for.
            logger.warning(
                "OCTO_AGENT_TOKEN is set: every agent holding it authenticates as "
                "tenant_id=default and one leak covers the whole fleet. It stops "
                "being accepted in prod on %s — migrate to per-tenant provisioning "
                "keys (POST /api/auth/agent/token).",
                AGENT_TOKEN_SUNSET.isoformat(),
            )

    return settings
