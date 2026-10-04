"""General request rate limiting: token buckets per principal and per tenant (#320).

Before this the only limiter in the API was the login one (#157), and an
authenticated principal — a console session, a service token, a sensor — could
call anything as fast as it could open connections. One customer's runaway
script was every customer's outage.

**What is limited.** A request is charged when it authenticates, because that
is the first point at which the API knows *who* is asking; keying on anything
the client presents before that (an unverified token, a header) would let the
client pick a fresh bucket per request. Three kinds of principal bucket —
``user``, ``service_token``, ``agent`` — and one ``tenant`` bucket shared by a
tenant's users and service tokens. Sensors and endpoint agents are charged to
their own bucket only: a fleet's traffic grows with its size, and a tenant
bucket sized for people would throttle a large fleet's heartbeats. A platform
admin acts for the installation, not for a tenant, and is charged to its own
bucket only.

Requests that do not authenticate are not charged: the probes (``/livez``,
``/readyz``, ``/api/health``), ``/metrics`` and the console's static files have
no principal, and the unauthenticated write paths — login, MFA, token
exchange — are under the login limiter, which counts *failures* per address
and username. That one stays separate on purpose: it limits guessing, which
this cannot see, and it is the audit trail as well (``auth_audit``).

**Why the buckets are rows.** Every manifest may run several replicas, and the
load balancer picks which one serves a request; an in-process bucket would be
multiplied by the replica count and reset by every rollout — the same reason
``auth_audit`` keeps its counter in a table. NATS is optional here and
Postgres is not, so Postgres holds them: one ``INSERT … ON CONFLICT DO UPDATE``
per charge, computed entirely from the row and the database's clock, so two
replicas charging one bucket at once are serialised by the row lock and never
read-modify-write past each other.

**SQLite** is the single-process dev fallback (#174 refuses it in prod), and
gets an in-process bucket instead. That is a real limiter for the one process
that can use that file, and nothing more: it is not shared, and it starts full
after a restart.

**Failing open.** If the bucket cannot be read — the database is down, a
statement timed out — the request is let through and a warning is logged.
The limiter protects the API from callers; turning a database blip into a
429 for everyone would make it the outage it exists to prevent, and the
request that follows will meet the same database anyway.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from api.db import tenant_scope
from api.services import metrics as metrics_service
from api.settings import Settings

logger = logging.getLogger(__name__)

SCOPE_USER = "user"
SCOPE_SERVICE_TOKEN = "service_token"
SCOPE_AGENT = "agent"
SCOPE_TENANT = "tenant"

#: Rows untouched for longer than this are full buckets again, and are pruned.
#: Raised to the slowest configured refill when that is longer, so a prune can
#: never hand a principal tokens it had not earned back yet.
_MIN_PRUNE_HORIZON_SECONDS = 3600.0
#: How often one replica may run the prune. Opportunistic, like
#: ``auth_audit._maybe_prune``: the table holds one row per active principal,
#: so a sweep every few minutes is plenty and needs no worker thread.
_PRUNE_INTERVAL_SECONDS = 300.0
#: How often the fail-open warning is repeated while the database is away.
_WARN_INTERVAL_SECONDS = 60.0
#: The in-process store's size at which idle buckets are dropped.
_MEMORY_MAX_KEYS = 10_000


class RateLimited(Exception):
    """The bucket for ``scope`` has no token; retry after ``retry_after`` seconds."""

    def __init__(self, scope: str, retry_after: int) -> None:
        super().__init__(f"Rate limit exceeded; retry after {retry_after} seconds")
        self.scope = scope
        self.retry_after = retry_after


@dataclass(frozen=True)
class Limit:
    """Refill rate in tokens per second, and the bucket's capacity."""

    per_second: float
    burst: int

    @property
    def enabled(self) -> bool:
        return self.per_second > 0


class Buckets(Protocol):
    def take(self, key: str, limit: Limit) -> float | None:
        """Spend one token; ``None`` when spent, else the seconds until one is due."""

    def prune(self, horizon_seconds: float) -> None:
        """Drop buckets idle for longer than ``horizon_seconds``."""

    def clear(self) -> None:
        """Forget every bucket (tests)."""


def _wait_for_token(available: float, limit: Limit) -> float:
    return max(0.0, (1.0 - available) / limit.per_second)


# One statement, decided from the row as it is when the row lock is taken:
# refill by the time since ``refilled_at`` (never negative — a replica whose
# statement began before a peer's commit, and so carries an older
# ``statement_timestamp()``, must not rewind the clock), cap at the
# burst, spend one. The ``WHERE`` makes the update conditional, so an empty
# bucket returns no row and is left exactly as it was — a refused request costs
# nothing, and a principal hammering an empty bucket does not keep it empty.
_TAKE = text(
    """
    INSERT INTO rate_limit_buckets AS b (bucket_key, tokens, refilled_at)
    VALUES (:key, CAST(:burst AS double precision) - 1,
            EXTRACT(EPOCH FROM statement_timestamp())::double precision)
    ON CONFLICT (bucket_key) DO UPDATE SET
        tokens = LEAST(
            CAST(:burst AS double precision),
            b.tokens + CAST(:rate AS double precision) * GREATEST(
                0, EXTRACT(EPOCH FROM statement_timestamp())::double precision - b.refilled_at
            )
        ) - 1,
        refilled_at = GREATEST(
            b.refilled_at, EXTRACT(EPOCH FROM statement_timestamp())::double precision
        )
    WHERE LEAST(
        CAST(:burst AS double precision),
        b.tokens + CAST(:rate AS double precision) * GREATEST(
            0, EXTRACT(EPOCH FROM statement_timestamp())::double precision - b.refilled_at
        )
    ) >= 1
    RETURNING b.tokens
    """
)

_AVAILABLE = text(
    """
    SELECT LEAST(
        CAST(:burst AS double precision),
        tokens + CAST(:rate AS double precision) * GREATEST(
            0, EXTRACT(EPOCH FROM statement_timestamp())::double precision - refilled_at
        )
    )
    FROM rate_limit_buckets WHERE bucket_key = :key
    """
)

_PRUNE = text(
    "DELETE FROM rate_limit_buckets"
    " WHERE refilled_at < EXTRACT(EPOCH FROM statement_timestamp())::double precision - :horizon"
)


class DatabaseBuckets:
    """Buckets as rows of ``rate_limit_buckets``, shared by every replica."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def take(self, key: str, limit: Limit) -> float | None:
        params = {"key": key, "burst": limit.burst, "rate": limit.per_second}
        # Across tenants: the limiter runs while authentication is still
        # deciding whose request this is, and the table holds no tenant rows.
        with tenant_scope.system("rate limit bucket"):
            with self._session_factory() as session, session.begin():
                if session.execute(_TAKE, params).first() is not None:
                    return None
                available = session.execute(_AVAILABLE, params).scalar_one_or_none()
        return _wait_for_token(float(available if available is not None else 0.0), limit)

    def prune(self, horizon_seconds: float) -> None:
        with tenant_scope.system("rate limit prune"):
            with self._session_factory() as session, session.begin():
                session.execute(_PRUNE, {"horizon": horizon_seconds})

    def clear(self) -> None:
        with tenant_scope.system("rate limit reset"):
            with self._session_factory() as session, session.begin():
                session.execute(text("DELETE FROM rate_limit_buckets"))


class MemoryBuckets:
    """In-process buckets for the SQLite fallback. Not shared between processes."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}

    def take(self, key: str, limit: Limit) -> float | None:
        now = self._clock()
        with self._lock:
            tokens, refilled_at = self._buckets.get(key, (float(limit.burst), now))
            available = min(
                float(limit.burst), tokens + limit.per_second * max(0.0, now - refilled_at)
            )
            if available < 1.0:
                return _wait_for_token(available, limit)
            self._buckets[key] = (available - 1.0, now)
            if len(self._buckets) > _MEMORY_MAX_KEYS:
                self._drop_idle(now, horizon_seconds=_MIN_PRUNE_HORIZON_SECONDS)
        return None

    def prune(self, horizon_seconds: float) -> None:
        with self._lock:
            self._drop_idle(self._clock(), horizon_seconds=horizon_seconds)

    def _drop_idle(self, now: float, *, horizon_seconds: float) -> None:
        stale = [k for k, (_, at) in self._buckets.items() if now - at > horizon_seconds]
        for key in stale:
            del self._buckets[key]

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


_settings: Settings | None = None
_buckets: Buckets | None = None
_state_lock = threading.Lock()
_last_prune = 0.0
_last_warning = 0.0


def configure(settings: Settings) -> None:
    """Point the limiter at ``settings``' database, or at process memory for SQLite."""
    global _settings, _buckets, _last_prune
    from api.db.engine import get_session_factory

    with _state_lock:
        _settings = settings
        _last_prune = 0.0
        if not settings.rate_limit_enabled:
            _buckets = None
        elif settings.postgres_url.strip().lower().startswith("sqlite"):
            _buckets = MemoryBuckets()
        else:
            _buckets = DatabaseBuckets(get_session_factory(settings.postgres_url))


def principal_limit(settings: Settings, scope: str) -> Limit:
    if scope == SCOPE_AGENT:
        return Limit(settings.rate_limit_agent_per_second, settings.rate_limit_agent_burst)
    if scope == SCOPE_TENANT:
        return Limit(settings.rate_limit_tenant_per_second, settings.rate_limit_tenant_burst)
    return Limit(settings.rate_limit_principal_per_second, settings.rate_limit_principal_burst)


def _prune_horizon(settings: Settings) -> float:
    horizon = _MIN_PRUNE_HORIZON_SECONDS
    for scope in (SCOPE_USER, SCOPE_AGENT, SCOPE_TENANT):
        limit = principal_limit(settings, scope)
        if limit.enabled:
            horizon = max(horizon, limit.burst / limit.per_second)
    return horizon


def charge(scope: str, key: str) -> None:
    """Spend one token from ``scope``'s bucket for ``key``, or raise :class:`RateLimited`.

    ``key`` identifies the principal or the tenant and is stored as given;
    callers build it from verified identity only (``api/auth.py``).
    """
    settings, buckets = _settings, _buckets
    if settings is None or buckets is None:
        return
    limit = principal_limit(settings, scope)
    if not limit.enabled:
        return
    try:
        wait = buckets.take(f"{scope}:{key}", limit)
        _maybe_prune(settings, buckets)
    except SQLAlchemyError:
        # Deliberate fail-open, see the module docstring: a limiter that 429s
        # every request while the database is away is an outage of its own.
        _warn_unavailable()
        return
    if wait is None:
        return
    retry_after = max(1, math.ceil(wait))
    metrics_service.RATE_LIMITED_TOTAL.labels(scope).inc()
    logger.info("rate limited: %s %s, retry after %ss", scope, key, retry_after)
    raise RateLimited(scope, retry_after)


def _maybe_prune(settings: Settings, buckets: Buckets) -> None:
    global _last_prune
    now = time.monotonic()
    with _state_lock:
        if _last_prune and now - _last_prune < _PRUNE_INTERVAL_SECONDS:
            return
        _last_prune = now
    buckets.prune(_prune_horizon(settings))


def _warn_unavailable() -> None:
    global _last_warning
    now = time.monotonic()
    with _state_lock:
        if _last_warning and now - _last_warning < _WARN_INTERVAL_SECONDS:
            return
        _last_warning = now
    logger.warning("rate limit buckets unavailable; letting requests through", exc_info=True)


def reset_for_tests(settings: Settings) -> None:
    """Empty the buckets, which no foreign key clears with the tenants."""
    configure(settings)
    if _buckets is not None:
        _buckets.clear()
