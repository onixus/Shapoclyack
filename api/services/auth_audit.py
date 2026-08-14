"""Login rate limiting and the authentication audit trail (#157).

Before this, ``POST /api/auth/login`` was unlimited and unrecorded: guessing a
password cost only bandwidth, and a successful guess left no trace that
distinguished it from an ordinary sign-in.

**Why the counter is a table.** Every ``k8s/`` manifest may now run more than
one API replica (ROADMAP P1.6), and which replica serves an attempt is the load
balancer's choice. An in-process counter would therefore be divided by the
replica count — five attempts allowed per replica, not per account — and would
reset on every rollout. The shape here is the one already used by
``api/services/endpoint_inventory.py``: count the rows in a window.

**Why the counter and the log are the same rows.** The limiter's question
("how many failures for this pair recently") is a predicate over the audit
trail. A separate counter table would have to be kept in agreement with the log
it summarises, and would need this table's index anyway.

**Two limits, not one.** The pair ``(username, client_ip)`` is the limit the
issue asks for and the one that protects an account. It does nothing about one
address walking a *username list*, so a second, looser limit counts an
address's failures across all usernames. Both windows are the same length, and
either one tripping refuses the attempt.

Lockout is a **decaying window**, never a flag on the account: the correct
password works again once the window passes, with no operator involved, and an
attacker cannot lock a known username out permanently by failing on purpose.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.settings import Settings

logger = logging.getLogger(__name__)

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_LOCKED = "locked"

# Values allowed in ``auth_events.reason``. Kept as constants so the admin
# endpoint's consumers have a closed set to switch on.
REASON_INVALID_CREDENTIALS = "invalid_credentials"
REASON_RATE_LIMITED_PAIR = "rate_limited_user_ip"
REASON_RATE_LIMITED_IP = "rate_limited_ip"

_settings: Settings | None = None
_prune_lock = threading.Lock()
_last_prune: datetime | None = None
# Pruning is opportunistic (see _maybe_prune) rather than a worker thread: this
# table grows only with login attempts, so a sweep an hour is far more often
# than its growth needs.
_PRUNE_INTERVAL = timedelta(hours=1)


@dataclass(frozen=True)
class Lockout:
    """An attempt refused before the password was checked."""

    reason: str
    retry_after_seconds: int


def _now() -> datetime:
    # Naive UTC, matching every other timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "auth_audit.configure() not called"
    return _settings


def _to_dict(row: models.AuthEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "occurred_at": _iso(row.occurred_at),
        "username": row.username,
        "client_ip": row.client_ip,
        "outcome": row.outcome,
        "reason": row.reason,
    }


def check_lockout(username: str, client_ip: str) -> Lockout | None:
    """Return the refusal to apply to this attempt, or None to let it proceed.

    Counts *failures* only. A successful login does not clear the window — it
    does not need to, because the window is short and a legitimate user who has
    just succeeded is not being counted for their next attempt either. What it
    does mean is that the limit is on failures per window, full stop, which is
    the property that is easy to state and easy to verify.
    """
    settings = _require_settings()
    if not settings.login_rate_limit_enabled:
        return None

    window = max(1, settings.login_rate_limit_window_seconds)
    cutoff = _now() - timedelta(seconds=window)

    with get_session(settings.postgres_url) as session:
        # One round trip for both counters: the per-IP limit is a superset of
        # the pair's rows, so counting them separately would read the same rows
        # twice.
        rows = session.execute(
            select(models.AuthEvent.username, models.AuthEvent.occurred_at).where(
                models.AuthEvent.client_ip == client_ip,
                models.AuthEvent.occurred_at >= cutoff,
                models.AuthEvent.outcome == OUTCOME_FAILURE,
            )
        ).all()

    if not rows:
        return None

    pair_times = [occurred_at for name, occurred_at in rows if name == username]
    pair_max = max(1, settings.login_rate_limit_max_failures)
    ip_max = max(1, settings.login_rate_limit_ip_max_failures)

    if len(pair_times) >= pair_max:
        return Lockout(
            reason=REASON_RATE_LIMITED_PAIR,
            retry_after_seconds=_retry_after(pair_times, pair_max, window),
        )
    if len(rows) >= ip_max:
        return Lockout(
            reason=REASON_RATE_LIMITED_IP,
            retry_after_seconds=_retry_after([t for _, t in rows], ip_max, window),
        )
    return None


def _retry_after(times: list[datetime], limit: int, window: int) -> int:
    """Seconds until the window has decayed enough for one more attempt.

    That is when the ``limit``-th *oldest* counted failure leaves the window —
    not when the newest does, which would restart the wait on every refused
    attempt and turn a 15-minute lockout into an indefinite one for anyone
    still retrying.
    """
    ordered = sorted(times)
    expiring = ordered[len(ordered) - limit]
    remaining = (expiring + timedelta(seconds=window) - _now()).total_seconds()
    return max(1, int(remaining) + 1)


def record(
    *,
    username: str,
    client_ip: str,
    outcome: str,
    reason: str | None = None,
) -> None:
    """Append one attempt to the audit trail and count it in ``/metrics``.

    Best-effort with respect to the caller: an audit write that fails must not
    turn a valid login into a 500. It is logged at error level, and the metric
    still moves, so the failure is visible rather than silent.
    """
    settings = _require_settings()
    metrics_service.AUTH_ATTEMPTS_TOTAL.labels(outcome).inc()
    try:
        with get_session(settings.postgres_url) as session:
            session.add(
                models.AuthEvent(
                    occurred_at=_now(),
                    username=username[:128],
                    client_ip=client_ip[:64],
                    outcome=outcome,
                    reason=reason,
                )
            )
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to record auth event (%s) for %r", outcome, username)
        return
    _maybe_prune(settings)


def record_locked(*, username: str, client_ip: str, lockout: Lockout) -> None:
    """Record a refused-while-locked attempt, at most once per window.

    A locked-out client typically keeps trying, and each of those requests is
    an unauthenticated write to this table if recorded naively — the audit
    trail becomes the amplification. The first refusal in a window is the one
    that carries the information ("this pair hit the limit at this time"); the
    rest are the same fact repeated, and are counted in ``/metrics`` instead.
    """
    settings = _require_settings()
    metrics_service.AUTH_ATTEMPTS_TOTAL.labels(OUTCOME_LOCKED).inc()
    cutoff = _now() - timedelta(seconds=max(1, settings.login_rate_limit_window_seconds))
    try:
        with get_session(settings.postgres_url) as session:
            already = session.execute(
                select(models.AuthEvent.id)
                .where(
                    models.AuthEvent.username == username[:128],
                    models.AuthEvent.client_ip == client_ip[:64],
                    models.AuthEvent.outcome == OUTCOME_LOCKED,
                    models.AuthEvent.occurred_at >= cutoff,
                )
                .limit(1)
            ).first()
            if already is not None:
                return
            session.add(
                models.AuthEvent(
                    occurred_at=_now(),
                    username=username[:128],
                    client_ip=client_ip[:64],
                    outcome=OUTCOME_LOCKED,
                    reason=lockout.reason,
                )
            )
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to record lockout for %r", username)


def list_events(
    *,
    offset: int = 0,
    limit: int = 100,
    q: str | None = None,
    outcome: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Newest-first page of attempts, with ``total`` counted after filtering.

    Filtering and counting are pushed into SQL like the other Postgres-backed
    lists (ROADMAP P3.2): this table is the one that grows with hostile
    traffic, so reading it into the process to filter is exactly the wrong
    shape.
    """
    settings = _require_settings()
    needle = (q or "").strip().lower()

    with get_session(settings.postgres_url) as session:
        conditions = []
        if needle:
            pattern = f"%{needle}%"
            conditions.append(
                or_(
                    func.lower(models.AuthEvent.username).like(pattern),
                    func.lower(models.AuthEvent.client_ip).like(pattern),
                )
            )
        if outcome:
            conditions.append(models.AuthEvent.outcome == outcome)

        total = session.execute(
            select(func.count()).select_from(models.AuthEvent).where(*conditions)
        ).scalar_one()
        rows = (
            session.execute(
                select(models.AuthEvent)
                .where(*conditions)
                # id breaks ties: two attempts can share a timestamp at this
                # resolution, and an unstable order would repeat or skip a row
                # across pages.
                .order_by(models.AuthEvent.occurred_at.desc(), models.AuthEvent.id.desc())
                .offset(offset)
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [_to_dict(row) for row in rows], int(total)


def _maybe_prune(settings: Settings) -> None:
    """Drop events past the retention window, at most once an hour per process.

    Opportunistic rather than a worker thread: the table only grows when
    someone tries to log in, so the sweep can ride along with the writes that
    cause the growth. Every replica prunes; the delete is idempotent.
    """
    global _last_prune
    days = settings.auth_event_retention_days
    if days <= 0:
        return
    now = _now()
    with _prune_lock:
        if _last_prune is not None and now - _last_prune < _PRUNE_INTERVAL:
            return
        _last_prune = now
    cutoff = now - timedelta(days=days)
    try:
        with get_session(settings.postgres_url) as session:
            session.execute(delete(models.AuthEvent).where(models.AuthEvent.occurred_at < cutoff))
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to prune auth_events")


def reset_for_tests() -> None:
    global _last_prune
    settings = _require_settings()
    _last_prune = None
    with get_session(settings.postgres_url) as session:
        session.query(models.AuthEvent).delete()
