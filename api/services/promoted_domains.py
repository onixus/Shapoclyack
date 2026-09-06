"""Related domains an operator promoted into a tenant's scan scope (org_profile M4).

The org-profile stage of the scanner proposes domains that *probably* belong
to the organisation and never scans them itself. Promotion is the operator's
decision that they do, and this module is where that decision lives and where
``jobs.start_scan`` reads it back: a promoted domain is a target of every scan
the tenant starts afterwards, not a note in the run that proposed it.

The decision is keyed on ``(tenant, domain)`` and nothing else. The run that
proposed the domain is kept as evidence (``source_run_id``), but neither
listing nor withdrawing depends on it: run retention (#187) deletes runs, and
a promotion that could only be undone through a run that no longer exists
would be exactly the trap migration ``0031`` says is unacceptable.

Two things the caller does not get to skip. A promotion is checked against the
tenant's approved scan scope (#226) at the moment it is made — "yes, ours" is
not "yes, you may scan it", and an admin approves the latter — including the
resolve-time deny check a typed target gets, and checked again when a scan
starts, because the scope may have been narrowed since. In both places the
scope wins. And both directions are journalled in ``auth_events`` with the
actor, the way host-key pins are (#241): a change to what the platform scans
that left no trace is itself worth noticing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import auth_audit, scan_scopes
from api.settings import Settings
from scanner.pipeline import scan_scope as scope_rules

_log = logging.getLogger(__name__)

#: One normaliser for the name that is stored, scope-checked and compared —
#: the same one the scope matcher itself uses, so they cannot drift apart.
normalize_domain = scope_rules.normalize_domain


@dataclass(frozen=True)
class PromotedDomain:
    tenant_id: str
    domain: str
    source_run_id: str
    promoted_by: str
    promoted_at: datetime


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _from_row(row: models.TenantPromotedDomain) -> PromotedDomain:
    return PromotedDomain(
        tenant_id=row.tenant_id,
        domain=row.domain,
        source_run_id=row.source_run_id or "",
        promoted_by=row.promoted_by or "",
        promoted_at=row.promoted_at,
    )


def _journal(*, username: str, reason: str, detail: str) -> None:
    """Best-effort, like ``scan_scopes.record_denial``: the change has already
    been made when this runs, and losing the journal write must not turn a
    clean 200 into a 500 — but it is logged, because a scope change that
    left no trace is itself worth noticing."""
    try:
        auth_audit.record_trust_change(username=username, reason=reason, detail=detail[:1000])
    except Exception:  # noqa: BLE001 - see docstring
        _log.exception("Failed to journal promoted-domain change: %s", detail)


def promote(
    settings: Settings,
    *,
    tenant_id: str,
    domain: str,
    source_run_id: str,
    promoted_by: str,
) -> PromotedDomain:
    """Record the decision. Idempotent under concurrency: two writers racing
    on the same ``(tenant, domain)`` both return the row the winner wrote,
    and the first attribution is kept.

    Raises ``scan_scopes.ScanScopeDenied`` when the tenant's approved scope
    does not cover the domain — by suffix, or because its current addresses
    land in a denied range — so the operator learns now, not at the next
    scan start, and the row is never written.
    """
    name = normalize_domain(domain)
    scope = scan_scopes.load_scope(settings, tenant_id)
    scope.check(ranges=[], domains=[name])
    resolved = scan_scopes.resolution_refusals(settings, scope, [name])
    if resolved:
        raise scan_scopes.ScanScopeDenied(
            f"targets resolve into a denied range for tenant {tenant_id}: "
            + ", ".join(detail for _, detail in resolved),
            tenant_id=tenant_id,
            targets=[detail for _, detail in resolved],
        )

    with get_session(settings.postgres_url) as session:
        row = models.TenantPromotedDomain(
            tenant_id=tenant_id,
            domain=name,
            source_run_id=(source_run_id or "")[:200],
            promoted_by=(promoted_by or "")[:200],
            promoted_at=_now(),
        )
        inserted = insert_if_absent(session, row, f"{tenant_id}/{name}")
        if not inserted:
            row = session.get(models.TenantPromotedDomain, (tenant_id, name))
            assert row is not None  # the loser of the race reads the winner's row
        record = _from_row(row)

    if inserted:
        _journal(
            username=promoted_by,
            reason=auth_audit.REASON_PROMOTED_DOMAIN_ADDED,
            detail=f"tenant={tenant_id} domain={name} run={source_run_id}",
        )
    return record


def withdraw(settings: Settings, *, tenant_id: str, domain: str, withdrawn_by: str) -> bool:
    """Withdraw a promotion, keyed on the tenant alone. Returns False when
    there was none to withdraw. Journalled with the actor: the row carried
    who promoted the domain and when, and deleting it must not be the moment
    that record disappears."""
    name = normalize_domain(domain)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantPromotedDomain, (tenant_id, name))
        if row is None:
            return False
        detail = (
            f"tenant={tenant_id} domain={name} run={row.source_run_id} "
            f"promoted_by={row.promoted_by} promoted_at={row.promoted_at.isoformat()}"
        )
        session.delete(row)
    _journal(
        username=withdrawn_by,
        reason=auth_audit.REASON_PROMOTED_DOMAIN_WITHDRAWN,
        detail=detail,
    )
    return True


def list_promoted(settings: Settings, tenant_id: str) -> list[PromotedDomain]:
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.TenantPromotedDomain)
            .where(models.TenantPromotedDomain.tenant_id == tenant_id)
            .order_by(models.TenantPromotedDomain.domain)
        ).scalars()
        return [_from_row(row) for row in rows]


def promoted_names(settings: Settings, tenant_id: str) -> list[str]:
    """Just the domains, sorted — what a scan start merges into its targets."""
    with get_session(settings.postgres_url) as session:
        return list(
            session.execute(
                select(models.TenantPromotedDomain.domain)
                .where(models.TenantPromotedDomain.tenant_id == tenant_id)
                .order_by(models.TenantPromotedDomain.domain)
            ).scalars()
        )


def split_for_scan(
    settings: Settings, scope: scan_scopes.ScanScope, domains: list[str]
) -> tuple[list[str], list[str]]:
    """``(admitted, refused)`` against the scope as it stands right now.

    The same two checks a typed target gets at scan admission — the suffix
    rules through the scanner's own ``filter_names`` (one implementation of
    "deny beats allow", not two) and the resolve-time deny check — with one
    difference in what happens on refusal: a promoted domain the scope no
    longer covers is dropped from the scan, not a reason to refuse it. The
    operator's other targets were checked on their own and are still theirs
    to scan; the refusal is recorded on the job so the narrowing is visible.
    """
    result = scope_rules.filter_names(scope, domains)
    refused = list(result.refused)
    admitted = list(result.kept)
    for name, detail in scan_scopes.resolution_refusals(settings, scope, admitted):
        refused.append(detail)
        admitted = [item for item in admitted if item != name]
    return admitted, refused


def reset_for_tests(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(delete(models.TenantPromotedDomain))
