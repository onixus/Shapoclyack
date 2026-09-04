"""Related domains an operator promoted into a tenant's scan scope (org_profile M4).

The org-profile stage of the scanner proposes domains that *probably* belong
to the organisation and never scans them itself. Promotion is the operator's
decision that they do, and this module is where that decision lives and where
``jobs.start_scan`` reads it back: a promoted domain is a target of every scan
the tenant starts afterwards, not a note in the run that proposed it.

Two things the caller does not get to skip. A promotion is checked against the
tenant's approved scan scope (#226) at the moment it is made — "yes, ours" is
not "yes, you may scan it", and an admin approves the latter — and checked
again when a scan starts, because the scope may have been narrowed since. In
both places the scope wins.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session
from api.services import scan_scopes
from api.settings import Settings


@dataclass(frozen=True)
class PromotedDomain:
    tenant_id: str
    domain: str
    source_run_id: str
    promoted_by: str
    promoted_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "domain": self.domain,
            "source_run_id": self.source_run_id,
            "promoted_by": self.promoted_by,
            "promoted_at": self.promoted_at.isoformat(),
        }


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _from_row(row: models.TenantPromotedDomain) -> PromotedDomain:
    return PromotedDomain(
        tenant_id=row.tenant_id,
        domain=row.domain,
        source_run_id=row.source_run_id or "",
        promoted_by=row.promoted_by or "",
        promoted_at=row.promoted_at,
    )


def promote(
    settings: Settings,
    *,
    tenant_id: str,
    domain: str,
    source_run_id: str,
    promoted_by: str,
) -> PromotedDomain:
    """Record the decision. Idempotent: promoting again keeps the first
    attribution rather than rewriting who decided.

    Raises ``scan_scopes.ScanScopeDenied`` when the tenant's approved scope
    does not cover the domain — the operator learns now, not at the next scan
    start, and the row is never written.
    """
    name = normalize_domain(domain)
    scope = scan_scopes.load_scope(settings, tenant_id)
    scope.check(ranges=[], domains=[name])

    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantPromotedDomain, (tenant_id, name))
        if row is None:
            row = models.TenantPromotedDomain(
                tenant_id=tenant_id,
                domain=name,
                source_run_id=(source_run_id or "")[:200],
                promoted_by=(promoted_by or "")[:200],
                promoted_at=_now(),
            )
            session.add(row)
            session.flush()
        return _from_row(row)


def withdraw(settings: Settings, *, tenant_id: str, domain: str) -> bool:
    """Withdraw a promotion. Returns False when there was none to withdraw."""
    name = normalize_domain(domain)
    with get_session(settings.postgres_url) as session:
        result = session.execute(
            delete(models.TenantPromotedDomain).where(
                models.TenantPromotedDomain.tenant_id == tenant_id,
                models.TenantPromotedDomain.domain == name,
            )
        )
        return bool(result.rowcount)


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
    return [item.domain for item in list_promoted(settings, tenant_id)]


def split_by_scope(
    scope: scan_scopes.ScanScope, domains: list[str]
) -> tuple[list[str], list[str]]:
    """``(admitted, refused)`` against the scope as it stands right now.

    A promoted domain the scope no longer covers is dropped from the scan, not
    a reason to refuse the scan: the operator's other targets were checked on
    their own and are still theirs to scan. The refusal is recorded on the job
    so the narrowing is visible rather than silent.
    """
    admitted: list[str] = []
    refused: list[str] = []
    for name in domains:
        reason = scope.rejects_domain(name)
        if reason:
            refused.append(f"{name} ({reason})")
        else:
            admitted.append(name)
    return admitted, refused


def reset_for_tests(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(delete(models.TenantPromotedDomain))
