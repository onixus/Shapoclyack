"""Tenant-scoped catalogue persistence; built-in catalogues stay immutable (#356)."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from api.db.compliance_models import ComplianceFrameworkDefinition as Definition
from api.db.engine import get_session
from api.db.models import Tenant
from api.services import audit as audit_service
from api.services.compliance import definitions, frameworks

if TYPE_CHECKING:
    from api.services.audit import AuditContext
    from api.settings import Settings

MAX_FRAMEWORKS_PER_TENANT = 32
MAX_CONTROLS_PER_TENANT = 1000
CUSTOM_SCOPE_NOTICE = (
    "Customer-defined technical evidence mapping; not a certification or a legal "
    "compliance assessment. Policy, organisational and legal obligations are not automatically assessed. "
)


class CatalogueConflict(ValueError):
    """A definition is immutable or the tenant's catalogue budget is exhausted."""


def _tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("an explicit tenant is required")
    return tenant_id


def _runtime(document: dict[str, Any]) -> frameworks.Framework:
    body = definitions.normalize(document)
    return frameworks.Framework(
        framework_id=body["framework_id"], name=body["name"], version=body["version"],
        scope_note=CUSTOM_SCOPE_NOTICE + body["scope_note"],
        controls=tuple(frameworks.Control(
            control_id=row["control_id"], title=row["title"],
            signals=tuple(row["signals"]),
            combinations=tuple(tuple(group) for group in row["combinations"]),
            requires=tuple(row["requires"]), severity_floor=row["severity_floor"],
            rationale=row["rationale"],
        ) for row in body["controls"]),
    )


def _document(row: Definition) -> dict[str, Any]:
    if definitions.digest(row.definition) != row.definition_sha256:
        raise ValueError("stored compliance definition digest mismatch")
    return {
        "definition": row.definition,
        "definition_sha256": row.definition_sha256,
        "created_at": row.created_at.isoformat() + "Z",
        "created_by": row.created_by,
    }


def import_definition(
    settings: Settings, *, tenant_id: str, content: str, format: str,
    audit: AuditContext,
) -> tuple[dict[str, Any], bool]:
    """Validate before opening a transaction; definition and audit commit together.

    IDs are immutable within a tenant. Repeating identical canonical content is
    idempotent; changing it requires a new ID so old evidence remains attributable.
    A tenant-row lock serialises the bounded catalogue admission across replicas.
    """
    tenant_id = _tenant(tenant_id)
    document = definitions.parse(content, format)
    _runtime(document)  # Also check against the runtime's closed vocabulary.
    digest = definitions.digest(document)
    with get_session(settings.postgres_url) as session:
        tenant = session.execute(
            select(Tenant).where(Tenant.tenant_id == tenant_id).with_for_update()
        ).scalar_one_or_none()
        if tenant is None or tenant.status != "active":
            raise CatalogueConflict("tenant is not active")
        existing = session.get(Definition, (tenant_id, document["framework_id"]))
        if existing is not None:
            if existing.definition_sha256 != digest:
                raise CatalogueConflict("framework_id already exists; import a new version with a new ID")
            return _document(existing), False
        count = session.scalar(
            select(func.count()).select_from(Definition).where(Definition.tenant_id == tenant_id)
        ) or 0
        if count >= MAX_FRAMEWORKS_PER_TENANT:
            raise CatalogueConflict(f"tenant is limited to {MAX_FRAMEWORKS_PER_TENANT} custom frameworks")
        controls = session.scalar(
            select(func.sum(Definition.control_count)).where(Definition.tenant_id == tenant_id)
        ) or 0
        if controls + len(document["controls"]) > MAX_CONTROLS_PER_TENANT:
            raise CatalogueConflict(f"tenant is limited to {MAX_CONTROLS_PER_TENANT} custom controls")
        row = Definition(
            tenant_id=tenant_id, framework_id=document["framework_id"],
            name=document["name"], version=document["version"], scope_note=document["scope_note"],
            control_count=len(document["controls"]), definition=document,
            definition_sha256=digest, created_at=datetime.now(UTC).replace(tzinfo=None),
            created_by=audit.actor,
        )
        session.add(row)
        audit_service.record(
            session, audit, action="compliance.framework.import",
            resource_type="compliance_framework", resource_id=row.framework_id, tenant_id=tenant_id,
            after={"framework_id": row.framework_id, "version": row.version,
                   "control_count": row.control_count, "definition_sha256": digest},
        )
        session.flush()
        return _document(row), True


def get_definition(settings: Settings, *, tenant_id: str, framework_id: str) -> dict[str, Any] | None:
    tenant_id = _tenant(tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.get(Definition, (tenant_id, framework_id))
        return _document(row) if row is not None else None


def resolve_framework(
    settings: Settings, framework_id: str, tenant_id: str | None,
) -> frameworks.Framework | None:
    built_in = frameworks.get_framework(framework_id)
    if built_in is not None:
        return built_in
    # A system/report caller without a scope sees built-ins, never a union of
    # customer definitions. HTTP routes require a tenant before reaching here.
    if not tenant_id:
        return None
    item = get_definition(settings, tenant_id=tenant_id, framework_id=framework_id)
    return _runtime(item["definition"]) if item is not None else None


def all_frameworks(settings: Settings, tenant_id: str | None) -> list[frameworks.Framework]:
    result = list(frameworks.FRAMEWORKS.values())
    if tenant_id:
        with get_session(settings.postgres_url) as session:
            rows = session.scalars(select(Definition).where(
                Definition.tenant_id == _tenant(tenant_id)
            ).order_by(Definition.framework_id)).all()
            result.extend(_runtime(_document(row)["definition"]) for row in rows)
    return result


def list_frameworks(settings: Settings, *, tenant_id: str) -> list[dict[str, Any]]:
    tenant_id = _tenant(tenant_id)
    result = frameworks.list_frameworks()
    # List metadata only, not up to 32 MiB of definition payloads on every page load.
    with get_session(settings.postgres_url) as session:
        rows = session.execute(select(
            Definition.framework_id, Definition.name, Definition.version,
            Definition.scope_note, Definition.control_count,
        ).where(Definition.tenant_id == tenant_id).order_by(Definition.framework_id)).all()
        result.extend({
            "framework_id": row.framework_id, "name": row.name, "version": row.version,
            "scope_note": CUSTOM_SCOPE_NOTICE + row.scope_note, "control_count": row.control_count,
        } for row in rows)
    return result
