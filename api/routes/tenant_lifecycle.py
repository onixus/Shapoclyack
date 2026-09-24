"""Suspending, resuming and deleting a tenant (#325).

Every route here is ``platform.tenant.lifecycle`` — platform admins only; a
service token never reaches them, since it is never the platform admin — and
every change is behind a step-up, like the legal hold next door: each one
either locks a customer out or destroys what it had.

The answers are the platform admin's, whole: the suspension's reason, the
legal hold's reason and author (a 409 names them), and the deletion journal.
None of it is served to the tenant's own members, who see only that their
tenant is not active.
"""

from __future__ import annotations

from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import StepUpDep, TokenUser, get_settings, require_platform_permission
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.schemas import (
    SuspendTenantRequest,
    TenantDeletionApproval,
    TenantDeletionInfo,
    TenantDeletionRequest,
    TenantLifecycleInfo,
)
from api.services import legal_hold
from api.services import tenant_lifecycle as lifecycle
from api.settings import Settings

router = APIRouter(tags=["tenant-lifecycle"])

LifecycleAdmin = Annotated[
    TokenUser,
    Depends(require_platform_permission(permission_catalog.PLATFORM_TENANT_LIFECYCLE)),
]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def _refuse(exc: Exception) -> NoReturn:
    """One mapping from the service's refusals to HTTP, for every route here."""
    # LegalHoldActive is a PermissionError too: tested first, because the hold
    # is a 409 (it lasts exactly as long as the hold) and not a 403.
    if isinstance(exc, legal_hold.LegalHoldActive):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, lifecycle.SecondApproverRequired):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if isinstance(exc, lifecycle.LifecycleConflict):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    raise exc


_REFUSALS = (LookupError, ValueError, PermissionError, lifecycle.LifecycleConflict)


@router.get("/tenants/{tenant_id}/lifecycle", response_model=TenantLifecycleInfo)
def get_lifecycle(
    tenant_id: str,
    _: LifecycleAdmin,
    settings: SettingsDep,
) -> TenantLifecycleInfo:
    """The tenant's status and why, its legal hold, and its deletion with every step.

    Answers for a tenant that has been purged too, from the journal
    (``status: deleted``), so the page an admin was watching does not turn
    into a 404 at the moment the purge completes.
    """
    try:
        described = lifecycle.describe(settings, tenant_id)
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


@router.post("/tenants/{tenant_id}/suspend", response_model=TenantLifecycleInfo)
def suspend_tenant(
    tenant_id: str,
    body: SuspendTenantRequest,
    user: LifecycleAdmin,
    _: StepUpDep,
    settings: SettingsDep,
    audit: AuditDep,
) -> TenantLifecycleInfo:
    """Suspend the tenant and cut every path it had in.

    Its members' sessions end where this was the only active tenant they could
    act in, its service tokens and provisioning keys are revoked (unless
    ``revoke_credentials`` is false), its queued scans are cancelled and its
    agents' running ones asked to stop, and its schedules and notifications
    pause. Suspending a suspended tenant changes nothing.
    """
    try:
        described = lifecycle.suspend(
            settings,
            tenant_id,
            reason=body.reason,
            actor=user.username,
            revoke_credentials=body.revoke_credentials,
            audit=audit,
        )
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


@router.post("/tenants/{tenant_id}/resume", response_model=TenantLifecycleInfo)
def resume_tenant(
    tenant_id: str,
    user: LifecycleAdmin,
    _: StepUpDep,
    settings: SettingsDep,
    audit: AuditDep,
) -> TenantLifecycleInfo:
    """Put a suspended tenant back into service.

    What the suspension paused resumes; what it revoked stays revoked — mint
    new provisioning keys and service tokens. Overdue schedules move to their
    next occurrence instead of all firing now.
    """
    try:
        described = lifecycle.resume(settings, tenant_id, actor=user.username, audit=audit)
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


@router.post(
    "/tenants/{tenant_id}/deletion",
    response_model=TenantLifecycleInfo,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_tenant_deletion(
    tenant_id: str,
    body: TenantDeletionRequest,
    user: LifecycleAdmin,
    _: StepUpDep,
    settings: SettingsDep,
    audit: AuditDep,
) -> TenantLifecycleInfo:
    """Step one: suspend the tenant and open its deletion. Nothing is deleted yet.

    ``confirm`` must be the tenant id. The purge can be approved once the grace
    period (``OCTO_TENANT_DELETION_GRACE_DAYS``) is over, and until then this
    can be cancelled. 409 for a tenant on legal hold, for the default tenant,
    and for one whose deletion is already open.
    """
    try:
        described = lifecycle.request_deletion(
            settings,
            tenant_id,
            confirm=body.confirm,
            reason=body.reason,
            actor=user.username,
            audit=audit,
        )
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


@router.delete("/tenants/{tenant_id}/deletion", response_model=TenantLifecycleInfo)
def cancel_tenant_deletion(
    tenant_id: str,
    user: LifecycleAdmin,
    _: StepUpDep,
    settings: SettingsDep,
    audit: AuditDep,
) -> TenantLifecycleInfo:
    """Withdraw the deletion during its grace period. The tenant stays suspended.

    409 once the purge has started: what it deleted is not coming back.
    """
    try:
        described = lifecycle.cancel_deletion(
            settings, tenant_id, actor=user.username, audit=audit
        )
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


@router.post("/tenants/{tenant_id}/deletion/approve", response_model=TenantLifecycleInfo)
def approve_tenant_deletion(
    tenant_id: str,
    body: TenantDeletionApproval,
    user: LifecycleAdmin,
    _: StepUpDep,
    settings: SettingsDep,
    audit: AuditDep,
) -> TenantLifecycleInfo:
    """Step two: start the purge. Irreversible.

    After the grace period, by a platform admin other than the requester
    (``OCTO_TENANT_DELETION_TWO_PERSON``, 403 otherwise), with the tenant id
    typed again. 409 for a tenant on legal hold.
    """
    try:
        described = lifecycle.approve_deletion(
            settings, tenant_id, confirm=body.confirm, actor=user.username, audit=audit
        )
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


@router.post("/tenants/{tenant_id}/deletion/retry", response_model=TenantLifecycleInfo)
def retry_tenant_deletion(
    tenant_id: str,
    user: LifecycleAdmin,
    _: StepUpDep,
    settings: SettingsDep,
    audit: AuditDep,
) -> TenantLifecycleInfo:
    """Make a failing purge due now, or resume one a legal hold stopped.

    A blocked purge resumes only here, and only once the hold is released: the
    release and the destruction of what the hold preserved are two decisions.
    """
    try:
        described = lifecycle.retry_deletion(
            settings, tenant_id, actor=user.username, audit=audit
        )
    except _REFUSALS as exc:
        _refuse(exc)
    return TenantLifecycleInfo.model_validate(described)


# Under ``/tenants`` like the rest, so the service-token scope layer refuses it
# with every other tenant administration route (``tenants`` is in
# ``service_tokens.FORBIDDEN_RESOURCES``) before the permission check does.
@router.get("/tenants/deletions", response_model=list[TenantDeletionInfo])
def list_tenant_deletions(
    _: LifecycleAdmin,
    settings: SettingsDep,
    state: Annotated[
        str | None,
        Query(pattern="^(pending|cancelled|purging|blocked|completed)$"),
    ] = None,
) -> list[TenantDeletionInfo]:
    """The deletion journal, newest first, tombstones included.

    ``?state=completed`` is the list to re-apply after restoring a backup
    taken before any of them (``docs/tenant-lifecycle.md``).
    """
    return [
        TenantDeletionInfo.model_validate(row)
        for row in lifecycle.list_deletions(settings, state=state)
    ]
