"""Tenant-uploaded brute-force wordlists (Phase 8.2, UI-managed).

An operator uploads a wordlist file here; a later scan references it by id
(``StartScanRequest.wordlist_id``) to run subdomain/bucket brute force with a
custom list instead of the built-in one. The body is normalized and stored in
Postgres by ``api/services/wordlists.py`` — this module is just the HTTP edge:
tenant scoping, the multipart upload, and the size cap.

Writes require the tenant ``operator`` role (same as starting a scan — a
wordlist only widens *this tenant's own* discovery, unlike a webhook, which
sends data outward and so needs ``admin``).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.schemas import WordlistInfo
from api.services import wordlists
from api.settings import Settings

router = APIRouter(prefix="/wordlists", tags=["wordlists"])


def _scope(principal: TenantPrincipal) -> str | None:
    """Unscoped platform admin keeps the cross-tenant view (as for webhooks)."""
    if principal.is_platform_admin and not principal.tenant_requested:
        return None
    return principal.tenant_id


def _require_own_wordlist(wordlist_id: str, principal: TenantPrincipal) -> dict:
    """404 for a wordlist in another tenant — its id's existence is not the
    caller's business, as for jobs, schedules and webhooks."""
    row = wordlists.get_wordlist(wordlist_id)
    if row is None or (
        not principal.is_platform_admin and row.get("tenant_id") != principal.tenant_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Wordlist not found")
    return row


@router.get("", response_model=list[WordlistInfo])
def list_wordlists(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> list[dict]:
    return wordlists.list_wordlists(_scope(principal))


@router.post("", response_model=WordlistInfo, status_code=status.HTTP_201_CREATED)
async def upload_wordlist(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
    file: Annotated[UploadFile, File(description="Newline-separated wordlist file")],
    kind: Annotated[str, Form()] = "subdomain",
    name: Annotated[str | None, Form()] = None,
) -> dict:
    # Read with a hard cap so a huge upload cannot exhaust memory: read one byte
    # past the limit and reject if we got it, rather than trusting Content-Length.
    limit = settings.wordlist_max_body_bytes
    raw = await file.read(limit + 1)
    if len(raw) > limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Wordlist body exceeds {limit} bytes",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Wordlist must be UTF-8 text",
        ) from exc

    resolved_name = (name or file.filename or "").strip()
    try:
        return wordlists.create_wordlist(
            tenant_id=principal.tenant_id,
            name=resolved_name,
            kind=kind,
            raw_content=text,
            username=principal.username,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.get("/{wordlist_id}", response_model=WordlistInfo)
def get_wordlist(
    wordlist_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> dict:
    return _require_own_wordlist(wordlist_id, principal)


@router.delete("/{wordlist_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_wordlist(
    wordlist_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> None:
    _require_own_wordlist(wordlist_id, principal)
    wordlists.delete_wordlist(wordlist_id)
