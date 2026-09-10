"""The administrative audit trail, read side (#327).

``GET /api/auth/events`` next door answers "who signed in"; this answers "what
was changed". Admin in a tenant is enough to read that tenant's rows — the
people who administer a customer are the ones who have to review its changes —
while the platform admin's listing spans every tenant and can be narrowed with
``?tenant_id=``. Rows with no tenant at all (creating a console account,
editing the installation-wide scanner config) are platform-level acts and
appear only in the platform admin's answer.

The export streams. A year of one tenant's changes is a file, not a JSON
response body, and building it in memory to hand to a browser download is how a
list endpoint becomes an availability problem.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Annotated, Any, Iterator

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from api.auth import Role, TenantPrincipal, require_tenant
from api.routes._pagination import PageQuery, build_page
from api.schemas import AuditEventInfo, Page
from api.services import audit as audit_service
from api.services.pagination import DEFAULT_LIMIT, MAX_LIMIT

router = APIRouter(tags=["audit"])

# The export's column order. Explicit rather than derived from the first row:
# a CSV whose columns move when a row happens to have no ``before`` is not a
# file anyone can diff against last quarter's.
_CSV_COLUMNS = (
    "id",
    "occurred_at",
    "tenant_id",
    "actor",
    "actor_type",
    "action",
    "resource_type",
    "resource_id",
    "client_ip",
    "user_agent",
    "request_id",
    "before",
    "after",
)


def _tenant_scope(principal: TenantPrincipal) -> str | None:
    """None for a platform admin who named no tenant — i.e. "every tenant".

    The same shape the cross-tenant listings use (``api/routes/agents.py``):
    naming a tenant narrows the answer, and a tenant admin's own tenant is the
    only value their principal can carry.
    """
    if principal.is_platform_admin and not principal.tenant_requested:
        return None
    return principal.tenant_id


# Leading characters a spreadsheet reads as the start of a formula rather than
# as text. Tab and carriage return are here because Excel strips them before
# deciding, so ``\t=cmd|…`` is a formula too.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> Any:
    """Neutralise a cell a spreadsheet would evaluate instead of display.

    Almost every column in this export is attacker-influenced: an agent picks
    its own ``agent_id``, a viewer picks their ``User-Agent``, and a
    ``resource_id`` is whatever was named in the request that got refused. A
    trail whose whole purpose is to be opened in Excel by someone reviewing an
    incident is the last place to hand that straight to the formula parser, so
    a leading formula character gets an apostrophe in front of it — the
    convention every spreadsheet reads back as literal text.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_rows(events: Iterator[dict[str, Any]]) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    yield _drain(buffer)
    for event in events:
        row = dict(event)
        # The two JSON columns go in as JSON text: a CSV cell holding a Python
        # dict repr is not something the spreadsheet on the other end can read.
        for key in ("before", "after"):
            row[key] = json.dumps(row[key], default=str) if row.get(key) is not None else ""
        writer.writerow({key: _csv_cell(value) for key, value in row.items()})
        yield _drain(buffer)


def _drain(buffer: io.StringIO) -> str:
    value = buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    return value


def _ndjson_rows(events: Iterator[dict[str, Any]]) -> Iterator[str]:
    for event in events:
        yield json.dumps(event, default=str) + "\n"


@router.get("/audit", response_model=None)
def list_audit_events(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    offset: Annotated[int, Query(ge=0, description="Rows to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Rows per page")] = DEFAULT_LIMIT,
    actor: Annotated[str | None, Query(description="Exact actor (username, token or agent)")] = None,
    action: Annotated[str | None, Query(description="Exact action, e.g. user.role_change")] = None,
    resource_type: Annotated[str | None, Query(description="Exact resource type")] = None,
    resource_id: Annotated[str | None, Query(description="Exact resource id")] = None,
    from_: Annotated[
        datetime | None, Query(alias="from", description="Only events at or after this UTC time")
    ] = None,
    to: Annotated[
        datetime | None, Query(description="Only events at or before this UTC time")
    ] = None,
    export_format: Annotated[
        str | None,
        Query(alias="format", pattern="^(csv|ndjson)$", description="Stream an export instead"),
    ] = None,
) -> Page[AuditEventInfo] | StreamingResponse:
    """Recorded changes, newest first. Admin in the tenant; platform admin sees all.

    Takes ``offset``/``limit`` but not the ``q``/``sort``/``order`` of the other
    paginated lists, and does not advertise them: this is a log, so the only
    order anybody reads it in is newest-first, and the filters below are exact
    because "every change to *this* token" is the question — a substring match
    over a trail is how the wrong row gets read as the right one. A parameter
    accepted and quietly ignored is worse than one that is not there.

    ``?format=csv`` and ``?format=ndjson`` stream **every** matching event, not
    the current page: an export bounded by ``limit`` is a page with a filename.
    """
    scope = {
        "tenant_id": _tenant_scope(principal),
        "actor": actor,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "since": _naive(from_),
        "until": _naive(to),
    }
    if export_format:
        events = audit_service.iter_events(**scope)
        if export_format == "csv":
            stream, media_type, suffix = _csv_rows(events), "text/csv", "csv"
        else:
            stream, media_type, suffix = _ndjson_rows(events), "application/x-ndjson", "ndjson"
        return StreamingResponse(
            stream,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="audit-events.{suffix}"'},
        )
    items, total = audit_service.list_events(**scope, offset=offset, limit=limit)
    params = PageQuery(offset=offset, limit=limit, q=None, sort=None, order="desc")
    return build_page([AuditEventInfo.model_validate(item) for item in items], total, params)


def _naive(value: datetime | None) -> datetime | None:
    """Drop the offset after converting to UTC — the column is naive UTC.

    A client that sends ``2026-09-01T00:00:00+03:00`` means an instant, and
    comparing that instant's *local* reading against a UTC column would silently
    shift the window by the offset.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)
