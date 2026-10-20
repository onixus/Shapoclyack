"""HTTP shell of the bounded export endpoints, shared by assets and vulnerabilities."""

from __future__ import annotations

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from api.services import api_exports


def export_response(
    settings,
    *,
    tenant_id: str,
    resource: str,
    format: str,
    cursor: str | None,
    limit: int,
) -> StreamingResponse:
    """One export page as a streamed CSV/NDJSON response with X-Next-Cursor."""
    try:
        rows, next_cursor = api_exports.export_page(
            settings, tenant_id=tenant_id, resource=resource, cursor=cursor, limit=limit
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    headers = {
        "Content-Disposition": f'attachment; filename="{resource}.{format}"',
        "Cache-Control": "no-store",
    }
    if next_cursor:
        headers["X-Next-Cursor"] = next_cursor
    return StreamingResponse(
        api_exports.stream_rows(resource, rows, format),
        media_type="text/csv" if format == "csv" else "application/x-ndjson",
        headers=headers,
    )
