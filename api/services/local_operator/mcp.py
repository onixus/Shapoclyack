"""Read-only MCP tools. Authority comes exclusively from the authenticated principal."""
from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from api.auth import TenantPrincipal
from api.services import runs
from api.settings import Settings

PROTOCOL_VERSION = "2025-06-18"
MAX_RESULT_BYTES = 64 * 1024


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ListRuns(Arguments):
    offset: Annotated[int, Field(ge=0, le=100000)] = 0
    limit: Annotated[int, Field(ge=1, le=50)] = 20


class GetRun(Arguments):
    run_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*$")]


TOOLS = {
    "list_runs": (ListRuns, "List stored scan summaries in the selected tenant; no scans are started."),
    "get_run_summary": (GetRun, "Read stored counts from a scan in the selected tenant. Counts are observations, not verified vulnerabilities."),
}


def list_tools() -> list[dict[str, Any]]:
    return [
        {"name": name, "description": description, "inputSchema": schema.model_json_schema(),
         "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}}
        for name, (schema, description) in TOOLS.items()
    ]


def result(data: dict[str, Any], *, error: bool = False) -> dict[str, Any]:
    encoded = json.dumps(data, ensure_ascii=True, allow_nan=False)
    if len(encoded.encode()) > MAX_RESULT_BYTES:
        encoded = '{"error":"Result exceeds limit; request a smaller page"}'
        error = True
    return {"content": [{"type": "text", "text": encoded}], "isError": error}


def call_tool(settings: Settings, principal: TenantPrincipal, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Unknown tools/arguments raise ValueError; missing evidence is a tool error."""
    if name not in TOOLS:
        raise ValueError("Unknown tool")
    try:
        args = TOOLS[name][0].model_validate(arguments)
    except ValidationError as exc:
        raise ValueError("Invalid tool arguments") from exc
    # Deliberately never use the platform-admin fleet-wide REST exception.
    if not principal.tenant_id:
        raise ValueError("A selected tenant is required")
    if isinstance(args, ListRuns):
        items, total = runs.list_runs(settings, offset=args.offset, limit=args.limit, tenant_id=principal.tenant_id)
        fields = {"run_id", "tenant_id", "started_at", "alive_hosts", "open_host_port_pairs", "potential_vulnerabilities", "unconfirmed_findings", "vulnerable_hosts", "surface", "has_summary"}
        return result({"items": [item.model_dump(mode="json", include=fields) for item in items], "total": total, "offset": args.offset, "limit": args.limit})
    detail = runs.get_run_detail(settings, args.run_id, tenant_id=principal.tenant_id)
    if detail is None:
        return result({"error": "Run not found"}, error=True)
    # Never expose arbitrary artifacts, metadata, filesystem paths or secrets.
    fields = ("alive_hosts", "open_host_port_pairs", "potential_vulnerabilities", "unconfirmed_findings", "vulnerable_hosts")
    raw = detail.summary or {}
    counts = {key: value for key in fields if type(value := raw.get(key)) is int and value >= 0}
    return result({"run_id": detail.run_id, "counts": counts, "has_summary": detail.summary is not None,
                   "evidence": {"run_id": detail.run_id, "artifact": "summary.json"},
                   "notice": "Stored scanner observations; not proof of exploitation or current exposure."})
