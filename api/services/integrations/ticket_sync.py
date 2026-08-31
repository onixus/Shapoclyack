"""Two-way ticket status synchronisation for Jira, ServiceNow and DefectDojo (#183).

Inbound: poll the tracker and reconcile the finding's lifecycle state.
Outbound: reflect a local state change onto the ticket.

SAFETY: like ``tickets.py``, the wire is ``delivery.request`` — SSRF-validated,
pinned DNS, redirects never followed. The base URL is not derived from the
stored ``ticket_url`` string; it is the URL of the tenant's subscription for
that transport, which is also where the credential lives. A tracker that we
have no subscription for is a tracker we have no business calling.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from api.services.integrations.delivery import DeliveryResult, request
from api.services.integrations.tickets import (
    TicketSpecError,
    request_headers,
    validate_transport,
)

logger = logging.getLogger(__name__)

# Remote status -> lifecycle state. Only the states a tracker can honestly
# assert are mapped: a tracker never tells us a finding is VERIFYING, because
# only a scan can say that.
JIRA_STATUS_MAP = {
    "done": "CLOSED",
    "closed": "CLOSED",
    "resolved": "CLOSED",
    "complete": "CLOSED",
    "in progress": "FIXING",
    "in review": "FIXING",
    "to do": "PLANNED",
    "open": "OPEN",
    "reopened": "OPEN",
}

# ServiceNow incident_state standard values.
SNOW_STATE_MAP = {
    "1": "OPEN",       # New
    "2": "FIXING",     # In Progress
    "3": "PLANNED",    # On Hold
    "6": "CLOSED",     # Resolved
    "7": "CLOSED",     # Closed
    "8": "CLOSED",     # Canceled
}


def map_remote_status_to_vuln_state(
    transport: str, remote_data: dict[str, Any]
) -> tuple[str | None, str | None]:
    """Map a tracker payload to ``(suggested_state, raw_remote_status)``."""
    t = validate_transport(transport)
    if t == "jira":
        fields = remote_data.get("fields") if isinstance(remote_data.get("fields"), dict) else {}
        status_obj = fields.get("status") if isinstance(fields.get("status"), dict) else {}
        raw_status = str(status_obj.get("name") or "").strip()
        return JIRA_STATUS_MAP.get(raw_status.lower()), raw_status

    if t == "servicenow":
        result = remote_data.get("result", remote_data)
        if isinstance(result, list):
            result = result[0] if result else {}
        if not isinstance(result, dict):
            return None, None
        raw_state = str(result.get("incident_state") or result.get("state") or "").strip()
        return SNOW_STATE_MAP.get(raw_state), str(result.get("state") or raw_state) or None

    if t == "defectdojo":
        active = bool(remote_data.get("active", True))
        is_mitigated = bool(remote_data.get("is_mitigated", False))
        false_p = bool(remote_data.get("false_p", False))
        if is_mitigated or false_p or not active:
            label = "Mitigated" if is_mitigated else ("False Positive" if false_p else "Inactive")
            return "CLOSED", label
        return "FIXING", "Active"

    return None, None


def _url(base_url: str, path: str, query: str = "") -> str:
    """Join a path onto the subscription's base URL, host preserved.

    Built by parts rather than by ``urljoin`` so a ticket key that starts with
    ``/`` or contains ``..`` cannot walk the request onto another path or host.
    """
    parts = urlsplit(base_url)
    if not parts.scheme or not parts.netloc:
        raise TicketSpecError(f"ticket base URL is not absolute: {base_url!r}")
    root = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, f"{root}/{path.lstrip('/')}", query, ""))


def _decode(result: DeliveryResult) -> dict[str, Any]:
    if not result.body:
        return {}
    try:
        parsed = json.loads(result.body)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def fetch_ticket_status(
    *,
    transport: str,
    base_url: str,
    ticket_key: str,
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: int = 10,
    allow_private: bool = False,
    request_fn=request,
) -> tuple[str | None, str | None, dict[str, Any]]:
    """Read one ticket. Returns ``(suggested_state, raw_status, raw_payload)``.

    A tracker we cannot reach, or one that answers 4xx/5xx, yields
    ``(None, None, {"error": ...})``: an unreadable ticket must never be read
    as "the work is done".
    """
    t = validate_transport(transport)
    headers = request_headers(t, secret=secret, extra_headers=extra_headers)
    key = quote(str(ticket_key), safe="")

    if t == "jira":
        url = _url(base_url, f"rest/api/2/issue/{key}")
    elif t == "servicenow":
        url = _url(base_url, "api/now/table/incident", f"sysparm_query=number={key}&sysparm_limit=1")
    elif t == "defectdojo":
        url = _url(base_url, f"api/v2/findings/{key}/")
    else:
        raise TicketSpecError(f"unsupported ticket transport: {transport}")

    result = request_fn(
        "GET",
        url,
        b"",
        headers,
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
        capture_body=True,
    )
    if not result.ok:
        logger.warning(
            "Ticket fetch failed for %s (%s): %s", ticket_key, t, result.error
        )
        return None, None, {"error": result.error, "status_code": result.status_code}

    data = _decode(result)
    suggested, raw = map_remote_status_to_vuln_state(t, data)
    return suggested, raw, data


def _servicenow_sys_id(
    *,
    base_url: str,
    ticket_key: str,
    headers: dict[str, str],
    timeout_seconds: int,
    allow_private: bool,
    request_fn,
) -> str | None:
    """Resolve an incident number to its ``sys_id``.

    The Table API updates by ``sys_id`` in the path; a PATCH against the
    collection URL with a ``sysparm_query`` updates nothing.
    """
    url = _url(
        base_url,
        "api/now/table/incident",
        f"sysparm_query=number={quote(str(ticket_key), safe='')}"
        "&sysparm_fields=sys_id&sysparm_limit=1",
    )
    result = request_fn(
        "GET",
        url,
        b"",
        headers,
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
        capture_body=True,
    )
    if not result.ok:
        return None
    payload = _decode(result).get("result")
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    if isinstance(payload, dict):
        return str(payload.get("sys_id") or "") or None
    return None


def push_status_update(
    *,
    transport: str,
    base_url: str,
    ticket_key: str,
    to_state: str,
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: int = 10,
    allow_private: bool = False,
    request_fn=request,
) -> bool:
    """Reflect a local lifecycle change onto the ticket. Best effort."""
    t = validate_transport(transport)
    headers = request_headers(t, secret=secret, extra_headers=extra_headers)
    key = quote(str(ticket_key), safe="")
    closed = to_state == "CLOSED"

    if t == "defectdojo":
        body = json.dumps({"active": not closed, "is_mitigated": closed}).encode("utf-8")
        result = request_fn(
            "PATCH",
            _url(base_url, f"api/v2/findings/{key}/"),
            body,
            headers,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
        )
        return result.ok

    if t == "servicenow":
        sys_id = _servicenow_sys_id(
            base_url=base_url,
            ticket_key=ticket_key,
            headers=headers,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            request_fn=request_fn,
        )
        if not sys_id:
            logger.warning("ServiceNow incident %s has no resolvable sys_id", ticket_key)
            return False
        target_state = "6" if closed else "2"
        body = json.dumps({"incident_state": target_state, "state": target_state}).encode("utf-8")
        result = request_fn(
            "PATCH",
            _url(base_url, f"api/now/table/incident/{quote(sys_id, safe='')}"),
            body,
            headers,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
        )
        return result.ok

    if t == "jira":
        # Jira moves an issue by transition id, and which ids exist depends on
        # the project's workflow, so the available set is read first.
        trans_url = _url(base_url, f"rest/api/2/issue/{key}/transitions")
        listing = request_fn(
            "GET",
            trans_url,
            b"",
            headers,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
            capture_body=True,
        )
        if not listing.ok:
            return False
        target_name = "Done" if closed else "In Progress"
        matching_id = None
        for entry in _decode(listing).get("transitions", []) or []:
            if isinstance(entry, dict) and str(entry.get("name", "")).lower() == target_name.lower():
                matching_id = entry.get("id")
                break
        if not matching_id:
            logger.info(
                "Jira issue %s has no '%s' transition available", ticket_key, target_name
            )
            return False
        body = json.dumps({"transition": {"id": matching_id}}).encode("utf-8")
        result = request_fn(
            "POST",
            trans_url,
            body,
            headers,
            timeout_seconds=timeout_seconds,
            allow_private=allow_private,
        )
        return result.ok

    return False
