"""Two-way ticket status synchronization for Jira, ServiceNow, and DefectDojo (Sprint 2).

Provides inbound polling/reconciliation and outbound status reflection over the
delivery/safe-http transport layer.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin

import httpx

from api.services.integrations.tickets import (
    _USER_AGENT,
    TicketSpecError,
    request_headers,
    validate_transport,
)

logger = logging.getLogger(__name__)

# Standard remote status mappings to Shapoclyack lifecycle states
JIRA_STATUS_MAP = {
    "done": "CLOSED",
    "closed": "CLOSED",
    "resolved": "CLOSED",
    "complete": "CLOSED",
    "in progress": "FIXING",
    "in review": "VERIFYING",
    "to do": "PLANNED",
    "open": "OPEN",
    "reopened": "OPEN",
}

# ServiceNow incident state standard values
SNOW_STATE_MAP = {
    "1": "OPEN",          # New
    "2": "FIXING",        # In Progress
    "3": "PLANNED",       # On Hold
    "6": "CLOSED",        # Resolved
    "7": "CLOSED",        # Closed
    "8": "CLOSED",        # Canceled
}


def map_remote_status_to_vuln_state(transport: str, remote_data: dict[str, Any]) -> tuple[str | None, str | None]:
    """Map foreign tracker response payload to (suggested_state, raw_remote_status)."""
    t = validate_transport(transport)
    if t == "jira":
        fields = remote_data.get("fields") if isinstance(remote_data.get("fields"), dict) else {}
        status_obj = fields.get("status") if isinstance(fields.get("status"), dict) else {}
        raw_status = str(status_obj.get("name") or "").strip()
        normalized = raw_status.lower()
        suggested = JIRA_STATUS_MAP.get(normalized)
        return suggested, raw_status

    if t == "servicenow":
        result = remote_data.get("result") if isinstance(remote_data.get("result"), dict) else remote_data
        if isinstance(result, list) and len(result) > 0:
            result = result[0]
        raw_state = str(result.get("incident_state") or result.get("state") or "").strip()
        suggested = SNOW_STATE_MAP.get(raw_state)
        display_status = str(result.get("state") or raw_state)
        return suggested, display_status

    if t == "defectdojo":
        active = bool(remote_data.get("active", True))
        is_mitigated = bool(remote_data.get("is_mitigated", False))
        false_p = bool(remote_data.get("false_p", False))

        if is_mitigated or false_p or not active:
            return "CLOSED", "Mitigated" if is_mitigated else ("False Positive" if false_p else "Inactive")
        return "FIXING", "Active"

    return None, None


def fetch_ticket_status(
    *,
    transport: str,
    base_url: str,
    ticket_key: str,
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: int = 10,
) -> tuple[str | None, str | None, dict[str, Any]]:
    """Fetch remote ticket details from foreign tracker.

    Returns (suggested_lifecycle_state, raw_remote_status, raw_response_dict).
    """
    t = validate_transport(transport)
    headers = request_headers(t, secret=secret, extra_headers=extra_headers)
    root = base_url.rstrip("/") + "/"

    if t == "jira":
        url = urljoin(root, f"rest/api/2/issue/{ticket_key}")
    elif t == "servicenow":
        url = urljoin(root, f"api/now/table/incident?sysparm_query=number={ticket_key}")
    elif t == "defectdojo":
        url = urljoin(root, f"api/v2/findings/{ticket_key}/")
    else:
        raise TicketSpecError(f"unsupported ticket transport: {transport}")

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code >= 400:
                logger.warning("Ticket fetch returned %s for %s (%s)", resp.status_code, ticket_key, t)
                return None, None, {"error": f"HTTP {resp.status_code}", "status_code": resp.status_code}
            data = resp.json()
            suggested, raw = map_remote_status_to_vuln_state(t, data)
            return suggested, raw, data
    except Exception as exc:
        logger.exception("Failed to fetch remote ticket %s (%s)", ticket_key, t)
        return None, None, {"error": str(exc)}


def push_status_update(
    *,
    transport: str,
    base_url: str,
    ticket_key: str,
    to_state: str,
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: int = 10,
) -> bool:
    """Push local vulnerability state change to foreign ticket tracker."""
    t = validate_transport(transport)
    headers = request_headers(t, secret=secret, extra_headers=extra_headers)
    root = base_url.rstrip("/") + "/"

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            if t == "defectdojo":
                url = urljoin(root, f"api/v2/findings/{ticket_key}/")
                patch_body = {
                    "active": to_state != "CLOSED",
                    "is_mitigated": to_state == "CLOSED",
                }
                resp = client.patch(url, headers=headers, json=patch_body)
                return resp.status_code < 400

            if t == "servicenow":
                url = urljoin(root, f"api/now/table/incident?sysparm_query=number={ticket_key}")
                target_state = "6" if to_state == "CLOSED" else "2"
                resp = client.patch(url, headers=headers, json={"incident_state": target_state, "state": target_state})
                return resp.status_code < 400

            if t == "jira":
                # Outbound transition via Jira Transitions API
                trans_url = urljoin(root, f"rest/api/2/issue/{ticket_key}/transitions")
                # First get available transitions
                get_trans = client.get(trans_url, headers=headers)
                if get_trans.status_code == 200:
                    trans_list = get_trans.json().get("transitions", [])
                    target_name = "Done" if to_state == "CLOSED" else "In Progress"
                    matching_id = None
                    for tr in trans_list:
                        if tr.get("name", "").lower() == target_name.lower():
                            matching_id = tr.get("id")
                            break
                    if matching_id:
                        post_resp = client.post(trans_url, headers=headers, json={"transition": {"id": matching_id}})
                        return post_resp.status_code < 400
                return False
    except Exception:
        logger.exception("Failed to push status update for ticket %s (%s)", ticket_key, t)
        return False
    return False
