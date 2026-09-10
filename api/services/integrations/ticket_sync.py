"""Two-way ticket status synchronisation for Jira, ServiceNow and DefectDojo (#183).

Inbound: poll the tracker and reconcile the finding's lifecycle state. On a
cadence, by ``ticket_sync_worker.py`` (#347), and on demand from
``POST /api/vulnerabilities/{id}/ticket/sync``.
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

from api.services import vuln_states
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
        # An active DefectDojo finding used to suggest FIXING. It does not mean
        # that: ``active`` is the absence of a mitigation, and it is the state
        # every finding is created in — it says nothing about whether anybody
        # has started. Suggesting FIXING from it was harmless while the sync
        # was a button somebody pressed once; on a cadence (#347) it dragged
        # every OPEN, ACKNOWLEDGED and PLANNED finding on a DefectDojo
        # subscription into FIXING within one interval, and back again after
        # any operator moved it, because all three of those moves are legal.
        # DefectDojo can honestly assert one thing about lifecycle — that the
        # work is done — so that is the only thing read from it.
        return None, "Active"

    return None, None


# --------------------------------------------------------------------------
# Outbound: lifecycle state -> the tracker's own idea of that state (#347)
# --------------------------------------------------------------------------
#
# This used to be a boolean — ``CLOSED`` meant "Done" / state 6 / is_mitigated
# and every other state meant "In Progress" / state 2 / active. So a finding an
# operator had only *acknowledged* arrived in the tracker as work already under
# way, and moving one from FIXING back to PLANNED (which is what a stalled fix
# looks like) changed nothing the assignee could see. The maps below say what
# each lifecycle state actually is on each tracker.
#
# Two rules shaped them, and both are about not fighting the inbound map in
# ``JIRA_STATUS_MAP`` / ``SNOW_STATE_MAP``:
#
# - **Round-trip stability.** What we push has to read back either as the state
#   the finding is already in, or as one it cannot legally move to. Otherwise
#   the next poll drags the finding somewhere nobody asked for, we push that,
#   and the pair oscillates on every tick. ACKNOWLEDGED is therefore not "In
#   Progress": that reads back as FIXING, and FIXING is a legal move from
#   ACKNOWLEDGED.
# - **Only states the tracker can hold.** VERIFYING is absent from the
#   ServiceNow and DefectDojo maps — neither has a "we are re-scanning" state,
#   and a finding moving FIXING → VERIFYING leaves the incident exactly where
#   it already was. Pushing nothing is the honest answer there.

#: Jira transition *names*, in preference order. Names rather than ids because
#: the ids are per-workflow: the issue's available set is read first and the
#: first match wins. ``OPEN`` is the reopen, and it is the case that used to be
#: a silent no-op — the only name tried for a non-closed target was "In
#: Progress", which a Done issue does not offer.
JIRA_TRANSITIONS: dict[str, tuple[str, ...]] = {
    vuln_states.OPEN: ("Reopen", "Reopen Issue", "Back to Open", "Open"),
    vuln_states.ACKNOWLEDGED: ("Triage", "Acknowledge"),
    vuln_states.PLANNED: ("Selected for Development", "Planned", "Backlog", "To Do"),
    vuln_states.FIXING: ("In Progress", "Start Progress"),
    # VERIFYING is absent here too, and for the round-trip reason rather than
    # for lack of a name: "In Review" and "In Progress" both read back as
    # FIXING, and VERIFYING → FIXING is legal, so pushing either would pull a
    # finding out of a verification scan it is still waiting on. No Jira status
    # maps to VERIFYING by design (only a scan can assert it), so there is
    # nothing to push that survives being read back.
    vuln_states.CLOSED: (
        "Done",
        "Resolve Issue",
        "Resolved",
        "Close Issue",
        "Closed",
        "Complete",
    ),
}

#: ServiceNow ``incident_state``: the inverse of :data:`SNOW_STATE_MAP` wherever
#: one exists (1 New, 2 In Progress, 3 On Hold, 6 Resolved).
SNOW_PUSH_STATE: dict[str, str] = {
    vuln_states.OPEN: "1",
    vuln_states.ACKNOWLEDGED: "1",
    vuln_states.PLANNED: "3",
    vuln_states.FIXING: "2",
    vuln_states.CLOSED: "6",
}

#: DefectDojo has no workflow, only flags: a finding is mitigated or it is not.
#: So the map is genuinely binary here — that is the tracker's vocabulary, not
#: a shortcut — and every not-closed state pushes the same pair. ``verified`` is
#: deliberately left alone: it is the tracker's own triage verdict, and
#: overwriting it from our lifecycle would erase a decision somebody made over
#: there. VERIFYING is absent for the same reason as in the ServiceNow map.
DEFECTDOJO_PUSH_FLAGS: dict[str, dict[str, bool]] = {
    vuln_states.OPEN: {"active": True, "is_mitigated": False},
    vuln_states.ACKNOWLEDGED: {"active": True, "is_mitigated": False},
    vuln_states.PLANNED: {"active": True, "is_mitigated": False},
    vuln_states.FIXING: {"active": True, "is_mitigated": False},
    vuln_states.CLOSED: {"active": False, "is_mitigated": True},
}


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
    auth_mode: str | None = None,
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
    headers = request_headers(t, secret=secret, extra_headers=extra_headers, auth_mode=auth_mode)
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
        # ``retryable`` is the delivery layer's own classification (5xx and
        # timeouts yes, 4xx no). The sync worker backs a whole subscription off
        # on it: a tracker that is down should not be asked once per linked
        # finding, while a single 404 ticket key should not silence the rest.
        return None, None, {
            "error": result.error,
            "status_code": result.status_code,
            "retryable": bool(result.retryable),
        }

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
    auth_mode: str | None = None,
    timeout_seconds: int = 10,
    allow_private: bool = False,
    request_fn=request,
) -> bool:
    """Reflect a local lifecycle change onto the ticket. Best effort.

    ``False`` means the ticket was not moved — the tracker refused, the
    workflow has no step for this state, or the tracker has no equivalent for
    it at all (see the maps above). The caller treats the whole reflection as
    best effort: a foreign tracker never fails a local transition.
    """
    t = validate_transport(transport)
    headers = request_headers(t, secret=secret, extra_headers=extra_headers, auth_mode=auth_mode)
    key = quote(str(ticket_key), safe="")

    if t == "defectdojo":
        flags = DEFECTDOJO_PUSH_FLAGS.get(to_state)
        if flags is None:
            logger.info(
                "DefectDojo has no equivalent of %s; finding %s left as it is",
                to_state,
                ticket_key,
            )
            return False
        body = json.dumps(flags, separators=(",", ":"), sort_keys=True).encode("utf-8")
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
        target_state = SNOW_PUSH_STATE.get(to_state)
        if target_state is None:
            logger.info(
                "ServiceNow has no incident_state for %s; incident %s left as it is",
                to_state,
                ticket_key,
            )
            return False
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
        candidates = JIRA_TRANSITIONS.get(to_state, ())
        if not candidates:
            logger.info("No Jira transition is mapped for %s; %s left as it is", to_state, ticket_key)
            return False
        available = {
            str(entry.get("name", "")).strip().lower(): entry.get("id")
            for entry in _decode(listing).get("transitions", []) or []
            if isinstance(entry, dict) and entry.get("id")
        }
        matching_id = next(
            (available[name.lower()] for name in candidates if name.lower() in available), None
        )
        if not matching_id:
            # Not a warning: a workflow legitimately need not offer a step for
            # every state of *our* lifecycle. It is logged with what was tried
            # so an operator can see which name to add, which the old single
            # hard-coded name made impossible to work out.
            logger.info(
                "Jira issue %s offers none of %s for %s (available: %s)",
                ticket_key,
                ", ".join(candidates),
                to_state,
                ", ".join(sorted(available)) or "none",
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
