"""Ticket-creation transports over the 10.3 delivery queue (ROADMAP P2).

Jira, ServiceNow and DefectDojo are not a second queue: a subscription with
``transport`` other than ``webhook`` still enqueues a ``webhook_deliveries``
row, still retries 5xx/timeouts, still dead-letters a 4xx. What changes is
the POST — HMAC-signed event JSON would be rejected by those APIs, so this
module builds the native create-issue body and reads the issue key back.

SAFETY: the wire still goes through ``delivery.post`` (SSRF, no redirects,
pinned DNS). Credentials live in ``secret`` / ``Authorization``, never in
``transport_config``.

HONESTY: a created ticket records that we *asked* the tracker to open work
for this event. It is not confirmation the CVE is exploitable, and we do
not sync status back when the finding closes.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin, urlsplit

from api.services.integrations.delivery import DeliveryResult, post

TRANSPORTS = ("webhook", "jira", "servicenow", "defectdojo")
TICKET_TRANSPORTS = ("jira", "servicenow", "defectdojo")

_USER_AGENT = "Shapoclyack-Ticket/1"


class TicketSpecError(ValueError):
    """The subscription is missing a required adapter knob. Not retryable."""


def validate_transport(value: str | None) -> str:
    transport = (value or "webhook").strip().lower() or "webhook"
    if transport not in TRANSPORTS:
        raise ValueError(
            f"unknown transport {value!r}; expected one of {', '.join(TRANSPORTS)}"
        )
    return transport


def validate_transport_config(transport: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    cfg = dict(raw or {})
    if transport == "webhook":
        return {}
    if transport == "jira":
        project = str(cfg.get("project_key") or "").strip()
        if not project:
            raise TicketSpecError("jira transport_config.project_key is required")
        issue_type = str(cfg.get("issue_type") or "Bug").strip() or "Bug"
        return {"project_key": project, "issue_type": issue_type}
    if transport == "servicenow":
        table = str(cfg.get("table") or "incident").strip() or "incident"
        if "/" in table or "\\" in table or ".." in table:
            raise TicketSpecError("servicenow transport_config.table is not a table name")
        return {"table": table}
    if transport == "defectdojo":
        test_id = cfg.get("test_id")
        if test_id is None or str(test_id).strip() == "":
            raise TicketSpecError("defectdojo transport_config.test_id is required")
        try:
            test_id_int = int(test_id)
        except (TypeError, ValueError) as exc:
            raise TicketSpecError("defectdojo transport_config.test_id must be an integer") from exc
        if test_id_int < 1:
            raise TicketSpecError("defectdojo transport_config.test_id must be >= 1")
        return {"test_id": test_id_int}
    return {}


def endpoint_url(transport: str, base: str, config: dict[str, Any]) -> str:
    """Instance URL from the subscription plus the native create path."""
    root = base.rstrip("/") + "/"
    if transport == "jira":
        return urljoin(root, "rest/api/2/issue")
    if transport == "servicenow":
        table = str(config.get("table") or "incident")
        return urljoin(root, f"api/now/table/{table}")
    if transport == "defectdojo":
        return urljoin(root, "api/v2/findings/")
    return base


def _envelope(payload: dict[str, Any]) -> dict[str, Any]:
    event = payload.get("event")
    if isinstance(event, dict):
        return event
    return payload


def _data(envelope: dict[str, Any]) -> dict[str, Any]:
    data = envelope.get("data")
    return data if isinstance(data, dict) else {}


def _summary(envelope: dict[str, Any]) -> str:
    kind = str(envelope.get("kind") or "event")
    host = envelope.get("host") or _data(envelope).get("host") or "unknown-host"
    cve = _data(envelope).get("cve") or envelope.get("cve")
    port = envelope.get("port") or _data(envelope).get("port")
    if kind == "test":
        return f"[Shapoclyack test] {host}"
    if cve:
        where = f"{host}:{port}" if port not in (None, "") else str(host)
        return f"{cve} on {where}"
    return f"{kind} on {host}"


def _description(envelope: dict[str, Any]) -> str:
    kind = str(envelope.get("kind") or "")
    host = envelope.get("host")
    port = envelope.get("port")
    run_id = envelope.get("run_id")
    data = _data(envelope)
    lines = [
        f"Shapoclyack event: {kind}",
        f"Host: {host}",
        f"Port: {port}",
        f"Run: {run_id}",
    ]
    for key in ("cve", "severity", "cvss", "script_id"):
        if data.get(key) not in (None, ""):
            lines.append(f"{key}: {data.get(key)}")
    lines.append(
        "This ticket was opened from an asset-change event. It is not "
        "confirmation that the finding is exploitable."
    )
    return "\n".join(str(item) for item in lines)


def _severity(envelope: dict[str, Any]) -> str:
    return str(_data(envelope).get("severity") or "unknown").lower()


def build_body(transport: str, payload: dict[str, Any], config: dict[str, Any]) -> bytes:
    envelope = _envelope(payload)
    if transport == "jira":
        body = {
            "fields": {
                "project": {"key": config["project_key"]},
                "issuetype": {"name": config.get("issue_type") or "Bug"},
                "summary": _summary(envelope)[:255],
                "description": _description(envelope),
            }
        }
    elif transport == "servicenow":
        body = {
            "short_description": _summary(envelope)[:160],
            "description": _description(envelope),
            "urgency": "1" if _severity(envelope) == "critical" else "2",
        }
    elif transport == "defectdojo":
        sev = _severity(envelope).capitalize()
        if sev not in {"Critical", "High", "Medium", "Low", "Info"}:
            sev = "Info"
        body = {
            "test": config["test_id"],
            "title": _summary(envelope)[:255],
            "severity": sev,
            "description": _description(envelope),
            "active": True,
            "verified": False,
            "numerical_severity": "S1" if sev == "Critical" else "S3",
        }
    else:
        raise TicketSpecError(f"not a ticket transport: {transport}")
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def request_headers(
    transport: str,
    *,
    secret: str | None,
    extra_headers: dict[str, str] | None,
) -> dict[str, str]:
    """Auth for the foreign API. Never HMAC — those APIs would reject it."""
    headers = {str(k): str(v) for k, v in (extra_headers or {}).items()}
    headers["Content-Type"] = "application/json"
    headers["User-Agent"] = _USER_AGENT
    has_auth = any(k.lower() == "authorization" for k in headers)
    token = (secret or "").strip()
    if token and not has_auth:
        if transport == "defectdojo":
            headers["Authorization"] = f"Token {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_created(
    transport: str, base_url: str, body: str | None
) -> tuple[str | None, str | None]:
    """Return ``(ticket_key, ticket_url)`` from a successful create response."""
    if not body:
        return None, None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None, None
    root = base_url.rstrip("/")
    if transport == "jira":
        key = str(parsed.get("key") or "").strip() or None
        if not key:
            return None, None
        return key, f"{root}/browse/{key}"
    if transport == "servicenow":
        result = parsed.get("result") if isinstance(parsed.get("result"), dict) else parsed
        number = str(result.get("number") or "").strip() or None
        sys_id = str(result.get("sys_id") or "").strip()
        url = f"{root}/nav_to.do?uri=incident.do?sys_id={sys_id}" if sys_id else None
        return number, url
    if transport == "defectdojo":
        finding_id = parsed.get("id")
        if finding_id is None:
            return None, None
        key = str(finding_id)
        return key, f"{root}/finding/{key}"
    return None, None


def deliver(
    *,
    transport: str,
    base_url: str,
    payload: dict[str, Any],
    secret: str | None,
    extra_headers: dict[str, str] | None,
    config: dict[str, Any],
    timeout_seconds: int,
    allow_private: bool,
    post_fn=post,
) -> DeliveryResult:
    """One native create-issue POST. Same SSRF/retry classification as webhooks."""
    try:
        cfg = validate_transport_config(transport, config)
        url = endpoint_url(transport, base_url, cfg)
        # Re-validate the constructed path so a weird table name cannot
        # walk the subscription URL into a different host.
        if urlsplit(url).hostname != urlsplit(base_url).hostname:
            raise TicketSpecError("ticket endpoint host does not match the subscription URL")
        body = build_body(transport, payload, cfg)
        headers = request_headers(transport, secret=secret, extra_headers=extra_headers)
    except TicketSpecError as exc:
        return DeliveryResult(
            ok=False,
            status_code=None,
            error=str(exc),
            retryable=False,
        )
    result = post_fn(
        url,
        body,
        headers,
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
        capture_body=True,
    )
    if not result.ok:
        return result
    key, ticket_url = parse_created(transport, base_url, result.body)
    return DeliveryResult(
        ok=True,
        status_code=result.status_code,
        error=None,
        retryable=False,
        duration_seconds=result.duration_seconds,
        body=result.body,
        ticket_key=key,
        ticket_url=ticket_url,
    )
