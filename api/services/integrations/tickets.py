"""Ticket-creation transports over the 10.3 delivery queue (ROADMAP P2).

Jira, ServiceNow, DefectDojo, GitHub Issues and GitLab Issues are not a second queue: a subscription with
``transport`` other than ``webhook`` still enqueues a ``webhook_deliveries``
row, still retries 5xx/timeouts, still dead-letters a 4xx. What changes is
the POST — HMAC-signed event JSON would be rejected by those APIs, so this
module builds the native create-issue body and reads the issue key back.

SAFETY: the wire still goes through ``delivery.post`` (SSRF, no redirects,
pinned DNS). Credentials live in ``secret`` / ``Authorization``, never in
``transport_config``.

HONESTY: a created ticket records that we *asked* the tracker to open work
for this event. It is not confirmation the CVE is exploitable. The ticket's
status is reconciled back onto the finding, but by ``ticket_sync.py`` (#183)
polling the tracker — not by this module, which only opens the ticket.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from api.services.integrations import ticket_mapping
from api.services.integrations.delivery import DeliveryResult, post

TRANSPORTS = ("webhook", "jira", "servicenow", "defectdojo", "github", "gitlab")
TICKET_TRANSPORTS = ("jira", "servicenow", "defectdojo", "github", "gitlab")

#: How ``secret`` is presented to the tracker (#347). Which one a tracker wants
#: is a deployment fact, not something we can infer from the transport name:
#: Jira Data Center takes a personal access token as ``Bearer``, while Jira
#: Cloud only accepts ``Basic base64(email:api_token)`` and answers 401 to a
#: bearer token. Before this knob, a Cloud tenant had to hand-write the whole
#: ``Authorization`` header into ``headers``, which put a credential in the
#: column meant for gateway tokens and made the tracker unreachable for
#: anyone who did not know to do it.
AUTH_MODES = ("bearer", "basic", "token")

#: The mode used when ``transport_config.auth_mode`` is unset — the behaviour
#: every subscription created before #347 already has.
DEFAULT_AUTH_MODES = {
    "jira": "bearer",
    "servicenow": "bearer",
    "defectdojo": "token",
    "github": "bearer",
    "gitlab": "bearer",
}

_GITHUB_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_GITLAB_PROJECT = re.compile(r"^(\d{1,18}|[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){1,19})$")
_JIRA_PROJECT = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_USER_AGENT = "Shapoclyack-Ticket/1"

#: ``DeliveryResult.error`` of a successful delivery that deliberately made no
#: ticket (a ``severity_rules`` entry with ``create: false``). The queue stores
#: it in ``last_error`` and ``last_status``, and the dispatcher counts it as
#: ``skipped`` rather than ``delivered``; the row itself stays ``delivered`` so
#: nothing that reads delivery statuses has a fourth one to learn.
SKIPPED_PREFIX = "skipped:"


def is_skipped(result: DeliveryResult) -> bool:
    return bool(result.ok and result.error and result.error.startswith(SKIPPED_PREFIX))


class TicketSpecError(ValueError):
    """The subscription is missing a required adapter knob. Not retryable."""


def validate_transport(value: str | None) -> str:
    transport = (value or "webhook").strip().lower() or "webhook"
    if transport not in TRANSPORTS:
        raise ValueError(
            f"unknown transport {value!r}; expected one of {', '.join(TRANSPORTS)}"
        )
    return transport


def validate_auth_mode(transport: str, value: Any) -> str:
    """The ``auth_mode`` of a ticket transport, defaulted per tracker.

    Rejected rather than defaulted when it is set to something unknown: an
    operator who typed ``basic_auth`` wants a 422 on the subscription, not a
    tracker that keeps answering 401 for a reason nothing in the UI explains.
    """
    mode = str(value or "").strip().lower()
    if not mode:
        return DEFAULT_AUTH_MODES.get(transport, "bearer")
    if mode not in AUTH_MODES:
        raise TicketSpecError(
            f"{transport} transport_config.auth_mode must be one of {', '.join(AUTH_MODES)}"
        )
    return mode


def validate_sync_interval(transport: str, value: Any) -> int:
    """Per-subscription poll cadence for the inbound sync worker (#347).

    0 means "use the platform default" (``OCTO_TICKET_SYNC_INTERVAL_SECONDS``).
    Floored at 60s so a mistyped value cannot turn one tenant's tracker into a
    target: the worker polls one GET per linked finding, and a self-hosted Jira
    with a few thousand of them notices.
    """
    if value in (None, ""):
        return 0
    try:
        seconds = int(value)
    except (TypeError, ValueError) as exc:
        raise TicketSpecError(
            f"{transport} transport_config.sync_interval_seconds must be an integer"
        ) from exc
    if seconds == 0:
        return 0
    if seconds < 60:
        raise TicketSpecError(
            f"{transport} transport_config.sync_interval_seconds must be 0 or >= 60"
        )
    return seconds


def _target_validator(transport: str):
    """The check for a transport's routable target (project, repo, test id)."""

    def check(value: Any) -> Any:
        if transport == "jira":
            text = str(value or "").strip()
            if not _JIRA_PROJECT.match(text):
                raise TicketSpecError("jira transport_config.project_key is not a project key")
            return text
        if transport == "github":
            text = str(value or "").strip()
            if not _GITHUB_REPO.match(text) or ".." in text:
                raise TicketSpecError("github transport_config.repository must be 'owner/repo'")
            return text
        if transport == "gitlab":
            text = str(value or "").strip()
            if not _GITLAB_PROJECT.match(text) or ".." in text:
                raise TicketSpecError(
                    "gitlab transport_config.project must be a numeric id or 'group/project'"
                )
            return text
        if transport == "defectdojo":
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise TicketSpecError("defectdojo transport_config.test_id must be an integer") from exc
            if number < 1:
                raise TicketSpecError("defectdojo transport_config.test_id must be >= 1")
            return number
        raise TicketSpecError(f"{transport} has no routable target")

    return check


def validate_transport_config(transport: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    cfg = dict(raw or {})
    if transport == "webhook":
        return {}
    # Shared by every ticket transport: how the credential is presented, and
    # how often the inbound worker reads this tenant's tickets back.
    common = {
        "auth_mode": validate_auth_mode(transport, cfg.get("auth_mode")),
        "sync_interval_seconds": validate_sync_interval(
            transport, cfg.get("sync_interval_seconds")
        ),
    }
    check = _target_validator(transport) if transport != "servicenow" else None
    if transport == "jira":
        if not str(cfg.get("project_key") or "").strip():
            raise TicketSpecError("jira transport_config.project_key is required")
        issue_type = str(cfg.get("issue_type") or "Bug").strip() or "Bug"
        base = {"project_key": check(cfg.get("project_key")), "issue_type": issue_type}
    elif transport == "servicenow":
        table = str(cfg.get("table") or "incident").strip() or "incident"
        if "/" in table or "\\" in table or ".." in table:
            raise TicketSpecError("servicenow transport_config.table is not a table name")
        base = {"table": table}
    elif transport == "defectdojo":
        test_id = cfg.get("test_id")
        if test_id is None or str(test_id).strip() == "":
            raise TicketSpecError("defectdojo transport_config.test_id is required")
        base = {"test_id": check(test_id)}
    elif transport == "github":
        if not str(cfg.get("repository") or "").strip():
            raise TicketSpecError("github transport_config.repository is required")
        base = {"repository": check(cfg.get("repository"))}
    elif transport == "gitlab":
        if not str(cfg.get("project") or "").strip():
            raise TicketSpecError("gitlab transport_config.project is required")
        try:
            confidential = ticket_mapping.strict_bool("confidential", cfg.get("confidential"), False)
        except ticket_mapping.MappingError as exc:
            raise TicketSpecError(f"gitlab transport_config.{exc}") from exc
        base = {"project": check(cfg.get("project")), "confidential": confidential}
    else:
        return {}
    try:
        mapping = ticket_mapping.validate_mapping(transport, cfg, check)
    except ticket_mapping.MappingError as exc:
        raise TicketSpecError(f"{transport} transport_config.{exc}") from exc
    return {**base, **mapping, **common}


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
    if transport == "github":
        # Both halves were validated as path-safe; quoting is belt and braces.
        return urljoin(root, f"repos/{quote(str(config['repository']), safe='/')}/issues")
    if transport == "gitlab":
        return urljoin(root, f"api/v4/projects/{quote(str(config['project']), safe='')}/issues")
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


def _description(envelope: dict[str, Any], esc=lambda text: text) -> str:
    kind = esc(str(envelope.get("kind") or ""))
    host = esc(str(envelope.get("host")))
    port = esc(str(envelope.get("port")))
    run_id = esc(str(envelope.get("run_id")))
    data = _data(envelope)
    lines = [
        f"Shapoclyack event: {kind}",
        f"Host: {host}",
        f"Port: {port}",
        f"Run: {run_id}",
    ]
    for key in ("cve", "severity", "cvss", "script_id"):
        if data.get(key) not in (None, ""):
            lines.append(f"{key}: {esc(str(data.get(key)))}")
    lines.append(
        "This ticket was opened from an asset-change event. It is not "
        "confirmation that the finding is exploitable."
    )
    return "\n".join(str(item) for item in lines)


def _severity(envelope: dict[str, Any]) -> str:
    return str(_data(envelope).get("severity") or "unknown").lower()


def _texts(
    transport: str,
    envelope: dict[str, Any],
    config: dict[str, Any],
    asset: dict[str, Any] | None,
) -> tuple[str, str, dict[str, str]]:
    """Summary, description and the single-line context for custom fields.

    The summary and custom fields get newline-free values; the description
    keeps line breaks. GitHub / GitLab bodies are Markdown, so scan-derived
    values are escaped there.
    """
    markdown = transport in ("github", "gitlab")
    line_ctx = ticket_mapping.build_context(envelope, asset, single_line=True)
    body_ctx = ticket_mapping.build_context(envelope, asset, markdown=markdown, single_line=markdown)
    summary_t = config.get("summary_template")
    description_t = config.get("description_template")
    summary = ticket_mapping.render(summary_t, line_ctx) if summary_t else _summary(envelope)
    summary = " ".join(summary.split())
    if description_t:
        description = ticket_mapping.render(description_t, body_ctx)
    else:
        description = _description(envelope, ticket_mapping.markdown_escape if markdown else lambda t: t)
    return summary, description, line_ctx


def plan(
    transport: str,
    payload: dict[str, Any],
    config: dict[str, Any],
    asset: dict[str, Any] | None = None,
) -> ticket_mapping.Resolution:
    """What the mapping decides for this event: skip, or where it goes."""
    envelope = _envelope(payload)
    res = ticket_mapping.resolve(config, _severity(envelope), asset)
    if not res.create and envelope.get("kind") == "test":
        # The Test button exists to prove the tracker is reachable with this
        # credential. A rule on ``unknown`` severity must not turn it into a
        # success that never contacted the tracker.
        return ticket_mapping.resolve({**config, "severity_rules": {}}, "unknown", asset)
    return res


def with_target(transport: str, config: dict[str, Any], target: Any) -> dict[str, Any]:
    """``config`` with the routed target substituted for the base one."""
    if target is None:
        return config
    key = ticket_mapping.TARGET_KEYS.get(transport)
    return {**config, key: target} if key else config


def build_body(
    transport: str,
    payload: dict[str, Any],
    config: dict[str, Any],
    asset: dict[str, Any] | None = None,
    resolution: ticket_mapping.Resolution | None = None,
) -> bytes:
    envelope = _envelope(payload)
    res = resolution or plan(transport, payload, config, asset)
    config = with_target(transport, config, res.target)
    summary, description, context = _texts(transport, envelope, config, asset)
    if transport == "jira":
        fields: dict[str, Any] = {
            "project": {"key": config["project_key"]},
            "issuetype": {"name": config.get("issue_type") or "Bug"},
            "summary": summary[:255],
            "description": description,
        }
        if res.priority:
            fields["priority"] = {"name": res.priority}
        if res.labels:
            # Jira labels cannot hold whitespace.
            fields["labels"] = [re.sub(r"\s+", "_", label) for label in res.labels]
        if config.get("components"):
            fields["components"] = [{"name": name} for name in config["components"]]
        for key, value in (config.get("custom_fields") or {}).items():
            if isinstance(value, str):
                fields[key] = ticket_mapping.render(value, context)
            elif isinstance(value, list):
                fields[key] = [ticket_mapping.render(v, context) for v in value]
            else:
                fields[key] = value
        body: dict[str, Any] = {"fields": fields}
    elif transport == "servicenow":
        body = {
            "short_description": summary[:160],
            "description": description,
            "urgency": res.priority or ("1" if _severity(envelope) == "critical" else "2"),
        }
    elif transport == "defectdojo":
        sev = _severity(envelope).capitalize()
        if sev not in {"Critical", "High", "Medium", "Low", "Info"}:
            sev = "Info"
        body = {
            "test": config["test_id"],
            "title": summary[:255],
            "severity": sev,
            "description": description,
            "active": True,
            "verified": False,
            "numerical_severity": "S1" if sev == "Critical" else "S3",
        }
    elif transport == "github":
        body = {"title": summary[:256], "body": description}
        if res.labels:
            body["labels"] = res.labels
    elif transport == "gitlab":
        body = {"title": summary[:255], "description": description}
        if res.labels:
            body["labels"] = ",".join(label.replace(",", " ") for label in res.labels)
        if config.get("confidential"):
            body["confidential"] = True
    else:
        raise TicketSpecError(f"not a ticket transport: {transport}")
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def request_headers(
    transport: str,
    *,
    secret: str | None,
    extra_headers: dict[str, str] | None,
    auth_mode: str | None = None,
) -> dict[str, str]:
    """Auth for the foreign API. Never HMAC — those APIs would reject it.

    ``auth_mode`` comes from ``transport_config`` and defaults per tracker to
    what this function did before #347. An ``Authorization`` header the
    operator wrote by hand still wins: it is the escape hatch for a tracker
    behind a scheme none of the three modes covers.
    """
    headers = {str(k): str(v) for k, v in (extra_headers or {}).items()}
    headers["Content-Type"] = "application/json"
    headers["User-Agent"] = _USER_AGENT
    if transport == "github":
        headers.setdefault("Accept", "application/vnd.github+json")
        headers.setdefault("X-GitHub-Api-Version", "2022-11-28")
    has_auth = any(k.lower() == "authorization" for k in headers)
    token = (secret or "").strip()
    if token and not has_auth:
        headers["Authorization"] = authorization_value(
            validate_auth_mode(transport, auth_mode), token
        )
    return headers


def authorization_value(auth_mode: str, token: str) -> str:
    """The ``Authorization`` value for one already-validated mode."""
    if auth_mode == "basic":
        # Jira Cloud's credential is a pair, and the pair is what has to be
        # encoded. A lone token base64'd here would be sent as a username with
        # an empty password, which Jira answers 401 to — the same symptom as no
        # credential at all, which is why this is a refusal and not a guess.
        if ":" not in token:
            raise TicketSpecError(
                "auth_mode 'basic' needs the secret as 'user:token' "
                "(for Jira Cloud, 'email:api_token')"
            )
        return "Basic " + base64.b64encode(token.encode("utf-8")).decode("ascii")
    if auth_mode == "token":
        return f"Token {token}"
    return f"Bearer {token}"


def _http_url(value: Any) -> str | None:
    """A tracker-supplied link, kept only when it is an http(s) URL."""
    text = str(value or "").strip()
    return text if text.startswith(("https://", "http://")) else None


def parse_created(
    transport: str,
    base_url: str,
    body: str | None,
    config: dict[str, Any] | None = None,
) -> tuple[str | None, str | None]:
    """Return ``(ticket_key, ticket_url)`` from a successful create response.

    GitHub and GitLab numbers are only unique inside a repository, so their key
    is ``<repository>#<number>``: the status poll can then find the issue from
    the key alone, with no subscription config in hand.
    """
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
    if transport in ("github", "gitlab") and isinstance(parsed, dict):
        number = parsed.get("number") if transport == "github" else parsed.get("iid")
        target = (config or {}).get("repository" if transport == "github" else "project")
        if number is None or not target:
            return None, None
        link = _http_url(parsed.get("html_url" if transport == "github" else "web_url"))
        return f"{target}#{number}", link
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
    asset: dict[str, Any] | None = None,
) -> DeliveryResult:
    """One native create-issue POST. Same SSRF/retry classification as webhooks.

    ``asset`` is the business context of the event's host (``business_unit``,
    ``environment``, ``criticality``, ``owner``) when the caller looked it up;
    only ``target_rules`` and asset placeholders read it.
    """
    try:
        # Validated again on every delivery, strictly: a stored config that no
        # longer passes (a rule tightened in a later release) fails here as a
        # permanent TicketSpecError rather than being sent half-understood.
        cfg = validate_transport_config(transport, config)
        resolution = plan(transport, payload, cfg, asset)
        if not resolution.create:
            # A deliberate "no ticket for this severity" is a successful
            # delivery, not a failure to retry or dead-letter. No ticket key
            # comes back, so nothing is linked to the finding.
            return DeliveryResult(
                ok=True,
                status_code=None,
                error=f"{SKIPPED_PREFIX} {resolution.skip_reason}",
                retryable=False,
                body=None,
            )
        cfg = with_target(transport, cfg, resolution.target)
        url = endpoint_url(transport, base_url, cfg)
        # Re-validate the constructed path so a weird table name cannot
        # walk the subscription URL into a different host.
        if urlsplit(url).hostname != urlsplit(base_url).hostname:
            raise TicketSpecError("ticket endpoint host does not match the subscription URL")
        body = build_body(transport, payload, cfg, asset, resolution)
        headers = request_headers(
            transport,
            secret=secret,
            extra_headers=extra_headers,
            auth_mode=cfg.get("auth_mode"),
        )
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
    key, ticket_url = parse_created(transport, base_url, result.body, cfg)
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
