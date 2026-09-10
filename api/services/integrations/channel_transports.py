"""The wire half of per-tenant notification channels (#351).

Everything here is stateless and database-free, so the adapters can be tested
without Postgres and the queue-free state in ``channels.py`` can be tested
without a network — the same split ``delivery.py`` / ``webhooks.py`` already
uses next door.

Five kinds, three shapes of wire:

* ``slack`` / ``msteams`` / ``mattermost`` — one JSON POST to an incoming
  webhook URL, through :func:`api.services.integrations.delivery.post`, so a
  chat URL gets the same SSRF validation, pinned DNS and no-redirect rules an
  event webhook does. The URL is the credential; nothing is signed, because
  none of those receivers would verify a signature.
* ``defectdojo`` — the *bulk* Generic Findings Import, i.e. the multipart
  ``/api/v2/reimport-scan/`` upload the scanner stage used to do with
  installation-wide credentials. The document and the encoder are imported
  from ``scanner/pipeline/defectdojo.py`` rather than rewritten: two mappings
  onto one API is how the two drift apart.
* ``email`` — ``smtplib`` against the installation's report relay
  (``OCTO_REPORT_SMTP_*``), with the tenant's recipient list. The relay is
  infrastructure, like Postgres; the recipient list is the part that used to
  cross tenants (``OCTO_SMTP_TO``).

HONESTY: there is no retry ladder here. A run summary is only interesting
while it is fresh, so a failure is reported to the caller — which records it on
the channel row and in the job log — rather than replayed for a quarter of an
hour into a channel that has moved on. The DefectDojo import is the one that
would benefit from a queue, and that is named as a limitation in
docs/configuration.md rather than pretended away.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from api.services import egress
from api.services.integrations.delivery import post, validate_url
from api.settings import Settings
from scanner.pipeline.defectdojo import (
    SCAN_TYPE,
    encode_multipart,
    map_vulnerabilities_to_generic_findings,
)
from scanner.pipeline.report import SEVERITY_ORDER

LOG = logging.getLogger("shapoclyack.channels")

KINDS = ("slack", "msteams", "mattermost", "email", "defectdojo")
#: Kinds delivered as a JSON POST to an incoming-webhook URL held in ``secret``.
CHAT_KINDS = ("slack", "msteams", "mattermost")

#: DefectDojo's own severity words, keyed by ours. Same table as the scanner
#: stage's, reached through the mapping helper for the document itself; this
#: copy is only for the ``minimum_severity`` form field.
_DD_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "unknown": "Info",
}

#: Recipients per email channel. A run summary is an operations notification,
#: not a mailing list, and an unbounded list is one PATCH away from using this
#: platform's relay to send somebody else's mail.
MAX_EMAIL_RECIPIENTS = 20

_USER_AGENT = "Shapoclyack-Notify/1"


class ChannelSpecError(ValueError):
    """The channel is missing a knob its adapter needs. Not retryable."""


@dataclass(frozen=True)
class SendOutcome:
    """What happened to one channel. ``status`` is what the row records.

    ``skipped`` is not a failure: an email channel on an installation with no
    relay configured has nothing wrong with *it*, and reporting that as an
    error would have an operator looking at the channel instead of at
    ``OCTO_REPORT_SMTP_HOST``.
    """

    ok: bool
    status: str
    detail: str | None = None


def validate_kind(value: str | None) -> str:
    kind = (value or "").strip().lower()
    if kind not in KINDS:
        raise ValueError(f"unknown channel kind {value!r}; expected one of {', '.join(KINDS)}")
    return kind


def validate_min_severity(value: str | None) -> str:
    """The floor this channel cares about. Empty means the default, not "all".

    A channel created without a floor gets ``high``, which is what the
    installation-wide alert config defaulted to — an upgrade must not turn a
    quiet Slack channel into every ``low`` on every host.
    """
    severity = (value or "").strip().lower() or "high"
    if severity not in SEVERITY_ORDER:
        raise ValueError(
            f"unknown severity {value!r}; expected one of {', '.join(SEVERITY_ORDER)}"
        )
    return severity


def _email_recipients(raw: Any) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise ChannelSpecError("email config.to must be a non-empty list of addresses")
    cleaned: list[str] = []
    for item in raw:
        address = str(item).strip()
        # Not a full RFC 5322 parse: the relay is the authority on an address.
        # What is checked is what would let one recipient become several — a
        # comma or a newline in a header value is header injection, not an
        # address.
        if "@" not in address or any(char in address for char in (",", "\r", "\n", ";")):
            raise ChannelSpecError(f"not an email address: {item!r}")
        if address not in cleaned:
            cleaned.append(address)
    if len(cleaned) > MAX_EMAIL_RECIPIENTS:
        raise ChannelSpecError(
            f"{len(cleaned)} recipients, limit {MAX_EMAIL_RECIPIENTS}"
        )
    return cleaned


def validate_config(kind: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    """The adapter knobs, normalised. Credentials are never in here.

    The return value replaces what the caller passed rather than being merged
    into it, so an unknown key is dropped instead of stored: ``config`` is read
    by the adapters, and a key one of them will silently ignore is a knob an
    operator believes they have set.
    """
    cfg = dict(raw or {})
    if kind in CHAT_KINDS:
        if kind == "mattermost":
            # The incoming webhook has a default channel; an override is a
            # Mattermost feature and is not a credential.
            channel = str(cfg.get("channel") or "").strip()
            return {"channel": channel} if channel else {}
        return {}
    if kind == "email":
        return {"to": _email_recipients(cfg.get("to"))}
    if kind == "defectdojo":
        product = str(cfg.get("product_name") or "").strip()
        if not product:
            # The knob that makes this per-tenant at the far end. Without it
            # two tenants' channels would import into whatever DefectDojo
            # auto-creates, which is the defect #351 is about, moved one hop.
            raise ChannelSpecError("defectdojo config.product_name is required")
        return {
            "product_name": product,
            "product_type_name": str(cfg.get("product_type_name") or "Shapoclyack").strip()
            or "Shapoclyack",
            "engagement_name": str(cfg.get("engagement_name") or "Shapoclyack").strip()
            or "Shapoclyack",
            "test_title": str(cfg.get("test_title") or "Shapoclyack scan").strip()
            or "Shapoclyack scan",
            "close_old_findings": bool(cfg.get("close_old_findings", False)),
        }
    return {}


def validate_endpoint(kind: str, value: str | None, *, allow_private: bool) -> str | None:
    """The instance URL, for the one kind that has a non-secret one.

    Refused for the others rather than ignored: a Slack channel with an
    ``endpoint`` set is an operator who has put the webhook URL in the column
    that is *not* encrypted, and answering 422 is how they find out now instead
    of from a database dump later.
    """
    url = (value or "").strip()
    if kind == "defectdojo":
        if not url:
            raise ChannelSpecError("defectdojo channel needs the instance URL in endpoint")
        return validate_url(url, allow_private=allow_private)
    if url:
        raise ChannelSpecError(
            f"{kind} channel has no endpoint; "
            + (
                "the incoming-webhook URL goes in secret, where it is encrypted"
                if kind in CHAT_KINDS
                else "recipients go in config.to"
            )
        )
    return None


def validate_secret(kind: str, value: str | None, *, allow_private: bool) -> str | None:
    """The credential, checked for the shape its adapter needs.

    For a chat kind that means validating it as a URL here, at write time, and
    again at send time — the same two-step ``delivery.validate_url`` does,
    because a hostname that resolved publicly when the channel was created can
    resolve to link-local by the time a scan finishes.
    """
    secret = (value or "").strip()
    if kind in CHAT_KINDS:
        if not secret:
            raise ChannelSpecError(f"{kind} channel needs the incoming-webhook URL as its secret")
        return validate_url(secret, allow_private=allow_private)
    if kind == "defectdojo":
        if not secret:
            raise ChannelSpecError("defectdojo channel needs the API token as its secret")
        return secret
    if secret:
        raise ChannelSpecError(
            "email channels carry no credential: the relay is configured "
            "installation-wide with OCTO_REPORT_SMTP_*"
        )
    return None


# --------------------------------------------------------------------------
# Chat
# --------------------------------------------------------------------------


def chat_body(kind: str, text: str, config: dict[str, Any] | None = None) -> bytes:
    """The native JSON one chat receiver expects.

    Teams connectors reject a bare ``{"text": …}`` unless it is wrapped in a
    MessageCard, and the ``summary`` field is what the notification list shows
    — without it the card renders as an empty row.
    """
    if kind == "msteams":
        payload: dict[str, Any] = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Shapoclyack scan complete",
            "text": text,
        }
    elif kind == "mattermost":
        payload = {"text": text}
        channel = str((config or {}).get("channel") or "").strip()
        if channel:
            payload["channel"] = channel
    elif kind == "slack":
        payload = {"text": text}
    else:
        raise ChannelSpecError(f"not a chat channel kind: {kind}")
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def send_chat(
    kind: str,
    *,
    webhook_url: str,
    text: str,
    config: dict[str, Any] | None = None,
    timeout_seconds: int,
    allow_private: bool,
    post_fn=post,
) -> SendOutcome:
    """One POST to a Slack / Teams / Mattermost incoming webhook."""
    try:
        body = chat_body(kind, text, config)
    except ChannelSpecError as exc:
        return SendOutcome(ok=False, status="error", detail=str(exc))
    result = post_fn(
        webhook_url,
        body,
        {"Content-Type": "application/json", "User-Agent": _USER_AGENT},
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
    )
    if result.ok:
        return SendOutcome(ok=True, status="ok")
    # The URL is the credential, so it must not end up in ``last_status`` —
    # ``delivery`` puts the status code and a bounded body excerpt in ``error``
    # and never the request URL, which is why this passes it through as-is.
    return SendOutcome(ok=False, status="error", detail=result.error or "send failed")


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------


def _tls_context(settings: Settings) -> ssl.SSLContext:
    """The STARTTLS context for the report relay.

    Same context, and the same reasoning, as ``reports/delivery.py``:
    ``smtp.starttls()`` with no context verifies neither chain nor hostname, so
    the default here verifies both and ``OCTO_REPORT_SMTP_VERIFY_TLS=false`` is
    the operator's own downgrade.
    """
    context = egress.ssl_context()
    if not settings.report_smtp_verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def send_email(
    settings: Settings,
    *,
    recipients: list[str],
    subject: str,
    text: str,
    timeout_seconds: int | None = None,
) -> SendOutcome:
    """Mail one run summary to a tenant's recipients through the shared relay.

    One message with the tenant's recipients in ``To``, not one per address:
    they are an operations channel for a single tenant, so they already see
    each other's addresses on every alert.

    ``timeout_seconds`` is the channel budget
    (``OCTO_NOTIFICATION_CHANNEL_TIMEOUT_SECONDS``), which is what
    docs/configuration.md advertises as *the* per-send knob. Without it this
    transport was the one exception, quietly answering to
    ``OCTO_REPORT_SMTP_TIMEOUT_SECONDS`` instead, so an operator with a slow
    relay raised the documented knob and nothing changed. ``None`` keeps the
    relay default, for the report factory's own callers.
    """
    if not settings.report_smtp_host or not settings.report_smtp_from:
        return SendOutcome(
            ok=False,
            status="skipped",
            detail="email channels need OCTO_REPORT_SMTP_HOST and OCTO_REPORT_SMTP_FROM",
        )
    if not recipients:
        return SendOutcome(ok=False, status="error", detail="no recipients configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.report_smtp_from
    message["To"] = ", ".join(recipients)
    message.set_content(text)

    try:
        with smtplib.SMTP(
            settings.report_smtp_host,
            settings.report_smtp_port,
            timeout=(
                timeout_seconds
                if timeout_seconds is not None
                else settings.report_smtp_timeout_seconds
            ),
        ) as smtp:
            if settings.report_smtp_starttls:
                smtp.starttls(context=_tls_context(settings))
            if settings.report_smtp_username and settings.report_smtp_password:
                smtp.login(settings.report_smtp_username, settings.report_smtp_password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        return SendOutcome(ok=False, status="error", detail=f"{type(exc).__name__}: {exc}"[:200])
    return SendOutcome(ok=True, status="ok")


# --------------------------------------------------------------------------
# DefectDojo (bulk import)
# --------------------------------------------------------------------------


def defectdojo_document(
    vulnerabilities: list[dict[str, Any]],
    *,
    run_id: str,
    min_severity: str,
    script_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The Generic Findings Import document, built by the scanner's mapper."""
    return map_vulnerabilities_to_generic_findings(
        vulnerabilities,
        run_id=run_id,
        min_severity=min_severity,
        include_without_cve=True,
        script_findings=script_findings or [],
    )


def send_defectdojo(
    *,
    endpoint: str,
    token: str,
    run_id: str,
    document: dict[str, Any],
    config: dict[str, Any],
    min_severity: str,
    timeout_seconds: int,
    allow_private: bool,
    post_fn=post,
) -> SendOutcome:
    """Upload one run's findings into *this tenant's* DefectDojo product.

    ``auto_create_context`` is always on and ``product_name`` is required, so
    tenant A's findings can only ever land in the product tenant A's channel
    names — the separation the installation-wide ``OCTO_DEFECTDOJO_*`` could
    not express.

    Unlike the scanner stage this never disables certificate verification:
    ``delivery.post`` uses the shared egress context, and a self-signed
    DefectDojo names its CA in ``OCTO_CA_BUNDLE``. A per-tenant knob that
    turned verification off would be a tenant admin downgrading the platform's
    egress.
    """
    fields = {
        "scan_type": SCAN_TYPE,
        "minimum_severity": _DD_SEVERITY.get(min_severity, "Info"),
        "active": "true",
        "verified": "false",
        "close_old_findings": "true" if config.get("close_old_findings") else "false",
        "auto_create_context": "true",
        "product_name": str(config.get("product_name") or ""),
        "product_type_name": str(config.get("product_type_name") or "Shapoclyack"),
        "engagement_name": str(config.get("engagement_name") or "Shapoclyack"),
        "test_title": str(config.get("test_title") or "Shapoclyack scan"),
    }
    body, content_type = encode_multipart(
        fields,
        {
            "file": (
                f"shapoclyack-{run_id}.json",
                json.dumps(document, indent=2).encode("utf-8"),
                "application/json",
            )
        },
    )
    result = post_fn(
        endpoint.rstrip("/") + "/api/v2/reimport-scan/",
        body,
        {
            "Authorization": f"Token {token}",
            "Content-Type": content_type,
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        },
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
    )
    if result.ok:
        return SendOutcome(ok=True, status="ok", detail=f"{len(document.get('findings') or [])} findings")
    return SendOutcome(ok=False, status="error", detail=result.error or "import failed")
