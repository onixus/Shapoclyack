"""Sending a rendered report to its recipients (Sprint 4).

Two transports, both fail-soft: every recipient gets an entry in the returned
list saying what happened to *it*. A single ``delivered`` boolean would make
"three of four customers got the report" indistinguishable from success, and
the one that did not is exactly the one somebody has to be told about.

**Webhook** goes through ``integrations.delivery.post`` rather than a plain
HTTP client, so a report URL inherits the SSRF validation, pinned DNS and
no-redirect rules the event webhooks already use. The target is re-validated
on every send: a hostname that resolved publicly when the schedule was written
can resolve to link-local by the time it fires.

**Email** is plain ``smtplib`` against the configured relay, with the report as
an attachment. It is deliberately not routed through the scanner's alert
mailer: an alert goes to an operations channel and a report goes to a customer,
so they need separate senders, relays and failure handling.
"""

from __future__ import annotations

import base64
import json
import logging
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from api.services.integrations import delivery as wire
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.reports.delivery")

# Beyond this a report is not emailed — most relays refuse a message this size
# and a bounce arrives hours later, if at all. The recipient's entry says so,
# and the report stays downloadable from the console.
MAX_EMAIL_ATTACHMENT_BYTES = 15 * 1024 * 1024

_MIME = {
    "pdf": ("application", "pdf"),
    "html": ("text", "html"),
    "json": ("application", "json"),
}


def _entry(recipient: dict[str, Any], status: str, error: str | None = None) -> dict[str, Any]:
    return {
        "transport": recipient.get("transport"),
        "target": recipient.get("target"),
        "status": status,
        "error": error,
    }


def _send_email(
    settings: Settings,
    recipient: dict[str, Any],
    *,
    report: dict[str, Any],
    payload: bytes,
    filename: str,
) -> dict[str, Any]:
    if not settings.report_smtp_host or not settings.report_smtp_from:
        return _entry(
            recipient,
            "skipped",
            "email delivery needs OCTO_REPORT_SMTP_HOST and OCTO_REPORT_SMTP_FROM",
        )
    if len(payload) > MAX_EMAIL_ATTACHMENT_BYTES:
        return _entry(
            recipient,
            "failed",
            f"report is {len(payload)} bytes, over the {MAX_EMAIL_ATTACHMENT_BYTES} email limit",
        )

    message = EmailMessage()
    message["Subject"] = report.get("title") or "Security report"
    message["From"] = settings.report_smtp_from
    message["To"] = recipient["target"]
    message.set_content(
        f"{report.get('title') or 'Security report'}\n\n"
        f"Generated {report.get('generated_at')}.\n"
        "The report is attached.\n"
    )
    maintype, subtype = _MIME.get(str(report.get("format")), ("application", "octet-stream"))
    message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)

    try:
        with smtplib.SMTP(
            settings.report_smtp_host,
            settings.report_smtp_port,
            timeout=settings.report_smtp_timeout_seconds,
        ) as smtp:
            if settings.report_smtp_starttls:
                try:
                    smtp.starttls()
                except smtplib.SMTPException:
                    # A relay that cannot do STARTTLS is a configuration
                    # decision, not a delivery failure — but it is recorded,
                    # because "the customer report went out in cleartext" is
                    # something an operator has to be able to discover.
                    LOG.warning("SMTP relay %s refused STARTTLS", settings.report_smtp_host)
            if settings.report_smtp_username:
                smtp.login(settings.report_smtp_username, settings.report_smtp_password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return _entry(recipient, "failed", f"{type(exc).__name__}: {exc}"[:300])
    return _entry(recipient, "delivered")


def _send_webhook(
    settings: Settings,
    recipient: dict[str, Any],
    *,
    report: dict[str, Any],
    payload: bytes,
    filename: str,
) -> dict[str, Any]:
    envelope = {
        "type": "report.generated",
        "report_id": report.get("report_id"),
        "tenant_id": report.get("tenant_id"),
        "title": report.get("title"),
        "kind": report.get("kind"),
        "format": report.get("format"),
        "generated_at": report.get("generated_at"),
        "filename": filename,
        # Base64 rather than multipart: the receiver is a JSON endpoint like
        # every other webhook this platform sends, and a second body encoding
        # would be a second parser for an integrator to get wrong.
        "content_base64": base64.b64encode(payload).decode("ascii"),
    }
    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    result = wire.post(
        recipient["target"],
        body,
        {"Content-Type": "application/json", "User-Agent": "Shapoclyack-Reports/1"},
        timeout_seconds=settings.webhook_timeout_seconds,
        allow_private=settings.webhook_allow_private_targets,
    )
    if result.ok:
        return _entry(recipient, "delivered")
    return _entry(recipient, "failed", result.error)


def deliver(
    settings: Settings,
    *,
    report: dict[str, Any],
    path: Path,
    recipients: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Send one rendered report to every recipient; never raises."""

    if not recipients:
        return []
    try:
        payload = path.read_bytes()
    except OSError as exc:
        return [_entry(entry, "failed", f"report file unreadable: {exc}") for entry in recipients]

    filename = path.name
    entries: list[dict[str, Any]] = []
    for recipient in recipients:
        transport = str(recipient.get("transport") or "")
        try:
            if transport == "email":
                entries.append(
                    _send_email(
                        settings, recipient, report=report, payload=payload, filename=filename
                    )
                )
            elif transport == "webhook":
                entries.append(
                    _send_webhook(
                        settings, recipient, report=report, payload=payload, filename=filename
                    )
                )
            else:
                entries.append(_entry(recipient, "failed", f"unknown transport {transport!r}"))
        except Exception as exc:  # noqa: BLE001 - one bad recipient is not the batch
            LOG.exception("Report delivery to %s failed", recipient.get("target"))
            entries.append(_entry(recipient, "failed", f"{type(exc).__name__}: {exc}"[:300]))
    return entries
