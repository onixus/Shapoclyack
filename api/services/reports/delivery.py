"""Sending a rendered report to its recipients (Sprint 4).

Three transports (email, webhook, and S3 since #355), all fail-soft: every recipient gets an entry in the returned
list saying what happened to *it*. A single ``delivered`` boolean would make
"three of four customers got the report" indistinguishable from success, and
the one that did not is exactly the one somebody has to be told about.

**Webhook** goes through ``integrations.delivery.post`` rather than a plain
HTTP client, so a report URL inherits the SSRF validation, pinned DNS and
no-redirect rules the event webhooks already use. The target is re-validated
on every send: a hostname that resolved publicly when the schedule was written
can resolve to link-local by the time it fires.

**S3** writes the report -- and its manifest and signature, so the bucket holds
the whole evidence package -- through the artifact store's own S3 client, to
``s3://<bucket>/<tenant id>/<folder>/<file>``: the tenant id always leads, the
folder is the tenant's own choice inside it. The
bucket must be on ``OCTO_REPORT_S3_BUCKETS`` and is never the artifact bucket:
the credentials are the platform's, and a tenant admin who could name any bucket
they reach would be writing into other tenants' data with them.

**Email** is plain ``smtplib`` against the configured relay, with the report as
an attachment. It is deliberately not routed through the scanner's alert
mailer: an alert goes to an operations channel and a report goes to a customer,
so they need separate senders, relays and failure handling.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from api.services import artifact_store, egress
from api.services.artifact_store import S3ArtifactStore, S3Config
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
    "csv": ("text", "csv"),
    "xlsx": ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
}


_S3_TARGET_RE = re.compile(r"^s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:/(.*))?$")


def parse_s3_target(target: str, settings: Settings | None = None) -> tuple[str, str]:
    """``(bucket, folder)`` for ``s3://bucket[/folder]``; ``ValueError`` if unusable.

    The folder is only a sub-folder of the owning tenant's own area: the object
    key is always ``<tenant id>/<folder>/<file>`` (see ``_send_s3``), so a
    target cannot point at another tenant's subtree. It goes through the
    artifact store's key normaliser, which refuses ``..`` and absolute segments.
    With ``settings`` the bucket is also checked against the allowlist and the
    platform must have S3 credentials to use."""

    match = _S3_TARGET_RE.match(target.strip())
    if not match:
        raise ValueError("an s3 target must look like s3://bucket or s3://bucket/prefix")
    bucket = match.group(1)
    try:
        raw_prefix = (match.group(2) or "").strip("/")
        prefix = artifact_store.normalize_prefix(raw_prefix) if raw_prefix else ""
    except Exception as exc:  # noqa: BLE001 - any refusal is a bad target
        raise ValueError(f"unusable s3 prefix: {exc}") from exc
    if settings is not None:
        if bucket not in settings.report_s3_buckets:
            raise ValueError(
                f"bucket {bucket!r} is not allowed; the operator lists permitted buckets "
                "in OCTO_REPORT_S3_BUCKETS"
            )
        if bucket == settings.artifact_s3_bucket.strip().lower():
            raise ValueError("reports cannot be delivered to the artifact store's own bucket")
        # Without this the client would fall through to boto3's ambient
        # credential chain (an instance role, ~/.aws) on an installation that
        # keeps its artifacts on disk -- credentials nobody configured for this.
        if settings.artifact_backend != "s3" and not (
            settings.artifact_s3_access_key_id and settings.artifact_s3_secret_access_key
        ):
            raise ValueError(
                "S3 delivery needs OCTO_ARTIFACT_BACKEND=s3 or explicit "
                "OCTO_ARTIFACT_S3_ACCESS_KEY_ID / OCTO_ARTIFACT_S3_SECRET_ACCESS_KEY"
            )
    return bucket, prefix


def _entry(recipient: dict[str, Any], status: str, error: str | None = None) -> dict[str, Any]:
    return {
        "transport": recipient.get("transport"),
        "target": recipient.get("target"),
        "status": status,
        "error": error,
    }


def _tls_context(settings: Settings) -> ssl.SSLContext:
    """The SSL context for STARTTLS against the report relay.

    ``smtp.starttls()`` with no context builds one that neither checks the
    hostname nor verifies the chain (``CERT_NONE``), so the encryption it puts
    on the wire protects the report from a passive listener and from nobody
    else. The default here is therefore a verifying context; an installation
    whose relay presents an internal certificate names its CA in
    ``OCTO_CA_BUNDLE`` (#359, added to the system store rather than replacing
    it), puts it in the image's trust store, or sets
    OCTO_REPORT_SMTP_VERIFY_TLS=false and owns the downgrade.

    SMTP takes the CA from ``egress`` and nothing else from it: a relay is
    dialed directly, because an HTTP proxy does not carry SMTP.
    """
    context = egress.ssl_context()
    if not settings.report_smtp_verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


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

    error = _smtp_send(settings, message)
    return _entry(recipient, "failed", error) if error else _entry(recipient, "delivered")


def _smtp_send(settings: Settings, message: EmailMessage) -> str | None:
    """Hand one message to the configured relay. Returns an error, or ``None``.

    Extracted from :func:`_send_email` when #349 added a second kind of mail
    (the SLA owner digest) — the TLS discipline below is the part that must not
    exist in two copies, because a second copy is where the downgrade gets
    reintroduced.
    """
    try:
        with smtplib.SMTP(
            settings.report_smtp_host,
            settings.report_smtp_port,
            timeout=settings.report_smtp_timeout_seconds,
        ) as smtp:
            if settings.report_smtp_starttls:
                try:
                    smtp.starttls(context=_tls_context(settings))
                except (smtplib.SMTPException, OSError) as exc:
                    # Refused: the message is *not* sent. Continuing would put
                    # the relay password and the customer's whole vulnerability
                    # report on the wire in cleartext, and record it as
                    # delivered — the operator asked for TLS, so a failure to
                    # get it is a delivery failure, not a downgrade to make
                    # quietly on their behalf. An installation with a relay
                    # that genuinely cannot do TLS sets
                    # OCTO_REPORT_SMTP_STARTTLS=false and owns that choice.
                    # A certificate that does not verify lands here too
                    # (ssl.SSLCertVerificationError is an OSError): an
                    # unauthenticated relay is a relay we cannot tell from the
                    # attacker sitting in front of it.
                    LOG.warning("SMTP relay %s refused STARTTLS", settings.report_smtp_host)
                    return (
                        f"relay refused STARTTLS ({type(exc).__name__}); refusing to send "
                        "the message in cleartext. Set OCTO_REPORT_SMTP_STARTTLS=false to "
                        "accept an unencrypted relay."
                    )
            if settings.report_smtp_username:
                smtp.login(settings.report_smtp_username, settings.report_smtp_password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return f"{type(exc).__name__}: {exc}"[:300]
    return None


def send_notice(
    settings: Settings, *, to: str, subject: str, body: str
) -> str | None:
    """Send one plain-text operational mail. Returns an error, or ``None``.

    The SLA owner digest (#349) goes out through here rather than through a
    mailer of its own: it is the same relay, the same sender and the same TLS
    rules, and an installation that configured
    ``OCTO_REPORT_SMTP_*`` has already said where its outbound mail goes.

    **The seam #351 replaces.** Per-tenant notification channels are that
    issue's subject: when a tenant has one configured, the digest should leave
    through it instead of through this installation-wide relay. Callers pass
    the recipient and the text and nothing else, so swapping the transport is a
    change here and at the one call site in
    ``api/services/sla_escalation.py``, not a change to what a digest is.
    """
    if not settings.report_smtp_host or not settings.report_smtp_from:
        return "email delivery needs OCTO_REPORT_SMTP_HOST and OCTO_REPORT_SMTP_FROM"
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.report_smtp_from
    message["To"] = to
    message.set_content(body)
    return _smtp_send(settings, message)


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


def _send_s3(
    settings: Settings,
    recipient: dict[str, Any],
    *,
    report: dict[str, Any],
    payload: bytes,
    filename: str,
    extras: dict[str, bytes],
) -> dict[str, Any]:
    # Re-validated on every send, like a webhook: the allowlist may have changed
    # since the schedule was written.
    bucket, folder = parse_s3_target(str(recipient["target"]), settings)
    tenant = str(report.get("tenant_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tenant) or tenant in {".", ".."}:
        return _entry(recipient, "failed", "report has no usable tenant id")
    # The tenant id leads the key whatever the target says, so the folder a
    # tenant admin chose can only ever be inside that tenant's own subtree of a
    # bucket shared with others.
    destination = S3ArtifactStore(
        S3Config(
            bucket=bucket,
            prefix=tenant,
            endpoint_url=settings.artifact_s3_endpoint_url,
            region=settings.artifact_s3_region,
            access_key_id=settings.artifact_s3_access_key_id,
            secret_access_key=settings.artifact_s3_secret_access_key,
            session_token=settings.artifact_s3_session_token,
            addressing_style=settings.artifact_s3_addressing_style,
            verify_tls=settings.artifact_s3_verify_tls,
        )
    )
    if not extras:
        # The S3 package is report + manifest. Without the manifest nothing
        # vouches for the file, and it is never re-signed after the fact (see
        # ``store.read_package_extras``), so nothing is written.
        return _entry(
            recipient, "failed", "no manifest exists for this report; refusing to deliver it unsigned"
        )
    base = f"{folder}/" if folder else ""
    media = _MIME.get(str(report.get("format")), ("application", "octet-stream"))
    # The report first: if the manifest write fails the recipient has the file and
    # the entry says what is missing, rather than the reverse.
    destination.put_bytes(f"{base}{filename}", payload, content_type="/".join(media))
    for name, data in extras.items():
        destination.put_bytes(f"{base}{name}", data, content_type="application/json")
    return _entry(recipient, "delivered")


def deliver(
    settings: Settings,
    *,
    report: dict[str, Any],
    payload: bytes,
    filename: str,
    recipients: list[dict[str, Any]],
    extras: dict[str, bytes] | None = None,
) -> list[dict[str, Any]]:
    """Send one rendered report to every recipient; never raises.

    Takes the bytes rather than a path since #336: a report lives in the
    artifact store, which on an object-storage installation is not a file this
    process can open. The caller fetches once and every recipient is sent the
    same copy -- which was already true, and is now the only thing that can be.
    """

    if not recipients:
        return []
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
            elif transport == "s3":
                entries.append(
                    _send_s3(
                        settings,
                        recipient,
                        report=report,
                        payload=payload,
                        filename=filename,
                        extras=extras or {},
                    )
                )
            else:
                entries.append(_entry(recipient, "failed", f"unknown transport {transport!r}"))
        except Exception as exc:  # noqa: BLE001 - one bad recipient is not the batch
            LOG.exception("Report delivery to %s failed", recipient.get("target"))
            entries.append(_entry(recipient, "failed", f"{type(exc).__name__}: {exc}"[:300]))
    return entries
