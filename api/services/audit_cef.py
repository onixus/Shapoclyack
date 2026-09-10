"""ArcSight CEF inside RFC 5424 syslog, for the audit trail (#328).

The pure half of the SIEM forwarder: an audit envelope in, one framed syslog
octet string out. It opens no sockets and reads no configuration, so the format
— which is the part every SIEM parser depends on and the part nobody can test
by looking at it — is testable on its own.

Two nested formats, and each has one escaping rule that matters:

``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions``
    The seven header fields are ``|``-separated, so a ``|`` *inside* one has to
    be written ``\\|`` and a ``\\`` as ``\\\\``. The extension half is
    ``key=value`` pairs separated by single spaces, so there a ``=`` has to be
    written ``\\=`` — and a space does **not**, because a value runs to the next
    ``key=``. Newlines are escaped in both halves: a raw one would end the
    syslog message early and hand the receiver two events, the second of which
    parses as garbage. This is the injection an attacker gets for free from any
    field they control — a username, a user agent — so it is escaped, never
    stripped.

``<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG``
    RFC 5424. Sent with RFC 6587 octet counting (``<length> <message>``) rather
    than newline framing, because the CEF payload may legitimately contain the
    escaped-but-still-two-character sequences a naive newline splitter mishandles
    and because octet counting is what every TLS-capable receiver expects.

**What does not fit.** ``before``/``after`` are already redacted and capped at
16 KiB by :func:`api.services.audit.record`, which is still far more than a
syslog receiver should be asked to swallow on one line, so :data:`MAX_MSG_CHARS`
caps the ``msg`` extension and replaces an oversized pair with a marker. The
full documents stay in ``audit_events`` and in ``GET /api/audit``; CEF is the
alert, not the archive.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

#: CEF dictionary version. Not the product version — that is the fourth header
#: field, which carries :data:`api.__version__`.
CEF_VERSION = "0"
CEF_VENDOR = "Shapoclyack"
CEF_PRODUCT = "api"

#: Syslog APP-NAME. RFC 5424 caps it at 48 printable ASCII characters.
SYSLOG_APP_NAME = "shapoclyack"
#: Syslog MSGID, so a receiver can select these without parsing the payload.
SYSLOG_MSGID = "audit"
#: Facility 13 = "log audit" (RFC 5424 table 1). The right one for this stream,
#: and the one SIEM ingest rules for CEF are usually written against.
DEFAULT_FACILITY = 13

#: Ceiling on the serialised ``before``/``after`` pair in the ``msg`` extension.
MAX_MSG_CHARS = 1024

#: What ``cs1``/tenant carries for a platform-level act. The same reserved
#: token ``nats_bus`` puts in the subject, so the SIEM's tenant column and the
#: NATS subject agree.
PLATFORM_TENANT = "_platform"

#: CEF severity when an action is not in :data:`_ACTION_SEVERITY`. Deliberately
#: mid-scale: an action this file has not been taught about is not thereby
#: harmless, and a new ``*.delete`` defaulting to 0 would be invisible.
DEFAULT_SEVERITY = 5

# CEF severity is 0..10. The scale here is "how much does an auditor want to be
# woken up": credentials minted or reset, privileges changed, and anything
# deleted sit at the top; ordinary creation and lifecycle changes in the
# middle; reads at the bottom. Keyed on the ACTION_* constants in
# api/services/audit.py.
_ACTION_SEVERITY = {
    # Credentials and privilege — the actions an attacker needs and an auditor
    # reads first.
    "user.role_change": 8,
    "user.password_reset": 8,
    "user.delete": 8,
    "membership.grant": 8,
    "membership.revoke": 8,
    "service_token.create": 8,
    "provisioning_key.create": 8,
    "agent.delete": 8,
    "config.update": 8,
    # Same weight as a config change: it redirects where exposure data goes.
    "notification_channel.create": 8,
    "notification_channel.update": 8,
    "notification_channel.delete": 6,
    # Revocations and lifecycle: still worth an alert, but they narrow access
    # rather than widening it.
    "user.create": 6,
    "user.disable": 6,
    "user.password_change": 5,
    "service_token.revoke": 6,
    "provisioning_key.revoke": 6,
    "agent.register": 6,
    "agent.disable": 6,
    "agent.enable": 6,
    "agent.quarantine": 7,
    "scan_scope.replace": 7,
    # A read, recorded because the artefact leaves the platform.
    "report.download": 3,
}

# Everything RFC 5424 forbids in a MSG and everything a CEF parser would
# mis-split. C0 controls except the ones handled by name below, plus DEL.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# HOSTNAME is one space-delimited RFC 5424 field: anything that is not a
# printable non-space character would shift every field after it by one.
_HOSTNAME_UNSAFE_RE = re.compile(r"[^\x21-\x7e]")


def severity_for(action: str) -> int:
    """CEF severity (0..10) for one audit action."""
    return _ACTION_SEVERITY.get(action or "", DEFAULT_SEVERITY)


def syslog_severity(cef_severity: int) -> int:
    """Map the CEF 0..10 scale onto the syslog 0..7 one for the PRI field.

    Three buckets, not eleven: a receiver filters on ``warning and above``, and
    inventing a distinct syslog level per CEF point would make that filter mean
    something different for every action.
    """
    if cef_severity >= 8:
        return 4  # warning
    if cef_severity >= 5:
        return 5  # notice
    return 6  # informational


def escape_header(value: Any) -> str:
    """Escape one CEF *header* field: ``\\`` and ``|``, plus line breaks."""
    return _escape(value, "|")


def escape_extension(value: Any) -> str:
    """Escape one CEF *extension* value: ``\\`` and ``=``, plus line breaks.

    A ``|`` needs no escaping here — the header is already over — and a space
    needs none either, since a value ends where the next ``key=`` begins.
    """
    return _escape(value, "=")


def _escape(value: Any, separator: str) -> str:
    """Stringify and escape for whichever CEF half ``separator`` belongs to.

    Order is the whole content of this function. The backslash is doubled
    *first*, so that the escapes added afterwards are the only single
    backslashes left; a newline then becomes the two-character sequence ``\\n``
    that CEF defines, which is what keeps a user-supplied value from ending the
    syslog message early. Doing it the other way round would double the
    backslash this function just wrote and hand the receiver a literal
    ``\\\\n``.
    """
    text = _stringify(value)
    text = text.replace("\\", "\\\\")
    text = text.replace(separator, "\\" + separator)
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
    return _CONTROL_RE.sub("", text)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, str) else str(value)


def parse_occurred_at(occurred_at: str | None) -> datetime | None:
    """The envelope's ISO-8601 ``occurred_at`` as an aware UTC datetime, or None.

    Unparseable rather than absent is the same answer here: the caller falls
    back to the present, which is wrong by a known and bounded amount, where
    guessing at a malformed timestamp would be wrong by an unknown one.
    """
    if not occurred_at:
        return None
    text = occurred_at.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _epoch_millis(occurred_at: str | None) -> int | None:
    """``rt`` wants milliseconds since the epoch; the envelope carries ISO-8601."""
    moment = parse_occurred_at(occurred_at)
    return None if moment is None else int(moment.timestamp() * 1000)


def _change_summary(data: dict[str, Any]) -> str | None:
    """The ``before``/``after`` pair as compact JSON, or a marker when too big."""
    before = data.get("before")
    after = data.get("after")
    if before is None and after is None:
        return None
    try:
        encoded = json.dumps(
            {"before": before, "after": after}, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return "{\"unserialisable\":true}"
    if len(encoded) > MAX_MSG_CHARS:
        return json.dumps(
            {"truncated": True, "bytes": len(encoded)}, separators=(",", ":")
        )
    return encoded


def format_cef(envelope: dict[str, Any], *, product_version: str) -> str:
    """One audit envelope as a CEF line (no syslog header, no framing).

    ``deviceEventClassId`` and ``name`` both carry the dotted action. That is
    deliberate: ArcSight wants a ``name`` with no variable content in it, and
    the action is exactly the low-cardinality label a SIEM correlation rule
    keys on. A friendlier label belongs in the SIEM's own lookup table, not in
    a field whose values this platform would then have to keep stable forever.
    """
    data = envelope.get("data")
    data = data if isinstance(data, dict) else {}
    action = str(data.get("action") or "")
    severity = severity_for(action)

    header = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            escape_header(CEF_VENDOR),
            escape_header(CEF_PRODUCT),
            escape_header(product_version),
            escape_header(action or "audit"),
            escape_header(action or "audit"),
            str(severity),
        ]
    )

    # Order is fixed so a diff between two forwarded events reads as a diff in
    # the events, not in the serialiser.
    extensions: list[tuple[str, Any]] = []
    rt = _epoch_millis(envelope.get("occurred_at"))
    if rt is not None:
        extensions.append(("rt", rt))
    extensions.extend(
        [
            ("externalId", data.get("audit_id")),
            ("act", action),
            # Every row in this table describes a change that happened; a
            # refused one is an auth_events row, a different stream.
            ("outcome", "success"),
            ("suser", data.get("actor")),
            ("src", data.get("client_ip")),
            ("requestClientApplication", data.get("user_agent")),
        ]
    )
    # The six custom-string slots and their labels. Emitted as pairs so a
    # missing value takes its label with it: a ``cs5Label=requestId`` with no
    # ``cs5`` next to it makes a SIEM's field mapping show an empty column that
    # looks like data loss rather than an absent optional field.
    for slot, (label, value) in enumerate(
        [
            # Never blank: a NULL tenant is a platform-level act, and the
            # reserved token says so rather than leaving a SIEM to guess what
            # an empty tenant column means.
            ("tenant", envelope.get("tenant_id") or PLATFORM_TENANT),
            ("resourceType", data.get("resource_type")),
            ("resourceId", data.get("resource_id")),
            ("actorType", data.get("actor_type")),
            ("requestId", data.get("request_id")),
            ("eventId", envelope.get("event_id")),
        ],
        start=1,
    ):
        if value is None or str(value) == "":
            continue
        extensions.append((f"cs{slot}Label", label))
        extensions.append((f"cs{slot}", value))

    summary = _change_summary(data)
    if summary is not None:
        extensions.append(("msg", summary))

    rendered = " ".join(
        f"{key}={escape_extension(value)}"
        for key, value in extensions
        # An empty value would render as a bare ``key=`` and some parsers read
        # the next pair as its value. Dropping the key says the same thing.
        if value is not None and str(value) != ""
    )
    return f"{header}|{rendered}"


def format_syslog(
    payload: str,
    *,
    severity: int,
    hostname: str,
    facility: int = DEFAULT_FACILITY,
    occurred_at: datetime | None = None,
) -> str:
    """Wrap a CEF line in an RFC 5424 header. No BOM — CEF over syslog omits it.

    ``STRUCTURED-DATA`` is ``-``: everything structured is already in the CEF
    extensions, and duplicating it into SD-elements would give a receiver two
    disagreeing copies to reconcile.

    ``occurred_at`` is the time of the *event*, not of the send, and callers
    pass it. A receiver that takes its timestamp from the syslog header rather
    than from ``rt`` — QRadar's Universal CEF does, by default — would
    otherwise stamp a whole replayed backlog with the minute the forwarder
    happened to reconnect, and an incident timeline built on that is wrong in
    the direction nobody checks.
    """
    pri = facility * 8 + severity
    moment = (occurred_at or datetime.now(UTC)).astimezone(UTC)
    timestamp = moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    # HOSTNAME is a single space-delimited field, so a space in it would shift
    # every field after it by one.
    host = _HOSTNAME_UNSAFE_RE.sub("_", _stringify(hostname))[:255] or "-"
    return (
        f"<{pri}>1 {timestamp} {host} {SYSLOG_APP_NAME} - {SYSLOG_MSGID} - {payload}"
    )


def frame(message: str) -> bytes:
    """RFC 6587 octet counting: ``<byte length> <message>``.

    The length counts *bytes*, not characters — a UTF-8 username makes the two
    differ, and a receiver that was handed a character count reads the next
    message's first bytes as the tail of this one.
    """
    body = message.encode("utf-8")
    return str(len(body)).encode("ascii") + b" " + body


def render(
    envelope: dict[str, Any],
    *,
    product_version: str,
    hostname: str,
    facility: int = DEFAULT_FACILITY,
) -> bytes:
    """Audit envelope → framed RFC 5424 syslog message carrying CEF."""
    data = envelope.get("data")
    action = str((data or {}).get("action") or "") if isinstance(data, dict) else ""
    cef = format_cef(envelope, product_version=product_version)
    message = format_syslog(
        cef,
        severity=syslog_severity(severity_for(action)),
        hostname=hostname,
        facility=facility,
        occurred_at=parse_occurred_at(
            envelope.get("occurred_at") if isinstance(envelope, dict) else None
        ),
    )
    return frame(message)
