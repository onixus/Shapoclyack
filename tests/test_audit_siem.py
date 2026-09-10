"""The audit trail on its way to a SIEM (#328).

Four things can go wrong between an ``audit_events`` row and a SIEM's search
bar, and each has its own section below:

* the event is announced for a change that never committed, or not announced
  for one that did;
* it lands on the wrong tenant's subject, which in a multi-tenant broker is a
  disclosure and not merely a routing bug;
* the CEF line is malformed, so a field an operator controls (a username, a
  user agent) ends the message early and the SIEM indexes garbage;
* the forwarder acknowledges an event the receiver never took, which loses it
  silently — the one failure an audit feed must not have.

Most of it needs no database at all: the format is pure, and the publish half
is exercised over the SQLite fallback so the ordering guarantee is testable
without Postgres.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from api.db import models
from api.db.engine import get_session, reset_for_tests as reset_engine
from api.services import audit as audit_service
from api.services import audit_cef, audit_events, nats_bus
from api.services import audit_syslog_forwarder as forwarder
from api.services.integrations import webhooks
from tests.conftest import make_settings


def _envelope(**overrides) -> dict:
    """An envelope shaped exactly like :func:`audit_events.build_envelope`."""
    data = {
        "audit_id": 42,
        "action": "user.role_change",
        "actor": "admin",
        "actor_type": "user",
        "resource_type": "user",
        "resource_id": "amy",
        "before": {"role": "viewer"},
        "after": {"role": "admin"},
        "client_ip": "10.0.0.1",
        "user_agent": "curl/8.6.0",
        "request_id": "req-1",
    }
    data.update(overrides.pop("data", {}))
    envelope = {
        "kind": audit_events.event_kind(str(data["action"])),
        "tenant_id": "acme",
        "event_id": "ev-audit-1",
        "occurred_at": "2026-09-10T10:00:00Z",
        "source": "audit",
        "data": data,
    }
    envelope.update(overrides)
    return envelope


def _extensions(cef: str) -> str:
    """The extension half of a CEF line: everything past the seventh ``|``.

    Split on the unescaped separator only — a ``\\|`` inside a header field is
    part of that field, which is the whole point of escaping it.
    """
    fields: list[str] = [""]
    escaped = False
    for char in cef:
        if escaped:
            fields[-1] += char
            escaped = False
        elif char == "\\":
            fields[-1] += char
            escaped = True
        elif char == "|":
            fields.append("")
        else:
            fields[-1] += char
    assert len(fields) >= 8, cef
    return "|".join(fields[7:])


# --------------------------------------------------------------------------- #
# CEF: escaping, and the fields a SIEM maps
# --------------------------------------------------------------------------- #


def test_pipe_in_a_header_field_is_escaped_not_dropped():
    """A ``|`` in an action would otherwise add an eighth header field."""
    line = audit_cef.format_cef(
        _envelope(data={"action": "user|create"}), product_version="1.0"
    )
    assert "|user\\|create|" in line
    # Seven header fields exactly, with the escaped pipe on the inside.
    assert line.split("|")[0] == "CEF:0"
    assert _extensions(line).startswith("rt=")


def test_backslash_and_equals_are_escaped_in_an_extension_value():
    line = audit_cef.format_cef(
        _envelope(data={"actor": "DOMAIN\\amy", "resource_id": "role=admin"}),
        product_version="1.0",
    )
    assert "suser=DOMAIN\\\\amy" in line
    assert "cs3=role\\=admin" in line


@pytest.mark.parametrize("injected", ["a\nb", "a\r\nb", "a\rb"])
def test_a_newline_cannot_end_the_message_early(injected):
    """The injection an operator gets for free from any field they control."""
    line = audit_cef.format_cef(
        _envelope(data={"user_agent": injected}), product_version="1.0"
    )
    assert "\n" not in line and "\r" not in line
    assert "requestClientApplication=a\\" in line


def test_control_characters_are_removed_rather_than_forwarded():
    line = audit_cef.format_cef(
        _envelope(data={"actor": "am\x00y\x07"}), product_version="1.0"
    )
    assert "suser=amy " in line


def test_the_documented_field_mapping_is_what_is_emitted():
    """docs/operations.md § Audit events to SIEM promises these names."""
    line = audit_cef.format_cef(_envelope(), product_version="0.44-0907")
    header, extensions = line.split("|", 1)[1], _extensions(line)
    assert header.startswith("Shapoclyack|api|0.44-0907|user.role_change|user.role_change|8")
    for pair in (
        "externalId=42",
        "act=user.role_change",
        "outcome=success",
        "suser=admin",
        "src=10.0.0.1",
        "cs1Label=tenant",
        "cs1=acme",
        "cs2Label=resourceType",
        "cs3=amy",
        "cs4=user",
        "cs5=req-1",
        "cs6=ev-audit-1",
    ):
        assert pair in extensions, pair
    assert 'msg={"before":{"role":"viewer"},"after":{"role":"admin"}}' in extensions


def test_a_missing_optional_field_takes_its_label_with_it():
    """A ``cs5Label`` with no ``cs5`` reads to a SIEM as an empty column."""
    line = audit_cef.format_cef(
        _envelope(data={"request_id": None}), product_version="1.0"
    )
    assert "cs5Label" not in line and "cs5=" not in line
    # ...and the slots either side are untouched.
    assert "cs4Label=actorType" in line and "cs6Label=eventId" in line


def test_a_platform_level_row_names_the_reserved_tenant_not_an_empty_one():
    line = audit_cef.format_cef(_envelope(tenant_id=None), product_version="1.0")
    assert f"cs1={audit_cef.PLATFORM_TENANT}" in line


def test_the_platform_token_matches_the_one_in_the_subject():
    """Two literals, one meaning: a drift would put the SIEM and NATS out of step."""
    assert audit_cef.PLATFORM_TENANT == nats_bus.PLATFORM_SUBJECT_TENANT


def test_an_oversized_change_document_becomes_a_marker():
    big = {"entries": ["x" * 50 for _ in range(100)]}
    line = audit_cef.format_cef(
        _envelope(data={"after": big}), product_version="1.0"
    )
    assert '"truncated":true' in line
    assert len(line) < audit_cef.MAX_MSG_CHARS + 1024


def test_severity_separates_a_privilege_change_from_a_report_download():
    assert audit_cef.severity_for(audit_service.ACTION_USER_ROLE) == 8
    assert audit_cef.severity_for(audit_service.ACTION_REPORT_DOWNLOAD) == 3
    # An action this table has not been taught about is not thereby harmless.
    assert audit_cef.severity_for("something.new") == audit_cef.DEFAULT_SEVERITY


# --------------------------------------------------------------------------- #
# RFC 5424 framing
# --------------------------------------------------------------------------- #


def test_rfc5424_header_has_the_fields_in_the_right_order():
    message = audit_cef.format_syslog(
        "CEF:0|x|y|z|a|b|5|", severity=4, hostname="api-0", facility=13
    )
    pri, _, rest = message.partition(">")
    assert pri == "<108"  # facility 13 * 8 + severity 4
    version, timestamp, host, app, procid, msgid, sd = rest.split(" ", 6)[:7]
    assert version == "1"
    assert timestamp.endswith("Z") and "T" in timestamp
    assert (host, app, procid, msgid) == ("api-0", "shapoclyack", "-", "audit")
    assert sd.startswith("- CEF:0|")


def test_a_hostname_with_a_space_cannot_shift_every_later_field():
    message = audit_cef.format_syslog(
        "CEF:0|", severity=5, hostname="api 0\nevil", facility=13
    )
    assert message.split(" ")[2] == "api_0_evil"


def test_octet_counting_counts_bytes_not_characters():
    """A UTF-8 name makes the two differ, and a receiver reads bytes."""
    message = audit_cef.format_syslog("CEF:0|ключ", severity=5, hostname="h")
    framed = audit_cef.frame(message)
    length, _, body = framed.partition(b" ")
    assert int(length) == len(body)
    assert len(body) > len(message)


def test_the_syslog_header_carries_the_event_time_not_the_send_time():
    """A replayed backlog must not all land on the minute it was replayed.

    QRadar's Universal CEF takes its timestamp from the syslog header rather
    than from `rt`, so a header stamped "now" would flatten thirty days of
    history into one minute and quietly falsify every incident timeline built
    on it.
    """
    framed = forwarder.render(
        _envelope(occurred_at="2026-01-02T03:04:05Z"), forwarder.ForwarderConfig({})
    )
    assert b" 2026-01-02T03:04:05.000Z " in framed


def test_an_unparseable_event_time_falls_back_to_now_rather_than_to_1970():
    framed = forwarder.render(
        _envelope(occurred_at="not a timestamp"), forwarder.ForwarderConfig({})
    )
    stamp = framed.split(b" ")[2].decode()
    assert stamp.startswith(str(datetime.now(UTC).year))


def test_render_picks_the_syslog_severity_from_the_action():
    framed = forwarder.render(_envelope(), forwarder.ForwarderConfig({}))
    # user.role_change is CEF 8 → syslog warning (4) → PRI 13*8+4.
    assert framed.split(b" ", 1)[1].startswith(b"<108>1 ")


# --------------------------------------------------------------------------- #
# Subjects: one tenant's audit trail must not land on another's subject
# --------------------------------------------------------------------------- #


def test_each_tenant_gets_its_own_subject():
    assert nats_bus.audit_event_subject("acme") == "events.audit.acme"
    assert nats_bus.audit_event_subject("globex") == "events.audit.globex"


def test_a_platform_level_row_does_not_land_on_the_default_tenant():
    """``default`` is a real tenant in every installation, so it is not the fallback."""
    subject = nats_bus.audit_event_subject("")
    assert subject == f"events.audit.{nats_bus.PLATFORM_SUBJECT_TENANT}"
    assert subject != nats_bus.audit_event_subject("default")


def test_a_legacy_tenant_id_is_hashed_rather_than_mangled_into_a_neighbour():
    """Two distinguishable ids must not collapse onto one subject."""
    first = nats_bus.audit_event_subject("acme.eu")
    second = nats_bus.audit_event_subject("acme_eu")
    assert first.startswith("events.audit.h_")
    assert first != second


# --------------------------------------------------------------------------- #
# Publication happens after the commit, and only after it
# --------------------------------------------------------------------------- #


@pytest.fixture()
def sqlite_settings(tmp_path):
    """Settings over a throwaway SQLite file.

    The ordering guarantee is a property of the SQLAlchemy session, not of
    Postgres, so this half of #328 is testable without the migrated database
    the rest of the API suite needs.
    """
    settings = make_settings(
        tmp_path, postgres_url=f"sqlite+pysqlite:///{tmp_path}/audit-siem.db"
    )
    audit_service.configure(settings)
    yield settings
    reset_engine()


@pytest.fixture()
def published(monkeypatch) -> list[dict]:
    """Capture what would have gone to the broker, in publish order."""
    seen: list[dict] = []

    def _capture(nats_url, envelopes, **kwargs):
        seen.extend(envelopes)
        return len(envelopes)

    monkeypatch.setattr(audit_events, "publish_envelopes", _capture)
    return seen


def test_a_committed_change_is_published_once_with_its_row_id(sqlite_settings, published):
    with get_session(sqlite_settings.postgres_url) as session:
        audit_service.record(
            session,
            None,
            action=audit_service.ACTION_USER_ROLE,
            resource_type="user",
            resource_id="amy",
            tenant_id="acme",
            before={"role": "viewer"},
            after={"role": "admin"},
        )
        assert published == [], "published before the transaction committed"

    assert len(published) == 1
    envelope = published[0]
    assert envelope["kind"] == "audit.user.role_change"
    assert envelope["tenant_id"] == "acme"
    assert envelope["data"]["audit_id"] > 0
    assert envelope["data"]["after"] == {"role": "admin"}


def test_a_rolled_back_change_announces_nothing(sqlite_settings, published):
    """The bus must not carry a change the database refused to keep.

    The rollback and a later commit share one session on purpose: a session
    that is simply closed after a rollback never reaches the commit hook at
    all, so it would pass this whether or not the rollback listener exists.
    Recording a second change afterwards and committing *that* is what makes
    the discarded snapshot observable — without the listener, the deleted
    user's event rides out on the created user's commit.
    """
    with get_session(sqlite_settings.postgres_url) as session:
        audit_service.record(
            session,
            None,
            action=audit_service.ACTION_USER_DELETE,
            resource_type="user",
            resource_id="amy",
            tenant_id="acme",
        )
        # The flush the real failure path would have reached, so the snapshot
        # exists and the rollback is what discards it.
        session.flush()
        session.rollback()

        audit_service.record(
            session,
            None,
            action=audit_service.ACTION_USER_CREATE,
            resource_type="user",
            resource_id="bob",
            tenant_id="acme",
        )

    assert [e["kind"] for e in published] == ["audit.user.create"]
    with get_session(sqlite_settings.postgres_url) as session:
        assert session.query(models.AuditEvent).count() == 1


def test_three_changes_in_one_request_publish_three_events_not_nine(
    sqlite_settings, published
):
    """``record`` arms the session on every row; the listeners must not stack."""
    with get_session(sqlite_settings.postgres_url) as session:
        for name in ("amy", "bob", "cleo"):
            audit_service.record(
                session,
                None,
                action=audit_service.ACTION_USER_CREATE,
                resource_type="user",
                resource_id=name,
                tenant_id="acme",
            )

    assert len(published) == 3
    assert {e["data"]["resource_id"] for e in published} == {"amy", "bob", "cleo"}


def test_no_broker_configured_publishes_nothing_and_raises_nothing(sqlite_settings):
    """The honest no-NATS case: the row lands, the feed is silent."""
    assert audit_events.publish_envelopes("", [_envelope()]) == 0


def test_an_unreachable_broker_is_not_re_dialled_on_every_change(monkeypatch):
    """A down broker costs one request ten seconds, not every request ten.

    These events are published from administrative requests, and
    ``nats_bus.get_bus`` does not cache a failure: it spends its connect and
    stream budget again on each call. Without the window below, a broker that
    is down adds that to every role change and token issue until it returns.
    """
    attempts: list[str] = []
    monkeypatch.setattr(
        audit_events.nats_bus, "get_bus", lambda url: attempts.append(url) or None
    )
    monkeypatch.setattr(audit_events, "_broker_down", ("", 0.0))

    for _ in range(3):
        assert audit_events.publish_envelopes("nats://down:4222", [_envelope()]) == 0
    assert attempts == ["nats://down:4222"]

    # ...and the verdict is about *that* broker, not about publishing at large:
    # a second URL is still dialled.
    assert audit_events.publish_envelopes("nats://other:4222", [_envelope()]) == 0
    assert attempts == ["nats://down:4222", "nats://other:4222"]


# --------------------------------------------------------------------------- #
# Webhook subscriptions on audit events
# --------------------------------------------------------------------------- #


def _routing(*kinds: str) -> dict:
    return {"enabled": True, "event_kinds": list(kinds), "min_severity": None}


def test_the_audit_wildcard_matches_every_action():
    assert webhooks.matches(_routing("audit.*"), _envelope())
    assert webhooks.matches(
        _routing("audit.*"), _envelope(kind="audit.service_token.create")
    )


def test_the_audit_wildcard_does_not_pull_in_asset_events():
    asset = {"kind": "new_cve", "tenant_id": "acme", "data": {"severity": "critical"}}
    assert not webhooks.matches(_routing("audit.*"), asset)


def test_one_exact_action_can_be_subscribed_to_on_its_own():
    routing = _routing("audit.user.role_change")
    assert webhooks.matches(routing, _envelope())
    assert not webhooks.matches(routing, _envelope(kind="audit.user.create"))


def test_an_unfiltered_subscription_does_not_start_receiving_the_trail():
    """The upgrade hazard: `event_kinds == []` predates the trail leaving at all.

    Those subscriptions were configured for CVE alerts, often into a shared
    chat channel. Letting "every kind" quietly grow to include who reset whose
    password, from which address, would be a disclosure introduced by a version
    bump rather than by anyone's decision.
    """
    unfiltered = {"enabled": True, "event_kinds": [], "min_severity": None}
    assert not webhooks.matches(unfiltered, _envelope())
    assert webhooks.matches(
        unfiltered, {"kind": "new_asset", "tenant_id": "acme", "data": {}}
    )


def test_an_unfiltered_subscription_still_honours_its_severity_floor():
    """The clause above must not short-circuit past the filter beneath it."""
    unfiltered = {"enabled": True, "event_kinds": [], "min_severity": "critical"}
    low = {"kind": "new_cve", "tenant_id": "acme", "data": {"severity": "low"}}
    high = {"kind": "new_cve", "tenant_id": "acme", "data": {"severity": "critical"}}
    assert not webhooks.matches(unfiltered, low)
    assert webhooks.matches(unfiltered, high)


def test_the_api_accepts_the_audit_kinds_it_documents():
    """`POST /api/webhooks` has to take what docs/api-and-rbac.md promises."""
    assert webhooks._validate_event_kinds(
        ["audit.*", "audit.user.role_change", "new_cve"]
    ) == ["audit.*", "audit.user.role_change", "new_cve"]
    # A kind that is neither an asset event nor an audit one is still refused,
    # and the message says what may be named instead.
    with pytest.raises(ValueError, match="audit.user.role_change"):
        webhooks._validate_event_kinds(["audit"])


def test_a_severity_filter_does_not_swallow_audit_events():
    """``min_severity`` is a statement about vulnerabilities, not about the trail."""
    routing = {"enabled": True, "event_kinds": ["audit.*"], "min_severity": "critical"}
    assert webhooks.matches(routing, _envelope())


def _subscribe(session, *, subscription_id: str, tenant_id: str, kinds: list[str]) -> None:
    """One subscription row, written directly.

    ``create_subscription`` would encrypt a generated signing secret, which
    needs a master key and says nothing about routing; the question here is
    which tenant's deliveries appear.
    """
    session.add(
        models.WebhookSubscription(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            name=subscription_id,
            url="https://receiver.example/hook",
            enabled=True,
            event_kinds=kinds,
            headers={},
            transport="webhook",
            transport_config={},
            created_at=datetime.now(UTC).replace(tzinfo=None),
            updated_at=datetime.now(UTC).replace(tzinfo=None),
        )
    )


def _deliveries(settings) -> list[tuple[str, str]]:
    with get_session(settings.postgres_url) as session:
        rows = session.query(models.WebhookDelivery).all()
        return sorted((row.subscription_id, row.event_id) for row in rows)


def test_an_audit_event_is_queued_only_for_its_own_tenants_subscriptions(sqlite_settings):
    """A misrouted audit event is a disclosure, not a routing bug."""
    webhooks.configure(sqlite_settings)
    with get_session(sqlite_settings.postgres_url) as session:
        _subscribe(session, subscription_id="own", tenant_id="acme", kinds=["audit.*"])
        _subscribe(session, subscription_id="other", tenant_id="globex", kinds=["audit.*"])
        _subscribe(session, subscription_id="assets", tenant_id="acme", kinds=["new_cve"])

    created = webhooks.enqueue_event(_envelope())

    assert len(created) == 1
    assert _deliveries(sqlite_settings) == [("own", "ev-audit-1")]


def test_a_platform_level_audit_event_reaches_no_webhook(sqlite_settings):
    """No tenant owns it, so there is no subscription that may be sent it."""
    webhooks.configure(sqlite_settings)
    with get_session(sqlite_settings.postgres_url) as session:
        _subscribe(session, subscription_id="own", tenant_id="acme", kinds=["audit.*"])

    assert webhooks.enqueue_event(_envelope(tenant_id=None)) == []
    assert _deliveries(sqlite_settings) == []


def test_a_redelivered_audit_event_does_not_page_anyone_twice(sqlite_settings):
    """Both sources are at-least-once; the queue is where that stops."""
    webhooks.configure(sqlite_settings)
    with get_session(sqlite_settings.postgres_url) as session:
        _subscribe(session, subscription_id="own", tenant_id="acme", kinds=["audit.*"])

    webhooks.enqueue_event(_envelope())
    assert webhooks.enqueue_event(_envelope()) == []
    assert len(_deliveries(sqlite_settings)) == 1


# --------------------------------------------------------------------------- #
# The forwarder: what it acknowledges, and when it reconnects
# --------------------------------------------------------------------------- #


class _FakeSocket:
    """Records what was written, and can be told to fail the next write."""

    def __init__(self, *, fail_writes: int = 0) -> None:
        self.written: list[bytes] = []
        self.closed = False
        self._fail_writes = fail_writes

    def sendall(self, payload: bytes) -> None:
        if self._fail_writes > 0:
            self._fail_writes -= 1
            raise OSError("connection reset by peer")
        self.written.append(payload)

    def close(self) -> None:
        self.closed = True


class _Msg:
    """Minimal stand-in for a JetStream message, like tests/test_webhook_worker.py."""

    def __init__(self, payload: bytes, subject: str = "events.audit.acme") -> None:
        self.data = payload
        self.subject = subject
        self.acked = False
        self.naked = False
        self.termed = False

    async def ack(self) -> None:
        self.acked = True

    async def nak(self) -> None:
        self.naked = True

    async def term(self) -> None:
        self.termed = True


def _config(**env) -> forwarder.ForwarderConfig:
    base = {
        "OCTO_AUDIT_SYSLOG_URL": "tls://siem.example:6514",
        "OCTO_AUDIT_SYSLOG_HOSTNAME": "api",
        # The default source is ``nats``, and validate() refuses that without a
        # broker; a test about the *target* URL should not have to say so.
        "OCTO_NATS_URL": "nats://broker:4222",
    }
    base.update(env)
    return forwarder.ForwarderConfig(base)


def _audit_row(resource_id: str, occurred_at: datetime | None = None) -> "models.AuditEvent":
    """One committed-looking audit row. ``occurred_at`` is naive UTC, as stored."""
    return models.AuditEvent(
        occurred_at=occurred_at or datetime.now(UTC).replace(tzinfo=None),
        tenant_id="acme",
        actor="admin",
        actor_type="user",
        action="user.create",
        resource_type="user",
        resource_id=resource_id,
    )


def _db_config(settings) -> forwarder.ForwarderConfig:
    """``db`` mode over the test's SQLite file, reading with no lag.

    The lag exists to cover ids that are assigned at INSERT and become visible
    at COMMIT; a test that writes its rows and then reads them would otherwise
    have to sleep through it for no guarantee.
    """
    return _config(
        OCTO_AUDIT_SYSLOG_SOURCE="db",
        OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS="0",
        OCTO_POSTGRES_URL=settings.postgres_url,
    )


def _source(sockets: list[_FakeSocket]) -> tuple[forwarder.NatsSource, forwarder.SyslogClient]:
    config = _config()
    client = forwarder.SyslogClient(config, connector=lambda: sockets.pop(0))
    source = forwarder.NatsSource(config=config, nats_url="nats://unused", client=client)
    # Nothing in these tests should sleep out a reconnect backoff.
    source._stop.set()
    return source, client


def test_an_event_the_socket_took_is_acked():
    sock = _FakeSocket()
    source, _client = _source([sock])
    msg = _Msg(json.dumps(_envelope()).encode("utf-8"))

    asyncio.run(source.handle_msg(msg))

    assert (msg.acked, msg.naked, msg.termed) == (True, False, False)
    assert len(sock.written) == 1
    assert b"CEF:0|Shapoclyack|api|" in sock.written[0]
    assert source.stats == {"messages": 1, "sent": 1, "nak": 0, "errors": 0}


def test_an_event_the_receiver_refused_is_naked_not_acked():
    """The one failure an audit feed must not have: a silent drop."""
    source, _client = _source([_FakeSocket(fail_writes=1)])
    msg = _Msg(json.dumps(_envelope()).encode("utf-8"))

    asyncio.run(source.handle_msg(msg))

    assert (msg.acked, msg.naked) == (False, True)
    assert source.stats["nak"] == 1


def test_a_failed_write_closes_the_socket_and_the_next_send_reconnects():
    broken, fresh = _FakeSocket(fail_writes=1), _FakeSocket()
    source, client = _source([broken, fresh])
    payload = json.dumps(_envelope()).encode("utf-8")

    asyncio.run(source.handle_msg(_Msg(payload)))
    assert broken.closed and not client.connected

    second = _Msg(payload)
    asyncio.run(source.handle_msg(second))
    assert second.acked
    assert len(fresh.written) == 1


def test_a_target_that_will_not_accept_a_connection_is_retried_not_crashed():
    def _refuse():
        raise ConnectionRefusedError("nobody is listening")

    client = forwarder.SyslogClient(_config(), connector=_refuse)
    assert client.send(b"1 x") is False
    assert not client.connected


def test_an_unparseable_message_is_terminated_rather_than_redelivered_forever():
    source, _client = _source([_FakeSocket()])
    msg = _Msg(b"not json")

    asyncio.run(source.handle_msg(msg))

    assert (msg.acked, msg.naked, msg.termed) == (False, False, True)
    assert source.stats["errors"] == 1


# --------------------------------------------------------------------------- #
# Forwarder configuration
# --------------------------------------------------------------------------- #


def test_udp_is_refused_with_a_reason_rather_than_half_implemented():
    with pytest.raises(ValueError, match="nothing to acknowledge"):
        _config(OCTO_AUDIT_SYSLOG_URL="udp://siem.example:514").validate()


def test_plain_tcp_is_allowed_because_some_installations_tunnel_it():
    _config(OCTO_AUDIT_SYSLOG_URL="tcp://siem.example:514").validate()


def test_an_unset_target_refuses_at_startup_instead_of_silently_forwarding_nothing():
    with pytest.raises(ValueError, match="OCTO_AUDIT_SYSLOG_URL"):
        _config(OCTO_AUDIT_SYSLOG_URL="").validate()


def test_an_empty_client_certificate_file_is_refused_at_startup(tmp_path):
    """The k8s example mounts three keys from one Secret, and an installation
    whose SIEM wants no client certificate leaves two of them empty — a file
    that exists and is zero bytes. Without this the TLS handshake fails inside
    the retry loop and the pod reconnects forever, logging a network problem
    for a configuration mistake."""
    blank = tmp_path / "client.pem"
    blank.write_bytes(b"")
    with pytest.raises(ValueError, match="is empty"):
        _config(OCTO_AUDIT_SYSLOG_CERT=str(blank)).validate()


def test_a_certificate_path_that_is_not_there_is_refused_at_startup(tmp_path):
    with pytest.raises(ValueError, match="is not a file"):
        _config(OCTO_AUDIT_SYSLOG_CA=str(tmp_path / "absent.pem")).validate()


def test_a_key_without_a_certificate_is_refused(tmp_path):
    key = tmp_path / "client.key"
    key.write_text("-----BEGIN PRIVATE KEY-----\n")
    with pytest.raises(ValueError, match="OCTO_AUDIT_SYSLOG_CERT"):
        _config(OCTO_AUDIT_SYSLOG_KEY=str(key)).validate()


def test_the_nats_source_says_which_variable_to_set_when_there_is_no_broker():
    config = _config(OCTO_NATS_URL="")
    with pytest.raises(ValueError, match="OCTO_AUDIT_SYSLOG_SOURCE=db"):
        forwarder.build_source(config, forwarder.SyslogClient(config))


def test_the_database_source_says_which_variable_it_needs():
    config = _config(OCTO_AUDIT_SYSLOG_SOURCE="db", OCTO_POSTGRES_URL="")
    with pytest.raises(ValueError, match="OCTO_POSTGRES_URL"):
        forwarder.build_source(config, forwarder.SyslogClient(config))


def test_the_forwarder_reads_its_own_environment_rather_than_the_api_contract(monkeypatch):
    """``load_settings`` under OCTO_ENV=prod demands a JWT secret, a CORS list and
    a base URL — none of which this process has any use for. Building a source
    with only the forwarder's own variables present is the assertion (#328)."""
    for name in ("OCTO_JWT_SECRET", "OCTO_CORS_ORIGINS", "OCTO_PUBLIC_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OCTO_ENV", "prod")
    config = _config(OCTO_NATS_URL="nats://broker:4222")
    source = forwarder.build_source(config, forwarder.SyslogClient(config))
    assert isinstance(source, forwarder.NatsSource)


# --------------------------------------------------------------------------- #
# The database source
# --------------------------------------------------------------------------- #


def test_the_database_source_forwards_oldest_first_and_keeps_its_place(sqlite_settings):
    sock = _FakeSocket()
    config = _db_config(sqlite_settings)
    client = forwarder.SyslogClient(config, connector=lambda: sock)
    source = forwarder.DatabaseSource(config=config, client=client)

    # Both behind the horizon, amy the older of the two: a SIEM reads a feed
    # oldest first, and the lag window would hide a row stamped in the future.
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(sqlite_settings.postgres_url) as session:
        for offset, name in enumerate(("amy", "bob")):
            session.add(_audit_row(name, now - timedelta(seconds=10 - offset)))

    assert source.forward_once() == 2
    assert [b"cs3=amy" in line for line in sock.written] == [True, False]
    # The cursor moved, so a second pass over the same rows sends nothing.
    assert source.forward_once() == 0
    assert len(sock.written) == 2


def test_a_row_committed_out_of_id_order_is_not_skipped_forever(sqlite_settings):
    """The failure a cursor on ``id`` alone has, and this one must not.

    Two concurrent requests can take their ids in one order and commit in the
    other: request A records at 12:00:00 and commits at 12:00:20 (id 2,
    occurred_at 12:00:00), request B records and commits at 12:00:10 (id 1,
    occurred_at 12:00:10). A reader that filtered on ``occurred_at`` but moved
    a cursor on ``id`` would forward id 2 — the only one past its lag horizon —
    set the cursor to 2, and then read ``id > 2`` for the rest of the
    installation's life. Row 1 would be a `user.delete` the SIEM never hears
    about and nothing ever reports as missing.

    Ordering by ``(occurred_at, id)`` and keying the cursor on the same pair is
    what makes "not yet visible" mean "not yet past the cursor".
    """
    sock = _FakeSocket()
    # A lag the fixture's timestamps sit either side of, so the horizon really
    # does hide one row on the first pass.
    config = _config(
        OCTO_AUDIT_SYSLOG_SOURCE="db",
        OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS="10",
        OCTO_POSTGRES_URL=sqlite_settings.postgres_url,
    )
    client = forwarder.SyslogClient(config, connector=lambda: sock)
    source = forwarder.DatabaseSource(config=config, client=client)

    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(sqlite_settings.postgres_url) as session:
        # id 1 is the *younger* row: recorded 5s ago, so inside the lag window.
        session.add(_audit_row("late-committer", now - timedelta(seconds=5)))
        session.flush()
        # id 2 is the older one: recorded 60s ago by a request that took a
        # minute to commit, so already past the horizon.
        session.add(_audit_row("long-transaction", now - timedelta(seconds=60)))

    assert source.forward_once() == 1, "only the row past the lag horizon"
    assert b"cs3=long-transaction" in sock.written[0]

    # Once the second row ages past the horizon it is still ahead of the
    # cursor, because the cursor is a timestamp first and an id second.
    source._config.db_lag_seconds = 0
    assert source.forward_once() == 1
    assert b"cs3=late-committer" in sock.written[1]
    assert source.forward_once() == 0


def test_the_database_cursor_does_not_advance_over_a_refused_row(sqlite_settings):
    """A cursor may only pass rows the SIEM actually has."""
    config = _db_config(sqlite_settings)
    client = forwarder.SyslogClient(config, connector=lambda: _FakeSocket(fail_writes=99))
    source = forwarder.DatabaseSource(config=config, client=client)
    source._stop.set()

    with get_session(sqlite_settings.postgres_url) as session:
        session.add(_audit_row("amy"))

    assert source.forward_once() == 0
    with get_session(sqlite_settings.postgres_url) as session:
        cursor = session.get(models.AuditForwardCursor, forwarder.CURSOR_NAME)
        assert cursor is not None and cursor.last_id == 0
