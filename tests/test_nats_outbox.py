"""The outbox behind a relaxed NATS readiness policy (review 2026-09-18, P2).

Two defects at once, and the tests are split the same way:

* ``publish_raw_results`` returned ``published=false`` and nobody looked, so a
  broker outage turned into an upload answered 200 whose ingest message was
  gone. Everything below the first divider is about that message surviving.
* NATS decided ``/readyz``, so the same outage emptied the Service of every API
  replica. That half is in ``tests/test_api_probes.py``, because it is a
  statement about the probes; the ``ingest_backlog`` check that replaced it
  reads the counts this module tests.
"""

from __future__ import annotations

import io
import tarfile
from datetime import UTC, datetime, timedelta

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import nats_bus, nats_outbox, results_ingest
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres

NATS_URL = "nats://nats.invalid:4222"


def _archive(data: bytes = b'{"ok":true}\n') -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="findings.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeBus:
    """A broker that accepts, or refuses, whatever is published to it."""

    def __init__(self, *, accepts: bool = True) -> None:
        self.accepts = accepts
        self.published: list[tuple[str, str]] = []

    def publish_ingest(self, payload, *, msg_id):
        self.published.append((str(payload.get("job_id")), msg_id))
        return self.accepts

    def publish_json(self, subject, payload, *, msg_id=None, headers=None):
        self.published.append((subject, str(msg_id)))
        return self.accepts


@pytest.fixture(autouse=True)
def _clean_outbox(tmp_path):
    """The table is not in ``reset_service_state``'s sweep, so clear it here."""
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    with get_session(settings.postgres_url) as session:
        session.query(models.NatsOutboxEntry).delete()
    yield
    with get_session(settings.postgres_url) as session:
        session.query(models.NatsOutboxEntry).delete()


def _entries(settings) -> list[models.NatsOutboxEntry]:
    with get_session(settings.postgres_url) as session:
        rows = session.query(models.NatsOutboxEntry).all()
        session.expunge_all()
        return rows


def test_a_refused_ingest_publish_is_written_down(tmp_path, monkeypatch):
    """The defect: with NATS unreachable the upload succeeded and the message
    for the analytical projection simply did not exist anywhere."""
    nats_bus.reset_bus_for_tests()
    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: None)
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    archive = _archive()

    result = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-1",
        run_id="run-1",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=archive,
        tenant_id="default",
    )

    assert result["published"] is False
    assert result["outbox_id"]
    rows = _entries(settings)
    assert len(rows) == 1
    assert rows[0].kind == nats_outbox.KIND_INGEST
    assert rows[0].job_id == "job-1"
    assert rows[0].run_id == "run-1"
    assert rows[0].msg_id == result["msg_id"]
    # The body, not a reference to rebuild it from: the run's files may be
    # retained away long before the broker comes back.
    assert rows[0].payload["archive_sha256"] == nats_bus.archive_sha256(archive)
    assert rows[0].payload["archive_b64"]


def test_a_successful_publish_records_nothing(tmp_path, monkeypatch):
    bus = FakeBus(accepts=True)
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: bus)
    settings = make_settings(tmp_path, nats_url=NATS_URL)

    result = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-2",
        run_id="run-2",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    assert result["published"] is True
    assert "outbox_id" not in result
    assert _entries(settings) == []


def test_the_same_message_is_recorded_once(tmp_path, monkeypatch):
    """A sensor retrying its upload, or a second replica failing the same
    publish, owes the stream one message — not two runs to ingest."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    archive = _archive()

    first = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-3",
        run_id="run-3",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=archive,
        tenant_id="default",
    )
    second = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-3",
        run_id="run-3",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=archive,
        tenant_id="default",
    )

    assert first["outbox_id"] == second["outbox_id"]
    assert len(_entries(settings)) == 1


def test_the_backlog_is_republished_when_the_broker_returns(tmp_path, monkeypatch):
    """Recovery, which is the condition the review put on relaxing readiness:
    the run reaches analytics without being scanned again."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-4",
        run_id="run-4",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    bus = FakeBus(accepts=True)
    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: bus)
    outcome = nats_outbox.reconcile_once(settings)

    assert outcome == {"republished": 1, "failed": 0, "dead": 0}
    assert [job for job, _ in bus.published] == ["job-4"]
    # Deleted, not kept: the body is megabytes of base64 and the stream now has it.
    assert _entries(settings) == []


def test_a_broker_that_is_still_down_keeps_the_row_and_backs_off(tmp_path, monkeypatch):
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-5",
        run_id="run-5",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    bus = FakeBus(accepts=False)
    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: bus)
    now = datetime.now(UTC).replace(tzinfo=None)
    outcome = nats_outbox.reconcile_once(settings, now=now)

    assert outcome == {"republished": 0, "failed": 1, "dead": 0}
    row = _entries(settings)[0]
    assert row.status == nats_outbox.STATUS_PENDING
    assert row.attempts == 1
    assert row.next_attempt_at > now
    # And a second pass before that deadline claims nothing at all.
    assert nats_outbox.reconcile_once(settings, now=now) == {
        "republished": 0,
        "failed": 0,
        "dead": 0,
    }


def test_a_broker_that_is_not_back_yet_spends_no_attempt(tmp_path, monkeypatch):
    """A tick against a broker that is still gone has refused nothing. Counting
    it would retire the backlog on the timer alone — a long enough outage would
    dead-letter every entry without one publish having been tried."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-10",
        run_id="run-10",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: None)
    assert nats_outbox.reconcile_once(settings) == {
        "republished": 0,
        "failed": 0,
        "dead": 0,
    }
    row = _entries(settings)[0]
    assert row.attempts == 0
    assert row.status == nats_outbox.STATUS_PENDING


def test_a_row_that_exhausts_its_attempts_goes_dead_and_is_requeueable(tmp_path, monkeypatch):
    """The DLQ half: a broker down longer than the retries cover leaves rows
    nobody will pick up again, and that has to be a decision an operator can
    see and reverse — not a silent expiry."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL, nats_outbox_max_attempts=2)
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-6",
        run_id="run-6",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    bus = FakeBus(accepts=False)
    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: bus)
    now = datetime.now(UTC).replace(tzinfo=None)
    nats_outbox.reconcile_once(settings, now=now)
    outcome = nats_outbox.reconcile_once(settings, now=now + timedelta(hours=1))

    assert outcome == {"republished": 0, "failed": 0, "dead": 1}
    assert _entries(settings)[0].status == nats_outbox.STATUS_DEAD
    assert nats_outbox.backlog(settings)["dead"] == 1

    assert nats_outbox.requeue_dead(settings) == 1
    bus.accepts = True
    assert nats_outbox.reconcile_once(settings)["republished"] == 1


def test_backlog_counts_what_health_reads(tmp_path, monkeypatch):
    """``is_backlogged`` is what turns `/api/health` degraded, so it has to
    distinguish a broker restart from analytics that are not catching up."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(
        tmp_path, nats_url=NATS_URL, nats_outbox_backlog_alert_seconds=300
    )
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-7",
        run_id="run-7",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    counts = nats_outbox.backlog(settings)
    assert counts["pending"] == 1
    assert counts["stale"] == 0
    # Fresh: one message owed during a broker restart is not yet a state an
    # operator has to be told about.
    assert nats_outbox.is_backlogged(settings) is False

    with get_session(settings.postgres_url) as session:
        row = session.query(models.NatsOutboxEntry).one()
        row.created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=3600)

    assert nats_outbox.backlog(settings)["stale"] == 1
    assert nats_outbox.is_backlogged(settings) is True


def test_a_disabled_outbox_says_so_instead_of_pretending(tmp_path, monkeypatch, caplog):
    """The only configuration in which a refused publish is still lost, and it
    is loud about it — an operator who turned the outbox off is choosing to
    re-scan rather than keep the bodies."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL, nats_outbox_enabled=False)

    with caplog.at_level("ERROR", logger="shapoclyack.nats-outbox"):
        result = nats_outbox.publish_ingest_or_record(
            settings,
            job_id="job-8",
            run_id="run-8",
            agent_id="agent-1",
            exit_code=0,
            archive_bytes=_archive(),
            tenant_id="default",
        )

    assert result["outbox_id"] is None
    assert _entries(settings) == []
    assert "the outbox is disabled" in caplog.text


def test_an_invalid_archive_still_raises_before_anything_is_recorded(tmp_path, monkeypatch):
    """Unchanged contract for the caller: a bad archive is a 400, not a row in
    a retry queue that will fail forever."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)

    with pytest.raises(results_ingest.IngestError):
        nats_outbox.publish_ingest_or_record(
            settings,
            job_id="job-9",
            run_id="run-9",
            agent_id="agent-1",
            exit_code=0,
            archive_bytes=b"not a tar.gz",
            tenant_id="default",
        )
    assert _entries(settings) == []
