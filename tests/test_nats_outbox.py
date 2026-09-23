"""The outbox behind a relaxed NATS readiness policy (review 2026-09-18, P2).

Two defects at once, and the tests are split the same way:

* ``publish_raw_results`` returned ``published=false`` and nobody looked, so a
  broker outage turned into an upload answered 200 whose ingest message was
  gone. Everything below the first divider is about that message surviving.
* NATS decided ``/readyz``, so the same outage emptied the Service of every API
  replica. That half is in ``tests/test_api_probes.py``, because it is a
  statement about the probes; the ``nats_outbox`` check that replaced it
  reads the counts this module tests.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
from datetime import UTC, datetime, timedelta

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import asset_events, nats_bus, nats_outbox, results_ingest
from api.services import jobs as jobs_service
from api.services.artifact_store import workspace as artifact_workspace
from scanner.pipeline.asset_identity import ip_identity_key
from tests.conftest import (
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

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
    """Empty both durable queues around each test in this module.

    ``tenants.reset_for_tests`` sweeps them for a test that builds a client;
    most of the tests here call the service directly with a ``make_settings``
    of their own and never reach it.
    """
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    with get_session(settings.postgres_url) as session:
        session.query(models.NatsOutboxEntry).delete()
        session.query(models.RunPublication).delete()
    yield
    with get_session(settings.postgres_url) as session:
        session.query(models.NatsOutboxEntry).delete()
        session.query(models.RunPublication).delete()


_AGENT_HEADERS = {"Authorization": "Bearer test-agent-token"}


def _claimed_job(client) -> tuple[str, str, str]:
    """Register a sensor, queue a job and claim it — the state before an upload."""
    agent_id = client.post(
        "/api/agent/register", headers=_AGENT_HEADERS, json={"hostname": "worker"}
    ).json()["agent_id"]
    operator = {"Authorization": f"Bearer {login(client, 'operator')}"}
    job = client.post(
        "/api/jobs",
        headers=operator,
        json={
            "mode": "safe",
            "skip_nse": True,
            "ranges": "127.0.0.1\n",
            "domains": "\n",
            "ports": "80\n",
        },
    ).json()
    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_AGENT_HEADERS
    )
    assert claimed.status_code == 200
    return agent_id, job["job_id"], job["run_id"]


def _entries(settings) -> list[models.NatsOutboxEntry]:
    with get_session(settings.postgres_url) as session:
        rows = session.query(models.NatsOutboxEntry).all()
        session.expunge_all()
        return rows


def _publications(settings) -> list[models.RunPublication]:
    """Runs still owed a publication — empty once the bus hop has been settled."""
    with get_session(settings.postgres_url) as session:
        rows = session.query(models.RunPublication).all()
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
    """The only configuration in which a refused publish can still be lost, and
    it says so — an operator who turned the outbox off is choosing to re-scan
    rather than keep the bodies.

    WARNING rather than ERROR, and the sentence is hedged, because one refusal
    here is not yet a loss: the publication itself then fails and retries
    (``OCTO_RUN_PUBLICATION_MAX_ATTEMPTS``), so a broker that blinked is
    covered by the next attempt. The ERROR belongs to the publication that
    ends ``dead``.
    """
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL, nats_outbox_enabled=False)

    with caplog.at_level("WARNING", logger="shapoclyack.nats-outbox"):
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
    # Not the "lost forever" it used to claim, which paged for a message the
    # publication's second attempt delivers fifteen seconds later.
    assert "only an outage that outlives those" in caplog.text


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


# --------------------------------------------------------------------------
# The production path.
#
# Everything above calls ``publish_ingest_or_record`` itself with the bus
# monkeypatched away, which proves the function works and says nothing about
# whether anything calls it. That gap is why the branch's central defect —
# nothing reaching the recorder at all — went green through ten tests. The
# ones below go through the real callers: the HTTP probe, the reconciler
# thread the app starts, and the upload route a sensor actually uses.
# --------------------------------------------------------------------------


def _record_one(settings, *, job_id: str, age: timedelta | None = None) -> str:
    """One recorded refusal, optionally backdated past the alert window."""
    outbox_id = nats_outbox.record_failed_publish(
        settings,
        kind=nats_outbox.KIND_INGEST,
        subject=nats_bus.ingest_results_subject("default"),
        msg_id=f"msg-{job_id}",
        payload={"job_id": job_id, "tenant_id": "default", "archive_b64": "x"},
        tenant_id="default",
        job_id=job_id,
        run_id=f"run-{job_id}",
    )
    if age is not None:
        with get_session(settings.postgres_url) as session:
            row = session.get(models.NatsOutboxEntry, outbox_id)
            row.created_at = datetime.now(UTC).replace(tzinfo=None) - age
    return outbox_id


@requires_postgres
def test_readyz_reports_a_backlog_that_is_actually_in_the_table(tmp_path, monkeypatch):
    """The probe, over HTTP, reading rows — not a patched ``_backlogged``.

    ``test_an_unrecovered_publish_backlog_is_its_own_check`` patches the
    detector out and so checks only that the check is wired into the report.
    This one leaves every layer in place: route → ``health.check_readiness`` →
    ``nats_outbox.backlog`` → Postgres. The broker is honestly unreachable, so
    ``nats`` is ``error`` too, and the reply is still 200 — that is the policy.
    """
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)
    client = configured_client(tmp_path, monkeypatch, nats_url=NATS_URL)
    settings = make_settings(tmp_path, nats_url=NATS_URL)

    clean = client.get("/readyz")
    assert clean.status_code == 200
    assert clean.json()["checks"]["nats_outbox"] == "ok"

    # Older than nats_outbox_backlog_alert_seconds: a broker restart is not a
    # backlog, an hour of unrecovered publications is.
    _record_one(settings, job_id="job-probe", age=timedelta(hours=1))

    response = client.get("/readyz")
    assert response.status_code == 200, "a backlog must not empty the Service"
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["nats_outbox"] == "error"
    assert body["checks"]["postgres"] == "ok"


@requires_postgres
def test_the_reconciler_thread_the_app_starts_drains_the_backlog(tmp_path, monkeypatch):
    """Through ``OutboxReconciler``, which is what ``api/app.py`` runs.

    ``reconcile_once`` is covered above; this is the object around it — the
    tick counting, the stats an operator reads, and the fact that a tick with
    the broker back deletes the row rather than merely reporting it.
    """
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    _record_one(settings, job_id="job-reconciler")

    bus = FakeBus(accepts=True)
    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: bus)
    reconciler = nats_outbox.OutboxReconciler(settings=settings, poll_interval_seconds=1.0)
    reconciler._tick()  # noqa: SLF001 - the timer body, without waiting for a timer

    assert reconciler.stats["ticks"] == 1
    assert reconciler.stats["republished"] == 1
    assert _entries(settings) == []


@requires_postgres
def test_a_refused_publish_at_upload_time_leaves_a_row_in_the_outbox(tmp_path, monkeypatch):
    """The whole point of the module, over the route a sensor actually uses.

    ``POST /api/agent/jobs/{id}/results`` with the broker down: the upload is
    answered 200 and the job succeeds — that part is the policy and is correct
    — and the ingest message must be in ``nats_outbox``, because otherwise the
    analytical projection has a permanent hole that no probe reports.

    The publication that owns the bus hop must close all the same: the run's
    artifacts, its assets and its findings are not the broker's business, and
    a ``run_publications`` row still owing this run would mean they are.
    """
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    client = configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", nats_url=NATS_URL
    )
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    agent_id, job_id, run_id = _claimed_job(client)

    upload = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_AGENT_HEADERS,
        data={"agent_id": agent_id, "exit_code": "0", "run_id": run_id},
        files={"archive": ("run.tar.gz", _archive(), "application/gzip")},
    )
    assert upload.status_code == 200

    rows = _entries(settings)
    assert len(rows) == 1, (
        f"a refused ingest publish left {len(rows)} outbox rows: the run is complete "
        "everywhere except analytics, and nothing will replay it"
    )
    assert rows[0].job_id == job_id
    assert rows[0].run_id == run_id
    assert rows[0].status == nats_outbox.STATUS_PENDING
    assert _publications(settings) == [], (
        "the run's publication is still owed, so a broker outage is holding the "
        "object store, the run directory and the job's own projections hostage"
    )


@requires_postgres
def test_the_outbox_being_off_keeps_the_publication_open(tmp_path, monkeypatch):
    """``OCTO_NATS_OUTBOX_ENABLED=false``: nothing durable, so nothing closed.

    The one configuration that still loses the message. It must not lose it
    *quietly*: with nowhere to write the refusal down, the bus hop fails, the
    publication stays owed and retries, and the operator gets a ``dead`` row
    and a note on the job instead of a green health check over a hole.
    """
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    client = configured_client(
        tmp_path,
        monkeypatch,
        job_execution_mode="agent",
        nats_url=NATS_URL,
        nats_outbox_enabled=False,
    )
    settings = make_settings(tmp_path, nats_url=NATS_URL, nats_outbox_enabled=False)
    agent_id, job_id, run_id = _claimed_job(client)

    upload = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_AGENT_HEADERS,
        data={"agent_id": agent_id, "exit_code": "0", "run_id": run_id},
        files={"archive": ("run.tar.gz", _archive(), "application/gzip")},
    )
    assert upload.status_code == 200

    assert _entries(settings) == []
    owed = _publications(settings)
    assert len(owed) == 1, (
        "a refused publish with the outbox disabled was reported as published: "
        "the ingest message is gone and nothing owes anybody an explanation"
    )
    assert owed[0].job_id == job_id


@requires_postgres
def test_a_recorded_message_is_dropped_when_a_later_attempt_delivers_it(
    tmp_path, monkeypatch
):
    """One message on the bus, not two, when the retry beats the reconciler.

    The replica that records a refusal can die before it closes the
    publication out, and the reconciler then replays the same hop — which the
    broker may well accept this time. Both the outbox row and that publish
    describe one run, so leaving the row behind puts the run on the stream a
    second time whenever the reconciler gets to it after the stream's duplicate
    window has passed.
    """
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    first = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-twice",
        run_id="run-twice",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )
    assert first["outbox_id"] is not None
    assert len(_entries(settings)) == 1

    bus = FakeBus(accepts=True)
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: bus)
    second = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-twice",
        run_id="run-twice",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_archive(),
        tenant_id="default",
    )

    assert second["published"] is True
    assert second["msg_id"] == first["msg_id"]
    assert _entries(settings) == [], (
        "the delivered message is still recorded, so the reconciler will put the "
        "same run on the stream a second time"
    )


# --------------------------------------------------------------------------
# The dead end, the claim window and the partial publish.
# --------------------------------------------------------------------------


def _big_archive() -> bytes:
    """An archive past ``results_ingest``'s inline cap, so no body is carried.

    Random bytes on purpose: the cap is on the *compressed* archive, and a
    repetitive 5 MB payload gzips down to a few kilobytes.
    """
    archive = _archive(os.urandom(5 * 1024 * 1024))
    # ``build_gateway_payload``'s max_inline_bytes default.
    assert len(archive) > 4_000_000
    return archive


@requires_postgres
def test_an_archive_too_large_to_replay_is_dead_on_arrival(tmp_path, monkeypatch):
    """The health signal that lies in the cheerful direction.

    Over the 4 MB cap ``build_gateway_payload`` sets ``archive_inline: false``
    and carries no body. Queued as ``pending``, such a row is republished, the
    broker accepts the body-less message, the republish counts as a success and
    the row is deleted — backlog zero, ``/api/health`` green, ClickHouse empty.
    Recorded ``dead`` instead: it needs a decision, not a retry.
    """
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)

    result = nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-big",
        run_id="run-big",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_big_archive(),
        tenant_id="default",
    )

    rows = _entries(settings)
    assert len(rows) == 1
    assert rows[0].payload.get("archive_inline") is False
    assert rows[0].status == nats_outbox.STATUS_DEAD
    assert rows[0].next_attempt_at is None
    assert result["outbox_id"] == rows[0].outbox_id
    # Dead counts as a backlog, so the operator is told rather than reassured.
    assert nats_outbox.is_backlogged(settings) is True


@requires_postgres
def test_requeue_leaves_a_body_it_cannot_replay_alone(tmp_path, monkeypatch):
    """...and the reconciler is never handed it either, so it cannot be
    'recovered' into a green check over an empty projection."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-big-2",
        run_id="run-big-2",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_big_archive(),
        tenant_id="default",
    )

    assert nats_outbox.requeue_dead(settings) == 0

    bus = FakeBus(accepts=True)
    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: bus)
    assert nats_outbox.reconcile_once(settings) == {
        "republished": 0,
        "failed": 0,
        "dead": 0,
    }
    assert bus.published == []
    assert [row.status for row in _entries(settings)] == [nats_outbox.STATUS_DEAD]


@requires_postgres
def test_discard_is_the_only_other_way_out_of_dead(tmp_path, monkeypatch):
    """``dead`` had one exit and it did not always work.

    ``is_backlogged`` is True while any row is ``dead``, nothing deletes such a
    row, and ``requeue_dead`` cannot help the ones with no body — so
    ``/api/health`` stayed degraded forever with no command to end it. An
    operator who has decided the run is not coming back needs to say so; a
    pending row is still the reconciler's and must survive.
    """
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    _record_one(settings, job_id="job-pending")
    nats_outbox.publish_ingest_or_record(
        settings,
        job_id="job-big-3",
        run_id="run-big-3",
        agent_id="agent-1",
        exit_code=0,
        archive_bytes=_big_archive(),
        tenant_id="default",
    )
    assert nats_outbox.backlog(settings) == {"pending": 1, "dead": 1, "stale": 0}

    assert nats_outbox.discard_dead(settings) == 1

    assert nats_outbox.backlog(settings) == {"pending": 1, "dead": 0, "stale": 0}
    assert [row.job_id for row in _entries(settings)] == ["job-pending"]
    assert nats_outbox.is_backlogged(settings) is False


@requires_postgres
def test_the_claim_window_covers_the_whole_batch_not_one_row(tmp_path, monkeypatch):
    """Two replicas must not publish the same megabytes at once.

    ``reconcile_once`` commits the claim — releasing the locks — and only then
    publishes the rows one at a time, so the last row of a batch waits out
    every row before it. A flat 30 s window expired mid-batch and a peer
    claimed the same rows: doubled traffic, doubled ``attempts``, duplicates on
    the stream. Asserted on the window rather than by racing two reconcilers,
    because the defect needs a batch slower than 30 s to show up in wall time.
    """
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    for index in range(3):
        _record_one(settings, job_id=f"job-batch-{index}")

    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        claimed = nats_outbox._claim_due(  # noqa: SLF001 - the claim is the subject
            session, now=now, limit=10, settings=settings
        )
        deadlines = [row.next_attempt_at for row in claimed]

    assert len(claimed) == 3
    per_row = max(30, settings.nats_outbox_retry_base_seconds)
    assert deadlines == [now + timedelta(seconds=per_row * 3)] * 3


def test_mixed_backlog_reserves_half_the_batch_for_ingest(tmp_path, monkeypatch):
    """A thousand old webhook events must not hide the next run publication."""
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    envelopes = [
        {
            "kind": "new_cve",
            "tenant_id": "default",
            "event_id": f"event-priority-{index}",
        }
        for index in range(6)
    ]
    assert nats_outbox.record_undelivered_asset_events(settings, envelopes) == 6
    for index in range(3):
        _record_one(settings, job_id=f"job-priority-{index}")

    now = datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=1)
    with get_session(settings.postgres_url) as session:
        claimed = nats_outbox._claim_due(  # noqa: SLF001 - claim policy is the subject
            session, now=now, limit=4, settings=settings
        )
        kinds = [row.kind for row in claimed]

    assert kinds == [
        nats_outbox.KIND_INGEST,
        nats_outbox.KIND_INGEST,
        nats_outbox.KIND_ASSET_EVENT,
        nats_outbox.KIND_ASSET_EVENT,
    ]


def test_backlog_and_gauge_are_split_by_kind(tmp_path, monkeypatch):
    monkeypatch.setattr(results_ingest.nats_bus, "get_bus", lambda url: None)
    settings = make_settings(
        tmp_path, nats_url=NATS_URL, nats_outbox_backlog_alert_seconds=300
    )
    _record_one(settings, job_id="job-kind-metric")
    nats_outbox.record_undelivered_asset_events(
        settings,
        [
            {
                "kind": "new_cve",
                "tenant_id": "default",
                "event_id": "event-kind-metric",
            }
        ],
    )
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        for row in session.query(models.NatsOutboxEntry).all():
            row.created_at = now - timedelta(hours=1)

    assert nats_outbox.backlog_by_kind(settings, now=now) == {
        nats_outbox.KIND_INGEST: {"pending": 1, "dead": 0, "stale": 1},
        nats_outbox.KIND_ASSET_EVENT: {"pending": 1, "dead": 0, "stale": 1},
    }

    nats_outbox._refresh_backlog_gauge(settings)  # noqa: SLF001

    for kind in (nats_outbox.KIND_INGEST, nats_outbox.KIND_ASSET_EVENT):
        assert nats_outbox.metrics_service.REGISTRY.get_sample_value(
            "octo_nats_outbox_backlog",
            {"kind": kind, "status": "stale"},
        ) == 1.0


def test_a_refused_legacy_subject_does_not_hold_the_run_back():
    """The deprecated copy must not be able to fail the publish.

    ``publish_ingest`` returned ``tenant and legacy``, so on an account whose
    per-subject permissions allow ``ingest.results.>`` and not the deprecated
    ``ingest.raw_results`` — an ordinary closed installation — *every* publish
    read as a failure. Every run was recorded, every row spent its attempts
    against a subject the broker was never going to accept, and hours later the
    backlog was ``dead`` and ``/api/health`` degraded, while the ClickHouse
    worker (bound to ``ingest.results.>``) had the runs all along.

    Nothing in this tree subscribes to the legacy subject; it is counted and
    logged instead.
    """
    bus = nats_bus.NatsBus.__new__(nats_bus.NatsBus)
    attempted: list[str] = []

    def _publish_json(subject, payload, *, msg_id=None, headers=None, retries=3):
        attempted.append(subject)
        return subject != nats_bus.SUBJECT_INGEST_RAW

    bus.publish_json = _publish_json
    refused_before = _legacy_count("refused")

    ok = bus.publish_ingest({"tenant_id": "default", "job_id": "job-legacy"}, msg_id="m")

    assert ok is True
    # Still attempted, and still counted: an operator who wants to retire the
    # copy needs to see that nothing outside the installation reads it either.
    assert attempted == [
        nats_bus.ingest_results_subject("default"),
        nats_bus.SUBJECT_INGEST_RAW,
    ]
    assert _legacy_count("refused") == refused_before + 1


def test_a_refused_tenant_subject_is_still_a_failed_publish():
    """The other half of the same flag, which the fix must not soften.

    The tenant subject is the one the ingest worker reads, so refusing it is
    exactly the case the outbox exists for — whatever the legacy copy did.
    """
    bus = nats_bus.NatsBus.__new__(nats_bus.NatsBus)

    def _publish_json(subject, payload, *, msg_id=None, headers=None, retries=3):
        return subject == nats_bus.SUBJECT_INGEST_RAW

    bus.publish_json = _publish_json

    assert bus.publish_ingest({"tenant_id": "default", "job_id": "job-t"}, msg_id="m") is False


def _legacy_count(outcome: str) -> float:
    from api.services import metrics as metrics_service

    return (
        metrics_service.REGISTRY.get_sample_value(
            "octo_nats_legacy_ingest_total", {"outcome": outcome}
        )
        or 0.0
    )


# ---------------------------------------------------------------------------
# Asset events: the row that used to have nowhere to wait.


def test_asset_events_a_dead_broker_refuses_are_kept_and_published_later(tmp_path, monkeypatch):
    """The cost the relaxed readiness policy would otherwise have introduced.

    Asset events are the only source of the webhook fan-out (``webhook_worker``
    is the sole caller of ``webhooks.enqueue_event``). While NATS blocked
    ``/readyz`` a broker outage took the replicas out of the Service, so the
    upload that produces these events was not accepted until the broker was
    back and the notification merely went out late. With the broker advisory
    the upload *is* accepted — and ``publish_events`` counted the envelopes
    ``skipped`` and moved on, so ``new_cve`` for that hour was never sent at
    all, with no alert anywhere.
    """
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    envelopes = [
        {
            "kind": "new_cve",
            "tenant_id": "default",
            "run_id": "run-ae",
            "job_id": "job-ae",
            "host": "10.0.0.1",
            "event_id": "event-ae-1",
        }
    ]
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)
    deferred_before = _asset_event_count("new_cve", "deferred")
    skipped_before = _asset_event_count("new_cve", "skipped")

    assert asset_events.publish_events(NATS_URL, envelopes, settings=settings) == 0

    # The two outcomes are the difference between a late webhook and one that
    # is never sent, and ``ShapoclyackAssetEventsSkipped`` pages on exactly one
    # of them — so a row in the table has to move ``deferred`` and leave
    # ``skipped`` where it was.
    assert _asset_event_count("new_cve", "deferred") == deferred_before + 1
    assert _asset_event_count("new_cve", "skipped") == skipped_before

    with get_session(settings.postgres_url) as session:
        rows = session.query(models.NatsOutboxEntry).all()
        recorded = [(r.kind, r.subject, r.msg_id, r.run_id, r.status) for r in rows]
    assert recorded == [
        (
            nats_outbox.KIND_ASSET_EVENT,
            nats_bus.asset_event_subject("default", "new_cve"),
            "event-ae-1",
            "run-ae",
            nats_outbox.STATUS_PENDING,
        )
    ]

    # And the reconciler puts it back on the stream the webhook worker reads,
    # through the same helper that would have sent it — not a raw publish.
    sent: list[dict] = []

    class _AssetBus:
        def publish_asset_event(self, envelope, **kwargs):
            sent.append(envelope)
            return True

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: _AssetBus())
    outcome = nats_outbox.reconcile_once(settings)

    assert outcome["republished"] == 1
    assert [envelope["event_id"] for envelope in sent] == ["event-ae-1"]
    with get_session(settings.postgres_url) as session:
        assert session.query(models.NatsOutboxEntry).count() == 0


def test_asset_events_without_the_outbox_are_still_counted_as_lost(tmp_path, monkeypatch):
    """``OCTO_NATS_OUTBOX_ENABLED=false`` keeps the old behaviour, loudly.

    ``skipped`` is the series ``ShapoclyackAssetEventsSkipped`` alerts on, and
    it has to stay distinct from ``deferred``: one is a notification that is
    late, the other one that is never sent.
    """
    settings = make_settings(tmp_path, nats_url=NATS_URL, nats_outbox_enabled=False)
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)
    skipped_before = _asset_event_count("new_cve", "skipped")
    deferred_before = _asset_event_count("new_cve", "deferred")

    asset_events.publish_events(
        NATS_URL,
        [{"kind": "new_cve", "tenant_id": "default", "event_id": "event-ae-2"}],
        settings=settings,
    )

    with get_session(settings.postgres_url) as session:
        assert session.query(models.NatsOutboxEntry).count() == 0
    assert _asset_event_count("new_cve", "skipped") == skipped_before + 1
    assert _asset_event_count("new_cve", "deferred") == deferred_before


def _asset_event_count(kind: str, outcome: str) -> float:
    from api.services import metrics as metrics_service

    return (
        metrics_service.REGISTRY.get_sample_value(
            "octo_asset_events_published_total", {"kind": kind, "outcome": outcome}
        )
        or 0.0
    )


def test_the_run_completion_path_hands_its_asset_events_to_the_outbox(tmp_path, monkeypatch):
    """The production call site, not ``publish_events`` called by hand.

    ``jobs._publish_asset_events_best_effort`` is the only place a finished
    run's events are published from, and the whole feature is the ``settings``
    it passes down: without that argument ``_hand_over`` counts the envelopes
    ``skipped`` and the table stays empty, which is the behaviour this change
    exists to end. Tested here rather than through an upload because this is
    the seam that can be refactored away without any other test noticing.
    """
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    run_dir = artifact_workspace.run_dir(settings, "run-jobs-ae", refresh=False)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "diff.json").write_text(
        json.dumps(
            {"events": [{"kind": "new_cve", "host": "10.0.0.7", "port": 443, "cve": "CVE-2024-7"}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)

    jobs_service._publish_asset_events_best_effort(  # noqa: SLF001
        settings, tenant_id="default", run_id="run-jobs-ae", job_id="job-jobs-ae"
    )

    with get_session(settings.postgres_url) as session:
        rows = session.query(models.NatsOutboxEntry).all()
        recorded = [(r.kind, r.subject, r.run_id, r.job_id, r.status) for r in rows]
    assert recorded == [
        (
            nats_outbox.KIND_ASSET_EVENT,
            nats_bus.asset_event_subject("default", "new_cve"),
            "run-jobs-ae",
            "job-jobs-ae",
            nats_outbox.STATUS_PENDING,
        )
    ]


def test_an_operator_decommission_waits_in_the_outbox_too(tmp_path, monkeypatch):
    """``PATCH /api/assets/{id}`` publishes after committing its own write.

    So a broker that is down owes this webhook a delay, not a loss: the asset
    row already says ``decommissioned`` and the subscriber that acts on it —
    stopping the on-call rotation for a retired host, say — would otherwise
    never hear. It used to be counted ``skipped``, which is the series that
    means "nowhere to wait" and would have named a configuration that was not
    the reason.
    """
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = make_settings(tmp_path, nats_url=NATS_URL)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.load_tenants(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    run_dir = settings.output_dir / "runs" / "run-decom"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(
        json.dumps([{"host": "10.0.2.11"}]), encoding="utf-8"
    )
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-decom")
    asset_id = ip_identity_key(tenant_id, "10.0.2.11")
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: None)

    updated = assets_service.update_asset(
        settings, tenant_id, asset_id, {"status": "decommissioned"}
    )

    assert updated["status"] == "decommissioned"
    with get_session(settings.postgres_url) as session:
        recorded = [
            (r.kind, r.subject, r.status)
            for r in session.query(models.NatsOutboxEntry).all()
        ]
    assert recorded == [
        (
            nats_outbox.KIND_ASSET_EVENT,
            nats_bus.asset_event_subject(tenant_id, "decommissioned_host"),
            nats_outbox.STATUS_PENDING,
        )
    ]


def test_a_row_a_peer_delivered_mid_flight_is_not_counted_as_republished(tmp_path, monkeypatch):
    """``_claim_due`` commits before publishing, so the row can go under us.

    A peer's ``_forget_recorded`` deletes a pending row whose message a later
    attempt delivered. ``_record_attempt`` already answered ``"gone"`` for
    that, but ``reconcile_once`` counted the pass as ``republished`` anyway and
    incremented the metric — a backlog reported as draining twice as fast as it
    is, which is the number an operator watches during an outage.
    """
    settings = make_settings(tmp_path, nats_url=NATS_URL)
    subject = nats_bus.ingest_results_subject("default")
    nats_outbox.record_failed_publish(
        settings,
        kind=nats_outbox.KIND_INGEST,
        subject=subject,
        msg_id="msg-gone",
        payload={"tenant_id": "default", "job_id": "job-gone"},
        tenant_id="default",
        job_id="job-gone",
        run_id="run-gone",
    )

    def _delivered_by_a_peer(bus, *, kind, subject, msg_id, payload):
        nats_outbox._forget_recorded(settings, subject=subject, msg_id=msg_id)  # noqa: SLF001
        return True

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: FakeBus())
    monkeypatch.setattr(nats_outbox, "_republish", _delivered_by_a_peer)

    outcome = nats_outbox.reconcile_once(settings)

    assert outcome == {"republished": 0, "failed": 0, "dead": 0}
    with get_session(settings.postgres_url) as session:
        assert session.query(models.NatsOutboxEntry).count() == 0
