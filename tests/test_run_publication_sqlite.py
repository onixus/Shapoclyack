"""The run publication's operator surface on the SQLite dev fallback (#425).

The lease is read on the database's clock, and ``clock_timestamp()`` is a
Postgres function: asked of SQLite it raised on every job card, on requeue and
discard, and on every lease renewal — which then never pushed the row's hold
forward, so the next tick took the row from the attempt still publishing it.
The fallback has one process and so one clock; it uses that.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from api.db import engine as db_engine
from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.services import run_publisher
from tests.conftest import make_settings


@pytest.fixture()
def sqlite_settings(tmp_path):
    db_engine.reset_for_tests()
    settings = make_settings(tmp_path, postgres_url=f"sqlite:///{tmp_path / 'dev.db'}")
    yield settings
    db_engine.reset_for_tests()


def _row(settings, *, status: str) -> str:
    now = run_publisher._now()  # noqa: SLF001
    with get_session(settings.postgres_url) as session:
        session.add(
            models.RunPublication(
                publication_id="pub-1",
                tenant_id="default",
                job_id="job-1",
                run_id="run-1",
                job_status="succeeded",
                staging_path="/nonexistent/.ingest-run-1",
                replica=settings.instance_id,
                status=status,
                attempts=1,
                claims=1,
                claims_base=0,
                fence=1,
                last_error="ArtifactStoreError: bucket unreachable",
                next_attempt_at=now,
                leased_until=now - timedelta(minutes=5),
                created_at=now,
                updated_at=now,
            )
        )
    return "pub-1"


def test_the_job_card_and_both_buttons_work_on_sqlite(sqlite_settings):
    settings = sqlite_settings
    assert run_publisher.publications_for_job(settings, "job-1", tenant_id=None) == []
    publication_id = _row(settings, status="dead")

    [view] = run_publisher.publications_for_job(settings, "job-1", tenant_id="default")
    assert (view["status"], view["actionable"]) == ("dead", True)
    requeued = run_publisher.requeue_publication(settings, publication_id, job_id="job-1")
    assert requeued is not None and requeued["status"] == "pending"


def test_a_lease_renews_on_sqlite(sqlite_settings):
    settings = sqlite_settings
    publication_id = _row(settings, status="pending")
    failed = metrics_service.REGISTRY.get_sample_value(
        "octo_run_publication_lease_renewal_total", {"outcome": "failed"}
    ) or 0.0
    with get_session(settings.postgres_url) as session:
        lease = run_publisher._Lease(  # noqa: SLF001
            settings, run_publisher._snapshot(session.get(models.RunPublication, publication_id))  # noqa: SLF001
        )

    lease._renew()  # noqa: SLF001

    assert (
        metrics_service.REGISTRY.get_sample_value(
            "octo_run_publication_lease_renewal_total", {"outcome": "failed"}
        )
        or 0.0
    ) == failed
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        assert row.leased_until > run_publisher._now()  # noqa: SLF001
        assert row.next_attempt_at > run_publisher._now()  # noqa: SLF001
    with pytest.raises(ValueError):
        # Pending, and held: the reconciler's.
        run_publisher.discard_publication(settings, publication_id)
