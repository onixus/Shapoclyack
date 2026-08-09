"""ROADMAP P1.6: advisory-lock leader election for the schedule dispatcher.

These exercise the real Postgres primitive rather than a mock — the whole point
of the design is what the *database* does when a leader's backend disappears,
which no fake can tell us.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from api.services import jobs as jobs_service
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.services import tenants as tenants_service
from api.services.leader_lock import LeaderLock
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres

# Kept away from SCHEDULE_DISPATCHER_LOCK_ID so a test run cannot contend with
# a dispatcher started by another test's app fixture.
TEST_LOCK_ID = 9101


@pytest.fixture()
def settings(tmp_path: Path):
    s = make_settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    scan_schedules.configure(s)
    scan_schedules.reset_for_tests()
    return s


@pytest.fixture()
def locks(settings):
    """Two contenders for one lock, released whatever the test does."""
    made = [
        LeaderLock(settings.postgres_url, object_id=TEST_LOCK_ID, name=f"test-{i}")
        for i in range(2)
    ]
    yield made
    for lock in made:
        lock.release()


def test_only_one_contender_leads(locks):
    first, second = locks
    assert first.acquire() is True
    assert second.acquire() is False
    assert second.is_leader is False


def test_leadership_transfers_after_release(locks):
    first, second = locks
    first.acquire()
    assert second.acquire() is False

    first.release()
    assert first.is_leader is False
    assert second.acquire() is True


def test_acquire_is_idempotent_and_releases_in_one_call(locks):
    """Advisory locks stack per session: locking twice needs unlocking twice.

    A leader re-checking every tick would therefore become impossible to
    release, holding the schedule hostage for the life of the process — so a
    holder must re-verify rather than re-lock.
    """
    first, second = locks
    for _ in range(3):
        assert first.acquire() is True

    first.release()
    assert second.acquire() is True


def test_a_dead_leader_frees_the_lock_for_its_peer(locks):
    """The reason this is a session lock and not a lease row: the database
    drops it when the backend goes, with no expiry to wait out."""
    first, second = locks
    first.acquire()

    # Closest thing to a crash we can stage in-process: end the backend session
    # that holds the lock, without telling the object that holds it.
    first._conn.invalidate()  # noqa: SLF001

    assert second.acquire() is True
    # The old leader finds out on its next tick and steps down rather than
    # dispatching against a connection Postgres already reclaimed.
    assert first.acquire() is False
    assert first.is_leader is False


def test_a_backend_without_advisory_locks_always_leads(settings, monkeypatch):
    """SQLite cannot be shared by replicas, so gating on a lock it does not
    have would just disable the dispatcher."""
    monkeypatch.setattr(
        "api.services.leader_lock.get_engine",
        lambda _url: types.SimpleNamespace(dialect=types.SimpleNamespace(name="sqlite")),
    )
    lock = LeaderLock(settings.postgres_url, object_id=TEST_LOCK_ID, name="sqlite")
    assert lock.acquire() is True
    assert lock.acquire() is True


def test_a_database_outage_elects_nobody(settings, monkeypatch):
    """A follower that cannot reach Postgres must not promote itself."""
    from sqlalchemy.exc import OperationalError

    def _down(_url):
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    monkeypatch.setattr("api.services.leader_lock.get_engine", _down)
    lock = LeaderLock(settings.postgres_url, object_id=TEST_LOCK_ID, name="down")
    assert lock.acquire() is False


def test_only_the_leading_dispatcher_ticks(settings, monkeypatch):
    """The end of the P1.6 story: a second replica's dispatcher thread runs but
    dispatches nothing."""
    started: list[int] = []
    monkeypatch.setattr(jobs_service, "get_job", lambda settings, job_id: None)
    monkeypatch.setattr(
        jobs_service, "start_scan", lambda *a, **k: started.append(1)
    )

    leader = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    follower = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    try:
        assert leader._lead() is True  # noqa: SLF001
        assert follower._lead() is False  # noqa: SLF001
        assert follower.stats["skipped_not_leader"] == 1
        assert follower.stats["is_leader"] == 0
        assert leader.stats["is_leader"] == 1
    finally:
        leader._lock.release()  # noqa: SLF001
        follower._lock.release()  # noqa: SLF001
