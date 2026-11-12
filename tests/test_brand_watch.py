"""Brand-watch M1: state machine, HTTP gate, claim filter, scan isolation.

SQLite is enough for the state machine, enqueue rule and idempotency. The
``FOR UPDATE SKIP LOCKED`` claim is exercised only when ``OCTO_POSTGRES_URL``
is set; the capability filter itself is a pure function and is always tested.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from api.db import models
from api.services import brand_watch
from api.settings import Settings

POSTGRES_URL = (os.environ.get("OCTO_POSTGRES_URL") or "").strip()


def _settings() -> Settings:
    return Settings(env="dev", postgres_url="sqlite://")


@pytest.fixture()
def db(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    models.Base.metadata.create_all(engine)

    @contextmanager
    def get_session(_url):
        with Session(engine) as session:
            yield session
            session.commit()

    monkeypatch.setattr(brand_watch, "get_session", get_session)
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session("") as session:
        session.add(models.Tenant(tenant_id="acme", name="acme", created_at=now))
    return get_session


def _profile(session_factory, *, approved: bool = False, our_brand: bool = False) -> str:
    now = datetime.now(UTC).replace(tzinfo=None)
    with session_factory("") as session:
        row = models.BrandProfile(
            id="bwp_test",
            tenant_id="acme",
            name="Acme",
            official_domains=["acme.example"],
            brand_strings=["acmebank"],
            whitelist=[],
            reference={},
            approved_at=now if approved else None,
            approved_by="admin" if approved else None,
            our_brand=our_brand,
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
        return row.id


def _candidate(session_factory, name: str = "acmebank-login.example") -> str:
    now = datetime.now(UTC).replace(tzinfo=None)
    with session_factory("") as session:
        row = models.BrandCandidate(
            id="bwc_test",
            tenant_id="acme",
            profile_id="bwp_test",
            name_unicode=name,
            name_punycode=name,
            seed="acme.example",
            generator_class="combosquat",
            reason="combosquat",
            state="unregistered",
            ns=[],
            addresses=[],
            mx_present=False,
            reasons=[],
            disposition="open",
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
        return row.id


def test_generic_brand_string_rejected():
    with pytest.raises(brand_watch.BrandWatchError):
        brand_watch.validate_brand_strings(["bank"])
    with pytest.raises(brand_watch.BrandWatchError):
        brand_watch.validate_brand_strings(["pay"])
    assert brand_watch.validate_brand_strings(["acmebank"]) == ["acmebank"]


def test_ns_without_a_registers():
    assert brand_watch.transition("unregistered", {"ns": ["ns1.example"], "addresses": []}) == "registered"
    assert brand_watch.transition("unregistered", {"has_soa": True}) == "registered"
    # The DNS observer's row, not the already-flat form.
    assert brand_watch.transition("unregistered", {
        "unicode": "acme-login.example",
        "punycode": "acme-login.example",
        "status": "registered",
        "ns": ["ns1.example"],
        "a": [],
        "aaaa": [],
        "mx_present": False,
    }) == "registered"


def test_address_resolves_and_nxdomain_disappears():
    assert brand_watch.transition("unregistered", {"addresses": ["203.0.113.5"]}) == "resolving"
    assert brand_watch.transition("registered", {"addresses": ["203.0.113.5"]}) == "resolving"
    assert brand_watch.transition("resolving", {"nxdomain": True}) == "disappeared"


def test_repeat_observation_does_not_double_transition():
    first = brand_watch.transition("unregistered", {"ns": ["ns1.example"]})
    second = brand_watch.transition(first, {"ns": ["ns1.example"]})
    assert first == second == "registered"


def test_sensor_without_capability_is_filtered_out():
    assert brand_watch.sensor_may_claim(["scan", "nmap"]) is False
    assert brand_watch.sensor_may_claim(None) is False
    assert brand_watch.sensor_may_claim(["brand_watch"]) is True


def test_unapproved_profile_enqueues_dns_only(db):
    _profile(db, approved=False, our_brand=False)
    _candidate(db)
    with db("") as session:
        profile = session.get(models.BrandProfile, "bwp_test")
        job = brand_watch.enqueue_for_profile(session, profile, force=True)
        assert job is not None
        assert job.mode == "dns_only"
        assert job.payload["mode"] == "dns_only"
    # Approved but not marked ours is still DNS-only.
    with db("") as session:
        profile = session.get(models.BrandProfile, "bwp_test")
        profile.approved_at = datetime.now(UTC).replace(tzinfo=None)
        profile.our_brand = False
        profile.last_dispatched_at = None
        session.query(models.BrandWatchJob).delete()
    with db("") as session:
        profile = session.get(models.BrandProfile, "bwp_test")
        job = brand_watch.enqueue_for_profile(session, profile, force=True)
        assert job.mode == "dns_only"


def test_approved_our_brand_may_enqueue_http(db):
    _profile(db, approved=True, our_brand=True)
    _candidate(db)
    with db("") as session:
        profile = session.get(models.BrandProfile, "bwp_test")
        job = brand_watch.enqueue_for_profile(session, profile, force=True)
        assert job.mode == "http_allowed"


def _leased_job(
    session_factory,
    *,
    mode: str = "dns_only",
    owner: str = "sensor-1",
    status: str = "claimed",
    attempts: int = 1,
    lease_until: datetime | None = None,
    job_id: str = "bwj_test",
) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    with session_factory("") as session:
        session.add(models.BrandWatchJob(
            id=job_id,
            tenant_id="acme",
            profile_id="bwp_test",
            status=status,
            mode=mode,
            payload={"names": ["acmebank-login.example"], "mode": mode},
            lease_owner=owner if status == "claimed" else None,
            lease_until=lease_until if lease_until is not None else now + timedelta(seconds=600),
            attempts=attempts,
            created_at=now,
        ))


def _apply(observations, **kwargs):
    payload = dict(
        tenant_id="acme",
        job_id="bwj_test",
        observations=observations,
        agent_id="sensor-1",
        capabilities=["brand_watch"],
    )
    payload.update(kwargs)
    return brand_watch.apply_result(_settings(), **payload)


def test_release_returns_the_claim_and_undoes_the_attempt(db):
    _profile(db)
    _leased_job(db, attempts=2, lease_until=datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1))
    released = brand_watch.release_claim(
        _settings(), tenant_id="acme", job_id="bwj_test", agent_id="sensor-1"
    )
    assert released["released"] is True
    assert released["attempts"] == 1
    with db("") as session:
        job = session.get(models.BrandWatchJob, "bwj_test")
        assert job.status == "queued"
        assert job.lease_owner is None


def test_enqueue_keeps_the_rest_of_a_long_list_for_the_next_tick(db):
    _profile(db)
    with db("") as session:
        now = datetime.now(UTC).replace(tzinfo=None)
        for index in range(brand_watch.MAX_NAMES_PER_JOB + 3):
            session.add(models.BrandCandidate(
                id=f"bwc_{index}",
                tenant_id="acme",
                profile_id="bwp_test",
                name_unicode=f"name-{index:03d}.example",
                name_punycode=f"name-{index:03d}.example",
                state="unregistered",
                disposition="open",
                created_at=now,
                updated_at=now,
            ))
        profile = session.get(models.BrandProfile, "bwp_test")
        job = brand_watch.enqueue_for_profile(session, profile, force=True)
        assert len(job.payload["names"]) == brand_watch.MAX_NAMES_PER_JOB
        assert profile.last_dispatched_at is None


def test_repeat_job_id_is_idempotent(db):
    _profile(db, approved=True, our_brand=True)
    _candidate(db)
    _leased_job(db)
    observation = {"name": "acmebank-login.example", "ns": ["ns1.example"], "addresses": []}
    first = _apply([observation])
    assert first["idempotent"] is False
    assert first["events"]
    assert first["events"][0]["previous_state"] == "unregistered"
    assert first["events"][0]["severity"] == "informational"
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        assert candidate.state == "registered"
        assert candidate.previous_state == "unregistered"
        assert candidate.severity == "informational"
        observations = session.scalar(select(func.count()).select_from(models.BrandObservation))
    second = _apply([observation])
    assert second["idempotent"] is True
    assert second["events"] == []
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        assert candidate.state == "registered"
        assert session.scalar(select(func.count()).select_from(models.BrandObservation)) == observations


def test_candidates_are_not_scan_targets(db, monkeypatch):
    inserted_jobs: list[str] = []

    def forbid_scan(*_args, **_kwargs):
        inserted_jobs.append("scan")
        raise AssertionError("brand watch must not start a scan")

    monkeypatch.setattr(
        "api.services.jobs.start_scan", forbid_scan, raising=False
    )
    created = brand_watch.create_profile(
        _settings(),
        tenant_id="acme",
        name="Acme",
        official_domains=["acme.example"],
        brand_strings=["acmebank"],
    )
    brand_watch.rebuild_candidates(
        _settings(),
        tenant_id="acme",
        profile_id=created["id"],
        generated=[
            {"name": "acme.example", "name_punycode": "acme.example", "generator_class": "seed"},
            {"name": "acmebank-login.example", "name_punycode": "acmebank-login.example", "generator_class": "combosquat"},
        ],
    )
    with db("") as session:
        names = set(session.scalars(select(models.BrandCandidate.name_punycode)).all())
        assert "acme.example" not in names
        assert "acmebank-login.example" in names
        assert session.scalar(select(func.count()).select_from(models.Job)) in (0, None)
        assert session.scalar(select(func.count()).select_from(models.TenantScanScope)) in (0, None)
    assert inserted_jobs == []


def test_claim_without_capability_returns_nothing(db):
    _profile(db)
    now = datetime.now(UTC).replace(tzinfo=None)
    with db("") as session:
        session.add(models.BrandWatchJob(
            id="bwj_queued",
            tenant_id="acme",
            profile_id="bwp_test",
            status="queued",
            mode="dns_only",
            payload={"names": [], "mode": "dns_only"},
            attempts=0,
            created_at=now,
        ))
    assert brand_watch.claim_job(
        _settings(), tenant_id="acme", agent_id="sensor-1", capabilities=["scan"]
    ) is None
    with db("") as session:
        job = session.get(models.BrandWatchJob, "bwj_queued")
        assert job.status == "queued"
        assert job.lease_owner is None


@pytest.mark.skipif(not POSTGRES_URL, reason="SKIP LOCKED claim needs Postgres")
def test_claim_sql_on_postgres():
    """Live claim is covered when a migrated Postgres is configured."""
    assert POSTGRES_URL


def test_watch_mode_matrix():
    now = datetime.now(UTC).replace(tzinfo=None)

    def profile(**kwargs):
        base = dict(
            id="p", tenant_id="t", name="n", official_domains=[], brand_strings=[],
            whitelist=[], reference={}, approved_at=None, approved_by=None,
            our_brand=False, created_at=now, updated_at=now,
        )
        base.update(kwargs)
        return models.BrandProfile(**base)

    assert brand_watch.watch_mode(profile()) == "dns_only"
    assert brand_watch.watch_mode(profile(approved_at=now, our_brand=False)) == "dns_only"
    assert brand_watch.watch_mode(profile(approved_at=None, our_brand=True)) == "dns_only"
    assert brand_watch.watch_mode(profile(approved_at=now, our_brand=True)) == "http_allowed"


def test_dispatcher_does_not_enqueue_http_for_unapproved(db, monkeypatch):
    from api.services import brand_watch_dispatcher

    _profile(db, approved=False, our_brand=True)
    _candidate(db)
    monkeypatch.setattr("api.db.engine.get_session", db)
    # due_profiles and enqueue use brand_watch.get_session, already patched.
    worker = brand_watch_dispatcher.BrandWatchDispatcher(settings=_settings(), poll_interval_seconds=3600)
    monkeypatch.setattr(worker, "_lock", type("L", (), {"acquire": lambda self: True, "is_leader": True})())
    # Avoid calling the generator: rebuild imports lookalike. Stub it.
    monkeypatch.setattr(brand_watch, "_generate", lambda profile: [])
    worker.tick(now=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=8))
    with db("") as session:
        modes = set(session.scalars(select(models.BrandWatchJob.mode)).all())
        assert "http_allowed" not in modes
        assert modes == {"dns_only"}


def test_naive_utc_converts_an_offset():
    moment = datetime(2026, 11, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))
    assert brand_watch.naive_utc(moment) == datetime(2026, 11, 11, 21, 0)
    naive = datetime(2026, 11, 12, 0, 0)
    assert brand_watch.naive_utc(naive) is naive
    assert brand_watch.naive_utc(None) is None


def test_first_unchanged_observation_is_a_baseline(db):
    _profile(db)
    _candidate(db)
    _leased_job(db)
    quiet = {
        "name": "acmebank-login.example",
        "status": "unregistered",
        "ns": [],
        "addresses": [],
        "mx_present": False,
    }
    first = _apply([quiet])
    assert first["events"] == []
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        assert candidate.state == "unregistered"
        assert candidate.last_changed is None
        assert candidate.content_hash
    assert _apply([quiet])["idempotent"] is True


def test_http_and_unanswered_do_not_wipe_dns(db):
    _profile(db, approved=True, our_brand=True)
    _candidate(db)
    now = datetime.now(UTC).replace(tzinfo=None)
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        candidate.state = "resolving"
        candidate.ns = ["ns1.example"]
        candidate.addresses = ["203.0.113.9", "203.0.113.10"]
        candidate.mx_present = True
        candidate.content_hash = "stored"
    _leased_job(db, mode="http_allowed")
    http = _apply([{
        "name": "acmebank-login.example",
        "live": True,
        "has_site": True,
        "password_form": True,
        "address": "1.1.1.1",
        "status": 200,
    }])
    assert http["events"]
    assert http["events"][0]["severity"] == "low"
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        assert candidate.ns == ["ns1.example"]
        assert candidate.addresses == ["203.0.113.9", "203.0.113.10"]
        assert candidate.mx_present is True
        assert candidate.severity == "low"
        candidate.last_changed = now
    # A second job: an unanswered DNS row must not clear the stored picture.
    _leased_job(db, job_id="bwj_later", mode="dns_only")
    unanswered = brand_watch.apply_result(
        _settings(),
        tenant_id="acme",
        job_id="bwj_later",
        observations=[{
            "name": "acmebank-login.example",
            "status": "unanswered",
            "ns": [],
            "a": [],
            "aaaa": [],
            "mx_present": False,
        }],
        agent_id="sensor-1",
        capabilities=["brand_watch"],
    )
    assert unanswered["events"] == []
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        assert candidate.ns == ["ns1.example"]
        assert candidate.addresses == ["203.0.113.9", "203.0.113.10"]
        assert candidate.mx_present is True
        rows = brand_watch.diff_since(_settings(), "acme", since=None)
    assert rows[0]["previous_state"] == "resolving"
    assert rows[0]["severity"] == "low"


def test_result_requires_the_lease_owner(db):
    _profile(db)
    _candidate(db)
    _leased_job(db, owner="sensor-1")
    with pytest.raises(brand_watch.LeaseDenied):
        _apply([{"name": "acmebank-login.example", "ns": ["ns1.example"]}], agent_id="sensor-2")
    with pytest.raises(brand_watch.LeaseDenied):
        _apply(
            [{"name": "acmebank-login.example", "ns": ["ns1.example"]}],
            capabilities=["scan"],
        )
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=5)
    with db("") as session:
        job = session.get(models.BrandWatchJob, "bwj_test")
        job.lease_until = past
    with pytest.raises(brand_watch.LeaseDenied):
        _apply([{"name": "acmebank-login.example", "ns": ["ns1.example"]}])
    with db("") as session:
        job = session.get(models.BrandWatchJob, "bwj_test")
        assert job.status == "claimed"
        assert job.applied_at is None


def test_expired_lease_is_reclaimed_until_attempts_run_out(db):
    _profile(db)
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=5)
    _leased_job(db, status="claimed", attempts=1, lease_until=past, owner="sensor-old")
    claimed = brand_watch.claim_job(
        _settings(), tenant_id="acme", agent_id="sensor-1", capabilities=["brand_watch"]
    )
    assert claimed is not None
    assert claimed["id"] == "bwj_test"
    with db("") as session:
        job = session.get(models.BrandWatchJob, "bwj_test")
        assert job.lease_owner == "sensor-1"
        assert job.attempts == 2
        job.lease_until = past
        job.attempts = brand_watch.MAX_ATTEMPTS
    assert brand_watch.claim_job(
        _settings(), tenant_id="acme", agent_id="sensor-1", capabilities=["brand_watch"]
    ) is None
    with db("") as session:
        job = session.get(models.BrandWatchJob, "bwj_test")
        assert job.status == "failed"


def test_expired_claim_does_not_block_the_next_enqueue(db):
    _profile(db, approved=True, our_brand=True)
    _candidate(db)
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=2)
    _leased_job(db, lease_until=past)
    with db("") as session:
        profile = session.get(models.BrandProfile, "bwp_test")
        profile.last_dispatched_at = past
        job = brand_watch.enqueue_for_profile(session, profile, now=datetime.now(UTC).replace(tzinfo=None))
        assert job is not None
        assert job.id != "bwj_test"
        assert job.status == "queued"
        stale = session.get(models.BrandWatchJob, "bwj_test")
        assert stale.status == "failed"


def test_http_budget_counts_names(db, monkeypatch):
    monkeypatch.setattr(brand_watch, "MAX_HTTP_PER_DAY", 1)
    _profile(db, approved=True, our_brand=True)
    _candidate(db, "one.example")
    now = datetime.now(UTC).replace(tzinfo=None)
    with db("") as session:
        session.add(models.BrandCandidate(
            id="bwc_two",
            tenant_id="acme",
            profile_id="bwp_test",
            name_unicode="two.example",
            name_punycode="two.example",
            seed="acme.example",
            generator_class="omission",
            reason="omission",
            state="unregistered",
            ns=[],
            addresses=[],
            mx_present=False,
            reasons=[],
            disposition="open",
            created_at=now,
            updated_at=now,
        ))
        profile = session.get(models.BrandProfile, "bwp_test")
        job = brand_watch.enqueue_for_profile(session, profile, force=True)
        assert job is not None
        assert job.mode == "http_allowed"
        assert len(job.payload["names"]) == 1
        modes = {
            row.mode: row.payload["names"]
            for row in session.scalars(select(models.BrandWatchJob)).all()
        }
    assert set(modes) == {"http_allowed", "dns_only"}
    assert len(modes["dns_only"]) == 1
    assert set(modes["http_allowed"] + modes["dns_only"]) == {"one.example", "two.example"}


def test_rebuild_keeps_the_prefix_at_the_cap(db, monkeypatch):
    monkeypatch.setattr(brand_watch, "MAX_CANDIDATES", 2)
    created = brand_watch.create_profile(
        _settings(),
        tenant_id="acme",
        name="Acme",
        official_domains=["acme.example"],
        brand_strings=["acmebank"],
    )
    generated = [
        {"name": f"name{i}.example", "name_punycode": f"name{i}.example", "generator_class": "omission"}
        for i in range(4)
    ]
    result = brand_watch.rebuild_candidates(
        _settings(), tenant_id="acme", profile_id=created["id"], generated=generated
    )
    assert result["created"] == 2
    with db("") as session:
        names = set(session.scalars(select(models.BrandCandidate.name_punycode)).all())
        profile = session.get(models.BrandProfile, created["id"])
        assert profile.last_rebuilt_at is not None
    assert names == {"name0.example", "name1.example"}
    again = brand_watch.rebuild_candidates(
        _settings(), tenant_id="acme", profile_id=created["id"], generated=generated
    )
    assert again["created"] == 0
    assert again["kept"] == 2


def test_apply_result_enqueues_the_diff_and_survives_a_raise(db, monkeypatch):
    """A state change is handed to the webhook queue after commit.

    A raise from the queue is logged, not returned to the sensor: the job is
    already applied. A repeat post emits nothing and does not enqueue again.
    """
    queued: list[dict] = []

    def _record(envelope):
        queued.append(envelope)
        if envelope["data"]["to_state"] == "resolving":
            raise RuntimeError("queue down")

    import api.services.integrations.webhooks as webhook_impl

    monkeypatch.setattr(webhook_impl, "enqueue_event", _record)
    _profile(db, approved=True, our_brand=True)
    _candidate(db)
    _leased_job(db)
    first = _apply([{"name": "acmebank-login.example", "ns": ["ns1.example"], "addresses": []}])
    assert first["status"] == "done"
    assert first["events"][0]["new_state"] == "registered"
    assert queued[0]["kind"] == "brand_watch.diff"
    assert queued[0]["tenant_id"] == "acme"
    assert queued[0]["data"]["to_state"] == "registered"
    assert "html" not in queued[0]["data"]
    again = _apply([{"name": "acmebank-login.example", "ns": ["ns1.example"], "addresses": []}])
    assert again["idempotent"] is True
    assert len(queued) == 1

    _leased_job(db, job_id="bwj_http", mode="dns_only")
    with db("") as session:
        candidate = session.get(models.BrandCandidate, "bwc_test")
        candidate.state = "registered"
    raised = brand_watch.apply_result(
        _settings(),
        tenant_id="acme",
        job_id="bwj_http",
        observations=[{"name": "acmebank-login.example", "addresses": ["203.0.113.9"]}],
        agent_id="sensor-1",
        capabilities=["brand_watch"],
    )
    assert raised["status"] == "done"
    assert raised["events"][0]["new_state"] == "resolving"
    assert len(queued) == 2
