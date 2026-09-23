"""Liveness / readiness probes and the honesty of `/api/health` (#331)."""

from __future__ import annotations

import pytest

from api.services import health as health_service
from tests.conftest import configured_client, make_settings, requires_postgres

# Not a module-level mark: the sweep itself (`check_readiness` against a
# ``Settings``) needs no database, and marking the module skipped the very
# tests that describe which dependencies block readiness on any machine
# without Postgres. Only the tests that build an app — and so a tenant store —
# carry the mark.


def _unreachable_postgres(monkeypatch) -> None:
    """Make the readiness sweep's ``SELECT 1`` fail the way a dead server does."""

    def _raise(url: str):
        raise RuntimeError("postgres is unreachable")

    monkeypatch.setattr(health_service.db_engine, "get_engine", _raise)


@requires_postgres
def test_livez_is_dependency_free(tmp_path, monkeypatch):
    """Liveness answers while Postgres is down: a restart does not fix a
    database outage, it only puts a crash loop on top of it."""
    client = configured_client(tmp_path, monkeypatch)
    _unreachable_postgres(monkeypatch)

    response = client.get("/livez")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@requires_postgres
def test_readyz_reports_the_checks_it_ran(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)

    response = client.get("/readyz")
    assert response.status_code == 200
    # NATS and ClickHouse are unconfigured in the suite, and an absent
    # dependency is not a failing one — it is not a check at all.
    assert response.json() == {"status": "ok", "checks": {"postgres": "ok"}}


@requires_postgres
def test_readyz_503_when_postgres_is_unreachable(tmp_path, monkeypatch):
    """The defect: readiness pointed at `/api/health`, which never touched
    Postgres, so a replica that could serve nothing stayed in the Service."""
    client = configured_client(tmp_path, monkeypatch)
    _unreachable_postgres(monkeypatch)

    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "checks": {"postgres": "error"}}


@requires_postgres
def test_health_status_follows_the_same_checks(tmp_path, monkeypatch):
    """Back-compatible shape, honest content: still 200 with `version` and
    `sso`, but `status` is no longer "ok" whatever the database is doing."""
    client = configured_client(tmp_path, monkeypatch)

    healthy = client.get("/api/health").json()
    assert healthy["status"] == "ok"
    assert healthy["checks"] == {"postgres": "ok"}
    assert healthy["nats"] is None

    _unreachable_postgres(monkeypatch)
    degraded = client.get("/api/health")
    assert degraded.status_code == 200
    body = degraded.json()
    assert body["status"] == "degraded"
    assert body["checks"] == {"postgres": "error"}
    assert body["version"] and body["sso"] is not None


def test_readiness_names_configured_dependencies_only(tmp_path, monkeypatch):
    """A configured, unreachable ClickHouse degrades the replica; the same
    ClickHouse left unconfigured is not reported at all."""
    monkeypatch.setattr(health_service, "_postgres_ok", lambda settings: True)
    monkeypatch.setattr(health_service.clickhouse_client, "ping", lambda url: False)
    settings = make_settings(tmp_path, clickhouse_url="http://clickhouse.invalid:8123")

    report = health_service.check_readiness(settings)
    assert report.healthy is False
    assert report.checks["clickhouse"] == "error"

    settings.clickhouse_url = ""
    assert "clickhouse" not in health_service.check_readiness(settings).checks


def test_clickhouse_degrades_but_does_not_unready_a_replica(tmp_path, monkeypatch):
    """The defect (#335): ClickHouse is one pod with no PDB, so making it
    decide `/readyz` meant a single restart of it took every API replica out of
    its Service at once — an outage of jobs, agents and runs in exchange for
    analytics that were down anyway."""
    monkeypatch.setattr(health_service, "_postgres_ok", lambda settings: True)
    monkeypatch.setattr(health_service.clickhouse_client, "ping", lambda url: False)
    settings = make_settings(tmp_path, clickhouse_url="http://clickhouse.invalid:8123")

    report = health_service.check_readiness(settings)
    assert report.ready is True
    assert report.healthy is False
    assert report.checks == {"postgres": "ok", "clickhouse": "error"}


@requires_postgres
def test_readyz_is_200_degraded_while_clickhouse_is_down(tmp_path, monkeypatch):
    """Serving, and saying what is wrong: the status code is for the kubelet,
    the body is for whoever reads it."""
    monkeypatch.setattr(health_service.clickhouse_client, "ping", lambda url: False)
    client = configured_client(
        tmp_path, monkeypatch, clickhouse_url="http://clickhouse.invalid:8123"
    )

    response = client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["clickhouse"] == "error"
    assert body["checks"]["postgres"] == "ok"


def test_nats_degrades_but_no_longer_unreadies_a_replica(tmp_path, monkeypatch):
    """The policy this replaces, and why (P2 of the 2026-09-18 review).

    NATS used to be in ``BLOCKING_CHECKS`` on the grounds that a replica
    without a broker cannot dispatch a job. It can: the offer is a
    notification, agents claim over HTTP, uploads have an HTTP route, and every
    read and write that is not a scan result never touches the bus — see the
    capability matrix in ``docs/high-availability.md``. Since all replicas share
    one broker, blocking on it converted a degraded installation into an
    unavailable one, all at once.

    This test is the new policy, deliberately spelled out: 200 and *degraded*.
    It is only defensible together with the outbox — a publish the broker
    refuses is recorded and replayed (``tests/test_nats_outbox.py``) — so if
    that ever goes away, this expectation has to go back to 503.
    """
    monkeypatch.setattr(health_service, "_postgres_ok", lambda settings: True)
    monkeypatch.setattr(health_service, "_nats_ok", lambda settings: False)
    monkeypatch.setattr(health_service, "_backlogged", lambda settings: False)
    settings = make_settings(tmp_path, nats_url="nats://nats.invalid:4222")

    report = health_service.check_readiness(settings)
    assert report.ready is True
    assert report.healthy is False
    assert report.checks["nats"] == "error"


def test_an_unrecovered_publish_backlog_is_its_own_check(tmp_path, monkeypatch):
    """Availability must not hide analytics falling behind: the broker can be
    answering again while the runs it refused are still unpublished, and that
    outlives the outage. Advisory like ClickHouse — a backlog is shared by every
    replica, so unreadying on it would be the outage this change removed."""
    monkeypatch.setattr(health_service, "_postgres_ok", lambda settings: True)
    monkeypatch.setattr(health_service, "_nats_ok", lambda settings: True)
    monkeypatch.setattr(health_service, "_backlogged", lambda settings: True)
    settings = make_settings(tmp_path, nats_url="nats://nats.invalid:4222")

    report = health_service.check_readiness(settings)
    assert report.ready is True
    assert report.healthy is False
    assert report.checks == {"postgres": "ok", "nats": "ok", "nats_outbox": "error"}


def test_no_broker_configured_means_no_backlog_check(tmp_path, monkeypatch):
    """An installation with no bus has nothing to publish and nothing to
    recover, and is ready rather than degraded — the same rule as the broker
    itself."""
    monkeypatch.setattr(health_service, "_postgres_ok", lambda settings: True)
    settings = make_settings(tmp_path)

    assert health_service.check_readiness(settings).checks == {"postgres": "ok"}


@requires_postgres
@pytest.mark.parametrize("path", ["/livez", "/readyz"])
def test_probes_stay_out_of_the_schema(tmp_path, monkeypatch, path):
    """Operational endpoints, not API surface — the same call as `/metrics`."""
    client = configured_client(tmp_path, monkeypatch, api_docs_enabled=True)
    assert path not in client.get("/openapi.json").json()["paths"]
