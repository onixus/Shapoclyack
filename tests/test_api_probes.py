"""Liveness / readiness probes and the honesty of `/api/health` (#331)."""

from __future__ import annotations

import pytest

from api.services import health as health_service
from tests.conftest import configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


def _unreachable_postgres(monkeypatch) -> None:
    """Make the readiness sweep's ``SELECT 1`` fail the way a dead server does."""

    def _raise(url: str):
        raise RuntimeError("postgres is unreachable")

    monkeypatch.setattr(health_service.db_engine, "get_engine", _raise)


def test_livez_is_dependency_free(tmp_path, monkeypatch):
    """Liveness answers while Postgres is down: a restart does not fix a
    database outage, it only puts a crash loop on top of it."""
    client = configured_client(tmp_path, monkeypatch)
    _unreachable_postgres(monkeypatch)

    response = client.get("/livez")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_reports_the_checks_it_ran(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)

    response = client.get("/readyz")
    assert response.status_code == 200
    # NATS and ClickHouse are unconfigured in the suite, and an absent
    # dependency is not a failing one — it is not a check at all.
    assert response.json() == {"status": "ok", "checks": {"postgres": "ok"}}


def test_readyz_503_when_postgres_is_unreachable(tmp_path, monkeypatch):
    """The defect: readiness pointed at `/api/health`, which never touched
    Postgres, so a replica that could serve nothing stayed in the Service."""
    client = configured_client(tmp_path, monkeypatch)
    _unreachable_postgres(monkeypatch)

    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "checks": {"postgres": "error"}}


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
    monkeypatch.setattr(health_service.clickhouse_client, "ping", lambda url: False)
    settings = make_settings(tmp_path, clickhouse_url="http://clickhouse.invalid:8123")

    report = health_service.check_readiness(settings)
    assert report.ready is False
    assert report.checks["clickhouse"] == "error"

    settings.clickhouse_url = ""
    assert "clickhouse" not in health_service.check_readiness(settings).checks


@pytest.mark.parametrize("path", ["/livez", "/readyz"])
def test_probes_stay_out_of_the_schema(tmp_path, monkeypatch, path):
    """Operational endpoints, not API surface — the same call as `/metrics`."""
    client = configured_client(tmp_path, monkeypatch, api_docs_enabled=True)
    assert path not in client.get("/openapi.json").json()["paths"]
