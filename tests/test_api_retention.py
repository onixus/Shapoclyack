"""The retention and legal-hold API: who may read, set and hold what (#332).

Three authorities, three kinds of people: a tenant's admin and auditor read
the windows, only its admin sets them — within bounds the platform configured —
and only a platform admin places or releases a hold. Each test pins one edge of
that, including the one a per-tenant API is most often wrong about: that the
tenant in the path is the only tenant the caller can reach.
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    auth_headers,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)
from tests.test_api_mfa import Clock, enrol

pytestmark = requires_postgres

ACME = "acme"
GLOBEX = "globex"


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    for tenant_id in (ACME, GLOBEX):
        created = client.post(
            "/api/tenants", headers=admin, json={"name": tenant_id, "tenant_id": tenant_id}
        )
        assert created.status_code in (200, 201), created.text
    return client, settings, admin


def _member(client, admin, username: str, tenant_id: str, role: str) -> dict[str, str]:
    """A global viewer holding ``role`` in one tenant: the authority is the membership's."""
    password = f"{username}-password-1234"
    created = client.post(
        "/api/users",
        headers=admin,
        json={"username": username, "password": password, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}", headers=admin, json={"role": role}
    )
    assert granted.status_code == 200, granted.text
    return bearer(login(client, username, password))


def _by_category(body: dict) -> dict[str, dict]:
    return {item["category"]: item for item in body["categories"]}


def _audit(client, headers, **params) -> list[dict]:
    response = client.get("/api/audit", headers=headers, params={"limit": 200, **params})
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_a_tenant_admin_reads_and_sets_its_own_windows(env):
    client, _settings, admin = env
    acme_admin = _member(client, admin, "ada", ACME, "admin")

    shown = client.get(f"/api/tenants/{ACME}/retention", headers=acme_admin)
    assert shown.status_code == 200, shown.text
    categories = _by_category(shown.json())
    # Every category, inherited or not: a missing one would read as "not kept".
    assert set(categories) == {
        "runs",
        "screenshots",
        "reports",
        "endpoint_snapshots",
        "endpoint_changes",
        "risk_snapshots",
        "webhook_deliveries",
        "workflow_markers",
        "audit_events",
    }
    assert categories["runs"] == {
        "category": "runs",
        "description": categories["runs"]["description"],
        "default_days": 30,
        "override_days": None,
        "effective_days": 30,
        "min_days": 1,
        "max_days": 365,
        "source": "default",
    }
    assert shown.json()["legal_hold"] is None

    saved = client.put(
        f"/api/tenants/{ACME}/retention",
        headers=acme_admin,
        json={"overrides": {"runs": 90, "audit_events": 730}, "note": "DPA annex 2"},
    )
    assert saved.status_code == 200, saved.text
    after = _by_category(saved.json())
    assert after["runs"]["effective_days"] == 90
    assert after["runs"]["source"] == "tenant"
    assert after["audit_events"]["effective_days"] == 730
    assert after["reports"]["source"] == "default"
    assert saved.json()["updated_by"] == "ada"

    # Recorded in the tenant's own trail, with the document before and after.
    rows = _audit(client, acme_admin, action="retention_policy.update")
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == ACME
    assert rows[0]["actor"] == "ada"
    assert rows[0]["before"] is None
    assert rows[0]["after"]["overrides"]["runs"] == 90

    # Whole-document: what is left out goes back to the default.
    replaced = client.put(
        f"/api/tenants/{ACME}/retention", headers=acme_admin, json={"overrides": {"runs": 60}}
    )
    assert _by_category(replaced.json())["audit_events"]["source"] == "default"

    assert (
        client.delete(f"/api/tenants/{ACME}/retention", headers=acme_admin).status_code == 204
    )
    reset = client.get(f"/api/tenants/{ACME}/retention", headers=acme_admin).json()
    assert all(item["source"] == "default" for item in reset["categories"])
    assert len(_audit(client, acme_admin, action="retention_policy.update")) == 3


def test_the_audit_floor_is_not_a_number_a_tenant_admin_can_reach_below(env):
    client, _settings, admin = env
    acme_admin = _member(client, admin, "ada", ACME, "admin")

    for overrides, needle in (
        ({"audit_events": 30}, "[365, 3650]"),
        ({"screenshots": 365}, "[1, 90]"),
        ({"runs": 0}, "[1, 365]"),
        ({"no_such_thing": 10}, "unknown retention categories"),
    ):
        refused = client.put(
            f"/api/tenants/{ACME}/retention", headers=acme_admin, json={"overrides": overrides}
        )
        assert refused.status_code == 422, (overrides, refused.text)
        assert needle in refused.json()["detail"]

    # The platform admin is held to the same bounds: they are configuration,
    # changed by deploying OCTO_RETENTION_BOUNDS, not by a request.
    assert (
        client.put(
            f"/api/tenants/{ACME}/retention",
            headers=admin,
            json={"overrides": {"audit_events": 30}},
        ).status_code
        == 422
    )
    shown = client.get(f"/api/tenants/{ACME}/retention", headers=acme_admin).json()
    assert all(item["source"] == "default" for item in shown["categories"])


def test_the_floor_follows_the_platforms_configuration(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, retention_bounds={"audit_events": {"min": 730}})
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    refused = client.put(
        "/api/tenants/default/retention", headers=admin, json={"overrides": {"audit_events": 400}}
    )
    assert refused.status_code == 422
    assert "[730, 3650]" in refused.json()["detail"]


def test_retention_is_scoped_to_the_tenant_in_the_path(env):
    client, _settings, admin = env
    acme_admin = _member(client, admin, "ada", ACME, "admin")
    acme_auditor = _member(client, admin, "aud", ACME, "auditor")
    acme_viewer = _member(client, admin, "vic", ACME, "viewer")

    # Another tenant's windows are neither readable nor writable.
    assert client.get(f"/api/tenants/{GLOBEX}/retention", headers=acme_admin).status_code == 403
    assert (
        client.put(
            f"/api/tenants/{GLOBEX}/retention",
            headers=acme_admin,
            json={"overrides": {"runs": 2}},
        ).status_code
        == 403
    )
    assert (
        client.delete(f"/api/tenants/{GLOBEX}/retention", headers=acme_admin).status_code == 403
    )
    # An auditor reads and writes nothing; a viewer does not even read.
    assert client.get(f"/api/tenants/{ACME}/retention", headers=acme_auditor).status_code == 200
    assert (
        client.put(
            f"/api/tenants/{ACME}/retention",
            headers=acme_auditor,
            json={"overrides": {"runs": 2}},
        ).status_code
        == 403
    )
    assert client.get(f"/api/tenants/{ACME}/retention", headers=acme_viewer).status_code == 403
    # And an unknown tenant is a 404 for whoever may ask about every tenant.
    assert client.get("/api/tenants/nope/retention", headers=admin).status_code == 404


def test_only_a_platform_admin_places_and_releases_a_hold(env):
    client, _settings, admin = env
    acme_admin = _member(client, admin, "ada", ACME, "admin")

    assert (
        client.put(
            f"/api/tenants/{ACME}/legal-hold", headers=acme_admin, json={"reason": "mine"}
        ).status_code
        == 403
    )
    placed = client.put(
        f"/api/tenants/{ACME}/legal-hold",
        headers=admin,
        json={"reason": "Preservation order, matter 2026-17"},
    )
    assert placed.status_code == 200, placed.text
    assert placed.json()["set_by"] == "admin"
    assert placed.json()["reason"] == "Preservation order, matter 2026-17"

    # The platform admin sees the whole hold; the tenant sees that there is one
    # and since when — the matter behind it may be one it must not learn of here.
    platform_view = client.get(f"/api/tenants/{ACME}/retention", headers=admin).json()
    assert platform_view["legal_hold"]["reason"] == "Preservation order, matter 2026-17"
    tenant_view = client.get(f"/api/tenants/{ACME}/retention", headers=acme_admin).json()
    assert tenant_view["legal_hold"]["set_at"] == platform_view["legal_hold"]["set_at"]
    assert tenant_view["legal_hold"]["reason"] is None
    assert tenant_view["legal_hold"]["set_by"] is None
    # Nor from its own trail: the hold is recorded at platform level.
    assert _audit(client, acme_admin, action="legal_hold.place") == []
    placed_rows = _audit(client, admin, action="legal_hold.place")
    assert [(row["resource_id"], row["tenant_id"]) for row in placed_rows] == [(ACME, None)]

    assert client.delete(f"/api/tenants/{ACME}/legal-hold", headers=acme_admin).status_code == 403
    assert client.delete(f"/api/tenants/{ACME}/legal-hold", headers=admin).status_code == 204
    assert client.get(f"/api/tenants/{ACME}/retention", headers=admin).json()["legal_hold"] is None
    released = _audit(client, admin, action="legal_hold.release")
    assert released[0]["before"]["reason"] == "Preservation order, matter 2026-17"

    assert (
        client.put("/api/tenants/nope/legal-hold", headers=admin, json={"reason": "x"}).status_code
        == 404
    )
    assert (
        client.put(
            f"/api/tenants/{ACME}/legal-hold", headers=admin, json={"reason": "   "}
        ).status_code
        == 422
    )


def test_amending_a_hold_keeps_when_it_was_placed(env):
    client, _settings, admin = env
    first = client.put(f"/api/tenants/{ACME}/legal-hold", headers=admin, json={"reason": "a"})
    again = client.put(f"/api/tenants/{ACME}/legal-hold", headers=admin, json={"reason": "b"})
    assert again.json()["reason"] == "b"
    assert again.json()["set_at"] == first.json()["set_at"]


def test_retention_and_hold_changes_need_a_recent_second_factor(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("api.services.mfa._now", clock)
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    enrol(client, headers, clock)

    for method, path, body in (
        ("put", "/api/tenants/default/retention", {"overrides": {"runs": 2}}),
        ("delete", "/api/tenants/default/retention", None),
        ("put", "/api/tenants/default/legal-hold", {"reason": "x"}),
        ("delete", "/api/tenants/default/legal-hold", None),
    ):
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
        refused = getattr(client, method)(path, **kwargs)
        assert refused.status_code == 403, (method, path, refused.text)
        assert "multi-factor" in refused.json()["detail"]
    # Reading is not a change and costs nothing extra.
    assert client.get("/api/tenants/default/retention", headers=headers).status_code == 200


def test_a_service_token_reaches_none_of_it(env):
    client, _settings, admin = env
    minted = client.post(
        f"/api/tenants/{ACME}/service-tokens",
        headers=admin,
        json={"name": "ci", "role": "admin", "scopes": ["*:read", "*:write"], "ttl_days": 1},
    )
    if minted.status_code == 404:  # pragma: no cover - service tokens disabled
        pytest.skip("service tokens are not mounted")
    assert minted.status_code in (200, 201), minted.text
    token = bearer(minted.json()["token"])
    assert client.get(f"/api/tenants/{ACME}/retention", headers=token).status_code == 403
    assert (
        client.put(
            f"/api/tenants/{ACME}/legal-hold", headers=token, json={"reason": "x"}
        ).status_code
        == 403
    )
