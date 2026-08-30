"""Route-level tests for the read-only GET /api/system status endpoint."""

from __future__ import annotations

import json

from api.auth import get_settings
from tests.conftest import api_client, login, requires_postgres

pytestmark = requires_postgres




def test_system_status_shape():
    client = api_client()
    token = login(client)
    response = client.get("/api/system", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()

    assert isinstance(body["app_version"], str) and body["app_version"]

    tool_names = {tool["name"] for tool in body["tools"]}
    assert tool_names == {"pulse", "naabu", "nuclei", "dnsx", "nmap"}
    # Fail-soft: a tool absent from the CI runner reports version=None + an error
    # string rather than 500-ing the endpoint.
    for tool in body["tools"]:
        assert tool["version"] is not None or tool["error"] is not None
        if tool["name"] == "nmap":
            assert tool.get("optional") is True
        else:
            assert tool.get("optional") is False

    enrichment_names = {db["name"] for db in body["enrichment"]}
    # The vendor advisory datasets behind software→CVE matching (Track E M1)
    # are reported here too: same envelope, same "how old and where from"
    # question this panel already answers.
    assert enrichment_names == {
        "epss",
        "kev",
        "exploit",
        "geoip",
        "cvss4",
        "asn",
        "advisories_debian",
        "advisories_ubuntu",
    }
    for db in body["enrichment"]:
        assert "stale" in db
        # Provenance is always present as keys, even with no manifest to read
        # (#246) — an older image reports None rather than dropping the fields.
        assert set(db) >= {"source", "origin", "updated", "entries"}

    assert set(body["scan_config"]["stages"]) >= {
        "fingerprint",
        "screenshots",
        "tls_posture",
        "nuclei",
        "pdf_summary",
    }
    assert "balanced" in body["scan_config"]["profiles"]
    assert body["scan_config"].get("service_backend") in ("pulse", "nmap", "hybrid", None)

    runtime = body["runtime"]
    assert isinstance(runtime["postgres_enabled"], bool)
    assert isinstance(runtime["job_execution_mode"], str)
    assert isinstance(runtime["endpoint_stale_hours"], int)

    # Endpoint-inventory footprint and retention posture (Agent_plan.md S9).
    endpoint = body["endpoint_inventory"]
    assert endpoint["snapshot_retention_days"] >= 1
    assert endpoint["change_retention_days"] >= endpoint["snapshot_retention_days"]
    assert endpoint["stale_hours"] == runtime["endpoint_stale_hours"]
    assert isinstance(endpoint["retention_enabled"], bool)
    # Counts are fail-soft: real ints when Postgres answers, None when it can't.
    assert endpoint["devices_total"] is None or endpoint["devices_total"] >= 0
    assert endpoint["devices_stale"] is None or endpoint["devices_stale"] >= 0


def test_system_status_leaks_no_secrets():
    client = api_client()
    token = login(client)
    response = client.get("/api/system", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    raw = response.text

    settings = get_settings()
    # The runtime block reports only booleans/counts — never the actual URLs
    # (which embed the Postgres password) or the JWT secret.
    if settings.postgres_url:
        assert settings.postgres_url not in raw
    assert settings.jwt_secret not in raw


def test_system_status_reports_only_parsed_trusted_proxies(tmp_path, monkeypatch):
    """The flag answers "is X-Forwarded-For being honoured", so it has to follow
    the parsed networks: unparsable entries are dropped with a warning, and a
    list of typos means every login is still attributed to the ingress peer."""
    from tests.conftest import auth_headers, configured_client

    typos = configured_client(tmp_path, monkeypatch, trusted_proxies=["not-an-ip", "10.0.0.0/99"])
    runtime = typos.get("/api/system", headers=auth_headers(typos, "admin")).json()["runtime"]
    assert runtime["trusted_proxies_configured"] is False

    real = configured_client(tmp_path, monkeypatch, trusted_proxies=["10.0.0.0/8"])
    runtime = real.get("/api/system", headers=auth_headers(real, "admin")).json()["runtime"]
    assert runtime["trusted_proxies_configured"] is True


def test_system_status_reports_where_each_dataset_came_from(tmp_path, monkeypatch):
    """Age answers "how old", never "where from". An image whose EPSS fetch
    403'd ships the committed baseline and looks, from outside, exactly like one
    that pulled a fresh corpus — which is the defect in #246. The manifest the
    build writes is what tells them apart, and it has to reach the API."""
    from tests.conftest import auth_headers, configured_client

    manifest = tmp_path / "enrichment-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "generated_at": "2026-08-27T00:00:00+00:00",
                "datasets": {
                    "epss": {
                        "source": "first-epss",
                        "origin": "stale",
                        "updated": "2026-08-26",
                        "entries": 365017,
                        "required": True,
                        "usable": True,
                    },
                    "kev": {
                        "source": "cisa-kev",
                        "origin": "fetch",
                        "updated": "2026-08-25",
                        "entries": 1676,
                        "required": True,
                        "usable": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OCTO_ENRICHMENT_MANIFEST", str(manifest))

    client = configured_client(tmp_path, monkeypatch)
    body = client.get("/api/system", headers=auth_headers(client, "admin")).json()
    databases = {db["name"]: db for db in body["enrichment"]}

    assert databases["epss"]["source"] == "first-epss"
    assert databases["epss"]["updated"] == "2026-08-26"
    assert databases["epss"]["entries"] == 365017
    # The dataset the build could not refresh says so by name, rather than
    # blending in with the ones it did.
    assert databases["epss"]["origin"] == "stale"
    assert databases["kev"]["origin"] == "fetch"
    # A dataset the manifest says nothing about still reports its own fields,
    # as None — the payload shape must not depend on the manifest's coverage.
    assert databases["cvss4"]["origin"] is None
    assert databases["cvss4"]["source"] is None


def test_system_status_survives_an_unreadable_manifest(tmp_path, monkeypatch):
    """Fail-soft like every other panel: a truncated sidecar on a shared volume
    degrades the origin fields to None, it does not 500 the status page."""
    from tests.conftest import auth_headers, configured_client

    manifest = tmp_path / "broken-manifest.json"
    manifest.write_text('{"datasets": {"epss": ', encoding="utf-8")
    monkeypatch.setenv("OCTO_ENRICHMENT_MANIFEST", str(manifest))

    client = configured_client(tmp_path, monkeypatch)
    response = client.get("/api/system", headers=auth_headers(client, "admin"))

    assert response.status_code == 200
    assert all(db["origin"] is None for db in response.json()["enrichment"])


def test_system_status_requires_auth():
    client = api_client()
    assert client.get("/api/system").status_code == 401


def test_system_status_reflects_config_overrides():
    """A saved override for an editable stage must show up in the Pipeline
    Stages panel, not just in GET /config -- system_status previously read
    only the base YAML file and silently ignored the overrides table."""
    client = api_client()
    admin_token = login(client, "admin")
    headers = {"Authorization": f"Bearer {admin_token}"}

    put_response = client.put(
        "/api/config",
        json={"overrides": {"fingerprint.enabled": True, "tls_posture.enabled": True}},
        headers=headers,
    )
    assert put_response.status_code == 200
    try:
        stages = client.get("/api/system", headers=headers).json()["scan_config"]["stages"]
        assert stages["fingerprint"] is True
        assert stages["tls_posture"] is True
        # Nuclei is enabled by default (Phase 4.2); only check editable stages we flipped.
        assert stages["nuclei"] is True
    finally:
        client.put("/api/config", json={"overrides": {}}, headers=headers)
