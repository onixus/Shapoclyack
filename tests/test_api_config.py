"""Route-level tests for the editable configurator (GET/PUT /api/config)."""

from __future__ import annotations


from api.auth import get_settings
from api.services import config_override
from api.services.config_override import SECRET_MASK
from tests.conftest import api_client, auth_headers, requires_postgres

pytestmark = requires_postgres




def test_get_config_shape():
    client = api_client()
    headers = auth_headers(client, "viewer")
    r = client.get("/api/config", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert "nuclei.enabled" in body["editable_paths"]
    assert "profiles.balanced.top_ports" in body["editable_paths"]
    assert isinstance(body["defaults"], dict)
    assert isinstance(body["effective"], dict)


def test_viewer_cannot_update():
    client = api_client()
    headers = auth_headers(client, "viewer")
    r = client.put("/api/config", headers=headers, json={"overrides": {"nuclei.enabled": True}})
    assert r.status_code == 403


def test_admin_update_and_reset():
    client = api_client()
    headers = auth_headers(client, "admin")

    # Apply an override — effective flips, overrides records it.
    r = client.put("/api/config", headers=headers, json={"overrides": {"nuclei.enabled": True}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["effective"]["nuclei.enabled"] is True
    assert body["overrides"]["nuclei.enabled"] is True

    # Reset clears overrides; effective returns to the base default.
    r = client.put("/api/config", headers=headers, json={"overrides": {}})
    assert r.status_code == 200
    assert r.json()["overrides"] == {}


def test_admin_update_rejects_invalid():
    client = api_client()
    headers = auth_headers(client, "admin")
    # Non-editable path.
    r = client.put("/api/config", headers=headers, json={"overrides": {"discovery.asn.enabled": True}})
    assert r.status_code == 422
    # Out-of-range value.
    r = client.put("/api/config", headers=headers, json={"overrides": {"profiles.safe.top_ports": 0}})
    assert r.status_code == 422


def test_nvd_api_key_is_never_returned_to_a_reader():
    """GET /api/config is viewer-readable, so a stored key must come back masked
    -- in every bucket, not just `overrides`."""
    client = api_client()
    admin = auth_headers(client, "admin")
    secret = "nvd-secret-value-under-test"
    r = client.put("/api/config", headers=admin, json={"overrides": {"enrichment.cvss4.nvd_api_key": secret}})
    assert r.status_code == 200, r.text

    viewer = auth_headers(client, "viewer")
    r = client.get("/api/config", headers=viewer)
    assert r.status_code == 200
    assert secret not in r.text
    assert r.json()["effective"]["enrichment.cvss4.nvd_api_key"] == SECRET_MASK

    # An unrelated edit echoes the mask back; the stored key must survive it.
    r = client.put(
        "/api/config",
        headers=admin,
        json={"overrides": {"enrichment.cvss4.nvd_api_key": SECRET_MASK, "nuclei.retries": 3}},
    )
    assert r.status_code == 200, r.text
    assert config_override.get_overrides(get_settings())["enrichment"]["cvss4"]["nvd_api_key"] == secret

    # Clear it so the shared dev database does not keep a test key around.
    client.put("/api/config", headers=admin, json={"overrides": {}})
