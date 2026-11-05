from __future__ import annotations

from api.services import ldap as ldap_service
from api.services import mfa as mfa_service
from api.services import saml as saml_service
from api.services.federated import FederatedIdentity
from tests.conftest import auth_headers, bearer, configured_client, make_settings, requires_postgres
from tests.test_saml import CERT, KEY

pytestmark = requires_postgres


def _identity(provider: str, tenant_id: str, *, role: str = "operator") -> FederatedIdentity:
    return FederatedIdentity(
        issuer=f"{provider}:https://idp.example.com",
        subject="directory-user-1",
        username="federated-user",
        email="federated@example.com",
        email_verified=True,
        role=role,
        tenant_id=tenant_id,
        jit_enabled=True,
        groups=["vm-ops"],
    )


def _saml_settings(tmp_path, **overrides):
    metadata = tmp_path / "idp.xml"
    metadata.write_text("not read by the mocked ACS", encoding="utf-8")
    return make_settings(
        tmp_path,
        saml_sp_entity_id="https://console.example.com/saml",
        saml_idp_metadata_path=str(metadata),
        saml_sp_x509_cert=CERT,
        saml_sp_private_key=KEY,
        saml_jit_provisioning=True,
        **overrides,
    )


def test_saml_acs_provisions_with_group_role_and_only_its_tenant(tmp_path, monkeypatch):
    settings = _saml_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = client.post("/api/tenants", headers=admin, json={"name": "Acme"}).json()["tenant_id"]
    globex = client.post("/api/tenants", headers=admin, json={"name": "Globex"}).json()["tenant_id"]
    monkeypatch.setattr(
        saml_service,
        "complete_login",
        lambda *_args, **_kwargs: saml_service.CompletedSamlLogin(
            _identity("saml", acme), "/runs"
        ),
    )

    response = client.post(
        "/api/auth/saml/acs", data={"SAMLResponse": "signed", "RelayState": "relay"}
    )

    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    me = client.get("/api/auth/me", headers=bearer(token))
    assert me.status_code == 200
    assert me.json()["tenants"] == [acme]
    assert me.json()["tenant_role"] == "operator"
    assert globex not in me.json()["tenants"]


def test_saml_callback_failures_do_not_issue_a_session(tmp_path, monkeypatch):
    settings = _saml_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)

    def refuse(*_args, **_kwargs):
        raise saml_service.SamlError("SAML response validation failed")

    monkeypatch.setattr(saml_service, "complete_login", refuse)
    response = client.post(
        "/api/auth/saml/acs", data={"SAMLResponse": "forged", "RelayState": "relay"}
    )
    assert response.status_code == 401
    assert "access_token" not in response.json()


def test_ldap_login_uses_the_same_session_and_mfa_path(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path,
        ldap_url="ldaps://ldap.example.com",
        ldap_base_dn="dc=example,dc=com",
        ldap_jit_provisioning=True,
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    monkeypatch.setattr(
        ldap_service,
        "authenticate",
        lambda *_args: _identity("ldap", "default"),
    )

    first = client.post(
        "/api/auth/ldap/login", json={"username": "federated-user", "password": "secret"}
    )
    assert first.status_code == 200, first.text
    assert first.json()["role"] == "operator"
    me = client.get("/api/auth/me", headers=bearer(first.json()["access_token"]))
    assert me.json()["username"] == "federated-user"

    monkeypatch.setattr(mfa_service, "is_enabled", lambda *_args: True)
    second = client.post(
        "/api/auth/ldap/login", json={"username": "federated-user", "password": "secret"}
    )
    assert second.status_code == 200
    assert second.json()["mfa_required"] is True
    assert second.json()["access_token"] is None
    assert second.json()["mfa_token"]


def test_ldap_invalid_credentials_are_generic_and_do_not_provision(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path,
        ldap_url="ldaps://ldap.example.com",
        ldap_base_dn="dc=example,dc=com",
        ldap_jit_provisioning=True,
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    monkeypatch.setattr(ldap_service, "authenticate", lambda *_args: None)

    response = client.post(
        "/api/auth/ldap/login", json={"username": "nobody", "password": "wrong"}
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_sso_status_lists_enabled_providers_without_infrastructure_details(tmp_path, monkeypatch):
    settings = _saml_settings(
        tmp_path,
        ldap_url="ldaps://ldap.example.com",
        ldap_base_dn="dc=example,dc=com",
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)

    response = client.get("/api/auth/sso")

    assert response.status_code == 200
    assert response.json()["providers"] == [
        {"provider": "saml", "login_url": "/api/auth/saml/login"},
        {"provider": "ldap", "login_url": "/api/auth/ldap/login"},
    ]
    assert "ldap.example.com" not in response.text
    assert "idp.xml" not in response.text
