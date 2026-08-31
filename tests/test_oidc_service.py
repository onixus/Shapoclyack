"""Unit tests for OIDC authentication service (Sprint 1 IAM)."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from api.services import oidc as oidc_service
from api.settings import Settings, load_settings


def test_pkce_generation():
    verifier, challenge = oidc_service.generate_pkce()
    assert len(verifier) >= 43
    assert len(challenge) > 20
    assert "=" not in challenge


def test_state_generation_and_verification():
    settings = load_settings()
    settings.jwt_secret = "test-secret-key-12345"
    state = oidc_service.generate_state(settings, redirect_to="/runs")

    data = oidc_service.verify_state(settings, state)
    assert data is not None
    assert data["redirect_to"] == "/runs"
    assert "nonce" in data

    # Tampered state fails
    assert oidc_service.verify_state(settings, state + "bad") is None

    # Expired state fails
    expired_state = oidc_service.generate_state(settings)
    with patch("time.time", return_value=time.time() + 1000):
        assert oidc_service.verify_state(settings, expired_state, max_age_seconds=600) is None


def test_resolve_role_from_claims():
    settings = load_settings()

    # Admin role mapping
    assert oidc_service.resolve_role_from_claims({"roles": ["admin"]}, settings) == "admin"
    assert oidc_service.resolve_role_from_claims({"roles": ["shapoclyack_admin"]}, settings) == "admin"
    assert oidc_service.resolve_role_from_claims({"realm_access": {"roles": ["admin"]}}, settings) == "admin"

    # Operator role mapping
    assert oidc_service.resolve_role_from_claims({"roles": ["operator"]}, settings) == "operator"
    assert oidc_service.resolve_role_from_claims({"roles": "secops, developer"}, settings) == "operator"

    # Viewer fallback
    assert oidc_service.resolve_role_from_claims({"roles": ["custom_reader"]}, settings) == "viewer"
    assert oidc_service.resolve_role_from_claims({}, settings) == "viewer"


def test_provision_or_get_user():
    settings = load_settings()
    settings.oidc_issuer_url = "https://idp.example.com/realms/corp"
    settings.oidc_auto_provision = True


    claims = {
        "sub": "auth0|1234567890",
        "email": "analyst@example.com",
        "preferred_username": "oidc_analyst",
        "roles": ["operator"],
    }

    user = oidc_service.provision_or_get_user(claims, settings)
    assert user["username"] == "oidc_analyst"
    assert user["role"] == "operator"
    assert user["email"] == "analyst@example.com"

    # Subsequent login returns the existing linked user
    claims_updated = {
        "sub": "auth0|1234567890",
        "email": "analyst_new@example.com",
        "preferred_username": "different_name",
        "roles": ["operator"],
    }
    user_second = oidc_service.provision_or_get_user(claims_updated, settings)
    assert user_second["username"] == "oidc_analyst"
