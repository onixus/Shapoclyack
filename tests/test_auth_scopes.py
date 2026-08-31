"""Unit tests for capability scopes enforcement (Sprint 1 IAM)."""

from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import Role, TenantPrincipal, TokenUser, create_access_token, require_scope
from api.services import service_tokens as st_service
from api.settings import load_settings

scope_router = APIRouter()


@scope_router.get("/protected/read-assets")
def read_assets(
    principal: Annotated[TenantPrincipal, Depends(require_scope("assets:read", Role.viewer))]
):
    return {"status": "ok", "user": principal.username}


@scope_router.post("/protected/write-assets")
def write_assets(
    principal: Annotated[TenantPrincipal, Depends(require_scope("assets:write", Role.operator))]
):
    return {"status": "ok", "user": principal.username}


@pytest.fixture
def scoped_app():
    app = create_app()
    app.include_router(scope_router)
    return app


def test_user_jwt_passes_all_scopes(scoped_app):
    settings = load_settings()
    user = TokenUser(username="operator", role=Role.operator)
    token = create_access_token(settings, user)
    client = TestClient(scoped_app)

    # User JWT has wildcards scopes
    r1 = client.get("/protected/read-assets", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200

    r2 = client.post("/protected/write-assets", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200


def test_service_token_enforces_scope(scoped_app):
    # Create operator token with only assets:read scope
    _, read_token = st_service.create_token(
        tenant_id="default",
        name="Read Only Token",
        role="operator",
        scopes=["assets:read"],
    )

    client = TestClient(scoped_app)

    # 1. Allowed scope passes
    r1 = client.get("/protected/read-assets", headers={"Authorization": f"Bearer {read_token}"})
    assert r1.status_code == 200

    # 2. Missing scope is rejected (403)
    r2 = client.post("/protected/write-assets", headers={"Authorization": f"Bearer {read_token}"})
    assert r2.status_code == 403
    assert "missing required scope" in r2.json()["detail"]
