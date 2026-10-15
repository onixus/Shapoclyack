"""Saved preferences cannot disclose or mutate another user or tenant's view."""

import time
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from api.auth import TenantPrincipal, get_settings
from api.db.models import ConsoleSavedView, Tenant
from api.routes import saved_views as routes
from api.services import saved_views as store
from tests.conftest import POSTGRES_URL, requires_postgres


@pytest.fixture
def env(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Tenant.__table__.create(engine)
    ConsoleSavedView.__table__.create(engine)

    @contextmanager
    def get_session(_url):
        with Session(engine) as session:
            yield session
            session.commit()

    monkeypatch.setattr(store, "get_session", get_session)
    with get_session("") as session:
        for tenant in ("alpha", "beta"):
            session.add(
                Tenant(tenant_id=tenant, name=tenant, created_at=datetime.now(UTC))
            )
    settings = SimpleNamespace(postgres_url="unused")
    principal = {"username": "alice", "tenant_id": "alpha"}
    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[routes.Principal.__metadata__[0].dependency] = lambda: (
        TenantPrincipal(**principal, role="viewer")
    )
    with TestClient(app) as client:
        yield client, principal, settings, get_session
    engine.dispose()


def body(**overrides):
    return {
        "page": "assets",
        "name": "Unowned",
        "state": {
            "version": 1,
            "search": "router",
            "sort": "last_seen",
            "order": "desc",
            "filters": {"unowned": True, "status": "active"},
        },
        **overrides,
    }


def test_personal_crud_and_tenant_isolation(env):
    client, principal, settings, _ = env
    created = client.post("/api/saved-views", json=body())
    assert created.status_code == 201, created.text
    view = created.json()
    assert view["compatible"] is True
    view_id = view["view_id"]
    for username, tenant in (("bob", "alpha"), ("alice", "beta")):
        principal.update(username=username, tenant_id=tenant)
        assert client.get("/api/saved-views?page=assets").json() == []
        assert (
            client.patch(
                f"/api/saved-views/{view_id}", json={"name": "Stolen"}
            ).status_code
            == 404
        )
        assert client.delete(f"/api/saved-views/{view_id}").status_code == 404
    principal.update(username="alice", tenant_id="alpha")
    assert client.get("/api/saved-views?page=vulnerabilities").json() == []
    assert (
        client.patch(f"/api/saved-views/{view_id}", json={"name": " Renamed "}).json()[
            "name"
        ]
        == "Renamed"
    )
    # Persistence is server-side, independent of a browser session or client instance.
    assert (
        store.list_views(settings, "alpha", "alice", "assets")[0]["state"]
        == view["state"]
    )
    assert client.delete(f"/api/saved-views/{view_id}").status_code == 204
    assert client.get("/api/saved-views?page=assets").json() == []


@pytest.mark.parametrize(
    "state",
    [
        {"version": 2},
        {"filters": {"tenant_id": "beta"}},
        {"filters": {"status": "removed"}},
        {"filters": {"unowned": "yes"}},
        {"sort": "private_column"},
        {"search": "x" * 513},
        {"filters": {"assetId": "x"}},
        {"order": "sideways"},
    ],
)
def test_schema_refuses_unknown_or_removed_filters(env, state):
    client, *_ = env
    assert (
        client.post(
            "/api/saved-views", json=body(state={**body()["state"], **state})
        ).status_code
        == 422
    )


def test_owner_is_never_taken_from_payload_and_blank_names_refused(env):
    client, *_ = env
    assert client.post("/api/saved-views", json=body(username="bob")).status_code == 422
    assert client.post("/api/saved-views", json=body(name="   ")).status_code == 422


def test_incompatible_persisted_view_can_be_renamed_deleted_but_not_applied(env):
    client, _, _, get_session = env
    view_id = client.post("/api/saved-views", json=body()).json()["view_id"]
    with get_session("") as session:
        session.get(ConsoleSavedView, view_id).state = {
            "version": 99,
            "filters": {"obsolete": True},
        }
    assert client.get("/api/saved-views?page=assets").json()[0]["compatible"] is False
    assert (
        client.patch(
            f"/api/saved-views/{view_id}", json={"name": "Old view"}
        ).status_code
        == 200
    )
    assert client.delete(f"/api/saved-views/{view_id}").status_code == 204


def test_admission_limit_is_per_account_not_per_page(env):
    client, principal, *_ = env
    for index in range(50):
        assert (
            client.post("/api/saved-views", json=body(name=f"View {index}")).status_code
            == 201
        )
    assert client.post("/api/saved-views", json=body()).status_code == 400
    principal["username"] = "bob"
    assert client.post("/api/saved-views", json=body()).status_code == 201


@pytest.mark.parametrize("detector", ["nuclei", "pulse", "pulse-plugin", "nmap-nse"])
def test_valid_findings_deep_link_filters_are_compatible(detector):
    assert store.compatible(
        "vulnerabilities",
        {"version": 1, "filters": {"detector": detector}, "sort": "contextual_score"},
    )


def test_saved_views_are_classified_for_privacy_and_tenant_purge():
    from api.services import data_subject
    from api.services.tenant_purge.postgres import POSTGRES_TABLES

    assert (
        data_subject.SUBJECT_COLUMNS[("console_saved_views", "username")][0]
        == data_subject.DELETED
    )
    assert (
        data_subject.SUBJECT_COLUMNS[("console_saved_views", "state")][0]
        == data_subject.DELETED
    )
    assert "console_saved_views" in POSTGRES_TABLES


def test_duplicate_names_are_refused_per_account_and_page(env):
    client, principal, *_ = env
    first = client.post("/api/saved-views", json=body(name="Edge")).json()
    dup = client.post("/api/saved-views", json=body(name="  edge "))
    assert dup.status_code == 409
    assert "already exists" in dup.json()["detail"]
    # Same name on another page, or for another account, is a different view.
    other_page = body(
        page="vulnerabilities",
        name="Edge",
        state={"version": 1, "filters": {"severity": "high"}},
    )
    assert client.post("/api/saved-views", json=other_page).status_code == 201
    second = client.post("/api/saved-views", json=body(name="Core")).json()
    renamed = client.patch(
        f"/api/saved-views/{second['view_id']}", json={"name": "EDGE"}
    )
    assert renamed.status_code == 409
    # Renaming a view to its own name (or changing only the case) is not a clash.
    same = client.patch(f"/api/saved-views/{first['view_id']}", json={"name": "EDGE"})
    assert same.status_code == 200
    principal["username"] = "bob"
    assert client.post("/api/saved-views", json=body(name="Edge")).status_code == 201


@requires_postgres
def test_concurrent_creates_cannot_exceed_the_cap(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from sqlalchemy import delete, select

    from api.db.engine import get_session
    from api.settings import Settings

    settings = Settings(postgres_url=POSTGRES_URL)
    tenant = "cap-" + uuid4().hex[:10]
    now = datetime.now(UTC)
    with get_session(POSTGRES_URL) as session:
        session.add(Tenant(tenant_id=tenant, name=tenant, created_at=now))
        session.flush()
        for index in range(49):
            session.add(
                ConsoleSavedView(
                    view_id=uuid4().hex,
                    tenant_id=tenant,
                    username="alice",
                    page="assets",
                    name=f"Seed {index}",
                    state={},
                    created_at=now,
                    updated_at=now,
                )
            )
    # Widen the window between the count and the insert so that, without the
    # tenant lock, every racer reads 49 before any of them commits.
    check = store.ensure_unique_name

    def slow_check(*args, **kwargs):
        time.sleep(0.3)
        return check(*args, **kwargs)

    monkeypatch.setattr(store, "ensure_unique_name", slow_check)
    racers = 8
    gate = Barrier(racers)

    def attempt(index):
        gate.wait(timeout=10)
        try:
            payload = store.ViewInput.model_validate(body(name=f"Racer {index}"))
            store.create_view(settings, tenant, "alice", payload)
            return True
        except ValueError:
            return False

    try:
        with ThreadPoolExecutor(racers) as pool:
            admitted = sum(pool.map(attempt, range(racers)))
        with get_session(POSTGRES_URL) as session:
            total = session.scalar(
                select(func.count())
                .select_from(ConsoleSavedView)
                .where(ConsoleSavedView.tenant_id == tenant)
            )
        assert (admitted, total) == (1, 50)
    finally:
        with get_session(POSTGRES_URL) as session:
            session.execute(delete(Tenant).where(Tenant.tenant_id == tenant))
