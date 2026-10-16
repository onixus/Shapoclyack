"""Durable personal views. Ownership always comes from the authenticated principal."""

from datetime import UTC, datetime
from typing import Literal, get_args
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError

from api.db.engine import get_session
from api.db.models import ConsoleSavedView
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.settings import Settings

Page = Literal["assets", "vulnerabilities"]
FILTERS = {
    "assets": {"status", "unowned"},
    "vulnerabilities": {
        "scope",
        "state",
        "severity",
        "sla",
        "staleDays",
        "unassigned",
        "source",
        "findingType",
        "detector",
        "exposure",
        "assetId",
    },
}
SORTS = {
    "assets": {
        "last_seen",
        "first_seen",
        "status",
        "asset_criticality",
        "asset_id",
        "owner_email",
        "business_service",
    },
    "vulnerabilities": {
        "cve",
        "severity",
        "state",
        "due_at",
        "last_seen_at",
        "first_seen_at",
        "contextual_score",
    },
}


MAX_VIEWS_PER_ACCOUNT = 50
NAME_KEY_CONSTRAINT = "uq_console_saved_views_name_key"


class DuplicateViewName(ValueError):
    """The account already has a view with this name on this page."""


class ViewLimitReached(ValueError):
    """The account is at the cap of saved views."""


class ViewState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal[1] = 1
    search: str = Field(default="", max_length=512)
    sort: str | None = Field(default=None, max_length=64)
    order: Literal["asc", "desc"] = "desc"
    filters: dict[str, str | bool] = Field(default_factory=dict, max_length=16)


class ViewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    page: Page
    name: str = Field(min_length=1, max_length=80)
    state: ViewState

    @model_validator(mode="after")
    def validate_view(self):
        self.name = self.name.strip()
        if not self.name:
            raise ValueError("View name cannot be blank")
        validate_state(self.page, self.state)
        return self


class ViewUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_name(self):
        self.name = self.name.strip()
        if not self.name:
            raise ValueError("View name cannot be blank")
        return self


# Allow-lists for the closed filters. Lifecycle states, SLA readings, sources and
# the three findings vocabularies come from the findings list itself; severities
# and asset statuses have no shared constant to derive from.
CHOICES = {
    "status": {"", "active", "stale", "decommissioned"},
    "scope": {"open", "all"},
    "state": {"", *vuln_states.ORDER},
    "severity": {"", "critical", "high", "medium", "low", "unknown"},
    "sla": {"", *vulns_service.SLA_STATES},
    "source": {"", *vulns_service.SOURCES},
    "findingType": {"", *get_args(vulns_service.FindingType)},
    "detector": {"", *get_args(vulns_service.DetectorSource)},
    "exposure": {"", *get_args(vulns_service.NetworkExposure)},
    "staleDays": {"", "14", "30", "90"},
}


def validate_state(page: str, state: ViewState):
    if state.sort is not None and state.sort not in SORTS[page]:
        raise ValueError("Unknown sort column")
    if set(state.filters) - FILTERS[page]:
        raise ValueError("Unknown filter; recreate this view with current filters")
    for key, value in state.filters.items():
        if key in CHOICES and value not in CHOICES[key]:
            raise ValueError("Unknown filter value")
        if key in {"unowned", "unassigned"}:
            if not isinstance(value, bool):
                raise ValueError("Boolean filter expected")
        elif not isinstance(value, str) or len(value) > 512:
            raise ValueError("Invalid filter value")


def compatible(page, state):
    try:
        validate_state(page, ViewState.model_validate(state))
        return True
    except (ValueError, ValidationError, KeyError):
        return False


def as_dict(row):
    return {
        "view_id": row.view_id,
        "page": row.page,
        "name": row.name,
        "state": row.state,
        "compatible": compatible(row.page, row.state),
    }


def owned(tenant_id, username):
    return select(ConsoleSavedView).where(
        ConsoleSavedView.tenant_id == tenant_id, ConsoleSavedView.username == username
    )


def name_key(name: str) -> str:
    """Case-insensitive identity of a name, computed here and not by the database.

    SQL ``lower()`` follows the database locale (SQLite and C-ctype Postgres
    leave Cyrillic untouched), so uniqueness rests on this stored key instead.
    """
    return name.casefold()


def lock_owner(session, tenant_id, username):
    """Serialize one account's admissions across replicas so the cap holds.

    A transaction-scoped advisory lock on the owner, not a lock on the tenant
    row: other accounts and the tenant's ingest are not made to wait. Name
    uniqueness does not depend on it - the unique constraint does.
    """
    if session.get_bind().dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"console_saved_views:{tenant_id}:{username}"},
    )


def refuse_duplicate(session, exc: IntegrityError):
    """Turn the name-key violation into the domain error; re-raise anything else."""
    session.rollback()
    if "name_key" in str(exc.orig):
        raise DuplicateViewName(
            "A saved view with this name already exists on this page"
        ) from exc
    raise exc


def list_views(settings: Settings, tenant_id: str, username: str, page: Page):
    with get_session(settings.postgres_url) as session:
        return [
            as_dict(row)
            for row in session.scalars(
                owned(tenant_id, username)
                .where(ConsoleSavedView.page == page)
                .order_by(ConsoleSavedView.created_at, ConsoleSavedView.view_id)
            )
        ]


def enforce_cap(session, tenant_id, username):
    count = session.scalar(
        select(func.count()).select_from(owned(tenant_id, username).subquery())
    )
    if count >= MAX_VIEWS_PER_ACCOUNT:
        raise ViewLimitReached(
            f"Delete a saved view before creating another (maximum {MAX_VIEWS_PER_ACCOUNT})"
        )


def delete_owner_views(session, username, tenant_id=None):
    """Drop an account's views (in one tenant, or everywhere).

    ``username`` has no foreign key (an SSO principal need not own a ``users``
    row), so account deletion and membership revocation call this explicitly;
    otherwise a re-created account of the same name would inherit the views.
    """
    stmt = delete(ConsoleSavedView).where(ConsoleSavedView.username == username)
    if tenant_id is not None:
        stmt = stmt.where(ConsoleSavedView.tenant_id == tenant_id)
    return session.execute(stmt).rowcount


def create_view(settings: Settings, tenant_id: str, username: str, payload: ViewInput):
    with get_session(settings.postgres_url) as session:
        lock_owner(session, tenant_id, username)
        enforce_cap(session, tenant_id, username)
        now = datetime.now(UTC)
        row = ConsoleSavedView(
            view_id=uuid4().hex,
            tenant_id=tenant_id,
            username=username,
            page=payload.page,
            name=payload.name,
            name_key=name_key(payload.name),
            state=payload.state.model_dump(),
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError as exc:
            refuse_duplicate(session, exc)
        return as_dict(row)


def change_view(
    settings: Settings,
    tenant_id: str,
    username: str,
    view_id: str,
    payload: ViewUpdate | None,
):
    with get_session(settings.postgres_url) as session:
        row = session.scalar(
            owned(tenant_id, username)
            .where(ConsoleSavedView.view_id == view_id)
            .with_for_update()
        )
        if row is None:
            return None
        if payload is None:
            session.delete(row)
            return True
        row.name = payload.name
        row.name_key = name_key(payload.name)
        row.updated_at = datetime.now(UTC)
        try:
            session.flush()
        except IntegrityError as exc:
            refuse_duplicate(session, exc)
        return as_dict(row)
