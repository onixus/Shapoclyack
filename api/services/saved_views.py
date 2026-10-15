"""Durable personal views. Ownership always comes from the authenticated principal."""

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import func, select

from api.db.engine import get_session
from api.db.models import ConsoleSavedView, Tenant
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


def validate_state(page: str, state: ViewState):
    if state.sort is not None and state.sort not in SORTS[page]:
        raise ValueError("Unknown sort column")
    if set(state.filters) - FILTERS[page]:
        raise ValueError("Unknown filter; recreate this view with current filters")
    choices = {
        "status": {"", "active", "stale", "decommissioned"},
        "scope": {"open", "all"},
        "state": {
            "",
            "OPEN",
            "ACKNOWLEDGED",
            "PLANNED",
            "FIXING",
            "VERIFYING",
            "CLOSED",
        },
        "severity": {"", "critical", "high", "medium", "low", "unknown"},
        "sla": {"", "on_track", "due_soon", "breached", "accepted", "none"},
        "source": {"", "scan", "endpoint_software", "retro_match"},
        "findingType": {"", "cve", "misconfiguration", "exposure"},
        "detector": {"", "nuclei", "pulse", "pulse-plugin", "nmap-nse"},
        "exposure": {"", "external", "internal", "unknown"},
        "staleDays": {"", "14", "30", "90"},
    }
    for key, value in state.filters.items():
        if key in choices and value not in choices[key]:
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


def create_view(settings: Settings, tenant_id: str, username: str, payload: ViewInput):
    with get_session(settings.postgres_url) as session:
        # Serialize admissions across replicas, so parallel requests cannot evade the cap.
        session.scalar(
            select(Tenant).where(Tenant.tenant_id == tenant_id).with_for_update()
        )
        count = session.scalar(
            select(func.count()).select_from(owned(tenant_id, username).subquery())
        )
        if count >= 50:
            raise ValueError("Delete a saved view before creating another (maximum 50)")
        now = datetime.now(UTC)
        row = ConsoleSavedView(
            view_id=uuid4().hex,
            tenant_id=tenant_id,
            username=username,
            page=payload.page,
            name=payload.name,
            state=payload.state.model_dump(),
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
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
        row.updated_at = datetime.now(UTC)
        return as_dict(row)
