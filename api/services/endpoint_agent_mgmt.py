"""Remote management of the Lariska endpoint agents (#358).

Two things an operator could previously only do by walking to the machine:
change what the agent collects and how often, and put a new build on it. Both
now travel in the heartbeat response, which the agent already polls and which
``api/routes/agents.py`` calls "the only channel that reaches a running agent".

**What a policy may not say.** ``server_url``, the provisioning key, the state
directory and ``allow_plain_http`` are absent from :data:`SETTABLE` on purpose.
An agent that can be told where to report is an agent that can be told to
report somewhere else, and the channel carrying that instruction is the very
thing an attacker who reached the API would use. The knobs here change how
noisy and how frequent an agent is, and nothing about who it trusts.

**Why the binary is served from here.** An upgrade is remote code execution by
construction, so the digest and the bytes come from one authenticated channel:
the heartbeat names a version and its sha256, and the download is the same API
with the same agent token. The agent refuses a download whose digest does not
match, and refuses the whole mechanism over plain HTTP unless its own config
opts in — see the Lariska side. Nothing here can make an agent upgrade that
has not asked; an installation that uploads no release never answers with one.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select

from api.db import models
from api.db.engine import get_session
from api.settings import Settings

_settings: Settings | None = None

#: Largest build the API will store and hand out. A cap rather than a stream:
#: the row is read whole to serve it, and an installation that needs to ship
#: something bigger than this to every endpoint has a distribution problem the
#: heartbeat is the wrong place to solve.
MAX_RELEASE_BYTES = 64 * 1024 * 1024

#: Settings an operator may decide centrally, with the bounds the agent itself
#: enforces. Validated here as well so one bad policy cannot quietly stop a
#: fleet from collecting: the agent would reject it and keep its previous
#: configuration, which looks identical to the policy never arriving.
SETTABLE: dict[str, tuple[int, int]] = {
    "inventory_interval_secs": (10, 86_400),
    "heartbeat_interval_secs": (10, 86_400),
    "request_timeout_secs": (1, 300),
    "inventory_full_refresh_interval_secs": (10, 86_400),
    "max_spool_entries": (1, 10_000),
}

LOG_LEVELS = ("error", "warn", "info", "debug", "trace")


class PolicyError(ValueError):
    """A policy an agent would refuse, refused here instead."""


class ReleaseError(ValueError):
    """A build the platform will not store or hand out."""


@dataclass(frozen=True)
class AgentPlan:
    """What one agent should be told on this heartbeat."""

    settings: dict[str, Any]
    revision: int
    update: dict[str, Any] | None
    #: Set when a version was asked for and cannot be served — an operator
    #: naming a build nobody uploaded is a mistake worth surfacing, and the
    #: agent is told nothing rather than something it cannot act on.
    update_blocked: str | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    if _settings is None:
        raise RuntimeError("endpoint_agent_mgmt.configure() was not called")
    return _settings


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def reset_for_tests() -> None:
    """Empty both tables.

    Releases are installation-wide rather than per tenant, so a test that
    uploads one leaves it visible to every test that runs after it in the same
    database -- which is how an assertion about "no build is stored yet"
    starts passing or failing depending on test order.
    """
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        session.query(models.EndpointAgentPolicy).delete()
        session.query(models.EndpointAgentRelease).delete()


def validate_settings(values: dict[str, Any]) -> dict[str, Any]:
    """Return ``values`` narrowed to :data:`SETTABLE`, or raise.

    Unknown keys are refused rather than dropped: silently ignoring
    ``server_url`` would leave an operator believing they had moved a fleet.
    """
    cleaned: dict[str, Any] = {}
    for key, raw in values.items():
        if key == "log_level":
            level = str(raw).strip().lower()
            if level not in LOG_LEVELS:
                raise PolicyError(
                    f"log_level must be one of {', '.join(LOG_LEVELS)} (got {raw!r})"
                )
            cleaned[key] = level
            continue
        if key not in SETTABLE:
            raise PolicyError(
                f"{key!r} is not a setting an operator may decide centrally; "
                f"allowed: {', '.join(sorted([*SETTABLE, 'log_level']))}"
            )
        try:
            number = int(raw)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"{key} must be a whole number (got {raw!r})") from exc
        low, high = SETTABLE[key]
        if not low <= number <= high:
            raise PolicyError(f"{key} must be between {low} and {high} (got {number})")
        cleaned[key] = number
    return cleaned


def set_policy(
    *,
    tenant_id: str,
    agent_id: str | None,
    settings: dict[str, Any] | None = None,
    desired_version: str | None = None,
    updated_by: str | None = None,
) -> dict[str, Any]:
    """Create or replace one policy row and bump its revision."""
    cleaned = validate_settings(settings or {})
    app_settings = _require_settings()
    now = _now()
    with get_session(app_settings.postgres_url) as session:
        row = session.scalar(
            select(models.EndpointAgentPolicy).where(
                models.EndpointAgentPolicy.tenant_id == tenant_id,
                models.EndpointAgentPolicy.agent_id.is_(None)
                if agent_id is None
                else models.EndpointAgentPolicy.agent_id == agent_id,
            )
        )
        if row is None:
            row = models.EndpointAgentPolicy(
                policy_id=f"eap_{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                agent_id=agent_id,
                settings=cleaned,
                desired_version=(desired_version or "").strip() or None,
                revision=1,
                updated_at=now,
                updated_by=updated_by,
            )
            session.add(row)
        else:
            row.settings = cleaned
            row.desired_version = (desired_version or "").strip() or None
            # Monotonic per row. The agent compares the *sum* of the rows that
            # apply to it, which stays monotonic when either changes — a max
            # would not: a default bumped to 4 and an override later bumped to
            # 4 is one change the agent would never see.
            row.revision = (row.revision or 0) + 1
            row.updated_at = now
            row.updated_by = updated_by
        session.flush()
        return _policy_info(row)


def delete_policy(*, tenant_id: str, agent_id: str | None) -> bool:
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        row = session.scalar(
            select(models.EndpointAgentPolicy).where(
                models.EndpointAgentPolicy.tenant_id == tenant_id,
                models.EndpointAgentPolicy.agent_id.is_(None)
                if agent_id is None
                else models.EndpointAgentPolicy.agent_id == agent_id,
            )
        )
        if row is None:
            return False
        session.delete(row)
        return True


def list_policies(tenant_id: str) -> list[dict[str, Any]]:
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        rows = session.scalars(
            select(models.EndpointAgentPolicy)
            .where(models.EndpointAgentPolicy.tenant_id == tenant_id)
            .order_by(models.EndpointAgentPolicy.agent_id.is_(None).desc())
        ).all()
        return [_policy_info(row) for row in rows]


def _policy_info(row: models.EndpointAgentPolicy) -> dict[str, Any]:
    return {
        "policy_id": row.policy_id,
        "tenant_id": row.tenant_id,
        "agent_id": row.agent_id,
        "settings": dict(row.settings or {}),
        "desired_version": row.desired_version,
        "revision": row.revision,
        "updated_at": row.updated_at.isoformat() + "Z" if row.updated_at else None,
        "updated_by": row.updated_by,
    }


def store_release(
    *,
    version: str,
    platform: str,
    content: bytes,
    notes: str | None = None,
    uploaded_by: str | None = None,
) -> dict[str, Any]:
    """Store one build, replacing any build already under the same identity.

    The digest is computed from the stored bytes rather than accepted from the
    uploader: it is what an endpoint will check a download against before
    running it, and a digest supplied alongside the bytes it describes proves
    nothing about them.
    """
    version = (version or "").strip()
    platform = (platform or "").strip()
    if not version or not platform:
        raise ReleaseError("version and platform are both required")
    if not content:
        raise ReleaseError("the uploaded build is empty")
    if len(content) > MAX_RELEASE_BYTES:
        raise ReleaseError(
            f"build is {len(content)} bytes, over the {MAX_RELEASE_BYTES}-byte limit"
        )

    digest = hashlib.sha256(content).hexdigest()
    app_settings = _require_settings()
    now = _now()
    with get_session(app_settings.postgres_url) as session:
        row = session.get(models.EndpointAgentRelease, (version, platform))
        if row is None:
            row = models.EndpointAgentRelease(
                version=version,
                platform=platform,
                sha256=digest,
                size_bytes=len(content),
                content=content,
                notes=notes,
                uploaded_at=now,
                uploaded_by=uploaded_by,
            )
            session.add(row)
        else:
            row.sha256 = digest
            row.size_bytes = len(content)
            row.content = content
            row.notes = notes
            row.uploaded_at = now
            row.uploaded_by = uploaded_by
        session.flush()
        return _release_info(row)


def list_releases() -> list[dict[str, Any]]:
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        rows = session.scalars(
            select(models.EndpointAgentRelease).order_by(
                models.EndpointAgentRelease.uploaded_at.desc()
            )
        ).all()
        return [_release_info(row) for row in rows]


def delete_release(*, version: str, platform: str) -> bool:
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        row = session.get(models.EndpointAgentRelease, (version, platform))
        if row is None:
            return False
        session.delete(row)
        return True


def get_release_bytes(*, version: str, platform: str) -> tuple[bytes, str] | None:
    """The build's bytes and digest, or ``None`` if it is not stored."""
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        row = session.get(models.EndpointAgentRelease, (version, platform))
        if row is None:
            return None
        return bytes(row.content), row.sha256


def _release_info(row: models.EndpointAgentRelease) -> dict[str, Any]:
    return {
        "version": row.version,
        "platform": row.platform,
        "sha256": row.sha256,
        "size_bytes": row.size_bytes,
        "notes": row.notes,
        "uploaded_at": row.uploaded_at.isoformat() + "Z" if row.uploaded_at else None,
        "uploaded_by": row.uploaded_by,
    }


def plan_for_agent(
    *,
    tenant_id: str,
    agent_id: str,
    current_version: str,
    platform: str | None,
) -> AgentPlan:
    """What this agent should be told now: merged settings, and an update or not.

    The tenant default and the agent's own row are merged field by field, the
    override winning, so a tenant-wide interval and one chatty machine's debug
    logging can coexist. The revision is the sum of the two, which is monotonic
    whichever of them changes.
    """
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        # ``agent_id IN (NULL, :agent)`` would never match the tenant default:
        # in SQL a comparison with NULL is never true, so the default row --
        # the one an installation is most likely to have set -- silently drops
        # out of the result and every agent is told nothing.
        rows = session.scalars(
            select(models.EndpointAgentPolicy).where(
                models.EndpointAgentPolicy.tenant_id == tenant_id,
                or_(
                    models.EndpointAgentPolicy.agent_id.is_(None),
                    models.EndpointAgentPolicy.agent_id == agent_id,
                ),
            )
        ).all()

        default = next((row for row in rows if row.agent_id is None), None)
        override = next((row for row in rows if row.agent_id == agent_id), None)

        merged: dict[str, Any] = {}
        revision = 0
        for row in (default, override):
            if row is None:
                continue
            merged.update(dict(row.settings or {}))
            revision += row.revision or 0

        desired = None
        for row in (default, override):
            if row is not None and row.desired_version:
                desired = row.desired_version

        if not desired or desired == (current_version or ""):
            return AgentPlan(settings=merged, revision=revision, update=None)

        if not platform:
            return AgentPlan(
                settings=merged,
                revision=revision,
                update=None,
                update_blocked=(
                    f"version {desired} requested, but this agent reports no platform"
                ),
            )

        release = session.get(models.EndpointAgentRelease, (desired, platform))
        if release is None:
            return AgentPlan(
                settings=merged,
                revision=revision,
                update=None,
                update_blocked=(
                    f"version {desired} requested, but no build is stored for {platform}"
                ),
            )

        return AgentPlan(
            settings=merged,
            revision=revision,
            update={
                "version": release.version,
                "platform": release.platform,
                "sha256": release.sha256,
                "size_bytes": release.size_bytes,
                "url": f"/api/endpoint/agent/releases/{release.version}/{release.platform}/download",
            },
        )
