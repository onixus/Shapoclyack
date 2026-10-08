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

**Why signed native packages are required.** An upgrade executes new code.
The API transports a byte-bound publisher envelope and package over the agent's
authenticated channel; the endpoint and its privileged supervisor independently
verify the signature against locally provisioned trust. Unsigned executable
uploads, offers and downloads are prohibited, including rows stored by older
API releases. Legacy endpoints require administrative native migration.
"""

from __future__ import annotations

import hashlib
import copy
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select

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

UNSIGNED_RELEASE_BLOCKED = (
    "unsigned executable updates are disabled; migrate legacy agents to a "
    "native installation with locally provisioned signing keys"
)


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


def validate_signed_manifest(envelope, *, version, platform, digest, size_bytes):
    """Validate the envelope shape and byte binding without receiving trust keys.

    Endpoint trust is provisioned locally and endpoints verify Ed25519. The
    platform must preserve the publisher's exact manifest and cannot manufacture
    a signature or silently adjust a signed expiry/sequence.
    """
    if envelope is None:
        return None
    if not isinstance(envelope, dict) or set(envelope) != {"manifest", "signature"}:
        raise ReleaseError(
            "signed_manifest must contain exactly manifest and signature"
        )
    manifest = envelope["manifest"]
    required = {
        "schema",
        "key_id",
        "version",
        "platform",
        "package_kind",
        "size_bytes",
        "sha256",
        "expires_at",
        "sequence",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ReleaseError("invalid signed manifest fields")
    if not isinstance(envelope["signature"], str) or not re.fullmatch(
        r"[0-9a-f]{128}", envelope["signature"]
    ):
        raise ReleaseError("invalid Ed25519 signature encoding")
    for key in ("schema", "size_bytes", "expires_at", "sequence"):
        if type(manifest[key]) is not int or not 0 <= manifest[key] <= 2**64 - 1:
            raise ReleaseError(f"manifest {key} must be an unsigned 64-bit integer")
    if (
        manifest["schema"] != 1
        or not isinstance(manifest["package_kind"], str)
        or manifest["package_kind"] not in {"deb", "rpm", "msi", "pkg"}
    ):
        raise ReleaseError("unsupported manifest schema or native package kind")
    if not isinstance(manifest["key_id"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,128}", manifest["key_id"]
    ):
        raise ReleaseError("invalid manifest key_id")
    if manifest["expires_at"] <= int(time.time()):
        raise ReleaseError("signed manifest has expired")
    if any(
        manifest[name] != value
        for name, value in (
            ("version", version),
            ("platform", platform),
            ("sha256", digest),
            ("size_bytes", size_bytes),
        )
    ):
        raise ReleaseError(
            "signed manifest does not describe the uploaded bytes/version/platform"
        )
    return copy.deepcopy(envelope)


def _lock_release_identity(session, version, platform):
    # Row locks cannot serialize the first uploads of two installer variants.
    # Serialize the pair so a concurrent unsigned upload cannot bypass native
    # promotion, and two writers cannot overwrite the release sequence floor.
    if session.get_bind().dialect.name == "postgresql":
        key = int.from_bytes(
            hashlib.sha256(f"endpoint-release:{version}/{platform}".encode()).digest()[
                :8
            ],
            "big",
            signed=True,
        )
        session.execute(select(func.pg_advisory_xact_lock(key)))


def store_release(
    *,
    version: str,
    platform: str,
    content: bytes,
    notes: str | None = None,
    uploaded_by: str | None = None,
    signed_manifest: dict[str, Any] | None = None,
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
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", version) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,64}", platform
    ):
        raise ReleaseError("version and platform must be bounded path-safe identifiers")
    if not content:
        raise ReleaseError("the uploaded build is empty")
    if len(content) > MAX_RELEASE_BYTES:
        raise ReleaseError(
            f"build is {len(content)} bytes, over the {MAX_RELEASE_BYTES}-byte limit"
        )

    digest = hashlib.sha256(content).hexdigest()
    signed_manifest = validate_signed_manifest(
        signed_manifest,
        version=version,
        platform=platform,
        digest=digest,
        size_bytes=len(content),
    )
    if signed_manifest is None:
        raise ReleaseError(UNSIGNED_RELEASE_BLOCKED)
    package_kind = signed_manifest["manifest"]["package_kind"]
    app_settings = _require_settings()
    now = _now()
    with get_session(app_settings.postgres_url) as session:
        _lock_release_identity(session, version, platform)
        variants = session.scalars(
            select(models.EndpointAgentRelease)
            .where(
                models.EndpointAgentRelease.version == version,
                models.EndpointAgentRelease.platform == platform,
            )
            .with_for_update()
        ).all()
        # Promotion to native updates retires the old unsigned executable.
        # Other signed installer formats retain their own sequence and bytes.
        for variant in variants:
            if variant.package_kind == "binary":
                session.delete(variant)
        row = next(
            (variant for variant in variants if variant.package_kind == package_kind),
            None,
        )
        if row is None:
            row = models.EndpointAgentRelease(
                version=version,
                platform=platform,
                package_kind=package_kind,
                sha256=digest,
                size_bytes=len(content),
                content=content,
                signed_manifest=signed_manifest,
                notes=notes,
                uploaded_at=now,
                uploaded_by=uploaded_by,
            )
            session.add(row)
        else:
            if row.signed_manifest:
                if (
                    signed_manifest["manifest"]["sequence"]
                    < row.signed_manifest["manifest"]["sequence"]
                ):
                    raise ReleaseError("release sequence cannot go backwards")
                if (
                    signed_manifest["manifest"]["sequence"]
                    == row.signed_manifest["manifest"]["sequence"]
                    and digest != row.sha256
                ):
                    raise ReleaseError(
                        "different bytes require a newer signed release sequence"
                    )
            row.signed_manifest = signed_manifest
            row.sha256 = digest
            row.size_bytes = len(content)
            row.content = content
            row.notes = notes
            row.uploaded_at = now
            row.uploaded_by = uploaded_by
        session.flush()
        return _release_info(row)


def list_releases(*, show_uploader: bool = True) -> list[dict[str, Any]]:
    """Every stored build, newest first.

    ``show_uploader=False`` blanks ``uploaded_by`` (#510): the builds are the
    installation's and a tenant reads the list to choose one, which needs the
    version and the digest, not the name of the platform account that put it
    there.
    """
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        rows = session.scalars(
            select(models.EndpointAgentRelease).order_by(
                models.EndpointAgentRelease.uploaded_at.desc()
            )
        ).all()
        infos = [_release_info(row) for row in rows]
    if not show_uploader:
        for info in infos:
            info["uploaded_by"] = None
    return infos


def _release_variant(session, *, version, platform, package_kind=None):
    query = select(models.EndpointAgentRelease).where(
        models.EndpointAgentRelease.version == version,
        models.EndpointAgentRelease.platform == platform,
    )
    if package_kind is not None:
        query = query.where(models.EndpointAgentRelease.package_kind == package_kind)
    rows = session.scalars(query.limit(2)).all()
    if len(rows) > 1:
        raise ReleaseError("multiple installer formats exist; specify package_kind")
    return rows[0] if rows else None


def delete_release(
    *, version: str, platform: str, package_kind: str | None = None
) -> dict[str, Any] | None:
    """Remove one build; what was removed, or ``None`` if nothing was stored.

    Returned rather than a bool because the row is gone afterwards and the
    audit record is the only place left that says which bytes endpoints were
    being handed under that version, and who put them there (#510).
    """
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        _lock_release_identity(session, version, platform)
        row = _release_variant(
            session, version=version, platform=platform, package_kind=package_kind
        )
        if row is None:
            return None
        info = _release_info(row)
        session.delete(row)
        return info


def get_release_bytes(
    *, version: str, platform: str, package_kind: str | None = None
) -> tuple[bytes, str] | None:
    """The build's bytes and digest, or ``None`` if it is not stored."""
    app_settings = _require_settings()
    with get_session(app_settings.postgres_url) as session:
        row = _release_variant(
            session, version=version, platform=platform, package_kind=package_kind
        )
        if row is None:
            return None
        # Old rows remain available for inspection/deletion, but a cached URL
        # must not bypass the same prohibition enforced on heartbeat offers.
        if not row.signed_manifest or row.package_kind == "binary":
            raise ReleaseError(UNSIGNED_RELEASE_BLOCKED)
        return bytes(row.content), row.sha256


def _release_info(row: models.EndpointAgentRelease) -> dict[str, Any]:
    return {
        "version": row.version,
        "platform": row.platform,
        "package_kind": row.package_kind,
        "sha256": row.sha256,
        "size_bytes": row.size_bytes,
        "signed_manifest": copy.deepcopy(row.signed_manifest),
        "notes": row.notes,
        "uploaded_at": row.uploaded_at.isoformat() + "Z" if row.uploaded_at else None,
        "uploaded_by": row.uploaded_by,
    }


def _native_package_kind(session, *, tenant_id, agent_id, platform, reported_kind):
    """Current Lariska omits its installer kind; infer only an unambiguous one.

    Linux collectors select package databases, not merely installed commands.
    A toolbox with both databases requires an explicit local installer report.
    """
    if "-windows-" in platform:
        supported = {"msi"}
    elif platform.endswith("-apple-darwin"):
        supported = {"pkg"}
    elif "-linux-" in platform:
        supported = {"deb", "rpm"}
    else:
        supported = set()
    if reported_kind is not None:
        return reported_kind if reported_kind in supported else None
    if len(supported) == 1:
        return next(iter(supported))
    if supported != {"deb", "rpm"}:
        return None
    device = session.scalar(
        select(models.EndpointDevice).where(
            models.EndpointDevice.tenant_id == tenant_id,
            models.EndpointDevice.agent_id == agent_id,
        )
    )
    if device is None:
        return None
    sources = {
        state["source"]
        for state in (device.source_states or [])
        if state.get("status") != "not_applicable"
    }
    if not device.source_states and device.latest_snapshot_id:
        sources = set(
            session.scalars(
                select(models.EndpointSoftwareItem.source).where(
                    models.EndpointSoftwareItem.snapshot_id
                    == device.latest_snapshot_id,
                    models.EndpointSoftwareItem.tenant_id == tenant_id,
                )
            ).all()
        )
    kinds = set()
    if sources & {"apt", "dpkg"}:
        kinds.add("deb")
    if "rpm" in sources:
        kinds.add("rpm")
    return next(iter(kinds)) if len(kinds) == 1 else None


def plan_for_agent(
    *,
    tenant_id: str,
    agent_id: str,
    current_version: str,
    platform: str | None,
    capabilities: list[str] | None = None,
    package_kind: str | None = None,
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

        signed_updates = "signed_updates" in (capabilities or [])
        variants = session.scalars(
            select(models.EndpointAgentRelease).where(
                models.EndpointAgentRelease.version == desired,
                models.EndpointAgentRelease.platform == platform,
            )
        ).all()
        if signed_updates and variants:
            native_kind = _native_package_kind(
                session,
                tenant_id=tenant_id,
                agent_id=agent_id,
                platform=platform,
                reported_kind=package_kind,
            )
            if native_kind is None:
                return AgentPlan(
                    settings=merged,
                    revision=revision,
                    update=None,
                    update_blocked="native installer format is unknown or ambiguous; report package_kind or submit package inventory",
                )
            release = next(
                (row for row in variants if row.package_kind == native_kind), None
            )
            if release is None:
                return AgentPlan(
                    settings=merged,
                    revision=revision,
                    update=None,
                    update_blocked=f"this agent requires a signed native package manifest for {native_kind}",
                )
        else:
            release = next(
                (row for row in variants if row.package_kind == "binary"), None
            )
            if release is None and variants:
                return AgentPlan(
                    settings=merged,
                    revision=revision,
                    update=None,
                    update_blocked="this agent lacks signed native update support; migrate it to a native installation before requesting this release",
                )
        if release is None:
            return AgentPlan(
                settings=merged,
                revision=revision,
                update=None,
                update_blocked=(
                    f"version {desired} requested, but no build is stored for {platform}"
                ),
            )

        if not release.signed_manifest or release.package_kind == "binary":
            return AgentPlan(
                settings=merged,
                revision=revision,
                update=None,
                update_blocked=UNSIGNED_RELEASE_BLOCKED,
            )

        if release.signed_manifest and "signed_updates" not in (capabilities or []):
            return AgentPlan(
                settings=merged,
                revision=revision,
                update=None,
                update_blocked=(
                    "this agent lacks signed native update support; migrate it to "
                    "a native installation before requesting this release"
                ),
            )

        if release.signed_manifest and release.signed_manifest["manifest"][
            "expires_at"
        ] <= int(time.time()):
            return AgentPlan(
                settings=merged,
                revision=revision,
                update=None,
                update_blocked="the signed update manifest has expired",
            )

        return AgentPlan(
            settings=merged,
            revision=revision,
            update={
                "version": release.version,
                "platform": release.platform,
                "sha256": release.sha256,
                "size_bytes": release.size_bytes,
                "signed_manifest": copy.deepcopy(release.signed_manifest),
                "url": f"/api/endpoint/agent/releases/{release.version}/{release.platform}/download?package_kind={release.package_kind}",
            },
        )
