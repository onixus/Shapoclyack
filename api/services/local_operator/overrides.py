"""Installation-wide, admin-edited inference endpoint over the deployment's.

The deployment (``OCTO_OPERATOR_*``) stays the floor: it alone switches the
operator and its worker on, and it alone permits hosted egress at all. A
platform admin may move the endpoint, model, key and per-request bounds within
that, and every stored value is re-validated through :class:`OperatorConfig`,
so an edit can never reach a state the environment could not.

Two rules keep a credential (and egress consent) with the endpoint it was
issued for:

* the deployment's API key and ``allow_external`` apply only while provider
  and base URL are the deployment's own; an edited endpoint states its own;
* a stored key is dropped when an edit moves the endpoint without restating it.
"""

from __future__ import annotations

import dataclasses
import logging
from datetime import UTC, datetime
from typing import Any

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services.crypto import envelope

from .config import PROVIDERS, OperatorConfig, OperatorConfigurationError

LOG = logging.getLogger(__name__)

SCOPE = "operator"
_KEY_CONTEXT = "operator_settings.api_key"
#: Editable fields, as ``OperatorConfig``/``operator_*`` names. Enablement,
#: worker, queue and response-size bounds stay deployment-owned.
EDITABLE = ("provider", "base_url", "model", "api_key", "allow_external", "timeout_seconds", "max_output_tokens")
_PUBLIC = tuple(name for name in EDITABLE if name != "api_key")


class OperatorSettingsError(ValueError):
    """A stable, sanitized code for the settings API."""


def _deployment(settings) -> dict[str, Any]:
    return {name: getattr(settings, "operator_" + name) for name in EDITABLE}


def _endpoint(values: dict[str, Any]) -> tuple[str, str]:
    provider = values["provider"]
    base_url = values["base_url"] or {"local": "http://127.0.0.1:8080/v1",
                                      "openrouter": "https://openrouter.ai/api/v1"}.get(provider, "")
    return provider, base_url.rstrip("/")


def load(settings) -> tuple[dict[str, Any], datetime | None, str | None]:
    """The stored override (secret still sealed), or ``{}`` with no database.

    A read failure is not "no override": falling back to the deployment's
    endpoint could re-enable egress an admin had moved away from, so it fails
    closed for every caller.
    """
    if not getattr(settings, "postgres_url", ""):
        return {}, None, None
    try:
        with get_session(settings.postgres_url) as session:
            row = session.get(models.ConfigOverride, SCOPE)
            if row is None:
                return {}, None, None
            if not isinstance(row.data, dict):
                raise OperatorConfigurationError("operator_settings_unreadable")
            return dict(row.data), row.updated_at, row.updated_by
    except Exception:  # noqa: BLE001 — any storage error is one sanitized code
        LOG.warning("operator settings: read failed", exc_info=True)
        raise OperatorConfigurationError("operator_settings_unavailable") from None


def apply(settings, stored: dict[str, Any]):
    """``settings`` with the override laid over its ``operator_*`` fields."""
    if not stored:
        return settings
    deployment = _deployment(settings)
    values = dict(deployment)
    values.update({name: stored[name] for name in _PUBLIC if name in stored})
    if values["provider"] != deployment["provider"] and "base_url" not in stored:
        # Another provider never inherits the deployment's endpoint.
        values["base_url"] = ""
    if "api_key" in stored:
        try:
            values["api_key"] = envelope.decrypt_secret(stored["api_key"], context=_KEY_CONTEXT) or ""
        except Exception:  # noqa: BLE001 — a key that cannot be opened is no key
            raise OperatorConfigurationError("operator_settings_unreadable") from None
    elif _endpoint(values) != _endpoint(deployment):
        values["api_key"] = ""
    if "allow_external" not in stored and _endpoint(values) != _endpoint(deployment):
        # Consent was given for the deployment's endpoint, not for this one.
        values["allow_external"] = False
    # Hosted egress needs the deployment's consent as well as the admin's.
    values["allow_external"] = bool(values["allow_external"]) and bool(settings.operator_allow_external)
    return dataclasses.replace(settings, **{"operator_" + name: value for name, value in values.items()})


def effective_settings(settings):
    return apply(settings, load(settings)[0])


def validate(settings, stored: dict[str, Any]) -> OperatorConfig:
    """Validate as if enabled, so a hosted edit without key or consent is refused now."""
    if stored.get("provider", settings.operator_provider) != "local" and not settings.operator_allow_external:
        raise OperatorSettingsError("hosted_operator_not_permitted_by_deployment")
    candidate = apply(settings, stored)
    try:
        config = OperatorConfig.from_settings(dataclasses.replace(candidate, operator_enabled=True))
    except OperatorConfigurationError as exc:
        raise OperatorSettingsError(str(exc)) from None
    if settings.operator_worker_enabled and config.timeout_seconds + 30 > settings.operator_worker_lease_seconds:
        raise OperatorSettingsError("operator_timeout_exceeds_worker_lease")
    return config


def build(settings, previous: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """The override document a PUT of ``changes`` would store (key still plaintext).

    ``changes`` holds only the fields the caller sent; ``api_key`` absent or
    ``None`` keeps the stored key while the endpoint is unchanged.
    """
    unknown = set(changes) - set(EDITABLE)
    if unknown:
        raise OperatorSettingsError("not_an_editable_operator_setting")
    if changes.get("provider") is not None and changes["provider"] not in PROVIDERS:
        raise OperatorSettingsError("unsupported_operator_provider")
    stored = {name: changes[name] for name in _PUBLIC if changes.get(name) is not None}
    if changes.get("api_key") is not None:
        stored["api_key"] = changes["api_key"]
    elif "api_key" in previous:
        before = apply(settings, previous)
        after = apply(settings, stored)
        if _endpoint(_deployment(before)) == _endpoint(_deployment(after)):
            stored["api_key"] = previous["api_key"]
    validate(settings, stored)
    return stored


def _audit_view(stored: dict[str, Any]) -> dict[str, Any]:
    view = {name: stored[name] for name in _PUBLIC if name in stored}
    if "api_key" in stored:
        view["credential"] = "set" if stored["api_key"] else "cleared"
    return view


def _write(settings, stored: dict[str, Any] | None, previous: dict[str, Any], *, username, audit) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ConfigOverride, SCOPE)
        if stored is None:
            if row is not None:
                session.delete(row)
        elif row is None:
            session.add(models.ConfigOverride(scope=SCOPE, data=stored, updated_at=datetime.now(UTC), updated_by=username))
        else:
            row.data = stored
            row.updated_at = datetime.now(UTC)
            row.updated_by = username
        audit_service.record(session, audit, action=audit_service.ACTION_CONFIG_UPDATE,
                             resource_type="operator_settings", resource_id=SCOPE,
                             before=_audit_view(previous), after=_audit_view(stored or {}))
    from . import runtime
    runtime.reset_cache()


def update(settings, changes: dict[str, Any], *, username: str | None = None, audit=None) -> dict[str, Any]:
    if not getattr(settings, "postgres_url", ""):
        raise OperatorSettingsError("operator_settings_storage_unavailable")
    previous = load(settings)[0]
    stored = build(settings, previous, changes)
    if stored.get("api_key"):
        stored["api_key"] = envelope.encrypt_secret(stored["api_key"], context=_KEY_CONTEXT)
    _write(settings, stored or None, previous, username=username, audit=audit)
    return stored


def reset(settings, *, username: str | None = None, audit=None) -> None:
    if not getattr(settings, "postgres_url", ""):
        raise OperatorSettingsError("operator_settings_storage_unavailable")
    previous = load(settings)[0]
    if previous:
        _write(settings, None, previous, username=username, audit=audit)


def _view(values: dict[str, Any]) -> dict[str, Any]:
    view = {name: values[name] for name in _PUBLIC}
    view["api_key_set"] = bool(values["api_key"])
    return view


def snapshot(settings) -> dict[str, Any]:
    """Deployment, override and effective values; never a credential."""
    stored, updated_at, updated_by = load(settings)
    deployment = _deployment(settings)
    error = effective = None
    try:
        candidate = apply(settings, stored)
        effective = _deployment(candidate)
        OperatorConfig.from_settings(candidate)
    except OperatorConfigurationError as exc:
        error = str(exc)
    if effective is not None:
        if stored.get("api_key"):
            key_source = "override"
        else:
            key_source = "deployment" if effective["api_key"] else "none"
        effective = {**_view(effective), "api_key_source": key_source}
    override = None
    if stored:
        override = {name: stored[name] for name in _PUBLIC if name in stored}
        if "api_key" in stored:
            override["api_key_set"] = bool(stored["api_key"])
    return {
        "enabled": bool(settings.operator_enabled),
        "worker_enabled": bool(settings.operator_worker_enabled),
        "external_permitted": bool(settings.operator_allow_external),
        "providers": sorted(PROVIDERS),
        "deployment": _view(deployment),
        "override": override,
        "effective": effective,
        "valid": error is None,
        "error": error,
        "updated_at": updated_at.isoformat() if updated_at else None,
        "updated_by": updated_by,
    }
