"""Installation-wide scanner-config overrides (editable configurator).

A single ``global`` row in ``config_overrides`` holds a nested dict that is
deep-merged onto the base scan config (``settings.config_path``) at job start.
This lets operators toggle pipeline stages and tune scan profiles without
editing the config file — which in real deployments is read-only (k8s
ConfigMap, ``:ro`` compose mount, baked into the image).

Only a strict whitelist of leaf paths is editable; everything else is rejected.
The merged result is additionally validated against the full pydantic
``AppConfig`` schema, so a bad combination can never be persisted.
"""

from __future__ import annotations

import copy
import logging
from datetime import UTC, datetime
from typing import Any, Callable

import yaml

from api.db import models
from api.db.engine import get_session
from api.settings import Settings
from scanner.pipeline.config_schema import ValidationError, load_config

LOG = logging.getLogger(__name__)

_SCOPE = "global"
_PROFILES = ("safe", "balanced", "fast")
_TIMINGS = {"T0", "T1", "T2", "T3", "T4", "T5"}
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_PROFILE_INT_MAX = 1_000_000


def _as_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("expected a boolean")
    return value


def _int_range(lo: int, hi: int) -> Callable[[Any], int]:
    def check(value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
            raise ValueError(f"expected an integer {lo}–{hi}")
        return value

    return check


def _timing(value: Any) -> str:
    if value not in _TIMINGS:
        raise ValueError(f"expected one of {sorted(_TIMINGS)}")
    return value


def _severities(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError("expected a list of strings")
    bad = [v for v in value if v not in _SEVERITIES]
    if bad:
        raise ValueError(f"unknown severities: {bad}")
    return value


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError("expected a list of strings")
    return value


# Static (non-profile) editable leaf paths → validator.
_STATIC_SPEC: dict[str, Callable[[Any], Any]] = {
    "fingerprint.enabled": _as_bool,
    "tls_posture.enabled": _as_bool,
    "nuclei.enabled": _as_bool,
    "nuclei.severities": _severities,
    "nuclei.exclude_tags": _str_list,
    "reporting.pdf_summary": _as_bool,
}
# Per-profile editable leaf → validator (path is profiles.<profile>.<leaf>).
_PROFILE_SPEC: dict[str, Callable[[Any], Any]] = {
    "discover_rate": _int_range(1, _PROFILE_INT_MAX),
    "port_rate": _int_range(1, _PROFILE_INT_MAX),
    "top_ports": _int_range(1, 65535),
    "nmap_timing": _timing,
}

EDITABLE_PATHS: list[str] = [
    *_STATIC_SPEC.keys(),
    *(f"profiles.{p}.{leaf}" for p in _PROFILES for leaf in _PROFILE_SPEC),
]


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


def unflatten(flat: dict[str, Any]) -> dict[str, Any]:
    """Turn a ``{"a.b.c": v}`` dot-path dict (what the UI sends) into a nested
    dict for storage / deep-merge."""
    out: dict[str, Any] = {}
    for path, value in flat.items():
        parts = str(path).split(".")
        node = out
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


def _validator_for(path: str) -> Callable[[Any], Any] | None:
    if path in _STATIC_SPEC:
        return _STATIC_SPEC[path]
    parts = path.split(".")
    if len(parts) == 3 and parts[0] == "profiles" and parts[1] in _PROFILES:
        return _PROFILE_SPEC.get(parts[2])
    return None


def validate_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Whitelist + type/range check. Raises ValueError with a readable message
    listing every rejected path. Returns the (normalized) overrides dict."""
    if not isinstance(data, dict):
        raise ValueError("overrides must be an object")
    errors: list[str] = []
    for path, value in _flatten(data).items():
        validator = _validator_for(path)
        if validator is None:
            errors.append(f"{path}: not an editable setting")
            continue
        try:
            validator(value)
        except ValueError as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise ValueError("invalid config overrides:\n  - " + "\n  - ".join(errors))
    return data


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def base_config_dict(settings: Settings) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(settings.config_path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, yaml.YAMLError):
        LOG.warning("config_override: could not read base config %s", settings.config_path)
        return {}


def get_overrides(settings: Settings) -> dict[str, Any]:
    try:
        with get_session(settings.postgres_url) as session:
            row = session.get(models.ConfigOverride, _SCOPE)
            return dict(row.data) if row and isinstance(row.data, dict) else {}
    except Exception:  # noqa: BLE001 — fail-soft: no overrides on any DB error
        LOG.warning("config_override: get_overrides failed", exc_info=True)
        return {}


def set_overrides(settings: Settings, data: dict[str, Any], *, username: str | None = None) -> dict[str, Any]:
    """Validate against the whitelist AND the full merged schema, then persist.
    Raises ValueError on any validation failure (nothing is written)."""
    validate_overrides(data)
    merged = _deep_merge(base_config_dict(settings), data)
    try:
        load_config(merged)
    except ValidationError as exc:
        raise ValueError(f"merged configuration is invalid: {exc}") from exc
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ConfigOverride, _SCOPE)
        if row is None:
            row = models.ConfigOverride(scope=_SCOPE, data=data, updated_at=datetime.now(UTC), updated_by=username)
            session.add(row)
        else:
            row.data = data
            row.updated_at = datetime.now(UTC)
            row.updated_by = username
    return data


def effective_config_path(settings: Settings, job_id: str) -> str:
    """Path to the config a scan should use: the base file when there are no
    overrides, else a freshly-written merged file under the writable state dir.
    Never raises — falls back to the base path on any error."""
    try:
        overrides = get_overrides(settings)
        if not overrides:
            return str(settings.config_path)
        merged = _deep_merge(base_config_dict(settings), overrides)
        dest_dir = settings.state_dir / "effective-config"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{job_id}.yaml"
        dest.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")
        return str(dest)
    except Exception:  # noqa: BLE001
        LOG.warning("config_override: effective_config_path failed; using base config", exc_info=True)
        return str(settings.config_path)


def editable_snapshot(settings: Settings) -> dict[str, Any]:
    """The current effective + default values for just the editable paths, plus
    the raw stored overrides — everything the configurator UI needs."""
    base = base_config_dict(settings)
    overrides = get_overrides(settings)
    merged = _deep_merge(base, overrides)
    base_flat = _flatten(base)
    merged_flat = _flatten(merged)
    effective = {p: merged_flat.get(p) for p in EDITABLE_PATHS if p in merged_flat}
    defaults = {p: base_flat.get(p) for p in EDITABLE_PATHS if p in base_flat}
    return {
        "editable_paths": EDITABLE_PATHS,
        "defaults": defaults,
        "effective": effective,
        "overrides": _flatten(overrides),
    }
