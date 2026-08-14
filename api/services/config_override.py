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
from typing import Any, Callable, get_args

import yaml

from api.db import models
from api.db.engine import get_session
from api.settings import Settings
from scanner.pipeline.config_schema import NaabuTopPorts, ValidationError, load_config

LOG = logging.getLogger(__name__)

_SCOPE = "global"
_PROFILES = ("safe", "balanced", "fast", "test")
_TIMINGS = {"T0", "T1", "T2", "T3", "T4", "T5"}
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_PROFILE_INT_MAX = 1_000_000
#: Derived from the schema so the two constraints cannot drift apart.
_NAABU_TOP_PORTS: tuple[int, ...] = get_args(NaabuTopPorts)


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


def _int_choices(choices: tuple[int, ...]) -> Callable[[Any], int]:
    def check(value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value not in choices:
            raise ValueError(f"expected one of {list(choices)}")
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


def _nonempty_str(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected a non-empty string")
    return value


def _enum(choices: tuple[str, ...]) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if value not in choices:
            raise ValueError(f"expected one of {list(choices)}")
        return value

    return check


_SERVICE_BACKENDS = ("nmap", "pulse", "hybrid")

#: Placeholder returned instead of a stored secret, and accepted back on update
#: to mean "leave the stored value alone".
SECRET_MASK = "••••••••"


def _secret(value: Any) -> str:
    """A write-only string: any string is accepted, including "" to clear it."""
    if not isinstance(value, str):
        raise ValueError("expected a string")
    return value.strip()


#: Editable paths whose value must never be returned by the API.
SECRET_PATHS: frozenset[str] = frozenset({"enrichment.cvss4.nvd_api_key"})


# Static (non-profile) editable leaf paths → validator. Ranges mirror the
# NucleiConfig pydantic bounds in scanner/pipeline/config_schema.py.
_STATIC_SPEC: dict[str, Callable[[Any], Any]] = {
    "fingerprint.enabled": _as_bool,
    "tls_posture.enabled": _as_bool,
    "tls_posture.hostname_mismatch": _as_bool,
    "nuclei.enabled": _as_bool,
    "nuclei.severities": _severities,
    "nuclei.exclude_tags": _str_list,
    "nuclei.templates_dir": _nonempty_str,
    "nuclei.concurrency": _int_range(1, 100),
    "nuclei.rate_limit": _int_range(1, 10_000),
    "nuclei.timeout_seconds": _int_range(1, 60),
    "nuclei.retries": _int_range(0, 5),
    "reporting.pdf_summary": _as_bool,
    "service_probe.backend": _enum(_SERVICE_BACKENDS),
    "service_probe.shadow": _as_bool,
    "enrichment.cvss4.nvd_api_key": _secret,
}
# Per-profile editable leaf → validator (path is profiles.<profile>.<leaf>).
_PROFILE_SPEC: dict[str, Callable[[Any], Any]] = {
    "discover_rate": _int_range(1, _PROFILE_INT_MAX),
    "port_rate": _int_range(1, _PROFILE_INT_MAX),
    # Not a count -- naabu's -top-ports takes a named port set (see
    # NaabuTopPorts in scanner/pipeline/config_schema.py). Rejected here so the
    # configurator names the two accepted values, instead of bouncing off the
    # AppConfig re-validation with a less specific message.
    "top_ports": _int_choices(_NAABU_TOP_PORTS),
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


def _restore_masked_secrets(stored: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """The UI only ever sees SECRET_MASK for a set secret, so it sends the mask
    back untouched on any unrelated edit. Treat that as "keep what is stored"
    -- otherwise saving, say, a rate limit would overwrite the key with a row
    of bullets. An empty string still clears it."""
    stored_flat = _flatten(stored)
    incoming_flat = _flatten(incoming)
    changed = False
    for path in SECRET_PATHS:
        if incoming_flat.get(path) != SECRET_MASK:
            continue
        changed = True
        if path in stored_flat:
            incoming_flat[path] = stored_flat[path]
        else:
            del incoming_flat[path]
    return unflatten(incoming_flat) if changed else incoming


def set_overrides(settings: Settings, data: dict[str, Any], *, username: str | None = None) -> dict[str, Any]:
    """Validate against the whitelist AND the full merged schema, then persist.
    Raises ValueError on any validation failure (nothing is written)."""
    data = _restore_masked_secrets(get_overrides(settings), data)
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


def effective_config_path(
    settings: Settings, job_id: str, extra: dict[str, Any] | None = None
) -> str:
    """Path to the config a scan should use: the base file when there are no
    overrides and no ``extra``, else a freshly-written merged file under the
    writable state dir.

    ``extra`` is a nested override deep-merged *after* the stored installation
    overrides — a per-job addition the configurator does not hold, currently
    the selected brute-force wordlist path (see ``api/services/jobs.py``). Unlike
    the stored overrides it is not whitelist-checked here, so callers must build
    it themselves from validated inputs, never from client-supplied config.

    Never raises — falls back to the base path on any error. ``extra`` is the
    exception: a job that asked for a specific wordlist must not silently run
    without it, so a failure to write the merged file with ``extra`` present is
    re-raised for the caller to surface."""
    overrides = get_overrides(settings)
    if not overrides and not extra:
        return str(settings.config_path)
    try:
        merged = _deep_merge(base_config_dict(settings), overrides)
        if extra:
            merged = _deep_merge(merged, extra)
        dest_dir = settings.state_dir / "effective-config"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{job_id}.yaml"
        dest.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")
        return str(dest)
    except Exception:  # noqa: BLE001
        if extra:
            raise
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
    overrides_flat = _flatten(overrides)
    # GET /config is viewer-readable, so secrets must never leave this process.
    # A set secret reads back as SECRET_MASK; sending the mask back on update
    # means "unchanged" (see set_overrides).
    for path in SECRET_PATHS:
        for bucket in (effective, defaults, overrides_flat):
            if bucket.get(path):
                bucket[path] = SECRET_MASK
    return {
        "editable_paths": EDITABLE_PATHS,
        "defaults": defaults,
        "effective": effective,
        "overrides": overrides_flat,
    }
