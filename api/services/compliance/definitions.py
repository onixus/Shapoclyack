"""Bounded, data-only JSON/CSV imports for tenant compliance catalogues (#356).

No expressions, SQL, Python or new evidence signals can be imported. Source
requirements are inferred from signals and may be strengthened, never weakened.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from typing import Any

MAX_BYTES = 1_048_576
MAX_CONTROLS = 500
SCHEMA_VERSION = 1
# Classification provenance, not another classifier. A conjunction must be
# satisfiable by one evidence item, which cannot be both an asset and a finding.
SIGNAL_SOURCES = {
    "unpatched_cve": "findings",
    "overdue_remediation": "findings",
    "overdue_fstec_window": "findings",
    "known_exploited": "findings",
    "internet_exposed_finding": "findings",
    "weak_cryptography": "findings",
    "insecure_protocol": "findings",
    "default_or_weak_credentials": "findings",
    "misconfiguration": "findings",
    "exposed_admin_service": "findings",
    "information_disclosure": "findings",
    "unowned_asset": "assets",
    "unclassified_asset": "assets",
    "stale_asset": "assets",
    "unassessable_software": "endpoint_inventory",
}
SOURCES = frozenset(SIGNAL_SOURCES.values())
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_METADATA = ("framework_id", "name", "version", "scope_note")
_CONTROL = (
    "control_id", "title", "signals", "combinations", "requires",
    "severity_floor", "rationale",
)


class DefinitionError(ValueError):
    """An import is invalid; no part of it may be persisted."""


def _text(value: Any, field: str, maximum: int, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DefinitionError(f"{field}: expected non-empty text, at most {maximum} characters")
    value = value.strip()
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise DefinitionError(f"{field}: invalid UTF-8 text") from exc
    if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in value):
        raise DefinitionError(f"{field}: control characters are not allowed")
    if identifier and (not re.fullmatch(r"[\w.-]+", value) or value in {".", ".."}):
        raise DefinitionError(f"{field}: expected letters, digits, dots, underscores or hyphens")
    return value


def _names(value: Any, field: str, allowed: frozenset[str] | set[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > len(allowed):
        raise DefinitionError(f"{field}: expected a bounded array of names")
    if any(not isinstance(item, str) or item not in allowed for item in value):
        raise DefinitionError(f"{field}: unknown name")
    if len(set(value)) != len(value):
        raise DefinitionError(f"{field}: duplicate name")
    return sorted(value)


def _object(value: Any, allowed: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise DefinitionError(f"{field}: expected an object")
    if set(value) - allowed:
        raise DefinitionError(f"{field}: unknown fields: {', '.join(sorted(set(value) - allowed))}")
    return value


def normalize(document: Any) -> dict[str, Any]:
    """Return the canonical, closed-schema representation, or reject the lot."""
    body = _object(document, {*_METADATA, "controls", "schema_version"}, "framework")
    version = body.get("schema_version", SCHEMA_VERSION)
    if type(version) is not int or version != SCHEMA_VERSION:
        raise DefinitionError("schema_version: only integer 1 is supported")
    metadata = {
        field: _text(body.get(field), field, maximum)
        for field, maximum in zip(_METADATA, (103, 256, 64, 4000), strict=True)
    }
    if not re.fullmatch(r"custom-[a-z0-9][a-z0-9._-]{0,95}", metadata["framework_id"]):
        raise DefinitionError("framework_id: use custom- followed by a lowercase, URL-safe identifier")
    controls = body.get("controls")
    if not isinstance(controls, list) or not 1 <= len(controls) <= MAX_CONTROLS:
        raise DefinitionError(f"controls: expected 1..{MAX_CONTROLS} controls")
    result = []
    seen: set[str] = set()
    for index, raw in enumerate(controls):
        label = f"controls[{index}]"
        row = _object(raw, set(_CONTROL), label)
        control_id = _text(row.get("control_id"), f"{label}.control_id", 64, identifier=True)
        if control_id in seen:
            raise DefinitionError(f"{label}: duplicate control_id {control_id}")
        seen.add(control_id)
        signals = _names(row.get("signals", []), f"{label}.signals", set(SIGNAL_SOURCES))
        groups = row.get("combinations", [])
        if not isinstance(groups, list) or len(groups) > 32:
            raise DefinitionError(f"{label}.combinations: expected at most 32 groups")
        combinations = []
        for group in groups:
            names = _names(group, f"{label}.combinations", set(SIGNAL_SOURCES))
            if len(names) < 2 or len({SIGNAL_SOURCES[name] for name in names}) != 1:
                raise DefinitionError(f"{label}: a combination needs two signals from the same evidence source")
            if names in combinations:
                raise DefinitionError(f"{label}: duplicate combination")
            combinations.append(names)
        if not signals and not combinations:
            raise DefinitionError(f"{label}: no observable technical signals; manual/legal controls cannot be assessed")
        inferred = {SIGNAL_SOURCES[name] for name in signals}
        inferred.update(SIGNAL_SOURCES[name] for group in combinations for name in group)
        requires = _names(row.get("requires", sorted(inferred)), f"{label}.requires", SOURCES)
        if not inferred <= set(requires):
            raise DefinitionError(f"{label}.requires: cannot omit sources required by the signals")
        floor = row.get("severity_floor", "low")
        if not isinstance(floor, str) or floor not in SEVERITIES:
            raise DefinitionError(f"{label}.severity_floor: unknown severity")
        result.append({
            "control_id": control_id,
            "title": _text(row.get("title"), f"{label}.title", 512),
            "signals": signals,
            "combinations": sorted(combinations),
            "requires": requires,
            "severity_floor": floor,
            "rationale": _text(row.get("rationale"), f"{label}.rationale", 4000),
        })
    normalized = {"schema_version": SCHEMA_VERSION, **metadata, "controls": result}
    if len(canonical_bytes(normalized)) > MAX_BYTES:
        raise DefinitionError("normalized definition exceeds the import size limit")
    return normalized


def canonical_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DefinitionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(text: str) -> Any:
    def reject_constant(value: str) -> Any:
        raise DefinitionError(f"non-finite JSON number: {value}")
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=reject_constant)
    except (ValueError, RecursionError) as exc:
        raise DefinitionError("invalid JSON: " + str(exc)) from exc


def parse(content: str, format: str) -> dict[str, Any]:
    """Parse JSON or CSV (array cells use JSON), accepting UTF-8 BOMs."""
    if not isinstance(content, str):
        raise DefinitionError("content must be UTF-8 text")
    try:
        size = len(content.encode("utf-8"))
    except UnicodeError as exc:
        raise DefinitionError("content must be valid UTF-8") from exc
    if size > MAX_BYTES:
        raise DefinitionError(f"import exceeds {MAX_BYTES} bytes")
    content = content.removeprefix("\ufeff")
    if format == "json":
        return normalize(_json(content))
    if format != "csv":
        raise DefinitionError("format must be json or csv")
    try:
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        headers = reader.fieldnames or []
        required = {*_METADATA, "control_id", "title", "rationale"}
        if len(set(headers)) != len(headers) or not required <= set(headers):
            raise DefinitionError("CSV: missing or duplicate headers")
        if set(headers) - {*_METADATA, *_CONTROL}:
            raise DefinitionError("CSV: unknown header")
        metadata: dict[str, Any] | None = None
        controls = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise DefinitionError("CSV: row has a different number of columns")
            current = {key: row[key] for key in _METADATA}
            if metadata is not None and current != metadata:
                raise DefinitionError("CSV: all rows must describe the same framework")
            metadata = current
            control: dict[str, Any] = {key: row[key] for key in _CONTROL if row.get(key)}
            for key in ("signals", "combinations", "requires"):
                if key in control:
                    control[key] = _json(control[key])
            controls.append(control)
            if len(controls) > MAX_CONTROLS:
                raise DefinitionError(f"CSV: more than {MAX_CONTROLS} controls")
        return normalize({**(metadata or {}), "controls": controls})
    except csv.Error as exc:
        raise DefinitionError("invalid CSV: " + str(exc)) from exc
