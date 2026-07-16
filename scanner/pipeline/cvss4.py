"""CVSS v4.0 lookup database for CVE enrichment."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)

# Qualitative severity from FIRST CVSS v4.0 score ranges (same bands as v3).
def score_to_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


class Cvss4Database:
    """JSON map: CVE-ID → {score, vector, severity}."""

    def __init__(self, entries: dict[str, dict[str, Any]] | None = None) -> None:
        self._entries = {k.upper(): v for k, v in (entries or {}).items()}

    @classmethod
    def load(cls, path: Path | None) -> Cvss4Database:
        if path is None or not path.is_file():
            return cls({})
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOG.warning("Failed to load CVSS4 database %s: %s", path, exc)
            return cls({})
        if not isinstance(raw, dict):
            LOG.warning("CVSS4 database %s must be a JSON object", path)
            return cls({})
        # Support both flat {CVE: {...}} and wrapped {entries: {CVE: {...}}} layouts.
        source = raw.get("entries") if isinstance(raw.get("entries"), dict) else raw
        entries: dict[str, dict[str, Any]] = {}
        for key, value in source.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            if not key.upper().startswith("CVE-"):
                continue
            score = value.get("score")
            try:
                score_f = float(score) if score is not None else None
            except (TypeError, ValueError):
                score_f = None
            entries[key.upper()] = {
                "score": score_f,
                "vector": value.get("vector") or value.get("vectorString") or "",
                "severity": value.get("severity") or score_to_severity(score_f),
            }
        LOG.info("Loaded CVSS4 database with %d CVE entries from %s", len(entries), path)
        return cls(entries)

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, cve: str | None) -> dict[str, Any] | None:
        if not cve:
            return None
        return self._entries.get(cve.upper())


def enrich_vulnerabilities(vulnerabilities: list[dict], database: Cvss4Database) -> list[dict]:
    """Attach cvss4 / cvss4_vector / cvss4_severity; prefer CVSS4 for display severity when present."""
    for item in vulnerabilities:
        hit = database.lookup(item.get("cve"))
        if not hit:
            item.setdefault("cvss4", None)
            item.setdefault("cvss4_vector", None)
            item.setdefault("cvss4_severity", None)
            continue
        item["cvss4"] = hit.get("score")
        item["cvss4_vector"] = hit.get("vector") or None
        item["cvss4_severity"] = hit.get("severity") or score_to_severity(hit.get("score"))
        # Prefer CVSS v4 for overall severity when a score is available.
        if item["cvss4"] is not None:
            item["severity"] = item["cvss4_severity"]
    vulnerabilities.sort(
        key=lambda item: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}.get(
                str(item.get("severity") or "unknown"), 0
            ),
            float(item["cvss4"]) if item.get("cvss4") is not None else float(item["cvss"] or 0.0),
        ),
        reverse=True,
    )
    return vulnerabilities
