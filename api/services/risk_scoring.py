"""Risk scoring for ClickHouse vulnerability rows (Phase 3).

Model ``mvp-1`` fills the enrichment columns that were stubs in ``mvp-0``:

* ``base_cvss`` — prefer CVSS4, else legacy CVSS
* ``epss_score`` — optional local CVE→EPSS overlay (else 0)
* ``asset_criticality`` — 0–4 from severity / CVSS bands
* ``exploit_active`` — 1 if CVE is in optional CISA KEV overlay
* ``cisa_decision`` — SSVC-lite Track / Attend / Act / Immediate
* ``contextual_score`` — 0–10 blend of CVSS, EPSS, exploit, criticality

Overlays (JSON) are opt-in so the image stays redistributable:

* ``OCTO_EPSS_DATABASE`` / default ``scanner/data/epss/epss-overlay.json``
* ``OCTO_KEV_DATABASE`` / default ``scanner/data/kev/kev-overlay.json``
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

LOG = logging.getLogger("octo-man.risk-scoring")

SCORING_MODEL_VERSION = "mvp-1"

_SEVERITY_CRITICALITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
    "info": 0,
}

# Ports that typically raise asset criticality one notch (capped at 4).
_HIGH_VALUE_PORTS = frozenset(
    {22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
)


def _load_cve_float_map(path: Path | None) -> dict[str, float]:
    if path is None or not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("Failed to load scoring overlay %s: %s", path, exc)
        return {}
    if not isinstance(raw, dict):
        return {}
    source = raw.get("entries") if isinstance(raw.get("entries"), dict) else raw
    out: dict[str, float] = {}
    for key, value in source.items():
        if not isinstance(key, str) or key in ("version", "source", "updated"):
            continue
        cve = key.upper()
        try:
            if isinstance(value, dict):
                score = value.get("epss") if "epss" in value else value.get("score")
            else:
                score = value
            out[cve] = float(score)
        except (TypeError, ValueError):
            continue
    LOG.info("Loaded %d EPSS entries from %s", len(out), path)
    return out


def _load_kev_set(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("Failed to load KEV overlay %s: %s", path, exc)
        return set()
    entries: Any
    if isinstance(raw, dict):
        entries = raw.get("entries") or raw.get("vulnerabilities") or raw.get("cves") or []
        if isinstance(entries, dict):
            entries = list(entries.keys())
    elif isinstance(raw, list):
        entries = raw
    else:
        return set()
    out: set[str] = set()
    for item in entries:
        if isinstance(item, str):
            out.add(item.upper())
        elif isinstance(item, dict):
            cve = item.get("cve") or item.get("cveID") or item.get("cve_id")
            if cve:
                out.add(str(cve).upper())
    LOG.info("Loaded %d KEV CVEs from %s", len(out), path)
    return out


class RiskScoring:
    """Stateless scorer with optional EPSS / KEV overlays."""

    def __init__(
        self,
        *,
        epss: dict[str, float] | None = None,
        kev: set[str] | None = None,
    ) -> None:
        self._epss = epss or {}
        self._kev = kev or set()

    @classmethod
    def from_env(cls) -> RiskScoring:
        epss_path = Path(
            os.environ.get("OCTO_EPSS_DATABASE", "scanner/data/epss/epss-overlay.json")
        )
        kev_path = Path(os.environ.get("OCTO_KEV_DATABASE", "scanner/data/kev/kev-overlay.json"))
        return cls(epss=_load_cve_float_map(epss_path), kev=_load_kev_set(kev_path))

    @staticmethod
    def base_cvss(item: dict[str, Any]) -> float:
        for key in ("cvss4", "cvss"):
            raw = item.get(key)
            if raw is None:
                continue
            try:
                return max(0.0, min(10.0, float(raw)))
            except (TypeError, ValueError):
                continue
        return 0.0

    @staticmethod
    def _severity(item: dict[str, Any], base_cvss: float) -> str:
        sev = str(item.get("severity") or item.get("cvss4_severity") or "").lower().strip()
        if sev in _SEVERITY_CRITICALITY:
            return sev
        if base_cvss >= 9.0:
            return "critical"
        if base_cvss >= 7.0:
            return "high"
        if base_cvss >= 4.0:
            return "medium"
        if base_cvss > 0:
            return "low"
        return "unknown"

    def asset_criticality(self, item: dict[str, Any], base_cvss: float) -> int:
        sev = self._severity(item, base_cvss)
        level = _SEVERITY_CRITICALITY.get(sev, 0)
        try:
            port = int(str(item.get("port") or "0").split("/")[0] or 0)
        except ValueError:
            port = 0
        if port in _HIGH_VALUE_PORTS:
            level = min(4, max(level + 1, 2))
        return int(level)

    def epss_score(self, cve: str) -> float:
        if not cve:
            return 0.0
        return float(self._epss.get(cve.upper(), 0.0))

    def exploit_active(self, cve: str) -> int:
        if cve and cve.upper() in self._kev:
            return 1
        return 0

    def cisa_decision(
        self,
        *,
        base_cvss: float,
        epss: float,
        exploit_active: int,
    ) -> str:
        if exploit_active and base_cvss >= 7.0:
            return "Immediate"
        if base_cvss >= 9.0 or (base_cvss >= 7.0 and epss >= 0.1):
            return "Act"
        if base_cvss >= 4.0 or epss >= 0.05:
            return "Attend"
        return "Track"

    def contextual_score(
        self,
        *,
        base_cvss: float,
        epss: float,
        exploit_active: int,
        asset_criticality: int,
    ) -> float:
        """0–10 score: CVSS-weighted with EPSS, exploit, and asset criticality."""
        score = (
            0.55 * base_cvss
            + 0.30 * (epss * 10.0)
            + 0.10 * (10.0 if exploit_active else 0.0)
            + 0.05 * (asset_criticality / 4.0 * 10.0)
        )
        return round(max(0.0, min(10.0, score)), 2)

    def score_vulnerability(self, item: dict[str, Any]) -> dict[str, Any]:
        cve = str(item.get("cve") or item.get("script_id") or "")
        base = self.base_cvss(item)
        epss = self.epss_score(cve) if cve.upper().startswith("CVE-") else 0.0
        exploit = self.exploit_active(cve) if cve.upper().startswith("CVE-") else 0
        criticality = self.asset_criticality(item, base)
        decision = self.cisa_decision(base_cvss=base, epss=epss, exploit_active=exploit)
        contextual = self.contextual_score(
            base_cvss=base,
            epss=epss,
            exploit_active=exploit,
            asset_criticality=criticality,
        )
        return {
            "base_cvss": base,
            "epss_score": epss,
            "asset_criticality": criticality,
            "exploit_active": exploit,
            "cisa_decision": decision,
            "contextual_score": contextual,
            "scoring_model_version": SCORING_MODEL_VERSION,
        }


_SCORER: RiskScoring | None = None


def get_scorer() -> RiskScoring:
    global _SCORER
    if _SCORER is None:
        _SCORER = RiskScoring.from_env()
    return _SCORER


def reset_scorer_for_tests(scorer: RiskScoring | None = None) -> None:
    global _SCORER
    _SCORER = scorer
