"""Risk scoring for ClickHouse vulnerability rows (Phase 3).

Model ``mvp-2`` scores each finding and explains the result:

* ``base_cvss`` — prefer CVSS4, else legacy CVSS
* ``epss_score`` — the finding's own EPSS when the scanner supplied one
  (Pulse ships real EPSS per finding), else the local CVE→EPSS overlay
* ``asset_criticality`` — operator-set value from the Phase 7 asset inventory
  when available (``Asset.asset_criticality``), else 0–4 from severity / CVSS
  bands and high-value ports (Phase 9.4)
* ``exploit_active`` — 1 if the finding is flagged ``in_kev`` by the scanner or
  the CVE is in the local CISA KEV overlay
* ``cisa_decision`` — SSVC-lite Track / Attend / Act / Immediate
* ``contextual_score`` — 0–10 blend of CVSS, EPSS, exploit, criticality,
  discounted by scanner confidence for unconfirmed findings
* ``risk_explanation`` — one line naming the factors that produced the above

Confidence handling (ROADMAP P4 "risk-priority explanation"): Pulse separates
observations from hypotheses and tells us which is which via ``finding_class``
/ ``confidence`` / ``requires_confirmation`` (GenDec ``docs/findings.md``). An
``exposure`` observation or an unverified ``keyword_cve`` must not be scored
like a confirmed version match, so both are discounted by their confidence and
capped below ``Act`` — the decision that would page someone.

Overlays (JSON) are opt-in so the image stays redistributable:

* ``OCTO_EPSS_DATABASE`` / default ``scanner/data/epss/epss-overlay.json``
* ``OCTO_KEV_DATABASE`` / default ``scanner/data/kev/kev-overlay.json``

The committed defaults are tiny seed stubs. They now matter less on the default
scan path — findings that arrive with their own EPSS/KEV data no longer depend
on them at all — but they still cover nuclei/NSE findings. A refresh job
(``scripts/fetch-epss-db.sh`` / ``scripts/fetch-kev-db.sh``) rewrites them with
the real feeds on a shared volume, and ``get_scorer`` hot-reloads changed
overlays without a restart (``OCTO_ENRICHMENT_RELOAD_SECONDS``, default 60).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

LOG = logging.getLogger("shapoclyack.risk-scoring")

SCORING_MODEL_VERSION = "mvp-2"

#: Finding classes the scanner cannot confirm on its own: an ``exposure`` is
#: "this service is reachable", a ``keyword_cve`` is an unverified NVD keyword
#: hit. Both are triage signal, never a confirmed vulnerability.
_UNCONFIRMED_CLASSES = frozenset({"exposure", "keyword_cve"})

#: Highest decision an unconfirmed finding may reach. ``Act``/``Immediate``
#: mean "work this now", which no hypothesis has earned.
_UNCONFIRMED_DECISION_CAP = "Attend"

_DECISION_RANK = {"Track": 0, "Attend": 1, "Act": 2, "Immediate": 3}

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

    def asset_criticality(
        self, item: dict[str, Any], base_cvss: float, *, override: int | None = None
    ) -> int:
        """0-4 criticality. When ``override`` is given (a Phase 7 asset's
        operator-set ``asset_criticality``), it wins outright; otherwise falls
        back to the severity/high-value-port heuristic below."""
        if override is not None:
            return max(0, min(4, int(override)))
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

    @staticmethod
    def _item_epss(item: dict[str, Any]) -> float | None:
        """EPSS the scanner attached to this finding, if any.

        Pulse ships real EPSS data per finding; when it is present it beats the
        local overlay, which on a default install is only a seed stub.
        """
        raw = item.get("epss")
        if raw is None:
            return None
        try:
            return max(0.0, min(1.0, float(raw)))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def confidence_factor(item: dict[str, Any]) -> tuple[float, bool]:
        """``(multiplier, unconfirmed)`` for a finding's scanner confidence.

        A confirmed finding is untouched. An unconfirmed one keeps a floor of
        0.4 of its score even at zero confidence — a reachable-service
        observation is still worth triaging, just never worth paging on.
        """
        finding_class = str(item.get("finding_class") or "").strip().lower()
        unconfirmed = bool(item.get("requires_confirmation")) or finding_class in _UNCONFIRMED_CLASSES
        if not unconfirmed:
            return 1.0, False
        try:
            confidence = max(0, min(100, int(item.get("confidence") or 0)))
        except (TypeError, ValueError):
            confidence = 0
        return 0.4 + 0.6 * (confidence / 100.0), True

    def cisa_decision(
        self,
        *,
        base_cvss: float,
        epss: float,
        exploit_active: int,
    ) -> str:
        if exploit_active and base_cvss >= 7.0:
            return "Immediate"
        if exploit_active:
            return "Act"
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

    def score_vulnerability(
        self, item: dict[str, Any], *, asset_criticality_override: int | None = None
    ) -> dict[str, Any]:
        cve = str(item.get("cve") or item.get("script_id") or "")
        is_cve = cve.upper().startswith("CVE-")
        base = self.base_cvss(item)

        epss_source = "none"
        item_epss = self._item_epss(item)
        if item_epss is not None:
            epss, epss_source = item_epss, "scanner"
        elif is_cve:
            epss = self.epss_score(cve)
            epss_source = "overlay" if epss else "none"
        else:
            epss = 0.0

        if item.get("in_kev"):
            exploit, kev_source = 1, "scanner"
        elif is_cve and self.exploit_active(cve):
            exploit, kev_source = 1, "overlay"
        else:
            exploit, kev_source = 0, "none"

        criticality = self.asset_criticality(item, base, override=asset_criticality_override)
        factor, unconfirmed = self.confidence_factor(item)
        decision = self.cisa_decision(base_cvss=base, epss=epss, exploit_active=exploit)
        capped = unconfirmed and _DECISION_RANK[decision] > _DECISION_RANK[_UNCONFIRMED_DECISION_CAP]
        if capped:
            decision = _UNCONFIRMED_DECISION_CAP
        contextual = round(
            self.contextual_score(
                base_cvss=base,
                epss=epss,
                exploit_active=exploit,
                asset_criticality=criticality,
            )
            * factor,
            2,
        )
        return {
            "base_cvss": base,
            "epss_score": epss,
            "asset_criticality": criticality,
            "exploit_active": exploit,
            "cisa_decision": decision,
            "contextual_score": contextual,
            "scoring_model_version": SCORING_MODEL_VERSION,
            "risk_explanation": self._explain(
                item,
                base_cvss=base,
                epss=epss,
                epss_source=epss_source,
                exploit_active=exploit,
                kev_source=kev_source,
                asset_criticality=criticality,
                asset_criticality_override=asset_criticality_override,
                factor=factor,
                unconfirmed=unconfirmed,
                capped=capped,
                decision=decision,
            ),
        }

    @staticmethod
    def _explain(
        item: dict[str, Any],
        *,
        base_cvss: float,
        epss: float,
        epss_source: str,
        exploit_active: int,
        kev_source: str,
        asset_criticality: int,
        asset_criticality_override: int | None,
        factor: float,
        unconfirmed: bool,
        capped: bool,
        decision: str,
    ) -> str:
        """One line naming every factor that moved the score (ROADMAP P4).

        Deliberately a plain string rather than structured factors: it is read
        by a human deciding whether to act, and it has to survive into a PDF, a
        ticket, and a table cell unchanged.
        """
        parts: list[str] = []
        parts.append(f"CVSS {base_cvss:g}" if base_cvss else "no CVSS")
        if epss:
            parts.append(f"EPSS {epss:.2f} ({epss_source})")
        if exploit_active:
            parts.append(f"in CISA KEV ({kev_source})")
        origin = "operator-set" if asset_criticality_override is not None else "heuristic"
        parts.append(f"asset criticality {asset_criticality}/4 ({origin})")
        if unconfirmed:
            finding_class = str(item.get("finding_class") or "unconfirmed").strip().lower()
            try:
                confidence = int(item.get("confidence") or 0)
            except (TypeError, ValueError):
                confidence = 0
            note = f"unconfirmed {finding_class} (scanner confidence {confidence}%) — score x{factor:.2f}"
            if capped:
                note += f", capped at {decision}"
            parts.append(note)
        return " · ".join(parts)


_SCORER: RiskScoring | None = None
_SCORER_MTIMES: tuple[float, float] | None = None
_SCORER_CHECKED_AT: float = 0.0
_SCORER_PINNED: bool = False


def _overlay_paths() -> tuple[Path, Path]:
    epss = Path(os.environ.get("OCTO_EPSS_DATABASE", "scanner/data/epss/epss-overlay.json"))
    kev = Path(os.environ.get("OCTO_KEV_DATABASE", "scanner/data/kev/kev-overlay.json"))
    return epss, kev


def _mtimes(paths: tuple[Path, Path]) -> tuple[float, float]:
    stamps: list[float] = []
    for path in paths:
        try:
            stamps.append(path.stat().st_mtime)
        except OSError:
            stamps.append(0.0)
    return stamps[0], stamps[1]


def _reload_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("OCTO_ENRICHMENT_RELOAD_SECONDS", "60")))
    except (TypeError, ValueError):
        return 60.0


def get_scorer() -> RiskScoring:
    """Return the process-wide scorer, hot-reloading when the EPSS/KEV overlay
    files change on disk.

    The overlay files' mtimes are re-checked at most once per
    ``OCTO_ENRICHMENT_RELOAD_SECONDS`` (default 60; set 0 to check every call).
    This lets a refresh CronJob rewrite the overlays on a shared volume and have
    every running API/ingest replica pick up fresh EPSS/KEV data without a
    process restart — the key requirement for staying fresh under load. The TTL
    gate keeps the steady-state cost at a cached attribute read (no per-call
    ``stat``). A scorer injected via ``reset_scorer_for_tests`` is pinned and
    never auto-reloaded.
    """
    global _SCORER, _SCORER_MTIMES, _SCORER_CHECKED_AT
    if _SCORER is not None and _SCORER_PINNED:
        return _SCORER
    if _SCORER is None:
        _SCORER = RiskScoring.from_env()
        _SCORER_MTIMES = _mtimes(_overlay_paths())
        _SCORER_CHECKED_AT = time.monotonic()
        return _SCORER
    now = time.monotonic()
    if now - _SCORER_CHECKED_AT < _reload_seconds():
        return _SCORER
    _SCORER_CHECKED_AT = now
    current = _mtimes(_overlay_paths())
    if current != _SCORER_MTIMES:
        LOG.info("Enrichment overlays changed on disk — reloading risk scorer")
        _SCORER = RiskScoring.from_env()
        _SCORER_MTIMES = current
    return _SCORER


def reset_scorer_for_tests(scorer: RiskScoring | None = None) -> None:
    global _SCORER, _SCORER_MTIMES, _SCORER_CHECKED_AT, _SCORER_PINNED
    _SCORER = scorer
    _SCORER_PINNED = scorer is not None
    _SCORER_MTIMES = None
    _SCORER_CHECKED_AT = 0.0
