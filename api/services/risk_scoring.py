"""Risk scoring for vulnerability findings — NIST SP 800-30 Rev. 1.

Model ``nist-1``. The previous model (``mvp-2``) was a weighted sum,
``0.55*CVSS + 0.30*EPSS + 0.10*exploit + 0.05*criticality``. Two things were
wrong with it, and both changed what an operator saw:

* **Asset criticality barely counted.** At weight 0.05 over a 0–4 scale, the
  entire difference between a lab box and a payment gateway was 0.5 points out
  of 10 — less than the rounding an operator would notice. Business context has
  to be able to change the answer, or it is decoration.
* **"Exploitable" was one bit.** ``exploit_active`` was 1 for CISA KEV and 0
  for everything else, which put "a working exploit has been public for three
  years" in the same bucket as "nobody has ever demonstrated this".

``nist-1`` assesses the two axes SP 800-30 defines and combines them through
Table I-2 (see ``api/services/nist_risk.py``):

**Likelihood** — will this be exploited?
    Technical reachability from the CVSS vector's exploitability metrics
    (AV/AC/AT/PR/UI), blended with EPSS, then floored and capped by exploit
    maturity (``api/services/exploit_evidence.py``): a finding with a public
    exploit cannot come out Low, and one nobody has ever demonstrated cannot
    come out High no matter how alarming its CVSS. Discounted by scanner
    confidence when the finding is a hypothesis rather than an observation.
    Then shifted by **network exposure** (#171): whether *this* host is
    reachable from outside, which is not what CVSS ``AV:N`` says. Then a
    small **compensating-control** discount (#173) only if fingerprint
    observed a CDN/WAF on the same host:port — named, never "WAF = safe".
    Then a small **same-asset path** raise (#173) when a local finding
    shares a P4.2-correlated asset with a network foothold — named, never
    "this is a domain takeover".

**Impact** — how bad if it is?
    The CVSS vector's impact metrics (VC/VI/VA, or C/I/A on v3), shifted by
    operator-set asset criticality. Criticality moves impact by up to ±40
    semi-quantitative points — enough to cross level boundaries in both
    directions, which is the point.

Outputs keep every ``mvp-2`` key so ClickHouse ingest and the UI are unaffected
(``contextual_score``, ``cisa_decision``, ``exploit_active``, …) and add the
assessment itself: ``likelihood``, ``impact``, ``risk_level``,
``exploit_maturity``, ``exploit_evidence``. ``risk_level`` is the NIST verdict;
``contextual_score`` remains a continuous 0–10 sort key, now derived from the
two axes rather than from a flat blend.

Confidence handling (ROADMAP P4 "risk-priority explanation"): Pulse separates
observations from hypotheses and tells us which is which via ``finding_class``
/ ``confidence`` / ``requires_confirmation`` (GenDec ``docs/findings.md``). An
``exposure`` observation or an unverified ``keyword_cve`` must not be scored
like a confirmed version match, so both are discounted by their confidence and
capped below ``Act`` — the decision that would page someone.

Overlays (JSON) are opt-in so the image stays redistributable:

* ``OCTO_EPSS_DATABASE`` / default ``scanner/data/epss/epss-overlay.json``
* ``OCTO_KEV_DATABASE`` / default ``scanner/data/kev/kev-overlay.json``
* ``OCTO_EXPLOIT_DATABASE`` / default ``scanner/data/exploit/exploit-overlay.json``

The committed defaults are tiny seed stubs. They now matter less on the default
scan path — findings that arrive with their own EPSS/KEV data no longer depend
on them at all — but they still cover nuclei/NSE findings. A refresh job
(``scripts/fetch-epss-db.sh`` / ``scripts/fetch-kev-db.sh`` /
``scripts/fetch-exploit-db.py``) rewrites them with the real feeds on a shared
volume, and ``get_scorer`` hot-reloads changed overlays without a restart
(``OCTO_ENRICHMENT_RELOAD_SECONDS``, default 60).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.services import nist_risk
from api.services.exploit_evidence import (
    ATTACKED,
    PROOF_OF_CONCEPT,
    THEORETICAL,
    UNKNOWN,
    UNPROVEN,
    WEAPONIZED,
    ExploitAssessment,
    ExploitEvidence,
)

LOG = logging.getLogger("shapoclyack.risk-scoring")

SCORING_MODEL_VERSION = "nist-1"

#: Semi-quantitative floor and ceiling each maturity level puts on likelihood.
#:
#: The ceilings are the load-bearing half. Without them a theoretical finding
#: with a perfect CVSS vector (network, no privileges, no interaction) scores as
#: likely, which is precisely the false urgency that makes operators stop
#: reading severity columns. Nothing that has never been demonstrated may exceed
#: Low (20), and nothing lacking public code may exceed Moderate (79).
#: ``unknown`` intentionally neither floors nor caps: no exploit-intelligence
#: source was configured, so the assessment must fall back to reachability and
#: EPSS rather than pretend to a verdict. Capping it like ``theoretical`` would
#: let an un-enriched installation rate its entire estate Low and call that a
#: clean bill of health.
_MATURITY_BOUNDS: dict[str, tuple[float, float]] = {
    ATTACKED: (96.0, 100.0),  # observed in the wild → Very High by definition
    WEAPONIZED: (80.0, 100.0),
    PROOF_OF_CONCEPT: (40.0, 95.0),  # real code exists, no observed campaigns
    UNPROVEN: (5.0, 79.0),
    THEORETICAL: (0.0, 20.0),
    UNKNOWN: (0.0, 100.0),
}

#: How far operator-set criticality may move impact, in Table D-2 points.
#: ±40 spans two adjacent levels, so a crown-jewel asset can lift a Moderate
#: impact to High and a lab box can drop it to Low — both directions matter.
_CRITICALITY_SWING = 20.0

#: How far network exposure (#171) may move likelihood, in Table D-2 points.
#: Same magnitude as criticality so "this host is on the internet" can change
#: the verdict. ``unknown`` shifts nothing — no observation is not "not
#: exposed".
_NETWORK_EXPOSURE_SWING = 20.0
#: Weak raise-only likelihood bump for an old CVE (#172). Never negative —
#: an unpatched old flaw is not safer for having been ignored. How long *we*
#: have had the finding open is SLA (#145), not this.
_CVE_AGE_RAISE = ((1.0, 0.0), (3.0, 4.0), (7.0, 8.0), (None, 12.0))
#: Small on-path likelihood discount when fingerprint saw a CDN/WAF on the
#: *same* host:port (#173). One observation, one discount — never per vendor
#: and never a qualitative "minus a level" rule. Seeing Cloudflare is not
#: evidence the WAF blocks this CVE. Names stay in lockstep with
#: ``scanner.pipeline.fingerprint._CDN_WAF_SIGNATURES``.
COMPENSATING_CONTROL_DISCOUNT = 6.0
CDN_WAF_PROVIDERS = frozenset(
    {"cloudflare", "akamai", "sucuri", "imperva_incapsula", "cloudfront", "fastly"}
)
#: Small raise when a local finding sits on the same asset as a network
#: foothold (#173). Not a step-model of privilege escalation, and not a
#: qualitative level rule. Two Moderates still do not become a takeover.
ATTACK_PATH_RAISE = 8.0
FOOTHOLD = "foothold"
LOCAL = "local"
ENRICHMENT_STALE_DAYS = 30
_CVE_ID_YEAR = re.compile(r"^CVE-(\d{4})-", re.I)
EXTERNAL = "external"
INTERNAL = "internal"
UNKNOWN_EXPOSURE = "unknown"
NETWORK_EXPOSURES = (EXTERNAL, INTERNAL, UNKNOWN_EXPOSURE)

_VECTOR_METRIC_RE = re.compile(r"([A-Z]{1,2}):([A-Z])")

#: CVSS exploitability metrics → ordinal ease. Higher is easier to reach.
#: These are ordinal positions, not CVSS's numeric weights: v4 scores through a
#: MacroVector lookup rather than a product, so reusing the v3.1 coefficients
#: would produce a number that looks like a CVSS sub-score and is not one.
#: NIST's scale is qualitative anyway — what is needed is an ordering.
_EXPLOITABILITY_METRICS: dict[str, dict[str, int]] = {
    "AV": {"N": 4, "A": 3, "L": 2, "P": 1},  # Attack Vector
    "AC": {"L": 2, "H": 1},  # Attack Complexity
    "AT": {"N": 2, "P": 1},  # Attack Requirements (v4 only)
    "PR": {"N": 3, "L": 2, "H": 1},  # Privileges Required
    "UI": {"N": 3, "P": 2, "A": 1},  # User Interaction (v4 adds A)
}
_EXPLOITABILITY_MIN = 5  # one point per metric
_EXPLOITABILITY_MAX = 14

#: CVSS impact metrics. v4 names them VC/VI/VA (Vulnerable System
#: Confidentiality/Integrity/Availability); v3 names them C/I/A.
_IMPACT_METRICS_V4 = ("VC", "VI", "VA")
_IMPACT_METRICS_V3 = ("C", "I", "A")
_IMPACT_VALUES = {"H": 3, "L": 2, "N": 1}
_IMPACT_MIN = 3
_IMPACT_MAX = 9

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


def _parse_vector(raw: str) -> dict[str, str]:
    """``CVSS:4.0/AV:N/AC:L/...`` → ``{"AV": "N", "AC": "L", ...}``.

    Fail-soft by design: a vector is enrichment, and a malformed one must
    degrade to the CVSS-score fallback rather than raise inside an ingest batch.
    ``X`` (Not Defined) values are dropped so a caller cannot tell them from a
    metric that was never present — both mean "no information".
    """
    if not raw:
        return {}
    out: dict[str, str] = {}
    for metric, value in _VECTOR_METRIC_RE.findall(str(raw).upper()):
        if value != "X":
            out.setdefault(metric, value)
    return out


def _finding_vector(item: dict[str, Any]) -> str:
    for key in ("cvss4_vector", "cvss_vector", "vector"):
        value = item.get(key)
        if value:
            return str(value)
    return ""


def exploitability_pct(vector: dict[str, str], base_cvss: float) -> tuple[float, str]:
    """0–100 technical reachability, and the source that produced it.

    Falls back to the CVSS score when no usable vector is present: a bare score
    conflates exploitability with impact, so the fallback is deliberately
    pulled toward the middle rather than trusted as if it were the real thing.
    """
    present = {m: v for m, v in vector.items() if m in _EXPLOITABILITY_METRICS}
    if not present:
        # 0-10 → 0-100, compressed toward the centre: an unknown vector is not
        # evidence of easy exploitation, nor of hard.
        return max(0.0, min(100.0, 25.0 + base_cvss * 5.0)), "cvss-score"
    total = 0
    for metric, weights in _EXPLOITABILITY_METRICS.items():
        value = present.get(metric)
        if value is None:
            # An absent metric scores as its easiest value: v3 vectors have no
            # AT, and treating that as "requirements exist" would make every v3
            # finding look harder to exploit than its v4 equivalent.
            total += max(weights.values())
            continue
        total += weights.get(value, min(weights.values()))
    span = _EXPLOITABILITY_MAX - _EXPLOITABILITY_MIN
    return round((total - _EXPLOITABILITY_MIN) / span * 100.0, 1), "cvss-vector"


def impact_pct(vector: dict[str, str], base_cvss: float) -> tuple[float, str]:
    """0–100 technical impact from the CVSS impact metrics, before criticality."""
    names = _IMPACT_METRICS_V4 if any(m in vector for m in _IMPACT_METRICS_V4) else _IMPACT_METRICS_V3
    present = {m: vector[m] for m in names if m in vector}
    if not present:
        return max(0.0, min(100.0, base_cvss * 10.0)), "cvss-score"
    total = sum(_IMPACT_VALUES.get(value, 1) for value in present.values())
    total += (len(names) - len(present)) * 1  # missing metric == None
    span = _IMPACT_MAX - _IMPACT_MIN
    return round((total - _IMPACT_MIN) / span * 100.0, 1), "cvss-vector"


def epss_pct(epss: float) -> float:
    """EPSS probability → 0–100 likelihood contribution.

    Not a linear rescale. EPSS is the probability of exploitation in the next
    30 days and its distribution is extremely skewed — the median CVE sits
    around 0.0005 and 0.5 is already the far tail. Linear scaling would make
    every real finding contribute ~0, so the top of the scale is anchored at
    0.5 and everything above saturates.
    """
    return max(0.0, min(100.0, float(epss) * 200.0))


def apply_criticality(technical_impact: float, criticality: int) -> float:
    """Shift technical impact by operator-set asset criticality (0–4).

    Criticality 2 is "no opinion" and shifts nothing, so an installation that
    never sets it gets the pure technical assessment rather than a silent
    penalty. Each step away moves impact by half the swing.
    """
    level = max(0, min(4, int(criticality)))
    shift = (level - 2) / 2.0 * _CRITICALITY_SWING
    return max(0.0, min(100.0, technical_impact + shift))


def _is_non_routable(host: str) -> bool:
    """RFC1918 / loopback / link-local / reserved — not internet-reachable."""
    try:
        addr = ipaddress.ip_address(host.strip())
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved


def resolve_network_exposure(
    *,
    host: str | None = None,
    operator_exposure: str | None = None,
    explicit: str | None = None,
) -> tuple[str, str]:
    """``(exposure, source)`` for likelihood (#171).

    Order is load-bearing. A public address is **not** evidence the host is
    internet-facing — that would launder a routing fact as a scan observation.
    RFC1918 *is* evidence it is not. Operator-set ``exposure_level=internet``
    is a named decision, not a measurement. ``unknown`` is the default so
    absence of data does not score as "nothing is exposed".
    """
    if explicit in NETWORK_EXPOSURES:
        return explicit, "finding"
    if host and _is_non_routable(host):
        return INTERNAL, "address-space"
    if operator_exposure == "internet":
        return EXTERNAL, "operator-set"
    if operator_exposure == "internal":
        return INTERNAL, "operator-set"
    return UNKNOWN_EXPOSURE, "none"


def apply_network_exposure(likelihood: float, exposure: str) -> float:
    """Shift likelihood after maturity bounds. ``unknown`` is a no-op."""
    if exposure == EXTERNAL:
        shift = _NETWORK_EXPOSURE_SWING
    elif exposure == INTERNAL:
        shift = -_NETWORK_EXPOSURE_SWING
    else:
        return likelihood
    return max(0.0, min(100.0, likelihood + shift))


def resolve_cve_age(
    *,
    cve: str,
    published: str | None = None,
    now: datetime | None = None,
) -> tuple[float | None, str]:
    """Years since the CVE became public, and where that date came from.

    Prefer NVD ``published``. The CVE-ID year is a coarse fallback so an
    un-refreshed ``cvss4.json`` (no ``published`` field yet) still distinguishes
    2015 from 2026. Missing both is ``none`` — no raise, not a penalty.
    """
    clock = now or datetime.now(UTC)
    if published:
        try:
            stamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=UTC)
            years = max(0.0, (clock - stamp.astimezone(UTC)).total_seconds() / (86400.0 * 365.25))
            return years, "nvd-published"
        except ValueError:
            pass
    match = _CVE_ID_YEAR.match(cve or "")
    if match:
        year = int(match.group(1))
        if 1999 <= year <= clock.year + 1:
            return float(max(0, clock.year - year)), "cve-id"
    return None, "none"


def cve_age_raise(years: float | None) -> float:
    """Raise-only likelihood bump. Under one year, and unknown age, add nothing."""
    if years is None or years < 1.0:
        return 0.0
    previous = 0.0
    for ceiling, bump in _CVE_AGE_RAISE:
        if ceiling is None or years < ceiling:
            return bump
        previous = bump
    return previous


def _endpoint_key(host: str | None, port: Any) -> tuple[str, int] | None:
    """``(host, port)`` identity for an on-path control. Port-less is not a match."""
    if not host:
        return None
    try:
        port_n = int(str(port).split("/")[0])
    except (TypeError, ValueError, AttributeError):
        return None
    if port_n <= 0:
        return None
    return str(host).strip().lower(), port_n


def _normalize_cdn_waf(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return ()
    seen: list[str] = []
    for item in raw:
        name = str(item).strip().lower().replace("-", "_").replace(" ", "_")
        if name in CDN_WAF_PROVIDERS and name not in seen:
            seen.append(name)
    return tuple(seen)


def index_cdn_waf(fingerprint: Any) -> dict[tuple[str, int], tuple[str, ...]]:
    """``fingerprint.json`` → ``{(host, port): providers}`` for on-path CDN/WAF.

    CMS/framework hits are ignored: a WordPress marker is not a control.
    Several findings for the same host:port (http and https) are unioned.
    """
    if not isinstance(fingerprint, dict):
        return {}
    findings = fingerprint.get("findings")
    if not isinstance(findings, list):
        return {}
    collected: dict[tuple[str, int], list[str]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = _endpoint_key(finding.get("host"), finding.get("port"))
        if key is None:
            continue
        names = _normalize_cdn_waf(finding.get("cdn_waf"))
        if not names:
            continue
        existing = collected.setdefault(key, [])
        for name in names:
            if name not in existing:
                existing.append(name)
    return {key: tuple(names) for key, names in collected.items()}


def resolve_compensating_control(
    *,
    host: str | None = None,
    port: Any = None,
    cdn_waf: Any = None,
    index: dict[tuple[str, int], tuple[str, ...]] | None = None,
) -> tuple[tuple[str, ...], str]:
    """``(providers, source)`` for an on-path CDN/WAF (#173).

    An explicit list on the finding wins (``finding``). Otherwise a fingerprint
    index hit on the **same** host:port (``fingerprint``). Anything else is
    ``none`` — we did not observe a control, which is not "there is none".
    """
    names = _normalize_cdn_waf(cdn_waf)
    if names:
        return names, "finding"
    if index:
        key = _endpoint_key(host, port)
        if key is not None:
            hit = index.get(key)
            if hit:
                return hit, "fingerprint"
    return (), "none"


def apply_compensating_control(
    likelihood: float, providers: tuple[str, ...] | list[str]
) -> float:
    """Small named discount. Several vendors on one endpoint still count once."""
    if not providers:
        return likelihood
    return max(0.0, min(100.0, likelihood - COMPENSATING_CONTROL_DISCOUNT))


def path_role(item: dict[str, Any]) -> str:
    """``foothold`` / ``local`` / ``""`` from what this finding actually says.

    An ``exposure`` is a reachable service, not a CVE — that is a foothold.
    Otherwise the CVSS attack vector: ``AV:N`` is network-reachable,
    ``AV:L`` / ``AV:P`` need a presence on the box. No vector is not a path.
    """
    finding_class = str(item.get("finding_class") or "").strip().lower()
    if finding_class == "exposure":
        return FOOTHOLD
    vector = _parse_vector(_finding_vector(item))
    av = vector.get("AV")
    if av == "N":
        return FOOTHOLD
    if av in {"L", "P"}:
        return LOCAL
    return ""


def apply_attack_path(likelihood: float, *, role: str, has_foothold: bool) -> float:
    """Raise only the local finding, and only when a foothold is on the same asset."""
    if role != LOCAL or not has_foothold:
        return likelihood
    return max(0.0, min(100.0, likelihood + ATTACK_PATH_RAISE))


def overlay_staleness(*, now: datetime | None = None) -> list[tuple[str, float]]:
    """``(name, age_days)`` for EPSS/KEV/exploit overlays older than the threshold."""
    clock = now or datetime.now(UTC)
    stale: list[tuple[str, float]] = []
    names = ("EPSS", "KEV", "exploit")
    for name, path in zip(names, _overlay_paths(), strict=True):
        try:
            age = (clock.timestamp() - path.stat().st_mtime) / 86400.0
        except OSError:
            continue
        if age > ENRICHMENT_STALE_DAYS:
            stale.append((name, age))
    return stale


class RiskScoring:
    """Stateless scorer with optional EPSS / KEV / exploit overlays."""

    def __init__(
        self,
        *,
        epss: dict[str, float] | None = None,
        kev: set[str] | None = None,
        exploits: ExploitEvidence | None = None,
        report_overlay_age: bool = False,
    ) -> None:
        self._epss = epss or {}
        self._kev = kev or set()
        # Defaults to an empty resolver rather than None so every call site can
        # assume it exists; with no overlay and no template corpus it still
        # answers from KEV and per-finding signals.
        self._exploits = exploits if exploits is not None else ExploitEvidence()
        # Tests construct a scorer in-memory; wall-clock overlay age must not
        # leak into their explanations. The process-wide get_scorer() turns this
        # on so a stale EPSS/KEV file is visible to operators (#172).
        self._report_overlay_age = report_overlay_age

    @classmethod
    def from_env(cls) -> RiskScoring:
        epss_path = Path(
            os.environ.get("OCTO_EPSS_DATABASE", "scanner/data/epss/epss-overlay.json")
        )
        kev_path = Path(os.environ.get("OCTO_KEV_DATABASE", "scanner/data/kev/kev-overlay.json"))
        return cls(
            epss=_load_cve_float_map(epss_path),
            kev=_load_kev_set(kev_path),
            exploits=ExploitEvidence.from_env(),
            report_overlay_age=True,
        )

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

    @staticmethod
    def likelihood_pct(
        *,
        exploitability: float,
        epss: float,
        maturity: str,
        confidence_factor: float,
    ) -> float:
        """0–100 likelihood: reachability and EPSS, bounded by exploit maturity.

        The blend leans on exploitability because it describes *this* finding,
        while EPSS is a population statistic about the CVE — informative, but it
        knows nothing about whether the affected port is reachable here.

        Maturity is applied last, as a floor **and** a ceiling, because it is
        the only input carrying evidence about whether exploitation happens at
        all. A public exploit cannot be argued down by an awkward vector, and a
        never-demonstrated flaw cannot be argued up by a pretty one.
        """
        blended = 0.65 * exploitability + 0.35 * epss_pct(epss)
        floor, ceiling = _MATURITY_BOUNDS.get(maturity, (0.0, 100.0))
        bounded = max(floor, min(ceiling, blended))
        # Confidence scales after bounding: a hypothesis about an actively
        # exploited CVE is still a hypothesis, so the discount must survive the
        # KEV floor rather than be erased by it.
        return round(max(0.0, min(100.0, bounded * confidence_factor)), 1)

    @staticmethod
    def contextual_score(*, likelihood: float, impact: float) -> float:
        """0–10 continuous sort key from the two axes.

        The geometric mean, so neither axis can carry a finding alone: a
        certain-but-harmless issue and a catastrophic-but-impossible one both
        land low, which is the ordering an operator working a queue wants. The
        NIST verdict is ``risk_level``; this exists because a table needs to be
        sortable within a level.
        """
        return round(math.sqrt(max(0.0, likelihood) * max(0.0, impact)) / 10.0, 2)

    def score_vulnerability(
        self,
        item: dict[str, Any],
        *,
        asset_criticality_override: int | None = None,
        operator_exposure: str | None = None,
        cdn_waf_index: dict[tuple[str, int], tuple[str, ...]] | None = None,
        same_asset_foothold: bool = False,
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

        assessment = self._exploits.assess(
            item, cve=cve if is_cve else "", epss=epss, kev_active=bool(exploit), kev_source=kev_source
        )

        vector = _parse_vector(_finding_vector(item))
        exploitability, exploitability_source = exploitability_pct(vector, base)
        technical_impact, impact_source = impact_pct(vector, base)
        contextual_impact = apply_criticality(technical_impact, criticality)

        raw_likelihood = self.likelihood_pct(
            exploitability=exploitability,
            epss=epss,
            maturity=assessment.maturity,
            confidence_factor=factor,
        )
        exposure, exposure_source = resolve_network_exposure(
            host=str(item.get("host") or "") or None,
            operator_exposure=operator_exposure,
            explicit=str(item["network_exposure"]) if item.get("network_exposure") else None,
        )
        exposed = apply_network_exposure(raw_likelihood, exposure)
        published = str(item.get("cve_published") or item.get("published") or "") or None
        age_years, age_source = resolve_cve_age(cve=cve, published=published)
        age_bump = cve_age_raise(age_years)
        providers, control_source = resolve_compensating_control(
            host=str(item.get("host") or "") or None,
            port=item.get("port"),
            cdn_waf=item.get("cdn_waf"),
            index=cdn_waf_index,
        )
        aged = min(100.0, exposed + age_bump)
        shielded = apply_compensating_control(aged, providers)
        role = path_role(item)
        likelihood = apply_attack_path(
            shielded, role=role, has_foothold=same_asset_foothold
        )
        path_bump = likelihood - shielded
        stale_overlays = overlay_staleness() if self._report_overlay_age else []
        likelihood_level = nist_risk.level_for(likelihood)
        impact_level = nist_risk.level_for(contextual_impact)
        risk = nist_risk.risk_level(likelihood_level, impact_level)

        decision = self.cisa_decision(base_cvss=base, epss=epss, exploit_active=exploit)
        capped = unconfirmed and _DECISION_RANK[decision] > _DECISION_RANK[_UNCONFIRMED_DECISION_CAP]
        if capped:
            decision = _UNCONFIRMED_DECISION_CAP

        return {
            # --- keys that existed in mvp-2; consumers depend on these ---
            "base_cvss": base,
            "epss_score": epss,
            "asset_criticality": criticality,
            "exploit_active": exploit,
            "cisa_decision": decision,
            "contextual_score": self.contextual_score(
                likelihood=likelihood, impact=contextual_impact
            ),
            "scoring_model_version": SCORING_MODEL_VERSION,
            # --- the NIST assessment itself ---
            "risk_level": risk,
            "likelihood": likelihood_level,
            "impact": impact_level,
            "likelihood_score": likelihood,
            "impact_score": round(contextual_impact, 1),
            "technical_impact_score": technical_impact,
            "exploitability_score": exploitability,
            "network_exposure": exposure,
            "network_exposure_source": exposure_source,
            "cdn_waf": list(providers),
            "compensating_control_source": control_source,
            "attack_path": "same-asset" if path_bump > 0 else None,
            **assessment.as_dict(),
            "risk_explanation": self._explain(
                item,
                base_cvss=base,
                epss=epss,
                epss_source=epss_source,
                assessment=assessment,
                asset_criticality=criticality,
                asset_criticality_override=asset_criticality_override,
                technical_impact=technical_impact,
                contextual_impact=contextual_impact,
                exploitability=exploitability,
                exploitability_source=exploitability_source,
                impact_source=impact_source,
                likelihood_level=likelihood_level,
                impact_level=impact_level,
                risk=risk,
                factor=factor,
                unconfirmed=unconfirmed,
                capped=capped,
                decision=decision,
                raw_likelihood=raw_likelihood,
                network_exposure=exposure,
                network_exposure_source=exposure_source,
                cve_age_years=age_years,
                cve_age_source=age_source,
                cve_age_bump=age_bump,
                compensating_control=providers,
                compensating_control_source=control_source,
                compensating_drop=aged - shielded,
                attack_path_bump=path_bump,
                stale_overlays=stale_overlays,
            ),
        }

    @staticmethod
    def _explain(
        item: dict[str, Any],
        *,
        base_cvss: float,
        epss: float,
        epss_source: str,
        assessment: ExploitAssessment,
        asset_criticality: int,
        asset_criticality_override: int | None,
        technical_impact: float,
        contextual_impact: float,
        exploitability: float,
        exploitability_source: str,
        impact_source: str,
        likelihood_level: str,
        impact_level: str,
        risk: str,
        factor: float,
        unconfirmed: bool,
        capped: bool,
        decision: str,
        raw_likelihood: float,
        network_exposure: str,
        network_exposure_source: str,
        cve_age_years: float | None,
        cve_age_source: str,
        cve_age_bump: float,
        compensating_control: tuple[str, ...],
        compensating_control_source: str,
        compensating_drop: float,
        attack_path_bump: float,
        stale_overlays: list[tuple[str, float]],
    ) -> str:
        """One line explaining the verdict, reading as the assessment's argument.

        Deliberately a plain string rather than structured factors: it is read
        by a human deciding whether to act, and it has to survive into a PDF, a
        ticket, and a table cell unchanged. It leads with the conclusion and
        then gives each axis its reason, so the sentence answers "why is this
        High" rather than listing inputs and leaving the reader to do the
        arithmetic.
        """
        verdict = nist_risk.label(risk)
        like = nist_risk.label(likelihood_level)
        imp = nist_risk.label(impact_level)

        # --- why this likelihood ---
        why_likely: list[str] = []
        maturity_phrase = {
            ATTACKED: "exploited in the wild",
            WEAPONIZED: "weaponized exploit available",
            PROOF_OF_CONCEPT: "public exploit/PoC code exists",
            UNPROVEN: "no public exploit found",
            THEORETICAL: "no known exploit — theoretical",
            UNKNOWN: "exploit maturity unknown — no exploit-intelligence source configured",
        }.get(assessment.maturity, assessment.maturity)
        if assessment.sources:
            maturity_phrase += f" [{', '.join(assessment.sources)}]"
        if assessment.verified_on_host:
            maturity_phrase += "; verified against this host"
        why_likely.append(maturity_phrase)
        if exploitability_source == "cvss-vector":
            why_likely.append(f"reachability {exploitability:g}/100 from CVSS vector")
        else:
            why_likely.append(f"reachability estimated from CVSS {base_cvss:g} (no vector)")
        if epss:
            why_likely.append(f"EPSS {epss:.3f} ({epss_source})")
        if unconfirmed:
            finding_class = str(item.get("finding_class") or "unconfirmed").strip().lower()
            try:
                confidence = int(item.get("confidence") or 0)
            except (TypeError, ValueError):
                confidence = 0
            note = f"unconfirmed {finding_class}, scanner confidence {confidence}% — likelihood x{factor:.2f}"
            if capped:
                note += f", decision capped at {decision}"
            why_likely.append(note)
        source_label = {
            "address-space": "address-space",
            "operator-set": "operator-set",
            "finding": "finding",
            "none": "no observation",
        }.get(network_exposure_source, network_exposure_source)
        shifted = apply_network_exposure(raw_likelihood, network_exposure)
        if network_exposure == UNKNOWN_EXPOSURE:
            why_likely.append(f"network exposure unknown ({source_label}) — no shift")
        elif abs(shifted - raw_likelihood) >= 0.05:
            direction = "raised" if shifted > raw_likelihood else "lowered"
            why_likely.append(
                f"network exposure {network_exposure} ({source_label}) {direction} "
                f"likelihood to {shifted:g}/100"
            )
        else:
            why_likely.append(
                f"network exposure {network_exposure} ({source_label}), no shift"
            )
        if cve_age_years is not None:
            if cve_age_bump > 0:
                why_likely.append(
                    f"CVE age {cve_age_years:.0f}y ({cve_age_source}) raised likelihood by {cve_age_bump:g}"
                )
            else:
                why_likely.append(f"CVE age {cve_age_years:.0f}y ({cve_age_source}), no raise")
        if compensating_control:
            why_likely.append(
                f"CDN/WAF {', '.join(compensating_control)} on this host:port "
                f"({compensating_control_source}) lowered likelihood by {compensating_drop:g} "
                f"— not proof the vuln is blocked"
            )
        if attack_path_bump > 0:
            why_likely.append(
                f"same-asset path: network foothold + local finding raised likelihood "
                f"by {attack_path_bump:g} — not a modelled exploit chain"
            )
        for overlay_name, age_days in stale_overlays:
            why_likely.append(
                f"{overlay_name} overlay {age_days:.0f}d old — not a fresh assessment"
            )

        # --- why this impact ---
        origin = "operator-set" if asset_criticality_override is not None else "heuristic"
        why_impact: list[str] = []
        if impact_source == "cvss-vector":
            why_impact.append(f"technical impact {technical_impact:g}/100 from CVSS vector")
        else:
            why_impact.append(f"technical impact from CVSS {base_cvss:g} (no vector)")
        shift = contextual_impact - technical_impact
        if abs(shift) >= 0.05:
            direction = "raised" if shift > 0 else "lowered"
            why_impact.append(
                f"asset criticality {asset_criticality}/4 ({origin}) {direction} it to {contextual_impact:g}/100"
            )
        else:
            why_impact.append(f"asset criticality {asset_criticality}/4 ({origin}), no shift")

        return (
            f"{verdict} risk (NIST SP 800-30) = likelihood {like} × impact {imp} · "
            f"likelihood: {'; '.join(why_likely)} · impact: {'; '.join(why_impact)}"
        )


_SCORER: RiskScoring | None = None
_SCORER_MTIMES: tuple[float, ...] | None = None
_SCORER_CHECKED_AT: float = 0.0
_SCORER_PINNED: bool = False


def _overlay_paths() -> tuple[Path, ...]:
    return (
        Path(os.environ.get("OCTO_EPSS_DATABASE", "scanner/data/epss/epss-overlay.json")),
        Path(os.environ.get("OCTO_KEV_DATABASE", "scanner/data/kev/kev-overlay.json")),
        Path(
            os.environ.get("OCTO_EXPLOIT_DATABASE", "scanner/data/exploit/exploit-overlay.json")
        ),
    )


def _mtimes(paths: tuple[Path, ...]) -> tuple[float, ...]:
    """Variadic since #144 added a third overlay — a fixed-arity tuple here was
    what silently left the new file out of the hot-reload check."""
    stamps: list[float] = []
    for path in paths:
        try:
            stamps.append(path.stat().st_mtime)
        except OSError:
            stamps.append(0.0)
    return tuple(stamps)


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
