"""Brand-watch similarity v1: rules, not a model.

Scores one already-fetched page against a brand and optional reference
material (favicon hashes, visible-text excerpts). No network, no HTML fetch,
no new dependency. Overlap is word-shingle Jaccard (k=5); MinHash is not
used because it is not in the project requirements.

The negative case is part of the contract: a news page that mentions the
brand in the body, but not in the title or the certificate, must not land
on high or critical. Mentioning the brand is not impersonation.
"""

from __future__ import annotations

import re
from typing import Any

SHINGLE_K = 5
#: Jaccard at or above this counts as "the page looks like the reference".
SHINGLE_MATCH = 0.35
#: Below this many visible words the page is an empty shell, not a site.
EMPTY_VISIBLE_WORDS = 8
YOUNG_DAYS = 30

#: Plan names. ``info`` is accepted as an alias of ``informational`` so a
#: caller that still says "info" does not invent a sixth rung.
SEVERITIES = ("informational", "low", "medium", "high", "critical")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
_SEVERITY_RANK["info"] = _SEVERITY_RANK["informational"]

#: Observation states this scorer may emit. ``confirmed`` is an analyst
#: disposition, never an automatic HTTP result. ``unregistered`` and
#: ``disappeared`` belong to the DNS observer.
STATES = frozenset({
    "unregistered",
    "registered",
    "resolving",
    "http_live",
    "parked",
    "suspicious",
    "confirmed",
    "disappeared",
})

_WORD_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def word_shingles(text: str, k: int = SHINGLE_K) -> frozenset[tuple[str, ...]]:
    """Lowercased word k-shingles. Shorter text yields an empty set."""
    words = tuple(word.casefold() for word in _WORD_RE.findall(text or ""))
    if len(words) < k:
        return frozenset()
    return frozenset(words[i : i + k] for i in range(len(words) - k + 1))


def jaccard(left: frozenset[Any], right: frozenset[Any]) -> float:
    """Jaccard index. Two empty sets overlap completely; one empty set does not."""
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    union = len(left | right)
    if union == 0:
        return 0.0
    return len(left & right) / union


def shingle_overlap(text: str, references: tuple[str, ...] | list[str]) -> float:
    """Best Jaccard of ``text`` against each reference excerpt."""
    if not references:
        return 0.0
    page = word_shingles(text)
    if not page:
        return 0.0
    return max(jaccard(page, word_shingles(ref)) for ref in references)


def _contains_brand(value: str, brand: str) -> bool:
    needle = (brand or "").strip().casefold()
    if not needle:
        return False
    return needle in (value or "").casefold()


def brand_in_cert(brand: str, subject_cn: str, san: tuple[str, ...] | list[str]) -> bool:
    """True when the brand appears in the certificate CN or any SAN value."""
    if _contains_brand(subject_cn, brand):
        return True
    return any(_contains_brand(name, brand) for name in san)


def score_observation(signals: dict[str, Any]) -> dict[str, Any]:
    """Apply the M2 ladder to signals the observer already collected.

    Expected keys (all optional; missing means false / absent):

    - ``brand``
    - ``registered`` — the name has a DNS or RDAP registration
    - ``parked`` — parking catalogue matched
    - ``live`` — a page was fetched (status and some body)
    - ``has_site`` — there is a page to look at (false for MX-only)
    - ``mx_present``
    - ``password_form``
    - ``brand_in_title``
    - ``brand_in_cert``
    - ``favicon_match``
    - ``young_domain`` — RDAP created within 30 days
    - ``young_cert`` — cert ``not_before`` within 30 days
    - ``empty_spa`` — almost no visible text
    - ``shingle_overlap`` — float, already computed
    - ``skip_reason`` — set by the observer when the page must not be scored
      as a look-alike (``empty_spa``, ``no_public_address``, ...)

    Returns ``severity``, ``reasons``, ``state``, and ``skipped``. A skip is
    never high. A news-style mention (brand only in the body, no title, no
    cert, no favicon, no password form, no MX) stays at ``low``.

    States are the plan's set: ``registered``, ``resolving``, ``http_live``,
    ``parked``, ``suspicious``. This function never emits ``confirmed``.
    """
    reasons: list[str] = []
    skip = signals.get("skip_reason") or ""
    if signals.get("empty_spa") and not skip:
        skip = "empty_spa"
    if skip:
        reasons.append(f"skipped:{skip}")
        # An empty shell that answered is still http_live. Other skips
        # (refused address, no public answer) are not a live site.
        state = "http_live" if skip == "empty_spa" or signals.get("live") else "resolving"
        return {
            "severity": "informational",
            "reasons": reasons,
            "state": state,
            "skipped": True,
            "skip_reason": skip,
        }

    parked = bool(signals.get("parked"))
    registered = bool(signals.get("registered")) or parked
    live = bool(signals.get("live"))
    has_site = bool(signals.get("has_site", live))
    mx = bool(signals.get("mx_present"))
    password = bool(signals.get("password_form"))
    brand_title = bool(signals.get("brand_in_title"))
    brand_cert = bool(signals.get("brand_in_cert"))
    brand_signal = brand_title or brand_cert
    favicon = bool(signals.get("favicon_match"))
    young_domain = bool(signals.get("young_domain"))
    young_cert = bool(signals.get("young_cert"))
    overlap = float(signals.get("shingle_overlap") or 0.0)
    text_match = overlap >= SHINGLE_MATCH

    if parked:
        reasons.append("parked")
    if registered and not live:
        reasons.append("registered")
    if mx:
        reasons.append("mx_present")
    if password:
        reasons.append("password_form")
    if brand_title:
        reasons.append("brand_in_title")
    if brand_cert:
        reasons.append("brand_in_cert")
    if favicon:
        reasons.append("favicon_match")
    if young_domain:
        reasons.append("young_domain")
    if young_cert:
        reasons.append("young_cert")
    if text_match:
        reasons.append("shingle_overlap")
    if live and not brand_title:
        reasons.append("live_without_brand_in_title")

    # Suspicious rungs first. A parking title that also carries the brand, or
    # a cert for a name that has no page yet, must not be swallowed by the
    # informational parked/registered return below.
    # critical / high need brand AND a young cert, plus a form or MX.
    # Favicon match raises severity to critical. It does not confirm: an
    # analyst sets confirmed, this scorer never does. Both rungs stay suspicious.
    # A news page that only mentions the brand in the body has neither
    # brand_signal nor a form, so it never reaches this rung.
    if brand_signal and young_cert and (password or mx):
        if favicon:
            return _result("critical", reasons, "suspicious")
        return _result("high", reasons, "suspicious")

    # medium: young domain AND brand in title or cert.
    if young_domain and brand_signal:
        return _result("medium", reasons, "suspicious")

    # informational: parked, no MX, no form. MX or a form on a parking page
    # stays parked but is not informational — the ladder climbs one step.
    if parked and not mx and not password:
        return _result("informational", reasons, "parked")
    if parked:
        return _result("medium", reasons, "parked")

    # MX without a site raises severity: there is mail on a name that does
    # not serve a page. That is medium, not high — high still needs the
    # young-cert-and-brand pair above.
    if mx and not has_site:
        reasons.append("mx_without_site")
        return _result("medium", reasons, "resolving")

    # low: a live site that does not put the brand in the title. A news
    # mention lives here even when the body names the brand.
    if live or has_site:
        return _result("low", reasons, "http_live")

    if registered:
        return _result("informational", reasons, "registered")
    return _result("informational", reasons or ["unregistered"], "unregistered")


def _result(severity: str, reasons: list[str], state: str) -> dict[str, Any]:
    return {
        "severity": severity,
        "reasons": list(reasons),
        "state": state,
        "skipped": False,
        "skip_reason": None,
    }


def severity_at_least(severity: str, floor: str) -> bool:
    """Whether ``severity`` is at or above ``floor`` on the ladder."""
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(floor, 0)
