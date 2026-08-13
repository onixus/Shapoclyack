"""NIST SP 800-30 Rev. 1 risk assessment primitives.

The model this replaces was a weighted sum: ``0.55*CVSS + 0.30*EPSS + …``. A
weighted sum cannot express the thing that actually decides priority — that a
severe vulnerability nobody can reach is not urgent, and a moderate one being
exploited against a crown-jewel asset is. SP 800-30 states risk as a function
of two independent assessments and combines them through a fixed table:

    risk = f(likelihood of occurrence, level of impact)

Keeping the axes separate is the point. It is also what makes the result
explainable: "High, because likelihood is High (exploited in the wild, network
reachable) and impact is High (full compromise on a criticality-4 asset)" is a
sentence an operator can argue with. "7.8" is not.

Scales are the five qualitative levels from Appendix D, with the
semi-quantitative 0–100 ranges from Table D-2 used internally so the inputs can
be blended before being cut back into levels.
"""

from __future__ import annotations

VERY_LOW = "very_low"
LOW = "low"
MODERATE = "moderate"
HIGH = "high"
VERY_HIGH = "very_high"

#: Worst-last, so an index into this is an ordering.
LEVELS = (VERY_LOW, LOW, MODERATE, HIGH, VERY_HIGH)
LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}

#: NIST SP 800-30 Rev. 1, Table D-2 — semi-quantitative values per qualitative
#: level. Read as "a score in this range is this level".
_LEVEL_BANDS = (
    (96, VERY_HIGH),
    (80, HIGH),
    (21, MODERATE),
    (5, LOW),
    (0, VERY_LOW),
)

#: NIST SP 800-30 Rev. 1, **Table I-2** (Assessment Scale — Level of Risk,
#: Combination of Likelihood and Impact), transcribed verbatim. Rows are
#: likelihood, columns are impact, both ordered Very Low → Very High.
#:
#: Transcribed rather than computed on purpose: the table is deliberately
#: *not* symmetric — a Very High likelihood against a Very Low impact is still
#: Very Low risk, while Very Low likelihood against Very High impact is Low.
#: Any formula smooth enough to be worth writing would disagree with the
#: standard somewhere, and then this would be "NIST-inspired", not NIST.
_RISK_MATRIX: dict[str, tuple[str, ...]] = {
    #        impact:   VL          L      M         H          VH
    VERY_HIGH: (VERY_LOW, LOW, MODERATE, HIGH, VERY_HIGH),
    HIGH: (VERY_LOW, LOW, MODERATE, HIGH, VERY_HIGH),
    MODERATE: (VERY_LOW, LOW, MODERATE, MODERATE, HIGH),
    LOW: (VERY_LOW, LOW, LOW, LOW, MODERATE),
    VERY_LOW: (VERY_LOW, VERY_LOW, VERY_LOW, LOW, LOW),
}


def level_for(score: float) -> str:
    """Qualitative level for a 0–100 semi-quantitative score (Table D-2)."""
    value = max(0.0, min(100.0, float(score)))
    for floor, name in _LEVEL_BANDS:
        if value >= floor:
            return name
    return VERY_LOW


def risk_level(likelihood: str, impact: str) -> str:
    """Combine two qualitative levels through Table I-2."""
    row = _RISK_MATRIX.get(likelihood)
    if row is None:
        return VERY_LOW
    return row[LEVEL_RANK.get(impact, 0)]


def label(level: str) -> str:
    """Human form for reports and explanations (``very_high`` → ``Very High``)."""
    return level.replace("_", " ").title()
