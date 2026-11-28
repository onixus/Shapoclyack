"""FTT-PULSE-2026-060: throughput OKR engineering closure checklist gate.

Docs-only; no network I/O. Ensures the closure checklist exists and lists
required human actions (merge stack, IB sign-off) without inventing S6 scope.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
FTT_060 = DOCS / "ftt-pulse-2026-060-throughput-okr-engineering-closure.md"
CHECKLIST = DOCS / "throughput-okr-closure-checklist.md"
OKR_DOC = DOCS / "throughput-okr-10k.md"

REQUIRED_CHECKLIST_MARKERS = (
    "FTT-PULSE-2026-060",
    "engineering",
    "CLOSED",
    "#681",
    "#682",
    "#684",
    "#688",
    "#685",
    "#686",
    "#687",
    "#689",
    "IB sign-off",
    "Pulse image pin",
    "Live-estate Measure",
    "S6",
    "Rejected",
    "bottom-up",
)

REQUIRED_FTT_MARKERS = (
    "FTT-PULSE-2026-060",
    "throughput-okr-closure-checklist.md",
    "SEC-01",
    "меняет код сенсора",
)


@pytest.mark.parametrize("path", [FTT_060, CHECKLIST])
def test_closure_docs_exist(path: Path) -> None:
    assert path.is_file(), f"missing {path.relative_to(REPO_ROOT)}"


def test_ftt_060_passport_and_sec() -> None:
    text = FTT_060.read_text(encoding="utf-8")
    for marker in REQUIRED_FTT_MARKERS:
        assert marker in text, f"FTT-060 missing {marker!r}"


def test_checklist_lists_human_actions_and_rejects_s6() -> None:
    text = CHECKLIST.read_text(encoding="utf-8")
    for marker in REQUIRED_CHECKLIST_MARKERS:
        assert marker in text, f"checklist missing {marker!r}"
    # Must not invent new S6 implementation scope
    assert "do not invent" in text.lower() or "Explicit non-goals" in text
    assert "eBPF" in text or "XDP" in text or "masscan" in text or "S6" in text


def test_okr_doc_points_to_engineering_closure() -> None:
    text = OKR_DOC.read_text(encoding="utf-8")
    assert "FTT-060" in text or "ftt-pulse-2026-060" in text
    assert "throughput-okr-closure-checklist.md" in text
    assert "Engineering closure" in text or "engineering closure" in text.lower()
