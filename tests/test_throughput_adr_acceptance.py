"""FTT-PULSE-2026-059: throughput ADR acceptance pack consistency.

Guards the Accepted/Rejected statuses for ADRs 0009–0016 against README drift.
Docs-only; no network I/O.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ADR_DIR = REPO_ROOT / "docs" / "adr"
README = ADR_DIR / "README.md"
FTT_059 = REPO_ROOT / "docs" / "ftt-pulse-2026-059-throughput-adr-acceptance.md"
IB_PROTOCOL = REPO_ROOT / "docs" / "security-acceptance-throughput-okr.md"
OKR_DOC = REPO_ROOT / "docs" / "throughput-okr-10k.md"

# id -> expected status keyword in the ADR body
THROUGHPUT_PACK = {
    "0009": "Accepted",
    "0010": "Accepted",
    "0011": "Accepted",
    "0012": "Accepted",
    "0013": "Accepted",
    "0014": "Accepted",
    "0015": "Accepted",
    "0016": "Rejected",
}

ADR_FILES = {
    "0009": "0009-scan-throughput-okr.md",
    "0010": "0010-throughput-s1-s3-sharding.md",
    "0011": "0011-executor-queue-depth-autoscale.md",
    "0012": "0012-stage2-enrichment-queue.md",
    "0013": "0013-product-defaults-speed-intents.md",
    "0014": "0014-throughput-heuristics-s5.md",
    "0015": "0015-stage2-queue-depth-keda.md",
    "0016": "0016-reject-s6-ebpf-masscan-okr.md",
}


def _status_from_adr(text: str) -> str | None:
    """Return Accepted / Rejected / Proposed from the ADR status line."""
    # Table form: | **Status** | **Accepted** — … |
    m = re.search(
        r"\|\s*\*\*Status\*\*\s*\|\s*\*\*(Accepted|Rejected|Proposed)\*\*",
        text,
    )
    if m:
        return m.group(1)
    # Bullet form: - **Status**: **Accepted** …
    m = re.search(
        r"\*\*Status\*\*\s*:\s*\*\*(Accepted|Rejected|Proposed)\*\*",
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1)
    m = re.search(
        r"\*\*Status\*\*\s*:\s*(Accepted|Rejected|Proposed)\b",
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).capitalize()
    return None


@pytest.mark.parametrize("adr_id,filename", sorted(ADR_FILES.items()))
def test_throughput_adr_file_exists_with_expected_status(adr_id: str, filename: str) -> None:
    path = ADR_DIR / filename
    assert path.is_file(), f"missing ADR file {filename}"
    text = path.read_text(encoding="utf-8")
    status = _status_from_adr(text)
    assert status == THROUGHPUT_PACK[adr_id], (
        f"ADR {adr_id} status={status!r}, expected {THROUGHPUT_PACK[adr_id]!r}"
    )
    assert "onixus" in text.lower() or adr_id == "0016" or "FTT-PULSE-2026-059" in text
    assert "FTT-PULSE-2026-059" in text or "ftt-pulse-2026-059" in text.lower()


def test_readme_indexes_throughput_pack_statuses() -> None:
    readme = README.read_text(encoding="utf-8")
    for adr_id, expected in THROUGHPUT_PACK.items():
        # Row starts with | [00NN](
        row_match = re.search(
            rf"\|\s*\[{adr_id}\]\([^)]+\)\s*\|[^|]+\|\s*\*\*{expected}\*\*",
            readme,
        )
        assert row_match, f"README missing {adr_id} with status {expected}"


def test_ftt_059_and_ib_protocol_exist() -> None:
    assert FTT_059.is_file()
    assert IB_PROTOCOL.is_file()
    ftt = FTT_059.read_text(encoding="utf-8")
    assert "FTT-PULSE-2026-059" in ftt
    assert "0016" in ftt
    ib = IB_PROTOCOL.read_text(encoding="utf-8")
    assert "ADR 0016" in ib or "0016" in ib


def test_okr_doc_cites_acceptance_pack_and_rejects_s6() -> None:
    text = OKR_DOC.read_text(encoding="utf-8")
    assert "FTT-059" in text or "ftt-pulse-2026-059" in text
    assert "0016-reject-s6" in text or "ADR 0016" in text
    assert "ADR acceptance pack" in text


def test_adr_0016_rejects_s6_as_okr_primary() -> None:
    text = (ADR_DIR / ADR_FILES["0016"]).read_text(encoding="utf-8")
    assert "Rejected" in text
    assert "OKR primary" in text or "okr primary" in text.lower()
    assert "eBPF" in text or "XDP" in text or "masscan" in text
