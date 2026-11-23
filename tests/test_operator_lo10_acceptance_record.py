"""LO-10 must not be marked accepted by a software-only record."""
import re
from pathlib import Path

RECORD = Path(__file__).resolve().parents[1] / "docs/local-operator-lo10-software-acceptance.md"
PASS = re.compile(
    r"(?<!not )(?<!is not )\baccepted\b|quality_gate_passed[`* ]*(?:is|=|:)\s*`?true\b",
    re.IGNORECASE,
)


def test_lo10_record_refuses_a_software_only_pass():
    text = RECORD.read_text()
    lowered = text.lower()
    assert "not accepted" in lowered
    assert "quality_gate_passed" in text
    assert "is not true" in lowered
    for gate in ("190-case", "60-minute", "offline cold start", "machine_verified",
                 "Finished: SUCCESS", "#609"):
        assert gate in text
    assert PASS.search(text) is None, PASS.search(text).group(0)
