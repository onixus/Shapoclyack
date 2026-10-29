from __future__ import annotations

import json

import pytest

from scanner.pipeline import perimeter_observations as po


def make_record(**kw):
    base = dict(tenant_id="tenant-a", run_id="run-1", family="rdp.x224.negotiation",
                implementation_sha256="a" * 64,
                endpoint={"host": "[2001:db8::1]", "port": 3389, "transport": "tcp"},
                variant="rdp-negotiation-ssl-hybrid-hybrid-ex-v1", state="responded",
                outcome={"result": "selected", "selected_protocol": "PROTOCOL_SSL"},
                observed_at="2026-10-29T12:00:00Z")
    base.update(kw)
    return po.record(**base)


def test_receipt_is_canonical_and_not_findings_shaped(tmp_path):
    row = make_record()
    doc = po.document([row], tenant_id="tenant-a", run_id="run-1")
    assert doc["schema"] == "octo.perimeter_observation.v1"
    assert doc["records"] == [row]
    assert row["subject"] == {"host": "2001:db8::1", "port": 3389, "transport": "tcp"}
    assert "vulnerabilities" not in doc and "findings" not in doc
    result = po.write_receipt(tmp_path, [row], tenant_id="tenant-a", run_id="run-1")
    loaded = json.loads((tmp_path / po.FILENAME).read_text())
    assert loaded == result == doc
    assert not (tmp_path / "vulnerabilities.json").exists()
    assert not (tmp_path / "report_sources.json").exists()
    from scanner.pipeline.evidence_artifacts import EvidenceReader
    reader = EvidenceReader(tmp_path, "tenant-a", "run-1")
    reader.pulse()
    assert reader.rows == []


def test_receipt_deterministic_order_and_tamper_validation():
    a = make_record(endpoint={"host": "example.com", "port": 3389, "transport": "tcp"})
    b = make_record(endpoint={"host": "10.0.0.1", "port": 3389, "transport": "tcp"})
    assert po.document([a, b], tenant_id="tenant-a", run_id="run-1") == po.document([b, a], tenant_id="tenant-a", run_id="run-1")
    with pytest.raises(ValueError):
        po.document([{**a, "outcome": {"selected_protocol": "secret"}}], tenant_id="tenant-a", run_id="run-1")
    with pytest.raises(ValueError):
        po.document([a], tenant_id="tenant-b", run_id="run-1")


@pytest.mark.parametrize("kw", [
    {"state": "not-a-state"}, {"state": "failed", "outcome": {"raw": "x" * 3000}},
    {"implementation_sha256": "bad"}, {"endpoint": {"host": "evil/path", "port": 3389, "transport": "tcp"}},
    {"endpoint": {"host": "example.com", "port": True, "transport": "tcp"}},
    {"variant": "a\nb"}, {"outcome": {"payload": {"nested": "raw"}}},
])
def test_receipt_rejects_out_of_scope_or_unbounded_data(kw):
    with pytest.raises(ValueError):
        make_record(**kw)


def test_atomic_writer_rejects_symlink_target_and_preserves_other_artifacts(tmp_path):
    row = make_record()
    other = tmp_path / "vulnerabilities.json"
    other.write_text("unchanged")
    (tmp_path / po.FILENAME).symlink_to(other)
    with pytest.raises(ValueError):
        po.write_receipt(tmp_path, [row], tenant_id="tenant-a", run_id="run-1")
    assert other.read_text() == "unchanged"


def test_failed_and_unknown_are_explicit_states_not_invented_negative_facts():
    for state in ("failed", "skipped", "unknown"):
        record = make_record(state=state, outcome=None)
        assert record["state"] == state and record["outcome"] is None
