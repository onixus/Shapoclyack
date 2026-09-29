"""Offline contract fixtures; never invoke a scanner or an external address."""
from __future__ import annotations

import copy
import itertools
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.pipeline import evidence_artifacts as ea
from scanner.pipeline.finding_evidence import (
    MAX_ARTIFACT_REFS, PREVIEW_LIMIT, aggregate, observation, safe_text, timestamp,
)

CVE = "CVE-2024-1234"
BASE = {"host": "192.0.2.1", "port": "443", "protocol": "tcp", "cve": CVE,
        "rule_id": "rule", "title": "Example", "severity": "high"}
REF = {"path": "pulse/raw.json", "sha256": "a" * 64, "locator": "/findings/0"}


def obs(row=None, source="pulse", tenant="tenant-a", run="run-1", ref=None):
    return observation({**BASE, **(row or {})}, source=source, tenant_id=tenant, run_id=run,
                       artifact_ref=ref or REF)


def test_same_subject_cve_preserves_two_sources_and_deduplicates_replay():
    a, b = obs(), obs(source="nuclei")
    result = aggregate([a, b, a, b])
    assert result["finding_count"] == 1
    assert result["observation_count"] == 2
    assert result["findings"][0]["sources"] == ["nuclei", "pulse"]
    assert result["findings"][0]["assessment"]["machine_verified"] is False


def test_all_input_permutations_and_input_immutability():
    rows = [obs(), obs({"confidence": 0}, source="nuclei"), obs({"confidence": 90}, source="nmap-nse")]
    original = copy.deepcopy(rows)
    expected = aggregate(rows)
    for permutation in itertools.permutations(rows):
        assert aggregate(list(permutation)) == expected
        assert aggregate(list(permutation) * 2) == expected
    assert rows == original


@pytest.mark.parametrize("change", [
    {"protocol": "udp"}, {"protocol": "unknown"}, {"port": "8443"},
    {"host": "site.example"}, {"sni": "site.example"}, {"affected_object": "/admin"},
    {"host": "https://192.0.2.1/"},
])
def test_incomplete_subject_is_not_a_wildcard(change):
    assert aggregate([obs(), obs(change)])["finding_count"] == 2


def test_tenants_and_runs_have_distinct_observations_but_stable_subject_groups():
    assert aggregate([obs(), obs(tenant="tenant-b")])["finding_count"] == 2
    result = aggregate([obs(), obs(run="run-2")])
    assert result["finding_count"] == 1 and result["observation_count"] == 2


def test_ipv6_and_port_spelling_normalization():
    a = obs({"host": "2001:db8::1", "port": "443"})
    b = obs({"host": "[2001:0db8:0:0:0:0:0:1]:443", "port": 443})
    assert a == b
    assert aggregate([a, b])["observation_count"] == 1


def test_url_host_case_default_port_and_timezone_normalization():
    a = obs({"host": "https://SITE.example/", "observed_at": "2026-09-01T12:00:00+03:00"})
    b = obs({"host": "https://site.example:443/", "observed_at": "2026-09-01T09:00:00Z"})
    assert a == b


@pytest.mark.parametrize("url", ["https://other.example/a", "https://site.example/b",
                                    "https://site.example/a?x=1", "https://site.example/a?x=2"])
def test_virtual_hosts_and_affected_objects_are_distinct(url):
    assert aggregate([obs({"host": "https://site.example/a"}), obs({"host": url})])["finding_count"] == 2


def test_url_credentials_and_paths_are_not_disclosed_in_projection():
    a = obs({"host": "https://user:supersecret@site.example/private-value?token=tok123#frag"})
    text = json.dumps(aggregate([a]))
    assert all(secret not in text for secret in ("supersecret", "private-value", "tok123", "frag"))
    assert a["subject"]["authority"] == "site.example:443"


@pytest.mark.parametrize("row", [
    {"host": "https://site.example:0/", "port": None},
    {"host": "https://site.example:443/", "port": 80},
    {"host": "https://site.example/", "protocol": "udp"},
    {"host": "host\nname"}, {"port": True}, {"port": -1}, {"port": 65536},
    {"protocol": "sctp"},
])
def test_invalid_or_contradictory_subject_is_rejected(row):
    with pytest.raises(ValueError):
        obs(row)


def test_latest_metadata_does_not_erase_older_stronger_evidence():
    early = obs({"observed_at": "2026-09-01T10:00:00Z", "confidence": 99})
    later = obs({"observed_at": "2026-09-02T10:00:00Z", "confidence": 10})
    unknown = obs({"confidence": 0})
    result = aggregate([later, unknown, early])["findings"][0]
    assert result["observation_count"] == 3
    assert result["assessment"]["latest_observation_ids"] == [later["observation_id"]]
    assert result["assessment"]["undated_observation_ids"] == [unknown["observation_id"]]
    assert "confidence" in result["assessment"]["differing_fields"]


@pytest.mark.parametrize("value", ["2026-09-01", "2026-09-01T12:00:00", "invalid", None])
def test_missing_or_naive_timestamps_are_not_invented(value):
    assert timestamp(value) is None


def test_known_secrets_redacted_before_truncation_and_zero_confidence_preserved():
    raw = 'Authorization: Bearer hidden\nCookie: session=hidden\npassword="hidden" api_key=hidden'
    assert "hidden" not in safe_text(raw)
    assert len(safe_text("x" * 10000)) == PREVIEW_LIMIT
    assert obs({"confidence": 0})["confidence"] == 0
    for invalid in (True, float("nan"), float("inf"), -1, 101):
        assert obs({"confidence": invalid})["confidence"] is None


def test_body_fields_do_not_enter_contract():
    result = obs({"request": "request-secret", "response": "response-secret", "extracted-results": ["secret"]})
    assert "secret" not in json.dumps(result)


def test_refs_merge_without_new_observations_and_are_bounded():
    rows = [obs(ref={**REF, "locator": f"/findings/{i}"}) for i in range(20)]
    result = aggregate(rows)["findings"][0]["observations"][0]
    assert len(result["artifact_refs"]) == MAX_ARTIFACT_REFS
    assert result["artifact_refs_truncated"] is True
    assert aggregate(rows)["observation_count"] == 1


def test_mutated_observation_cannot_enter_aggregate():
    item = obs()
    item["tenant_id"] = "tenant-b"
    with pytest.raises(ValueError):
        aggregate([item])


@pytest.fixture
def run_files(tmp_path):
    (tmp_path / "pulse").mkdir()
    (tmp_path / "nmap").mkdir()
    (tmp_path / "pulse/raw.json").write_text(json.dumps({
        "meta": {"version": "1.1.0"},
        "findings": [{"ip": "192.0.2.1", "port": 443, "cve_id": CVE,
                      "finding_class": "version_cve", "confidence": 70, "severity": "high"}],
    }))
    # Synthetic fixture of fields used by the pinned Nuclei adapter, not a live scan.
    event = {"template-id": "cve-fixture", "host": "192.0.2.1", "port": "443", "type": "tcp",
             "info": {"name": "Fixture", "severity": "high", "classification": {"cve-id": [CVE]}},
             "timestamp": "2026-09-01T10:00:00Z", "matcher-name": "marker",
             "request": "private request", "response": "private response", "extracted-results": ["private extraction"]}
    (tmp_path / "nuclei_raw.jsonl").write_text(json.dumps(event) + "\n" + json.dumps(event) + "\n")
    (tmp_path / "nmap/result.xml").write_text(
        f'<nmaprun version="7.95"><host><address addr="192.0.2.1" addrtype="ipv4"/>'
        f'<ports><port portid="443" protocol="tcp"><state state="open"/>'
        f'<script id="vulners" output="{CVE} 7.5"/></port></ports></host></nmaprun>'
    )
    (tmp_path / "vulnerabilities.json").write_text('[{"legacy":"unchanged"}]')
    return tmp_path


def test_offline_artifacts_three_sources_no_network_and_no_legacy_mutations(run_files, monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("network/process not permitted")
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    before = {str(p): p.read_bytes() for p in run_files.rglob("*") if p.is_file()}
    result = ea.write_evidence_artifact(run_files, tenant_id="tenant", run_id="run")
    assert result["finding_count"] == 1 and result["observation_count"] == 3
    assert result["projection_incomplete"] is False
    assert result["coverage"] == "unknown"
    assert {str(p): p.read_bytes() for p in map(Path, before)} == before
    assert result == ea.write_evidence_artifact(run_files, tenant_id="tenant", run_id="run")
    assert "private" not in json.dumps(result)
    rows = result["findings"][0]["observations"]
    assert {r["source"]: r["engine_version"] for r in rows} == {"pulse": "1.1.0", "nuclei": None, "nmap-nse": "7.95"}
    assert all(r["artifact_refs"][0]["sha256"] for r in rows)


def test_distinct_extracted_evidence_is_hashed_not_dropped(run_files):
    path = run_files / "nuclei_raw.jsonl"
    raw = json.loads(path.read_text().splitlines()[0])
    other = {**raw, "extracted-results": ["different private extraction"]}
    path.write_text(json.dumps(raw) + "\n" + json.dumps(other))
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert result["observation_count"] == 4
    assert "private" not in json.dumps(result)


def test_incomplete_and_missing_artifacts_never_prove_remediation(run_files):
    (run_files / "pulse/raw.json").write_text("not JSON")
    (run_files / "nuclei_raw.jsonl").write_text('broken\n{"type":"http"}\n')
    (run_files / "nmap/result.xml").unlink()
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert result["projection_incomplete"] is True and result["coverage"] == "unknown"
    assert result["finding_count"] == 0
    assert {d["code"] for d in result["diagnostics"]} >= {"invalid_json", "invalid_jsonl_row", "missing"}


def test_xml_entities_are_rejected(run_files):
    (run_files / "nmap/result.xml").write_text('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>')
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert {"artifact": "nmap/result.xml", "code": "invalid_xml"} in result["diagnostics"]


def test_escaped_symlink_is_not_read(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    external = tmp_path / "external"
    external.write_text("must not be read")
    (root / "nuclei_raw.jsonl").symlink_to(external)
    result = ea.EvidenceReader(root, "tenant", "run").build()
    assert {"artifact": "nuclei_raw.jsonl", "code": "unsafe_path"} in result["diagnostics"]


def test_exhausted_byte_budget_stays_bounded(run_files, monkeypatch):
    monkeypatch.setattr(ea, "MAX_TOTAL_BYTES", 10)
    reader = ea.EvidenceReader(run_files, "tenant", "run")
    result = reader.build()
    assert reader.bytes_read == 11
    assert result["projection_incomplete"] is True
    assert result["observation_count"] == 0


def test_observation_cap_is_visible(run_files, monkeypatch):
    monkeypatch.setattr(ea, "MAX_OBSERVATIONS", 1)
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert result["projection_incomplete"] is True
    assert result["observation_count"] == 1


def test_cli_runs_only_offline_projection(run_files):
    script = Path(__file__).resolve().parents[1] / "scripts/build-finding-evidence.py"
    completed = subprocess.run([sys.executable, str(script), str(run_files), "--tenant-id", "tenant",
                                "--run-id", "run"], capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
    assert "3 observations" in completed.stdout
    assert (run_files / "finding_evidence.json").is_file()


def test_truncated_rule_labels_do_not_merge_distinct_non_cve_findings():
    a = obs({"cve": None, "rule_id": "x" * 300 + "a"})
    b = obs({"cve": None, "rule_id": "x" * 300 + "b"})
    assert a["rule_id"] == b["rule_id"]
    assert aggregate([a, b])["finding_count"] == 2


def test_source_tenant_cannot_override_explicit_context(run_files):
    path = run_files / "pulse/raw.json"
    raw = json.loads(path.read_text())
    raw["findings"][0]["tenant_id"] = "other-tenant"
    path.write_text(json.dumps(raw))
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert {r["tenant_id"] for f in result["findings"] for r in f["observations"]} == {"tenant"}


def test_optional_absent_engine_is_diagnosed_but_not_a_parse_error(run_files):
    (run_files / "nmap/result.xml").unlink()
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert result["projection_incomplete"] is False
    assert {"artifact": "nmap", "code": "missing"} in result["diagnostics"]
    assert result["coverage"] == "unknown"


def test_no_source_files_is_not_a_successful_projection(tmp_path):
    result = ea.EvidenceReader(tmp_path, "tenant", "run").build()
    assert result["projection_incomplete"] is True
    assert result["observation_count"] == 0


def test_empty_findings_falls_back_to_legacy_pulse_cves(run_files):
    path = run_files / "pulse/raw.json"
    raw = json.loads(path.read_text())
    raw["cves"], raw["findings"] = raw["findings"], []
    path.write_text(json.dumps(raw))
    result = ea.EvidenceReader(run_files, "tenant", "run").build()
    assert result["observation_count"] == 3


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "https://example.com/file", "nmap/../secret", "nmap\\file"])
def test_artifact_references_are_relative_and_validated(path):
    with pytest.raises(ValueError):
        obs(ref={**REF, "path": path})
