import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return json.loads((ROOT / "apex-contract" / "manifest.json").read_text(encoding="utf-8"))


def test_apex_contract_identity_and_ownership_boundary():
    manifest = _manifest()
    assert manifest["apex_contract_version"] == "1.0"
    assert manifest["canonical"]["repo"] == "onixus/unified-platform"
    assert manifest["system"] == "shapoclyack"
    assert manifest["namespace"] == "shapoclyack"

    ownership = manifest["ownership"]
    assert ownership["gateway_is_source_of_truth"] is False
    assert ownership["clickhouse_is_transactional_source"] is False
    assert {"assets", "findings", "remediation-lifecycle"}.issubset(
        set(ownership["authoritative_domains"])
    )

    identity = manifest["identity"]
    assert identity["trust_unsigned_role_header"] is False
    assert identity["owning_service_authorizes_mutations"] is True


def test_apex_contract_preserves_asset_and_evidence_identity():
    manifest = _manifest()
    resources = manifest["resources"]
    assert {"asset", "finding", "evidence"}.issubset(set(resources["owns"]))

    boundaries = {item["name"]: item for item in manifest["boundaries"]}
    assert "lariska-agent-v1" in boundaries
    pulse = boundaries["pulse-engine-v3"]
    assert pulse["event_type"] == "apex.pulse.scan_report.v3"
    assert pulse["payload_schema_id"] == "https://pulse.dev/schemas/v3/scan-report.json"
    assert "pulse-engine-v1" not in boundaries


def test_pulse_boundary_lists_the_report_schemas_the_adapter_reads():
    from scanner.pipeline.pulse_probe import REPORT_SCHEMAS

    boundaries = {item["name"]: item for item in _manifest()["boundaries"]}
    accepted = boundaries["pulse-engine-v3"]["accepted_report_schemas"]
    assert accepted == list(REPORT_SCHEMAS)
    # The boundary's event version and the newest report schema move together.
    assert accepted[-1] == "pulse.scan.v3"
