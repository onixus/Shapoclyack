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
    assert identity["production_trusts_unsigned_role_header"] is False
    assert identity["owning_service_authorizes_mutations"] is True


def test_apex_contract_preserves_asset_and_evidence_identity():
    manifest = _manifest()
    resources = manifest["resources"]
    assert {"asset", "finding", "evidence"}.issubset(set(resources["owns"]))

    boundaries = {item["name"]: item for item in manifest["boundaries"]}
    assert "lariska-agent-v1" in boundaries
    assert boundaries["pulse-engine-v1"]["event_type"] == "apex.pulse.scan_report.v1"
