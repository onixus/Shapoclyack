import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return json.loads((ROOT / "apex-contract.json").read_text(encoding="utf-8"))


def test_apex_contract_identity_and_ownership_boundary():
    manifest = _manifest()
    assert manifest["contract"]["version"] == "1.0"
    assert manifest["contract"]["canonical_repo"] == "onixus/unified-platform"
    assert manifest["system"] == {
        "id": "shapoclyack",
        "namespace": "shapoclyack",
        "role": "easm-rbvm",
    }

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
    refs = {item["kind"]: item for item in manifest["resources"]}
    assert refs["asset"]["local_id_field"] == "asset_id"
    assert refs["asset"]["urn_prefix"] == "urn:apex:asset:shapoclyack:"
    assert refs["finding"]["urn_prefix"] == "urn:apex:finding:shapoclyack:"
    assert refs["evidence"]["urn_prefix"] == "urn:apex:evidence:shapoclyack:"

    integration = manifest["integration"]
    assert "pulse.scan-observation" in integration["consumes"]
    assert "lariska.inventory-snapshot" in integration["consumes"]
