"""Data-only import validation does not need a database."""
from __future__ import annotations

import copy
import csv
import io
import json

import pytest

from api.services.compliance import definitions as d


def example():
    return {
        "framework_id": "custom-acme-v1", "name": "ACME", "version": "1",
        "scope_note": "Technical observations only.",
        "controls": [{"control_id": "АНЗ.1", "title": "Known vulnerabilities",
                      "signals": ["unpatched_cve"], "rationale": "Open CVEs on the estate."}],
    }


def csv_document(document):
    out = io.StringIO(newline="")
    metadata = ("framework_id", "name", "version", "scope_note")
    fields = [*metadata, "control_id", "title", "signals", "combinations", "requires", "severity_floor", "rationale"]
    writer = csv.DictWriter(out, fields)
    writer.writeheader()
    for control in document["controls"]:
        row = {key: document[key] for key in metadata} | control
        for key in ("signals", "combinations", "requires"):
            if key in row:
                row[key] = json.dumps(row[key])
        writer.writerow(row)
    return out.getvalue()


def test_json_csv_bom_and_digest_roundtrip():
    raw = example()
    normalized = d.normalize(raw)
    assert d.parse("\ufeff" + json.dumps(raw), "json") == normalized
    assert d.parse("\ufeff" + csv_document(raw), "csv") == normalized
    assert d.normalize(normalized) == normalized
    assert d.digest(d.parse(json.dumps(raw, indent=3), "json")) == d.digest(normalized)
    assert normalized["controls"][0]["requires"] == ["findings"]
    assert "requires" not in raw["controls"][0]


@pytest.mark.parametrize("patch", [
    {"signals": []}, {"signals": "unpatched_cve"}, {"signals": ["compliant"]},
    {"signals": ["unpatched_cve", "unpatched_cve"]}, {"signals": [1]},
    {"requires": []}, {"requires": ["assets"]}, {"requires": "findings"},
    {"severity_floor": "critical OR true"}, {"severity_floor": None},
    {"signals": ["stale_asset"], "severity_floor": "high"},
    {"signals": ["unassessable_software"], "severity_floor": "critical"},
    {"combinations": [["unpatched_cve"]]},
    {"combinations": [["unpatched_cve", "stale_asset"]]},
    {"combinations": [["unpatched_cve", "known_exploited"], ["known_exploited", "unpatched_cve"]]},
    {"control_id": "../escape"}, {"control_id": ""}, {"title": "\u0000"},
    {"title": "\ud800"}, {"rationale": ""}, {"expression": "1 == 1"},
])
def test_invalid_control_is_rejected_atomically(patch):
    raw = example()
    raw["controls"].append(dict(raw["controls"][0], control_id="second") | patch)
    with pytest.raises(d.DefinitionError):
        d.normalize(raw)


@pytest.mark.parametrize("patch", [
    {"framework_id": "pci-dss-4.0"}, {"framework_id": "custom-../escape"},
    {"schema_version": True}, {"schema_version": 2}, {"controls": []},
    {"controls": {}}, {"tenant_id": "another-tenant"}, {"name": None},
])
def test_invalid_framework(patch):
    with pytest.raises(d.DefinitionError):
        d.normalize(example() | patch)


def test_duplicate_controls_and_limits():
    raw = example()
    raw["controls"] *= 2
    with pytest.raises(d.DefinitionError, match="duplicate control_id"):
        d.normalize(raw)
    with pytest.raises(d.DefinitionError, match="controls"):
        d.normalize(example() | {"controls": example()["controls"] * (d.MAX_CONTROLS + 1)})
    with pytest.raises(d.DefinitionError, match="exceeds"):
        d.parse("я" * (d.MAX_BYTES // 2 + 1), "json")


@pytest.mark.parametrize("text", ['{"x":1,"x":2}', '{"x":NaN}', '[' * 2000, '{} trailing'])
def test_malformed_json(text):
    with pytest.raises(d.DefinitionError):
        d.parse(text, "json")


def test_csv_inconsistent_metadata_or_row_shape():
    raw = example()
    raw["controls"].append(dict(raw["controls"][0], control_id="second"))
    content = csv_document(raw)
    # Alter only the second row's framework name.
    lines = content.splitlines()
    lines[-1] = lines[-1].replace("ACME", "OTHER")
    with pytest.raises(d.DefinitionError, match="same framework"):
        d.parse("\n".join(lines), "csv")
    with pytest.raises(d.DefinitionError):
        d.parse(content + "missing,columns\n", "csv")
    with pytest.raises(d.DefinitionError):
        d.parse(content.replace("framework_id,name", "name,name", 1), "csv")


def test_source_requirements_cannot_be_weakened():
    raw = example()
    raw["controls"][0]["signals"] = ["stale_asset", "unpatched_cve"]
    assert d.normalize(raw)["controls"][0]["requires"] == ["assets", "findings"]
    raw["controls"][0]["requires"] = ["findings"]
    with pytest.raises(d.DefinitionError, match="cannot omit"):
        d.normalize(raw)


def test_valid_conjunction_and_strengthened_requirements():
    raw = example()
    control = raw["controls"][0]
    control["signals"] = []
    control["combinations"] = [["unpatched_cve", "internet_exposed_finding"]]
    control["requires"] = ["assets", "findings"]
    assert d.normalize(raw)["controls"][0]["requires"] == ["assets", "findings"]


def test_canonicalization_does_not_mutate_caller():
    raw = example()
    original = copy.deepcopy(raw)
    d.normalize(raw)
    assert raw == original


@pytest.mark.parametrize("content", ['{"\\ud800":1}', '{"\\ud800":1,"\\ud800":2}'])
def test_error_messages_are_safe_utf8_for_http(content):
    with pytest.raises(d.DefinitionError) as caught:
        d.parse(content, "json")
    assert str(caught.value).encode("utf-8")
