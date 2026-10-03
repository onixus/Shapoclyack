"""Signed evidence packages remain verifiable after leaving the platform."""
from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from api.services.compliance import evidence_package as package


KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def test_ed25519_package_roundtrip_and_key_pinning():
    payload = {
        "framework_id": "custom-acme-v1",
        "tenant_id": "acme",
        "controls": [{"id": "VM.1", "status": "passed"}],
    }
    envelope = package.sign_payload(
        payload,
        environ={package.SIGNING_KEY_ENV: KEY},
    )
    assert envelope["signature"]["algorithm"] == "Ed25519"
    assert len(envelope["signature"]["key_id"]) == 64
    assert package.verify(envelope) == payload
    assert package.verify(
        envelope,
        expected_key_id=envelope["signature"]["key_id"],
    ) == payload
    with pytest.raises(package.InvalidEvidencePackage, match="expected"):
        package.verify(envelope, expected_key_id="0" * 64)


def test_tampering_payload_or_signature_is_refused():
    envelope = package.sign_payload(
        {"tenant_id": "acme", "value": 1},
        environ={package.SIGNING_KEY_ENV: KEY},
    )
    changed = copy.deepcopy(envelope)
    changed["payload"]["value"] = 2
    with pytest.raises(package.InvalidEvidencePackage, match="SHA-256"):
        package.verify(changed)

    changed = copy.deepcopy(envelope)
    changed["signature"]["value"] = base64.b64encode(b"x" * 64).decode("ascii")
    with pytest.raises(package.InvalidEvidencePackage, match="signature is invalid"):
        package.verify(changed)


@pytest.mark.parametrize("raw", ["", "short", "00" * 31, "00" * 33])
def test_signing_identity_is_explicit_and_strict(raw):
    with pytest.raises(package.SigningUnavailable):
        package.sign_payload(
            {"tenant_id": "acme"},
            environ={package.SIGNING_KEY_ENV: raw},
        )


def test_canonical_payload_ignores_mapping_insertion_order():
    left = package.sign_payload(
        {"b": 2, "a": {"y": 2, "x": 1}},
        environ={package.SIGNING_KEY_ENV: KEY},
    )
    right = package.sign_payload(
        {"a": {"x": 1, "y": 2}, "b": 2},
        environ={package.SIGNING_KEY_ENV: KEY},
    )
    assert left["payload_sha256"] == right["payload_sha256"]
    # Ed25519 is deterministic for one key and one message.
    assert left["signature"]["value"] == right["signature"]["value"]


def test_standalone_verifier_needs_no_platform_and_agrees(tmp_path):
    script = Path(__file__).resolve().parent.parent / "scripts" / "verify-compliance-evidence.py"
    envelope = package.sign_payload(
        {"tenant_id": "acme", "framework_id": "custom-acme-v1", "имя": "проверка"},
        environ={package.SIGNING_KEY_ENV: KEY},
    )
    target = tmp_path / "evidence.json"
    target.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")
    key_id = envelope["signature"]["key_id"]

    # -S -I and a foreign cwd would not stop an ``api`` import by themselves;
    # the check is that the script names no platform module at all.
    assert "import api" not in script.read_text() and "from api" not in script.read_text()

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script), str(target), *args],
            capture_output=True, text=True, cwd=tmp_path, check=False,
        )

    ok = run("--key-id", key_id)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["key_id"] == key_id
    assert run("--key-id", "0" * 64).returncode == 1

    envelope["payload"]["tenant_id"] = "other"
    target.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
    assert run().returncode == 1
