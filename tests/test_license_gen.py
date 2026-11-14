"""Tests for the offline product-license generator CLI."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from api.services.licensing.format import (
    build_payload,
    calculate_expiry,
    sign_license,
    verify_license,
)
from tools.license_gen import cli


def test_month_calculator_jan_31_plus_one_month() -> None:
    start = datetime(2026, 1, 31, 12, 0, 0, tzinfo=UTC)
    valid_from, expires_at = calculate_expiry(valid_from=start, months=1)
    assert valid_from == start.replace(microsecond=0)
    # Non-leap year: clamp to 28 Feb.
    assert expires_at == datetime(2026, 2, 28, 12, 0, 0, tzinfo=UTC)


def test_sign_verify_roundtrip_ephemeral_key() -> None:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    payload = build_payload(
        customer_name="Roundtrip Co",
        days=30,
        lariska=True,
        brand_watch=True,
    )
    document = sign_license(payload, private_key=seed)
    verified = verify_license(document, expected_public_key=document["signature"]["public_key"])
    assert verified.customer_name == "Roundtrip Co"
    assert verified.features.lariska is True
    assert verified.features.brand_watch is True
    assert verified.expires_at > verified.valid_from


def test_cli_generate_keypair(tmp_path: Path) -> None:
    out = tmp_path / "keypair.json"
    rc = cli.main(["--generate-keypair", "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "signing_key_base64" in data
    assert "public_key_base64" in data
    assert "key_id" in data
    assert len(data["key_id"]) == 64


def test_cli_generate_license_days_with_features(tmp_path: Path) -> None:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    seed_file = tmp_path / "seed.txt"
    seed_file.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
    license_path = tmp_path / "license.json"

    rc = cli.main(
        [
            "--customer",
            "Acme Corp",
            "--days",
            "30",
            "--lariska",
            "--brand-watch",
            "--signing-key",
            str(seed_file),
            "--output",
            str(license_path),
        ]
    )
    assert rc == 0
    document = json.loads(license_path.read_text(encoding="utf-8"))
    assert document["format"] == "shapoclyack-license"
    assert document["version"] == 1
    payload = document["payload"]
    assert payload["customer_name"] == "Acme Corp"
    assert payload["features"]["lariska"] is True
    assert payload["features"]["brand_watch"] is True
    verified = verify_license(document, expected_public_key=document["signature"]["public_key"])
    assert verified.features.brand_watch is True


def test_cli_reject_multiple_duration_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv(
        "OCTO_LICENSE_SIGNING_KEY", base64.b64encode(seed).decode("ascii")
    )
    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--customer",
                "Acme",
                "--days",
                "30",
                "--months",
                "1",
            ]
        )
    # argparse mutually exclusive group → exit code 2
    assert exc.value.code != 0


def test_cli_print_public_key(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    seed_file = tmp_path / "seed.txt"
    seed_file.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
    out = tmp_path / "pub.json"
    rc = cli.main(
        ["--signing-key", str(seed_file), "--print-public-key", "--output", str(out)]
    )
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    expected_pub = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    assert data["public_key_base64"] == expected_pub
    assert data["env_hint"]["OCTO_LICENSE_PUBLIC_KEY"] == expected_pub
