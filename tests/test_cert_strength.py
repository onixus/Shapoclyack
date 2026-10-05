"""Key-size and signature-digest findings shared by every tls_posture source (DQ2)."""

from __future__ import annotations

import pytest

from scanner.pipeline.cert_strength import (
    cert_strength_issues,
    weak_key_issue,
    weak_signature_issue,
)


@pytest.mark.parametrize(
    ("key_type", "bits", "severity"),
    [
        ("rsa", 2048, None),
        ("rsa", 4096, None),
        ("rsa", 2047, "medium"),
        ("rsa", 1024, "medium"),
        ("rsa", 1023, "high"),
        ("rsa", 512, "high"),
        ("dsa", 1024, "medium"),
        ("RSA", 1024, "medium"),  # nmap and cryptography disagree on case
        ("rsaEncryption", 1024, "medium"),
        ("ec", 256, None),
        ("ec", 224, None),
        ("ec", 192, "medium"),
        ("id-ecPublicKey", 160, "medium"),
        ("ed25519", None, None),
        ("ed448", 456, None),
    ],
)
def test_weak_key_thresholds(key_type, bits, severity):
    issue = weak_key_issue(key_type, bits)
    if severity is None:
        assert issue is None
    else:
        assert issue is not None
        assert issue["kind"] == "weak_key"
        assert issue["severity"] == severity
        assert issue["bits"] == bits


@pytest.mark.parametrize(
    ("key_type", "bits"),
    [
        # 256 bits is a strong EC key and a broken RSA one: without the type
        # there is nothing to judge.
        (None, 256),
        ("", 1024),
        ("gost2012", 256),
        ("rsa", None),
        ("rsa", "n/a"),
        ("rsa", 0),
    ],
)
def test_weak_key_needs_a_known_type_and_size(key_type, bits):
    assert weak_key_issue(key_type, bits) is None


@pytest.mark.parametrize(
    "algorithm",
    [
        "sha1WithRSAEncryption",
        "ecdsa-with-SHA1",
        "dsaWithSHA1",
        "dsa_with_SHA1",
        "RSA-SHA1",
        "md5WithRSAEncryption",
        "md2WithRSAEncryption",
        "sha1WithRSA",
    ],
)
def test_weak_signature_digests(algorithm):
    issue = weak_signature_issue(algorithm)
    assert issue is not None
    assert issue["kind"] == "weak_signature"
    assert issue["severity"] == "medium"
    assert issue["algorithm"] == algorithm


@pytest.mark.parametrize(
    "algorithm",
    [
        "sha256WithRSAEncryption",
        "sha384WithRSAEncryption",
        "ecdsa-with-SHA256",
        "ecdsa-with-SHA512",
        "ED25519",
        "RSASSA-PSS",  # the hash lives in the parameters, not the name
        "",
        None,
    ],
)
def test_strong_or_unknown_signatures_are_not_findings(algorithm):
    assert weak_signature_issue(algorithm) is None


def test_cert_strength_issues_reads_the_normalized_cert_fields():
    cert = {
        "public_key_type": "rsa",
        "public_key_bits": 1024,
        "signature_algorithm": "sha1WithRSAEncryption",
    }
    assert [issue["kind"] for issue in cert_strength_issues(cert)] == ["weak_key", "weak_signature"]


def test_cert_strength_issues_without_data_is_silent():
    # A Pulse row: names and dates, no key or signature fields.
    assert cert_strength_issues({"subject_cn": "app.local", "issuer_cn": "R3"}) == []
    assert cert_strength_issues(None) == []
