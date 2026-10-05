"""Certificate key and signature strength (DQ2).

Pure functions over the ``cert`` dicts that ``tls_posture.py`` builds from its
sources. No I/O, no network. Three fields are read, all optional:

  * ``public_key_type`` -- ``rsa``, ``dsa``, ``ec``, ``ed25519``/``ed448``, as
    nmap's ``ssl-cert`` prints it ("Public Key type: rsa") and as the stdlib
    probe derives it from the leaf's DER;
  * ``public_key_bits`` -- RSA/DSA modulus size, EC curve size;
  * ``signature_algorithm`` -- the leaf's signature algorithm by its OpenSSL
    long name (``sha256WithRSAEncryption``, ``ecdsa-with-SHA1``,
    ``dsaWithSHA1``).

Two findings come out of them:

  * ``weak_key`` -- RSA/DSA under 2048 bits (medium; high under 1024, which is
    factorable in practice), EC under 224 bits (medium). An unknown key type
    yields nothing: 256 bits is a strong EC key and a broken RSA one, so the
    size alone cannot be judged.
  * ``weak_signature`` -- the leaf is signed with MD2/MD4/MD5 or SHA-1
    (medium). RSASSA-PSS names no hash in the algorithm name and is not judged.

NO DATA, NO FINDING: a source that did not record a field produces no finding
for it, never a guess. Pulse ``tls[]`` rows carry neither field today, so this
check is silent on the Pulse path.
"""

from __future__ import annotations

import re
from typing import Any

RSA_DSA_MIN_BITS = 2048
RSA_DSA_BROKEN_BITS = 1024
EC_MIN_BITS = 224

_KEY_TYPES = {
    "rsa": "rsa",
    "rsaencryption": "rsa",
    "dsa": "dsa",
    "dsaencryption": "dsa",
    "ec": "ec",
    "ecdsa": "ec",
    "ecpublickey": "ec",
    "id-ecpublickey": "ec",
    "ed25519": "ed25519",
    "ed448": "ed448",
}

# Hash tokens of a broken signature digest. Algorithm names glue the hash to
# the key algorithm with "With" (sha1WithRSAEncryption, dsaWithSHA1) or with
# punctuation (ecdsa-with-SHA1, RSA-SHA1), so the name is split on both before
# the tokens are compared -- a substring test would also need to tell "sha1"
# from "sha1024" if such a name ever appeared.
_WEAK_DIGESTS = {"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha1": "SHA-1"}
_ALG_SPLIT_RE = re.compile(r"[^a-z0-9]+|with")


def normalize_key_type(raw: Any) -> str | None:
    """Map a source's key-type label to ``rsa``/``dsa``/``ec``/``ed25519``/``ed448``."""
    if not raw:
        return None
    return _KEY_TYPES.get(str(raw).strip().lower())


def weak_key_issue(key_type: Any, bits: Any) -> dict[str, Any] | None:
    """A ``weak_key`` issue for this key, or ``None`` when it is adequate or unknown."""
    kind = normalize_key_type(key_type)
    try:
        size = int(bits)
    except (TypeError, ValueError):
        return None
    if kind is None or size <= 0:
        return None

    if kind in ("rsa", "dsa"):
        if size >= RSA_DSA_MIN_BITS:
            return None
        severity = "high" if size < RSA_DSA_BROKEN_BITS else "medium"
        minimum = RSA_DSA_MIN_BITS
    elif kind == "ec":
        if size >= EC_MIN_BITS:
            return None
        severity = "medium"
        minimum = EC_MIN_BITS
    else:
        # Ed25519/Ed448 have a fixed, adequate strength.
        return None

    return {
        "kind": "weak_key",
        "severity": severity,
        "key_type": kind,
        "bits": size,
        "detail": f"{kind.upper()} {size}-bit key (minimum {minimum})",
    }


def weak_signature_issue(signature_algorithm: Any) -> dict[str, Any] | None:
    """A ``weak_signature`` issue when the leaf's digest is MD2/MD4/MD5/SHA-1."""
    if not signature_algorithm:
        return None
    name = str(signature_algorithm).strip()
    tokens = {token for token in _ALG_SPLIT_RE.split(name.lower()) if token}
    for token, label in _WEAK_DIGESTS.items():
        if token in tokens:
            return {
                "kind": "weak_signature",
                "severity": "medium",
                "algorithm": name,
                "detail": f"certificate signed with {name} ({label})",
            }
    return None


def cert_strength_issues(cert: dict[str, Any] | None) -> list[dict[str, Any]]:
    """``weak_key`` / ``weak_signature`` issues for one normalized ``cert`` dict."""
    if not isinstance(cert, dict):
        return []
    issues: list[dict[str, Any]] = []
    key_issue = weak_key_issue(cert.get("public_key_type"), cert.get("public_key_bits"))
    if key_issue is not None:
        issues.append(key_issue)
    sig_issue = weak_signature_issue(cert.get("signature_algorithm"))
    if sig_issue is not None:
        issues.append(sig_issue)
    return issues
