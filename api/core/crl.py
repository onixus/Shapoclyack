"""Validate PEM CRL bundles before installing them in a TLS verifier."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Iterable

from cryptography import x509


def validate_bundle(
    data: bytes, issuers: Iterable[x509.Certificate], *, now: datetime | None = None
) -> tuple[x509.CertificateRevocationList, ...]:
    now = now or datetime.now(UTC)
    pattern = b"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----"
    blocks = re.findall(pattern, data, re.DOTALL)
    if not blocks or re.sub(pattern, b"", data, flags=re.DOTALL).strip():
        raise ValueError("Expected a PEM CRL bundle")
    issuers = tuple(issuers)
    crls = tuple(x509.load_pem_x509_crl(block) for block in blocks)
    for crl in crls:
        if (
            crl.next_update_utc is None
            or not crl.last_update_utc <= now < crl.next_update_utc
        ):
            raise ValueError("CRL is not currently valid")
        if not any(
            crl.issuer == issuer.subject and crl.is_signature_valid(issuer.public_key())
            for issuer in issuers
        ):
            raise ValueError("CRL is not signed by a configured client CA")
    return crls
