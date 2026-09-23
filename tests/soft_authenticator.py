"""A software WebAuthn authenticator for the tests (#315).

It does what a security key does, byte for byte: an ES256 key pair generated
here, a ``none`` attestation object carrying the COSE public key, and
assertions whose signature is a real ECDSA-P256 signature over
``authenticatorData || SHA-256(clientDataJSON)``. The API under test verifies
them with the same library it uses in production — nothing on the server side
is mocked, which is the point: a test that stubbed the verifier would pass
against a server that checked nothing.

The knobs are the ways a real attack differs from a real login: the origin the
"browser" reports (a phishing page), the RP ID it hashes, and the signature
counter (a cloned key replays an old one).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

_FLAG_UP = 0x01
_FLAG_UV = 0x04
_FLAG_AT = 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    """One credential on one authenticator."""

    def __init__(self, origin: str) -> None:
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0

    @property
    def credential_id_b64(self) -> str:
        return b64url(self.credential_id)

    def _cose_public_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    @staticmethod
    def _client_data(kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}
        ).encode()

    def create(
        self, public_key: dict[str, Any], *, origin: str | None = None, rp_id: str | None = None
    ) -> dict[str, Any]:
        """Answer ``navigator.credentials.create()`` for these options."""
        client_data = self._client_data(
            "webauthn.create", public_key["challenge"], origin or self.origin
        )
        rp_hash = hashlib.sha256((rp_id or public_key["rp"]["id"]).encode()).digest()
        auth_data = (
            rp_hash
            + bytes([_FLAG_UP | _FLAG_UV | _FLAG_AT])
            + self.sign_count.to_bytes(4, "big")
            + bytes(16)  # AAGUID: none
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_public_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["usb"],
            },
        }

    def get(
        self,
        public_key: dict[str, Any],
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        sign_count: int | None = None,
        signing_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> dict[str, Any]:
        """Answer ``navigator.credentials.get()``: a signed assertion.

        The counter advances by one per call, as a hardware key's does, unless
        ``sign_count`` pins it — which is what a clone replaying its copy of the
        counter looks like.
        """
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count
        client_data = self._client_data(
            "webauthn.get", public_key["challenge"], origin or self.origin
        )
        rp_hash = hashlib.sha256((rp_id or public_key["rpId"]).encode()).digest()
        auth_data = rp_hash + bytes([_FLAG_UP | _FLAG_UV]) + sign_count.to_bytes(4, "big")
        signature = (signing_key or self.key).sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
            },
        }
