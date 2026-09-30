"""Signed, archivable point-in-time compliance evidence packages (#356).

A package is JSON and self-verifying: the payload is canonicalized, hashed with
SHA-256 and signed with a dedicated Ed25519 key. The public key is embedded so
an archive can detect later corruption without this installation. Authenticity
still requires the verifier to pin the expected key id out of band; an attacker
who can replace both payload and embedded key can otherwise sign a new package.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from api import __version__
from api.db import models
from api.db.engine import get_session
from api.services import artifact_store, audit as audit_service, bdu_fstec, system_status
from api.services.compliance import frameworks, registry, service

SIGNING_KEY_ENV = "OCTO_EVIDENCE_SIGNING_KEY"
FORMAT = "shapoclyack.compliance-evidence"
VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
_KEY_BYTES = 32
_KEY_ID_DOMAIN = b"shapoclyack/compliance-evidence/ed25519/v1"


class SigningUnavailable(RuntimeError):
    """The installation has no usable evidence signing identity."""


class InvalidEvidencePackage(ValueError):
    """An evidence package is malformed or does not verify."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _decode_private_key(raw: str) -> bytes:
    value = str(raw or "").strip()
    candidate: bytes | None = None
    if len(value) == _KEY_BYTES * 2:
        try:
            candidate = bytes.fromhex(value)
        except ValueError:
            candidate = None
    if candidate is None:
        try:
            candidate = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            candidate = None
    if candidate is None or len(candidate) != _KEY_BYTES:
        raise SigningUnavailable(
            f"{SIGNING_KEY_ENV} must be a 32-byte Ed25519 private seed as base64 or hex"
        )
    return candidate


def _private_key(environ: dict[str, str] | None = None) -> Ed25519PrivateKey:
    env = os.environ if environ is None else environ
    raw = (env.get(SIGNING_KEY_ENV) or "").strip()
    if not raw:
        raise SigningUnavailable(
            f"{SIGNING_KEY_ENV} is not configured; signed evidence packages are unavailable"
        )
    return Ed25519PrivateKey.from_private_bytes(_decode_private_key(raw))


def _raw_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    return hashlib.sha256(_KEY_ID_DOMAIN + _raw_public(key)).hexdigest()[:16]


def sign_payload(
    payload: dict[str, Any],
    *,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    key = _private_key(environ)
    body = canonical_bytes(payload)
    public = _raw_public(key)
    return {
        "format": FORMAT,
        "version": VERSION,
        "payload_sha256": hashlib.sha256(body).hexdigest(),
        "payload": payload,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id(key),
            "public_key": base64.b64encode(public).decode("ascii"),
            "value": base64.b64encode(key.sign(body)).decode("ascii"),
        },
    }


def verify(
    package: dict[str, Any],
    *,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(package, dict) or package.get("format") != FORMAT or package.get("version") != VERSION:
        raise InvalidEvidencePackage("unsupported evidence package format")
    payload = package.get("payload")
    signature = package.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise InvalidEvidencePackage("evidence package is missing payload or signature")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise InvalidEvidencePackage("unsupported evidence signature algorithm")
    try:
        public_raw = base64.b64decode(str(signature["public_key"]), validate=True)
        signed = base64.b64decode(str(signature["value"]), validate=True)
        public = Ed25519PublicKey.from_public_bytes(public_raw)
    except (KeyError, ValueError, binascii.Error) as exc:
        raise InvalidEvidencePackage("malformed evidence signature") from exc
    actual_key_id = key_id(public)
    if signature.get("key_id") != actual_key_id:
        raise InvalidEvidencePackage("evidence signing key id does not match the embedded public key")
    if expected_key_id is not None and actual_key_id != expected_key_id:
        raise InvalidEvidencePackage(
            f"evidence package was signed by {actual_key_id}, expected {expected_key_id}"
        )
    body = canonical_bytes(payload)
    digest = hashlib.sha256(body).hexdigest()
    if package.get("payload_sha256") != digest:
        raise InvalidEvidencePackage("evidence payload SHA-256 does not match")
    try:
        public.verify(signed, body)
    except InvalidSignature as exc:
        raise InvalidEvidencePackage("evidence signature is invalid") from exc
    return payload


def _framework_document(
    settings,
    *,
    tenant_id: str,
    framework: frameworks.Framework,
) -> dict[str, Any]:
    custom = registry.get_definition(
        settings,
        tenant_id=tenant_id,
        framework_id=framework.framework_id,
    )
    if custom is not None:
        return {
            "kind": "custom",
            "sha256": custom["definition_sha256"],
            "definition": custom["definition"],
            "created_at": custom["created_at"],
            "created_by": custom["created_by"],
        }
    document = dataclasses.asdict(framework)
    return {
        "kind": "builtin",
        "sha256": hashlib.sha256(canonical_bytes(document)).hexdigest(),
        "definition": document,
    }


def _enrichment_provenance() -> dict[str, Any]:
    raw = system_status.enrichment_manifest()
    result: dict[str, Any] = {}
    for name, record in sorted(raw.items()):
        if not isinstance(record, dict):
            continue
        result[name] = {
            key: record.get(key)
            for key in (
                "source",
                "origin",
                "source_origin",
                "updated",
                "entries",
                "usable",
                "origin_urls",
            )
        }
    return result


def build_payload(
    settings,
    *,
    tenant_id: str,
    framework_id: str,
) -> dict[str, Any] | None:
    framework = registry.resolve_framework(settings, framework_id, tenant_id)
    if framework is None:
        return None
    posture = service.snapshot(
        settings,
        framework_id=framework_id,
        tenant_id=tenant_id,
    )
    if posture is None:
        return None
    return {
        "format": FORMAT,
        "version": VERSION,
        "tenant_id": tenant_id,
        "framework_id": framework.framework_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "producer": {"name": "Shapoclyack", "version": __version__},
        "framework": _framework_document(
            settings,
            tenant_id=tenant_id,
            framework=framework,
        ),
        "posture": posture,
        "enrichment": _enrichment_provenance(),
        "bdu_fstec": bdu_fstec.dataset_info(),
        "scope_notice": (
            "This package records technical evidence observed by the platform at generation "
            "time. It is not a certification or a legal compliance opinion."
        ),
    }


def create(
    settings,
    *,
    tenant_id: str,
    framework_id: str,
    actor: str,
    audit,
) -> dict[str, Any] | None:
    """Create a signed JSON artifact and its generated_reports row.

    Artifact bytes are written first. If the database transaction fails, those
    bytes are deleted so there is no unindexed evidence object outside retention.
    """
    payload = build_payload(
        settings,
        tenant_id=tenant_id,
        framework_id=framework_id,
    )
    if payload is None:
        return None
    package = sign_payload(payload)
    encoded = (
        json.dumps(package, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    report_id = f"rpt_{uuid.uuid4().hex[:16]}"
    key = artifact_store.keys.report_key(tenant_id, f"{report_id}.json")
    store = artifact_store.get_store(settings)
    store.put_bytes(key, encoded, content_type="application/json")
    now = datetime.now(UTC)
    row = models.GeneratedReport(
        report_id=report_id,
        tenant_id=tenant_id,
        template_id=None,
        schedule_id=None,
        kind="compliance_evidence",
        fmt="json",
        status="ready",
        title=f"Compliance evidence — {framework_id}",
        storage_path=key,
        size_bytes=len(encoded),
        error=None,
        delivery=[],
        generated_at=now,
        generated_by=actor,
    )
    try:
        with get_session(settings.postgres_url) as session:
            session.add(row)
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_COMPLIANCE_EVIDENCE_CREATE,
                resource_type="compliance_evidence",
                resource_id=report_id,
                tenant_id=tenant_id,
                after={
                    "framework_id": framework_id,
                    "payload_sha256": package["payload_sha256"],
                    "key_id": package["signature"]["key_id"],
                    "size_bytes": len(encoded),
                },
            )
            session.flush()
    except Exception:
        try:
            store.delete(key)
        except artifact_store.ArtifactStoreError:
            pass
        raise
    return {
        "report_id": report_id,
        "tenant_id": tenant_id,
        "template_id": None,
        "schedule_id": None,
        "kind": "compliance_evidence",
        "format": "json",
        "status": "ready",
        "title": row.title,
        "size_bytes": len(encoded),
        "error": None,
        "delivery": [],
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "generated_by": actor,
    }
