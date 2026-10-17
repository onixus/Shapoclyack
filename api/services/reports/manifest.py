"""Hash manifest and signature for a generated report (#355).

A report that leaves the installation -- emailed, posted to a webhook, dropped in
a bucket -- is evidence only if the recipient can tell it is the file that was
generated. Each report therefore gets a **manifest** beside it in the artifact
store, ``reports/<tenant>/<id>.manifest.json``: the SHA-256 and size of every
file in the package, signed with the installation's evidence key.

The signature is the one the compliance evidence packages already use
(:mod:`api.services.compliance.evidence_package`, ``OCTO_EVIDENCE_SIGNING_KEY``,
Ed25519 over the canonical JSON of the payload), so one key id is pinned for both
and ``scripts/verify-compliance-evidence.py`` verifies a report manifest offline
without this platform. A manifest is told apart from a compliance package by
``payload.kind``.

Signing is fail-soft by design: with no key configured the report is still
generated, and the manifest is written *unsigned* (hashes only, ``signature``
absent). An unsigned manifest says so when verified -- it is never reported as
valid -- but a missing key must not stop a monthly report reaching a customer.

Imports of ``evidence_package`` are deferred: that module imports the report
store, which imports this one.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from api.services import artifact_store
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.reports.manifest")

KIND = "report-manifest"
MANIFEST_SUFFIX = ".manifest.json"
MEDIA_TYPE = "application/json"


def manifest_key(report_key: str) -> str:
    """The manifest's key: the report's key with its extension swapped."""
    stem, _, _ext = report_key.rpartition(".")
    return f"{stem or report_key}{MANIFEST_SUFFIX}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_payload(
    *, report_id: str, tenant_id: str, generated_at: str | None, files: dict[str, bytes]
) -> dict[str, Any]:
    return {
        "kind": KIND,
        "report_id": report_id,
        "tenant_id": tenant_id,
        "generated_at": generated_at,
        "files": [
            {"name": name, "sha256": _sha256(data), "size_bytes": len(data)}
            for name, data in sorted(files.items())
        ],
    }


def seal(payload: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """``(document, key_id)``: signed when a key is configured, else hashes only."""
    from api.services.compliance import evidence_package as evidence

    try:
        document = evidence.sign_payload(payload)
    except evidence.SigningUnavailable as exc:
        LOG.info("Report manifest written unsigned: %s", exc)
        body = evidence.canonical_bytes(payload)
        return (
            {
                "format": evidence.FORMAT,
                "version": evidence.VERSION,
                "payload_sha256": _sha256(body),
                "payload": payload,
                "signature": None,
            },
            None,
        )
    return document, document["signature"]["key_id"]


def write(
    settings: Settings,
    *,
    report_key: str,
    report_id: str,
    tenant_id: str,
    generated_at: str | None,
    files: dict[str, bytes],
) -> str | None:
    """Store the manifest next to the report; return the signing key id or ``None``."""
    document, key_id = seal(
        build_payload(
            report_id=report_id, tenant_id=tenant_id, generated_at=generated_at, files=files
        )
    )
    artifact_store.get_store(settings).put_bytes(
        manifest_key(report_key),
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"),
        content_type=MEDIA_TYPE,
    )
    return key_id


def delete(settings: Settings, report_key: str) -> None:
    artifact_store.get_store(settings).delete(manifest_key(report_key))


def verify(
    settings: Settings,
    *,
    report_key: str,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    """Re-check a stored report against its manifest.

    ``status`` is one of ``valid`` (signed, signature good, every file matches),
    ``unsigned`` (hashes match but nothing vouches for the manifest), ``tampered``
    (a file differs from the manifest, or the signature does not verify) and
    ``untrusted`` (intact, but signed by a key other than ``expected_key_id``)
    and ``missing`` (no manifest, or the report object is gone). The files are
    re-read from the store rather than trusted from the row: that is the point.
    """
    from api.services.compliance import evidence_package as evidence

    store = artifact_store.get_store(settings)
    result: dict[str, Any] = {
        "status": "missing",
        "signed": False,
        "signature_valid": None,
        "key_id": None,
        "key_matches_installation": None,
        "files": [],
        "detail": None,
    }
    try:
        document = json.loads(store.get_bytes(manifest_key(report_key)))
    except artifact_store.ArtifactNotFound:
        result["detail"] = "no manifest was stored for this report"
        return result
    except ValueError:
        result.update(status="tampered", detail="the stored manifest is not valid JSON")
        return result

    payload = document.get("payload") if isinstance(document, dict) else None
    if not isinstance(payload, dict) or payload.get("kind") != KIND:
        result.update(status="tampered", detail="the stored manifest is not a report manifest")
        return result

    signature = document.get("signature")
    if signature:
        result["signed"] = True
        try:
            # The pin is checked by the caller's intent, not folded into the
            # signature result: a manifest signed by somebody else is intact but
            # not trusted, which is a different answer from "altered".
            evidence.verify(document)
            result["signature_valid"] = True
        except evidence.InvalidEvidencePackage as exc:
            result["signature_valid"] = False
            result["detail"] = str(exc)
        result["key_id"] = signature.get("key_id")
        current = evidence.current_key_id()
        result["key_matches_installation"] = None if current is None else result["key_id"] == current
    else:
        # Unsigned: the payload digest still catches an edit that forgot to fix it.
        if document.get("payload_sha256") != _sha256(evidence.canonical_bytes(payload)):
            result["detail"] = "the manifest was modified"
            result["signature_valid"] = False

    files_ok = True
    for entry in payload.get("files") or []:
        name = str(entry.get("name"))
        # The entry names a file beside the manifest; it is never joined onto a
        # path, only matched against the one report this manifest belongs to.
        expected = entry.get("sha256")
        actual: str | None
        if report_key.rsplit("/", 1)[-1] == name:
            try:
                actual = _sha256(store.get_bytes(report_key))
            except artifact_store.ArtifactNotFound:
                actual = None
        else:
            actual = None
        state = "ok" if actual == expected else ("missing" if actual is None else "modified")
        files_ok = files_ok and state == "ok"
        result["files"].append(
            {"name": name, "sha256": expected, "actual_sha256": actual, "status": state}
        )

    if (
        expected_key_id is not None
        and result["signature_valid"]
        and result["key_id"] != expected_key_id
    ):
        result["status"] = "untrusted"
        result["detail"] = f"signed by {result['key_id']}, not the expected {expected_key_id}"
    elif result["signature_valid"] is False or not files_ok:
        if any(f["status"] == "missing" for f in result["files"]) and result["signature_valid"] is not False:
            result["status"] = "missing"
            result["detail"] = result["detail"] or "the report object is no longer in the store"
        else:
            result["status"] = "tampered"
            result["detail"] = result["detail"] or "a file does not match its manifest"
    else:
        result["status"] = "valid" if result["signed"] else "unsigned"
    return result
