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
import os
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
        # A key that is set but unusable (wrong length, bad base64) is an
        # operator mistake that otherwise reads as "signing is off": say so loudly.
        if os.environ.get(evidence.SIGNING_KEY_ENV, "").strip():
            LOG.warning("Report manifest written UNSIGNED, the signing key is unusable: %s", exc)
        else:
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
    report_id: str,
    tenant_id: str,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    """Re-check a stored report against its manifest.

    ``status`` is one of

    * ``valid`` -- signed by **this installation's** key, signature good, every
      file matches, and the manifest is about this very report;
    * ``valid_with_supplied_key`` -- the same, but the signer is a key other than
      the installation's current one that the *caller* named in
      ``expected_key_id`` (an old key after a rotation). Deliberately a
      different word: it proves the manifest is intact and signed by the key the
      caller trusts, not that this installation signed it;
    * ``unsigned`` -- hashes match but nothing vouches for the manifest;
    * ``untrusted`` -- intact, but signed by a key nobody here vouches for: the
      key embedded in the manifest is the attacker's to choose, so a signature
      by an unpinned key proves nothing, and with no key configured and none
      supplied there is nothing to pin;
    * ``tampered`` -- a file, the manifest or its signature changed, the
      manifest lists no files, or it names a different report or tenant. Beats
      ``untrusted``: the louder signal wins;
    * ``missing`` -- no manifest, or the report object is gone.

    The files are re-read from the store rather than trusted from the row: that
    is the point.
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

    problems: list[str] = []
    if payload.get("report_id") != report_id or payload.get("tenant_id") != tenant_id:
        problems.append("the manifest names a different report or tenant")
    entries = payload.get("files")
    if not isinstance(entries, list) or not entries:
        problems.append("the manifest lists no files")
        entries = []

    signature = document.get("signature")
    if signature:
        result["signed"] = True
        try:
            evidence.verify(document, expected_kind=KIND)
            result["signature_valid"] = True
        except evidence.InvalidEvidencePackage as exc:
            result["signature_valid"] = False
            problems.append(str(exc))
        result["key_id"] = signature.get("key_id") if isinstance(signature, dict) else None
    else:
        # Unsigned: the payload digest still catches an edit that forgot to fix it.
        if document.get("payload_sha256") != _sha256(evidence.canonical_bytes(payload)):
            result["signature_valid"] = False
            problems.append("the manifest was modified")
    current = evidence.current_key_id()
    if result["key_id"] is not None and current is not None:
        result["key_matches_installation"] = result["key_id"] == current

    object_missing = False
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append("the manifest has a malformed file entry")
            continue
        name = str(entry.get("name"))
        expected = entry.get("sha256")
        actual: str | None = None
        # The entry names a file beside the manifest; it is never joined onto a
        # path, only matched against the one report this manifest belongs to.
        if report_key.rsplit("/", 1)[-1] == name:
            try:
                actual = _sha256(store.get_bytes(report_key))
            except artifact_store.ArtifactNotFound:
                actual = None
        state = "ok" if actual == expected else ("missing" if actual is None else "modified")
        object_missing = object_missing or state == "missing"
        if state == "modified":
            problems.append("a file does not match its manifest")
        result["files"].append(
            {"name": name, "sha256": expected, "actual_sha256": actual, "status": state}
        )

    if problems or result["signature_valid"] is False:
        result["status"] = "tampered"
        result["detail"] = "; ".join(dict.fromkeys(problems)) or "the manifest does not verify"
    elif object_missing:
        result["status"] = "missing"
        result["detail"] = "the report object is no longer in the store"
    elif not result["signed"]:
        result["status"] = "unsigned"
    elif current is not None and result["key_id"] == current:
        result["status"] = "valid"
    elif expected_key_id is not None and result["key_id"] == expected_key_id:
        result["status"] = "valid_with_supplied_key"
    else:
        result["status"] = "untrusted"
        result["detail"] = (
            "signed by a key this installation does not sign with"
            if current is not None
            else "no signing key is configured here to vouch for the signature"
        )
        if expected_key_id is not None:
            result["detail"] += f"; it is not the supplied {expected_key_id}"
    return result
