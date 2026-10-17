"""Integrity checks on a sensor's run archive: artifact schemas and signature (#366).

``results_ingest`` only decides whether the *container* is safe to open. Two
questions it does not ask are answered here, before anything is extracted:

1. **Is what the sensor wrote shaped like what the scanner writes?** The main
   run artifacts are checked against the JSON schemas below. A file that is not
   valid JSON, or lacks a field the API reads, is refused with the file and the
   path of the offending value in the reason. Compatibility rule: *unknown
   properties are always allowed* (a newer sensor may add fields; an older API
   must not choke on them) and *a missing optional file is fine* (a failed or
   cancelled run legitimately wrote only part of the tree). What is refused is
   a present file that is malformed or misses a required property, or whose
   ``run_meta.json`` names another run than the upload. (A run with no
   ``summary.json`` is accepted: the API already shows it as "no summary".)
2. **Did the sensor that owns this job produce these exact bytes?** The sensor
   signs a canonical message (see :func:`signing_message`) with the ed25519 key
   whose public half it registered; the API pins that key per agent (first
   registration wins, a different key is refused until an operator resets it)
   and verifies here. ``OCTO_REQUIRE_SIGNED_RESULTS`` decides what an upload with
   *no* signature means; a signature that is present but wrong is always
   refused, because that is either tampering or a sensor whose key was
   regenerated, and both want an operator's eyes.

The schema subset is evaluated by a small validator in this module instead of
the ``jsonschema`` package: the schemas are written in JSON Schema syntax (so
they can be exported unchanged), but the API image has no other use for the
dependency and every new wheel is a lockfile and a supply-chain entry.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import logging
import tarfile
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from api.services import metrics as metrics_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.ingest")

SIGNATURE_ALGORITHM = "ed25519"
#: Domain separator: a signature made for a run archive can never be a valid
#: signature over anything else this key might one day sign.
SIGNING_DOMAIN = "shapoclyack-run-archive-v1"

#: Largest single artifact the validator will parse. The archive as a whole is
#: bounded by ``results_ingest.MAX_UNCOMPRESSED_BYTES``; this keeps one huge
#: member from being decoded into a Python object tree several times its size.
MAX_VALIDATED_MEMBER_BYTES = 256 * 1024 * 1024

SCHEMA_MODES = ("enforce", "warn", "off")


class ResultsRejected(ValueError):
    """An upload refused on integrity grounds; ``code`` names the check."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


# --------------------------------------------------------------------------
# Schemas (JSON Schema subset: type, required, properties, items, enum,
# minimum, minLength, minItems). additionalProperties is never restricted.
# --------------------------------------------------------------------------

_HOST_ROWS = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["host"],
        "properties": {"host": {"type": "string", "minLength": 1}},
    },
}

ARTIFACT_SCHEMAS: dict[str, dict[str, Any]] = {
    "run_meta.json": {
        "type": "object",
        "required": ["run_id"],
        "properties": {
            "run_id": {"type": "string", "minLength": 1},
            "profile": {"type": "string"},
            "started_at": {"type": "string"},
        },
    },
    "summary.json": {
        "type": "object",
        # Nothing required: the API reads every key with a default (an older
        # scanner has fewer of them) and shows "no summary" for a missing file.
        # What is checked is the type of the ones that are there.
        "properties": {
            "total_targets": {"type": "integer", "minimum": 0},
            "alive_hosts": {"type": "integer", "minimum": 0},
            "potential_vulnerabilities": {"type": "integer", "minimum": 0},
            "vulnerabilities_by_severity": {"type": "object"},
        },
    },
    "vulnerabilities.json": _HOST_ROWS,
    "findings.json": _HOST_ROWS,
    "alive_hosts.json": _HOST_ROWS,
    "hosts_without_open_ports.json": _HOST_ROWS,
    "os_findings.json": _HOST_ROWS,
    "script_findings.json": _HOST_ROWS,
}

def _type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    # bool is an int subclass in Python and a different type in JSON.
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _validate(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    expected = schema.get("type")
    if expected is not None:
        kinds = [expected] if isinstance(expected, str) else list(expected)
        if not any(_type_ok(value, kind) for kind in kinds):
            errors.append(f"{path}: expected {'/'.join(kinds)}, got {type(value).__name__}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: not one of {schema['enum']}")
    if isinstance(value, str) and len(value) < int(schema.get("minLength", 0)):
        errors.append(f"{path}: must not be empty")
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and "minimum" in schema
        and value < schema["minimum"]
    ):
        errors.append(f"{path}: below minimum {schema['minimum']}")
    if isinstance(value, dict):
        for name in schema.get("required", ()):
            if name not in value:
                errors.append(f"{path}: missing required property '{name}'")
        for name, sub in (schema.get("properties") or {}).items():
            if name in value:
                _validate(value[name], sub, f"{path}.{name}", errors)
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            errors.append(f"{path}: needs at least {schema['minItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                _validate(item, item_schema, f"{path}[{index}]", errors)
                if len(errors) >= 5:
                    return


def validate_document(name: str, document: Any) -> list[str]:
    """Schema errors for one parsed artifact (empty list = valid)."""
    schema = ARTIFACT_SCHEMAS.get(name)
    if schema is None:
        return []
    errors: list[str] = []
    _validate(document, schema, name, errors)
    return errors[:5]


def schema_mode(settings: Settings) -> str:
    mode = str(getattr(settings, "result_schema_mode", "enforce") or "enforce").lower()
    return mode if mode in SCHEMA_MODES else "enforce"


def validate_artifacts(
    archive_bytes: bytes,
    *,
    run_id: str | None,
    exit_code: int = 0,
    cancelled: bool = False,
) -> None:
    """Parse the known artifacts straight out of the tar and check them.

    Raises :class:`ResultsRejected` (code ``schema``) naming the first problem
    found. Reads members from the in-memory archive; nothing touches the disk.
    """
    seen: dict[str, Any] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            for member in tf.getmembers():
                name = member.name.replace("\\", "/")
                if name.startswith("./"):
                    name = name[2:]
                # Only top-level files are the run's own artifacts; a nested
                # summary.json (a sub-report) is not what the API reads.
                if "/" in name or name not in ARTIFACT_SCHEMAS or not member.isfile():
                    continue
                if member.size > MAX_VALIDATED_MEMBER_BYTES:
                    raise ResultsRejected(
                        "schema", f"{name}: larger than {MAX_VALIDATED_MEMBER_BYTES} bytes"
                    )
                handle = tf.extractfile(member)
                raw = handle.read() if handle is not None else b""
                try:
                    document = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise ResultsRejected("schema", f"{name}: not valid JSON ({exc})") from exc
                errors = validate_document(name, document)
                if errors:
                    raise ResultsRejected("schema", "; ".join(errors))
                seen[name] = document
    except tarfile.TarError:
        # A broken container is the extractor's to refuse (IngestError, which
        # leaves the job claimable for a retry): it is a transport fault more
        # often than a verdict on the sensor, and extraction reports it with
        # the wording operators already know.
        return

    meta = seen.get("run_meta.json")
    if run_id and isinstance(meta, dict) and str(meta.get("run_id")) != str(run_id):
        # Binds the content to the job: an archive of another run, replayed
        # under this job's id, carries its own run id in its metadata.
        raise ResultsRejected(
            "schema",
            f"run_meta.json is for run '{meta.get('run_id')}', the upload is for '{run_id}'",
        )


# --------------------------------------------------------------------------
# Signature
# --------------------------------------------------------------------------


def archive_digest(archive_bytes: bytes) -> str:
    return hashlib.sha256(archive_bytes).hexdigest()


def signing_message(
    *,
    agent_id: str,
    job_id: str,
    run_id: str | None,
    exit_code: int,
    attempt: int | None,
    archive_sha256: str,
) -> bytes:
    """The exact bytes a sensor signs and the API verifies.

    Identity and context are inside the message, not beside it: the signature
    is worthless to anyone who would move the archive to another sensor
    (``agent_id``), another job or run (``job_id``, ``run_id``), another attempt
    of the same job (``attempt``) or who would flip the reported outcome
    (``exit_code``). ``agent/result_signing.py`` builds the same string; a test
    pins the two to one vector.
    """
    return "\n".join(
        [
            SIGNING_DOMAIN,
            f"agent={agent_id}",
            f"job={job_id}",
            f"run={run_id or ''}",
            f"exit={int(exit_code)}",
            f"attempt={'' if attempt is None else int(attempt)}",
            f"sha256={archive_sha256}",
        ]
    ).encode("utf-8")


def parse_public_key(value: str) -> bytes:
    """Raw 32-byte ed25519 public key from its base64 form, or ``ValueError``."""
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("result signing key is not valid base64") from exc
    if len(raw) != 32:
        raise ValueError("result signing key must be a raw 32-byte ed25519 public key")
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ValueError("result signing key is not a valid ed25519 public key") from exc
    return raw


def key_fingerprint(public_key_b64: str) -> str:
    """Short stable id of a public key (first 16 hex of sha256 of the raw key)."""
    return hashlib.sha256(parse_public_key(public_key_b64)).hexdigest()[:16]


@dataclass(frozen=True)
class SignatureResult:
    #: ``verified`` | ``unsigned`` | ``unverifiable`` (signed, but no key pinned)
    outcome: str
    detail: str = ""


def verify_signature(
    settings: Settings,
    *,
    pinned_key_b64: str | None,
    signature_b64: str | None,
    key_id: str | None,
    agent_id: str,
    job_id: str,
    run_id: str | None,
    exit_code: int,
    attempt: int | None,
    archive_bytes: bytes,
) -> SignatureResult:
    """Check the upload's signature against the key pinned for ``agent_id``.

    Returns the outcome for the caller to count and audit; raises
    :class:`ResultsRejected` (code ``signature``) when the upload must be
    refused: a wrong signature always, a missing one or a missing pinned key
    only when ``require_signed_results`` is on.
    """
    required = bool(getattr(settings, "require_signed_results", False))
    if not signature_b64:
        if required:
            raise ResultsRejected(
                "signature",
                "unsigned results are refused (OCTO_REQUIRE_SIGNED_RESULTS is on); "
                "upgrade the sensor so it signs its archives",
            )
        return SignatureResult("unsigned", "the upload carried no signature")
    if not pinned_key_b64:
        if required:
            raise ResultsRejected(
                "signature",
                "the upload is signed but no result signing key is registered for "
                "this sensor; it must register its public key first",
            )
        return SignatureResult("unverifiable", "no result signing key is registered")
    pinned_id = key_fingerprint(pinned_key_b64)
    if key_id and key_id != pinned_id:
        raise ResultsRejected(
            "signature",
            f"signed with key {key_id}, but the key pinned for this sensor is {pinned_id}; "
            "an operator must reset the sensor's result key after a reinstall",
        )
    try:
        signature = base64.b64decode(signature_b64.strip(), validate=True)
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(pinned_key_b64))
        public.verify(
            signature,
            signing_message(
                agent_id=agent_id,
                job_id=job_id,
                run_id=run_id,
                exit_code=exit_code,
                attempt=attempt,
                archive_sha256=archive_digest(archive_bytes),
            ),
        )
    except (InvalidSignature, binascii.Error, ValueError) as exc:
        raise ResultsRejected(
            "signature", "the archive signature does not verify against the pinned key"
        ) from exc
    return SignatureResult("verified")


def count(check: str, outcome: str) -> None:
    metrics_service.RESULT_INTEGRITY_TOTAL.labels(check=check, outcome=outcome).inc()
