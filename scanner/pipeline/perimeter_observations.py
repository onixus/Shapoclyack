"""Versioned, neutral perimeter-observation receipts.

This artifact is deliberately separate from finding_evidence.json and every
vulnerability/report/tracker input. It records bounded positive observations and
per-check completion state; it is not a coverage or remediation decision engine.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "octo.perimeter_observation.v1"
FILENAME = "observation_receipt.json"
MAX_RECORDS = 10_000
MAX_FILE_BYTES = 16 * 1024 * 1024
_FAMILY = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_STATES = {"planned", "submitted", "responded", "failed", "skipped", "unknown"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _endpoint(host: str, port: int, transport: str) -> dict[str, Any]:
    if not isinstance(host, str) or len(host) > 253 or any(ord(ch) < 33 for ch in host):
        raise ValueError("invalid endpoint host")
    raw = host.strip().strip("[]")
    try:
        normalized = str(ipaddress.ip_address(raw))
    except ValueError:
        normalized = raw.rstrip(".").encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9_.-]+", normalized):
            raise ValueError("invalid endpoint host")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid endpoint port")
    if transport not in {"tcp", "udp"}:
        raise ValueError("invalid transport")
    return {"host": normalized, "port": port, "transport": transport}


_RDP_SELECTED = frozenset({"PROTOCOL_SSL", "PROTOCOL_HYBRID", "PROTOCOL_HYBRID_EX"})


def _check_rdp_outcome(outcome: dict[str, Any]) -> None:
    """Only the two shapes ``rdp_observation.parse_reply`` can decode."""
    if set(outcome) == {"result", "selected_protocol"} and outcome["result"] == "selected":
        if outcome["selected_protocol"] not in _RDP_SELECTED:
            raise ValueError("invalid RDP X.224 outcome")
    elif set(outcome) == {"result", "failure_code"} and outcome["result"] == "explicit_failure":
        code = outcome["failure_code"]
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 0xFFFFFFFF:
            raise ValueError("invalid RDP failure code")
    else:
        raise ValueError("invalid RDP X.224 outcome")


def record(*, tenant_id: str, run_id: str, family: str, implementation_sha256: str,
           endpoint: dict[str, Any], variant: str, state: str, outcome: dict[str, Any] | None,
           observed_at: str | None = None, evidence_sha256: str | None = None) -> dict[str, Any]:
    """Build a single record from trusted run scope and bounded decoded fields."""
    if (not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 128
            or not isinstance(run_id, str) or not run_id or len(run_id) > 128
            or any(ord(c) < 32 for c in tenant_id + run_id)):
        raise ValueError("explicit tenant and run context required")
    if not isinstance(family, str) or not _FAMILY.fullmatch(family):
        raise ValueError("invalid check family")
    if not isinstance(implementation_sha256, str) or not _DIGEST.fullmatch(implementation_sha256):
        raise ValueError("invalid implementation digest")
    if not isinstance(endpoint, dict):
        raise ValueError("invalid endpoint")
    subject = _endpoint(endpoint.get("host"), endpoint.get("port"), endpoint.get("transport"))
    if not isinstance(variant, str) or not variant or len(variant) > 128 or any(ord(c) < 32 for c in variant):
        raise ValueError("invalid request variant")
    if state not in _STATES:
        raise ValueError("invalid observation state")
    if observed_at is not None:
        if not isinstance(observed_at, str) or len(observed_at) > 40:
            raise ValueError("invalid timestamp")
        try:
            parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
    if outcome is not None:
        if not isinstance(outcome, dict) or len(_canonical(outcome)) > 2048:
            raise ValueError("outcome must be a bounded object")
        # This channel is for decoded protocol facts only: no arbitrary payload/string dumps.
        if any(not isinstance(k, str) or len(k) > 64 for k in outcome):
            raise ValueError("invalid outcome field")
        if any(not isinstance(v, (str, int, bool, type(None))) for v in outcome.values()):
            raise ValueError("invalid decoded outcome value")
        if any(isinstance(v, str) and len(v) > 256 for v in outcome.values()):
            raise ValueError("decoded outcome field too long")
        if family == "rdp.x224.negotiation":
            if state != "responded":
                raise ValueError("RDP decoded outcome requires responded state")
            _check_rdp_outcome(outcome)
    elif family == "rdp.x224.negotiation" and state == "responded":
        raise ValueError("RDP responded state requires a decoded outcome")
    if evidence_sha256 is not None and (not isinstance(evidence_sha256, str) or not _DIGEST.fullmatch(evidence_sha256)):
        raise ValueError("invalid evidence digest")
    if observed_at is None:
        observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    else:
        observed_at = observed_at.strip()
    core = {
        "schema": SCHEMA,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "family": family,
        "implementation_sha256": implementation_sha256,
        "subject": subject,
        "variant": variant,
        "state": state,
        "outcome": outcome,
        "observed_at": observed_at,
        "evidence_sha256": evidence_sha256,
    }
    return {**core, "observation_id": "pobs:" + _sha(core)}


def document(records: list[dict[str, Any]], *, tenant_id: str, run_id: str, omitted_targets: int = 0) -> dict[str, Any]:
    """Create deterministic additive sidecar document from validated records."""
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("invalid receipt records")
    if isinstance(omitted_targets, bool) or not isinstance(omitted_targets, int) or omitted_targets < 0:
        raise ValueError("invalid omitted target count")
    checked = []
    for item in records:
        if not isinstance(item, dict) or item.get("schema") != SCHEMA:
            raise ValueError("invalid observation record")
        if item.get("tenant_id") != tenant_id or item.get("run_id") != run_id:
            raise ValueError("receipt context mismatch")
        core = {k: v for k, v in item.items() if k != "observation_id"}
        if item.get("observation_id") != "pobs:" + _sha(core):
            raise ValueError("invalid observation identity")
        checked.append(item)
    checked.sort(key=lambda r: (r["family"], r["subject"]["host"], r["subject"]["port"], r["variant"], r["observation_id"]))
    result = {"schema": SCHEMA, "context": {"tenant_id": tenant_id, "run_id": run_id}, "records": checked}
    if omitted_targets:
        result["omitted_targets"] = omitted_targets
    return result


def write_receipt(root: Path, records: list[dict[str, Any]], *, tenant_id: str, run_id: str,
                  omitted_targets: int = 0) -> dict[str, Any]:
    """Atomically replace only observation_receipt.json under a trusted run directory."""
    base = root.resolve(strict=True)
    if not base.is_dir() or (base / FILENAME).is_symlink():
        raise ValueError("invalid run artifact directory")
    result = document(records, tenant_id=tenant_id, run_id=run_id, omitted_targets=omitted_targets)
    temp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=base,
                                         prefix=".observation-receipt-", suffix=".tmp", delete=False) as handle:
            temp = handle.name
            json.dump(result, handle, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, base / FILENAME)
    finally:
        if temp is not None:
            Path(temp).unlink(missing_ok=True)
    return result
