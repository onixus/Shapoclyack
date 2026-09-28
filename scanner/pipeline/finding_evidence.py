"""Versioned, read-only evidence projection; not a tracker identity migration.

This module performs no I/O, DNS resolution, risk scoring or lifecycle updates.
An unknown protocol, authority or object is not a wildcard for a known one.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

OBSERVATION_SCHEMA = "octo.finding_observation.v1"
EVIDENCE_SCHEMA = "octo.finding_evidence.v1"
PREVIEW_LIMIT = 512
LABEL_LIMIT = 256
MAX_ARTIFACT_REFS = 8
_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_SECRET_LINE = re.compile(r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*")
_SECRET_FIELD = re.compile(
    r'''(?i)["']?\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|session[_-]?id)["']?\s*[:=]\s*'''
)
_BARE_SECRET_END = re.compile(r"[\s,;&]")
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _redact_secret_values(text: str) -> str:
    """Consume complete quoted values, including escaped quotes/backslashes.

    Scan each value once rather than backtracking over an untrusted long string.
    An unterminated quote or an ambiguous suffix hides the rest of the preview;
    truncating or falling back to a bare token there could reveal a secret tail.
    """
    parts: list[str] = []
    cursor = 0
    while match := _SECRET_FIELD.search(text, cursor):
        start = end = match.end()
        if start < len(text) and text[start] in {"\"", "'"}:
            quote = text[start]
            end += 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == quote:
                    end += 1
                    # A quote immediately followed by value text is ambiguous.
                    if end < len(text) and not (text[end].isspace() or text[end] in ",;}&]"):
                        end = len(text)
                    break
                else:
                    end += 1
            end = min(end, len(text))
        elif start < len(text) and text[start] in "{[":
            # Structured secret values have no safe scalar boundary here.
            end = len(text)
        else:
            delimiter = _BARE_SECRET_END.search(text, start)
            end = delimiter.start() if delimiter else len(text)
        parts.extend((text[cursor:start], "[REDACTED]"))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def safe_text(value: Any, limit: int = PREVIEW_LIMIT) -> str:
    """Redact known credential fields before truncation; never pass HTTP bodies.

    This is not a general secret detector. Adapters use an allowlist of fields;
    arbitrary requests, responses and extracted values are never projected.
    """
    text = value if isinstance(value, str) else ""
    text = _SECRET_LINE.sub(lambda m: m.group(1) + ": [REDACTED]", text)
    text = _redact_secret_values(text)
    # URLs in free text may contain credentials anywhere, including the path.
    text = _URL.sub("[URL omitted; see source artifact]", text)
    text = "".join(c for c in text if c >= " " or c in "\n\t")
    return text[:limit]


def _host(value: str) -> str:
    value = value.strip().strip("[]")
    if not value or len(value) > 253 or any(c.isspace() for c in value):
        raise ValueError("invalid endpoint host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9_.-]+", value):
            raise ValueError("invalid endpoint host")
        return value


def _port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not re.fullmatch(r"\d{1,5}", str(value)):
        raise ValueError("invalid endpoint port")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("invalid endpoint port")
    return port


def subject(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a declared subject without inferring a DNS/IP relationship.

    HTTP matched-at identifies the observed object, not a reverse-DNS name.
    Query values and potentially sensitive paths stay in the source artifact;
    a digest of the exact path/query preserves object separation. Percent escapes,
    path case, query order and duplicate query parameters remain significant.
    """
    host = str(row.get("host") or row.get("ip") or "")
    matched = str(row.get("matched_at") or "")
    url = matched if matched.lower().startswith(("http://", "https://")) else host
    protocol = str(row.get("protocol") or "unknown").lower()
    if protocol in {"syn", "tcpsyn"}:
        protocol = "tcp"
    if protocol not in {"tcp", "udp", "unknown"}:
        raise ValueError("unsupported transport")
    port = _port(row.get("port"))
    authority = scheme = None
    object_id = None
    if url.lower().startswith(("http://", "https://")):
        if any(ord(c) < 32 for c in url):
            raise ValueError("control character in URL")
        parsed = urlsplit(url)
        name = _host(parsed.hostname or "")
        url_port = parsed.port
        if url_port is None:
            url_port = 443 if parsed.scheme.lower() == "https" else 80
        if port is not None and port != url_port:
            raise ValueError("conflicting endpoint ports")
        if protocol == "udp":
            raise ValueError("conflicting HTTP transport")
        port, protocol, scheme = _port(url_port), "tcp", parsed.scheme.lower()
        authority = f"[{name}]:{port}" if ":" in name else f"{name}:{port}"
        object_id = "url:" + digest([scheme, authority, parsed.path or "/", parsed.query])
        host = name
    else:
        try:
            host = _host(host)
        except ValueError:
            # host:port or [IPv6]:port; a bare IPv6 was handled above.
            parsed = urlsplit("//" + host)
            if parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
                raise ValueError("invalid endpoint") from None
            embedded_port = _port(parsed.port)
            if embedded_port is None or (port is not None and embedded_port != port):
                raise ValueError("conflicting endpoint ports") from None
            host, port = _host(parsed.hostname or ""), embedded_port
    explicit_object = row.get("affected_object")
    if isinstance(explicit_object, str) and explicit_object:
        # Preserve both identities: an object qualifier must not erase the URL,
        # and HTTP must not discard an explicit affected object. Keep the old
        # URL-only and non-HTTP hashes when no new distinction is needed.
        object_id = ("url-object:" + digest([object_id, explicit_object])
                     if object_id is not None else "object:" + digest(explicit_object))
    # SNI is explicit evidence, not inferred from a TLS service name or an IP.
    sni = _host(row["sni"]) if isinstance(row.get("sni"), str) and row["sni"] else None
    return {"host": host, "port": port, "protocol": protocol,
            "scheme": scheme, "authority": authority, "sni": sni, "object_id": object_id}


def timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None



def _reference(value: dict[str, Any]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "locator"}:
        raise ValueError("invalid artifact reference")
    path, sha, locator = value["path"], value["sha256"], value["locator"]
    if not all(isinstance(v, str) for v in (path, sha, locator)):
        raise ValueError("invalid artifact reference")
    if (not path or len(path) > 1024 or "\\" in path or ":" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or not re.fullmatch(r"[0-9a-f]{64}", sha)
            or not locator or len(locator) > 128
            or any(ord(c) < 32 for c in path + locator)):
        raise ValueError("invalid artifact reference")
    return {"path": path, "sha256": sha, "locator": locator}


def observation(
    row: dict[str, Any], *, tenant_id: str, run_id: str, source: str,
    artifact_ref: dict[str, Any],
) -> dict[str, Any]:
    """Create one positive observation; caller supplies trusted tenant/run scope.

    Source names are labels, never proof of exploitation. Negative evidence and
    automatic verification/closure are deliberately outside this contract.
    """
    if (not tenant_id or not run_id or len(tenant_id) > 128 or len(run_id) > 128
            or any(ord(c) < 32 for c in tenant_id + run_id)):
        raise ValueError("explicit tenant and run context required")
    cve = str(row.get("cve") or "").upper()
    if cve and not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE identifier")
    rule = safe_text(row.get("rule_id"), LABEL_LIMIT)
    title = safe_text(row.get("title"), LABEL_LIMIT)
    if not cve and not rule:
        raise ValueError("missing finding identifier")
    confidence = row.get("confidence")
    if (isinstance(confidence, bool) or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence) or not 0 <= confidence <= 100):
        confidence = None
    kind = row.get("evidence_kind")
    if kind not in {"version_match", "keyword_hypothesis", "exposure", "tls_observation",
                    "template_match", "nse_report"}:
        kind = "unclassified"
    severity = str(row.get("severity") or "unknown").lower()
    if severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
        severity = "unknown"
    data = {
        "schema": OBSERVATION_SCHEMA, "tenant_id": tenant_id, "run_id": run_id,
        "source": source, "engine_version": safe_text(row.get("engine_version"), 80) or None,
        "ruleset_version": safe_text(row.get("ruleset_version"), 80) or None,
        "rule_id": rule or None, "rule_digest": digest(str(row.get("rule_id") or "")), "matcher": safe_text(row.get("matcher"), LABEL_LIMIT) or None,
        "observed_at": timestamp(row.get("observed_at")), "subject": subject(row),
        "cve": cve or None, "title": title, "evidence_kind": kind, "confidence": confidence,
        "severity": severity, "requires_confirmation": row.get("requires_confirmation") is not False,
        "preview": safe_text(row.get("preview", row.get("evidence"))),
    }
    # Hash only allowlisted evidence, never copy request/response/extracted bodies.
    data["evidence_digest"] = digest(row.get("evidence_material", [str(row.get("evidence") or ""), str(row.get("matcher") or "")]))
    data["observation_id"] = "obs:" + digest(data)
    data["artifact_refs"] = [_reference(artifact_ref)]
    return data


def aggregate(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic union; keep conflicting and older observations, not a winner.

    This projection has its own ID namespace. It cannot be used as finding_key
    or as evidence that a missing/failed/skipped check remediated a vulnerability.
    """
    groups: dict[str, dict[str, Any]] = {}
    for item in observations:
        # Validate the hash rather than accepting mutated or cross-version rows.
        data = {key: value for key, value in item.items() if key not in {"observation_id", "artifact_refs", "artifact_refs_truncated"}}
        if data.get("schema") != OBSERVATION_SCHEMA or item.get("observation_id") != "obs:" + digest(data):
            raise ValueError("invalid observation contract")
        identity = {"tenant_id": item["tenant_id"], "subject": item["subject"],
                    "issue": item["cve"] or [item["source"], item["rule_digest"]]}
        key = "evidence:" + digest(identity)
        group = groups.setdefault(key, {"evidence_id": key, "identity": identity, "observations": {}})
        seen = group["observations"]
        oid = item["observation_id"]
        was_truncated = item.get("artifact_refs_truncated", False)
        if not isinstance(was_truncated, bool):
            raise ValueError("invalid artifact reference completeness")
        if oid not in seen:
            seen[oid] = {**item, "artifact_refs": {}, "artifact_refs_truncated": False}
        # Lost references cannot become complete merely by reloading a sidecar.
        # Union the flag too, including when a complete copy arrived first.
        seen[oid]["artifact_refs_truncated"] |= was_truncated
        for ref in item["artifact_refs"]:
            ref = _reference(ref)
            seen[oid]["artifact_refs"][canonical_json(ref)] = dict(ref)
    findings = []
    for key in sorted(groups):
        group = groups[key]
        rows = []
        for oid, item in sorted(group["observations"].items()):
            refs = [ref for _, ref in sorted(item["artifact_refs"].items())]
            rows.append({**item, "artifact_refs": refs[:MAX_ARTIFACT_REFS],
                         "artifact_refs_truncated": item["artifact_refs_truncated"] or len(refs) > MAX_ARTIFACT_REFS})
        dated = [item["observed_at"] for item in rows if item["observed_at"]]
        latest = max(dated, default=None)
        by_field = defaultdict(set)
        for item in rows:
            for field in ("severity", "confidence", "requires_confirmation", "evidence_kind"):
                if item[field] is not None:
                    by_field[field].add(canonical_json(item[field]))
        findings.append({**group, "observations": rows, "observation_count": len(rows),
                         "sources": sorted({item["source"] for item in rows}),
                         "assessment": {
                             "policy": "preserve-observations-no-lifecycle-decision-v1",
                             "latest_observed_at": latest,
                             "latest_observation_ids": [item["observation_id"] for item in rows
                                                        if latest and item["observed_at"] == latest],
                             "undated_observation_ids": [item["observation_id"] for item in rows
                                                         if not item["observed_at"]],
                             "differing_fields": sorted(field for field, values in by_field.items() if len(values) > 1),
                             "machine_verified": False,
                         }})
    return {"schema": EVIDENCE_SCHEMA, "mode": "shadow", "coverage": "unknown",
            "finding_count": len(findings), "observation_count": sum(f["observation_count"] for f in findings),
            "findings": findings}
