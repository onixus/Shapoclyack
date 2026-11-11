"""Brand-watch M2: score an HTTP observation and build the diff event.

Pure functions. No database, no network, no HTML in the payload. The scanner
observer (:mod:`scanner.brand_watch.http_observe`) fetches; this module turns
that evidence pack into a severity and a ``brand_watch.diff`` notification.

:func:`apply_http_observation` is the entry the API service can call later
without this module reaching into ``api/services/brand_watch.py``.
"""

from __future__ import annotations

from typing import Any

from scanner.brand_watch.similarity import score_observation

EVENT_TYPE = "brand_watch.diff"

#: Plan states. ``confirmed`` may appear as a previous state an analyst set;
#: this module never writes it as the result of an HTTP observation.
STATES = frozenset({
    "unregistered",
    "registered",
    "resolving",
    "http_live",
    "parked",
    "suspicious",
    "confirmed",
    "disappeared",
})
SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})


def score_http_observation(observation: dict[str, Any]) -> dict[str, Any]:
    """Severity ladder over an evidence pack. Does not re-fetch."""
    signals = {
        "brand": observation.get("brand") or "",
        "registered": bool(observation.get("registered")),
        "parked": bool(observation.get("parked")),
        "live": bool(observation.get("live")),
        "has_site": bool(observation.get("has_site")),
        "mx_present": bool(observation.get("mx_present")),
        "password_form": bool(observation.get("password_form")),
        "brand_in_title": bool(observation.get("brand_in_title")),
        "brand_in_cert": bool(observation.get("brand_in_cert")),
        "favicon_match": bool(observation.get("favicon_match")),
        "young_domain": bool(observation.get("young_domain")),
        "young_cert": bool(observation.get("young_cert")),
        "empty_spa": bool(observation.get("empty_spa")),
        "shingle_overlap": observation.get("shingle_overlap") or 0.0,
        "skip_reason": observation.get("skip_reason"),
    }
    scored = score_observation(signals)
    return {
        "name": observation.get("name") or "",
        "severity": scored["severity"],
        "reasons": list(scored["reasons"]),
        "state": _state(scored["state"], observation),
        "skipped": scored["skipped"],
        "skip_reason": scored["skip_reason"],
    }


def _state(scored_state: str, observation: dict[str, Any]) -> str:
    if scored_state in STATES and scored_state != "confirmed":
        return scored_state
    raw = observation.get("state")
    if isinstance(raw, str) and raw in STATES and raw != "confirmed":
        return raw
    return "unregistered"


def evidence_summary(observation: dict[str, Any]) -> dict[str, Any]:
    """The fields safe to keep. Raw HTML is dropped if a caller left it in."""
    cert = observation.get("cert") if isinstance(observation.get("cert"), dict) else {}
    summary = {
        "name": observation.get("name") or "",
        "address": observation.get("address") or "",
        "dns": _dns_summary(observation),
        "rdap_created": observation.get("rdap_created"),
        "cert": {
            "subject_cn": cert.get("subject_cn") or "",
            "san": list(cert.get("san") or []),
            "not_before": cert.get("not_before"),
        },
        "body_sha256": observation.get("body_sha256"),
        "favicon_sha256": observation.get("favicon_sha256"),
        "title": _clip(observation.get("title") or "", 200),
        "excerpt": _clip(observation.get("excerpt") or "", 200),
        "status": observation.get("status"),
        "redirect_host": observation.get("redirect_host"),
        "parked": bool(observation.get("parked")),
        "parking_marker": observation.get("parking_marker"),
    }
    _drop_html(summary)
    return summary


def _dns_summary(observation: dict[str, Any]) -> dict[str, Any]:
    dns = observation.get("dns")
    if isinstance(dns, dict):
        return {
            "addresses": [str(item) for item in dns.get("addresses") or ()],
            "mx": bool(dns.get("mx", observation.get("mx_present"))),
            "registered": bool(dns.get("registered", observation.get("registered"))),
        }
    return {
        "addresses": [observation["address"]] if observation.get("address") else [],
        "mx": bool(observation.get("mx_present")),
        "registered": bool(observation.get("registered")),
    }


def _clip(value: str, limit: int) -> str:
    text = " ".join(str(value).split())
    if "<" in text or ">" in text:
        # A title that still contains markup was not stripped. Drop it rather
        # than forward a fragment of the page.
        return ""
    return text[:limit]


def _drop_html(summary: dict[str, Any]) -> None:
    for key in ("html", "body", "raw_html", "page", "pem", "peer_cert"):
        summary.pop(key, None)


def build_diff_event(
    *,
    name: str,
    from_state: str | None,
    to_state: str,
    severity: str,
    reasons: list[str],
) -> dict[str, Any]:
    """A ``brand_watch.diff`` event. The payload is the diff and nothing else.

    This is not a finished-scan notification. ``reasons`` are short tokens
    (``password_form``, ``young_cert``), never page text.
    """
    clean_reasons = [str(item) for item in reasons if isinstance(item, str) and "<" not in item]
    return {
        "type": EVENT_TYPE,
        "payload": {
            "name": name,
            "from_state": _coerce_state(from_state),
            "to_state": _coerce_state(to_state),
            "severity": severity if severity in SEVERITIES else "informational",
            "reasons": clean_reasons,
        },
    }


def _coerce_state(state: str | None) -> str | None:
    if state is None:
        return None
    if state in STATES:
        return state
    return "unregistered"


def apply_http_observation(
    observation: dict[str, Any],
    *,
    previous_state: str | None = None,
) -> dict[str, Any]:
    """Score one evidence pack and build the diff event for it.

    ``observation`` is the dict :func:`scanner.brand_watch.http_observe.observe_http`
    returns. The result carries the score, a trimmed evidence summary, and
    the notification event. No I/O.
    """
    scored = score_http_observation(observation)
    event = build_diff_event(
        name=scored["name"] or str(observation.get("name") or ""),
        from_state=previous_state,
        to_state=scored["state"],
        severity=scored["severity"],
        reasons=scored["reasons"],
    )
    return {
        "score": scored,
        "evidence": evidence_summary(observation),
        "event": event,
    }
