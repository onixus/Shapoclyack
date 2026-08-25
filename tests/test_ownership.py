"""Domain ownership via RDAP (org_profile M1, #182)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.pipeline import safe_http
from scanner.pipeline.config_schema import OwnershipConfig
from scanner.pipeline.ownership import (
    _get_json,
    _parse_rdap_domain,
    _rdap_urls,
    resolve_ownership,
)

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.example/v1/"]],
        [["dev"], ["http://insecure.example/", "https://rdap.google.example/rdap/"]],
    ]
}

PUBLIC_DOMAIN = {
    "ldhName": "example.com",
    "status": ["client transfer prohibited"],
    "secureDNS": {"delegationSigned": True},
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2028-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:44Z"},
    ],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET."}, {"ldhName": "b.iana-servers.net"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Registrar"]]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Abuse Desk"],
                            ["email", {}, "text", "abuse@registrar.example"],
                            ["tel", {}, "text", "+1.5555550100"],
                        ],
                    ],
                }
            ],
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["fn", {}, "text", "Jane Doe"],
                    ["org", {}, "text", "Example Holding LLC"],
                    ["adr", {}, "text", ["", "", "1 Example Way", "Springfield", "", "", "US"]],
                    ["tel", {}, "text", "+1.5555550111"],
                ],
            ],
        },
    ],
}

NATURAL_PERSON_DOMAIN = {
    "ldhName": "private.example",
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["kind", {}, "text", "individual"],
                    ["fn", {}, "text", "Ivan Petrov"],
                    ["adr", {}, "text", ["", "", "12 Lenina St", "Tver", "", "", "RU"]],
                    ["tel", {}, "text", "+7.9995550122"],
                ],
            ],
        }
    ],
}

# Same thing without the explicit kind -- the common registry shape, and the
# one where "is this a company or a person" cannot be answered from the data.
AMBIGUOUS_REGISTRANT_DOMAIN = {
    "ldhName": "ambiguous.example",
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Ivan Petrov"]]],
        }
    ],
}

REDACTED_DOMAIN = {
    "ldhName": "masked.com",
    "remarks": [{"title": "REDACTED FOR PRIVACY", "description": ["Some fields are not public."]}],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]],
        }
    ],
}


def _config(**overrides) -> OwnershipConfig:
    return OwnershipConfig(**{"enabled": True, **overrides})


def _patch_lookups(monkeypatch, payloads: dict[str, dict | None]) -> list[str]:
    """Answer the bootstrap fetch from BOOTSTRAP and each RDAP URL from ``payloads``."""
    requested: list[str] = []

    def _fake_get_json(url: str, timeout: float, max_retries: int = 2):
        requested.append(url)
        if url.endswith("/rdap/dns.json"):
            return BOOTSTRAP
        domain = url.rsplit("/", 1)[-1]
        return payloads.get(domain)

    monkeypatch.setattr("scanner.pipeline.ownership._get_json", _fake_get_json)
    return requested


def test_ownership_disabled(tmp_path: Path):
    result = resolve_ownership(
        ["example.com"], OwnershipConfig(enabled=False), tmp_path, tmp_path / "state"
    )
    assert result["skipped_reason"] == "ownership.disabled"
    assert (tmp_path / "ownership.json").exists()


def test_ownership_no_domains(tmp_path: Path):
    result = resolve_ownership([], _config(), tmp_path, tmp_path / "state")
    assert result["skipped_reason"] == "no_domains"
    assert result["domains"] == {}


def test_ownership_records_public_registrant(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"example.com": PUBLIC_DOMAIN})

    result = resolve_ownership(["example.com"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["example.com"]
    assert record["status"] == "ok"
    assert record["org_name"] == "Example Holding LLC"
    assert record["registrar"] == "RESERVED-Registrar"
    assert record["abuse_email"] == "abuse@registrar.example"
    assert record["registrant_status"] == "public"
    assert record["created"] == "1995-08-14T04:00:00Z"
    assert record["expires"] == "2028-08-13T04:00:00Z"
    assert record["dnssec"] is True
    assert record["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert result["truncated"] is False

    saved = json.loads((tmp_path / "ownership.json").read_text(encoding="utf-8"))
    assert saved["identifiers"][0] == {
        "kind": "org_name",
        "value": "Example Holding LLC",
        "source": "rdap_domain",
        "domain": "example.com",
        "confidence": 0.9,
    }
    lines = (tmp_path / "ownership_findings.txt").read_text(encoding="utf-8").splitlines()
    assert lines == ["example.com:ok:registrant=public:registrar=RESERVED-Registrar"]


@pytest.mark.parametrize(
    ("domain", "payload", "person", "address", "phone"),
    [
        # Registrant carries both org and fn: the fn is a contact person.
        ("example.com", PUBLIC_DOMAIN, "Jane Doe", "1 Example Way", "5555550111"),
        # Registrant is a private person: fn is the only name there is, and it
        # is the one path through which a natural-person name could reach disk.
        ("private.example", NATURAL_PERSON_DOMAIN, "Ivan Petrov", "12 Lenina St", "9995550122"),
    ],
)
def test_ownership_never_persists_the_raw_contact_block(
    tmp_path: Path, monkeypatch, domain, payload, person, address, phone
):
    _patch_lookups(monkeypatch, {domain: payload})

    resolve_ownership([domain], _config(), tmp_path, tmp_path / "state")

    raw = (tmp_path / "ownership.json").read_text(encoding="utf-8")
    # Natural-person name, postal address and phone numbers are parsed in
    # memory and dropped -- none of them may reach disk.
    assert person not in raw
    assert address not in raw
    assert phone not in raw
    assert "vcardArray" not in raw
    assert "entities" not in raw


def test_ownership_does_not_promote_a_private_person_to_org_name(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"private.example": NATURAL_PERSON_DOMAIN})

    result = resolve_ownership(["private.example"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["private.example"]
    assert record["org_name"] is None
    # "registered by a human" is its own answer -- not "public", which would
    # claim we identified an organization, and not "unknown".
    assert record["registrant_status"] == "natural_person"
    assert result["identifiers"] == []


def test_ownership_will_not_guess_an_org_from_a_bare_fn(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"ambiguous.example": AMBIGUOUS_REGISTRANT_DOMAIN})

    result = resolve_ownership(["ambiguous.example"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["ambiguous.example"]
    # Deliberate false negative: an fn with no kind could be either, and
    # writing a possible person's name at confidence 0.9 is the worse error.
    assert record["org_name"] is None
    assert record["registrant_status"] == "unidentified"
    assert "Ivan Petrov" not in (tmp_path / "ownership.json").read_text(encoding="utf-8")


def test_ownership_reads_an_org_declared_through_kind(tmp_path: Path, monkeypatch):
    payload = {
        "ldhName": "kindorg.example",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["kind", {}, "text", "org"], ["fn", {}, "text", "Example Holding LLC"]],
                ],
            }
        ],
    }
    _patch_lookups(monkeypatch, {"kindorg.example": payload})

    result = resolve_ownership(["kindorg.example"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["kindorg.example"]
    assert record["org_name"] == "Example Holding LLC"
    assert record["registrant_status"] == "public"


def test_ownership_marks_a_masked_registrant_as_redacted(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"masked.com": REDACTED_DOMAIN})

    result = resolve_ownership(["masked.com"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["masked.com"]
    assert record["status"] == "ok"
    assert record["org_name"] is None
    # "hidden from us" is not the same answer as "there is nothing there".
    assert record["registrant_status"] == "redacted"
    assert result["identifiers"] == []


def test_ownership_missing_rdap_object_is_not_ok(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"gone.com": None})

    result = resolve_ownership(["gone.com"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["gone.com"]
    assert record["status"] == "not_checked"
    assert record["reason"] == "rdap_not_found"
    assert record["registrant_status"] == "unknown"


def test_ownership_transport_failure_is_an_error_not_ok(tmp_path: Path, monkeypatch):
    def _fake_get_json(url: str, timeout: float, max_retries: int = 2):
        if url.endswith("/rdap/dns.json"):
            return BOOTSTRAP
        raise safe_http.SafeHttpError("HTTP 503")

    monkeypatch.setattr("scanner.pipeline.ownership._get_json", _fake_get_json)

    result = resolve_ownership(["example.com"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["example.com"]
    assert record["status"] == "error"
    assert record["reason"] == "rdap_unavailable"


def test_ownership_truncates_past_max_domains(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"a.com": PUBLIC_DOMAIN, "b.com": PUBLIC_DOMAIN})

    result = resolve_ownership(
        ["a.com", "b.com"], _config(max_domains=1), tmp_path, tmp_path / "state"
    )

    assert result["truncated"] is True
    assert result["seed_domains"] == ["a.com"]
    assert list(result["domains"]) == ["a.com"]


def test_ownership_stops_at_the_stage_deadline(tmp_path: Path, monkeypatch):
    _patch_lookups(monkeypatch, {"a.com": PUBLIC_DOMAIN, "b.com": PUBLIC_DOMAIN})
    clock = iter([0.0, 0.0, 1e6])
    monkeypatch.setattr("scanner.pipeline.ownership.time.perf_counter", lambda: next(clock))

    result = resolve_ownership(["a.com", "b.com"], _config(), tmp_path, tmp_path / "state")

    assert result["truncated"] is True
    assert list(result["domains"]) == ["a.com"]


def test_ownership_caches_the_bootstrap_between_domains(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / "state"
    requested = _patch_lookups(monkeypatch, {"a.com": PUBLIC_DOMAIN, "b.com": PUBLIC_DOMAIN})

    resolve_ownership(["a.com", "b.com"], _config(), tmp_path, state_dir)

    assert requested.count("https://data.iana.org/rdap/dns.json") == 1
    assert (state_dir / "rdap_dns_bootstrap.json").exists()

    requested.clear()
    resolve_ownership(["a.com"], _config(), tmp_path, state_dir)
    assert "https://data.iana.org/rdap/dns.json" not in requested


def test_rdap_urls_prefer_the_registry_then_fall_back(tmp_path: Path, monkeypatch):
    services = {"com": "https://rdap.verisign.example/v1/"}
    assert _rdap_urls("example.com", services) == [
        "https://rdap.verisign.example/v1/domain/example.com",
        "https://rdap.org/domain/example.com",
    ]
    # Unknown TLD: rdap.org only.
    assert _rdap_urls("example.invalidtld", services) == [
        "https://rdap.org/domain/example.invalidtld"
    ]


def test_parse_ignores_a_plain_http_bootstrap_entry(tmp_path: Path, monkeypatch):
    # The "dev" bootstrap entry lists an http URL first; only the https one is
    # usable, and safe_http would refuse the other anyway.
    requested = _patch_lookups(monkeypatch, {"example.dev": PUBLIC_DOMAIN})
    resolve_ownership(["example.dev"], _config(), tmp_path, tmp_path / "state")
    assert "https://rdap.google.example/rdap/domain/example.dev" in requested
    assert not any(url.startswith("http://") for url in requested)


def test_parse_rdap_domain_without_entities_is_unknown():
    record = _parse_rdap_domain({"ldhName": "bare.com"})
    assert record["registrant_status"] == "unknown"
    assert record["org_name"] is None
    assert record["dnssec"] is None
    assert record["nameservers"] == []


def test_get_json_retries_then_gives_up(monkeypatch):
    monkeypatch.setattr("scanner.pipeline.ownership.time.sleep", lambda seconds: None)
    statuses = [503, 503, 503]

    def _fake_get(url, **kwargs):
        return safe_http.SafeResponse(url=url, status=statuses.pop(0), headers={}, body=b"", truncated=False)

    monkeypatch.setattr("scanner.pipeline.safe_http.get", _fake_get)
    with pytest.raises(safe_http.SafeHttpError, match="HTTP 503"):
        _get_json("https://rdap.example.com/domain/example.com", 5.0)
    assert statuses == []


def test_get_json_returns_none_on_404(monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.safe_http.get",
        lambda url, **kwargs: safe_http.SafeResponse(
            url=url, status=404, headers={}, body=b"", truncated=False
        ),
    )
    assert _get_json("https://rdap.example.com/domain/gone.com", 5.0) is None


def test_get_json_does_not_retry_a_blocked_target(monkeypatch):
    calls: list[str] = []

    def _blocked(url, **kwargs):
        calls.append(url)
        raise safe_http.UnsafeTargetError("resolves to non-public address 169.254.169.254")

    monkeypatch.setattr("scanner.pipeline.safe_http.get", _blocked)
    with pytest.raises(safe_http.UnsafeTargetError):
        _get_json("https://evil.example/domain/example.com", 5.0)
    # Policy, not a transient failure: retrying reaches the same address.
    assert len(calls) == 1


def test_blocked_rdap_target_is_reported_as_an_error(tmp_path: Path, monkeypatch):
    def _fake_get_json(url: str, timeout: float, max_retries: int = 2):
        if url.endswith("/rdap/dns.json"):
            return BOOTSTRAP
        raise safe_http.UnsafeTargetError("resolves to non-public address 127.0.0.1")

    monkeypatch.setattr("scanner.pipeline.ownership._get_json", _fake_get_json)

    result = resolve_ownership(["example.com"], _config(), tmp_path, tmp_path / "state")

    record = result["domains"]["example.com"]
    assert record["status"] == "error"
    assert record["reason"] == "rdap_blocked_target"


def test_bootstrap_failure_falls_back_to_rdap_org(tmp_path: Path, monkeypatch):
    requested: list[str] = []

    def _fake_get_json(url: str, timeout: float, max_retries: int = 2):
        requested.append(url)
        if url.endswith("/rdap/dns.json"):
            raise safe_http.SafeHttpError("HTTP 500")
        return PUBLIC_DOMAIN

    monkeypatch.setattr("scanner.pipeline.ownership._get_json", _fake_get_json)

    result = resolve_ownership(["example.com"], _config(), tmp_path, tmp_path / "state")

    assert requested[-1] == "https://rdap.org/domain/example.com"
    assert result["domains"]["example.com"]["status"] == "ok"
    assert not (tmp_path / "state" / "rdap_dns_bootstrap.json").exists()
