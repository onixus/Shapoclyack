"""Unit tests for related domains discovery (org_profile M4, EPIC #182)."""

from __future__ import annotations

import json
from pathlib import Path
from scanner.pipeline.config_schema import RelatedDomainsConfig
from scanner.pipeline.related_domains import (
    _compute_confidence,
    _extract_cert_san_candidates,
    _extract_reverse_mx_candidates,
    _extract_reverse_ns_candidates,
    _is_excluded,
    discover_related_domains,
)


def test_is_excluded_providers():
    excluded = ["cloudflare.com", "awsdns", "google.com"]
    assert _is_excluded("ns1.cloudflare.com", excluded) is True
    assert _is_excluded("ns-123.awsdns-01.org", excluded) is True
    assert _is_excluded("aspmx.l.google.com", excluded) is True
    assert _is_excluded("ns1.mycustomdns.net", excluded) is False
    assert _is_excluded("mail.corporate.org", excluded) is False


def test_extract_cert_san_candidates(tmp_path: Path):
    seed_domains = {"example.com"}
    # tls_posture.json nests the certificate under each endpoint record.
    tls_payload = {
        "checked_count": 1,
        "findings": [
            {
                "host": "10.0.0.1",
                "port": "443",
                "cert": {
                    "san": "DNS:example.com, DNS:api.example.com, "
                           "DNS:example-partner.net, DNS:internal.corp",
                },
                "issues": [],
            }
        ],
    }
    (tmp_path / "tls_posture.json").write_text(json.dumps(tls_payload), encoding="utf-8")

    candidates = _extract_cert_san_candidates(tmp_path, seed_domains)
    assert "example-partner.net" in candidates
    assert "internal.corp" in candidates
    assert "example.com" not in candidates  # Seed domain filtered out
    assert candidates["example-partner.net"][0]["source"] == "cert_san"


def test_extract_reverse_ns_candidates(tmp_path: Path):
    seed_domains = {"example.com"}
    excluded_ns = ["cloudflare.com", "awsdns"]
    # dns_hygiene.json records these under "nameservers", not "ns".
    dns_payload = {
        "domains": {
            "example.com": {
                "status": "ok",
                "nameservers": ["ns1.cloudflare.com", "ns1.customdns.org"],
            },
            "affiliate.org": {
                "status": "ok",
                "nameservers": ["ns1.customdns.org"],
            },
        }
    }
    (tmp_path / "dns_hygiene.json").write_text(json.dumps(dns_payload), encoding="utf-8")

    candidates = _extract_reverse_ns_candidates(tmp_path, seed_domains, excluded_ns)
    assert "affiliate.org" in candidates
    assert candidates["affiliate.org"][0]["source"] == "reverse_ns"
    # The evidence claims a share with a verified domain, so it must name one.
    assert "example.com" in candidates["affiliate.org"][0]["detail"]


def test_reverse_ns_requires_an_actual_shared_seed_domain(tmp_path: Path):
    """A domain sitting alone on its own private nameserver shares it with
    nothing; claiming it "shares NS with verified domain(s)" is unfounded."""
    (tmp_path / "dns_hygiene.json").write_text(
        json.dumps({
            "domains": {
                "unrelated.org": {"status": "ok", "nameservers": ["ns1.customdns.org"]},
            }
        }),
        encoding="utf-8",
    )

    candidates = _extract_reverse_ns_candidates(tmp_path, {"example.com"}, ["cloudflare.com"])
    assert candidates == {}


def test_reverse_mx_reads_entries_out_of_the_mx_object(tmp_path: Path):
    """mail_posture stores ``mx`` as a dict; iterating it directly would treat
    the keys "entries"/"has_mx" as mail exchangers."""
    (tmp_path / "mail_posture.json").write_text(
        json.dumps({
            "domains": {
                "example.com": {
                    "status": "ok",
                    "mx": {
                        "entries": [{"preference": 10, "host": "mail.corpmx.net"}],
                        "has_mx": True,
                        "null_mx": False,
                        "truncated": False,
                    },
                },
                "affiliate.org": {
                    "status": "ok",
                    "mx": {
                        "entries": [{"preference": 10, "host": "mail.corpmx.net"}],
                        "has_mx": True,
                        "null_mx": False,
                        "truncated": False,
                    },
                },
            }
        }),
        encoding="utf-8",
    )

    candidates = _extract_reverse_mx_candidates(tmp_path, {"example.com"}, ["google.com"])

    assert "affiliate.org" in candidates
    assert candidates["affiliate.org"][0]["source"] == "reverse_mx"
    assert "mail.corpmx.net" in candidates["affiliate.org"][0]["detail"]
    # No fabricated candidates out of the dict's own keys.
    assert not any(k in candidates for k in ("entries", "has_mx", "null_mx", "truncated"))


def test_is_excluded_does_not_match_across_label_boundaries():
    """A bare substring test excluded "ns1.company.org" via the "ns1.com"
    provider entry."""
    excluded = ["ns1.com", "cloudflare.com", "awsdns"]
    assert _is_excluded("ns1.company.org", excluded) is False
    assert _is_excluded("ns1.com", excluded) is True
    assert _is_excluded("a.ns1.com", excluded) is True
    assert _is_excluded("ns-1.awsdns-07.org", excluded) is True


def test_compute_confidence_multisource():
    # Single source (cert_san) -> 0.70
    conf, sources = _compute_confidence([{"source": "cert_san"}])
    assert conf == 0.70
    assert sources == ["cert_san"]

    # Two sources (cert_san + ct_org) -> 1 - (1-0.7)*(1-0.5) = 1 - 0.15 = 0.85
    conf, sources = _compute_confidence([{"source": "cert_san"}, {"source": "ct_org"}])
    assert conf == 0.85
    assert set(sources) == {"cert_san", "ct_org"}


def test_discover_related_domains_pipeline(tmp_path: Path):
    # Setup mock artifacts
    (tmp_path / "ownership.json").write_text(
        json.dumps({
            "domains": {
                "example.com": {
                    "org_name": "Example Corp",
                    "registrar": "MarkMonitor",
                    "registrant_status": "public",
                }
            }
        }),
        encoding="utf-8",
    )

    (tmp_path / "tls_posture.json").write_text(
        json.dumps({
            "findings": [
                {
                    "host": "198.51.100.1",
                    "port": "443",
                    "cert": {"san": "DNS:example.com, DNS:example-service.com"},
                    "issues": [],
                }
            ]
        }),
        encoding="utf-8",
    )

    config = RelatedDomainsConfig(
        enabled=True,
        sources=["cert_san"],
        min_confidence=0.6,
        auto_merge=True,
        merge_into_scope=True,
        max_merged_domains=5,
    )

    result = discover_related_domains(tmp_path, config, seed_domains=["example.com"])

    assert result["status"] == "ok"
    assert result["confirmed_count"] >= 1
    assert any(c["domain"] == "example-service.com" for c in result["candidates"])

    cand = next(c for c in result["candidates"] if c["domain"] == "example-service.com")
    assert cand["status"] == "confirmed"
    assert cand["confidence"] >= 0.6

    # Verify artifacts generated
    assert (tmp_path / "related_domains.json").exists()
    assert (tmp_path / "org_profile.json").exists()
    assert (tmp_path / "merged_related_domains.txt").exists()


def test_max_candidates_capping(tmp_path: Path):
    # Create multiple SAN entries
    sans = [f"DNS:candidate{i}.org" for i in range(20)]
    (tmp_path / "tls_posture.json").write_text(
        json.dumps({
            "findings": [
                {"host": "1.1.1.1", "port": "443", "cert": {"san": ", ".join(sans)}, "issues": []}
            ]
        }),
        encoding="utf-8",
    )

    config = RelatedDomainsConfig(
        enabled=True,
        sources=["cert_san"],
        max_candidates=5,
    )

    result = discover_related_domains(tmp_path, config, seed_domains=["example.com"])
    assert result["total_candidates"] == 20
    assert len(result["candidates"]) == 5
    assert result["truncated"] is True


def test_auto_merge_requires_merge_into_scope(tmp_path: Path):
    """``merge_into_scope`` is the documented finding-only safety boundary, so
    ``auto_merge`` alone must not widen scope."""
    (tmp_path / "tls_posture.json").write_text(
        json.dumps({
            "findings": [
                {
                    "host": "198.51.100.1",
                    "port": "443",
                    "cert": {"san": "DNS:example.com, DNS:example-service.com"},
                    "issues": [],
                }
            ]
        }),
        encoding="utf-8",
    )

    config = RelatedDomainsConfig(
        enabled=True,
        sources=["cert_san"],
        auto_merge=True,
        merge_into_scope=False,
    )
    result = discover_related_domains(tmp_path, config, seed_domains=["example.com"])

    assert result["confirmed_count"] >= 1
    assert result["merged_domains"] == []
    assert result["auto_merged"] is False
    assert not (tmp_path / "merged_related_domains.txt").exists()
