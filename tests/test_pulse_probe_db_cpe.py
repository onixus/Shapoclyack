"""Every product Pulse's probes.json can name is mapped to NVD keys or knowingly not (#546)."""

from __future__ import annotations

import json
import re

from api.services import retro_match
from scanner.pipeline.pulse_probe import PROBE_DB

_NO_VERSION = retro_match._NO_VERSION  # noqa: SLF001 - the reason the test holds the table to


def _products() -> tuple[set[str], set[str]]:
    """(every product the database can emit, those some rule emits with a version)."""
    named: set[str] = set()
    versioned: set[str] = set()
    for probe in json.loads(PROBE_DB.read_text(encoding="utf-8"))["probes"]:
        for rule in probe["matches"]:
            product = rule.get("product", "")
            if not product:
                continue
            named.add(product)
            if re.search(r"\$\d", rule.get("version", "")):
                versioned.add(product)
    return named, versioned


def test_every_product_is_mapped_or_deliberately_unmapped():
    named, _ = _products()
    mapped = {p for p in named if retro_match.normalize_product(p) in retro_match.PRODUCT_TABLE}
    unmapped = set(retro_match.UNMAPPED_PROBE_PRODUCTS)
    assert not named - mapped - unmapped, "add a PRODUCT_TABLE row or an UNMAPPED_PROBE_PRODUCTS entry with a reason"
    assert not mapped & unmapped, "a product is either mapped or deliberately not"
    assert not unmapped - named, "UNMAPPED_PROBE_PRODUCTS names a product the database no longer emits"
    assert all(reason.strip() for reason in retro_match.UNMAPPED_PROBE_PRODUCTS.values())


def test_a_no_version_exemption_holds_only_while_the_rules_emit_no_version():
    _, versioned = _products()
    stale = sorted(
        product
        for product, reason in retro_match.UNMAPPED_PROBE_PRODUCTS.items()
        if reason == _NO_VERSION and product in versioned
    )
    assert not stale, f"{stale} now emit a version: map them or give the exemption another reason"


def test_mapped_probe_products_name_wellformed_nvd_keys():
    named, _ = _products()
    for product in named:
        for key in retro_match.PRODUCT_TABLE.get(retro_match.normalize_product(product), ()):
            assert re.fullmatch(r"[aho]:[a-z0-9_.\-]+:[a-z0-9_.\-]+", key), (product, key)


def test_apache_mina_sshd_is_filed_under_both_nvd_spellings():
    # CVE-2023-35887 is on apache:sshd; apache:mina_sshd is the older spelling (NVD CPE API, 2026-10-10).
    assert set(retro_match.PRODUCT_TABLE["apache mina sshd"]) == {"a:apache:sshd", "a:apache:mina_sshd"}
