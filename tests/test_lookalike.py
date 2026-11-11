"""Brand-watch M1 generators, and the six classes domain_monitor still uses."""

from __future__ import annotations

import inspect

from scanner.pipeline import domain_monitor, lookalike
from scanner.pipeline.lookalike import (
    COMBO_WORDS,
    SIX_CLASSES,
    _generate_typosquat_candidates,
    _split_domain,
    generate,
    generate_typosquat,
    is_brand_token,
    punycode_form,
)

_RECORD_FLAGS = frozenset({"-a", "-aaaa", "-ns", "-soa", "-mx", "-cname", "-txt"})


def _suffix_after_first_label(candidate: str) -> tuple[str, str]:
    label, _, suffix = candidate.partition(".")
    return label, suffix


def test_bbc_co_uk_suffix_is_not_cut():
    assert _split_domain("bbc.co.uk") == ("bbc", "co.uk")
    candidates = _generate_typosquat_candidates("bbc.co.uk", max_candidates=500)

    assert "bbcc.co.uk" in candidates
    assert "vbc.co.uk" in candidates
    assert "bbc.com" in candidates
    assert "bbc.uk" in candidates
    assert "bbc.co.com" not in candidates
    swaps = {"uk", "com", "net", "org", "co", "io", "info", "biz", "cc", "xyz"}
    for candidate in candidates:
        label, suffix = _suffix_after_first_label(candidate)
        assert suffix == "co.uk" or (label == "bbc" and suffix in swaps), candidate


def test_seed_and_registrable_domain_are_excluded():
    six = _generate_typosquat_candidates("www.bbc.co.uk", max_candidates=500)
    branded = generate("www.bbc.co.uk", max_candidates=500)

    assert "bbc.co.uk" not in six
    assert "www.bbc.co.uk" not in six
    names = {item["name"] for item in branded}
    assert "bbc.co.uk" not in names
    assert "www.bbc.co.uk" not in names
    assert "bbc.com" in names


def test_whitelist_is_excluded():
    blocked = {"qcme.com", "acme.ru", "login-acme.com"}
    names = {item["name"] for item in generate("acme.com", max_candidates=500, exclude=blocked)}

    assert names.isdisjoint(blocked)
    assert "acme.com" not in names
    # The same classes still run for names the caller did not exclude.
    assert "acme.net" in names
    assert "secure-acme.com" in names


def test_short_generic_token_is_not_a_brand():
    assert is_brand_token("bank") is False
    assert is_brand_token("pay") is False
    assert is_brand_token("PAY") is False
    assert is_brand_token("app") is False
    assert is_brand_token("a") is False
    assert is_brand_token("acme.com") is False
    assert is_brand_token("acme") is True


def test_combosquat_uses_only_the_fixed_dictionary():
    branded = generate("acme.com", max_candidates=500)
    combos = [item["name"] for item in branded if item["generator"] == "combosquat"]

    assert combos
    allowed = {f"{word}-acme.com" for word in COMBO_WORDS} | {
        f"acme-{word}.com" for word in COMBO_WORDS
    }
    assert set(combos) <= allowed
    assert "password-acme.com" not in {item["name"] for item in branded}
    assert "signin-acme.com" not in {item["name"] for item in branded}
    assert COMBO_WORDS == ("login", "secure", "support", "pay", "account", "sso", "update")


def test_bitsquatting_is_absent():
    defined = {
        name
        for name, value in vars(lookalike).items()
        if inspect.isfunction(value) or inspect.isclass(value)
    }
    assert not any("bitsquat" in name.lower() for name in defined)
    generators = {item["generator"] for item in generate("example.com", max_candidates=500)}
    assert "bitsquat" not in generators
    assert "bitsquatting" not in generators
    # 'e' with bit 1 flipped is 'g', which is not a QWERTY neighbour of 'e'.
    names = {item["name"] for item in generate("example.com", max_candidates=500)}
    assert "gxample.com" not in names
    assert "examplg.com" not in names


def test_generation_is_deterministic_and_records_punycode():
    first = generate("acme.com", max_candidates=500)
    second = generate("acme.com", max_candidates=500)
    assert first == second
    assert first
    for item in first:
        assert set(item) == {"name", "punycode", "generator"}
        assert item["punycode"] == punycode_form(item["name"])
    mixed = [item for item in first if item["generator"] == "mixed_homoglyph"]
    assert mixed
    assert any(not item["name"].isascii() and item["punycode"].startswith("xn--") for item in mixed)
    assert any(item["name"] == "acme.рф" and item["punycode"].endswith(".xn--p1ai") for item in first)


def test_cap_is_respected():
    capped = generate("example.com", max_candidates=6)
    assert len(capped) == 6
    assert generate("example.com", max_candidates=0) == []
    assert len(generate("example.com", max_candidates=1)) == 1
    wide = _generate_typosquat_candidates("example.com", max_candidates=12)
    assert 0 < len(wide) <= 12


def test_domain_monitor_imports_the_six_classes():
    assert domain_monitor._generate_typosquat_candidates is _generate_typosquat_candidates
    assert domain_monitor._split_domain is _split_domain
    assert SIX_CLASSES == (
        "omission",
        "transposition",
        "keyboard",
        "doubling",
        "homoglyph",
        "tld_swap",
    )
    tagged = generate_typosquat("example.com", max_candidates=500)
    assert tagged
    assert {item["generator"] for item in tagged} <= set(SIX_CLASSES)
    assert [item["name"] for item in tagged] == _generate_typosquat_candidates(
        "example.com", max_candidates=500
    )
    # Brand-watch classes stay off the six-class path domain_monitor calls.
    assert all(item["generator"] != "combosquat" for item in tagged)
    assert "login-example.com" not in _generate_typosquat_candidates("example.com", max_candidates=500)
