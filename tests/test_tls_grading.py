"""A-F grading of TLS suites (scanner/pipeline/tls_grading.py).

Two kinds of evidence, kept apart on purpose:

* the recorded Nmap 7.93 output of the corpus is the oracle -- but it only
  contains the letters A and F, so it proves those and nothing about C-E;
* the SSL Labs Server Rating Guide cases below are the spec for the rest. They
  are NOT checked against Nmap.
"""

from __future__ import annotations

import pytest

from scanner.pipeline.tls_enumeration import iana_cipher_names
from scanner.pipeline.tls_grading import (
    grade_cipher_suite,
    kex_bits_from_group,
    normalize_suite_name,
    worst_grade,
)
from tests.tls_corpus_helpers import kex_from_nmap_detail, nmap_suites

# Recorded suites where our letter differs from Nmap's: (name, detail) -> reason.
# Empty means "none" -- every entry must be justified, never added to make a test pass.
KNOWN_DIVERGENCES: dict[tuple[str, str], str] = {}


def test_corpus_has_the_recorded_suites():
    suites = nmap_suites()
    assert len(suites) == 122
    assert {s[5] for s in suites} == {"A", "F"}  # the oracle's whole range


def test_grader_matches_nmap_on_every_recorded_suite():
    mismatches = []
    for ip, port, version, name, detail, nmap_letter in nmap_suites():
        ours = grade_cipher_suite(name, **kex_from_nmap_detail(detail))
        if ours != nmap_letter and (name, detail) not in KNOWN_DIVERGENCES:
            mismatches.append((ip, port, version, name, detail, nmap_letter, ours))
    assert mismatches == []


def test_only_anonymous_exchange_is_f_in_the_oracle():
    f_names = {s[3] for s in nmap_suites() if s[5] == "F"}
    assert f_names and all("_anon_" in n for n in f_names)


@pytest.mark.parametrize(
    ("name", "kwargs", "grade"),
    [
        # strong, with and without exchange detail
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", {"kex_group": "secp384r1"}, "A"),
        ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", {"kex_group": "x25519"}, "A"),
        ("TLS_AES_128_GCM_SHA256", {}, "A"),
        ("TLS_AKE_WITH_AES_256_GCM_SHA384", {"kex_group": "ecdh_x25519"}, "A"),
        ("TLS_AES_256_GCM_SHA384", {"kex_group": "ffdhe2048"}, "A"),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", {"kex_bits": 2048}, "A"),
        # ceilings
        ("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", {"kex_group": "x25519"}, "F"),
        ("TLS_DH_anon_WITH_AES_256_GCM_SHA384", {"kex_bits": 4096}, "F"),
        ("TLS_RSA_WITH_NULL_SHA256", {"kex_bits": 2048}, "F"),
        ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", {}, "F"),
        ("TLS_RSA_WITH_DES_CBC_SHA", {"kex_bits": 2048}, "F"),
        ("TLS_RSA_WITH_RC4_128_SHA", {"kex_bits": 2048}, "C"),
        ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", {"kex_group": "secp256r1"}, "C"),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", {"kex_bits": 2048}, "C"),
        ("TLS_RSA_WITH_IDEA_CBC_SHA", {"kex_bits": 2048}, "C"),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", {"kex_bits": 2048}, "A"),
        # key exchange strength
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", {"kex_bits": 2048}, "A"),
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", {"kex_bits": 1024}, "B"),
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", {"kex_bits": 512}, "D"),
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", {}, "B"),  # unknown DH size: cannot rule out Logjam
        ("TLS_RSA_WITH_AES_256_GCM_SHA384", {"kex_bits": 1024}, "B"),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", {"kex_group": "secp160r1"}, "B"),
    ],
)
def test_ssl_labs_guide_cases(name, kwargs, grade):
    assert grade_cipher_suite(name, **kwargs) == grade


@pytest.mark.parametrize("name", ["", "garbage", "TLS_FOO_WITH_BAR_BAZ", "TLS_FALLBACK_SCSV",
                                  "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "ECDHE-RSA-AES128-GCM-SHA256", None])
def test_unknown_suite_has_no_grade(name):
    assert grade_cipher_suite(name) is None  # type: ignore[arg-type]


def test_ake_spelling_is_iana_spelling():
    assert normalize_suite_name("TLS_AKE_WITH_AES_128_GCM_SHA256") == "TLS_AES_128_GCM_SHA256"
    assert normalize_suite_name(" TLS_RSA_WITH_AES_128_CBC_SHA ") == "TLS_RSA_WITH_AES_128_CBC_SHA"


def test_garbage_kex_hints_do_not_raise():
    assert grade_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA", kex_bits="2048") == "A"  # type: ignore[arg-type]
    assert grade_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA", kex_bits=True) == "A"
    assert grade_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA", kex_bits=-5, kex_group=7) == "A"  # type: ignore[arg-type]


def test_group_sizes():
    assert kex_bits_from_group("x25519") == 253
    assert kex_bits_from_group("ecdh_x25519") == 253
    assert kex_bits_from_group("SECP384R1") == 384
    assert kex_bits_from_group("ffdhe3072") == 3072
    assert kex_bits_from_group("nonsense") is None


def test_worst_grade():
    assert worst_grade(["A", "C", None, "B"]) == "C"
    assert worst_grade([None]) is None
    assert worst_grade([]) is None


def test_every_iana_suite_is_graded_or_a_known_pseudo_suite():
    names = iana_cipher_names()
    assert len(names) > 300
    assert names[0xC02F] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert names[0x1301] == "TLS_AES_128_GCM_SHA256"
    ungraded = sorted(n for n in names.values() if grade_cipher_suite(n) is None)
    # SCSVs are not suites; the rest are post-2023 additions this table of ciphers does not know yet.
    assert ungraded == sorted(
        [
            "TLS_ASCONAEAD128_ASCONHASH256", "TLS_ASCONAEAD128_SHA256", "TLS_AEGIS_256_SHA512",
            "TLS_AEGIS_128L_SHA256", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_FALLBACK_SCSV",
            "TLS_SHA256_SHA256", "TLS_SHA384_SHA384",
        ]
    )
