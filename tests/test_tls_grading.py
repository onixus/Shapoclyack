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
    grade_cipher_suite_detail,
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


# --- the point scale itself (SSL Labs guide), where points decide, not ceilings ----------
# Expected letters are worked out by hand from the guide's table, e.g. 3DES (112-bit,
# 20 points) with a 2048-bit exchange: (30*90 + 40*20) / 70 = 50.0 -> C, exactly on the
# threshold. Ceilings are in play too (a finite-field exchange under 1024 caps at D),
# which is why 3DES, the one cipher that scores 20, is the probe for the low end.

_FF_BITS = (256, 511, 512, 1023, 1024, 2047, 2048, 4095, 4096)
_EC_BITS = (80, 111, 112, 159, 160, 191, 192, 223, 224, 255, 256, 383, 384, 511, 512, 571)


@pytest.mark.parametrize(
    ("name", "letters"),
    [
        ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DDDDBBAAA"),
        ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DDDDBBAAA"),
        ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "EEEEDDCCC"),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "EEEEDDCCC"),
    ],
)
def test_finite_field_exchange_size_scale(name, letters):
    assert "".join(grade_cipher_suite(name, kex_bits=b) for b in _FF_BITS) == letters


@pytest.mark.parametrize(
    ("name", "letters"),
    [
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "CCCCBBBBAAAAAAAA"),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "BBBBBBBBAAAAAAAA"),
        ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "EEEEDDDDCCCCCCCC"),
    ],
)
def test_elliptic_curve_size_scale(name, letters):
    assert "".join(grade_cipher_suite(name, kex_bits=b) for b in _EC_BITS) == letters


@pytest.mark.parametrize(
    ("name", "kex_bits", "letter"),
    [
        # cipher points: 128-bit 80, 256-bit 100 -- 128-bit with the weakest scored exchange
        ("TLS_RSA_WITH_AES_128_GCM_SHA256", 4096, "A"),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 112, "C"),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 112, "B"),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 224, "A"),
        ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 4096, "C"),
    ],
)
def test_cipher_points_and_weights(name, kex_bits, letter):
    assert grade_cipher_suite(name, kex_bits=kex_bits) == letter


# The guide's tables, boundary by boundary. Few real suites sit on a boundary, so the
# scale functions are pinned directly: the letters above only show their effect.


@pytest.mark.parametrize(
    ("bits", "points"),
    [(0, 0), (-1, 0), (1, 20), (112, 20), (127, 20), (128, 80), (255, 80), (256, 100), (448, 100)],
)
def test_cipher_strength_points(bits, points):
    from scanner.pipeline.tls_grading import _score_cipher

    assert _score_cipher(bits) == points


@pytest.mark.parametrize(
    ("bits", "points"),
    [(1, 20), (511, 20), (512, 40), (1023, 40), (1024, 80), (2047, 80), (2048, 90), (4095, 90), (4096, 100), (16384, 100)],
)
def test_key_exchange_points(bits, points):
    from scanner.pipeline.tls_grading import _score_rsa_equivalent

    assert _score_rsa_equivalent(bits) == points


@pytest.mark.parametrize(
    ("ec_bits", "rsa_bits"),
    [(1, 512), (111, 512), (112, 768), (159, 768), (160, 1024), (191, 1024), (192, 1536), (223, 1536),
     (224, 2048), (255, 2048), (256, 3072), (383, 3072), (384, 7680), (511, 7680), (512, 15360), (571, 15360)],
)
def test_curve_size_to_equivalent_modulus(ec_bits, rsa_bits):
    from scanner.pipeline.tls_grading import _ec_to_rsa_equivalent

    assert _ec_to_rsa_equivalent(ec_bits) == rsa_bits


@pytest.mark.parametrize(
    ("score", "letter"),
    [(100, "A"), (80, "A"), (79.99, "B"), (65, "B"), (64.99, "C"), (50, "C"), (49.99, "D"),
     (35, "D"), (34.99, "E"), (20, "E"), (19.99, "F"), (0, "F")],
)
def test_score_to_letter(score, letter):
    from scanner.pipeline.tls_grading import _letter

    assert _letter(score) == letter


def test_score_weights_are_thirty_to_forty():
    from scanner.pipeline.tls_grading import _combine

    assert _combine(100, 100) == 100
    assert _combine(90, 80) == pytest.approx(84.2857, abs=1e-3)
    assert _combine(20, 80) == pytest.approx(54.2857, abs=1e-3)
    assert _combine(90, 20) == pytest.approx(50.0)
    assert _combine(0, 100) == pytest.approx(57.1429, abs=1e-3)
    assert _combine(None, 80) == pytest.approx(88.5714, abs=1e-3)  # unmeasured exchange: full points


@pytest.mark.parametrize(
    ("name", "grade"),
    [
        ("TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", "F"),  # only the EXPORT marker makes this F (RC4 is capped at C)
        ("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "F"),
        ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "F"),
        ("TLS_RSA_WITH_NULL_MD5", "F"),
        ("TLS_KRB5_WITH_DES_CBC_SHA", "F"),
        ("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "C"),  # 64-bit block, like GOST 28147
        ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "C"),
        ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "A"),
    ],
)
def test_ceilings_by_suite_family(name, grade):
    assert grade_cipher_suite(name) == grade


def test_upper_bound_flag():
    d = grade_cipher_suite_detail
    assert d("TLS_RSA_WITH_AES_128_CBC_SHA") == ("A", True)
    assert d("TLS_RSA_WITH_AES_128_CBC_SHA", kex_bits=2048) == ("A", False)
    assert d("TLS_DHE_RSA_WITH_AES_128_CBC_SHA") == ("B", True)
    assert d("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", kex_group="x25519") == ("A", False)
    assert d("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", kex_group="nonsense") == ("A", True)
    assert d("TLS_AES_128_GCM_SHA256") == ("A", False)  # TLS 1.3 names no exchange; its groups are all strong
    assert d("TLS_ECDH_anon_WITH_AES_128_CBC_SHA") == ("F", False)
    assert d("TLS_PSK_WITH_AES_128_CBC_SHA") == ("A", False)
    assert d("garbage") == (None, False)


def test_ec_exchange_size_over_the_largest_curve_is_not_a_curve_size():
    # 2048 is an RSA/DH modulus in the wrong field: ignored, not read as a huge curve
    assert grade_cipher_suite_detail("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kex_bits=2048) == ("C", True)
    assert grade_cipher_suite_detail("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kex_bits=571) == ("C", False)
    assert grade_cipher_suite_detail("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kex_bits=572) == ("C", True)
    assert grade_cipher_suite_detail("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kex_bits=100) == ("E", False)
