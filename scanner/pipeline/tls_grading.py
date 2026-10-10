"""A-F grade for one TLS cipher suite, computed on our side.

Pulse (like any engine that only reports what a server accepts) hands over
suites and, at best, the key-exchange group or size; the letter is ours to
give, so the ``weak_cipher_grade`` threshold means the same thing whichever
source filled ``cipher_versions``.

Method: the public Qualys SSL Labs *SSL Server Rating Guide* -- the strength
of the key exchange and of the bulk cipher turn into points, the points into a
letter, and some properties cap the letter whatever the points say:

* key exchange: <512 bits 20, <1024 40, <2048 80, <4096 90, else 100
  (an elliptic-curve size is first converted to the RSA/DH size of the same
  security level);
* bulk cipher: no encryption 0, <128 effective bits 20, <256 80, else 100;
* weights 30 (key exchange) : 40 (cipher), the protocol's 30 is judged on the
  protocol itself (``weak_protocol``), so it is left out of a per-suite grade;
* letter: >=80 A, >=65 B, >=50 C, >=35 D, >=20 E, else F.

Caps: anonymous key exchange, NULL cipher, EXPORT suites and ciphers of 64
effective bits or fewer -> F; RC4 and 64-bit block ciphers (3DES, IDEA, GOST
28147, Magma) -> C; a finite-field exchange under 2048 bits -> B (under 1024 -> D), and an
elliptic-curve one under 224 bits -> B.

This is written from that public guide and checked against recorded Nmap
output (``tests/fixtures/nmap_pulse_corpus``); no Nmap source was consulted.

A suite this module cannot parse gets ``None`` -- never an invented letter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ORDER = "ABCDEF"

# group label (lower case, as Pulse/OpenSSL/Nmap spell it) -> field size in bits
_EC_GROUP_BITS = {
    "secp192r1": 192, "prime192v1": 192, "secp224r1": 224, "secp256r1": 256, "prime256v1": 256,
    "secp384r1": 384, "secp521r1": 521, "secp160r1": 160, "secp160r2": 160, "secp160k1": 160,
    "secp192k1": 192, "secp224k1": 224, "secp256k1": 256,
    "sect163k1": 163, "sect163r1": 163, "sect163r2": 163, "sect193r1": 193, "sect193r2": 193,
    "sect233k1": 233, "sect233r1": 233, "sect239k1": 239, "sect283k1": 283, "sect283r1": 283,
    "sect409k1": 409, "sect409r1": 409, "sect571k1": 571, "sect571r1": 571,
    "brainpoolp256r1": 256, "brainpoolp384r1": 384, "brainpoolp512r1": 512,
    "x25519": 253, "x448": 448, "curve25519": 253, "curve448": 448,
}
_MAX_EC_BITS = 571  # sect571 / secp521: the largest named curve
_SCORED_KEX = ("ecdhe", "ecdh", "rsa", "dhe", "dh")
_FFDHE_RE = re.compile(r"^ffdhe(\d{3,5})$")

# (cipher token regex, effective key bits, block bits or None, flags)
# First match wins; order matters (3DES before DES, AES_128_CCM before AES_128).
_CIPHERS: tuple[tuple[str, int, int | None, str], ...] = (
    (r"NULL", 0, None, "null"),
    (r"3DES_EDE_CBC", 112, 64, ""),
    (r"DES40_CBC|DES_CBC_40", 40, 64, "export"),
    (r"DES_CBC", 56, 64, ""),
    (r"RC2_CBC_40", 40, 64, "export"),
    (r"RC4_40", 40, None, "rc4 export"),
    (r"RC4", 128, None, "rc4"),
    (r"IDEA", 128, 64, ""),
    (r"28147", 256, 64, ""),
    (r"MAGMA", 256, 64, ""),
    (r"KUZNYECHIK", 256, None, ""),
    (r"AES_?256", 256, None, ""),
    (r"AES_?128", 128, None, ""),
    (r"CAMELLIA_?256", 256, None, ""),
    (r"CAMELLIA_?128", 128, None, ""),
    (r"ARIA_?256", 256, None, ""),
    (r"ARIA_?128", 128, None, ""),
    (r"CHACHA20", 256, None, ""),
    (r"SEED", 128, None, ""),
    (r"SM4", 128, None, ""),
)
_CIPHER_RES = tuple((re.compile(p), bits, block, flags) for p, bits, block, flags in _CIPHERS)


@dataclass(frozen=True)
class _Parsed:
    kex: str  # rsa | dhe | ecdhe | dh | ecdh | anon | tls13 | other
    bits: int
    block: int | None
    flags: str


def _score_cipher(bits: int) -> int:
    if bits <= 0:
        return 0
    if bits < 128:
        return 20
    if bits < 256:
        return 80
    return 100


def _score_rsa_equivalent(bits: int) -> int:
    if bits < 512:
        return 20
    if bits < 1024:
        return 40
    if bits < 2048:
        return 80
    if bits < 4096:
        return 90
    return 100


def _ec_to_rsa_equivalent(ec_bits: int) -> int:
    """Field size of a curve -> the RSA/DH size of about the same strength."""
    for limit, rsa in ((112, 512), (160, 768), (192, 1024), (224, 1536), (256, 2048), (384, 3072), (512, 7680)):
        if ec_bits < limit:
            return rsa
    return 15360


def _combine(kex_points: int | None, cipher_points: int) -> float:
    """Weights 30 : 40 (the guide's key exchange : cipher strength); unmeasured exchange counts 100."""
    return (30 * (100 if kex_points is None else kex_points) + 40 * cipher_points) / 70


def _letter(score: float) -> str:
    for threshold, letter in ((80, "A"), (65, "B"), (50, "C"), (35, "D"), (20, "E")):
        if score >= threshold:
            return letter
    return "F"


def normalize_suite_name(name: str) -> str:
    """Strip whitespace and map the ``TLS_AKE_WITH_*`` spelling of TLS 1.3 suites to IANA's."""
    n = (name or "").strip()
    if n.startswith("TLS_AKE_WITH_"):
        n = "TLS_" + n[len("TLS_AKE_WITH_"):]
    return n


def _parse(name: str) -> _Parsed | None:
    n = normalize_suite_name(name)
    if not n.startswith("TLS_") or n.endswith("_SCSV"):
        return None
    body = n[4:]
    if "_WITH_" in body:
        kex_part, _, rest = body.partition("_WITH_")
    else:
        kex_part, rest = "", body  # TLS 1.3: TLS_AES_128_GCM_SHA256
    upper_kex = kex_part.upper()
    if not kex_part:
        kex = "tls13"
    elif "ANON" in upper_kex:
        kex = "anon"
    elif upper_kex.startswith("ECDHE"):
        kex = "ecdhe"
    elif upper_kex.startswith("DHE"):
        kex = "dhe"
    elif upper_kex.startswith("ECDH"):
        kex = "ecdh"
    elif upper_kex.startswith("DH"):
        kex = "dh"
    elif upper_kex.startswith("RSA") and "PSK" not in upper_kex:
        kex = "rsa"
    else:
        kex = "other"  # PSK, SRP, KRB5, GOST, ...: no public size to score

    for rx, bits, block, flags in _CIPHER_RES:
        if rx.search(rest.upper()):
            export = "export" in flags or "EXPORT" in upper_kex or "EXPORT" in rest.upper()
            return _Parsed(
                kex=kex,
                bits=bits,
                block=block,
                flags=flags + (" export" if export and "export" not in flags else ""),
            )
    return None


def kex_bits_from_group(group: str | None) -> int | None:
    """Size (bits) for a named EC group or ffdhe group; ``None`` when not recognised."""
    if not isinstance(group, str):
        return None
    g = group.strip().lower()
    if g.startswith("ecdh_"):
        g = g[5:]
    if g in _EC_GROUP_BITS:
        return _EC_GROUP_BITS[g]
    m = _FFDHE_RE.match(g)
    return int(m.group(1)) if m else None


def grade_cipher_suite(name: str, *, kex_bits: int | None = None, kex_group: str | None = None) -> str | None:
    """Letter A-F for one suite, or ``None``; see ``grade_cipher_suite_detail``."""
    return grade_cipher_suite_detail(name, kex_bits=kex_bits, kex_group=kex_group)[0]


def grade_cipher_suite_detail(
    name: str,
    *,
    kex_bits: int | None = None,
    kex_group: str | None = None,
) -> tuple[str | None, bool]:
    """``(letter, upper_bound)`` for one suite; letter A-F for one suite, or ``None`` when the suite is not understood.

    ``name`` is the IANA name, or Nmap's ``TLS_AKE_WITH_*`` variant of a TLS
    1.3 name. ``kex_bits`` is the RSA/DH modulus size for finite-field
    exchanges, or the CURVE size for an EC exchange (x25519 is 253); a value over
    571 given for an EC exchange cannot be a curve size and is ignored; ``kex_group`` names the
    group (``x25519``, ``secp256r1``, ``ffdhe2048``) and supplies the size
    when ``kex_bits`` is absent. Without either, the exchange is not scored
    (and a finite-field DH of unknown size is capped at B): the letter is then
    the best the suite can earn, and ``upper_bound`` is ``True``: the letter may be
    too good and a weak exchange (a 1024-bit DH, say) cannot show in it.
    """
    parsed = _parse(name)
    if parsed is None:
        return None, False
    if parsed.kex == "anon" or "export" in parsed.flags or parsed.bits <= 64:  # bits 0 is NULL
        return "F", False

    bits = kex_bits if isinstance(kex_bits, int) and not isinstance(kex_bits, bool) and kex_bits > 0 else None
    if bits is None:
        bits = kex_bits_from_group(kex_group)
    group = kex_group.strip().lower() if isinstance(kex_group, str) else ""
    if group.startswith("ecdh_"):
        group = group[5:]
    if parsed.kex in ("ecdhe", "ecdh"):
        is_ec = True
    elif parsed.kex == "tls13":
        # TLS 1.3 names no exchange; the group (or, failing that, the size) says which.
        is_ec = group in _EC_GROUP_BITS or (not _FFDHE_RE.match(group) and bits is not None and bits < 1024)
    else:
        is_ec = False

    if is_ec and bits is not None and bits > _MAX_EC_BITS:
        bits = None  # not a curve size (an RSA/DH modulus in the wrong field): do not score it
    kex_score: int | None = None
    caps: list[str] = []
    if bits is not None and parsed.kex in ("ecdhe", "ecdh", "tls13", "rsa", "dhe", "dh"):
        if is_ec:
            kex_score = _score_rsa_equivalent(_ec_to_rsa_equivalent(bits))
            if bits < 224:
                caps.append("B")
        else:
            kex_score = _score_rsa_equivalent(bits)
            if bits < 2048:
                caps.append("D" if bits < 1024 else "B")
    elif bits is None and parsed.kex in ("dhe", "dh"):
        caps.append("B")  # DH parameters of unknown size: cannot rule out a weak group

    cipher_score = _score_cipher(parsed.bits)
    # An exchange nobody measured does not pull the letter down: the grade is then
    # what the cipher alone allows, i.e. an upper bound for that suite.
    score = _combine(kex_score, cipher_score)
    if "rc4" in parsed.flags or (parsed.block is not None and parsed.block <= 64):
        caps.append("C")
    # kex_score is None with a scoreable exchange: the full points above were an assumption.
    upper_bound = kex_score is None and parsed.kex in _SCORED_KEX
    return max([_letter(score), *caps]), upper_bound


def worst_grade(grades: list[str | None]) -> str | None:
    """The worst letter among known grades; ``None`` when none is known."""
    known = [g for g in grades if g in tuple(_ORDER)]
    return max(known) if known else None
