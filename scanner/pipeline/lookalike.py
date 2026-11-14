"""Look-alike domain generators.

The six typo classes that ``domain_monitor`` has always used live here so a
brand-watch pass and the domain-monitor stage share one implementation.
``generate_typosquat_candidates`` is that six-class path: omission, adjacent
transposition, QWERTY-adjacent substitution, doubling/de-doubling, the ASCII
homoglyph pairs, and the original TLD swap list. The Public Suffix List
decides what is label and what is suffix, so for ``bbc.co.uk`` only ``bbc``
is mutated and ``co.uk`` is swapped whole. The seed itself and its
registrable domain are never candidates.

Brand watch adds classes on top of those six and never feeds them back into
``domain_monitor``: ЙЦУКЕН adjacency, mixed latin/cyrillic homoglyphs, a
punycode form stored beside the unicode name, combosquat from a fixed
dictionary, and a wider TLD swap table (``.ru`` / ``.рф`` / ``.su`` plus the
original list). Bitsquatting is off. There is no model. Generation is
deterministic and capped, and every candidate records the class that
produced it.
"""

from __future__ import annotations

import itertools
import unicodedata
from collections.abc import Iterable, Sequence

from .public_suffix import registrable_domain

_KEYBOARD_ADJACENCY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij",
    "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdz", "d": "serfx", "f": "drtgc",
    "g": "ftyhv", "h": "gyujb", "j": "hikun", "k": "jiolm", "l": "kop", "z": "asx",
    "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_HOMOGLYPH_SUBS = (
    ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("0", "o"), ("o", "0"),
    ("1", "l"), ("l", "1"), ("5", "s"), ("s", "5"),
)
_TLD_SWAP_LIST = ("com", "net", "org", "co", "io", "info", "biz", "cc", "xyz")

#: The six classes domain_monitor has always interleaved. Brand-watch classes
#: are not in this tuple: feeding them into the six-class path would change
#: which candidates a capped domain_monitor run reports.
SIX_CLASSES: tuple[str, ...] = (
    "omission",
    "transposition",
    "keyboard",
    "doubling",
    "homoglyph",
    "tld_swap",
)

#: ЙЦУКЕН neighbours, lowercase. Used only by brand watch.
_CYRILLIC_KEYBOARD = {
    "й": "цф", "ц": "йуыв", "у": "цкы", "к": "уена", "е": "кнп", "н": "егпр",
    "г": "ншро", "ш": "гщло", "щ": "шздл", "з": "щхдже", "х": "зэж", "ъ": "э",
    "ф": "йыя", "ы": "фцвчй", "в": "уыачц", "а": "квпм", "п": "еарм", "р": "нпои",
    "о": "гшлрит", "л": "шщдбо", "д": "щзжбл", "ж": "здэю", "э": "хъж",
    "я": "фч", "ч": "яыс", "с": "чвм", "м": "сапи", "и": "мрт", "т": "роиь",
    "ь": "тоб", "б": "льдю", "ю": "бж",
}

#: One latin letter, the cyrillic letters a reader can mistake for it.
#: Substituting one occurrence at a time keeps the set finite and ordered.
_LATIN_TO_CYRILLIC = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
    "k": "к", "h": "н", "b": "в", "m": "м", "t": "т",
}

#: Combosquat words, and the only words brand watch may glue onto a brand.
#: Not a wordlist and not extended at runtime.
COMBO_WORDS: tuple[str, ...] = (
    "login", "secure", "support", "pay", "account", "sso", "update",
)

#: Added to the original swap list for brand watch only. ``.рф`` is stored as
#: unicode; ``punycode_form`` records the A-label beside it.
BRAND_TLD_EXTRA: tuple[str, ...] = ("ru", "рф", "su")

#: A short generic token is not a brand by itself. Matching it would generate
#: look-alikes of the word, not of an organisation.
GENERIC_TOKENS = frozenset({
    "bank", "pay", "mail", "shop", "app", "web", "www", "login", "secure",
    "support", "account", "sso", "update", "admin", "auth", "cloud", "online",
    "service", "portal", "id", "me", "my", "go", "io", "ai", "com", "net",
    "org", "ru", "su",
})

_BRAND_CLASS_ORDER: tuple[str, ...] = (
    *SIX_CLASSES,
    "cyrillic_keyboard",
    "mixed_homoglyph",
    "combosquat",
    "tld_swap_brand",
)


def _split_domain(domain: str) -> tuple[str, str]:
    """Split a seed into (registrable label, public suffix) by the Public
    Suffix List: "example.com" -> ("example", "com"), "bbc.co.uk" ->
    ("bbc", "co.uk"), "x.github.io" -> ("x", "github.io"). A subdomain seed
    is cut to its registrable domain first, so "shop.example.com.ru" ->
    ("example", "com.ru"): the generators then mutate the one label a
    squatter would register and never a dot or a suffix label.

    A name with no registrable domain (a public suffix itself, an IP literal,
    a bare label) keeps the old split at the last dot -- "co.uk" ->
    ("co", "uk") -- so such a seed still yields what it did before."""
    registrable = registrable_domain(domain)
    if registrable:
        label, _, suffix = registrable.partition(".")
        return label, suffix
    parts = domain.split(".")
    if len(parts) < 2:
        return domain, ""
    return ".".join(parts[:-1]), parts[-1]


def _omission_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i in range(len(label)):
        new_label = label[:i] + label[i + 1 :]
        if new_label:
            out.append(f"{new_label}.{tld}")
    return out


def _transposition_candidates(label: str, tld: str) -> list[str]:
    out = []
    chars = list(label)
    for i in range(len(chars) - 1):
        swapped = chars.copy()
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        out.append(f"{''.join(swapped)}.{tld}")
    return out


def _keyboard_adjacent_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i, ch in enumerate(label):
        for adj in _KEYBOARD_ADJACENCY.get(ch.lower(), ""):
            new_label = label[:i] + adj + label[i + 1 :]
            out.append(f"{new_label}.{tld}")
    return out


def _doubling_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i, ch in enumerate(label):
        out.append(f"{label[:i] + ch + ch + label[i + 1:]}.{tld}")
    for i in range(len(label) - 1):
        if label[i] == label[i + 1]:
            new_label = label[:i] + label[i + 1 :]
            out.append(f"{new_label}.{tld}")
    return out


def _homoglyph_candidates(label: str, tld: str) -> list[str]:
    out = []
    for old, new in _HOMOGLYPH_SUBS:
        if old in label:
            out.append(f"{label.replace(old, new)}.{tld}")
    return out


def _tld_swap_candidates(label: str, tld: str) -> list[str]:
    """Replace the whole public suffix, never just its last label.

    ``tld`` is everything ``_split_domain`` put right of the label, so
    "bbc" + "co.uk" gives "bbc.com", "bbc.co", ... and not "bbc.co.com". A
    multi-label suffix also contributes its own TLD, first: "bbc.uk" for
    "co.uk", "example.ru" for "com.ru" -- the nearest look-alike of such a
    seed, and one the fixed list does not carry. For a private-section
    suffix the platform is swapped away too ("x.github.io" -> "x.io",
    "x.com"): the same name under a registry, not a neighbour on the
    platform, which the label mutations already cover."""
    swaps = list(_TLD_SWAP_LIST)
    if "." in tld:
        swaps.insert(0, tld.rsplit(".", 1)[1])
    return [f"{label}.{new_tld}" for new_tld in dict.fromkeys(swaps) if new_tld != tld]


def _round_robin(class_lists: list[list[str]]) -> list[str]:
    """Interleave several candidate-class lists round-robin (one from each
    class in turn, cycling back), deduping case-insensitively."""
    result: list[str] = []
    seen: set[str] = set()
    for item in itertools.chain.from_iterable(itertools.zip_longest(*class_lists)):
        if item is None:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _generate_typosquat_candidates(domain: str, max_candidates: int) -> list[str]:
    """Generate look-alike domain candidates for ``domain`` via six classes
    of typo/homoglyph generators, interleaved round-robin and capped at
    ``max_candidates``."""
    tagged = generate_typosquat(domain, max_candidates)
    return [item["name"] for item in tagged]


def generate_typosquat(domain: str, max_candidates: int) -> list[dict[str, str]]:
    """The six-class path, each candidate tagged with its generator class.

    Same names, same order and the same cap as
    ``_generate_typosquat_candidates``. Brand-watch classes are not included.
    """
    domain = domain.strip().lower().rstrip(".")
    label, tld = _split_domain(domain)
    if not label or not tld:
        return []

    class_lists = [
        [(name, "omission") for name in _omission_candidates(label, tld)],
        [(name, "transposition") for name in _transposition_candidates(label, tld)],
        [(name, "keyboard") for name in _keyboard_adjacent_candidates(label, tld)],
        [(name, "doubling") for name in _doubling_candidates(label, tld)],
        [(name, "homoglyph") for name in _homoglyph_candidates(label, tld)],
        [(name, "tld_swap") for name in _tld_swap_candidates(label, tld)],
    ]
    own = {domain, f"{label}.{tld}"}
    return _cap_tagged(class_lists, own, max_candidates)


def _cyrillic_keyboard_candidates(label: str, tld: str) -> list[str]:
    """One ЙЦУКЕН-neighbour substitution per character, in label order."""
    out = []
    for i, ch in enumerate(label):
        for adj in _CYRILLIC_KEYBOARD.get(ch, ""):
            out.append(f"{label[:i] + adj + label[i + 1 :]}.{tld}")
    return out


def _mixed_homoglyph_candidates(label: str, tld: str) -> list[str]:
    """One latin letter replaced by its cyrillic look-alike, per occurrence.

    The whole-label swap is not generated: a fully cyrillic label is a
    different name, and the single-letter form is the one a reader confuses
    with the brand. Order is left to right, and the cyrillic substitutes of
    one letter stay in the table's order.
    """
    out = []
    for i, ch in enumerate(label):
        for sub in _LATIN_TO_CYRILLIC.get(ch, ""):
            out.append(f"{label[:i] + sub + label[i + 1 :]}.{tld}")
    return out


def _combosquat_candidates(label: str, tld: str) -> list[str]:
    """``word-label`` and ``label-word`` for the fixed dictionary only.

    Hyphenated so the brand label is still the thing being watched, and so a
    word that happens to be a prefix of the label does not collapse into an
    omission. The dictionary is not extended.
    """
    out = []
    for word in COMBO_WORDS:
        if word == label:
            continue
        out.append(f"{word}-{label}.{tld}")
        out.append(f"{label}-{word}.{tld}")
    return out


def _brand_tld_swap_candidates(label: str, tld: str) -> list[str]:
    """The original swap list, then ``.ru`` / ``.рф`` / ``.su``.

    Extras are appended, not substituted: a brand-watch pass still sees
    ``example.com`` for a ``.ru`` seed. The suffix's own TLD, which the
    six-class swap already contributes, is not repeated here.
    """
    swaps = list(_TLD_SWAP_LIST) + list(BRAND_TLD_EXTRA)
    return [f"{label}.{new_tld}" for new_tld in dict.fromkeys(swaps) if new_tld != tld]


def punycode_form(name: str) -> str:
    """The IDNA A-label form of ``name``, or ``name`` when it is already ASCII.

    Stored beside the unicode candidate. A label IDNA refuses (an empty
    label, a disallowed character) is left as given rather than dropped: the
    candidate is still a name the generator produced.
    """
    text = name.strip().rstrip(".").lower()
    if text.isascii():
        return text
    labels = []
    for label in text.split("."):
        if label.isascii():
            labels.append(label)
            continue
        try:
            labels.append("xn--" + label.encode("punycode").decode("ascii"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def is_brand_token(token: str) -> bool:
    """False for a short generic word (``bank``, ``pay`` and the like).

    A brand token is a single label, at least four characters, and not in
    the generic list. Digits and hyphens are allowed; a dot is a domain, not
    a token, and is rejected.
    """
    text = unicodedata.normalize("NFC", token.strip().lower())
    if not text or "." in text or len(text) < 4:
        return False
    return text not in GENERIC_TOKENS


def _cap_tagged(
    class_lists: Sequence[Sequence[tuple[str, str]]],
    excluded: Iterable[str],
    max_candidates: int,
) -> list[dict[str, str]]:
    """Round-robin the class lists, drop exclusions, cap, attach punycode."""
    blocked = {item.strip().lower().rstrip(".") for item in excluded if item and item.strip()}
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    if max_candidates <= 0:
        return out
    for item in itertools.chain.from_iterable(itertools.zip_longest(*class_lists)):
        if item is None:
            continue
        name, generator = item
        key = name.lower()
        if key in seen or key in blocked:
            continue
        seen.add(key)
        out.append({
            "name": name,
            "punycode": punycode_form(name),
            "generator": generator,
        })
        if len(out) >= max_candidates:
            break
    return out


def generate(
    domain: str,
    max_candidates: int,
    *,
    exclude: set[str] | None = None,
) -> list[dict[str, str]]:
    """Brand-watch candidates: the six classes plus the brand-watch classes.

    ``exclude`` is the official domains and the explicit whitelist. The seed
    and its registrable domain are excluded as well, whether or not the
    caller listed them. Each item is ``name``, ``punycode`` and
    ``generator``. Order is deterministic: one candidate from each class in
    :data:`_BRAND_CLASS_ORDER`, then the next, case-insensitive duplicates
    dropped on the first class that produced them.
    """
    domain = domain.strip().lower().rstrip(".")
    label, tld = _split_domain(domain)
    if not label or not tld:
        return []

    by_class = {
        "omission": _omission_candidates(label, tld),
        "transposition": _transposition_candidates(label, tld),
        "keyboard": _keyboard_adjacent_candidates(label, tld),
        "doubling": _doubling_candidates(label, tld),
        "homoglyph": _homoglyph_candidates(label, tld),
        "tld_swap": _tld_swap_candidates(label, tld),
        "cyrillic_keyboard": _cyrillic_keyboard_candidates(label, tld),
        "mixed_homoglyph": _mixed_homoglyph_candidates(label, tld),
        "combosquat": _combosquat_candidates(label, tld),
        "tld_swap_brand": _brand_tld_swap_candidates(label, tld),
    }
    class_lists = [
        [(name, generator) for name in by_class[generator]]
        for generator in _BRAND_CLASS_ORDER
    ]
    own = {domain, f"{label}.{tld}"}
    if exclude:
        own.update(item.strip().lower().rstrip(".") for item in exclude if item and item.strip())
    return _cap_tagged(class_lists, own, max_candidates)
