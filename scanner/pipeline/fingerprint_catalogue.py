"""Web technology catalogue for ``fingerprint.py`` (DQ4).

The stage fetches the root of each open web port; this module decides what
that answer says. The knowledge lives in ``fingerprint_catalogue.json`` next
to this file -- data, not code, so adding a product is a reviewed JSON entry
plus a fixture, never a new lambda. It sits next to the module rather than
under ``scanner/data`` for the reason ``public_suffix.py`` gives: the images
mount the shared enrichment volume over ``scanner/data``, and a volume seeded
before this file existed would hide it.

Every entry names a technology, its category, the matchers that identify it,
optionally how to read its version, and optionally its NVD CPE
``part:vendor:product``. The file is validated when it is loaded (pydantic,
``extra="forbid"``): an unknown category, a regex that does not compile or
can repeat without bound, a version rule without a ``version`` group or a
matcher that reads a cookie's value is refused instead of matching nothing.

Matchers
--------
``{"from": <source>, ...}`` with one source and at most one test
(``contains`` / ``equals`` / ``regex``):

* ``header`` -- ``name`` or ``prefix``; no test means presence;
* ``cookie`` -- ``name`` or ``prefix`` of a ``Set-Cookie``. Presence only: a
  cookie's value is a session secret and is never read or reported;
* ``status`` -- the HTTP status code, as text;
* ``url`` -- path and query of the URL that answered (same-address redirects
  followed): a root that redirects to ``/dana-na/...`` has said what it is;
* ``title`` -- the first ``<title>``;
* ``generator`` -- each ``<meta name="generator">``;
* ``meta`` -- the ``content`` of the ``<meta>`` whose ``name`` or ``property``
  is ``name``; no test means presence;
* ``asset`` -- what the page itself loads or submits to: ``src`` of script,
  img, iframe..., ``href`` of ``<link>``, ``action`` of ``<form>``. A
  same-origin reference reads as a path (``/wp-content/...``), any other as
  ``//host/path``, so a hot-linked image from someone's WordPress is not
  WordPress here. An ``<a href>`` is navigation, not an asset, and is skipped;
* ``attr`` -- an attribute (``name``) of an element (``tag``), or the element
  itself when no ``name`` is given;
* ``script`` -- the text of inline ``<script>`` elements;
* ``json`` -- the body, but only when the response *is* JSON: a JSON content
  type and a body that opens with ``{`` or ``[``. A tutorial quoting
  ``curl :9200`` inside ``<pre>`` is HTML and is not Elasticsearch;
* ``body`` -- the raw body. Last resort, for product text that has no
  structure (an error page); always paired in an ``all`` with something only
  the product sends -- the status it answers with, its title.

``{"all": [...]}`` is a conjunction for markers that are only specific
together. All comparisons ignore case. A matcher may override the entry's
``confidence``; a technology's confidence is the best of the matchers that
fired. There are two levels on purpose: ``high`` (the product says so itself
-- its own header, cookie, exact page title, or markup only it serves) and
``medium`` (strong, but a shared component, a reverse proxy or a customised
page could produce it). ``fingerprint.py`` raises exposure findings on
``high`` only; ``medium`` is inventory.

Cost is bounded on purpose, because the input is written by the host being
scanned. The page is read once by a linear scan (``parse_page``) with caps on
tags, attributes and script text; every catalogue regex must have a bounded
repeat count (``{0,512}``, never ``*``/``+``), which the loader enforces; and
``classify`` takes a deadline, checked between technologies, after which it
raises :class:`ClassificationTimeout` instead of running on.
"""

from __future__ import annotations

import functools
import html
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from re import _constants as _sre_constants  # type: ignore[attr-defined]
from re import _compiler as _sre_compiler  # type: ignore[attr-defined]
from re import _parser as _sre_parser  # type: ignore[attr-defined]
from typing import Any, Literal, get_args
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

CATALOGUE_PATH = Path(__file__).with_name("fingerprint_catalogue.json")
LOG = logging.getLogger("shapoclyack.fingerprint")

#: Categories the catalogue may use. ``fingerprint.py`` derives the legacy
#: ``cdn_waf`` / ``cms_framework`` lists and the exposure findings from these.
Category = Literal[
    "cdn_waf",
    "load_balancer",
    "proxy_cache",
    "web_server",
    "app_server",
    "framework",
    "cms",
    "ecommerce",
    "admin_panel",
    "database_ui",
    "database",
    "storage",
    "devops",
    "monitoring",
    "remote_access",
    "network_appliance",
    "mail_webmail",
    "collaboration",
    "business_app",
]
CATEGORIES: tuple[str, ...] = get_args(Category)
Confidence = Literal["high", "medium"]
CONFIDENCE_RANK = {"medium": 1, "high": 2}
Source = Literal[
    "header", "cookie", "status", "url", "title", "generator", "meta", "asset", "attr", "script", "json", "body"
]
VersionSource = Literal["header", "title", "generator", "meta", "asset", "script", "json", "body"]

#: Body needles shorter than this are words, not markers.
MIN_BODY_NEEDLE = 5
#: The largest repeat a catalogue regex may ask for, and the largest product
#: of nested repeats. A pattern over a body the scanned host wrote must not be
#: able to backtrack across all of it.
MAX_REGEX_REPEAT = 1024
MAX_REGEX_NESTED = 4096
#: A disclosed version is a short dotted token that starts with a digit.
#: Anything else a version regex captured is a mis-anchored rule, not a version.
_VERSION_RE = re.compile(r"^\d[0-9A-Za-z.+~_-]{0,39}$")
#: ``part:vendor:product`` as NVD writes it, CPE 2.3 escapes (``joomla\!``) kept.
_CPE_KEY_RE = re.compile(r"^[aho]:(?:[a-z0-9._~-]|\\[^a-z0-9]){1,64}:(?:[a-z0-9._~-]|\\[^a-z0-9]){1,64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_]{1,47}$")
#: A distribution's build of the product: the upstream version in the banner
#: is not the code that runs (backports), so it stays out of the CPE.
_DISTRO_RE = re.compile(
    r"(ubuntu|debian|[+~.-]deb\d{1,2}|\.el\d{1,2}|centos|red ?hat|rhel|fedora|suse|alpine|amzn|astra|red ?os|alt ?linux)",
    re.IGNORECASE,
)
_DISTRO_NAMES = (
    ("ubuntu", "ubuntu"),
    ("debian", "debian"),
    ("deb", "debian"),
    (".el", "rhel"),
    ("centos", "centos"),
    ("redos", "redos"),
    ("red os", "redos"),
    ("red", "rhel"),
    ("rhel", "rhel"),
    ("fedora", "fedora"),
    ("suse", "suse"),
    ("alpine", "alpine"),
    ("amzn", "amazon"),
    ("astra", "astra"),
    ("alt", "altlinux"),
)

#: Evidence strings are for a human reading a finding, not a copy of the
#: response: values are cut, bodies are never quoted beyond the marker itself.
EVIDENCE_MAX = 160
MAX_EVIDENCE_ITEMS = 5

#: Page-scan caps. A real login page has a few dozen tags; these leave room
#: for a heavy portal and stop a hostile one from costing more than a bounded
#: amount of work.
MAX_TAGS = 2048
MAX_TAG_LEN = 2048
MAX_ATTRS = 32
MAX_VALUE = 2048
MAX_SCRIPTS = 64
MAX_SCRIPT_LEN = 64 * 1024
MAX_TITLE_LEN = 4096

#: Where a URL-valued attribute is an asset of the page rather than a link.
_ASSET_ATTRS = {
    "script": "src",
    "img": "src",
    "iframe": "src",
    "frame": "src",
    "embed": "src",
    "source": "src",
    "link": "href",
    "form": "action",
    "object": "data",
}

_TAG_NAME_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9:_-]{0,63}")
_ATTR_NAME_RE = re.compile(r"[^\s\"'=<>/`]{1,64}")
_WS_RE = re.compile(r"\s{0,64}")
_BARE_VALUE_RE = re.compile(r"[^\s>]{0,2048}")
_TITLE_CLOSE_RE = re.compile(r"</title\s{0,8}>", re.IGNORECASE)
_SCRIPT_CLOSE_RE = re.compile(r"</script\s{0,8}>", re.IGNORECASE)
_JSON_START_RE = re.compile(r"\s{0,64}[\[{]")
_MATRIX_RE = re.compile(r";[^/]{0,2048}")


class ClassificationTimeout(Exception):
    """``classify`` ran past its deadline; the response is left unclassified."""


def _clip(text: str, limit: int = EVIDENCE_MAX) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _strip_matrix(path: str) -> str:
    """``/a;jsessionid=x/b`` -> ``/a/b``: a path parameter can be a session id."""
    return _MATRIX_RE.sub("", path)


_REPEATS = (_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT, _sre_constants.POSSESSIVE_REPEAT)
_SINGLE_CHAR_OPS = (
    _sre_constants.LITERAL,
    _sre_constants.NOT_LITERAL,
    _sre_constants.ANY,
    _sre_constants.IN,
)
#: The alphabet a character-class overlap is judged on: ASCII, Latin-1 and
#: enough Cyrillic to cover the catalogue's own patterns.
_LINT_ALPHABET = [chr(c) for c in range(256)] + [chr(c) for c in range(0x400, 0x460)] + ["·", "®"]


def _char_matcher(item: Any) -> re.Pattern[str] | None:
    """A one-character pattern equivalent to ``item``, or None when it is not one character."""
    op, _ = item
    if op not in _SINGLE_CHAR_OPS:
        return None
    sub = _sre_parser.SubPattern(_sre_parser.State(), [item])
    try:
        return _sre_compiler.compile(sub, re.IGNORECASE)
    except Exception:  # noqa: BLE001 - a lint helper; an uncompilable fragment is judged overlapping
        return None


def _edge(items: list[Any], first: bool) -> Any | None:
    """The first (or last) atom of a sequence, looking into groups."""
    seq = [item for item in items if item[0] is not _sre_constants.AT]
    if not seq:
        return None
    item = seq[0] if first else seq[-1]
    if item[0] is _sre_constants.SUBPATTERN:
        return _edge(list(item[1][3]), first)
    return item


def _variable_repeat(item: Any) -> Any | None:
    if item is not None and item[0] in _REPEATS:
        low, high, sub = item[1]
        if low != high:
            return item
    return None


def _overlap(left: Any, right: Any) -> bool:
    """Can the end of one repeat and the start of the next match the same character?"""
    left_atom = _edge(list(left[1][2]), first=False)
    right_atom = _edge(list(right[1][2]), first=True)
    if left_atom is None or right_atom is None:
        return True
    a, b = _char_matcher(left_atom), _char_matcher(right_atom)
    if a is None or b is None:
        return True
    return any(a.fullmatch(ch) and b.fullmatch(ch) for ch in _LINT_ALPHABET)


def _bounded(pattern: str) -> None:
    r"""Refuse a regex whose backtracking is not obviously bounded.

    * a repeat without a bound (``*``, ``+``, ``{n,}``) or above
      ``MAX_REGEX_REPEAT``, or nested repeats whose product exceeds
      ``MAX_REGEX_NESTED``;
    * an alternation inside a repeat (``(?:a|ab){0,64}``): every iteration can
      take either branch;
    * two variable repeats in a row whose characters overlap
      (``a{0,99}a{0,99}``, ``\s{0,8}[ \t]{0,8}``): the split between them is
      tried every way. A lookaround between them is looked through.

    These are shapes, not proofs. The tests also time every shipped pattern
    against a hostile corpus (``stress``); nothing is timed at scan time.
    """

    def walk(items: Any, outer: int, in_repeat: bool) -> None:
        seq = list(items)
        previous = None
        for item in seq:
            op, av = item
            if op is _sre_constants.BRANCH and in_repeat:
                raise ValueError(f"regex {pattern!r} has an alternation inside a repeat")
            if op in (_sre_constants.ASSERT, _sre_constants.ASSERT_NOT):
                inner = _variable_repeat(_edge(list(av[1]), first=True))
                if previous is not None and inner is not None and _overlap(previous, inner):
                    raise ValueError(f"regex {pattern!r} has adjacent repeats over the same characters")
                walk(av[1], outer, in_repeat)
                continue
            if op is _sre_constants.AT:
                continue
            current = _variable_repeat(_edge([item], first=True))
            if previous is not None and current is not None and _overlap(previous, current):
                raise ValueError(f"regex {pattern!r} has adjacent repeats over the same characters")
            previous = _variable_repeat(_edge([item], first=False))
            if op in _REPEATS:
                low, high, sub = av
                if high == _sre_constants.MAXREPEAT or high > MAX_REGEX_REPEAT:
                    raise ValueError(
                        f"regex {pattern!r} repeats without a bound; write {{0,{MAX_REGEX_REPEAT}}} or less"
                    )
                if outer * max(high, 1) > MAX_REGEX_NESTED:
                    raise ValueError(f"regex {pattern!r} nests repeats beyond {MAX_REGEX_NESTED}")
                walk(sub, outer * max(high, 1), True)
                continue
            for part in av if isinstance(av, (list, tuple)) else (av,):
                if isinstance(part, _sre_parser.SubPattern):
                    walk(part, outer, in_repeat)
                elif isinstance(part, list):
                    for sub in part:
                        if isinstance(sub, _sre_parser.SubPattern):
                            walk(sub, outer, in_repeat)

    walk(_sre_parser.parse(pattern), 1, False)


#: Inputs the catalogue tests time every regex against, built per pattern from
#: its own literal characters and a few generic ones. CPU time, median of
#: STRESS_REPEATS: the shipped patterns take ~5 ms at worst, so the budget is
#: wide enough that a busy machine does not fail a sound pattern and narrow
#: enough that exponential backtracking is caught a few characters in.
STRESS_INPUT_LEN = 64 * 1024
STRESS_BUDGET_SECONDS = 0.25
STRESS_REPEATS = 3
_STRESS_GENERIC = " a1<>\"'/.-:{"


def _literals(pattern: str) -> str:
    found: list[str] = []

    def walk(items: Any) -> None:
        for op, av in items:
            if op is _sre_constants.LITERAL:
                found.append(chr(av))
            for part in av if isinstance(av, (list, tuple)) else (av,):
                if isinstance(part, _sre_parser.SubPattern):
                    walk(part)
                elif isinstance(part, list):
                    for sub in part:
                        if isinstance(sub, _sre_parser.SubPattern):
                            walk(sub)

    walk(_sre_parser.parse(pattern))
    return "".join(found)


def _stress_lengths() -> list[int]:
    """1..64 one at a time, then doubling to ``STRESS_INPUT_LEN``.

    Exponential backtracking roughly doubles per character, so growing one
    character at a time over short inputs refuses such a pattern a step after
    it crosses the budget instead of hanging on the first long input.
    """
    lengths = list(range(1, 65))
    while lengths[-1] < STRESS_INPUT_LEN:
        lengths.append(min(lengths[-1] * 2, STRESS_INPUT_LEN))
    return lengths


def stress(pattern: re.Pattern[str], budget: float = STRESS_BUDGET_SECONDS) -> None:
    """Run ``pattern`` over growing hostile inputs; raise when a search exceeds ``budget``.

    A test tool (``tests/test_fingerprint_catalogue.py``), never run at scan
    time: a timing is a fact about the machine as much as about the pattern,
    and a busy sensor must not refuse a sound catalogue. The shape lint in
    ``_bounded`` is what loading enforces; this measures what the lint cannot
    prove, before a pattern ships. A single ``re.search`` holds the GIL and
    cannot be pre-empted by the stage's deadline (checked between
    technologies), which is why that has to happen before, not during, a scan.
    """
    literal = _literals(pattern.pattern)
    units = list(dict.fromkeys(literal[:16] + _STRESS_GENERIC))
    if len(literal) > 1:
        units.append(literal[:-1])
    for unit in units:
        for length in _stress_lengths():
            text = (unit * (length // len(unit) + 1))[:length]
            timings = []
            for _ in range(STRESS_REPEATS):
                start = time.process_time()
                pattern.search(text)
                timings.append(time.process_time() - start)
            took = sorted(timings)[len(timings) // 2]
            if took > budget:
                raise ValueError(
                    f"regex {pattern.pattern!r} took {took:.3f}s on {length} hostile characters (budget {budget}s)"
                )


def _compile(pattern: str) -> re.Pattern[str]:
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"regex {pattern!r} does not compile: {exc}") from exc
    _bounded(pattern)
    return compiled


# ---------------------------------------------------------------- the page


@dataclass(frozen=True)
class Tag:
    name: str
    attrs: tuple[tuple[str, str], ...]

    def get(self, name: str) -> str | None:
        for key, value in self.attrs:
            if key == name:
                return value
        return None


@dataclass(frozen=True)
class Page:
    """What the HTML says, read once."""

    title: str = ""
    tags: tuple[Tag, ...] = ()
    scripts: tuple[str, ...] = ()
    scripts_lower: tuple[str, ...] = ()
    metas: tuple[tuple[str, str], ...] = ()
    generators: tuple[str, ...] = ()
    password_input: bool = False


def _parse_attrs(inner: str) -> tuple[tuple[str, str], ...]:
    """Attributes of one tag, in a single forward pass (no backtracking)."""
    found: list[tuple[str, str]] = []
    i, n = 0, len(inner)
    while i < n and len(found) < MAX_ATTRS:
        name_match = _ATTR_NAME_RE.search(inner, i)
        if name_match is None:
            break
        name = name_match.group(0).lower()
        j = _WS_RE.match(inner, name_match.end()).end()  # type: ignore[union-attr]
        value = ""
        if j < n and inner[j] == "=":
            j = _WS_RE.match(inner, j + 1).end()  # type: ignore[union-attr]
            if j < n and inner[j] in "\"'":
                close = inner.find(inner[j], j + 1)
                end = close if close >= 0 else n
                value = inner[j + 1 : end]
                i = end + 1
            else:
                bare = _BARE_VALUE_RE.match(inner, j)
                value = bare.group(0) if bare else ""
                i = bare.end() if bare and bare.end() > j else j + 1
        else:
            i = max(j, name_match.end())
        found.append((name, html.unescape(value[:MAX_VALUE])))
    return tuple(found)


def parse_page(body: str) -> Page:
    """Tags, title, inline scripts and metas of ``body`` in one linear scan.

    Every step is bounded: a ``<`` with no ``>`` within ``MAX_TAG_LEN`` is not
    a tag, the next ``>`` is found once and reused for every ``<`` before it,
    and at most ``MAX_TAGS`` tags and ``MAX_SCRIPTS`` scripts are kept.
    """
    tags: list[Tag] = []
    scripts: list[str] = []
    title: str | None = None
    n = len(body)
    pos = 0
    gt = -1
    close_dash = close_bang = -1
    while len(tags) < MAX_TAGS:
        lt = body.find("<", pos)
        if lt < 0 or lt + 1 >= n:
            break
        if gt <= lt:
            gt = body.find(">", lt + 1)
            if gt < 0:
                break
        if body.startswith("<!--", lt):
            # A comment is not markup: a <title> or <script> inside it is text.
            # HTML ends one at "-->" or "--!>", and "<!-->" / "<!--->" are
            # complete empty comments. The next closer of each kind is found
            # once and reused, so a page of openers stays linear.
            if body.startswith("<!-->", lt):
                pos = lt + 5
                continue
            if body.startswith("<!--->", lt):
                pos = lt + 6
                continue
            if close_dash <= lt + 4 - 1:
                close_dash = body.find("-->", lt + 4)
                close_dash = n if close_dash < 0 else close_dash
            if close_bang <= lt + 4 - 1:
                close_bang = body.find("--!>", lt + 4)
                close_bang = n if close_bang < 0 else close_bang
            if close_dash == n and close_bang == n:
                break
            pos = close_dash + 3 if close_dash <= close_bang else close_bang + 4
            continue
        name_match = _TAG_NAME_RE.match(body, lt + 1)
        if name_match is None or gt - lt > MAX_TAG_LEN:
            pos = lt + 1
            continue
        name = name_match.group(0).lower()
        tags.append(Tag(name, _parse_attrs(body[name_match.end() : gt])))
        pos = gt + 1
        if name == "title" and title is None:
            close = _TITLE_CLOSE_RE.search(body, pos, min(n, pos + MAX_TITLE_LEN))
            title = " ".join(html.unescape(body[pos : close.start()]).split())[:512] if close else ""
            if close:
                pos = close.end()
        elif name == "script" and len(scripts) < MAX_SCRIPTS:
            # Markup quoted inside a script (a form a SPA draws) is a string,
            # not this page's: step over the whole script to its close. The
            # search either finds the close and moves past it, or reaches the
            # end once and stops the scan, so the walk stays linear.
            close = _SCRIPT_CLOSE_RE.search(body, pos)
            if close is None:
                # The body was cut inside this script (body_max_bytes): what
                # arrived of it is still script text -- Grafana's boot data
                # alone outgrows a 64 KiB read. Nothing after it is markup.
                if n > pos:
                    scripts.append(body[pos : pos + MAX_SCRIPT_LEN])
                break
            if close.start() > pos:
                scripts.append(body[pos : min(close.start(), pos + MAX_SCRIPT_LEN)])
            pos = close.end()
    metas: list[tuple[str, str]] = []
    generators: list[str] = []
    password = False
    for tag in tags:
        if tag.name == "meta":
            key = (tag.get("name") or tag.get("property") or "").strip().lower()
            content = " ".join((tag.get("content") or "").split())
            if key:
                metas.append((key, content))
                if key == "generator" and content:
                    generators.append(content)
        elif tag.name == "input" and (tag.get("type") or "").strip().lower() == "password":
            password = True
    return Page(
        title=title or "",
        tags=tuple(tags),
        scripts=tuple(scripts),
        scripts_lower=tuple(text.lower() for text in scripts),
        metas=tuple(metas),
        generators=tuple(generators),
        password_input=password,
    )


def page_title(body: str) -> str:
    """The first ``<title>``, entity-decoded and whitespace-collapsed ('' if none)."""
    return parse_page(body).title


def meta_generators(body: str) -> tuple[str, ...]:
    """``content`` of every ``<meta name="generator">``, in document order."""
    return parse_page(body).generators


def cookie_names(headers: httpx.Headers) -> frozenset[str]:
    """Lower-cased names of the cookies the response sets. Values are dropped here."""
    names = set()
    for raw in headers.get_list("set-cookie"):
        name, sep, _ = raw.partition("=")
        if sep and name.strip():
            names.add(name.strip().lower())
    return frozenset(names)


def url_path(url: str) -> str:
    """``/path?query`` of ``url``, matrix parameters dropped; '' when unknown."""
    if not url:
        return ""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        return ""
    path = _strip_matrix(parsed.path or "/")
    query = parsed.query.decode("ascii", errors="replace")
    return f"{path}?{query}" if query else path


def _assets(tags: tuple[Tag, ...], page_url: str) -> tuple[str, ...]:
    try:
        base = httpx.URL(page_url) if page_url else None
    except (httpx.InvalidURL, TypeError, ValueError):
        base = None
    base_host = (base.host or "").lower() if base is not None else ""
    base_path = (base.path or "/") if base is not None else "/"
    found: list[str] = []
    for tag in tags:
        attr = _ASSET_ATTRS.get(tag.name)
        raw = (tag.get(attr) or "").strip() if attr else ""
        if not raw or raw.startswith(("#", "data:", "javascript:", "mailto:")):
            continue
        parts = urlsplit(raw if "://" in raw or raw.startswith("//") else urljoin(base_path, raw))
        host = (parts.hostname or "").lower()
        path = _strip_matrix(parts.path or "/")
        if parts.query:
            path = f"{path}?{parts.query}"
        found.append(path if not host or host == base_host else f"//{host}{path}")
    return tuple(value[:MAX_VALUE] for value in found)


@dataclass(frozen=True)
class Response:
    """The one response the stage classifies, pre-digested for matching."""

    status: int
    headers: httpx.Headers
    body: str
    body_lower: str
    page: Page
    cookies: frozenset[str]
    #: Path and query of the URL that answered ('' when unknown).
    url_path: str = ""
    assets: tuple[str, ...] = ()
    is_json: bool = False

    @classmethod
    def build(cls, status: int, headers: httpx.Headers, body: str, url: str = "") -> Response:
        page = parse_page(body)
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        is_json = (content_type == "application/json" or content_type.endswith("+json")) and bool(
            _JSON_START_RE.match(body)
        )
        return cls(
            status=status,
            headers=headers,
            body=body,
            body_lower=body.lower(),
            page=page,
            cookies=cookie_names(headers),
            url_path=url_path(url),
            assets=_assets(page.tags, url),
            is_json=is_json,
        )

    @property
    def title(self) -> str:
        return self.page.title

    @property
    def generators(self) -> tuple[str, ...]:
        return self.page.generators

    def header_value(self, name: str) -> str | None:
        values = self.headers.get_list(name)
        if not values:
            return None
        return ", ".join(values)[:MAX_VALUE]


# ---------------------------------------------------------------- matchers


class Matcher(BaseModel):
    """One condition over the response; see the module docstring for the grammar."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source: Source | None = Field(default=None, alias="from")
    name: str | None = None
    prefix: str | None = None
    tag: str | None = None
    contains: str | None = None
    equals: str | None = None
    regex: str | None = None
    all_of: list[Matcher] | None = Field(default=None, alias="all")
    confidence: Confidence | None = None

    _pattern: re.Pattern[str] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _shape(self) -> Matcher:
        tests = [t for t in (self.contains, self.equals, self.regex) if t is not None]
        if self.all_of is not None:
            if self.source is not None or self.name or self.prefix or self.tag or tests:
                raise ValueError("an 'all' matcher carries only sub-matchers (and a confidence)")
            if len(self.all_of) < 2:
                raise ValueError("an 'all' matcher needs at least two sub-matchers")
            return self
        if self.source is None:
            raise ValueError("a matcher needs 'from' or 'all'")
        if len(tests) > 1:
            raise ValueError("a matcher takes at most one of contains/equals/regex")
        if any(t == "" for t in tests):
            raise ValueError("an empty test matches everything")
        for written in (self.name, self.prefix, self.tag):
            if written is not None and written != written.lower():
                raise ValueError("header, cookie, meta, tag and attribute names are written lower-case")
        if self.prefix is not None and self.source not in ("header", "cookie"):
            raise ValueError(f"a {self.source} matcher takes no prefix")
        if self.tag is not None and self.source != "attr":
            raise ValueError(f"a {self.source} matcher takes no tag")
        if self.source in ("header", "cookie"):
            if (self.name is None) == (self.prefix is None):
                raise ValueError(f"a {self.source} matcher needs exactly one of name/prefix")
            if self.source == "cookie" and tests:
                raise ValueError("cookie matchers test presence only: a cookie value is a secret")
            if self.source == "header" and "set-cookie".startswith(self.name or self.prefix or "-"):
                raise ValueError("Set-Cookie is read through a cookie matcher, which never sees values")
        elif self.source == "meta":
            if self.name is None:
                raise ValueError("a meta matcher names the meta (name or property)")
        elif self.source == "attr":
            if self.tag is None and self.name is None:
                raise ValueError("an attr matcher names a tag, an attribute or both")
            if self.name is None and tests:
                raise ValueError("an attr matcher without an attribute tests the element's presence only")
        else:
            if self.name is not None:
                raise ValueError(f"a {self.source} matcher takes no name")
            if not tests:
                raise ValueError(f"a {self.source} matcher needs contains/equals/regex")
            if self.source in ("body", "script", "json") and self.equals is not None:
                raise ValueError(f"a {self.source} matcher takes contains or regex, not equals")
            if (
                self.source in ("body", "script", "json")
                and self.contains is not None
                and len(self.contains) < MIN_BODY_NEEDLE
            ):
                raise ValueError(f"needle {self.contains!r} is too short to be a marker")
        if self.regex is not None:
            self._pattern = _compile(self.regex)
        return self

    def evaluate(self, resp: Response) -> str | None:
        """Evidence string when this matcher fires, else ``None``."""
        if self.all_of is not None:
            parts = []
            for sub in self.all_of:
                hit = sub.evaluate(resp)
                if hit is None:
                    return None
                parts.append(hit)
            return " + ".join(parts)
        source = self.source
        if source == "header":
            return self._evaluate_header(resp)
        if source == "cookie":
            if self.name is not None:
                return f"cookie {self.name}" if self.name in resp.cookies else None
            assert self.prefix is not None
            hits = sorted(c for c in resp.cookies if c.startswith(self.prefix))
            return f"cookie {hits[0]}" if hits else None
        if source == "status":
            return f"status {resp.status}" if self._test(str(resp.status)) else None
        if source == "url":
            if not resp.url_path or not self._test(resp.url_path):
                return None
            # The path, not the query: a redirect target's query can carry a
            # return URL or a token, and the path is what identified it.
            path, _, query = resp.url_path.partition("?")
            return f'url "{_clip(path, 120)}{"?…" if query else ""}"'
        if source == "title":
            return f'title "{_clip(resp.title)}"' if resp.title and self._test(resp.title) else None
        if source == "generator":
            for generator in resp.generators:
                if self._test(generator):
                    return f'generator "{_clip(generator)}"'
            return None
        if source == "meta":
            for key, content in resp.page.metas:
                if key == self.name and (self._untested or self._test(content)):
                    return _clip(f'meta {key}="{content}"')
            return None
        if source == "asset":
            for asset in resp.assets:
                if self._test(asset):
                    return f'asset "{_clip(asset.partition("?")[0], 120)}"'
            return None
        if source == "attr":
            return self._evaluate_attr(resp)
        if source == "script":
            for text, lowered in zip(resp.page.scripts, resp.page.scripts_lower):
                hit = self._search(text, lowered)
                if hit is not None:
                    return f"script {hit}"
            return None
        if source == "json":
            if not resp.is_json:
                return None
            hit = self._search(resp.body, resp.body_lower)
            return f"json {hit}" if hit is not None else None
        hit = self._search(resp.body, resp.body_lower)
        return f"body {hit}" if hit is not None else None

    @property
    def _untested(self) -> bool:
        return self.contains is None and self.equals is None and self._pattern is None

    def _search(self, text: str, lowered: str) -> str | None:
        if self.contains is not None:
            return f'contains "{self.contains}"' if self.contains.lower() in lowered else None
        assert self._pattern is not None
        found = self._pattern.search(text)
        return f'matches "{_clip(found.group(0), 80)}"' if found else None

    def _evaluate_header(self, resp: Response) -> str | None:
        if self.name is not None:
            names = [self.name]
        else:
            assert self.prefix is not None
            names = sorted({k.lower() for k in resp.headers.keys() if k.lower().startswith(self.prefix)})
        for name in names:
            value = resp.header_value(name)
            if value is None:
                continue
            if self._untested:
                return _clip(f"header {name}: {value}") if value else f"header {name}"
            if self._test(value):
                return _clip(f"header {name}: {value}")
        return None

    def _evaluate_attr(self, resp: Response) -> str | None:
        for tag in resp.page.tags:
            if self.tag is not None and tag.name != self.tag:
                continue
            if self.name is None:
                return f"element <{tag.name}>"
            value = tag.get(self.name)
            if value is None:
                continue
            if self._untested or self._test(value):
                return _clip(f'attr <{tag.name}> {self.name}="{value}"')
        return None

    def _test(self, value: str) -> bool:
        if self.contains is not None:
            return self.contains.lower() in value.lower()
        if self.equals is not None:
            return value.strip().lower() == self.equals.lower()
        assert self._pattern is not None
        return self._pattern.search(value) is not None


class VersionRule(BaseModel):
    """Where a technology states its own version. ``regex`` names a ``version`` group."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source: VersionSource = Field(alias="from")
    name: str | None = None
    regex: str

    _pattern: re.Pattern[str] = PrivateAttr()

    @model_validator(mode="after")
    def _shape(self) -> VersionRule:
        if (self.source in ("header", "meta")) != (self.name is not None):
            raise ValueError("a version rule names a header or meta exactly when it reads one")
        if self.name is not None and self.name != self.name.lower():
            raise ValueError("header and meta names are written lower-case")
        self._pattern = _compile(self.regex)
        if "version" not in self._pattern.groupindex:
            raise ValueError(f"version regex {self.regex!r} has no (?P<version>...) group")
        return self

    def texts(self, resp: Response) -> list[str]:
        if self.source == "header":
            assert self.name is not None
            return [resp.header_value(self.name) or ""]
        if self.source == "meta":
            return [content for key, content in resp.page.metas if key == self.name]
        if self.source == "title":
            return [resp.title]
        if self.source == "generator":
            return list(resp.generators)
        if self.source == "asset":
            return list(resp.assets)
        if self.source == "script":
            return list(resp.page.scripts)
        if self.source == "json":
            return [resp.body] if resp.is_json else []
        return [resp.body]

    def extract(self, resp: Response) -> tuple[str, str] | None:
        """``(version, the text it was read from)``."""
        for text in self.texts(resp):
            found = self._pattern.search(text)
            if found and found.group("version") and _VERSION_RE.match(found.group("version")):
                return found.group("version"), text
        return None

    @property
    def label(self) -> str:
        return f"{self.source} {self.name}" if self.name is not None else self.source


class Technology(BaseModel):
    """One catalogue entry."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: Category
    confidence: Confidence = "medium"
    #: ``part:vendor:product`` verified against the NVD CPE dictionary. Left
    #: out rather than guessed: a wrong key is a wrong CVE list later.
    cpe: str | None = None
    #: False where the version the product shows is not the one NVD files it
    #: under (Exchange and SharePoint builds, MiniServ's shared numbering).
    version_in_cpe: bool = True
    #: The root is served to anybody whether or not the product enforces a
    #: login behind it -- a single-page app shell (Argo CD, Portainer, Harbor,
    #: Kubernetes Dashboard), a welcome page (Keycloak, vCenter), CouchDB's
    #: welcome document. ``fingerprint.py`` rates such a root "reachable,
    #: authentication not determinable" rather than open.
    root_is_public: bool = False
    match: list[Matcher] = Field(min_length=1)
    version: list[VersionRule] = Field(default_factory=list)
    note: str | None = None

    @model_validator(mode="after")
    def _shape(self) -> Technology:
        if not _ID_RE.match(self.id):
            raise ValueError(f"technology id {self.id!r} must be lower-case [a-z0-9_]")
        if self.cpe is not None and not _CPE_KEY_RE.match(self.cpe):
            raise ValueError(f"cpe {self.cpe!r} is not part:vendor:product")
        return self


class Catalogue(BaseModel):
    """The whole file."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal[1] = Field(alias="schema")
    updated: str
    note: str
    technologies: list[Technology] = Field(min_length=1)
    #: Entries ``load_catalogue`` dropped, ``{"id", "error"}`` -- recorded in
    #: ``fingerprint.json`` rather than failing the run.
    rejected: list[dict[str, str]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> Catalogue:
        seen: set[str] = set()
        for tech in self.technologies:
            if tech.id in seen:
                raise ValueError(f"technology id {tech.id!r} appears twice")
            seen.add(tech.id)
        return self

    def patterns(self) -> list[re.Pattern[str]]:
        """Every compiled regex in the catalogue, matchers and version rules."""
        found: list[re.Pattern[str]] = []

        def walk(matchers: list[Matcher]) -> None:
            for matcher in matchers:
                if matcher.all_of is not None:
                    walk(matcher.all_of)
                elif matcher._pattern is not None:
                    found.append(matcher._pattern)

        for tech in self.technologies:
            walk(tech.match)
            found.extend(rule._pattern for rule in tech.version)
        return found

    def classify(
        self,
        status: int,
        headers: httpx.Headers,
        body: str,
        url: str = "",
        *,
        deadline: float | None = None,
    ) -> list[Match]:
        """Every technology the response identifies, in catalogue order.

        ``deadline`` is a ``time.monotonic()`` instant; past it the remaining
        technologies are not tried and :class:`ClassificationTimeout` is raised.
        """
        return self.match_response(Response.build(status, headers, body, url), deadline=deadline)

    def match_response(self, resp: Response, *, deadline: float | None = None) -> list[Match]:
        """``classify`` for a response already built (``fingerprint.py`` keeps the page)."""
        found = []
        for tech in self.technologies:
            if deadline is not None and time.monotonic() > deadline:
                raise ClassificationTimeout(f"stopped before {tech.id}")
            hit = match_technology(tech, resp)
            if hit is not None:
                found.append(hit)
        return found


@dataclass(frozen=True)
class Match:
    technology: Technology
    confidence: str
    evidence: tuple[str, ...]
    version: str | None = None
    #: ``header x-jenkins`` / ``generator`` / ``json`` / ...
    version_source: str | None = None
    #: The distribution named next to a header-stated version, and that header.
    distro_hint: str | None = None
    banner: str | None = None

    @property
    def cpe(self) -> str | None:
        if self.technology.cpe is None:
            return None
        version = self.version if self.technology.version_in_cpe and self.distro_hint is None else None
        return cpe_name(self.technology.cpe, version)

    def as_dict(self) -> dict[str, Any]:
        out = {
            "id": self.technology.id,
            "name": self.technology.name,
            "category": self.technology.category,
            "version": self.version,
            "cpe": self.cpe,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }
        if self.distro_hint is not None:
            out["distro_hint"] = self.distro_hint
            out["banner"] = self.banner
        return out


def distro_of(text: str) -> str | None:
    """The distribution a banner names (``Apache/2.4.52 (Ubuntu)``), if any."""
    found = _DISTRO_RE.search(text)
    if found is None:
        return None
    token = found.group(1).lower().lstrip("+~-")
    for prefix, name in _DISTRO_NAMES:
        if token.startswith(prefix):
            return name
    return token


def match_technology(tech: Technology, resp: Response) -> Match | None:
    evidence: list[str] = []
    best = 0
    for matcher in tech.match:
        hit = matcher.evaluate(resp)
        if hit is None:
            continue
        evidence.append(hit)
        best = max(best, CONFIDENCE_RANK[matcher.confidence or tech.confidence])
    if not evidence:
        return None
    version = version_source = distro = banner = None
    for rule in tech.version:
        extracted = rule.extract(resp)
        if extracted is not None:
            version, text = extracted
            version_source = rule.label
            if rule.source == "header":
                distro = distro_of(text)
                banner = _clip(text) if distro else None
            break
    confidence = next(name for name, rank in CONFIDENCE_RANK.items() if rank == best)
    return Match(
        technology=tech,
        confidence=confidence,
        evidence=tuple(evidence[:MAX_EVIDENCE_ITEMS]),
        version=version,
        version_source=version_source,
        distro_hint=distro,
        banner=banner,
    )


_CPE_SPECIAL = re.compile(r"([^A-Za-z0-9._-])")


def cpe_name(key: str, version: str | None) -> str:
    """CPE 2.3 formatted string for ``part:vendor:product`` and an optional version.

    ``retro_match.parse_cpe`` reads this form back, so a later step can hand
    these to the NVD range matcher unchanged.
    """
    escaped = _CPE_SPECIAL.sub(r"\\\1", version) if version else "*"
    return f"cpe:2.3:{key}:{escaped}:*:*:*:*:*:*:*"


def _empty_catalogue(rejected: list[dict[str, str]]) -> Catalogue:
    return Catalogue.model_construct(schema_version=1, updated="", note="", technologies=[], rejected=rejected)


@functools.lru_cache(maxsize=1)
def load_catalogue(path: Path = CATALOGUE_PATH) -> Catalogue:
    """The catalogue, entry by entry: a broken entry is dropped, never the run.

    Each technology is validated on its own (schema and the regex shape
    lint, both deterministic). One that fails is logged, left out and listed
    in ``rejected``, which the stage writes into ``fingerprint.json``; a
    duplicate id keeps the first. An unreadable file leaves an empty
    catalogue -- the stage then identifies nothing and says why -- because a
    catalogue problem is a bug to fix, not a reason to lose the rest of the
    scan. The tests hold the shipped file to zero rejections.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("technologies"), list):
            raise ValueError("no technologies list")
    except (OSError, ValueError) as exc:
        LOG.error("fingerprint catalogue %s unusable, nothing will be identified: %s", path, exc)
        return _empty_catalogue([{"id": "", "error": _clip(f"catalogue unusable: {exc}", 300)}])
    kept: list[Technology] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in raw["technologies"]:
        tid = str(entry.get("id") or "") if isinstance(entry, dict) else ""
        try:
            tech = Technology.model_validate(entry)
            if tech.id in seen:
                raise ValueError(f"technology id {tech.id!r} appears twice")
        except Exception as exc:  # noqa: BLE001 - one bad entry is dropped and reported, not fatal to the run
            LOG.error("fingerprint catalogue: entry %r dropped: %s", tid, exc)
            rejected.append({"id": tid, "error": _clip(str(exc), 300)})
            continue
        seen.add(tech.id)
        kept.append(tech)
    if not kept:
        return _empty_catalogue(rejected)
    try:
        return Catalogue.model_validate(
            {
                "schema": raw.get("schema"),
                "updated": raw.get("updated", ""),
                "note": raw.get("note", ""),
                "technologies": kept,
                "rejected": rejected,
            }
        )
    except ValueError as exc:
        LOG.error("fingerprint catalogue %s header unusable, nothing will be identified: %s", path, exc)
        return _empty_catalogue([*rejected, {"id": "", "error": _clip(f"catalogue header: {exc}", 300)}])
