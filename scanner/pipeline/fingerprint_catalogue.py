"""Web technology catalogue for ``fingerprint.py`` (DQ4).

The stage makes one GET per open web port; this module decides what that one
response says. The knowledge lives in ``fingerprint_catalogue.json`` next to
this file -- data, not code, so adding a product is a reviewed JSON entry plus
a fixture, never a new lambda. It sits next to the module rather than under
``scanner/data`` for the reason ``public_suffix.py`` gives: the images mount
the shared enrichment volume over ``scanner/data``, and a volume seeded before
this file existed would hide it.

Every entry names a technology, its category, the matchers that identify it,
optionally how to read its version, and optionally its NVD CPE
``part:vendor:product``. The file is validated when it is loaded (pydantic,
``extra="forbid"``): an unknown category, a regex that does not compile, a
version rule without a ``version`` group or a matcher that reads a cookie's
value is refused instead of silently matching nothing.

Matchers
--------
``{"from": <source>, ...}`` with one source and at most one test:

* ``header`` -- ``name`` or ``prefix`` (header names, case-insensitive); with
  no test the header's presence is the match, else ``contains`` / ``equals``
  / ``regex`` against its value;
* ``cookie`` -- ``name`` or ``prefix`` of a ``Set-Cookie`` name. Presence only:
  a cookie's value is a session secret and is never read or reported;
* ``body`` -- ``contains`` or ``regex`` over the (size-capped) body;
* ``title`` -- ``equals`` / ``contains`` / ``regex`` over the ``<title>`` text;
* ``generator`` -- the same tests over each ``<meta name="generator">``;
* ``url`` -- the same tests over the path (and query) the response came from
  once redirects were followed: a root that redirects to
  ``/dana-na/auth/url_default/welcome.cgi`` has said what it is.

``{"all": [...]}`` is a conjunction for markers that are only specific
together. All comparisons ignore case. A matcher may override the entry's
``confidence``; a technology's confidence is the best of the matchers that
fired. There are two levels on purpose: ``high`` (the product says so itself
-- its own header, cookie or exact page title) and ``medium`` (strong, but a
shared component or a reverse proxy could produce it). Anything weaker is not
a signature and has no place here.

What this is not: it never sends a request, never follows a link and never
looks at anything but the response ``fingerprint.py`` already fetched. Body
markers are paths, element ids and script variables -- never a product name
on its own, because a blog post about Jenkins is not Jenkins -- and the
paths of the most consequential products are anchored to a quote (``["']/dana-na/``)
so an intranet page *linking* to the VPN is not taken for the VPN. The negative
corpus in ``tests/fixtures/fingerprint/web_responses.json`` holds the catalogue
to that.
"""

from __future__ import annotations

import functools
import html
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, get_args

import httpx
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

CATALOGUE_PATH = Path(__file__).with_name("fingerprint_catalogue.json")

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

#: Body needles shorter than this are words, not markers.
MIN_BODY_NEEDLE = 5
#: A disclosed version is a short dotted token that starts with a digit.
#: Anything else a version regex captured is a mis-anchored rule, not a version.
_VERSION_RE = re.compile(r"^\d[0-9A-Za-z.+~_-]{0,39}$")
#: ``part:vendor:product`` as NVD writes it, CPE 2.3 escapes (``joomla\!``) kept.
_CPE_KEY_RE = re.compile(r"^[aho]:(?:[a-z0-9._~-]|\\[^a-z0-9])+:(?:[a-z0-9._~-]|\\[^a-z0-9])+$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_]{1,47}$")

#: Evidence strings are for a human reading a finding, not a copy of the
#: response: header values and titles are cut, bodies are never quoted beyond
#: the marker itself.
EVIDENCE_MAX = 160
MAX_EVIDENCE_ITEMS = 5

_TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_META_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""")


def _clip(text: str, limit: int = EVIDENCE_MAX) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _compile(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"regex {pattern!r} does not compile: {exc}") from exc


@dataclass(frozen=True)
class Response:
    """The one response the stage fetched, pre-digested for matching."""

    status: int
    headers: httpx.Headers
    body: str
    body_lower: str
    title: str
    generators: tuple[str, ...]
    cookies: frozenset[str]
    #: Path and query of the URL that answered ('' when unknown).
    url_path: str = ""

    @classmethod
    def build(cls, status: int, headers: httpx.Headers, body: str, url: str = "") -> Response:
        return cls(
            status=status,
            headers=headers,
            body=body,
            body_lower=body.lower(),
            title=page_title(body),
            generators=meta_generators(body),
            cookies=cookie_names(headers),
            url_path=url_path(url),
        )

    def header_value(self, name: str) -> str | None:
        values = self.headers.get_list(name)
        if not values:
            return None
        return ", ".join(values)


def url_path(url: str) -> str:
    """``/path?query`` of ``url``; '' for an empty or unparsable one."""
    if not url:
        return ""
    try:
        return httpx.URL(url).raw_path.decode("ascii", errors="replace")
    except (httpx.InvalidURL, TypeError, ValueError):
        return ""


def page_title(body: str) -> str:
    """The first ``<title>``, entity-decoded and whitespace-collapsed ('' if none)."""
    match = _TITLE_RE.search(body)
    if match is None:
        return ""
    return " ".join(html.unescape(match.group(1)).split())[:512]


def meta_generators(body: str) -> tuple[str, ...]:
    """``content`` of every ``<meta name="generator">``, in document order."""
    found: list[str] = []
    for tag in _META_RE.findall(body):
        attrs: dict[str, str] = {}
        for name, dq, sq, bare in _ATTR_RE.findall(tag):
            attrs[name.lower()] = html.unescape(dq or sq or bare)
        if attrs.get("name", "").strip().lower() == "generator" and attrs.get("content", "").strip():
            found.append(" ".join(attrs["content"].split()))
    return tuple(found)


def cookie_names(headers: httpx.Headers) -> frozenset[str]:
    """Lower-cased names of the cookies the response sets. Values are dropped here."""
    names = set()
    for raw in headers.get_list("set-cookie"):
        name, sep, _ = raw.partition("=")
        if sep and name.strip():
            names.add(name.strip().lower())
    return frozenset(names)


class Matcher(BaseModel):
    """One condition over the response; see the module docstring for the grammar."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source: Literal["header", "cookie", "body", "title", "generator", "url"] | None = Field(
        default=None, alias="from"
    )
    name: str | None = None
    prefix: str | None = None
    contains: str | None = None
    equals: str | None = None
    regex: str | None = None
    all_of: list[Matcher] | None = Field(default=None, alias="all")
    confidence: Confidence | None = None

    _pattern: re.Pattern[str] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _shape(self) -> Matcher:
        selectors = (self.name, self.prefix)
        tests = [t for t in (self.contains, self.equals, self.regex) if t is not None]
        if self.all_of is not None:
            if self.source is not None or any(s is not None for s in selectors) or tests:
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
        if self.source in ("header", "cookie"):
            if (self.name is None) == (self.prefix is None):
                raise ValueError(f"a {self.source} matcher needs exactly one of name/prefix")
            if self.source == "cookie" and tests:
                raise ValueError("cookie matchers test presence only: a cookie value is a secret")
            if (self.name or self.prefix or "") != (self.name or self.prefix or "").lower():
                raise ValueError("header and cookie names are written lower-case")
            if self.source == "header" and "set-cookie".startswith(self.name or self.prefix or "-"):
                raise ValueError("Set-Cookie is read through a cookie matcher, which never sees values")
        else:
            if any(s is not None for s in selectors):
                raise ValueError(f"a {self.source} matcher takes no name/prefix")
            if not tests:
                raise ValueError(f"a {self.source} matcher needs contains/equals/regex")
            if self.source == "body" and self.equals is not None:
                raise ValueError("a body matcher takes contains or regex, not equals")
            if self.source == "body" and self.contains is not None and len(self.contains) < MIN_BODY_NEEDLE:
                raise ValueError(f"body needle {self.contains!r} is too short to be a marker")
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
        if self.source == "header":
            return self._evaluate_header(resp)
        if self.source == "cookie":
            if self.name is not None:
                return f"cookie {self.name}" if self.name in resp.cookies else None
            assert self.prefix is not None
            hits = sorted(c for c in resp.cookies if c.startswith(self.prefix))
            return f"cookie {hits[0]}" if hits else None
        if self.source == "body":
            if self.contains is not None:
                return f'body contains "{self.contains}"' if self.contains.lower() in resp.body_lower else None
            assert self._pattern is not None
            found = self._pattern.search(resp.body)
            return f'body matches "{_clip(found.group(0), 80)}"' if found else None
        if self.source == "title":
            return f'title "{_clip(resp.title)}"' if resp.title and self._test(resp.title) else None
        if self.source == "url":
            if not resp.url_path or not self._test(resp.url_path):
                return None
            # The path, not the query: a redirect target's query can carry a
            # return URL or a token, and the path is what identified it.
            path, _, query = resp.url_path.partition("?")
            return f'url "{_clip(path, 120)}{"?…" if query else ""}"'
        for generator in resp.generators:
            if self._test(generator):
                return f'generator "{_clip(generator)}"'
        return None

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
            if self.contains is None and self.equals is None and self._pattern is None:
                return _clip(f"header {name}: {value}") if value else f"header {name}"
            if self._test(value):
                return _clip(f"header {name}: {value}")
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

    source: Literal["header", "body", "title", "generator"] = Field(alias="from")
    name: str | None = None
    regex: str

    _pattern: re.Pattern[str] = PrivateAttr()

    @model_validator(mode="after")
    def _shape(self) -> VersionRule:
        if (self.source == "header") != (self.name is not None):
            raise ValueError("a version rule names a header exactly when it reads one")
        if self.name is not None and self.name != self.name.lower():
            raise ValueError("header names are written lower-case")
        self._pattern = _compile(self.regex)
        if "version" not in self._pattern.groupindex:
            raise ValueError(f"version regex {self.regex!r} has no (?P<version>...) group")
        return self

    def extract(self, resp: Response) -> str | None:
        if self.source == "header":
            assert self.name is not None
            texts = [resp.header_value(self.name) or ""]
        elif self.source == "body":
            texts = [resp.body]
        elif self.source == "title":
            texts = [resp.title]
        else:
            texts = list(resp.generators)
        for text in texts:
            found = self._pattern.search(text)
            if found and found.group("version") and _VERSION_RE.match(found.group("version")):
                return found.group("version")
        return None

    @property
    def label(self) -> str:
        return f"header {self.name}" if self.source == "header" else self.source


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

    @model_validator(mode="after")
    def _unique(self) -> Catalogue:
        seen: set[str] = set()
        for tech in self.technologies:
            if tech.id in seen:
                raise ValueError(f"technology id {tech.id!r} appears twice")
            seen.add(tech.id)
        return self

    def classify(self, status: int, headers: httpx.Headers, body: str, url: str = "") -> list[Match]:
        """Every technology the response identifies, in catalogue order."""
        resp = Response.build(status, headers, body, url)
        found = []
        for tech in self.technologies:
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
    #: ``header x-jenkins`` / ``body`` / ``title`` / ``generator``.
    version_source: str | None = None

    @property
    def cpe(self) -> str | None:
        if self.technology.cpe is None:
            return None
        version = self.version if self.technology.version_in_cpe else None
        return cpe_name(self.technology.cpe, version)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.technology.id,
            "name": self.technology.name,
            "category": self.technology.category,
            "version": self.version,
            "cpe": self.cpe,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


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
    version = version_source = None
    for rule in tech.version:
        version = rule.extract(resp)
        if version is not None:
            version_source = rule.label
            break
    confidence = next(name for name, rank in CONFIDENCE_RANK.items() if rank == best)
    return Match(
        technology=tech,
        confidence=confidence,
        evidence=tuple(evidence[:MAX_EVIDENCE_ITEMS]),
        version=version,
        version_source=version_source,
    )


_CPE_SPECIAL = re.compile(r"([^A-Za-z0-9._-])")


def cpe_name(key: str, version: str | None) -> str:
    """CPE 2.3 formatted string for ``part:vendor:product`` and an optional version.

    ``retro_match.parse_cpe`` reads this form back, so a later step can hand
    these to the NVD range matcher unchanged.
    """
    escaped = _CPE_SPECIAL.sub(r"\\\1", version) if version else "*"
    return f"cpe:2.3:{key}:{escaped}:*:*:*:*:*:*:*"


@functools.lru_cache(maxsize=1)
def load_catalogue(path: Path = CATALOGUE_PATH) -> Catalogue:
    """The validated catalogue. A broken file raises (``pydantic.ValidationError``)."""
    return Catalogue.model_validate_json(path.read_text(encoding="utf-8"))
