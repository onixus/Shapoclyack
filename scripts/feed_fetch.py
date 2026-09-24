#!/usr/bin/env python3
"""One download path for every enrichment feed script (#339).

The feed scripts used to fetch in three different ways: ``curl`` in the shell
fetchers, bare ``urllib.request.urlopen`` in ``fetch-cvss4-db.py`` and
``fetch-exploit-db.py``, and ``api/services/egress.py`` in the advisory and NVD
CPE fetchers. Only the last honoured ``OCTO_HTTPS_PROXY`` / ``OCTO_NO_PROXY`` /
``OCTO_CA_BUNDLE`` (#359), and only two of the eleven upstream URLs could be
pointed at a mirror at all. On a network whose only way out is an inspecting
proxy, or one with no way out and an internal mirror instead, that is the
difference between a refresh that works and one that fails half the feeds.

So every script now downloads through here, and this goes through the same
egress module as the API:

* **Mirror overrides.** :func:`feed_url` reads one variable per upstream
  (``EPSS_URL``, ``NVD_API_URL``, ...; the table is in docs/air-gap.md) and
  falls back to the public URL. ``https``, ``http`` and ``file`` are accepted —
  a mounted directory is a perfectly good mirror — and anything else is refused
  by name rather than handed to a handler nobody meant to enable.
* **Proxy and trust store.** ``api.services.egress.build_opener`` where the API
  package is installed; ``agent.egress`` otherwise. The scanner image ships
  ``agent/`` and not ``api/``, and the agent module is the declared
  byte-for-byte mirror of the API's (tests/test_agent_proxy_ca.py holds the two
  together), so the choice changes nothing but the import. ``OCTO_CA_BUNDLE`` is
  *added to* the system store and verification is never turned off.
* **No downgrade.** A redirect from ``https`` to anything else is refused. The
  default ``urllib`` handler follows it, and a mirror that bounces a feed to
  plain HTTP has just handed the content to anyone on the path.
* **Bounded.** A socket timeout, a wall-clock deadline for the whole body (the
  NVD trickle described in fetch-cvss4-db.py is not unique to NVD) and a byte
  ceiling enforced while streaming.
* **No secrets in logs or data.** :func:`redact_url` drops userinfo and blanks
  credential-looking query parameters — the MaxMind download URL carries the
  licence key in its query string — before a URL is printed or recorded.

Usage (the shell fetchers call it like this)::

    python3 scripts/feed_fetch.py get "$URL" -o /tmp/feed.csv.gz
    python3 scripts/feed_fetch.py mmdb /tmp/download -o geoip.mmdb --edition GeoLite2-City
    python3 scripts/feed_fetch.py ca-bundle -o /tmp/ca.pem    # for git (nuclei-templates)
    python3 scripts/feed_fetch.py redact "$URL"               # safe to print
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import ssl
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Run as a script, sys.path[0] is scripts/ — not the repo root — so neither
# `api` nor `agent` beside it is importable. Same fix as fetch-cvss4-db.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from api.services import egress
except ImportError:  # the scanner image carries agent/ but not api/
    from agent import egress  # type: ignore[no-redef]

#: Schemes a feed URL may use. ``file`` is how a mirror mounted into the pod,
#: or a directory copied off removable media, is named.
ALLOWED_SCHEMES = ("https", "http", "file")

DEFAULT_TIMEOUT_SECONDS = 60.0
#: Whole-body wall-clock ceiling; see the module docstring.
DEFAULT_DEADLINE_SECONDS = 900.0
#: Several times the largest feed (the GeoIP City database): the ceiling is
#: there to stop a runaway, not to size a feed.
DEFAULT_MAX_BYTES = 512 * 1024 * 1024

USER_AGENT = "shapoclyack-feed-fetch"

#: Query parameters whose values are credentials. Matched as substrings of the
#: parameter name, case-insensitively: ``license_key``, ``apiKey``, ``token``,
#: ``X-Amz-Signature``...
_SECRET_PARAM = re.compile(r"key|token|secret|passw|signature|sig$|auth", re.IGNORECASE)
REDACTED = "REDACTED"

#: A City database is well under this unpacked; a gzip that expands past it
#: is not one.
MMDB_MAX_BYTES = 1024 * 1024 * 1024

#: The marker the MaxMind DB format puts in front of its metadata section.
#: Present in every .mmdb (MaxMind and DB-IP alike) and in nothing that is not
#: one: an HTML error page served with a 200 has no business passing for a
#: database.
MMDB_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class FeedError(RuntimeError):
    """A feed could not be fetched or is not what it claims to be."""


class FeedURLError(FeedError, ValueError):
    """A feed URL names a scheme no fetcher here opens. A ``ValueError`` too,
    like ``api.services.advisories.fetch.FeedURLError``: it is configuration."""


def redact_url(url: str) -> str:
    """``url`` with userinfo dropped and credential query values blanked."""
    parts = urlsplit((url or "").strip())
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port else host
    query = urlencode(
        [
            (name, REDACTED if _SECRET_PARAM.search(name) else value)
            for name, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def check_url(url: str, *, variable: str | None = None) -> str:
    """Refuse a URL whose scheme is not one a feed may use."""
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        where = f"{variable}=" if variable else ""
        raise FeedURLError(
            f"{where}{redact_url(url)}: unsupported scheme {scheme or '(none)'!r}; "
            f"a feed URL must be one of {', '.join(ALLOWED_SCHEMES)}"
        )
    return url


def feed_url(variable: str, default: str) -> str:
    """The URL a feed is fetched from: ``$variable`` if set, else ``default``.

    Read when called, not at import, so a value set after the module loaded —
    by a test, or by the caller of a long-running process — is the one used.
    """
    raw = os.environ.get(variable, "").strip()
    return check_url(raw or default, variable=variable if raw else None)


class _NoDowngradeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never from ``https`` to anything weaker."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        old = urlsplit(req.full_url).scheme.lower()
        new = urlsplit(newurl).scheme.lower()
        allowed = ("https",) if old == "https" else ("http", "https")
        if new not in allowed:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"refusing redirect from {old} to {new} ({redact_url(newurl)})",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener_for(url: str) -> urllib.request.OpenerDirector:
    """This process's proxy and trust store for ``url``, and no downgrades."""
    return egress.build_opener(check_url(url), _NoDowngradeRedirect())


def urlopen(request: urllib.request.Request | str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS):
    """``urllib.request.urlopen`` through :func:`opener_for`."""
    if isinstance(request, str):
        request = urllib.request.Request(request, headers={"User-Agent": USER_AGENT})
    return opener_for(request.full_url).open(request, timeout=timeout)  # noqa: S310 - scheme checked


def read_bounded(
    response,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    sink=None,
) -> int:
    """Copy a response body to ``sink`` (or discard it), within both bounds."""
    deadline = time.monotonic() + deadline_seconds
    total = 0
    while True:
        chunk = response.read(256 * 1024)
        if not chunk:
            return total
        total += len(chunk)
        if total > max_bytes:
            raise FeedError(f"response exceeded the {max_bytes} byte ceiling; aborted")
        if time.monotonic() > deadline:
            raise FeedError(f"response body exceeded {deadline_seconds:.0f}s ({total} bytes read)")
        if sink is not None:
            sink.write(chunk)


def download(
    url: str,
    dest: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> int:
    """Fetch ``url`` to ``dest`` (written beside it, then renamed). Returns bytes."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response, partial.open("wb") as sink:
            size = read_bounded(
                response, max_bytes=max_bytes, deadline_seconds=deadline_seconds, sink=sink
            )
        if size == 0:
            raise FeedError("empty response")
        partial.replace(dest)
        return size
    finally:
        partial.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# .mmdb unpacking (GeoIP / ASN)
# --------------------------------------------------------------------------


def looks_like_mmdb(data: bytes) -> bool:
    # The metadata section sits in the last 128 KiB of the file by the format's
    # own definition, which is where the reader looks for it too.
    return MMDB_METADATA_MARKER in data[-128 * 1024 :]


def unpack_mmdb(src: Path, dest: Path, *, edition: str | None = None) -> None:
    """Write the MaxMind DB inside ``src`` to ``dest``.

    ``src`` may be the database itself, a gzip of it (DB-IP's ``.mmdb.gz``) or a
    gzipped tarball holding one (MaxMind's ``.tar.gz``), so one ``GEOIP_URL`` can
    name whichever of the three a mirror keeps. Only a *regular file* member
    whose name ends in ``.mmdb`` (and, with ``edition``, is that edition) is ever
    read out of a tarball, and nothing is extracted to disk by name: the member's
    bytes are read and validated, so a link or a ``../`` in an archive from a
    mirror cannot write anywhere.
    """
    raw = src.read_bytes()
    data = raw
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as unzipped:
            data = unzipped.read(MMDB_MAX_BYTES + 1)
        if len(data) > MMDB_MAX_BYTES:
            raise FeedError(f"{src.name} expands past {MMDB_MAX_BYTES} bytes; refusing")
    # A tarball is recognised by its ustar magic, not by failing the .mmdb
    # check: the database inside it carries the metadata marker too, and a
    # tarball taken for a database is a corrupt GeoIP file that "passed".
    if data[257:262] == b"ustar":
        try:
            archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        except tarfile.TarError as exc:
            raise FeedError(f"{src.name} is neither a MaxMind DB nor a tarball holding one") from exc
        wanted = f"{edition}.mmdb" if edition else None
        found: bytes | None = None
        with archive:
            for member in archive:
                name = member.name.rsplit("/", 1)[-1]
                if not member.isfile() or not name.endswith(".mmdb"):
                    continue
                if wanted and name != wanted:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                found = handle.read()
                break
        if found is None:
            raise FeedError(f"no {wanted or '*.mmdb'} regular file in {src.name}")
        data = found
    if not looks_like_mmdb(data):
        raise FeedError(f"{src.name} does not hold a MaxMind DB (no metadata marker)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_bytes(data)
    try:
        _open_mmdb(tmp)
    except Exception as exc:  # noqa: BLE001 - any reader failure is "not a database"
        tmp.unlink(missing_ok=True)
        raise FeedError(f"{src.name} does not hold a readable MaxMind DB: {exc}") from exc
    tmp.replace(dest)


def _open_mmdb(path: Path) -> None:
    """Have the real reader parse the metadata, where the images ship it.

    ``maxminddb`` comes with ``geoip2`` (requirements.txt); a host that runs
    this script without it still gets the marker check above.
    """
    try:
        import maxminddb  # noqa: PLC0415 - optional, see docstring
    except ImportError:
        return
    with maxminddb.open_database(str(path)) as reader:
        reader.metadata()


# --------------------------------------------------------------------------
# A CA file for tools that replace the trust store instead of adding to it
# --------------------------------------------------------------------------


def system_ca_file() -> Path | None:
    """The OpenSSL default CA file this Python was built against, if present."""
    paths = ssl.get_default_verify_paths()
    for candidate in (paths.cafile, paths.openssl_cafile):
        if candidate and os.path.isfile(candidate):
            return Path(candidate)
    return None


def write_ca_bundle(out: Path) -> Path | None:
    """System store + ``OCTO_CA_BUNDLE`` in one PEM file, or ``None`` if unset.

    git's ``GIT_SSL_CAINFO`` (and curl's ``--cacert``) *replace* the trust
    store, where ``OCTO_CA_BUNDLE`` is defined as an *addition* to it (#359).
    Handing git the concatenation keeps that meaning: the internal root is
    trusted and so is everything the system already trusted.
    """
    bundle = egress.ca_bundle()
    if not bundle:
        return None
    parts: list[bytes] = []
    system = system_ca_file()
    if system is not None:
        parts.append(system.read_bytes())
    parts.append(Path(bundle).read_bytes())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\n".join(parts))
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _cmd_get(args: argparse.Namespace) -> int:
    try:
        size = download(
            check_url(args.url),
            args.output,
            timeout=args.timeout,
            deadline_seconds=args.deadline,
            max_bytes=args.max_bytes,
        )
    except (FeedError, OSError, ValueError, egress.EgressConfigError) as exc:
        # URLError/HTTPError are OSError subclasses. The message may embed the
        # URL, so it is the redacted one that is printed, never the raw.
        message = str(exc).replace(args.url, redact_url(args.url))
        print(f"error: {redact_url(args.url)}: {message}", file=sys.stderr)
        return 1
    if urlsplit(args.url).scheme == "http":
        print(
            f"warning: {redact_url(args.url)} is plain http; nothing vouches for "
            "these bytes on the way (prefer https with OCTO_CA_BUNDLE)",
            file=sys.stderr,
        )
    print(f"fetched {size} bytes from {redact_url(args.url)}")
    return 0


def _cmd_mmdb(args: argparse.Namespace) -> int:
    try:
        unpack_mmdb(args.source, args.output, edition=args.edition)
    except (FeedError, OSError, EOFError, gzip.BadGzipFile, tarfile.TarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_redact(args: argparse.Namespace) -> int:
    print(redact_url(args.url))
    return 0


def _cmd_ca_bundle(args: argparse.Namespace) -> int:
    try:
        written = write_ca_bundle(args.output)
    except (OSError, egress.EgressConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    # 3, not 0: "there is nothing to add" is not the same as "here is a file",
    # and the caller must not point a tool at a path that was never written.
    return 0 if written else 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    get = sub.add_parser("get", help="download one URL to a file")
    get.add_argument("url")
    get.add_argument("-o", "--output", type=Path, required=True)
    get.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    get.add_argument("--deadline", type=float, default=DEFAULT_DEADLINE_SECONDS)
    get.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    get.set_defaults(func=_cmd_get)

    mmdb = sub.add_parser("mmdb", help="extract and validate a MaxMind DB")
    mmdb.add_argument("source", type=Path)
    mmdb.add_argument("-o", "--output", type=Path, required=True)
    mmdb.add_argument("--edition", default=None, help="e.g. GeoLite2-City: pick this .mmdb out of a tarball")
    mmdb.set_defaults(func=_cmd_mmdb)

    redact = sub.add_parser("redact", help="print a URL with its credentials removed")
    redact.add_argument("url")
    redact.set_defaults(func=_cmd_redact)

    ca = sub.add_parser("ca-bundle", help="system store + OCTO_CA_BUNDLE, for tools that replace the store")
    ca.add_argument("-o", "--output", type=Path, default=Path(tempfile.gettempdir()) / "shapoclyack-ca.pem")
    ca.set_defaults(func=_cmd_ca_bundle)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
