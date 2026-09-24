"""Every enrichment feed can be pointed at a mirror, and nothing phones home (#339).

Before this, three of the eleven upstream URLs could be overridden and none of
the fetchers but the advisory ones went through the proxy/CA settings of #359.
An air-gapped or proxy-only site therefore lost half its feeds with nothing to
configure. These tests drive each fetcher — the shell scripts, the Python
scripts and the in-process fetchers — at a loopback server, a ``file://``
directory or an injected opener, and check that it went where it was told and
recorded that without the credentials. No test here opens a socket beyond
127.0.0.1.
"""

from __future__ import annotations

import ast
import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from api.services import cpe_ranges_fetch
from api.services.advisories import fetch as advisory_fetch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import feed_fetch  # noqa: E402 - needs the path above

GEOIP_FIXTURE = REPO_ROOT / "tests" / "data" / "geoip" / "GeoIP2-City-Test.mmdb"
ADVISORY_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "advisories"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _Mirror(ThreadingHTTPServer):
    files: dict[str, bytes]
    requests: list[str]

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


@pytest.fixture()
def mirror():
    """A loopback HTTP mirror: path → bytes, recording every request."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server hook
            server = self.server
            server.requests.append(self.path)  # type: ignore[attr-defined]
            body = server.files.get(urlsplit(self.path).path)  # type: ignore[attr-defined]
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            return

    server = _Mirror(("127.0.0.1", 0), Handler)
    server.files = {}
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _env(**extra: str) -> dict[str, str]:
    """The test process's environment minus every proxy and OCTO_ setting.

    Loopback only: OCTO_NO_PROXY keeps an ambient proxy (this container has
    one) from being asked for 127.0.0.1.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in ("https_proxy", "http_proxy", "no_proxy", "all_proxy")
        and not key.startswith("OCTO_")
        and key not in ("MAXMIND_LICENSE_KEY", "NVD_API_KEY")
    }
    env["OCTO_NO_PROXY"] = "127.0.0.1,localhost"
    env.update(extra)
    return env


def _run(argv: list[str], **extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, text=True, check=False, cwd=REPO_ROOT, env=_env(**extra), timeout=120
    )


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _recording_opener(answers, seen: list[str]):
    def open_(request, timeout=None):  # noqa: ARG001 - urlopen signature
        seen.append(request.full_url)
        return _Response(json.dumps(answers(request.full_url)).encode("utf-8"))

    return open_


# --------------------------------------------------------------------------
# The shared machinery
# --------------------------------------------------------------------------


#: The two implementations: the scripts' (scripts/feed_fetch.py, which has to
#: run in the scanner image without the api package) and the in-process
#: fetchers' (api/services/advisories/fetch.py). Resolved inside each test so a
#: missing one is that test's failure, not the module's.
_SIDES = {"scripts": feed_fetch, "api": advisory_fetch}


@pytest.mark.parametrize("side", sorted(_SIDES))
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=abc123&suffix=tar.gz",
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=REDACTED&suffix=tar.gz",
        ),
        ("https://mirror:s3cret@nexus.corp:8443/raw/epss.csv.gz", "https://nexus.corp:8443/raw/epss.csv.gz"),
        ("https://nexus.corp/raw/kev.json?apiKey=k&token=t&x=1", "https://nexus.corp/raw/kev.json?apiKey=REDACTED&token=REDACTED&x=1"),
        ("file:///mnt/mirror/kev.json", "file:///mnt/mirror/kev.json"),
        ("https://[fd00::1]:8443/nvd", "https://[fd00::1]:8443/nvd"),
    ],
)
def test_urls_are_recorded_and_printed_without_credentials(side: str, url: str, expected: str) -> None:
    """The MaxMind URL carries the licence key; a Nexus URL often carries basic
    auth. Both sides redact the same way — a URL one of them prints and the
    other redacts is a key in a log."""
    assert _SIDES[side].redact_url(url) == expected


@pytest.mark.parametrize("side", sorted(_SIDES))
def test_an_override_wins_and_a_bad_scheme_is_refused(side: str, monkeypatch) -> None:
    resolve = _SIDES[side].feed_url
    monkeypatch.delenv("SOME_FEED_URL", raising=False)
    assert resolve("SOME_FEED_URL", "https://upstream.example/feed") == "https://upstream.example/feed"
    monkeypatch.setenv("SOME_FEED_URL", "  file:///mnt/mirror/feed  ")
    assert resolve("SOME_FEED_URL", "https://upstream.example/feed") == "file:///mnt/mirror/feed"
    for bad in ("ftp://mirror/feed", "gopher://x", "/mnt/mirror/feed", "javascript:alert(1)"):
        monkeypatch.setenv("SOME_FEED_URL", bad)
        with pytest.raises(ValueError, match="unsupported scheme"):
            resolve("SOME_FEED_URL", "https://upstream.example/feed")


def test_a_redirect_from_https_to_anything_weaker_is_refused() -> None:
    handler = feed_fetch._NoDowngradeRedirect()
    request = urllib.request.Request("https://mirror.corp/kev.json")
    with pytest.raises(urllib.error.HTTPError, match="refusing redirect from https to http"):
        handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, "http://mirror.corp/kev.json")
    followed = handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, "https://cdn.corp/kev.json")
    assert followed.full_url == "https://cdn.corp/kev.json"
    plain = urllib.request.Request("http://mirror.corp/kev.json")
    assert handler.redirect_request(plain, io.BytesIO(), 302, "Found", {}, "https://mirror.corp/kev.json")


def test_download_is_bounded_and_atomic(mirror, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OCTO_NO_PROXY", "127.0.0.1")
    mirror.files["/big"] = b"x" * 4096
    mirror.files["/empty"] = b""
    dest = tmp_path / "out.bin"
    dest.write_bytes(b"previous")

    with pytest.raises(feed_fetch.FeedError, match="byte ceiling"):
        feed_fetch.download(f"{mirror.base}/big", dest, max_bytes=1024)
    with pytest.raises(feed_fetch.FeedError, match="empty response"):
        feed_fetch.download(f"{mirror.base}/empty", dest)
    with pytest.raises(urllib.error.HTTPError):
        feed_fetch.download(f"{mirror.base}/missing", dest)
    assert dest.read_bytes() == b"previous"
    assert not list(tmp_path.glob("*.part"))

    assert feed_fetch.download(f"{mirror.base}/big", dest) == 4096
    assert dest.read_bytes() == b"x" * 4096


def test_the_scanner_image_downloads_through_the_agent_mirror_of_egress(tmp_path: Path) -> None:
    """The scanner image ships agent/ and not api/, and runs the feed scripts
    at build time. There the helper must fall back to agent.egress — the
    declared byte-for-byte mirror — rather than fail to import."""
    src = tmp_path / "feed.txt"
    src.write_text("data", encoding="utf-8")
    code = (
        "import sys; sys.modules['api'] = None; sys.path.insert(0, 'scripts'); "
        "import feed_fetch; from pathlib import Path; "
        f"feed_fetch.download({src.as_uri()!r}, Path({str(tmp_path / 'out.txt')!r})); "
        "print(feed_fetch.egress.__name__)"
    )
    proc = _run([sys.executable, "-c", code])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "agent.egress"
    assert (tmp_path / "out.txt").read_text(encoding="utf-8") == "data"


def test_the_ca_bundle_is_added_to_the_system_store_for_git(tmp_path: Path, monkeypatch) -> None:
    """git's GIT_SSL_CAINFO replaces its trust store; OCTO_CA_BUNDLE means
    "also trust this" (#359). The file handed to git has to be both."""
    internal = tmp_path / "corp-root.pem"
    internal.write_text("-----BEGIN CERTIFICATE-----\nMIIBinternal\n-----END CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(internal))
    out = feed_fetch.write_ca_bundle(tmp_path / "combined.pem")
    assert out is not None
    combined = out.read_bytes()
    assert combined.endswith(internal.read_bytes())
    system = feed_fetch.system_ca_file()
    if system is not None:
        assert combined.startswith(system.read_bytes())
    monkeypatch.delenv("OCTO_CA_BUNDLE")
    assert feed_fetch.write_ca_bundle(tmp_path / "none.pem") is None


# --------------------------------------------------------------------------
# The shell fetchers
# --------------------------------------------------------------------------


def test_epss_reads_its_mirror(tmp_path: Path) -> None:
    csv = "#model_version:v2025.03.14,score_date:2026-09-20T00:00:00+0000\ncve,epss,percentile\nCVE-2026-0001,0.51,0.9\n"
    src = tmp_path / "mirror" / "epss_scores-current.csv.gz"
    src.parent.mkdir()
    src.write_bytes(gzip.compress(csv.encode()))
    out = tmp_path / "epss.json"

    proc = _run(["bash", "scripts/fetch-epss-db.sh", "-o", str(out)], EPSS_URL=src.as_uri())

    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["entries"] == {"CVE-2026-0001": 0.51}
    assert payload["updated"] == "2026-09-20"
    assert payload["origin_url"] == src.as_uri()


def test_kev_reads_its_mirror_and_records_it_without_the_token(mirror, tmp_path: Path) -> None:
    mirror.files["/kev/known_exploited_vulnerabilities.json"] = json.dumps(
        {"dateReleased": "2026-09-19T12:00:00Z", "vulnerabilities": [{"cveID": "CVE-2026-0002"}]}
    ).encode()
    out = tmp_path / "kev.json"
    url = f"{mirror.base}/kev/known_exploited_vulnerabilities.json?token=s3cret"

    proc = _run(["bash", "scripts/fetch-kev-db.sh", "-o", str(out)], KEV_URL=url)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert mirror.requests == ["/kev/known_exploited_vulnerabilities.json?token=s3cret"]
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["entries"] == ["CVE-2026-0002"]
    assert payload["origin_url"].endswith("?token=REDACTED")
    assert "s3cret" not in proc.stdout + proc.stderr + out.read_text(encoding="utf-8")


def _maxmind_tarball(tmp_path: Path) -> Path:
    """MaxMind's layout, plus a decoy: a symlink named like the database that
    points at a host file. Only the regular member may be read."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        decoy = tarfile.TarInfo("GeoLite2-City_20260920/GeoLite2-City.mmdb")
        decoy.type = tarfile.SYMTYPE
        decoy.linkname = "/etc/passwd"
        archive.addfile(decoy)
        data = GEOIP_FIXTURE.read_bytes()
        real = tarfile.TarInfo("GeoLite2-City_20260920/GeoLite2-City.mmdb")
        real.size = len(data)
        archive.addfile(real, io.BytesIO(data))
    path = tmp_path / "GeoLite2-City.tar.gz"
    path.write_bytes(buf.getvalue())
    return path


@pytest.mark.parametrize("shape", ["mmdb", "mmdb.gz", "tar.gz"])
def test_geoip_reads_any_shape_a_mirror_keeps(tmp_path: Path, shape: str) -> None:
    if shape == "mmdb":
        src = tmp_path / "geoip.mmdb"
        src.write_bytes(GEOIP_FIXTURE.read_bytes())
    elif shape == "mmdb.gz":
        src = tmp_path / "dbip-city-lite.mmdb.gz"
        src.write_bytes(gzip.compress(GEOIP_FIXTURE.read_bytes()))
    else:
        src = _maxmind_tarball(tmp_path)
    out = tmp_path / "data" / "geoip.mmdb"

    # No MAXMIND_LICENSE_KEY: with a mirror there is no key to send.
    proc = _run(["bash", "scripts/fetch-geoip-db.sh", "-o", str(out)], GEOIP_URL=src.as_uri())

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert out.read_bytes() == GEOIP_FIXTURE.read_bytes()


def test_a_mirror_answering_with_a_page_does_not_replace_the_database(tmp_path: Path) -> None:
    page = tmp_path / "asn.mmdb"
    page.write_text("<!DOCTYPE html><html>Log in to Nexus</html>", encoding="utf-8")
    out = tmp_path / "data" / "asn.mmdb"
    out.parent.mkdir()
    out.write_bytes(GEOIP_FIXTURE.read_bytes())

    proc = _run(["bash", "scripts/fetch-asn-db.sh", "-o", str(out)], ASN_URL=page.as_uri())

    assert proc.returncode != 0
    assert "MaxMind DB" in proc.stderr
    assert out.read_bytes() == GEOIP_FIXTURE.read_bytes()


# --------------------------------------------------------------------------
# The Python fetchers
# --------------------------------------------------------------------------


def _nvd_page() -> bytes:
    return json.dumps(
        {
            "totalResults": 1,
            "startIndex": 0,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1111",
                        "published": "2026-09-01T00:00:00.000",
                        "metrics": {
                            "cvssMetricV40": [
                                {
                                    "type": "Primary",
                                    "cvssData": {
                                        "baseScore": 9.3,
                                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                        "version": "4.0",
                                    },
                                }
                            ]
                        },
                    }
                }
            ],
        }
    ).encode()


def test_cvss4_reads_the_nvd_mirror(mirror, tmp_path: Path) -> None:
    mirror.files["/nvd/rest/json/cves/2.0"] = _nvd_page()
    out = tmp_path / "cvss4.json"

    proc = _run(
        [sys.executable, "scripts/fetch-cvss4-db.py", "--last-mod-days", "1", "--sleep", "0", "-o", str(out)],
        NVD_API_URL=f"{mirror.base}/nvd/rest/json/cves/2.0",
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert mirror.requests and all(r.startswith("/nvd/rest/json/cves/2.0?") for r in mirror.requests)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["entries"]["CVE-2026-1111"]["score"] == 9.3
    assert payload["origin_url"] == f"{mirror.base}/nvd/rest/json/cves/2.0"


def test_cvss4_refuses_a_mirror_it_cannot_open_before_retrying_it(tmp_path: Path) -> None:
    proc = _run(
        [sys.executable, "scripts/fetch-cvss4-db.py", "--last-mod-days", "1", "-o", str(tmp_path / "o.json")],
        NVD_API_URL="ftp://mirror.corp/nvd",
    )
    assert proc.returncode == 2
    assert "unsupported scheme" in proc.stderr


def test_exploit_overlay_reads_both_mirrors(tmp_path: Path) -> None:
    csv = tmp_path / "files_exploits.csv"
    csv.write_text("id,file,description,codes\n1,x.py,poc,CVE-2026-2222;OSVDB-1\n", encoding="utf-8")
    msf = tmp_path / "modules_metadata_base.json"
    msf.write_text(
        json.dumps({"exploit/x": {"type": "exploit", "references": ["CVE-2026-3333"]}}), encoding="utf-8"
    )
    out = tmp_path / "exploit.json"

    proc = _run(
        [sys.executable, "scripts/fetch-exploit-db.py", "-o", str(out)],
        EXPLOITDB_CSV_URL=csv.as_uri(),
        METASPLOIT_MODULES_URL=msf.as_uri(),
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["entries"]["CVE-2026-2222"]["maturity"] == "proof_of_concept"
    assert payload["entries"]["CVE-2026-3333"]["maturity"] == "weaponized"
    assert payload["origin_urls"] == [csv.as_uri(), msf.as_uri()]


def test_the_nvd_cpe_harvest_reads_the_mirror_in_process(monkeypatch) -> None:
    """The in-process fetcher and fetch-cvss4-db.py read one variable: a mirror
    of the CVE API serves both."""
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    monkeypatch.setenv("NVD_API_URL", "https://reader:pw@nvd-mirror.corp/rest/json/cves/2.0")
    seen: list[str] = []
    page = {"totalResults": 0, "startIndex": 0, "vulnerabilities": []}

    harvest = cpe_ranges_fetch.harvest(sleep_seconds=0, opener=_recording_opener(lambda _: page, seen), retries=0)

    assert seen and all(url.startswith("https://reader:pw@nvd-mirror.corp/rest/json/cves/2.0?") for url in seen)
    dataset = cpe_ranges_fetch.merge(None, harvest, replace=True)
    assert dataset["origin_url"] == "https://nvd-mirror.corp/rest/json/cves/2.0"


def test_the_nvd_cpe_harvest_refuses_a_bad_mirror_before_any_request(monkeypatch) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    monkeypatch.setenv("NVD_API_URL", "gopher://nvd-mirror.corp/")
    with pytest.raises(ValueError, match="unsupported scheme"):
        cpe_ranges_fetch.harvest(sleep_seconds=0, opener=lambda *a, **k: pytest.fail("opened"), retries=0)


@pytest.mark.parametrize(
    ("dataset", "variable", "fixture"),
    [
        ("debian", "DEBIAN_TRACKER_URL", "debian-tracker-sample.json"),
        ("ubuntu", "UBUNTU_USN_URL", "ubuntu-usn-sample.json"),
    ],
)
def test_the_vendor_advisories_read_their_mirrors_in_process(
    monkeypatch, tmp_path: Path, dataset: str, variable: str, fixture: str
) -> None:
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    monkeypatch.setenv(variable, f"https://nexus.corp/raw/{dataset}.json?apiKey=k")
    payload = json.loads((ADVISORY_FIXTURES / fixture).read_text(encoding="utf-8"))
    seen: list[str] = []
    out = tmp_path / f"{dataset}.json"

    written = advisory_fetch.refresh(dataset, path=out, opener=_recording_opener(lambda _: payload, seen))

    assert written > 0
    assert seen == [f"https://nexus.corp/raw/{dataset}.json?apiKey=k"]
    assert json.loads(out.read_text(encoding="utf-8"))["origin_url"] == (
        f"https://nexus.corp/raw/{dataset}.json?apiKey=REDACTED"
    )


def _cvrf_month() -> dict:
    return {
        "ProductTree": {
            "FullProductName": [{"ProductID": "11929", "Value": "Windows 11 Version 24H2 for x64-based Systems"}]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-1111",
                "Threats": [{"Type": 3, "Description": {"Value": "Critical"}, "ProductID": ["11929"]}],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": "5034123"},
                        "ProductID": ["11929"],
                        "FixedBuild": "10.0.26100.3000",
                    }
                ],
            }
        ],
    }


def test_msrc_reads_the_index_and_every_month_from_the_mirror(monkeypatch, tmp_path: Path) -> None:
    """The index names each month by an absolute api.msrc.microsoft.com URL.
    With a mirror configured those are read from the mirror, and a month
    listed on some third host is skipped rather than fetched."""
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    monkeypatch.setenv("MSRC_CVRF_BASE_URL", "https://nexus.corp/msrc/cvrf/v3.0/")
    index = {
        "value": [
            {"ID": "2026-Sep", "InitialReleaseDate": "2026-09-09",
             "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep"},
            {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-12",
             "CvrfUrl": "https://elsewhere.example/cvrf/2026-Aug"},
        ]
    }
    seen: list[str] = []

    written = advisory_fetch.refresh_msrc(
        path=tmp_path / "msrc.json",
        opener=_recording_opener(lambda url: index if url.endswith("/updates") else _cvrf_month(), seen),
    )

    assert written == 1
    assert seen == [
        "https://nexus.corp/msrc/cvrf/v3.0/updates",
        "https://nexus.corp/msrc/cvrf/v3.0/cvrf/2026-Sep",
    ]
    stored = json.loads((tmp_path / "msrc.json").read_text(encoding="utf-8"))
    assert stored["origin_url"] == "https://nexus.corp/msrc/cvrf/v3.0/updates"


def test_msrc_without_a_mirror_reads_what_the_index_says(monkeypatch) -> None:
    monkeypatch.delenv("MSRC_CVRF_BASE_URL", raising=False)
    base = advisory_fetch.msrc_base_url()
    assert base == advisory_fetch.MSRC_API_BASE
    listed = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep"
    assert advisory_fetch.msrc_document_url(listed, base) == listed


# --------------------------------------------------------------------------
# nuclei-templates from a git mirror
# --------------------------------------------------------------------------


def _git(*args: str, cwd: Path) -> str:
    env = _env(
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    return subprocess.run(  # noqa: S603 - fixed argv
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture()
def templates_mirror(tmp_path: Path) -> tuple[Path, str]:
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    work = tmp_path / "work"
    (work / "http" / "cves").mkdir(parents=True)
    (work / "http" / "cves" / "CVE-2026-4444.yaml").write_text("id: CVE-2026-4444\n", encoding="utf-8")
    _git("init", "-q", "-b", "main", cwd=work)
    _git("add", ".", cwd=work)
    _git("commit", "-q", "-m", "templates", cwd=work)
    _git("tag", "-a", "v10.0.0", "-m", "v10.0.0", cwd=work)
    commit = _git("rev-parse", "HEAD", cwd=work)
    bare = tmp_path / "nuclei-templates.git"
    _git("clone", "-q", "--bare", str(work), str(bare), cwd=tmp_path)
    return bare, commit


@pytest.fixture()
def no_nuclei_updates(tmp_path: Path) -> tuple[Path, Path]:
    """A `nuclei` on PATH that records being called at all."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "nuclei-was-called"
    fake = bindir / "nuclei"
    fake.write_text(f'#!/bin/sh\necho "$@" >> {marker}\n', encoding="utf-8")
    fake.chmod(0o755)
    return bindir, marker


def _templates(dest: Path, bindir: Path, **extra: str) -> subprocess.CompletedProcess[str]:
    return _run(
        ["bash", "scripts/fetch-nuclei-templates.sh", str(dest)],
        PATH=f"{bindir}:{os.environ['PATH']}",
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_CONFIG_NOSYSTEM="1",
        **extra,
    )


@pytest.mark.parametrize("by", ["tag", "commit"])
def test_templates_come_from_the_mirror_pinned_and_nuclei_is_never_asked(
    templates_mirror, no_nuclei_updates, tmp_path: Path, by: str
) -> None:
    bare, commit = templates_mirror
    bindir, marker = no_nuclei_updates
    dest = tmp_path / "templates"
    dest.mkdir()
    (dest / "old.yaml").write_text("id: old\n", encoding="utf-8")

    proc = _templates(
        dest,
        bindir,
        NUCLEI_TEMPLATES_REPO=bare.as_uri(),
        NUCLEI_TEMPLATES_REF="v10.0.0" if by == "tag" else commit,
        NUCLEI_TEMPLATES_COMMIT=commit,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (dest / "http" / "cves" / "CVE-2026-4444.yaml").is_file()
    assert not (dest / "old.yaml").exists()  # swapped, not merged
    assert not (dest / ".git").exists()
    recorded = json.loads((dest / ".shapoclyack-templates.json").read_text(encoding="utf-8"))
    assert recorded["commit"] == commit
    assert not marker.exists(), "nuclei was invoked in mirror mode"
    assert not list(tmp_path.glob(".nuclei-templates*"))


def test_templates_at_a_commit_other_than_the_pin_are_refused(templates_mirror, no_nuclei_updates, tmp_path: Path) -> None:
    """A tag on a mirror can be moved; the commit pin is what cannot."""
    bare, _ = templates_mirror
    bindir, marker = no_nuclei_updates
    dest = tmp_path / "templates"
    dest.mkdir()
    (dest / "old.yaml").write_text("id: old\n", encoding="utf-8")

    proc = _templates(
        dest, bindir, NUCLEI_TEMPLATES_REPO=bare.as_uri(), NUCLEI_TEMPLATES_REF="v10.0.0",
        NUCLEI_TEMPLATES_COMMIT="0" * 40,
    )

    assert proc.returncode == 1
    assert "not the pinned" in proc.stderr
    assert (dest / "old.yaml").is_file()
    assert not marker.exists()


def test_a_mirror_without_a_ref_is_refused(templates_mirror, no_nuclei_updates, tmp_path: Path) -> None:
    bare, _ = templates_mirror
    bindir, marker = no_nuclei_updates
    proc = _templates(tmp_path / "templates", bindir, NUCLEI_TEMPLATES_REPO=bare.as_uri())
    assert proc.returncode == 2
    assert "NUCLEI_TEMPLATES_REF" in proc.stderr
    assert not marker.exists()


# --------------------------------------------------------------------------
# Offline mode: nothing is fetched, nothing is demoted
# --------------------------------------------------------------------------


def test_offline_refresh_makes_no_request_and_keeps_the_bundle_provenance(mirror, tmp_path: Path) -> None:
    """On an air-gapped cluster the API's enrichment initContainer runs on
    every rollout. Online, each feed would time out and the manifest would
    turn every bundle-installed dataset into `stale`. Offline, it must do
    neither — and every mirror variable is set here to prove it asked none."""
    dest = tmp_path / "data"
    (dest / "kev").mkdir(parents=True)
    kev = {"source": "cisa-kev", "updated": "2026-09-20", "entries": [f"CVE-2026-{i:05d}" for i in range(500)]}
    (dest / "kev" / "kev-overlay.json").write_text(json.dumps(kev), encoding="utf-8")
    (dest / "enrichment-manifest.json").write_text(
        json.dumps({"datasets": {"kev": {"origin": "bundle"}}}), encoding="utf-8"
    )
    urls = {
        variable: f"{mirror.base}/{variable}"
        for variable in (
            "EPSS_URL", "KEV_URL", "GEOIP_URL", "ASN_URL", "NVD_API_URL",
            "DEBIAN_TRACKER_URL", "UBUNTU_USN_URL", "MSRC_CVRF_BASE_URL",
        )
    }

    proc = _run(
        ["bash", "scripts/fetch-enrichment.sh"],
        OCTO_ENRICHMENT_OFFLINE=" True ",
        OCTO_ENRICHMENT_DIR=str(dest),
        OCTO_ENRICHMENT_SEED_DIR=str(REPO_ROOT / "scanner" / "data"),
        OCTO_ADVISORY_FETCH_ENABLED="true",
        OCTO_NVD_CPE_FETCH_ENABLED="true",
        **urls,
    )

    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    assert mirror.requests == []
    manifest = json.loads((dest / "enrichment-manifest.json").read_text(encoding="utf-8"))
    assert manifest["datasets"]["kev"]["origin"] == "bundle"
    # The seed floor still applies: a fresh volume is not left empty.
    assert (dest / "cvss4" / "cvss4.json").is_file()
    assert manifest["datasets"]["cvss4"]["origin"] == "seed"


# --------------------------------------------------------------------------
# The scanner's own tools: no phone-home
# --------------------------------------------------------------------------


_PD_TOOLS = {"naabu", "dnsx", "nuclei"}
_UPDATE_FLAGS = {"-update-templates", "-ut", "-update", "-up", "-update-template-dir", "-ud"}


def _pd_argv_literals() -> list[tuple[str, int, list[str]]]:
    found = []
    for path in sorted((REPO_ROOT / "scanner").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.List) or not node.elts:
                continue
            head = node.elts[0]
            if isinstance(head, ast.Constant) and head.value in _PD_TOOLS:
                flags = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                found.append((str(path.relative_to(REPO_ROOT)), node.lineno, flags))
    return found


def test_every_projectdiscovery_invocation_disables_the_update_check() -> None:
    """naabu, dnsx and nuclei check for a newer release on every start unless
    told not to — nuclei also installs templates it cannot find. Measured
    (v2.6.1 / v1.2.3 / v3.11.1, fresh $HOME, no network namespace, strace):
    each invocation the scanner made attempted DNS for the update host (12
    connect() calls for naabu and dnsx, 105 and a template install attempt for
    nuclei), and none with -disable-update-check. On an air-gapped network that
    is a timeout per call; on any network it is a beacon."""
    invocations = _pd_argv_literals()
    assert len(invocations) >= 9, invocations  # the test must not pass vacuously
    for where, line, flags in invocations:
        assert "-disable-update-check" in flags or "-duc" in flags, f"{where}:{line} {flags[0]} phones home"
        assert not _UPDATE_FLAGS & set(flags), f"{where}:{line} asks {flags[0]} to update itself"
