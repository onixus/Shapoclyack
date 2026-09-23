"""The opt-in NVD CPE-range refresh: normalisation, merge, and the CLI's guards.

No network: the harvest is driven through the injectable opener that
``advisories.fetch.fetch_json`` already takes. The CVE documents below are the
NVD CVE API 2.0 shape, trimmed to the fields the normaliser reads.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
import os
import subprocess
import urllib.parse
from pathlib import Path

import pytest

from api.services import cpe_ranges, cpe_ranges_fetch

REPO_ROOT = Path(__file__).resolve().parent.parent


def _seed_covered(until: datetime) -> dict:
    payload = json.loads((REPO_ROOT / "scanner/data/nvd-cpe/nvd-cpe-ranges.json").read_text())
    payload["covered_until"] = until.isoformat(timespec="seconds")
    return payload


def _cve(cve_id: str, matches: list[dict], *, score: float = 8.1, status: str = "Analyzed") -> dict:
    return {
        "cve": {
            "id": cve_id,
            "vulnStatus": status,
            "published": "2024-07-01T13:15:10.023",
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}
                ]
            },
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches}]}],
        }
    }


REGRESSHION = _cve(
    "CVE-2024-6387",
    [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "4.4"},
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "8.5",
            "versionEndExcluding": "9.8",
        },
        # The exact form NVD uses for a portable release.
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*"},
        # Not vulnerable: the platform half of a "running on" configuration.
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
        # An OS statement: not kept with the default parts.
        {"vulnerable": True, "criteria": "cpe:2.3:o:netapp:ontap:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.9"},
        # "Every version": dropped.
        {"vulnerable": True, "criteria": "cpe:2.3:a:somevendor:someproduct:*:*:*:*:*:*:*:*"},
    ],
)


def test_normalize_keeps_bounded_application_statements() -> None:
    cve_id, info, statements = cpe_ranges_fetch.normalize_cve(REGRESSHION)
    assert cve_id == "CVE-2024-6387"
    assert info == {"cvss": 8.1, "severity": "high", "published": "2024-07-01"}
    assert statements == [
        ("a:openbsd:openssh", {"cve": "CVE-2024-6387", "ee": "4.4"}),
        ("a:openbsd:openssh", {"cve": "CVE-2024-6387", "si": "8.5", "ee": "9.8"}),
        ("a:openbsd:openssh", {"cve": "CVE-2024-6387", "v": "9.7p1"}),
    ]


def test_a_rejected_cve_harvests_no_statements() -> None:
    _, _, statements = cpe_ranges_fetch.normalize_cve(
        _cve("CVE-2024-0001", REGRESSHION["cve"]["configurations"][0]["nodes"][0]["cpeMatch"], status="Rejected")
    )
    assert statements == []


def test_an_incremental_merge_replaces_a_cve_whole_and_leaves_the_rest() -> None:
    existing = {
        "entries": {
            "a:openbsd:openssh": [
                {"cve": "CVE-2024-6387", "si": "8.0", "ee": "9.9"},  # NVD has since narrowed it
                {"cve": "CVE-2023-48795", "ee": "9.6"},
            ],
            "a:vendor:gone": [{"cve": "CVE-2020-0001", "v": "1.0"}],
        },
        "cves": {"CVE-2023-48795": {"cvss": 5.9}, "CVE-2020-0001": {"cvss": 5.0}},
    }
    harvest = cpe_ranges_fetch.Harvest()
    harvest.add_page(
        {"vulnerabilities": [REGRESSHION, _cve("CVE-2020-0001", [], status="Rejected")]},
        parts=("a",),
    )

    merged = cpe_ranges_fetch.merge(existing, harvest, replace=False)

    openssh = merged["entries"]["a:openbsd:openssh"]
    assert {"cve": "CVE-2023-48795", "ee": "9.6"} in openssh
    assert {"cve": "CVE-2024-6387", "si": "8.0", "ee": "9.9"} not in openssh
    assert {"cve": "CVE-2024-6387", "si": "8.5", "ee": "9.8"} in openssh
    # A rejected CVE disappears, and a product with nothing left goes with it.
    assert "a:vendor:gone" not in merged["entries"]
    assert set(merged["cves"]) == {"CVE-2023-48795", "CVE-2024-6387"}


def test_a_merged_dataset_is_one_the_loader_reads(tmp_path: Path) -> None:
    harvest = cpe_ranges_fetch.Harvest()
    harvest.add_page({"vulnerabilities": [REGRESSHION]}, parts=("a",))
    path = tmp_path / "ranges.json"
    cpe_ranges_fetch.write_dataset(path, cpe_ranges_fetch.merge(None, harvest, replace=True))
    loaded = cpe_ranges.load_dataset(path)
    assert loaded.available
    assert len(loaded.ranges_for("a:openbsd:openssh")) == 3
    assert loaded.cve_info("CVE-2024-6387")["severity"] == "high"


# --------------------------------------------------------------------------
# The network half, without a network
# --------------------------------------------------------------------------


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(pages: list[dict], seen: list[str]):
    def open_(request, timeout=None):
        seen.append(request.full_url)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
        index = int(query["startIndex"][0])
        page = pages[0] if index == 0 else pages[1]
        return _Response(json.dumps(page).encode("utf-8"))

    return open_


def test_harvest_refuses_without_the_flag(monkeypatch) -> None:
    monkeypatch.delenv("OCTO_NVD_CPE_FETCH_ENABLED", raising=False)
    with pytest.raises(cpe_ranges_fetch.FetchDisabledError):
        cpe_ranges_fetch.harvest(opener=lambda *a, **k: pytest.fail("opened a socket"))


def test_harvest_pages_until_the_total_and_sends_the_window(monkeypatch) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    other = _cve("CVE-2023-48795", [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.6"}
    ], score=5.9)
    pages = [
        {"totalResults": 2, "vulnerabilities": [REGRESSHION]},
        {"totalResults": 2, "vulnerabilities": [other]},
    ]
    seen: list[str] = []
    now = datetime.now(UTC)
    result = cpe_ranges_fetch.harvest(
        window=(now - timedelta(days=8), now),
        sleep_seconds=0,
        opener=_opener(pages, seen),
        retries=0,
    )
    assert result.complete and result.pages == 2
    assert set(result.statements) == {"CVE-2024-6387", "CVE-2023-48795"}
    assert "lastModStartDate" in seen[0] and "lastModEndDate" in seen[0]
    assert "startIndex=1" in seen[1]


def test_a_failed_page_marks_the_harvest_incomplete(monkeypatch) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")

    def broken(request, timeout=None):
        raise OSError("connection reset")

    result = cpe_ranges_fetch.harvest(sleep_seconds=0, opener=broken, retries=0)
    assert result.complete is False


def test_the_window_is_capped_like_nvd_caps_it(monkeypatch) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    with pytest.raises(ValueError, match="120"):
        now = datetime.now(UTC)
        cpe_ranges_fetch.harvest(
            window=(now - timedelta(days=121), now),
            opener=lambda *a, **k: pytest.fail("fetched"),
        )


# --------------------------------------------------------------------------
# The CLI (scripts/fetch-nvd-cpe.py)
# --------------------------------------------------------------------------


def _cli():
    import importlib.util

    spec = importlib.util.spec_from_file_location("fetch_nvd_cpe_cli", REPO_ROOT / "scripts" / "fetch-nvd-cpe.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_cli_is_off_by_default(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OCTO_NVD_CPE_FETCH_ENABLED", raising=False)
    cli = _cli()
    out = tmp_path / "ranges.json"
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "-o", str(out)])
    assert cli.main() == cli.EXIT_DISABLED
    assert not out.exists()


def test_cli_does_not_publish_an_incomplete_harvest(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    cli = _cli()
    out = tmp_path / "ranges.json"
    out.write_text(json.dumps(_seed_covered(datetime.now(UTC))), encoding="utf-8")
    before = out.read_bytes()
    incomplete = cpe_ranges_fetch.Harvest(complete=False)
    monkeypatch.setattr(cpe_ranges_fetch, "harvest", lambda **kwargs: incomplete)
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "-o", str(out)])
    assert cli.main() == cli.EXIT_FAILED
    assert out.read_bytes() == before
    assert not out.with_suffix(".json.fetch").exists()


def test_cli_refuses_a_full_harvest_below_the_floor(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    cli = _cli()
    out = tmp_path / "ranges.json"
    small = cpe_ranges_fetch.Harvest()
    small.add_page({"vulnerabilities": [REGRESSHION]}, parts=("a",))
    monkeypatch.setattr(cpe_ranges_fetch, "harvest", lambda **kwargs: small)
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "--full", "-o", str(out)])
    assert cli.main() == cli.EXIT_FAILED
    assert not out.exists()


def test_cli_refuses_to_merge_over_an_unreadable_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    cli = _cli()
    out = tmp_path / "ranges.json"
    out.write_text("{truncated", encoding="utf-8")
    monkeypatch.setattr(cpe_ranges_fetch, "harvest", lambda **kwargs: pytest.fail("harvested"))
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "-o", str(out)])
    assert cli.main() == cli.EXIT_FAILED
    assert out.read_text(encoding="utf-8") == "{truncated"


def test_cli_merges_an_increment_into_the_existing_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    cli = _cli()
    out = tmp_path / "ranges.json"
    out.write_text(json.dumps(_seed_covered(datetime.now(UTC))), encoding="utf-8")
    fresh = cpe_ranges_fetch.Harvest()
    fresh.add_page(
        {"vulnerabilities": [_cve("CVE-2099-0001", [
            {"vulnerable": True, "criteria": "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*", "versionEndExcluding": "4.98"}
        ])]},
        parts=("a",),
    )
    monkeypatch.setattr(cpe_ranges_fetch, "harvest", lambda **kwargs: fresh)
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "-o", str(out)])
    assert cli.main() == cli.EXIT_OK
    loaded = cpe_ranges.load_dataset(out)
    exim = {s.cve for s in loaded.ranges_for("a:exim:exim")}
    assert {"CVE-2099-0001", "CVE-2019-10149"} <= exim
    assert loaded.source == cpe_ranges.SOURCE


# --------------------------------------------------------------------------
# The shell and the service read one flag the same way
# --------------------------------------------------------------------------

FLAG_SPELLINGS = (
    "true", "TRUE", "1", "yes", "on", " true", "true\n", "\ttrue\t",
    "false", "0", "no", "off", "", "enabled", "tr ue",
)


@pytest.mark.parametrize("raw", FLAG_SPELLINGS)
def test_the_shell_and_the_service_agree_on_the_nvd_cpe_flag(raw: str, monkeypatch) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", raw)
    expected = cpe_ranges_fetch.fetch_enabled()
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", "-c", f'source "{REPO_ROOT / "scripts" / "fetch-enrichment.sh"}"; nvd_cpe_fetch_enabled'],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "OCTO_NVD_CPE_FETCH_ENABLED": raw},
    )
    assert (proc.returncode == 0) is expected, f"{raw!r}: {proc.stdout}{proc.stderr}"


def test_the_manifest_floors_the_dataset_and_reports_the_seed_as_a_stub(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("enrichment_manifest", REPO_ROOT / "scripts" / "enrichment_manifest.py")
    manifest = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(manifest)
    record = manifest.inspect_json_dataset(
        REPO_ROOT / "scanner/data/nvd-cpe/nvd-cpe-ranges.json", manifest._JSON_DATASETS["nvd_cpe"][1]
    )
    assert record["present"] and record["entries"] == 8
    assert record["usable"] is False
    assert manifest._JSON_DATASETS["nvd_cpe"][2] is False


# --------------------------------------------------------------------------
# Review of PR #444: a partial harvest must not pass as a complete one, and an
# increment must not leave a hole
# --------------------------------------------------------------------------


def test_an_empty_page_before_the_end_marks_the_harvest_incomplete(monkeypatch) -> None:
    """NVD answering 200 with no vulnerabilities on page 2 of 3 used to end
    the loop as if the corpus were exhausted — and publish two thirds of it."""
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    pages = [
        {"totalResults": 5, "startIndex": 0, "vulnerabilities": [REGRESSHION]},
        {"totalResults": 5, "startIndex": 1, "vulnerabilities": []},
    ]
    result = cpe_ranges_fetch.harvest(sleep_seconds=0, opener=_opener(pages, []), retries=0)
    assert result.complete is False


@pytest.mark.parametrize(
    "second",
    [
        {"message": "error", "vulnerabilities": []},  # no totalResults: an error body
        {"totalResults": 2, "startIndex": 0, "vulnerabilities": [REGRESSHION]},  # wrong offset
    ],
)
def test_a_page_that_cannot_be_the_rest_marks_the_harvest_incomplete(monkeypatch, second) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    pages = [{"totalResults": 2, "startIndex": 0, "vulnerabilities": [REGRESSHION]}, second]
    result = cpe_ranges_fetch.harvest(sleep_seconds=0, opener=_opener(pages, []), retries=0)
    assert result.complete is False


def test_the_increment_continues_from_the_files_coverage_not_eight_days_back() -> None:
    now = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
    existing = {"covered_until": "2026-09-01T03:00:00+00:00", "entries": {}}
    start, end = cpe_ranges_fetch.increment_window(existing, now=now)
    assert end == now
    assert start == datetime(2026, 8, 31, 3, 0, tzinfo=UTC)  # a day of overlap


def test_a_file_without_covered_until_continues_from_its_updated_date() -> None:
    now = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
    start, _ = cpe_ranges_fetch.increment_window({"updated": "2026-09-10"}, now=now)
    assert start == datetime(2026, 9, 9, tzinfo=UTC)


def test_a_gap_beyond_nvds_window_requires_a_full_harvest() -> None:
    now = datetime(2026, 9, 23, tzinfo=UTC)
    with pytest.raises(cpe_ranges_fetch.WindowError, match="--full"):
        cpe_ranges_fetch.increment_window({"covered_until": "2026-05-01T00:00:00+00:00"}, now=now)


def test_an_explicit_window_that_would_leave_a_hole_is_refused() -> None:
    now = datetime(2026, 9, 23, tzinfo=UTC)
    with pytest.raises(cpe_ranges_fetch.WindowError, match="would be lost"):
        cpe_ranges_fetch.increment_window(
            {"covered_until": "2026-09-01T00:00:00+00:00"}, now=now, last_mod_days=8
        )


def test_the_merged_dataset_says_what_it_covers_not_when_it_was_written() -> None:
    harvest = cpe_ranges_fetch.Harvest(covered_until=datetime(2026, 9, 1, 6, 0, tzinfo=UTC))
    harvest.add_page({"vulnerabilities": [REGRESSHION]}, parts=("a",))
    merged = cpe_ranges_fetch.merge(None, harvest, replace=True)
    assert merged["updated"] == "2026-09-01"
    assert merged["covered_until"] == "2026-09-01T06:00:00+00:00"


def test_cli_after_a_long_outage_fails_and_says_run_full(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    cli = _cli()
    out = tmp_path / "ranges.json"
    out.write_text(json.dumps(_seed_covered(datetime.now(UTC) - timedelta(days=200))), encoding="utf-8")
    before = out.read_bytes()
    monkeypatch.setattr(cpe_ranges_fetch, "harvest", lambda **kwargs: pytest.fail("harvested"))
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "-o", str(out)])
    assert cli.main() == cli.EXIT_FAILED
    assert "--full" in capsys.readouterr().err
    assert out.read_bytes() == before


def test_cli_asks_nvd_for_the_whole_gap(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_NVD_CPE_FETCH_ENABLED", "true")
    cli = _cli()
    out = tmp_path / "ranges.json"
    covered = datetime.now(UTC) - timedelta(days=30)
    out.write_text(json.dumps(_seed_covered(covered)), encoding="utf-8")
    asked: dict = {}

    def fake(**kwargs):
        asked.update(kwargs)
        return cpe_ranges_fetch.Harvest(covered_until=kwargs["window"][1])

    monkeypatch.setattr(cpe_ranges_fetch, "harvest", fake)
    monkeypatch.setattr("sys.argv", ["fetch-nvd-cpe.py", "-o", str(out)])
    assert cli.main() == cli.EXIT_OK
    start, end = asked["window"]
    assert start <= covered and end - start >= timedelta(days=30)
