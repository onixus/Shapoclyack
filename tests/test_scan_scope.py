"""The approved scope, enforced on what is actually scanned (#244).

#226 checked the targets at the API's door. The scanner then resolved the names
again — minutes later for an ad-hoc scan, hours later for a scheduled one — and
scanned whatever the second answer said. The record in between is the scanned
party's to change, so a name that passed admission could be pointing into a
denied range by the time the scan reached it, and nothing looked.

These tests drive the real pipeline as far as its target list, with only the
DNS answer stubbed: the point is not that a filter function works, it is that
the run stops using the address.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scanner import exit_codes
from scanner import main as scanner_main
from scanner.pipeline import scan_scope

ALLOW_EXAMPLE = {"effect": "allow", "kind": "domain", "value": "customer.example"}
ALLOW_PUBLIC = {"effect": "allow", "kind": "cidr", "value": "203.0.113.0/24"}
DENY_METADATA = {"effect": "deny", "kind": "cidr", "value": "169.254.0.0/16"}
DENY_RFC1918 = {"effect": "deny", "kind": "cidr", "value": "10.0.0.0/8"}

RUN_ID = "20260827T120000Z"


def _document(*entries: dict, approved: bool = True) -> dict:
    """A scope document shaped exactly as ``start_scan`` writes one."""
    return {
        "version": scan_scope.DOCUMENT_VERSION,
        "tenant_id": "acme",
        "approved": approved,
        "entries": list(entries),
    }


def _config(tmp_path: Path) -> Path:
    """The installation's own config, re-homed into the test's directories.

    Read from ``scanner/config/default.yaml`` rather than hand-written so the
    run exercises the defaults an installation actually ships — every
    scope-expanding discovery stage off, which is what lets the pipeline reach
    its target list without a network.
    """
    raw = yaml.safe_load(Path("scanner/config/default.yaml").read_text(encoding="utf-8"))
    raw["runtime"]["output_dir"] = str(tmp_path / "output")
    raw["runtime"]["state_dir"] = str(tmp_path / "state")
    raw["runtime"]["logs_dir"] = str(tmp_path / "output" / "logs")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return config_path


def _write(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class ScanRun:
    """What one pipeline invocation left behind."""

    def __init__(self, exit_code: int, run_dir: Path, resolved_names: list[str]) -> None:
        self.exit_code = exit_code
        self.run_dir = run_dir
        #: The names the resolve stage was asked about — a name refused before
        #: resolve never appears here.
        self.resolved_names = resolved_names

    @property
    def targets(self) -> list[str]:
        path = self.run_dir / "all_targets.txt"
        return path.read_text(encoding="utf-8").split() if path.is_file() else []

    @property
    def denials(self) -> dict:
        path = self.run_dir / scan_scope.DENIED_ARTIFACT
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _scan(
    tmp_path: Path,
    monkeypatch,
    *,
    ranges: list[str],
    domains: list[str],
    resolves_to: list[str],
    document: dict | None,
) -> ScanRun:
    """Run the pipeline over these targets, with DNS answering ``resolves_to``.

    Stops at the pipeline's own "no targets" gate or at discovery, whichever
    comes first — everything under test happens before either.
    """
    config_path = _config(tmp_path)
    ranges_file = _write(tmp_path / "ranges.txt", ranges)
    domains_file = _write(tmp_path / "domains.txt", domains)

    asked: list[str] = []

    def _fake_resolve(fqdns, output_dir, *, timeout, retries):  # noqa: ANN001
        asked.extend(fqdns)
        return sorted(set(resolves_to)) if fqdns else []

    monkeypatch.setattr(scanner_main, "resolve_fqdns", _fake_resolve)
    # Discovery would reach the network; the run's target list is settled
    # before it, so stop there rather than pretending to probe.
    monkeypatch.setattr(scanner_main, "run_discovery_stage", lambda **kwargs: [])

    argv = [
        "scanner.main",
        "--config",
        str(config_path),
        "--ranges",
        str(ranges_file),
        "--domains",
        str(domains_file),
        "--run-id",
        RUN_ID,
        "--skip-nse",
    ]
    if document is not None:
        scope_file = tmp_path / "scan_scope.json"
        scope_file.write_text(json.dumps(document), encoding="utf-8")
        argv.extend(["--scan-scope", str(scope_file)])
    monkeypatch.setattr("sys.argv", argv)

    args = scanner_main.parse_args()
    exit_code = scanner_main._run_pipeline(args)
    return ScanRun(exit_code, tmp_path / "output" / "runs" / RUN_ID, asked)


# --- the TOCTOU itself ------------------------------------------------------


def test_a_name_that_passed_admission_is_dropped_when_it_resolves_into_a_denied_range(
    tmp_path: Path, monkeypatch
):
    """The gap #226 named and could not close.

    ``www.customer.example`` is inside the scope by suffix, so admission
    accepted it and would accept it again. Between then and now the record it
    points at — owned by the scanned party — moved to a denied address. The
    scanner resolves for itself, so it is the only barrier that can see this.
    """
    document = _document(ALLOW_EXAMPLE, ALLOW_PUBLIC, DENY_RFC1918)
    scope = scan_scope.from_document(document)
    assert scope is not None
    # Admission's verdict has not changed: the name is still in scope.
    assert scope.rejects_domain("www.customer.example") is None

    run = _scan(
        tmp_path,
        monkeypatch,
        ranges=[],
        domains=["www.customer.example"],
        resolves_to=["10.1.2.3"],
        document=document,
    )

    assert run.resolved_names == ["www.customer.example"]
    assert run.targets == []
    assert run.exit_code == exit_codes.INPUT_ERROR
    assert run.denials["denied"] == ["resolved -> 10.1.2.3 (denied by 10.0.0.0/8)"]


def test_the_same_name_is_scanned_when_the_record_has_not_moved(tmp_path: Path, monkeypatch):
    """The other half: the filter drops the denied answer, not the name."""
    run = _scan(
        tmp_path,
        monkeypatch,
        ranges=[],
        domains=["www.customer.example"],
        resolves_to=["203.0.113.10"],
        document=_document(ALLOW_EXAMPLE, ALLOW_PUBLIC, DENY_RFC1918),
    )

    assert run.targets == ["203.0.113.10"]
    assert run.denials["denied"] == []


def test_a_resolved_address_outside_every_allowed_range_is_still_scanned(
    tmp_path: Path, monkeypatch
):
    """Resolved addresses meet the deny half of the scope only.

    Approving ``customer.example`` is its own permission and says nothing about
    the addresses behind it. Requiring them to also sit inside an approved CIDR
    would refuse every engagement scoped by domain — which is most of them — so
    ``198.51.100.7`` is scanned even though no allow entry covers it.
    """
    run = _scan(
        tmp_path,
        monkeypatch,
        ranges=[],
        domains=["www.customer.example"],
        resolves_to=["198.51.100.7"],
        document=_document(ALLOW_EXAMPLE, DENY_METADATA),
    )

    assert run.targets == ["198.51.100.7"]
    assert run.denials["denied"] == []


# --- the target files the API never opens -----------------------------------


def test_the_default_target_files_are_checked_against_the_scope(tmp_path: Path, monkeypatch):
    """The second hole #226 left open, closed by the same document.

    A scan with no target overrides runs the installation's own target files.
    The API does not open them, so all it could ask was whether the tenant had
    a scope at all — not whether these lines are inside it. Here they are read
    by the process that holds the scope.
    """
    run = _scan(
        tmp_path,
        monkeypatch,
        ranges=["203.0.113.0/24", "169.254.169.254/32", "192.0.2.0/24"],
        domains=["shop.customer.example", "unrelated.example.org"],
        resolves_to=["203.0.113.10"],
        document=_document(ALLOW_EXAMPLE, ALLOW_PUBLIC, DENY_METADATA),
    )

    assert run.targets == ["203.0.113.0/24", "203.0.113.10"]
    # The refused name never reached the resolver, let alone the scan.
    assert run.resolved_names == ["shop.customer.example"]
    assert sorted(run.denials["denied"]) == [
        "169.254.169.254/32 (denied by 169.254.0.0/16)",
        "192.0.2.0/24 (not inside any allowed range)",
        "unrelated.example.org (not under any allowed domain)",
    ]


# --- an empty scope ---------------------------------------------------------


def test_a_scope_with_no_entries_scans_nothing(tmp_path: Path, monkeypatch):
    """"No entries means no scanning" holds here too, and says so.

    The run stops instead of quietly scanning zero targets: an empty result and
    a refused engagement look identical in the artifacts otherwise.
    """
    run = _scan(
        tmp_path,
        monkeypatch,
        ranges=["203.0.113.0/24"],
        domains=["www.customer.example"],
        resolves_to=["203.0.113.10"],
        document=_document(approved=False),
    )

    assert run.exit_code == exit_codes.INPUT_ERROR
    assert run.resolved_names == []
    assert run.targets == []
    assert run.denials["approved"] is False
    assert run.denials["denied"] == ["all targets (tenant has no approved scan scope)"]


def test_a_run_that_carries_no_scope_at_all_is_unfiltered(tmp_path: Path, monkeypatch):
    """A standalone run has no tenant and no control plane; it is not refused.

    An absent document is not an empty scope. Treating it as one would stop
    every direct ``python -m scanner.main`` invocation over a control with
    nothing to enforce.
    """
    run = _scan(
        tmp_path,
        monkeypatch,
        ranges=["10.1.2.0/24"],
        domains=[],
        resolves_to=[],
        document=None,
    )

    assert run.targets == ["10.1.2.0/24"]
    assert run.denials == {}


# --- the document -----------------------------------------------------------


def test_the_document_round_trips_without_changing_a_verdict():
    """The scope the API approved and the scope the run enforces are one scope."""
    original = scan_scope.ScanScope(
        tenant_id="acme",
        allow_networks=(scan_scope._network("203.0.113.0/24"),),
        deny_networks=(scan_scope._network("169.254.0.0/16"),),
        allow_domains=("customer.example",),
        deny_domains=("internal.customer.example",),
        approved=True,
    )

    restored = scan_scope.from_document(original.to_document())

    assert restored == original


def test_the_wildcard_survives_the_document():
    """A grandfathered allow-all scope must still be allow-all inside the run."""
    scope = scan_scope.from_document(
        _document(
            {"effect": "allow", "kind": "cidr", "value": "*"},
            {"effect": "allow", "kind": "domain", "value": "*"},
        )
    )

    assert scope is not None
    assert scope.rejects_network("10.1.2.0/24") is None
    assert scope.rejects_domain("anything.example") is None


def test_a_malformed_document_leaves_the_run_unfiltered_rather_than_empty(tmp_path: Path):
    """A truncated file is a reason to say so, not a verdict.

    Read as an empty scope it would stop the run; read as a scope it would
    permit everything. It is neither, so the loader answers None and the
    absence is logged.
    """
    path = tmp_path / "scan_scope.json"
    path.write_text('{"version": 1, "tenant_id": "acme"', encoding="utf-8")

    assert scan_scope.load_scope_file(path) is None
    assert scan_scope.load_scope_file(tmp_path / "absent.json") is None
    assert scan_scope.load_scope_file(None) is None


def test_an_unparseable_deny_entry_does_not_quietly_widen_the_scope():
    """A control that cannot be applied is dropped loudly, never permissively."""
    scope = scan_scope.from_document(
        _document(
            ALLOW_PUBLIC,
            {"effect": "deny", "kind": "cidr", "value": "not-a-network"},
        )
    )

    assert scope is not None
    assert scope.deny_networks == ()
    assert scope.rejects_network("203.0.113.0/24") is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("shop.customer.example", None),
        ("CUSTOMER.EXAMPLE.", None),
        ("db.internal.customer.example", "denied by internal.customer.example"),
        ("customer.example.attacker.test", "not under any allowed domain"),
    ],
)
def test_names_discovered_after_admission_meet_the_full_check(name: str, expected: str | None):
    """CT and Cloudflare add names no API check has ever seen.

    They are held to allow *and* deny, unlike resolved addresses: a name is the
    kind of target the scope speaks about directly.
    """
    scope = scan_scope.from_document(
        _document(ALLOW_EXAMPLE, {"effect": "deny", "kind": "domain", "value": "internal.customer.example"})
    )
    assert scope is not None

    assert scan_scope.filter_names(scope, [name]).kept == ([] if expected else [name])
    assert scope.rejects_domain(name) == expected
