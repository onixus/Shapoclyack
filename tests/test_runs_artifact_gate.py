"""The restricted-artifact gate belongs to the service, not only to the routes.

The routes already 404 a viewer on ownership.json. This file covers the layer
below them: a caller that forgets the flag must not get the file. Route tests
for the same predicate live in ``tests/test_api_restricted_artifacts.py``,
which needs Postgres; these do not.
"""

from __future__ import annotations

import json
from pathlib import Path

from api.services import runs as runs_service
from api.settings import Settings


def _seed(tmp_path: Path) -> Settings:
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "ownership.json").write_text(json.dumps({"seed_domains": []}), encoding="utf-8")
    (run_dir / "ownership_findings.txt").write_text("example.com:ok\n", encoding="utf-8")
    (run_dir / "summary.json").write_text("{}", encoding="utf-8")
    return Settings(output_dir=tmp_path)


def test_resolve_artifact_refuses_a_restricted_name_by_default(tmp_path: Path):
    settings = _seed(tmp_path)

    assert runs_service.resolve_artifact(settings, "run-1", "ownership.json") is None
    assert runs_service.resolve_artifact(settings, "run-1", "ownership_findings.txt") is None
    assert runs_service.read_artifact_text(settings, "run-1", "ownership.json") is None


def test_resolve_artifact_hands_it_over_when_the_caller_opts_in(tmp_path: Path):
    settings = _seed(tmp_path)

    target = runs_service.resolve_artifact(
        settings, "run-1", "ownership.json", allow_restricted=True
    )

    assert target is not None and target.name == "ownership.json"
    text = runs_service.read_artifact_text(
        settings, "run-1", "ownership.json", allow_restricted=True
    )
    assert text is not None and "seed_domains" in text


def test_an_ordinary_artifact_is_untouched_by_the_gate(tmp_path: Path):
    settings = _seed(tmp_path)

    assert runs_service.resolve_artifact(settings, "run-1", "summary.json") is not None
