"""The enrichment fetch runs once per build, not once per image and platform.

Dockerfile and Dockerfile.allinone fetch enrichment data in a stage of their
own, on the build platform, and copy the result into the final stage. The data
does not depend on the architecture, and the NVD walk inside it is long enough
that four copies of it in parallel get throttled into timeouts. The second image
of a build reuses the first one's stage from the BuildKit cache only while the
two stages are instruction for instruction the same.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = ["Dockerfile", "Dockerfile.allinone"]


def _stages(name: str) -> list[tuple[str, list[str]]]:
    """(FROM line, instruction lines) per stage; comments and blank lines dropped."""
    stages: list[tuple[str, list[str]]] = []
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("FROM "):
            stages.append((line, []))
        elif stages:
            stages[-1][1].append(line)
    return stages


def _enrichment(name: str) -> tuple[str, list[str]]:
    found = [s for s in _stages(name) if s[0].endswith(" AS enrichment")]
    assert len(found) == 1, f"{name}: expected one enrichment stage"
    return found[0]


def test_enrichment_stage_is_identical_in_both_dockerfiles() -> None:
    assert _enrichment("Dockerfile") == _enrichment("Dockerfile.allinone")


@pytest.mark.parametrize("name", DOCKERFILES)
def test_enrichment_stage_runs_on_the_build_platform(name: str) -> None:
    head, body = _enrichment(name)
    assert head.startswith("FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:")
    final_from = _stages(name)[-1][0]
    # Same base as the runtime: the fetch scripts run on the image's python.
    assert head.split()[2] == final_from.split()[1]
    text = "\n".join(body)
    assert "--mount=type=secret,id=nvd_api_key,required=false" in text
    assert "bash scripts/fetch-enrichment.sh" in text
    assert "ARG ENRICHMENT_STRICT=0" in body
    # The fetch imports scanner.pipeline.cvss4, scripts/*.py and, for vendor
    # advisories, api.services (which reaches agent.runtime.egress).
    for src in ("scanner", "scripts", "api", "agent"):
        assert f"COPY {src} /app/{src}" in body
    assert "COPY scanner/data /opt/shapoclyack/seed-data" in body


@pytest.mark.parametrize("name", DOCKERFILES)
def test_final_stage_copies_the_data_instead_of_fetching(name: str) -> None:
    final_from, body = _stages(name)[-1]
    assert "--platform" not in final_from
    text = "\n".join(body)
    assert "fetch-enrichment.sh" not in text
    assert "nvd_api_key" not in text
    copy = "COPY --from=enrichment /app/scanner/data /app/scanner/data"
    assert copy in body
    # Over the committed seed, not under it, and before /app is chowned to the
    # runtime user.
    assert body.index("COPY scanner /app/scanner") < body.index(copy)
    chown = next(i for i, line in enumerate(body) if re.search(r"chown -R \w+:\w+ /app", line))
    assert body.index(copy) < chown
    # The pristine seed the runtime refresh floors from stays in the image.
    assert "COPY scanner/data /opt/shapoclyack/seed-data" in body
