"""Exercise the actual Actions release gate before a registry write can run."""

import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/docker-publish.yml").read_text())
STEPS = WORKFLOW["jobs"]["build-and-push"]["steps"]
GATE = next(step for step in STEPS if step.get("id") == "release")


@pytest.mark.parametrize("suffix,stable", [("", "true"), ("-alpha1", "false"),
                                         ("-beta2", "false"), ("-rc1", "false")])
def test_release_gate_classifies_stable_and_prerelease(tmp_path, suffix, stable):
    output = tmp_path / "outputs"
    tag = "shapoclyack-0.47-1009" + suffix
    result = subprocess.run(
        ["bash", "-c", GATE["run"]],
        env={**os.environ, "RELEASE_REF_TYPE": "tag", "RELEASE_TAG": tag,
             "GITHUB_OUTPUT": str(output)}, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text() == f"tag={tag}\nstable={stable}\n"


@pytest.mark.parametrize("kind,tag", [("branch", "shapoclyack-0.47-1009"),
                                    ("tag", "v0.47"), ("tag", "latest"),
                                    ("tag", "shapoclyack-0.47-1009-rc1\nlatest")])
def test_release_gate_rejects_untrusted_refs_before_build(tmp_path, kind, tag):
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-c", GATE["run"]],
        env={**os.environ, "RELEASE_REF_TYPE": kind, "RELEASE_TAG": tag,
             "GITHUB_OUTPUT": str(output)}, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert not output.exists()


def test_publish_consumes_validated_tags_and_strict_enrichment():
    metadata = next(step for step in STEPS if step.get("id") == "meta")
    assert metadata["with"]["tags"].splitlines() == [
        "type=raw,value=${{ steps.release.outputs.tag }}",
        "type=raw,value=latest,enable=${{ steps.release.outputs.stable == 'true' }}",
    ]
    build = next(step for step in STEPS if step.get("id") == "build")
    assert "ENRICHMENT_STRICT=1" in build["with"]["build-args"].splitlines()
    assert STEPS.index(GATE) < STEPS.index(build)
    signing = STEPS[-1]
    assert signing["env"]["RELEASE_TAG"] == "${{ steps.release.outputs.tag }}"
    assert 'args+=(--release "${RELEASE_TAG}")' in signing["run"]
