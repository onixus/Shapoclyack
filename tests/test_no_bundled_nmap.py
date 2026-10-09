"""Nmap is not built or distributed (NPSL, #97); users bring their own."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

BUILD_FILES = [
    "Dockerfile",
    "Dockerfile.allinone",
    "Dockerfile.api",
    "Jenkinsfile",
    "Jenkinsfile.publish",
    ".github/workflows/ci.yml",
    ".github/workflows/docker-publish.yml",
    ".github/actions/synthetic-load-test/action.yml",
]


@pytest.mark.parametrize("name", BUILD_FILES)
def test_build_files_carry_no_nmap_install_path(name: str) -> None:
    text = (ROOT / name).read_text(encoding="utf-8")
    assert "INSTALL_NMAP" not in text
    assert not re.search(r"apt-get install[^\n]*\bnmap\b", text)
    assert "-nmap" not in text.replace("pulse-nmap", "")


def test_publish_matrix_has_no_nmap_variants() -> None:
    jenkins = (ROOT / "Jenkinsfile.publish").read_text(encoding="utf-8")
    matrix = jenkins.split("def MATRIX = [", 1)[1].split("\n]", 1)[0]
    assert re.findall(r"name: '([\w-]+)'", matrix) == ["scanner", "api", "aio"]

    workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text(encoding="utf-8")
    assert re.findall(r"- name: ([\w-]+)\n\s+dockerfile:", workflow) == ["scanner", "api", "aio"]


def test_user_guide_is_linked_from_docs_index() -> None:
    assert (ROOT / "docs/nmap-external.md").is_file()
    assert "(nmap-external.md)" in (ROOT / "docs/README.md").read_text(encoding="utf-8")
