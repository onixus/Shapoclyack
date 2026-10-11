"""Nmap is not built, distributed or run (NPSL #97; removed from the product in #548)."""

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


def test_migration_note_is_linked_from_docs_index() -> None:
    assert (ROOT / "docs/nmap-migration.md").is_file()
    assert not (ROOT / "docs/nmap-external.md").exists()
    assert "(nmap-migration.md)" in (ROOT / "docs/README.md").read_text(encoding="utf-8")


def test_the_removed_modules_stay_removed() -> None:
    for name in ("scanner/pipeline/nse.py", "scanner/pipeline/pulse_shadow.py", "scripts/compare-pulse-nmap.py"):
        assert not (ROOT / name).exists(), name


#: What starting Nmap looks like in Python: a PATH lookup, or an argv whose first
#: element is the program. Mentions in comments, docstrings and data are fine
#: (the legacy readers say "nmap" everywhere); running it is not.
_RUNS_NMAP = re.compile(
    r"""which\(\s*["']nmap["']|\[\s*["']nmap["']\s*[,\]]|\bnmap_bin\b|run_command\(\s*\[\s*["']nmap""",
)


def _python_sources() -> list[Path]:
    return [
        path
        for top in ("api", "agent", "scanner", "scripts")
        for path in (ROOT / top).rglob("*.py")
        if "migrations" not in path.parts
    ]


def test_no_code_path_runs_nmap() -> None:
    offenders = [
        str(path.relative_to(ROOT))
        for path in _python_sources()
        if _RUNS_NMAP.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_every_shipped_config_loads_without_a_removed_nmap_key() -> None:
    """The refusal added in #548 is only fair if nothing we ship trips it."""
    import yaml

    from scanner.pipeline.config_schema import load_config

    shipped = [
        *sorted((ROOT / "scanner/config").glob("*.yaml")),
        *sorted((ROOT / "tests/load").glob("config*.yaml")),
        ROOT / "tests/e2e/config.yaml",
        ROOT / "k8s/shapoclyack/base/config/k8s.yaml",
    ]
    assert len(shipped) >= 7
    for path in shipped:
        load_config(yaml.safe_load(path.read_text(encoding="utf-8")))
