"""nuclei's out-of-band (interactsh) testing: off by default, self-hosted if on.

Left to its defaults nuclei v3.11.1 registers with ProjectDiscovery's public
interactsh servers (``oast.pro`` and five more) and has every scanned host
call back to them. On the kind stand the image's nuclei made 200 lookups of
those six names in one run, to 1.1.1.1/1.0.0.1/8.8.8.8/8.8.4.4 as well as to
the cluster resolver; with ``-no-interactsh`` it made none, and the two OAST
templates tried against a stub target sent it nothing ("interactsh client not
initialized"). Against a stub interactsh server named by
``nuclei.interactsh_server`` the same two templates registered, polled and
matched, with the token below arriving as the ``Authorization`` header.
"""

from __future__ import annotations

import logging
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from scanner.pipeline import nuclei_scan
from scanner.pipeline.config_schema import (
    NucleiConfig,
    ProfileNucleiConfig,
    load_config,
    merge_nuclei_config,
)
from scanner.pipeline.nuclei_scan import INTERACTSH_TOKEN_ENV, run_nuclei_scan

DEFAULT_YAML = Path(__file__).resolve().parents[1] / "scanner" / "config" / "default.yaml"

#: nuclei v3.11.1's stderr (no -silent) after a successful registration,
#: copied from the stand. A failed one prints no line at all about it.
REGISTERED = (
    "[INF] Targets loaded for current scan: 1\n"
    "[INF] Using Interactsh Server: oast.corp.example\n"
    "[INF] Scan completed in 5.042761044s. 2 matches found.\n"
)
NOT_REGISTERED = (
    "[INF] Targets loaded for current scan: 1\n"
    "[INF] Scan completed in 30.019094972s. No results found.\n"
)


@pytest.fixture()
def nuclei_run(tmp_path: Path, monkeypatch):
    """Run the stage against a recording fake; return (result, argv, seen).

    ``seen`` is what the fake found on disk *while nuclei would have been
    running*: the ``-config`` file's mode and parsed content, if one was passed.
    """
    monkeypatch.setattr(nuclei_scan.shutil, "which", lambda name: "/usr/local/bin/nuclei")
    templates = tmp_path / "templates"
    templates.mkdir()
    output_dir = tmp_path / "run"
    output_dir.mkdir()

    def run(*, fail: bool = False, stderr: str = REGISTERED, **config):
        argv: list[str] = []
        seen: dict = {}

        def fake_run_command(command, **kwargs):
            argv.extend(command)
            if "-config" in command:
                path = Path(command[command.index("-config") + 1])
                seen["path"] = path
                seen["mode"] = stat.S_IMODE(path.stat().st_mode)
                seen["dir_mode"] = stat.S_IMODE(path.parent.stat().st_mode)
                seen["content"] = yaml.safe_load(path.read_text(encoding="utf-8"))
            if fail:
                raise TimeoutError("nuclei took too long")
            Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", stderr)

        monkeypatch.setattr(nuclei_scan, "run_command", fake_run_command)
        cfg = NucleiConfig(enabled=True, templates_dir=str(templates), **config)
        result = run_nuclei_scan(["10.0.0.1:80/tcp"], cfg, output_dir)
        return result, argv, seen

    run.output_dir = output_dir
    return run


def test_oast_is_off_by_default(nuclei_run, monkeypatch):
    monkeypatch.delenv(INTERACTSH_TOKEN_ENV, raising=False)
    result, argv, seen = nuclei_run()

    assert "-no-interactsh" in argv
    assert "-interactsh-server" not in argv
    assert "-config" not in argv and seen == {}
    # The update check nuclei always had, still there next to it.
    assert "-disable-update-check" in argv
    assert "-silent" in argv
    assert result["interactsh"] == "disabled"
    assert result["interactsh_registered"] is None
    assert '"interactsh": "disabled"' in (nuclei_run.output_dir / "nuclei.json").read_text()


def test_a_token_without_a_server_turns_nothing_on(nuclei_run, monkeypatch):
    monkeypatch.setenv(INTERACTSH_TOKEN_ENV, "t0ken")
    result, argv, seen = nuclei_run()
    assert "-no-interactsh" in argv
    assert "-config" not in argv and seen == {}
    assert "t0ken" not in " ".join(argv)


def test_a_named_server_is_used_and_nothing_else(nuclei_run, monkeypatch):
    monkeypatch.delenv(INTERACTSH_TOKEN_ENV, raising=False)
    result, argv, seen = nuclei_run(interactsh_server="https://oast.corp.example/")

    assert argv[argv.index("-interactsh-server") + 1] == "https://oast.corp.example"
    assert "-no-interactsh" not in argv
    assert "-config" not in argv
    assert result["interactsh"] == "https://oast.corp.example"
    assert result["interactsh_registered"] is True


def test_a_registration_that_never_happened_is_reported_not_swallowed(
    nuclei_run, monkeypatch, caplog
):
    """On the stand an unresolvable server cost 30 s and left no line at all
    under -silent, while every OAST template was skipped. -silent is dropped
    in this mode so nuclei's success line can be looked for."""
    monkeypatch.delenv(INTERACTSH_TOKEN_ENV, raising=False)
    with caplog.at_level(logging.WARNING, logger="shapoclyack.nuclei"):
        result, argv, _ = nuclei_run(interactsh_server="oast.corp.example", stderr=NOT_REGISTERED)

    assert "-silent" not in argv
    assert result["interactsh"] == "oast.corp.example"
    assert result["interactsh_registered"] is False
    assert "never registered with interactsh server oast.corp.example" in caplog.text


def test_the_token_reaches_nuclei_in_a_private_file_and_nowhere_else(
    nuclei_run, monkeypatch, tmp_path
):
    token = 'tok:en #1 "q"'  # YAML-significant characters, as a real one may have
    monkeypatch.setenv(INTERACTSH_TOKEN_ENV, token)
    result, argv, seen = nuclei_run(interactsh_server="oast.corp.example")

    assert token not in " ".join(argv)
    assert seen["content"] == {"interactsh-token": token}
    assert seen["mode"] == 0o600
    assert seen["dir_mode"] == 0o700
    # Not under the run directory, which is uploaded, and gone afterwards.
    assert nuclei_run.output_dir not in seen["path"].parents
    assert not seen["path"].parent.exists()
    leaked = [p for p in tmp_path.rglob("*") if p.is_file() and token in p.read_text(errors="ignore")]
    assert leaked == []
    assert result["interactsh"] == "oast.corp.example"


def test_the_token_file_is_removed_when_nuclei_fails(nuclei_run, monkeypatch):
    monkeypatch.setenv(INTERACTSH_TOKEN_ENV, "t0ken")
    result, argv, seen = nuclei_run(fail=True, interactsh_server="oast.corp.example")
    assert result["skipped_reason"] == "nuclei_run_failed"
    assert not seen["path"].parent.exists()


def test_an_unwritable_token_file_turns_oast_off_rather_than_registering_without_it(
    nuclei_run, monkeypatch
):
    monkeypatch.setenv(INTERACTSH_TOKEN_ENV, "t0ken")

    def no_tmp(**kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(nuclei_scan.tempfile, "mkdtemp", no_tmp)
    result, argv, seen = nuclei_run(interactsh_server="oast.corp.example")
    assert "-no-interactsh" in argv
    assert "-interactsh-server" not in argv
    assert result["interactsh"] == "disabled"


@pytest.mark.parametrize(
    ("raw", "stored"),
    [
        ("", ""),
        ("   ", ""),
        ("oast.corp.example", "oast.corp.example"),
        (" oast.corp.example ", "oast.corp.example"),
        ("oast.corp.example/", "oast.corp.example"),
        ("https://oast.corp.example", "https://oast.corp.example"),
        ("HTTPS://oast.corp.example/", "https://oast.corp.example"),
        ("http://oast-1.internal", "http://oast-1.internal"),
        ("oast", "oast"),
    ],
)
def test_interactsh_server_accepts_a_domain(raw, stored):
    assert NucleiConfig(interactsh_server=raw).interactsh_server == stored


@pytest.mark.parametrize(
    "raw",
    [
        "oast.corp.example:8443",  # the port would land inside every payload hostname
        "https://oast.corp.example:443",
        "https://oast.corp.example/interactsh",
        "https://oast.corp.example/?x=1",
        "https://user:pw@oast.corp.example",
        "ftp://oast.corp.example",
        "10.0.0.5",  # payloads are subdomains of the server name
        "https://10.0.0.5",
        "[2001:db8::5]",
        "oast.pro,oast.live",  # nuclei would pick one at random
        "oast corp.example",
        "-oast.corp.example",
        "oast..corp.example",
    ],
)
def test_interactsh_server_refuses_anything_else(raw):
    with pytest.raises(ValidationError):
        NucleiConfig(interactsh_server=raw)


def test_the_shipped_config_leaves_oast_off():
    raw = yaml.safe_load(DEFAULT_YAML.read_text(encoding="utf-8"))
    assert load_config(raw).nuclei.interactsh_server == ""


def test_a_speed_profile_does_not_drop_the_server():
    base = NucleiConfig(interactsh_server="oast.corp.example")
    merged = merge_nuclei_config(base, ProfileNucleiConfig(rate_limit=10))
    assert merged.interactsh_server == "oast.corp.example"
    assert merged.rate_limit == 10


def test_the_env_name_is_the_documented_one():
    # docs/network-requirements.md and default.yaml name it; a rename has to
    # touch them too.
    assert INTERACTSH_TOKEN_ENV == "OCTO_INTERACTSH_TOKEN"
    assert INTERACTSH_TOKEN_ENV in DEFAULT_YAML.read_text(encoding="utf-8")
    docs = Path(__file__).resolve().parents[1] / "docs" / "network-requirements.md"
    assert INTERACTSH_TOKEN_ENV in docs.read_text(encoding="utf-8")
