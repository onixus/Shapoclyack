"""Live dnsx and nuclei runs with the flags the scanner builds.

Skipped unless ``OCTO_PD_LIVE`` is set, like ``test_naabu_live.py`` (which
covers naabu's host discovery): elsewhere these binaries are fakes that record
argv, and a fake accepts any flag. CI sets the variable in the image smoke
stage. Nothing here needs the network: the target is a local HTTP server and
the interactsh server is one that refuses the connection.
"""

from __future__ import annotations

import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_scan import INTERACTSH_TOKEN_ENV, run_nuclei_scan
from scanner.pipeline.resolve import resolve_fqdns

LIVE = os.environ.get("OCTO_PD_LIVE", "").strip()

pytestmark = pytest.mark.skipif(
    not LIVE or shutil.which("dnsx") is None or shutil.which("nuclei") is None,
    reason="OCTO_PD_LIVE not set, or dnsx/nuclei is not on PATH (live binaries)",
)

PLAIN = """\
id: live-plain
info: {name: live plain, author: shapoclyack, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/plain"]
    matchers:
      - {type: word, words: ["live-ok"]}
"""

OAST = """\
id: live-oast
info: {name: live oast, author: shapoclyack, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/oast?u={{interactsh-url}}"]
    matchers:
      - {type: word, part: interactsh_protocol, words: ["http"]}
"""


@pytest.fixture()
def target():
    paths: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            paths.append(self.path)
            body = b"live-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], paths
    server.shutdown()


@pytest.fixture()
def templates(tmp_path):
    directory = tmp_path / "templates"
    directory.mkdir()
    (directory / "live-plain.yaml").write_text(PLAIN, encoding="utf-8")
    (directory / "live-oast.yaml").write_text(OAST, encoding="utf-8")
    return directory


def test_dnsx_starts_with_the_update_check_off(tmp_path):
    # run_command raises on a non-zero exit, which is how a refused flag shows.
    resolve_fqdns(["localhost"], tmp_path, timeout=60, retries=0)


def test_nuclei_default_runs_and_skips_oast(tmp_path, templates, target):
    port, paths = target
    config = NucleiConfig(templates_dir=str(templates), http_ports=[port], https_ports=[])
    result = run_nuclei_scan([f"127.0.0.1:{port}/tcp"], config, tmp_path / "run")

    assert result["skipped_reason"] is None
    assert [f["template_id"] for f in result["findings"]] == ["live-plain"]
    assert result["interactsh"] == "disabled"
    assert "/plain" in paths
    assert not any(p.startswith("/oast") for p in paths)


def test_nuclei_starts_with_a_server_and_a_token_file(tmp_path, templates, target, monkeypatch):
    port, _ = target
    monkeypatch.setenv(INTERACTSH_TOKEN_ENV, "live-token")
    config = NucleiConfig(
        templates_dir=str(templates),
        http_ports=[port],
        https_ports=[],
        # Resolves from /etc/hosts and refuses the connection: nuclei has to
        # start with -interactsh-server and -config, and then fail to register.
        interactsh_server="http://localhost",
    )
    result = run_nuclei_scan([f"127.0.0.1:{port}/tcp"], config, tmp_path / "run")

    assert result["skipped_reason"] is None
    assert [f["template_id"] for f in result["findings"]] == ["live-plain"]
    assert result["interactsh_registered"] is False
