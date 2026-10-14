"""Shared contracts survive native sensor and minimal API packaging."""

from __future__ import annotations

import ast
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path


from agent.update import extract_agent_package
from scripts.sensor_bundle import build_archive

ROOT = Path(__file__).resolve().parents[1]


def _isolated(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    # -I -S excludes the checkout and all installed third-party dependencies.
    env = {
        key: value
        for key, value in os.environ.items()
        if "PROXY" not in key.upper() and key != "OCTO_CA_BUNDLE"
    }
    return subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(root), *args],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def _native_tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    shutil.copytree(ROOT / "agent", source / "agent", ignore=shutil.ignore_patterns("__pycache__"))
    # Exercise the default tracked-file archive builder, not its whole-tree escape.
    subprocess.run(["git", "init", "-q", str(source)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "add", "agent"], check=True, capture_output=True)
    install = tmp_path / "native"
    install.mkdir()
    extract_agent_package(build_archive(source / "agent"), install)
    return install


def test_shared_runtime_has_only_standard_library_dependencies():
    for path in (ROOT / "agent/runtime").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert all(name.split(".")[0] in sys.stdlib_module_names for name in names), (
                path.name, names
            )


def test_native_archive_contains_shared_modules_and_imports_without_control_plane(tmp_path):
    install = _native_tree(tmp_path)
    result = _isolated(
        install,
        "import importlib.util,sys; sys.path.insert(0,sys.argv[1]); "
        "assert all(importlib.util.find_spec(n) is None for n in "
        "('api','scanner','fastapi','sqlalchemy')); "
        "import agent.worker,agent.runtime.egress,agent.runtime.process,agent.runtime.invocation; "
        "assert not any(n == 'api' or n.startswith('api.') for n in sys.modules)",
    )
    assert result.returncode == 0, result.stderr


def test_api_image_declared_copy_layout_imports_shared_adapters(tmp_path):
    stage = tmp_path / "api-image"
    stage.mkdir()
    # Materialize actual local COPY entries that ship API and shared code.
    for line in (ROOT / "Dockerfile.api").read_text().splitlines():
        words = line.split()
        if len(words) != 3 or words[0] != "COPY":
            continue
        source, dest = words[1:]
        if source != "api" and not source.startswith("agent/"):
            continue
        target = stage / Path(dest).relative_to("/app")
        target.parent.mkdir(parents=True, exist_ok=True)
        if (ROOT / source).is_dir():
            shutil.copytree(ROOT / source, target, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(ROOT / source, target)
    result = _isolated(
        stage,
        "import importlib.util,sys; sys.path.insert(0,sys.argv[1]); "
        "assert all(importlib.util.find_spec(n) is None for n in ('fastapi','sqlalchemy')); "
        "from api.services import egress,local_scan_executor; "
        "from agent.runtime.egress import Proxy; assert egress.Proxy is Proxy; "
        "assert importlib.util.find_spec('agent.worker') is None",
    )
    assert result.returncode == 0, result.stderr


def test_native_sensor_client_calls_local_api_without_control_plane(tmp_path):
    install = _native_tree(tmp_path)
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization")))
            body = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        result = _isolated(
            install,
            "import sys; sys.path.insert(0,sys.argv[1]); "
            "from agent.worker import AgentClient; "
            "assert AgentClient(sys.argv[2],'packaging-test',timeout=3)._request"
            "('GET','/api/health') == {'status':'ok'}",
            f"http://127.0.0.1:{server.server_port}",
        )
        assert result.returncode == 0, result.stderr
        assert requests == [("/api/health", "Bearer packaging-test")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
