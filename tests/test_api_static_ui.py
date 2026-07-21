from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _client(web_dist: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("OCTO_WEB_DIST", str(web_dist))
    return TestClient(create_app())


def test_serves_next_export_routes(tmp_path: Path, monkeypatch) -> None:
    web = tmp_path / "web-dist"
    (web / "_next" / "static").mkdir(parents=True)
    (web / "_next" / "static" / "chunk.js").write_text("console.log(1)", encoding="utf-8")
    (web / "index.html").write_text("<html>home</html>", encoding="utf-8")
    # Next export flat HTML files (default trailingSlash=false)
    (web / "login.html").write_text("<html>login</html>", encoding="utf-8")
    (web / "assets.html").write_text("<html>assets-page</html>", encoding="utf-8")
    (web / "runs.html").write_text("<html>runs-list</html>", encoding="utf-8")
    (web / "runs").mkdir()
    (web / "runs" / "view.html").write_text("<html>run-view</html>", encoding="utf-8")

    client = _client(web, monkeypatch)
    assert client.get("/").text == "<html>home</html>"
    assert client.get("/login").text == "<html>login</html>"
    assert client.get("/login/").text == "<html>login</html>"
    assert client.get("/assets").text == "<html>assets-page</html>"
    assert client.get("/runs").text == "<html>runs-list</html>"
    assert client.get("/runs/view").text == "<html>run-view</html>"
    assert client.get("/runs/view?runId=abc").text == "<html>run-view</html>"
    assert "console.log(1)" in client.get("/_next/static/chunk.js").text
    assert client.get("/api/health").json()["status"] == "ok"


def test_serves_next_directory_index_routes(tmp_path: Path, monkeypatch) -> None:
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "_next").mkdir()
    (web / "index.html").write_text("<html>home</html>", encoding="utf-8")
    (web / "login").mkdir()
    (web / "login" / "index.html").write_text("<html>login-dir</html>", encoding="utf-8")

    client = _client(web, monkeypatch)
    assert client.get("/login").text == "<html>login-dir</html>"


def test_serves_vite_assets_mount(tmp_path: Path, monkeypatch) -> None:
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "index.html").write_text("<html>vite</html>", encoding="utf-8")
    (web / "assets").mkdir()
    (web / "assets" / "app.js").write_text("vite-bundle", encoding="utf-8")

    client = _client(web, monkeypatch)
    assert client.get("/").text == "<html>vite</html>"
    assert client.get("/assets/app.js").text == "vite-bundle"
