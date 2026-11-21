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


def test_console_shell_is_not_an_api_operation(tmp_path: Path, monkeypatch) -> None:
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "index.html").write_text("<html>home</html>", encoding="utf-8")
    client = _client(web, monkeypatch)
    paths = client.get("/openapi.json").json()["paths"]
    assert not any("full_path" in path for path in paths)


def test_non_console_prefixes_miss_as_json(tmp_path: Path, monkeypatch) -> None:
    """A slash or an unknown child under an API prefix is not the console.

    The packaged API scan requests those variants. Answering them with
    index.html made a missing route look like a successful HTML document.
    """
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "index.html").write_text("<html>home</html>", encoding="utf-8")
    client = _client(web, monkeypatch)
    for path in (
        "/scim",
        "/scim/v2/Users/user_id/",
        "/openapi.json/",
        "/api/does-not-exist",
    ):
        response = client.get(path)
        assert response.status_code == 404, path
        assert response.headers["content-type"].startswith("application/json"), path
        assert "home" not in response.text
    assert client.get("/no-such-page").text == "<html>home</html>"


def test_unknown_api_path_is_json_not_the_shell(tmp_path: Path, monkeypatch) -> None:
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "index.html").write_text("<html>home</html>", encoding="utf-8")
    client = _client(web, monkeypatch)
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"
    assert "home" not in response.text
    assert client.get("/no-such-page").text == "<html>home</html>"


def test_serves_vite_assets_mount(tmp_path: Path, monkeypatch) -> None:
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "index.html").write_text("<html>vite</html>", encoding="utf-8")
    (web / "assets").mkdir()
    (web / "assets" / "app.js").write_text("vite-bundle", encoding="utf-8")

    client = _client(web, monkeypatch)
    assert client.get("/").text == "<html>vite</html>"
    assert client.get("/assets/app.js").text == "vite-bundle"


def test_percent_encoded_traversal_does_not_escape_web_dist(tmp_path: Path, monkeypatch) -> None:
    """GHSA-cpcx-h7mr-24pc: the SPA fallback is unauthenticated, so a path that
    resolves outside the web root read any file the API process could.

    Percent-encoded on purpose: a literal ``/../`` is collapsed before routing,
    so it never reproduced the defect. ``%2e%2e%2f`` reaches the handler as a
    real ``..`` segment. All three lookups are covered — the file, the
    ``.html`` sibling, and the directory ``index.html`` — because a check on
    only the first leaves the other two serving the same files.
    """
    web = tmp_path / "web-dist"
    web.mkdir()
    (web / "index.html").write_text("<html>home</html>", encoding="utf-8")
    (tmp_path / "secret.env").write_text("OCTO_JWT_SECRET=leaked", encoding="utf-8")
    (tmp_path / "secret.html").write_text("<html>leaked</html>", encoding="utf-8")
    (tmp_path / "secretdir").mkdir()
    (tmp_path / "secretdir" / "index.html").write_text("<html>leaked-dir</html>", encoding="utf-8")

    client = _client(web, monkeypatch)
    for path in ("/%2e%2e%2fsecret.env", "/%2e%2e%2fsecret", "/%2e%2e%2fsecretdir"):
        response = client.get(path)
        assert response.status_code == 200
        # Falls through to the SPA shell like any other unknown route.
        assert response.text == "<html>home</html>", path
        assert "leaked" not in response.text
