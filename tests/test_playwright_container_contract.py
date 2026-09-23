"""Contract for the browser runtime shipped with scanner images (#367)."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DOCKERFILES = (ROOT / "Dockerfile", ROOT / "Dockerfile.allinone")
API_DOCKERFILE = ROOT / "Dockerfile.api"
SCREENSHOT_REQUIREMENTS = ROOT / "requirements-screenshots.txt"
SMOKE_SCRIPT = ROOT / "scripts/check-playwright-runtime.py"


def test_playwright_is_pinned_outside_the_api_requirements():
    requirements = [
        line.strip()
        for line in SCREENSHOT_REQUIREMENTS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert requirements == ["playwright==1.63.0"]
    assert "playwright" not in (ROOT / "requirements.txt").read_text(
        encoding="utf-8"
    ).lower()
    assert "playwright" not in (ROOT / "requirements-api.txt").read_text(
        encoding="utf-8"
    ).lower()


def test_scanner_images_install_shared_chromium_headless_shell():
    for path in SCANNER_DOCKERFILES:
        text = path.read_text(encoding="utf-8")
        assert "requirements-screenshots.txt" in text, path
        assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in text, path
        assert "python -m playwright install --with-deps --only-shell chromium" in text, path
        assert "chmod -R a+rX \"${PLAYWRIGHT_BROWSERS_PATH}\"" in text, path
        assert "python /app/scripts/check-playwright-runtime.py" in text, path

        smoke_position = text.index("python /app/scripts/check-playwright-runtime.py")
        user_positions = [
            text.rfind("USER scanner", 0, smoke_position),
            text.rfind("USER octo", 0, smoke_position),
        ]
        assert max(user_positions) >= 0, f"{path} runs the browser smoke check as root"


def test_api_only_image_does_not_gain_a_browser_runtime():
    text = API_DOCKERFILE.read_text(encoding="utf-8")
    assert "requirements-screenshots.txt" not in text
    assert "PLAYWRIGHT_BROWSERS_PATH" not in text
    assert "playwright install" not in text


def test_browser_smoke_script_is_network_free_and_valid_python():
    source = SMOKE_SCRIPT.read_text(encoding="utf-8")
    ast.parse(source, filename=str(SMOKE_SCRIPT))
    assert "page.set_content(" in source
    assert "page.goto(" not in source
    assert "http://" not in source
    assert "https://" not in source
    assert "PNG_SIGNATURE" in source


def test_docs_no_longer_claim_official_images_lack_playwright():
    configuration = (ROOT / "docs/configuration.md").read_text(encoding="utf-8")
    third_party = (ROOT / "docs/third-party.md").read_text(encoding="utf-8")
    default_config = (ROOT / "scanner/config/default.yaml").read_text(encoding="utf-8")

    assert "not baked into the default image" not in configuration
    assert "official scanner and all-in-one images include" in configuration.lower()
    assert "Playwright 1.63.0" in third_party
    assert "scanner/all-in-one images include chromium" in default_config.lower()
