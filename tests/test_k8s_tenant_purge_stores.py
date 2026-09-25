"""Every shipped API deployment can finish a tenant purge (#325, review round 2).

A purge step whose store is not configured fails unless the installation
declares the store unused (``OCTO_TENANT_PURGE_UNUSED_STORES``), and the
approval refuses up front on a replica that would fail that way. The shipped
manifests have to agree with that rule, or every deletion on them is refused —
so each overlay is rendered and its API container checked: for ClickHouse and
for NATS, the URL is set or the store is declared unused.

Needs the ``kustomize`` binary on ``PATH`` — the one
``k8s/scripts/validate-kustomize.sh`` uses; skipped without it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / "k8s" / "shapoclyack"
OVERLAYS = sorted(path for path in (ROOT / "overlays").iterdir() if path.is_dir())

#: Store name in OCTO_TENANT_PURGE_UNUSED_STORES -> the URL that configures it.
STORES = {"clickhouse": "OCTO_CLICKHOUSE_URL", "jetstream": "OCTO_NATS_URL"}


def _kustomize() -> str | None:
    return shutil.which("kustomize")


def _api_env(overlay: Path) -> dict[str, str] | None:
    rendered = subprocess.run(
        [_kustomize(), "build", str(overlay)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for document in yaml.safe_load_all(rendered):
        if not document or document.get("kind") != "Deployment":
            continue
        if document["metadata"]["name"] != "shapoclyack-api":
            continue
        for container in document["spec"]["template"]["spec"].get("containers", []):
            if container["name"] == "api":
                return {
                    item["name"]: item.get("value") or "" for item in container.get("env") or []
                }
    return None


@pytest.mark.skipif(_kustomize() is None, reason="kustomize not installed")
@pytest.mark.parametrize("overlay", OVERLAYS, ids=[path.name for path in OVERLAYS])
def test_every_overlays_api_has_each_purge_store_configured_or_declared_unused(overlay):
    env = _api_env(overlay)
    if env is None:
        pytest.skip(f"{overlay.name} renders no API deployment")
    unused = {
        part.strip() for part in env.get("OCTO_TENANT_PURGE_UNUSED_STORES", "").split(",") if part.strip()
    }
    for store, url in STORES.items():
        assert env.get(url) or store in unused, (
            f"{overlay.name}: {url} is empty and {store} is not in "
            f"OCTO_TENANT_PURGE_UNUSED_STORES ({sorted(unused)}): every purge would stop there"
        )
