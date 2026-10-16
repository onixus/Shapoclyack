#!/usr/bin/env bash
#
# ci-sdk.sh: the generated Python SDK stays in step with the API (#354).
#
# 1. Dumps the OpenAPI schema of a default-configured app (every optional
#    router on, throwaway SQLite state, no network) and runs the generator in
#    --check mode: a changed v1 operation without a regenerated
#    sdk/shapoclyack/operations.py fails here, not only in the pytest parity test.
# 2. Builds the sdk/ wheel with --no-deps into a temp dir, when setuptools and
#    wheel are already installed (nothing is downloaded: --no-build-isolation).
#    Without them the build is skipped with a notice.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
PYTHON="${PYTHON:-python}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

"${PYTHON}" - "${work}" <<'PY'
import json
import sys
from pathlib import Path

import api.app
from tests.conftest import make_settings

work = Path(sys.argv[1])
settings = make_settings(work, postgres_url=f"sqlite:///{work / 'schema.db'}")
settings.state_dir.mkdir(parents=True, exist_ok=True)
api.app.get_settings = lambda: settings
(work / "openapi.json").write_text(json.dumps(api.app.create_app().openapi()))
PY
"${PYTHON}" scripts/generate-api-client.py "${work}/openapi.json" --check
echo "[sdk] operations.py matches the OpenAPI schema"

if "${PYTHON}" -c 'import setuptools, wheel' >/dev/null 2>&1; then
  # Built from a copy so setuptools' build/ and *.egg-info stay out of the tree.
  cp -R sdk "${work}/sdk"
  "${PYTHON}" -m pip wheel --quiet --no-deps --no-build-isolation \
    --wheel-dir "${work}/wheel" "${work}/sdk"
  ls "${work}/wheel"/shapoclyack*.whl >/dev/null
  echo "[sdk] wheel builds: $(ls "${work}/wheel")"
else
  echo "[sdk] setuptools/wheel not installed; wheel build skipped"
fi
