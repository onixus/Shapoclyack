#!/usr/bin/env bash
#
# ci-dast.sh: DAST of the Shapoclyack API, and of nothing else.
#
# The product scans other people's networks. A scan of the product must not
# become one of those, so the stand has no route out and the API is told not
# to start a scan of its own. What is exercised is the control plane — auth,
# validation, headers, error handling — against the image this job just built.
#
# The stand is three containers on a network created with `--internal`, so
# there is no default route and no path to the agent's LAN, to the controller,
# or to the internet:
#
#   postgres   the same pinned image the Tests stage uses, data on a bounded
#              tmpfs so a run leaves no volume behind;
#   api        the API image of this build. OCTO_ENV=dev so the published demo
#              accounts exist, OCTO_ALLOW_SCAN_START=false so a request cannot
#              turn the stand into a scanner, and a wildcard CORS only because
#              the browser passive rules need one to judge;
#   zap        ghcr.io/zaproxy/zaproxy, pinned by digest. It imports
#              /openapi.json from the stand and runs the packaged API scan.
#
# The scan is authenticated. A hook logs in as the seeded admin once, before
# the import, and ZAP replays that bearer on every request. The OpenAPI import
# does not follow links, so the hook cannot widen the target, and a request
# that did leave the stand would fail rather than land somewhere: the network
# has no default route.
#
# The gate is ZAP's own exit code. By default every alert is a warning, a
# warning exits 2 and a failure exits 1, and -I is deliberately absent —
# ignoring warnings is how a DAST stage stays green while saying nothing. The
# HTML and JSON reports are written into the workspace either way, so a red
# build still has the findings.
#
# Names come from the caller. A multibranch job numbers every branch from #1,
# so a fixed network or container name collides the moment two branches build
# at once; the same rule as CI_SLUG in the Jenkinsfile.
#
# Usage: scripts/ci-dast.sh <api-image> [name]
#   api-image   The API image this job built (Jenkins: ${IMAGE_TAG}-api).
#   name        Suffix for the network and containers. Default: DAST_NAME, else
#               the current user and pid. Must be unique per concurrent run.
#
#   ZAP_IMAGE       Scanner image. Default: zaproxy stable, pinned by digest
#                   (#313); :stable alone would be a different engine per run.
#   POSTGRES_IMAGE  Same pin as the Tests stage.
#   DAST_MINUTES    Budget for the active scan, and for ZAP startup plus the
#                   passive scan. Default: 15. The active scan of the full
#                   OpenAPI document is the long part; the cap stops a hung
#                   rule from holding the build. The stand's access token
#                   outlives both budgets plus the OpenAPI import. The hook
#                   logs in once, and a token that dies mid-scan is a 401 the
#                   gate does not fail.
#   DAST_REPORT_DIR Directory for zap-report.html and zap-report.json. The
#                   daemon resolves the mount, so this must be a host path.
#                   Default: the repository root.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

API_IMAGE="${1:?usage: scripts/ci-dast.sh <api-image> [name]}"
RAW_NAME="${2:-${DAST_NAME:-${USER:-ci}-$$}}"
NAME="$(printf '%s' "${RAW_NAME}" | tr -c 'A-Za-z0-9-' '-' | tr '[:upper:]' '[:lower:]')"
NAME="${NAME#-}"
NAME="${NAME%-}"
if [ -z "${NAME}" ]; then
  echo "[dast] refusing to run: the run name sanitised to nothing" >&2
  exit 1
fi

ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea}"
DAST_MINUTES="${DAST_MINUTES:-15}"
case "${DAST_MINUTES}" in
  ''|*[!0-9]*)
    echo "[dast] DAST_MINUTES must be a positive number of minutes" >&2
    exit 1
    ;;
esac
if [ "${DAST_MINUTES}" -lt 1 ]; then
  echo "[dast] DAST_MINUTES must be a positive number of minutes" >&2
  exit 1
fi
# zap_started logs in once, then -T and the active-scan cap can each run for
# DAST_MINUTES. Five minutes covers the OpenAPI import between them. The
# access token is capped by the session's absolute end, and an idle timeout
# that is not strictly longer refuses startup in dev as well as prod.
ACCESS_MINUTES=$(( DAST_MINUTES * 2 + 5 ))
IDLE_MINUTES=$(( ACCESS_MINUTES + 5 ))
SESSION_MINUTES=$(( ACCESS_MINUTES + 5 ))
REPORT_DIR="${DAST_REPORT_DIR:-${ROOT_DIR}}"

NET="shapoclyack-dast-${NAME}"
PG="shapoclyack-dast-pg-${NAME}"
API="shapoclyack-dast-api-${NAME}"
SCANNER="shapoclyack-dast-zap-${NAME}"

# Dev-only, and the same values the test suite already publishes. They exist
# so the scan can authenticate; they are not an operator password.
JWT_SECRET="dast-only-jwt-signing-key-32b-min"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin-change-me"

cleanup() {
  local status=$?
  docker rm -f "${SCANNER}" "${API}" "${PG}" >/dev/null 2>&1 || true
  docker network rm "${NET}" >/dev/null 2>&1 || true
  rm -f "${REPORT_DIR}/.dast-env"
  if [ "${status}" -ne 0 ]; then
    echo "[dast] failed (exit ${status}); reports, if any, are in ${REPORT_DIR}" >&2
  fi
}
trap cleanup EXIT

echo "[dast] target image: ${API_IMAGE}"
echo "[dast] scanner: ${ZAP_IMAGE}"
if ! docker image inspect "${API_IMAGE}" >/dev/null 2>&1; then
  echo "[dast] ${API_IMAGE} is not a local image. Build it in this job first;" >&2
  echo "[dast] the scan refuses to pull an API image on its own." >&2
  exit 1
fi

docker rm -f "${SCANNER}" "${API}" "${PG}" >/dev/null 2>&1 || true
docker network rm "${NET}" >/dev/null 2>&1 || true
# --internal: no default route. A container on this network can reach its
# neighbours and nothing else, which is the whole of the containment.
docker network create --internal "${NET}" >/dev/null

# Bounded tmpfs, as in the Tests stage: an anonymous volume survives the
# container and a handful of runs filled the Docker VM disk.
docker run -d --name "${PG}" --network "${NET}" --network-alias pg \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=1g \
  -e POSTGRES_DB=shapoclyack -e POSTGRES_USER=octo -e POSTGRES_PASSWORD=octo-ci-secret \
  "${POSTGRES_IMAGE}" >/dev/null

# No published port. The only way to reach this listener is from ${NET}.
# Written once and shared: the migrate container and the API get the same
# configuration, and a second copy is how those two drift.
mkdir -p "${REPORT_DIR}"
ENV_FILE="${REPORT_DIR}/.dast-env"
cat > "${ENV_FILE}" <<EOF
OCTO_ENV=dev
OCTO_POSTGRES_URL=postgresql+psycopg://octo:octo-ci-secret@pg:5432/shapoclyack
OCTO_JWT_SECRET=${JWT_SECRET}
OCTO_ALLOW_SCAN_START=false
OCTO_API_DOCS=enabled
OCTO_API_CORS=*
OCTO_PUBLIC_BASE_URL=http://api:8080
OCTO_ACCESS_TOKEN_EXPIRE_MINUTES=${ACCESS_MINUTES}
OCTO_SESSION_IDLE_MINUTES=${IDLE_MINUTES}
OCTO_JWT_EXPIRE_MINUTES=${SESSION_MINUTES}
# The API image also carries the console. That shell is HTML with the inline
# scripts a static Next export needs, and this scan judges API content types.
# Point the dist at a path that is not a directory so the shell is not mounted.
OCTO_WEB_DIST=/opt/shapoclyack-dast-no-console
EOF

echo "[dast] waiting for postgres"
ready=0
for _ in $(seq 1 30); do
  if docker exec "${PG}" pg_isready -U octo -d shapoclyack >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "${ready}" -ne 1 ]; then
  echo "[dast] postgres never became ready" >&2
  docker logs --tail 40 "${PG}" >&2 || true
  exit 1
fi

echo "[dast] migrating"
if ! docker run --rm --network "${NET}" --env-file "${ENV_FILE}" --entrypoint python \
  "${API_IMAGE}" -m api.db.migrate; then
  echo "[dast] migration failed" >&2
  exit 1
fi

docker run -d --name "${API}" --network "${NET}" --network-alias api \
  --env-file "${ENV_FILE}" \
  "${API_IMAGE}" >/dev/null

echo "[dast] waiting for /api/health"
healthy=0
for _ in $(seq 1 60); do
  if docker run --rm --network "${NET}" --entrypoint python "${API_IMAGE}" -c \
    "import urllib.request; urllib.request.urlopen('http://api:8080/api/health', timeout=4)" \
    >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 2
done
if [ "${healthy}" -ne 1 ]; then
  echo "[dast] the API never became healthy; last logs:" >&2
  docker logs --tail 60 "${API}" >&2 || true
  exit 1
fi

mkdir -p "${REPORT_DIR}"
rm -f "${REPORT_DIR}/zap-report.html" "${REPORT_DIR}/zap-report.json" \
  "${REPORT_DIR}/zap-auth-hook.py" "${REPORT_DIR}/.dast-env"
cat > "${REPORT_DIR}/zap-auth-hook.py" <<'PY'
"""Log in once, before the import, and replay that bearer on every request.

The packaged API scan imports the spec and then attacks what the spec names.
zap_started runs first, so the replacer rule already exists when the import
starts, and the import does not follow links — which is what keeps the
authentication step from widening the target.
"""

import json
import os
import urllib.request


def _token():
    body = json.dumps(
        {"username": os.environ["DAST_USER"], "password": os.environ["DAST_PASSWORD"]}
    ).encode()
    request = urllib.request.Request(
        "http://api:8080/api/auth/login",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode())
    token = payload.get("access_token")
    if not token:
        raise SystemExit("login returned no access_token; refusing an anonymous scan")
    return token


def zap_started(zap, target):
    token = _token()
    zap.replacer.add_rule(
        description="CI session",
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring="Authorization",
        replacement="Bearer " + token,
    )
PY

# The scanner image runs as uid 1000. On a Linux runner the workspace is
# owned by a different uid and is not world-writable, so the report is never
# created and the missing file is reported as "the scan did not run".
# The directory only: the hook and the checkout stay as the runner wrote them.
chmod a+rwx "${REPORT_DIR}"

echo "[dast] scanning http://api:8080 through its OpenAPI document"
set +e
docker run --name "${SCANNER}" --network "${NET}" \
  -v "${REPORT_DIR}":/zap/wrk:rw \
  -e "DAST_USER=${ADMIN_USER}" -e "DAST_PASSWORD=${ADMIN_PASSWORD}" \
  --entrypoint zap-api-scan.py "${ZAP_IMAGE}" \
  -t http://api:8080/openapi.json -f openapi \
  -O http://api:8080 \
  -J zap-report.json -r zap-report.html \
  -T "${DAST_MINUTES}" \
  -z "-config ascan.maxScanDurationInMins=${DAST_MINUTES}" \
  --hook /zap/wrk/zap-auth-hook.py
zap_status=$?
set -e

echo "[dast] zap-api-scan.py exited ${zap_status}"
if [ ! -s "${REPORT_DIR}/zap-report.json" ]; then
  echo "[dast] no JSON report was written; the scan did not run" >&2
  exit 1
fi
exit "${zap_status}"
