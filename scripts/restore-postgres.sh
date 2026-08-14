#!/usr/bin/env sh
set -eu

usage() {
  cat <<'EOF'
Usage: scripts/restore-postgres.sh --namespace NAMESPACE --backup FILE [--checksum FILE]

Restores a pg_dump custom-format archive into the Shapoclyack PostgreSQL pod in
an isolated Kubernetes namespace. The script refuses to run against the default
production namespace unless ALLOW_PRODUCTION_RESTORE=1 is set explicitly.

Requirements: kubectl, sha256sum (or shasum), and a ready shapoclyack-postgres pod.
EOF
}

namespace=""
backup=""
checksum=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --namespace)
      namespace="${2:-}"
      shift 2
      ;;
    --backup)
      backup="${2:-}"
      shift 2
      ;;
    --checksum)
      checksum="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[ -n "$namespace" ] || { echo "--namespace is required" >&2; exit 2; }
[ -n "$backup" ] || { echo "--backup is required" >&2; exit 2; }
[ -f "$backup" ] || { echo "backup not found: $backup" >&2; exit 2; }

if [ "$namespace" = "network-scan" ] && [ "${ALLOW_PRODUCTION_RESTORE:-0}" != "1" ]; then
  echo "refusing restore into network-scan; use an isolated namespace or set ALLOW_PRODUCTION_RESTORE=1" >&2
  exit 3
fi

if [ -z "$checksum" ]; then
  checksum="${backup}.sha256"
fi

if [ -f "$checksum" ]; then
  echo "Verifying backup checksum..."
  expected="$(awk '{print $1}' "$checksum")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$backup" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$backup" | awk '{print $1}')"
  else
    echo "neither sha256sum nor shasum is available" >&2
    exit 4
  fi
  [ "$expected" = "$actual" ] || {
    echo "checksum mismatch for $backup" >&2
    exit 4
  }
else
  echo "checksum file not found: $checksum" >&2
  exit 4
fi

selector='app.kubernetes.io/name=shapoclyack,app.kubernetes.io/component=postgres'
pod="$(kubectl -n "$namespace" get pods -l "$selector" \
  -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\n"}{end}' | head -n 1)"

[ -n "$pod" ] || {
  echo "no running PostgreSQL pod found in namespace $namespace" >&2
  exit 5
}

kubectl -n "$namespace" wait --for=condition=Ready "pod/$pod" --timeout=120s

remote="/tmp/shapoclyack-restore.dump"
echo "Copying archive to $namespace/$pod..."
kubectl -n "$namespace" cp "$backup" "$pod:$remote"

started="$(date +%s)"
echo "Restoring database in $namespace..."
kubectl -n "$namespace" exec "$pod" -- sh -ec '
  export PGPASSWORD="$POSTGRES_PASSWORD"
  pg_restore \
    --host=127.0.0.1 \
    --port=5432 \
    --username=octo \
    --dbname=shapoclyack \
    --clean \
    --if-exists \
    --no-owner \
    --no-privileges \
    --exit-on-error \
    /tmp/shapoclyack-restore.dump
  rm -f /tmp/shapoclyack-restore.dump
'

echo "Validating restored database..."
kubectl -n "$namespace" exec "$pod" -- sh -ec '
  export PGPASSWORD="$POSTGRES_PASSWORD"
  pg_isready -h 127.0.0.1 -U octo -d shapoclyack
  psql -h 127.0.0.1 -U octo -d shapoclyack -v ON_ERROR_STOP=1 -Atc \
    "select version_num from alembic_version limit 1" >/dev/null
  psql -h 127.0.0.1 -U octo -d shapoclyack -v ON_ERROR_STOP=1 -Atc \
    "select count(*) from tenants" >/dev/null
'

finished="$(date +%s)"
duration="$((finished - started))"
printf 'restore_success namespace=%s duration_seconds=%s backup=%s\n' \
  "$namespace" "$duration" "$backup"
