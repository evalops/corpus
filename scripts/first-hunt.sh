#!/usr/bin/env bash
# First successful retro-hunt path: Postgres → server → import → rule →
# bundle → hunt → blast-radius. Loopback only; no admin token required.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgres://corpus:corpus@127.0.0.1:5434/corpus}"
export CORPUS_CAS_ROOT="${CORPUS_CAS_ROOT:-./data/cas}"
export CORPUS_LISTEN="${CORPUS_LISTEN:-127.0.0.1:8080}"
export CORPUS_SERVER_URL="http://${CORPUS_LISTEN}"
# Prefer in-process scanning for a fast first-run on any host.
export CORPUS_SCANNER_TIER="${CORPUS_SCANNER_TIER:-inprocess}"

SERVER_LOG=".first-hunt-server.log"
SERVER_PID=""

cleanup() {
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "==> postgres"
docker compose up -d postgres
for _ in $(seq 1 60); do
    if docker compose exec -T postgres pg_isready -U corpus -d corpus >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "==> build"
cargo build -q

if [ ! -f testdata/corpus_demo_marker.yar ]; then
    bash scripts/gen-testdata.sh testdata
fi

echo "==> server"
rm -rf "${CORPUS_CAS_ROOT}"
cargo run -q -p corpus-server >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 120); do
    if curl -fsS "http://${CORPUS_LISTEN}/api/v1/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
curl -fsS "http://${CORPUS_LISTEN}/api/v1/health"
echo

CTL=(cargo run -q -p corpusctl --)

echo "==> import"
"${CTL[@]}" import testdata --capture-reason first-hunt

echo "==> rule + bundle"
"${CTL[@]}" rules add testdata/corpus_demo_marker.yar
BUNDLE_OUT=$("${CTL[@]}" bundles publish --rule CorpusDemoMarker --activate)
echo "${BUNDLE_OUT}"
DIGEST=$(echo "${BUNDLE_OUT}" | sed -n 's/^bundle_digest: \([0-9a-f]*\).*/\1/p')
if [ -z "${DIGEST}" ]; then
    echo "failed to parse bundle digest" >&2
    exit 1
fi

echo "==> hunt"
HUNT_OUT=$("${CTL[@]}" hunts create --bundle "${DIGEST}")
echo "${HUNT_OUT}"
HUNT_ID=$(echo "${HUNT_OUT}" | sed -n 's/^hunt_id: \([0-9a-f-]*\).*/\1/p')
"${CTL[@]}" hunts run "${HUNT_ID}"

echo "==> blast-radius"
"${CTL[@]}" report blast-radius --hunt "${HUNT_ID}"

echo
echo "OK: first hunt complete (hunt_id=${HUNT_ID})."
echo "OpenAPI: http://${CORPUS_LISTEN}/api/v1/openapi.json"
echo "Deploy notes: docs/deploy.md"
