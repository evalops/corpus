#!/usr/bin/env bash
# Milestone 0 end-to-end demo:
#   Postgres via docker compose -> migrations -> directory import ->
#   rule + immutable bundle -> retro-hunt (twice, proving idempotency) ->
#   blast-radius JSON report -> forward-coverage check.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgres://corpus:corpus@127.0.0.1:5433/corpus}"
export CORPUS_CAS_ROOT="${CORPUS_CAS_ROOT:-./data/cas}"
export CORPUS_LISTEN="${CORPUS_LISTEN:-127.0.0.1:8080}"
export CORPUS_SERVER_URL="http://${CORPUS_LISTEN}"
export CORPUS_TEST_DATABASE_URL="$DATABASE_URL"

SERVER_LOG=".demo-server.log"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "==> starting postgres (docker compose)"
docker compose up -d postgres
for i in $(seq 1 60); do
    if docker compose exec -T postgres pg_isready -U corpus -d corpus >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "==> building workspace"
cargo build

echo "==> generating fixtures"
bash scripts/gen-testdata.sh testdata

echo "==> starting corpus-server (applies migrations at boot)"
rm -rf "$CORPUS_CAS_ROOT"
cargo run -p corpus-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 120); do
    if curl -fsS "http://${CORPUS_LISTEN}/api/v1/health" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS "http://${CORPUS_LISTEN}/api/v1/health" && echo

CTL="cargo run -q -p corpusctl --"
# Demo runs under an explicit tenant so multi-tenancy is exercised end-to-end.
# The seeded `default` tenant still works when --tenant is omitted.
TENANT_SLUG="demo"
echo "==> ensuring demo tenant exists"
$CTL tenants create --slug "$TENANT_SLUG" --name "Demo tenant" >/dev/null 2>&1 \
  || $CTL tenants get "$TENANT_SLUG"
$CTL tenants list
CTL_T="$CTL --tenant $TENANT_SLUG"

echo "==> importing testdata (first pass: uploads)"
$CTL_T import testdata --capture-reason baseline

echo "==> re-importing (second pass: dedup hits still record occurrences)"
$CTL_T import testdata --capture-reason baseline

echo "==> registering rule"
$CTL_T rules add testdata/corpus_demo_marker.yar

echo "==> publishing immutable bundle with forward coverage active"
BUNDLE_OUT=$($CTL_T bundles publish --rule CorpusDemoMarker --activate)
echo "$BUNDLE_OUT"
DIGEST=$(echo "$BUNDLE_OUT" | sed -n 's/^bundle_digest: \([0-9a-f]*\).*/\1/p')

echo "==> creating and running retro-hunt"
HUNT_OUT=$($CTL_T hunts create --bundle "$DIGEST")
echo "$HUNT_OUT"
HUNT_ID=$(echo "$HUNT_OUT" | sed -n 's/^hunt_id: \([0-9a-f-]*\).*/\1/p')
$CTL_T hunts run "$HUNT_ID"

echo "==> re-running the same hunt (must hit the scan cache, no duplicate matches)"
$CTL_T hunts run "$HUNT_ID"

echo "==> blast-radius report for hunt $HUNT_ID"
$CTL_T report blast-radius --hunt "$HUNT_ID"

echo "==> forward coverage: importing the late marker file with the bundle active"
$CTL_T import testdata-late --capture-reason cli_import

echo "==> hunts known to the server (note the forward hunt)"
$CTL_T hunts list

echo "==> integration test against the same database (tempfile CAS)"
cargo test -p corpus-core --test ingest_hunt -- --nocapture

echo "==> demo complete"
