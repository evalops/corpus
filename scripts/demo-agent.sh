#!/usr/bin/env bash
# Milestone 1 end-to-end agent demo:
#   server up -> enroll -> Linux agent (fanotify in a privileged container)
#   baselines a tmpfs watch dir -> a dropped file is captured via fanotify
#   (proven by beating the long poll interval) -> an oversized file yields
#   TOO_LARGE -> corpusctl shows fleet health and coverage gaps.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgres://corpus:corpus@127.0.0.1:5434/corpus}"
export CORPUS_CAS_ROOT="${CORPUS_CAS_ROOT:-./data/cas}"
# Server must listen on all interfaces so the container can reach the host.
export CORPUS_LISTEN="${CORPUS_LISTEN:-0.0.0.0:8080}"
export CORPUS_AGENT_LISTEN="${CORPUS_AGENT_LISTEN:-0.0.0.0:8443}"
export CORPUS_SERVER_URL="http://127.0.0.1:8080"
export CORPUS_TEST_DATABASE_URL="$DATABASE_URL"
# Server cert SANs must cover the name the container uses for the host.
export CORPUS_CA_SANS="host.docker.internal"

SERVER_LOG=".demo-agent-server.log"
SERVER_PID=""
CONTAINER="corpus-agent-demo"
DEMO_DIR="agent-demo"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

wait_for() { # wait_for <description> <timeout_secs> <command...>
    local desc="$1" timeout="$2"; shift 2
    local elapsed=0
    until "$@" >/dev/null 2>&1; do
        sleep 2; elapsed=$((elapsed + 2))
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "TIMEOUT waiting for: $desc" >&2
            return 1
        fi
    done
    echo "OK ($elapsed s): $desc"
}

echo "==> starting postgres (docker compose)"
docker compose up -d postgres
for i in $(seq 1 60); do
    docker compose exec -T postgres pg_isready -U corpus -d corpus >/dev/null 2>&1 && break
    sleep 1
done

echo "==> building host binaries"
cargo build -p corpus-server -p corpusctl

echo "==> starting corpus-server"
cargo run -p corpus-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
wait_for "server health" 60 curl -fsS "http://127.0.0.1:8080/api/v1/health"

CTL="cargo run -q -p corpusctl --"

echo "==> minting one-time enrollment token"
TOKEN_OUT=$($CTL enroll-token create --label demo-agent --ttl-secs 3600)
echo "$TOKEN_OUT"
TOKEN=$(echo "$TOKEN_OUT" | sed -n 's/^enrollment_token: //p')
$CTL ca init

echo "==> mTLS default-on proof: bearer-only heartbeat on the plain listener is rejected"
curl -s -o /dev/null -w 'plain-listener bearer heartbeat -> HTTP %{http_code} (expect 401)\n' \
    -X POST "http://127.0.0.1:8080/api/v1/agents/heartbeat" \
    -H 'Authorization: Bearer cpagent-bogus' -H 'Content-Type: application/json' \
    -d '{"agent_version":"x","policy_digest":"x","baseline_state":"complete","baseline_percent":100,"queue_depth":0,"spool_bytes":0,"oldest_pending_secs":null,"sensor":"x","outcome_counts":{},"last_upload_at":null,"clock_offset_ms":null}'

echo "==> preparing fixtures and agent config"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/fixtures"
cat > "$DEMO_DIR/fixtures/app.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("corpus agent demo"); return 0; }
EOF
cc -O1 -o "$DEMO_DIR/fixtures/app.bin" "$DEMO_DIR/fixtures/app.c"
printf 'notes with CORPUS_DEMO_MARKER_STRING inside\n' > "$DEMO_DIR/fixtures/notes.txt"
printf 'dropped later, also has CORPUS_DEMO_MARKER_STRING\n' > "$DEMO_DIR/fixtures/dropped.txt"
head -c 300000 /dev/zero > "$DEMO_DIR/fixtures/big.bin"

cat > "$DEMO_DIR/agent.yaml" <<EOF
server_url: http://host.docker.internal:8080
agent_url: https://host.docker.internal:8443
enrollment_token: $TOKEN
host_name: corpus-demo-agent
state_dir: /agent/state
spool_dir: /agent/spool
heartbeat_interval_secs: 5
watch:
  paths: [/watch]
  poll_interval_secs: 45   # long on purpose: fanotify must beat this to prove itself
  debounce_ms: 500
  exclusions: []
baseline:
  enabled: true
limits:
  max_artifact_bytes: 200000   # big.bin (300000) must yield TOO_LARGE
  max_spool_bytes: 50000000
  max_concurrent_reads: 2
  stable_read_retries: 3
  max_attempts: 8
EOF

echo "==> building corpus-agent for Linux (first run is slow; cached in volumes)"
docker run --rm \
    -v "$PWD:/src:ro" \
    -v corpus-cargo-home:/cargo \
    -v corpus-target-linux:/target \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
    rust:1-bookworm \
    bash -c 'apt-get update -qq >/dev/null && apt-get install -y -qq protobuf-compiler >/dev/null && cd /src && cargo build -p corpus-agent'

echo "==> starting agent in a privileged Linux container (fanotify on tmpfs /watch)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --privileged --hostname corpus-demo-agent \
    -v "$PWD/$DEMO_DIR/fixtures:/fixtures:ro" \
    -v "$PWD/$DEMO_DIR/agent.yaml:/agent.yaml:ro" \
    -v corpus-target-linux:/target \
    rust:1-bookworm \
    bash -c 'mkdir -p /watch /agent && mount -t tmpfs tmpfs /watch && cp /fixtures/app.bin /fixtures/notes.txt /watch/ && exec /target/debug/corpus-agent --config /agent.yaml run'

wait_for "agent enrollment + fanotify mark" 60 docker logs "$CONTAINER"
docker logs "$CONTAINER" 2>&1 | grep -E 'enrolled|fanotify' || true
docker logs "$CONTAINER" 2>&1 | grep -q 'mTLS client cert issued' && echo "mTLS enrollment confirmed in agent log"

APP_SHA=$(shasum -a 256 "$DEMO_DIR/fixtures/app.bin" | cut -d' ' -f1)
DROP_SHA=$(shasum -a 256 "$DEMO_DIR/fixtures/dropped.txt" | cut -d' ' -f1)

echo "==> waiting for baseline captures (app.bin, notes.txt)"
wait_for "baseline capture of app.bin" 120 \
    sh -c "$CTL report blast-radius --sha256 $APP_SHA | grep -q artifact_id"
$CTL report blast-radius --sha256 "$APP_SHA" | python3 -c '
import json,sys
r=json.load(sys.stdin)
for o in r["occurrences"]:
    print("occurrence:", o["host_name"], o["path"], o["capture_reason"])'

echo "==> dropping a new file into the watch dir (must be captured via fanotify)"
DROP_START=$(date +%s)
docker exec "$CONTAINER" cp /fixtures/dropped.txt /watch/dropped.txt
wait_for "fanotify capture of dropped.txt" 40 \
    sh -c "$CTL report blast-radius --sha256 $DROP_SHA | grep -q artifact_id"
DROP_END=$(date +%s)
echo "dropped file captured after $((DROP_END - DROP_START))s (poll interval is 45s -> fanotify)"
$CTL report blast-radius --sha256 "$DROP_SHA" | python3 -c '
import json,sys
r=json.load(sys.stdin)
for o in r["occurrences"]:
    print("occurrence:", o["host_name"], o["path"], o["capture_reason"])'

echo "==> writing an oversized file (must yield TOO_LARGE)"
docker exec "$CONTAINER" cp /fixtures/big.bin /watch/big.bin
wait_for "TOO_LARGE gap for big.bin" 60 \
    sh -c "$CTL coverage gaps --outcome TOO_LARGE | grep -q big.bin"

echo "==> coverage gaps"
$CTL coverage gaps

echo "==> fleet health"
sleep 6  # allow one more heartbeat
$CTL agents list
AGENT_ID=$($CTL agents list | awk '{print $1}' | head -1)
$CTL agents status "$AGENT_ID"

echo "==> agent container log (tail)"
docker logs "$CONTAINER" 2>&1 | tail -15

echo "==> demo-agent complete"
