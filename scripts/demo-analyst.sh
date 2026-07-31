#!/usr/bin/env bash
# Milestone 5 (analyst surface) end-to-end demo:
# prevalence -> rarity search -> opinions -> trigger webhook with HMAC ->
# dropper hunt -> proof of absence -> MCP read-only tools.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgres://corpus:corpus@127.0.0.1:5434/corpus}"
export CORPUS_CAS_ROOT="${CORPUS_CAS_ROOT:-./data/cas}"
export CORPUS_LISTEN="${CORPUS_LISTEN:-127.0.0.1:8080}"
export CORPUS_SERVER_URL="http://${CORPUS_LISTEN}"
export CORPUS_TEST_DATABASE_URL="$DATABASE_URL"
export CORPUS_MCP_TOKEN="demo-mcp-token"

SERVER_LOG=".demo-analyst-server.log"
SERVER_PID=""
WEBHOOK_PID=""
DEMO_DIR="analyst-demo"

cleanup() {
    [ -n "$WEBHOOK_PID" ] && kill "$WEBHOOK_PID" 2>/dev/null || true
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "==> starting postgres (docker compose)"
docker compose up -d postgres
for i in $(seq 1 60); do
    docker compose exec -T postgres pg_isready -U corpus -d corpus >/dev/null 2>&1 && break
    sleep 1
done

echo "==> building workspace"
cargo build

echo "==> preparing fixture tree (rare + common files)"
rm -rf "$DEMO_DIR" data/cas
mkdir -p "$DEMO_DIR/host-a" "$DEMO_DIR/host-b" "$DEMO_DIR/host-c" "$DEMO_DIR/host-d"
printf 'seed binary CORPUS_ANALYST_MARKER seed\n' > "$DEMO_DIR/host-a/seed.bin"
printf 'rare helper dropped by seed\n' > "$DEMO_DIR/host-a/helper.bin"
printf 'ubiquitous runtime library\n' > "$DEMO_DIR/host-a/common.bin"
for H in host-b host-c host-d; do
    cp "$DEMO_DIR/host-a/common.bin" "$DEMO_DIR/$H/common.bin"
done

echo "==> starting corpus-server"
cargo run -p corpus-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 120); do
    curl -fsS "http://${CORPUS_LISTEN}/api/v1/health" >/dev/null 2>&1 && break
    sleep 1
done
CTL="cargo run -q -p corpusctl --"

echo "==> importing: seed + helper + common on host-a"
$CTL import "$DEMO_DIR/host-a" --capture-reason baseline >/dev/null

echo "==> simulating fleet: common.bin on host-b..d (backfill preserves host labels)"
for H in host-b host-c host-d; do
    $CTL backfill --root "$DEMO_DIR/$H" --observed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --host "$H" >/dev/null
done

SEED_SHA=$(shasum -a 256 "$DEMO_DIR/host-a/seed.bin" | cut -d' ' -f1)
HELPER_SHA=$(shasum -a 256 "$DEMO_DIR/host-a/helper.bin" | cut -d' ' -f1)
COMMON_SHA=$(shasum -a 256 "$DEMO_DIR/host-a/common.bin" | cut -d' ' -f1)

echo "==> prevalence"
$CTL prevalence "$COMMON_SHA"
$CTL prevalence "$SEED_SHA"

echo "==> rarity search (max 2 hosts)"
$CTL search --max-hosts 2 --since 1h | python3 -c '
import json,sys
for h in json.load(sys.stdin):
    print("rare:", h["sha256"][:16], "hosts:", h["prevalence"]["host_count"], "class:", h["artifact_class"])'

echo "==> opinions: suspicious -> malicious on the seed"
$CTL opinion set "$SEED_SHA" suspicious --reason "rare, near-drop of unknown origin" --actor demo-analyst >/dev/null
$CTL opinion set "$SEED_SHA" malicious --reason "confirmed by detonation elsewhere" --actor demo-analyst >/dev/null
$CTL opinion get "$SEED_SHA"
$CTL opinion history "$SEED_SHA" | python3 -c '
import json,sys
for o in json.load(sys.stdin):
    print("history:", o["opinion"], "by", o["actor"], "superseded:", o["superseded_by"] is not None)'

echo "==> webhook trigger (hunt_match) with HMAC verification"
python3 - >"$DEMO_DIR/webhook.log" 2>&1 <<'EOF' &
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        sig = self.headers.get("x-corpus-signature", "?")
        print("WEBHOOK sig=%s body=%s" % (sig, body.decode()), flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
http.server.HTTPServer(("127.0.0.1", 8899), H).serve_forever()
EOF
WEBHOOK_PID=$!
sleep 1
TRIG_OUT=$($CTL triggers create --name match-hook --condition hunt_match --webhook-url http://127.0.0.1:8899/hook)
echo "$TRIG_OUT"
TRIG_ID=$(echo "$TRIG_OUT" | sed -n 's/^trigger_id: \([0-9a-f-]*\).*/\1/p')
TRIG_SECRET=$(echo "$TRIG_OUT" | sed -n 's/^hmac_secret: //p')

echo "==> hunt matching the seed (fires the trigger)"
$CTL rules add /dev/stdin >/dev/null <<'EOF'
rule AnalystSeedMarker {
    strings:
        $m = "CORPUS_ANALYST_MARKER"
    condition:
        $m
}
EOF
DIGEST=$($CTL bundles publish --rule AnalystSeedMarker | sed -n 's/^bundle_digest: \([0-9a-f]*\).*/\1/p')
HUNT_ID=$($CTL hunts create --bundle "$DIGEST" | sed -n 's/^hunt_id: \([0-9a-f-]*\).*/\1/p')
$CTL hunts run "$HUNT_ID"
sleep 4
echo "--- webhook receiver log:"
cat "$DEMO_DIR/webhook.log"
echo "--- verifying HMAC locally:"
python3 - "$TRIG_SECRET" "$DEMO_DIR/webhook.log" <<'EOF'
import hmac, hashlib, sys, re
secret, log = sys.argv[1], open(sys.argv[2]).read()
m = re.search(r'sig=sha256=([0-9a-f]+) body=(.*)', log)
sig, body = m.group(1), m.group(2)
expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
print("signature valid:", hmac.compare_digest(sig, expected))
EOF

echo "==> dropper hunt around the seed"
$CTL hunt droppers --sha256 "$SEED_SHA" | python3 -c '
import json,sys
r = json.load(sys.stdin)
print(r["note"])
for c in r["candidates"]:
    print("candidate:", c["sha256"][:16], "host:", c["host_name"], "hosts:", c["host_count"], "delta_s:", c["min_time_delta_secs"])'

echo "==> proof of absence"
$CTL report blast-radius --sha256 "$(python3 -c 'print("ab"*32)')" | head -12

echo "==> MCP read-only tools"
curl -fsS -X POST "http://${CORPUS_LISTEN}/mcp" \
    -H "Authorization: Bearer $CORPUS_MCP_TOKEN" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python3 -c '
import json,sys
for t in json.load(sys.stdin)["result"]["tools"]:
    print("tool:", t["name"])'
curl -fsS -X POST "http://${CORPUS_LISTEN}/mcp" \
    -H "Authorization: Bearer $CORPUS_MCP_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"get_prevalence\",\"arguments\":{\"sha256\":\"$COMMON_SHA\"}}}" | python3 -c '
import json,sys
print("get_prevalence ->", json.load(sys.stdin)["result"]["content"][0]["text"])'

echo "==> integration test against the same database"
cargo test -p corpus-core --test analyst -- --nocapture

echo "==> demo-analyst complete"
