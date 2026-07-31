#!/usr/bin/env bash
# Milestone 4 (vault bootstrap) end-to-end demo:
#   two fake snapshots -> backfill -> hunt over backfilled history ->
#   OCI import of alpine (real registry) -> mock TAXII hash hunt ->
#   mock MalwareBazaar intel-scope import.
# No real malware anywhere: intel flows run against in-process mocks.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgres://corpus:corpus@127.0.0.1:5434/corpus}"
export CORPUS_CAS_ROOT="${CORPUS_CAS_ROOT:-./data/cas}"
export CORPUS_LISTEN="${CORPUS_LISTEN:-127.0.0.1:8080}"
export CORPUS_SERVER_URL="http://${CORPUS_LISTEN}"
export CORPUS_TEST_DATABASE_URL="$DATABASE_URL"

SERVER_LOG=".demo-bootstrap-server.log"
SERVER_PID=""
MOCK_PID=""
DEMO_DIR="bootstrap-demo"

cleanup() {
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
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

echo "==> preparing two fake snapshots"
rm -rf "$DEMO_DIR" data/cas
mkdir -p "$DEMO_DIR/snap1/etc" "$DEMO_DIR/snap2/etc" "$DEMO_DIR/snap2/opt"
printf 'tool binary v1 CORPUS_BOOTSTRAP_MARKER v1\n' > "$DEMO_DIR/snap1/etc/tool.bin"
printf 'app shared payload\n' > "$DEMO_DIR/snap1/etc/app.bin"
printf 'tool binary v2 changed CORPUS_BOOTSTRAP_MARKER v2\n' > "$DEMO_DIR/snap2/etc/tool.bin"
printf 'app shared payload\n' > "$DEMO_DIR/snap2/opt/app.bin"
cat > "$DEMO_DIR/snapshot-times.txt" <<EOF
$DEMO_DIR/snap1 2024-01-15T08:00:00Z
$DEMO_DIR/snap2 2024-03-20T08:00:00Z
EOF

echo "==> starting corpus-server (fresh CAS)"
cargo run -p corpus-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 120); do
    curl -fsS "http://${CORPUS_LISTEN}/api/v1/health" >/dev/null 2>&1 && break
    sleep 1
done

CTL="cargo run -q -p corpusctl --"

echo "==> backfilling snapshots oldest-to-newest (host prod-web-1)"
$CTL backfill --snapshot-times-file "$DEMO_DIR/snapshot-times.txt" --host prod-web-1

echo "==> blast radius of the shared payload (occurrence range spans both snapshots)"
APP_SHA=$(printf 'app shared payload\n' | shasum -a 256 | cut -d' ' -f1)
$CTL report blast-radius --sha256 "$APP_SHA" | python3 -c '
import json,sys
r=json.load(sys.stdin)
for h in r["hosts"]:
    print("host:", h["host_name"], "first:", h["first_observed"], "last:", h["last_observed"], "paths:", h["paths"])
for o in r["occurrences"]:
    print("occ:", o["path"], o["capture_reason"], o["observed_at"])'

echo "==> hunt over backfilled history (marker v2)"
$CTL rules add /dev/stdin <<'EOF'
rule BootstrapV2Marker {
    strings:
        $m = "CORPUS_BOOTSTRAP_MARKER v2"
    condition:
        $m
}
EOF
DIGEST=$($CTL bundles publish --rule BootstrapV2Marker | sed -n 's/^bundle_digest: \([0-9a-f]*\).*/\1/p')
HUNT_ID=$($CTL hunts create --bundle "$DIGEST" | sed -n 's/^hunt_id: \([0-9a-f-]*\).*/\1/p')
$CTL hunts run "$HUNT_ID"
$CTL report blast-radius --hunt "$HUNT_ID" | python3 -c '
import json,sys
r=json.load(sys.stdin)
for a in r["artifacts"]:
    print("matched artifact:", a["sha256"][:16], a["artifact_class"])
for o in r["occurrences"]:
    print("occ:", o["host_name"], o["path"], o["observed_at"], o["capture_reason"])'

echo "==> OCI import of alpine:3.20 from Docker Hub (real registry, anonymous token)"
$CTL import-oci alpine:3.20

echo "==> mock TAXII + MalwareBazaar servers"
python3 - "$APP_SHA" >"$DEMO_DIR/mock.log" 2>&1 <<'EOF' &
import http.server, json, sys, zipfile, io

APP_SHA = sys.argv[1]

stix = {"type": "bundle", "objects": [
    {"type": "indicator", "id": "indicator--demo1",
     "pattern": "[file:hashes.'SHA-256' = '%s']" % APP_SHA},
]}

sample_zip_buf = io.BytesIO()
with zipfile.ZipFile(sample_zip_buf, "w") as z:
    z.writestr("mock-sample.exe", b"MZ mock intel sample bytes (NOT real malware)")
SAMPLE_ZIP = sample_zip_buf.getvalue()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _body(self):
        n = int(self.headers.get("content-length", 0))
        return self.rfile.read(n) if n else b""
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if "/collections/" in self.path and "/objects/" in self.path:
            self._send(200, json.dumps(stix).encode(), "application/taxii+json;version=2.1")
        else:
            self._send(404, b"{}")
    def do_POST(self):
        body = self._body().decode()
        if "get_recent" in body:
            self._send(200, json.dumps({"query_status": "ok", "data": [
                {"sha256_hash": "0" * 64, "file_name": "mock-sample.exe"}]}).encode())
        elif "get_file" in body:
            self._send(200, SAMPLE_ZIP, "application/zip")
        else:
            self._send(404, b"{}")

http.server.HTTPServer(("127.0.0.1", 8899), H).serve_forever()
EOF
MOCK_PID=$!
sleep 2

echo "==> TAXII poll + auto hash hunt over endpoint-scope artifacts"
$CTL intel taxii --url http://127.0.0.1:8899 --collection col-1 --auto-hunt || true

echo "==> MalwareBazaar import (mocked, scope=intel, NO occurrences)"
$CTL intel malwarebazaar --url http://127.0.0.1:8899 --limit 1 || true

echo "==> blast radius of the intel sample: artifact present, zero occurrences"
MOCK_SHA=$(printf 'MZ mock intel sample bytes (NOT real malware)' | shasum -a 256 | cut -d' ' -f1)
$CTL report blast-radius --sha256 "$MOCK_SHA" | python3 -c '
import json,sys
r=json.load(sys.stdin)
print("artifacts:", len(r["artifacts"]), "occurrences:", len(r["occurrences"]))'

echo "==> integration test against the same database"
cargo test -p corpus-core --test bootstrap -- --nocapture

echo "==> demo-bootstrap complete"
