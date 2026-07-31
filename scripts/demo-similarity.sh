#!/usr/bin/env bash
# Milestone 3a end-to-end similarity demo:
#   two recompiled-with-tweak variants + an unrelated binary + two
#   near-identical blobs -> normalized_equivalent group, byte_similar
#   weak lead, blast-radius variant expansion.
set -euo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgres://corpus:corpus@127.0.0.1:5434/corpus}"
export CORPUS_CAS_ROOT="${CORPUS_CAS_ROOT:-./data/cas}"
export CORPUS_LISTEN="${CORPUS_LISTEN:-127.0.0.1:8080}"
export CORPUS_SERVER_URL="http://${CORPUS_LISTEN}"
export CORPUS_TEST_DATABASE_URL="$DATABASE_URL"

SERVER_LOG=".demo-similarity-server.log"
SERVER_PID=""
DEMO_DIR="demo-sim"

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
    docker compose exec -T postgres pg_isready -U corpus -d corpus >/dev/null 2>&1 && break
    sleep 1
done

echo "==> building workspace"
cargo build

echo "==> generating variant fixtures"
rm -rf "$DEMO_DIR" data/cas
mkdir -p "$DEMO_DIR"

# v1 and v2: same functions, one changed string -> same import table,
# different SHA-256. macOS: target macos11 for goblin-readable imports.
TARGET_FLAG=""
if [ "$(uname)" = "Darwin" ]; then
    case "$(uname -m)" in
        arm64) TARGET_FLAG="-target arm64-apple-macos11" ;;
        x86_64) TARGET_FLAG="-target x86_64-apple-macos10.15" ;;
    esac
fi

cat > "$DEMO_DIR/tool_v1.c" <<'EOF'
#include <stdio.h>
#include <string.h>
static int scan(const char *p) { return (int)strlen(p) * 7; }
static void report(int v) { printf("scanner v1 result: %d\n", v); }
int main(void) { report(scan("/usr/bin")); return 0; }
EOF
sed 's/scanner v1 result/scanner v2 result/' "$DEMO_DIR/tool_v1.c" > "$DEMO_DIR/tool_v2.c"

cat > "$DEMO_DIR/unrelated.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    FILE *f = fopen("/tmp/unrelated-demo", "w");
    if (!f) return 1;
    fwrite("x", 1, 1, f);
    fclose(f);
    return 0;
}
EOF

cc -O1 $TARGET_FLAG -o "$DEMO_DIR/tool_v1" "$DEMO_DIR/tool_v1.c"
cc -O1 $TARGET_FLAG -o "$DEMO_DIR/tool_v2" "$DEMO_DIR/tool_v2.c"
cc -O1 $TARGET_FLAG -o "$DEMO_DIR/unrelated" "$DEMO_DIR/unrelated.c"

# Two near-identical large blobs: byte_similar weak lead only.
python3 - <<EOF
d = bytes((i % 251) for i in range(8192))
e = bytearray(d); e[1000] ^= 0xff; e[5000] ^= 0xff
open("$DEMO_DIR/blob_d.bin", "wb").write(d)
open("$DEMO_DIR/blob_e.bin", "wb").write(bytes(e))
EOF

echo "==> starting corpus-server (fresh CAS)"
cargo run -p corpus-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 120); do
    curl -fsS "http://${CORPUS_LISTEN}/api/v1/health" >/dev/null 2>&1 && break
    sleep 1
done

CTL="cargo run -q -p corpusctl --"

echo "==> importing fixtures (post-commit similarity analysis runs automatically)"
$CTL import "$DEMO_DIR"

V1_SHA=$(shasum -a 256 "$DEMO_DIR/tool_v1" | cut -d' ' -f1)
V2_SHA=$(shasum -a 256 "$DEMO_DIR/tool_v2" | cut -d' ' -f1)
UN_SHA=$(shasum -a 256 "$DEMO_DIR/unrelated" | cut -d' ' -f1)
BD_SHA=$(shasum -a 256 "$DEMO_DIR/blob_d.bin" | cut -d' ' -f1)

echo "==> corpusctl similar <tool_v1> (expect normalized_equivalent -> tool_v2)"
$CTL similar "$V1_SHA"

echo "==> corpusctl variants <tool_v1> (expect group: tool_v1 + tool_v2)"
$CTL variants "$V1_SHA"

echo "==> corpusctl variants <unrelated> (expect isolated)"
$CTL variants "$UN_SHA"

echo "==> corpusctl similar <blob_d> (expect byte_similar weak lead -> blob_e)"
$CTL similar "$BD_SHA"

echo "==> corpusctl variants <blob_d> (expect EMPTY: fuzzy never merges groups)"
$CTL variants "$BD_SHA"

echo "==> blast-radius --sha256 <tool_v2> --expand-variants"
$CTL report blast-radius --sha256 "$V2_SHA" --expand-variants

echo "==> backfill (expect analyzed: 0 -- post-commit already covered everything)"
$CTL similarity backfill

echo "==> integration test against the same database"
cargo test -p corpus-core --test similarity -- --nocapture

echo "==> demo-similarity complete"
