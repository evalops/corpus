#!/usr/bin/env bash
# Generate the demo/test fixture directory. Fixtures are built, never
# committed: a tiny compiled binary via cc, two synthetic header fixtures
# written with printf, and text files carrying the demo marker string.
set -euo pipefail

OUT="${1:-testdata}"
rm -rf "$OUT"
mkdir -p "$OUT"

MARKER="CORPUS_DEMO_MARKER_STRING"

# 1. Tiny compiled fixture (Mach-O on macOS, ELF on Linux).
cat > "$OUT/hello.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("corpus demo fixture"); return 0; }
EOF
if command -v cc >/dev/null 2>&1; then
    cc -O1 -o "$OUT/hello-bin" "$OUT/hello.c"
else
    # Fallback: synthetic minimal header if no C compiler exists.
    printf '\x7fELF\x02\x01\x01\x00synthetic-elf-fixture' > "$OUT/hello-bin"
fi

# 2. Synthetic PE fixture (MZ + e_lfanew -> PE signature) built with printf.
printf 'MZ' > "$OUT/synthetic.exe"
head -c 58 /dev/zero >> "$OUT/synthetic.exe"
printf '\x80\x00\x00\x00' >> "$OUT/synthetic.exe"   # e_lfanew = 0x80
head -c 64 /dev/zero >> "$OUT/synthetic.exe"
printf 'PE\x00\x00' >> "$OUT/synthetic.exe"
printf '%s\n' "$MARKER embedded in synthetic PE body" >> "$OUT/synthetic.exe"

# 3. Text file carrying the marker (what the demo rule matches).
cat > "$OUT/notes.txt" <<EOF
Quarterly notes, totally benign.
Except this line carries the $MARKER marker.
EOF

# 4. A file with no marker (clean scan result).
printf 'just an ordinary text file with nothing interesting\n' > "$OUT/clean.txt"

# The demo rule. One rule per file (M0 registry constraint).
cat > "$OUT/corpus_demo_marker.yar" <<'EOF'
rule CorpusDemoMarker {
    meta:
        description = "Synthetic demo marker for the corpus M0 demo; not malware"
        author = "corpus"
        license = "Apache-2.0"
    strings:
        $m = "CORPUS_DEMO_MARKER_STRING"
    condition:
        $m
}
EOF

# Late-added file used to demonstrate forward coverage after activation.
# Kept OUTSIDE $OUT so the first import pass does not commit it early.
LATE_DIR="${OUT}-late"
rm -rf "$LATE_DIR"
mkdir -p "$LATE_DIR"
cat > "$LATE_DIR/late-marker.txt" <<EOF
This file appears after the bundle was activated and still carries $MARKER.
EOF

echo "fixtures generated in $OUT and $LATE_DIR:"
ls -la "$OUT" "$LATE_DIR"
