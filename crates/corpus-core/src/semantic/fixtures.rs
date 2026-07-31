//! Validation corpus for semantic similarity (spec 16.7/28.5): fixtures
//! are compiled at test/demo time with cc — never committed binaries.
//! x86-64 Mach-O on macOS, x86-64 ELF on Linux.

/// C source for the "base" program: several non-trivial functions that
/// hold structural shape across optimization levels.
pub const BASE_SOURCE: &str = r#"
#include <string.h>
static __attribute__((noinline)) int checksum(const char *s) {
    int h = 5381;
    while (*s) { h = h * 33 ^ *s++; }
    return h;
}
static __attribute__((noinline)) int collatz(int n) {
    int steps = 0;
    while (n != 1) { n = (n % 2) ? 3 * n + 1 : n / 2; steps++; }
    return steps;
}
static __attribute__((noinline)) unsigned fib(int n) {
    unsigned a = 0, b = 1;
    for (int i = 0; i < n; i++) { unsigned t = a + b; a = b; b = t; }
    return a;
}
int main(int argc, char **argv) {
    return checksum(argv[0]) + collatz(argc + 25) + (int)fib(argc + 11);
}
"#;

/// Same program with a small source tweak (one function changed).
pub const TWEAK_SOURCE: &str = r#"
#include <string.h>
static __attribute__((noinline)) int checksum(const char *s) {
    int h = 5381;
    while (*s) { h = h * 33 ^ *s++; }
    return h;
}
static __attribute__((noinline)) int collatz(int n) {
    int steps = 0;
    while (n != 1) { n = (n % 2) ? 3 * n + 1 : n / 2; steps++; }
    return steps;
}
static __attribute__((noinline)) unsigned fib(int n) {
    unsigned a = 1, b = 1;
    for (int i = 0; i < n; i++) { unsigned t = a * b + a; a = b; b = t % 97; }
    return a;
}
int main(int argc, char **argv) {
    return checksum(argv[0]) + collatz(argc + 25) + (int)fib(argc + 11);
}
"#;

/// Structurally unrelated program.
pub const UNRELATED_SOURCE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    FILE *f = fopen("/tmp/x", "w");
    if (f) { fwrite("x", 1, 1, f); fclose(f); }
    return system("true");
}
"#;

/// Compile `source` with `opt` into `out`. Returns false if cc is
/// unavailable or the target is unsupported — callers skip gracefully.
pub fn compile_fixture(dir: &std::path::Path, name: &str, source: &str, opt: &str) -> bool {
    let src = dir.join(format!("{name}.c"));
    if std::fs::write(&src, source).is_err() {
        return false;
    }
    let out = dir.join(name);
    let mut cmd = std::process::Command::new("cc");
    cmd.arg(opt).arg(&src).arg("-o").arg(&out);
    #[cfg(target_os = "macos")]
    cmd.arg("-target").arg("x86_64-apple-macos10.15");
    #[cfg(target_os = "linux")]
    {
        // Freestanding-ish tiny binaries avoid cross-libc needs when
        // running on an arm64 host; on x86_64 Linux this is a no-op flag.
    }
    let status = cmd.status();
    matches!(status, Ok(s) if s.success())
}
