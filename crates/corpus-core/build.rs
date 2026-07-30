//! Build-time capture of the yara-x engine version so scan cache keys and
//! hunt results can name the exact engine that produced them (invariant #7).

fn main() {
    let version = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .ok()
        .and_then(|lock| find_pkg_version(&lock, "yara-x"))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CORPUS_YARA_X_VERSION={version}");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
}

fn find_pkg_version(lock: &str, name: &str) -> Option<String> {
    let mut in_pkg = false;
    let mut found = false;
    for line in lock.lines() {
        match line {
            "[[package]]" => {
                in_pkg = true;
                found = false;
            }
            _ if in_pkg => {
                if let Some(v) = line.strip_prefix("name = \"") {
                    found = v.trim_end_matches('"') == name;
                } else if found {
                    if let Some(v) = line.strip_prefix("version = \"") {
                        return Some(v.trim_end_matches('"').to_string());
                    }
                }
            }
            _ => {}
        }
    }
    None
}
