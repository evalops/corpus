//! corpus-scanner: out-of-process YARA-X helper.
//!
//! Spawned by [`corpus_core::sandbox`] so rule evaluation cannot crash
//! the API server. Speaks a minimal stdin/stdout protocol: receive scan
//! job (rules + bytes/path), emit JSON match results or a structured
//! error, exit. Resource limits are applied by the parent when the OS
//! supports them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Job {
    /// (namespace, source) pairs of the immutable bundle.
    rules: Vec<(String, String)>,
    sample_path: String,
    /// Test seam: sleep before scanning so the parent's timeout fires.
    #[serde(default)]
    sleep_ms: u64,
}

#[derive(Debug, Serialize)]
struct Outcome {
    status: String,
    matches: serde_json::Value,
    duration_ms: i64,
    error_code: Option<String>,
}

fn main() {
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        std::process::exit(64);
    }
    let job: Job = match serde_json::from_str(&input) {
        Ok(j) => j,
        Err(e) => {
            println!("{{\"status\":\"error\",\"matches\":[],\"duration_ms\":0,\"error_code\":\"bad job json: {e}\"}}");
            std::process::exit(64);
        }
    };

    if job.sleep_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(job.sleep_ms));
    }

    let outcome = run(&job);
    println!("{}", serde_json::to_string(&outcome).unwrap());
}

fn run(job: &Job) -> Outcome {
    let rules = match corpus_core::scan::compile_bundle(&job.rules) {
        Ok(r) => r,
        Err(e) => {
            return Outcome {
                status: "error".into(),
                matches: serde_json::json!([]),
                duration_ms: 0,
                error_code: Some(format!("compile: {e}")),
            }
        }
    };
    let bytes = match std::fs::read(&job.sample_path) {
        Ok(b) => b,
        Err(e) => {
            return Outcome {
                status: "error".into(),
                matches: serde_json::json!([]),
                duration_ms: 0,
                error_code: Some(format!("read sample: {e}")),
            }
        }
    };
    let outcome = corpus_core::scan::scan_bytes(&rules, &bytes);
    let matches: Vec<serde_json::Value> = outcome
        .matches
        .iter()
        .map(|m| serde_json::to_value(m).unwrap_or_default())
        .collect();
    Outcome {
        status: outcome.status.as_str().to_string(),
        matches: serde_json::json!(matches),
        duration_ms: outcome.duration_ms,
        error_code: outcome.error_code,
    }
}
