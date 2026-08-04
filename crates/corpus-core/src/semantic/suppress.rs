//! Ubiquitous library / runtime function suppression before scoring.
//!
//! v1 uses a bundled baseline of name patterns and token-shape heuristics.
//! Suppressed functions remain in raw evidence but are excluded from
//! coverage denominators and matching when suppression is enabled.

use crate::semantic::edges::FunctionRow;
use serde::Serialize;

pub const SUPPRESSOR_VERSION: &str = "suppress:v1";

/// Names (case-insensitive substrings) treated as ubiquitous runtime.
const NAME_PATTERNS: &[&str] = &[
    "crt",
    "__libc",
    "_start",
    "__main",
    "maincrt",
    "scrt_common",
    "gs_handler",
    "security_check_cookie",
    "findpeb",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcmp",
    "strcpy",
    "malloc",
    "free",
    "calloc",
    "realloc",
    "operator new",
    "operator delete",
    "__chkstk",
    "_chkstk",
    "__security",
    "guard_check",
    "std::",
    "boost::",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SuppressionDecision {
    pub offset: u64,
    pub suppressed: bool,
    pub reason: Option<String>,
}

/// Decide suppression for one function. Never tenant-scoped in v1
/// (bundled baseline only — no cross-tenant prevalence).
pub fn decide(f: &FunctionRow) -> SuppressionDecision {
    if let Some(name) = &f.name {
        let lower = name.to_lowercase();
        for pat in NAME_PATTERNS {
            if lower.contains(pat) {
                return SuppressionDecision {
                    offset: f.offset,
                    suppressed: true,
                    reason: Some(format!("name_pattern:{pat}")),
                };
            }
        }
    }
    // Pure thunks already filtered by significance; tiny generic helpers
    // with very few distinct tokens are downweighted as likely CRT noise.
    if f.insn_count < 12 && f.token_hashes.len() <= 4 {
        return SuppressionDecision {
            offset: f.offset,
            suppressed: true,
            reason: Some("tiny_generic_shape".into()),
        };
    }
    SuppressionDecision {
        offset: f.offset,
        suppressed: false,
        reason: None,
    }
}

/// Partition into (kept for scoring, suppressed with decisions).
pub fn partition(functions: &[FunctionRow]) -> (Vec<FunctionRow>, Vec<SuppressionDecision>) {
    let mut kept = Vec::new();
    let mut decisions = Vec::new();
    for f in functions {
        let d = decide(f);
        if d.suppressed {
            decisions.push(d);
        } else {
            kept.push(f.clone());
            decisions.push(d);
        }
    }
    (kept, decisions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(offset: u64, name: &str, insns: usize, tokens: usize) -> FunctionRow {
        FunctionRow {
            offset,
            size: 32,
            name: Some(name.into()),
            insn_count: insns,
            token_hashes: (0..tokens as u64).collect(),
        }
    }

    #[test]
    fn suppresses_memcpy_by_name() {
        let f = named(0, "memcpy", 40, 20);
        let d = decide(&f);
        assert!(d.suppressed);
        assert!(d.reason.unwrap().contains("name_pattern"));
    }

    #[test]
    fn keeps_interesting_named_function() {
        let f = named(0, "decrypt_payload", 80, 40);
        assert!(!decide(&f).suppressed);
    }

    #[test]
    fn suppresses_tiny_generic() {
        let f = FunctionRow {
            offset: 1,
            size: 8,
            name: None,
            insn_count: 6,
            token_hashes: vec![1, 2],
        };
        assert!(decide(&f).suppressed);
    }

    #[test]
    fn partition_preserves_all_decisions() {
        let fns = vec![
            named(0, "memcpy", 40, 20),
            named(1, "decrypt_payload", 80, 40),
        ];
        let (kept, decisions) = partition(&fns);
        assert_eq!(kept.len(), 1);
        assert_eq!(decisions.len(), 2);
        assert_eq!(kept[0].name.as_deref(), Some("decrypt_payload"));
    }
}
