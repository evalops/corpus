//! Ubiquitous library / runtime function suppression before scoring.
//!
//! # Why suppression exists
//!
//! Semantic coverage is `matched_pairs / significant_functions`. CRT
//! helpers (`memcpy`, security cookies, C++ `operator new`, …) appear in
//! almost every PE/ELF and would inflate both the denominator and the
//! numerator when two unrelated binaries share the same toolchain.
//!
//! Suppression removes those functions from the *scoring* set while
//! keeping decisions in raw evidence so analysts can audit what was
//! dropped.
//!
//! # v1 policy (bundled baseline only)
//!
//! 1. **Name patterns** — case-insensitive substring match against a
//!    fixed list of runtime / standard-library names.
//! 2. **Tiny generic shape** — unnamed (or uninteresting) functions with
//!    `< 12` instructions and `≤ 4` distinct token hashes.
//!
//! There is **no cross-tenant prevalence** and **no tenant-specific
//! lists** in v1. That keeps isolation simple and decisions deterministic.
//!
//! # Pipeline position
//!
//! ```text
//! extract_and_store → FunctionRow[]
//!        │
//!        ▼
//! suppress::partition  → (kept, decisions[])
//!        │
//!        ▼
//! coverage / edge emission uses `kept` only
//! ```
//!
//! Significant-function filtering ([`crate::semantic::features::is_significant`])
//! already drops pure thunks; suppression is a second pass for ubiquitous
//! but otherwise "significant-looking" helpers.
//!
//! # Versioning
//!
//! [`SUPPRESSOR_VERSION`] is written into edge evidence and a
//! `similarity_feature` row (`family=semantic`, `name=suppression`) so
//! historical edges can be interpreted under the policy that produced them.

use crate::semantic::edges::FunctionRow;
use serde::Serialize;

/// Persisted identity of this suppressor implementation.
pub const SUPPRESSOR_VERSION: &str = "suppress:v1";

/// Names (case-insensitive substrings) treated as ubiquitous runtime.
///
/// Order is not significant. Patterns intentionally match decorated and
/// undecorated names (`__libc_start_main`, `std::vector`, …).
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

/// Per-function suppression outcome retained for evidence / audit.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SuppressionDecision {
    /// File offset of the function this decision applies to.
    pub offset: u64,
    /// True when the function is excluded from coverage scoring.
    pub suppressed: bool,
    /// Machine-readable reason (`name_pattern:memcpy`, `tiny_generic_shape`),
    /// or `None` when kept.
    pub reason: Option<String>,
}

/// Decide suppression for one function.
///
/// Never tenant-scoped in v1 (bundled baseline only — no cross-tenant
/// prevalence). Name patterns take precedence over shape heuristics.
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

/// Partition into (kept for scoring, *all* decisions including kept ones).
///
/// `decisions.len() == functions.len()` always. Callers that only need the
/// suppressed subset should filter on `decision.suppressed`.
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
