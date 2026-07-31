//! Rule registry helpers: source parsing, compile validation, immutable
//! bundle digests (spec 14.3-14.5).

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

/// Compiler configuration folded into every bundle digest. Bumping this
/// invalidates prior digests, which is the point: bundles are immutable.
pub const COMPILER_CONFIG: &str =
    concat!("yara-x-compiler:v1;engine=", env!("CORPUS_YARA_X_VERSION"));

/// Strip `//` and `/* */` comments so the name parser does not trip on
/// commented-out rules.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Extract the rule name from a YARA source file. M0 accepts exactly one
/// rule per registry entry so the stable id is unambiguous.
pub fn parse_rule_name(source: &str) -> Result<String> {
    let clean = strip_comments(source);
    let tokens: Vec<&str> = clean
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .collect();
    let positions: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| **t == "rule")
        .map(|(i, _)| i)
        .collect();
    match positions.len() {
        1 => {
            let name = tokens[positions[0] + 1];
            if name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            {
                Ok(name.to_string())
            } else {
                Err(Error::RuleParse(format!(
                    "invalid rule identifier {name:?}"
                )))
            }
        }
        0 => Err(Error::RuleParse("no `rule` definition found".into())),
        n => Err(Error::RuleParse(format!(
            "expected exactly one rule per file, found {n}; split multi-rule files before adding"
        ))),
    }
}

/// Validate that a rule source compiles under YARA-X. Returns the compiler
/// diagnostics on failure.
pub fn compile_validate(source: &str) -> Result<()> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(source)
        .map_err(|e| Error::RuleCompile(e.to_string()))?;
    Ok(())
}

/// Immutable bundle digest over canonically ordered rule sources plus the
/// compiler configuration (spec 14.5). Any change to membership, source,
/// or compiler config yields a new digest.
pub fn bundle_digest(rules: &[(String, String)], compiler_config: &str) -> String {
    let mut sorted: Vec<&(String, String)> = rules.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    h.update(b"corpus-rule-bundle-v1\0");
    for (stable_id, source) in sorted {
        h.update(stable_id.as_bytes());
        h.update(b"\0");
        h.update(source.as_bytes());
        h.update(b"\0");
    }
    h.update(compiler_config.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_A: &str = r#"rule Alpha { strings: $a = "aaa" condition: $a }"#;
    const RULE_B: &str = r#"// comment mentioning rule Fake
rule Beta {
  strings: $b = "bbb"
  condition: $b
}"#;

    #[test]
    fn parses_rule_name() {
        assert_eq!(parse_rule_name(RULE_A).unwrap(), "Alpha");
        assert_eq!(parse_rule_name(RULE_B).unwrap(), "Beta");
        assert!(parse_rule_name("rule One {} rule Two {}").is_err());
        assert!(parse_rule_name("strings only").is_err());
    }

    #[test]
    fn validates_compilation() {
        assert!(compile_validate(RULE_A).is_ok());
        assert!(compile_validate("rule Broken { condition: and }").is_err());
    }

    #[test]
    fn bundle_digest_is_deterministic_and_order_independent() {
        let rules = vec![
            ("Alpha".to_string(), RULE_A.to_string()),
            ("Beta".to_string(), RULE_B.to_string()),
        ];
        let mut reversed = rules.clone();
        reversed.reverse();
        let d1 = bundle_digest(&rules, COMPILER_CONFIG);
        let d2 = bundle_digest(&reversed, COMPILER_CONFIG);
        assert_eq!(d1, d2, "digest must not depend on submission order");
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn bundle_digest_changes_with_source_or_config() {
        let rules = vec![("Alpha".to_string(), RULE_A.to_string())];
        let base = bundle_digest(&rules, COMPILER_CONFIG);
        let tweaked = vec![("Alpha".to_string(), RULE_A.replace("aaa", "ccc"))];
        assert_ne!(base, bundle_digest(&tweaked, COMPILER_CONFIG));
        assert_ne!(base, bundle_digest(&rules, "other-config"));
    }
}
