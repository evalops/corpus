//! Malformed-binary contract tests for feature extraction and function
//! boundary recovery. Every input must return a bounded result (features
//! with optional limitation, or empty spans) without panicking or
//! unbounded allocation.

use crate::classify;
use crate::semantic::extract::{functions_for, MAX_FUNCTIONS};
use crate::similarity::extract::extract;

/// Resource bounds asserted by the contract suite.
const MAX_OUTPUT_FUNCTIONS: usize = MAX_FUNCTIONS;
const MAX_FEATURE_JSON_BYTES: usize = 64 * 1024;

fn assert_bounded_extract(bytes: &[u8], label: &str) {
    let _class = classify::classify(bytes);
    let features = extract(bytes);
    // size_bytes records input length.
    assert_eq!(
        features.size_bytes as usize,
        bytes.len(),
        "{label}: size_bytes mismatch"
    );
    let json = serde_json::to_vec(&serde_json::json!({
        "format": features.format,
        "arch": features.arch,
        "ssdeep": features.ssdeep,
        "normalized": features.normalized.len(),
        "limitation": features.parse_limitation,
    }))
    .unwrap();
    assert!(
        json.len() <= MAX_FEATURE_JSON_BYTES,
        "{label}: feature summary too large ({})",
        json.len()
    );

    for fmt in ["pe", "elf", "macho"] {
        let sections = functions_for(fmt, bytes);
        let total_fns: usize = sections.iter().map(|(_, s)| s.len()).sum();
        assert!(
            total_fns <= MAX_OUTPUT_FUNCTIONS,
            "{label}/{fmt}: function count {total_fns} exceeds bound"
        );
        for (code, spans) in &sections {
            assert!(
                code.bytes.len() <= bytes.len(),
                "{label}/{fmt}: code section larger than input"
            );
            for sp in spans {
                assert!(sp.size <= code.bytes.len() + 1, "{label}: span size unbounded");
            }
        }
    }
}

#[test]
fn empty_input_is_bounded() {
    assert_bounded_extract(&[], "empty");
}

#[test]
fn truncated_pe_header() {
    // MZ only
    assert_bounded_extract(b"MZ", "pe-mz-only");
    // MZ + truncated PE
    let mut buf = vec![0u8; 64];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3c] = 0x40; // e_lfanew past buffer
    assert_bounded_extract(&buf, "pe-truncated");
}

#[test]
fn truncated_elf_header() {
    let mut buf = b"\x7fELF".to_vec();
    buf.extend_from_slice(&[2, 1, 1, 0]); // partial
    assert_bounded_extract(&buf, "elf-partial");
    let mut fullish = vec![0u8; 64];
    fullish[..4].copy_from_slice(b"\x7fELF");
    fullish[4] = 2; // ELFCLASS64
    fullish[5] = 1; // little endian
    fullish[18] = 0x3e; // EM_X86_64 low
    assert_bounded_extract(&fullish, "elf-short");
}

#[test]
fn truncated_macho() {
    // 64-bit little-endian Mach-O magic, no load commands.
    let mut buf = vec![0u8; 32];
    buf[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    assert_bounded_extract(&buf, "macho-short");
}

#[test]
fn fat_macho_magic() {
    let mut buf = vec![0u8; 32];
    buf[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    buf[4..8].copy_from_slice(&2u32.to_be_bytes()); // nfat_arch
    assert_bounded_extract(&buf, "macho-fat");
}

#[test]
fn shebang_and_unknown() {
    assert_bounded_extract(b"#!/bin/sh\necho hi\n", "shebang");
    assert_bounded_extract(b"not a binary at all ~~~", "unknown");
}

#[test]
fn overlapping_and_adversarial_offsets() {
    // Random-ish bytes with PE-like and ELF-like fragments mixed.
    let mut buf = vec![0xCCu8; 4096];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3c] = 4;
    buf[4..8].copy_from_slice(b"PE\0\0");
    // Plant prologue patterns densely to stress the function bound.
    for i in (0..4096).step_by(4) {
        if i + 4 <= buf.len() {
            buf[i..i + 4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        }
    }
    assert_bounded_extract(&buf, "adversarial-prologues");
}

#[test]
fn invalid_offsets_do_not_panic() {
    let mut buf = vec![0u8; 128];
    buf[0] = b'M';
    buf[1] = b'Z';
    // e_lfanew points way past EOF
    buf[0x3c..0x40].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    assert_bounded_extract(&buf, "invalid-e-lfanew");
}

/// Deterministic seed corpus for CI fuzz smoke (no external services).
#[test]
fn fuzz_smoke_seed_corpus() {
    let seeds: &[&[u8]] = &[
        b"",
        b"MZ",
        b"\x7fELF",
        b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe",
        b"#!/usr/bin/env python3\nprint(1)\n",
        &[0xff; 16],
        &[0x00; 256],
        &[0x55, 0x48, 0x89, 0xe5, 0xc3],
    ];
    for (i, s) in seeds.iter().enumerate() {
        assert_bounded_extract(s, &format!("seed-{i}"));
    }
}
