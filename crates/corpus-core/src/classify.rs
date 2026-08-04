//! Magic-byte classification of code-bearing artifacts.
//!
//! # Authority
//!
//! Extensions are hints, never authority (spec 2.3 / 10.6). Only the
//! leading header bytes decide. M0 covers:
//!
//! - PE/COFF (`MZ` + PE signature)
//! - ELF (`\x7fELF`)
//! - Mach-O thin and fat (32/64-bit, LE/BE magics)
//! - Shebang scripts (`#!`)
//!
//! Everything else is [`ArtifactClass::Unknown`]. Classification is pure
//! and allocation-light so agents and the server share the same path.

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClass {
    Pe,
    Elf,
    MachO,
    MachOFat,
    Script,
    Unknown,
}

impl fmt::Display for ArtifactClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ArtifactClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactClass::Pe => "pe",
            ArtifactClass::Elf => "elf",
            ArtifactClass::MachO => "macho",
            ArtifactClass::MachOFat => "macho_fat",
            ArtifactClass::Script => "script",
            ArtifactClass::Unknown => "unknown",
        }
    }
}

/// Classify from the leading bytes of a file.
pub fn classify(bytes: &[u8]) -> ArtifactClass {
    if bytes.len() >= 4 {
        match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => return ArtifactClass::Elf,
            // Mach-O thin: big/little endian, 32/64 bit.
            [0xfe, 0xed, 0xfa, 0xce]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xcf, 0xfa, 0xed, 0xfe] => return ArtifactClass::MachO,
            // Mach-O universal (fat) binary.
            [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => return ArtifactClass::MachOFat,
            _ => {}
        }
    }
    // PE/COFF: MZ DOS stub, e_lfanew at 0x3c points at the PE signature.
    if bytes.len() >= 0x40 && bytes.starts_with(b"MZ") {
        let e_lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 4 <= bytes.len() && bytes[e_lfanew..e_lfanew + 4] == *b"PE\0\0" {
            return ArtifactClass::Pe;
        }
    }
    if bytes.starts_with(b"#!") {
        return ArtifactClass::Script;
    }
    ArtifactClass::Unknown
}

/// Classify a file on disk by reading only its header.
pub fn classify_path(path: &std::path::Path) -> std::io::Result<ArtifactClass> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf)?;
    Ok(classify(&buf[..n]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_fixture() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b
    }

    #[test]
    fn classifies_pe_by_header_not_extension() {
        assert_eq!(classify(&pe_fixture()), ArtifactClass::Pe);
        // An MZ stub without a valid PE signature is not a PE.
        let mut b = pe_fixture();
        b[0x80..0x84].copy_from_slice(b"PX\0\0");
        assert_eq!(classify(&b), ArtifactClass::Unknown);
    }

    #[test]
    fn classifies_elf() {
        let b = b"\x7fELF\x02\x01\x01\x00rest-of-header";
        assert_eq!(classify(b), ArtifactClass::Elf);
    }

    #[test]
    fn classifies_macho_variants() {
        assert_eq!(
            classify(&[0xfe, 0xed, 0xfa, 0xcf, 0, 0]),
            ArtifactClass::MachO
        );
        assert_eq!(
            classify(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0]),
            ArtifactClass::MachO
        );
        assert_eq!(
            classify(&[0xca, 0xfe, 0xba, 0xbe, 0, 0]),
            ArtifactClass::MachOFat
        );
    }

    #[test]
    fn classifies_script_and_unknown() {
        assert_eq!(classify(b"#!/bin/sh\necho hi"), ArtifactClass::Script);
        assert_eq!(classify(b"plain text, no magic"), ArtifactClass::Unknown);
        assert_eq!(classify(b""), ArtifactClass::Unknown);
    }

    #[test]
    fn truncated_mz_is_not_pe() {
        assert_eq!(classify(b"MZ"), ArtifactClass::Unknown);
    }
}
