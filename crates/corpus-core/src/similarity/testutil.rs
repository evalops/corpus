//! Test fixture builders: minimal but parseable PE and ELF binaries with
//! crafted imports/notes. Used by unit tests and the similarity
//! integration test. Not production code.

#![doc(hidden)]

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a minimal PE32 with one import (dll, func) in a crafted import
/// directory, one .text section whose body is `body`, a configurable
/// checksum, and an optional appended certificate table.
pub fn build_pe(dll: &str, func: &str, body: &[u8], checksum: u32, cert: Option<&[u8]>) -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    // DOS header.
    b[0] = b'M';
    b[1] = b'Z';
    w32(&mut b, 0x3c, 0x80);
    let pe = 0x80;
    b[pe..pe + 4].copy_from_slice(b"PE\0\0");
    // COFF header.
    w16(&mut b, pe + 4, 0x8664); // machine x86-64
    w16(&mut b, pe + 6, 1); // sections
    w16(&mut b, pe + 20, 0xe0); // size of optional header
    w16(&mut b, pe + 22, 0x0102); // characteristics: executable, 32bit
    let opt = pe + 24;
    w16(&mut b, opt, 0x10b); // PE32 magic
    w32(&mut b, opt + 16, 0x1000); // entry point RVA
    w32(&mut b, opt + 28, 0x400000); // image base
    w32(&mut b, opt + 32, 0x1000); // section alignment
    w32(&mut b, opt + 36, 0x200); // file alignment
    w32(&mut b, opt + 56, 0x2000); // size of image
    w32(&mut b, opt + 60, 0x200); // size of headers
    w32(&mut b, opt + 64, checksum); // CheckSum (excluded from authentihash)
    w16(&mut b, opt + 68, 3); // subsystem console
    w32(&mut b, opt + 92, 16); // number of rva and sizes
                               // Data directories at opt+96: [1] import, [4] certificate.
    w32(&mut b, opt + 96 + 8, 0x1000); // import RVA
    w32(&mut b, opt + 96 + 12, 0x28); // import size
                                      // Section header at opt+0xe0.
    let sh = opt + 0xe0;
    b[sh..sh + 5].copy_from_slice(b".text");
    w32(&mut b, sh + 8, 0x200); // virtual size
    w32(&mut b, sh + 12, 0x1000); // virtual address
    w32(&mut b, sh + 16, 0x200); // size of raw data
    w32(&mut b, sh + 20, 0x200); // pointer to raw data
    w32(&mut b, sh + 36, 0x6000_0020); // code | execute | read

    // .text raw at 0x200: import directory (2 descriptors), then data.
    let raw = 0x200;
    w32(&mut b, raw, 0x1040); // OriginalFirstThunk (ILT RVA)
    w32(&mut b, raw + 12, 0x1060); // Name RVA
    w32(&mut b, raw + 16, 0x1080); // FirstThunk (IAT RVA)
                                   // ILT at RVA 0x1040 -> raw 0x240; IAT at 0x1080 -> raw 0x280.
    w32(&mut b, raw + 0x40, 0x10a0); // hint/name RVA
    w32(&mut b, raw + 0x80, 0x10a0);
    // DLL name at RVA 0x1060 -> raw 0x260.
    b[raw + 0x60..raw + 0x60 + dll.len()].copy_from_slice(dll.as_bytes());
    // Hint/name at RVA 0x10a0 -> raw 0x2a0: u16 hint + name.
    b[raw + 0xa2..raw + 0xa2 + func.len()].copy_from_slice(func.as_bytes());
    // Body payload after the import structures.
    let body_off = raw + 0xc0;
    let n = body.len().min(0x400 - body_off);
    b[body_off..body_off + n].copy_from_slice(&body[..n]);

    if let Some(cert_bytes) = cert {
        let cert_off = b.len();
        b.extend_from_slice(cert_bytes);
        w32(&mut b, opt + 96 + 32, cert_off as u32); // cert table file offset
        w32(&mut b, opt + 96 + 36, cert_bytes.len() as u32);
    }
    b
}

/// Build a minimal ELF64 with a .note.gnu.build-id and a .comment section.
pub fn build_elf(build_id: &[u8], comment: &str) -> Vec<u8> {
    let shstr = b"\0.note.gnu.build-id\0.comment\0.shstrtab\0";
    let note = {
        let mut n = Vec::new();
        n.extend_from_slice(&4u32.to_le_bytes()); // namesz
        n.extend_from_slice(&(build_id.len() as u32).to_le_bytes()); // descsz
        n.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        n.extend_from_slice(b"GNU\0");
        n.extend_from_slice(build_id);
        n
    };
    let ehdr_size = 64usize;
    let note_off = ehdr_size;
    let comment_off = note_off + note.len();
    let shstr_off = comment_off + comment.len() + 1;
    let shoff = (shstr_off + shstr.len() + 7) & !7;

    let mut b = vec![0u8; shoff + 4 * 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // 64-bit
    b[5] = 1; // little-endian
    b[6] = 1; // version
    w16(&mut b, 16, 2); // ET_EXEC
    w16(&mut b, 18, 0x3e); // x86-64
    w32(&mut b, 20, 1);
    b[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    w16(&mut b, 52, 64); // ehsize
    w16(&mut b, 58, 64); // shentsize
    w16(&mut b, 60, 4); // shnum
    w16(&mut b, 62, 3); // shstrndx

    b[note_off..note_off + note.len()].copy_from_slice(&note);
    b[comment_off..comment_off + comment.len()].copy_from_slice(comment.as_bytes());
    b[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    let sh = |b: &mut [u8], i: usize, name: u32, ty: u32, off: usize, size: usize| {
        let o = shoff + i * 64;
        w32(b, o, name);
        w32(b, o + 4, ty);
        b[o + 24..o + 32].copy_from_slice(&(off as u64).to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&(size as u64).to_le_bytes());
    };
    sh(&mut b, 1, 1, 7, note_off, note.len()); // SHT_NOTE
    sh(&mut b, 2, 20, 1, comment_off, comment.len() + 1); // SHT_PROGBITS
    sh(&mut b, 3, 29, 3, shstr_off, shstr.len()); // SHT_STRTAB
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::similarity::extract::{extract, pe_authentihash};

    #[test]
    fn pe_fixture_parses_and_has_imports() {
        let pe = build_pe("KERNEL32.dll", "ExitProcess", b"body-v1", 0, None);
        let f = extract(&pe);
        assert_eq!(f.format, "pe", "goblin must parse the crafted PE");
        let imphash = f
            .normalized
            .iter()
            .find(|n| n.name == "imphash")
            .expect("imphash present");
        let other = build_pe(
            "KERNEL32.dll",
            "ExitProcess",
            b"body-v2-different",
            0xdead,
            None,
        );
        let f2 = extract(&other);
        let imphash2 = f2.normalized.iter().find(|n| n.name == "imphash").unwrap();
        assert_eq!(
            imphash.hash, imphash2.hash,
            "same imports -> same imphash despite body/checksum change"
        );
    }

    #[test]
    fn authentihash_ignores_checksum_and_cert_table() {
        let base = build_pe("KERNEL32.dll", "ExitProcess", b"body", 0, None);
        let with_checksum = build_pe("KERNEL32.dll", "ExitProcess", b"body", 0xcafebabe, None);
        assert_eq!(pe_authentihash(&base), pe_authentihash(&with_checksum));
        let with_cert = build_pe(
            "KERNEL32.dll",
            "ExitProcess",
            b"body",
            0,
            Some(b"FAKE-CERTIFICATE-BYTES"),
        );
        assert_eq!(pe_authentihash(&base), pe_authentihash(&with_cert));
        let different_body = build_pe("KERNEL32.dll", "ExitProcess", b"body!", 0, None);
        assert_ne!(pe_authentihash(&base), pe_authentihash(&different_body));
    }

    #[test]
    fn imphash_is_order_and_case_normalized() {
        let a = build_pe("KERNEL32.dll", "ExitProcess", b"x", 0, None);
        let b = build_pe("kernel32.dll", "exitprocess", b"x", 0, None);
        let fa = extract(&a);
        let fb = extract(&b);
        let ha = fa.normalized.iter().find(|n| n.name == "imphash").unwrap();
        let hb = fb.normalized.iter().find(|n| n.name == "imphash").unwrap();
        assert_eq!(ha.hash, hb.hash, "imphash lowercases dll and symbol");
        let c = build_pe("USER32.dll", "MessageBoxA", b"x", 0, None);
        let hc = extract(&c);
        let hc = hc.normalized.iter().find(|n| n.name == "imphash").unwrap();
        assert_ne!(ha.hash, hc.hash);
    }

    #[test]
    fn elf_fixture_build_id_and_comment() {
        let id = [0xde, 0xad, 0xbe, 0xef];
        let elf = build_elf(&id, "GCC: (GNU) 13.2.0");
        let f = extract(&elf);
        assert_eq!(f.format, "elf", "goblin must parse the crafted ELF");
        let bid = f
            .normalized
            .iter()
            .find(|n| n.name == "elf_build_id")
            .expect("build id");
        assert_eq!(bid.hash, "deadbeef");
        assert_eq!(f.compiler_hint.as_deref(), Some("GCC: (GNU) 13.2.0"));
        assert!(f.section_layout.is_some());
    }
}

#[cfg(test)]
mod real_binary_tests {
    /// Compiles a tiny C program if cc exists and verifies Mach-O/ELF
    /// import extraction against the real toolchain output (modern macOS
    /// uses chained fixups; this test guards that extraction path).
    #[test]
    fn real_compiled_binary_imports_extract() {
        let Ok(cc) = std::process::Command::new("cc").arg("--version").output() else {
            eprintln!("cc unavailable; skipping");
            return;
        };
        let _ = cc;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("t.c");
        std::fs::write(&src, "#include <stdio.h>\n#include <string.h>\nint main(void){char b[8]; strcpy(b,\"hi\"); puts(b); return strlen(b)>0?0:1;}\n").unwrap();
        let bin = dir.path().join("t");
        // Targeting macOS 11 forces classic bind opcodes; goblin cannot
        // read imports from the newer chained-fixups format. On Linux this
        // flag is rejected, so retry without it.
        let mut cmd = std::process::Command::new("cc");
        cmd.arg("-O1").arg(&src).arg("-o").arg(&bin);
        #[cfg(target_os = "macos")]
        cmd.arg("-target")
            .arg(if std::env::consts::ARCH == "aarch64" {
                "arm64-apple-macos11"
            } else {
                "x86_64-apple-macos10.15"
            });
        let status = cmd.status().unwrap();
        assert!(status.success());
        let bytes = std::fs::read(&bin).unwrap();
        let f = crate::similarity::extract::extract(&bytes);
        assert!(
            f.parse_limitation.is_none(),
            "parse failed: {:?}",
            f.parse_limitation
        );
        let import_hash = f.normalized.iter().find(|n| n.name.contains("import_hash"));
        assert!(
            import_hash.is_some(),
            "expected an import hash for a real compiled binary, got: {:?}",
            f.normalized.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
        assert!(f.import_set.is_some());
    }
}

/// Minimal ELF64 with a single .text section of arbitrary bytes.
pub fn build_elf_text(text: &[u8]) -> Vec<u8> {
    let shstr = b"\0.text\0.shstrtab\0";
    let ehdr_size = 64usize;
    let text_off = ehdr_size;
    let shstr_off = text_off + text.len();
    let shoff = (shstr_off + shstr.len() + 7) & !7;
    let mut b = vec![0u8; shoff + 3 * 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    w16(&mut b, 16, 2);
    w16(&mut b, 18, 0x3e);
    w32(&mut b, 20, 1);
    b[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    w16(&mut b, 52, 64);
    w16(&mut b, 58, 64);
    w16(&mut b, 60, 3);
    w16(&mut b, 62, 2);
    b[text_off..text_off + text.len()].copy_from_slice(text);
    b[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
    let sh = |b: &mut [u8], i: usize, name: u32, ty: u32, off: usize, size: usize, addr: u64| {
        let o = shoff + i * 64;
        w32(b, o, name);
        w32(b, o + 4, ty);
        b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&(off as u64).to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&(size as u64).to_le_bytes());
    };
    sh(&mut b, 1, 1, 1, text_off, text.len(), 0x400000);
    sh(&mut b, 2, 7, 3, shstr_off, shstr.len(), 0);
    b
}
