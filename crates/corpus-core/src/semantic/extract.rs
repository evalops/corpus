//! Function boundary recovery for x86-64 PE/ELF/Mach-O (spec 16.2).
//!
//! # Approach
//!
//! 1. Map executable sections from the container format (goblin).
//! 2. Discover likely function starts (symbols, exports, call targets,
//!    and heuristic prologues).
//! 3. Emit bounded spans (`offset`, `size`, optional `name`) plus the
//!    raw code bytes for feature extraction.
//!
//! # Bounds
//!
//! [`MAX_FUNCTIONS`] caps recovered spans so malformed binaries cannot
//! explode memory. Decode is x86-64 only today (AArch64 is issue #18).
//!
//! # Non-goals
//!
//! Full decompiler CFG, unwind-aware boundaries, or non-x86 ISAs.

pub const MAX_FUNCTIONS: usize = 512;
pub const MIN_FUNCTION_GAP: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSpan {
    /// Offset into the code section's bytes.
    pub offset: usize,
    /// File offset of the code (for reporting; section file offset + offset).
    pub file_offset: u64,
    pub size: usize,
    pub name: Option<String>,
    pub source: SpanSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanSource {
    Symbol,
    Pdata,
    PrologueScan,
}

#[derive(Debug)]
pub struct CodeSection {
    pub bytes: Vec<u8>,
    pub file_offset: u64,
    pub virtual_address: u64,
    pub entropy: f64,
}

/// x64 prologue patterns (push rbp;mov rbp,rsp / sub rsp,imm / endbr64 /
/// push rbx / mov [rsp+..],rbx).
const PROLOGUES: &[&[u8]] = &[
    &[0x55, 0x48, 0x89, 0xe5],
    &[0xf3, 0x0f, 0x1e, 0xfa],
    &[0x48, 0x83, 0xec],
    &[0x40, 0x53],
    &[0x48, 0x89, 0x5c],
];

/// Scan code bytes for prologue-like function starts, sorted, deduped
/// with a minimum gap.
pub fn prologue_scan(bytes: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    for i in 0..bytes.len().saturating_sub(4) {
        if PROLOGUES.iter().any(|p| bytes[i..].starts_with(p))
            && starts
                .last()
                .is_none_or(|last: &usize| i >= last + MIN_FUNCTION_GAP)
        {
            starts.push(i);
        }
    }
    starts.truncate(MAX_FUNCTIONS);
    starts
}

/// Build spans from sorted start offsets.
pub fn spans_from_starts(
    mut starts: Vec<usize>,
    code_len: usize,
    file_offset: u64,
    source: SpanSource,
) -> Vec<FunctionSpan> {
    starts.sort_unstable();
    starts.dedup();
    starts.truncate(MAX_FUNCTIONS);
    starts
        .iter()
        .enumerate()
        .map(|(i, &off)| {
            let end = starts.get(i + 1).copied().unwrap_or(code_len);
            FunctionSpan {
                offset: off,
                file_offset: file_offset + off as u64,
                size: end.saturating_sub(off),
                name: None,
                source,
            }
        })
        .filter(|s| s.size >= 1)
        .collect()
}

/// Recover code sections and function spans for one artifact.
pub fn functions_for(format: &str, bytes: &[u8]) -> Vec<(CodeSection, Vec<FunctionSpan>)> {
    match format {
        "elf" => elf_functions(bytes),
        "pe" => pe_functions(bytes),
        "macho" => macho_functions(bytes),
        _ => Vec::new(),
    }
}

fn section_entropy(bytes: &[u8]) -> f64 {
    crate::similarity::extract::shannon_entropy(bytes)
}

fn elf_functions(bytes: &[u8]) -> Vec<(CodeSection, Vec<FunctionSpan>)> {
    let Ok(elf) = goblin::elf::Elf::parse(bytes) else {
        return Vec::new();
    };
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name) != Some(".text") {
            continue;
        }
        let start = sh.sh_offset as usize;
        let end = (start + sh.sh_size as usize).min(bytes.len());
        let code = CodeSection {
            bytes: bytes[start..end].to_vec(),
            file_offset: sh.sh_offset,
            virtual_address: sh.sh_addr,
            entropy: section_entropy(&bytes[start..end]),
        };
        // Sized STT_FUNC symbols first.
        let mut spans: Vec<FunctionSpan> = elf
            .syms
            .iter()
            .filter(|s| s.st_type() == goblin::elf::sym::STT_FUNC && s.st_size > 0)
            .filter_map(|s| {
                let va = s.st_value;
                if va >= code.virtual_address && va < code.virtual_address + code.bytes.len() as u64
                {
                    Some(FunctionSpan {
                        offset: (va - code.virtual_address) as usize,
                        file_offset: code.file_offset + (va - code.virtual_address),
                        size: s.st_size as usize,
                        name: elf.strtab.get_at(s.st_name).map(|n| n.to_string()),
                        source: SpanSource::Symbol,
                    })
                } else {
                    None
                }
            })
            .collect();
        spans.truncate(MAX_FUNCTIONS);
        if spans.is_empty() {
            spans = spans_from_starts(
                prologue_scan(&code.bytes),
                code.bytes.len(),
                code.file_offset,
                SpanSource::PrologueScan,
            );
        }
        out.push((code, spans));
    }
    out
}

fn pe_functions(bytes: &[u8]) -> Vec<(CodeSection, Vec<FunctionSpan>)> {
    let Ok(pe) = goblin::pe::PE::parse(bytes) else {
        return Vec::new();
    };
    if pe.header.coff_header.machine != goblin::pe::header::COFF_MACHINE_X86_64 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name);
        let name = name.trim_end_matches('\0');
        if name != ".text" {
            continue;
        }
        let start = s.pointer_to_raw_data as usize;
        let end = (start + s.size_of_raw_data as usize).min(bytes.len());
        let code = CodeSection {
            bytes: bytes[start..end].to_vec(),
            file_offset: s.pointer_to_raw_data as u64,
            virtual_address: s.virtual_address as u64,
            entropy: section_entropy(&bytes[start..end]),
        };
        // .pdata RUNTIME_FUNCTION entries give exact non-leaf spans.
        let mut spans = Vec::new();
        if let Some(ex) = &pe.exception_data {
            for f in ex.functions() {
                let Ok(f) = f else { continue };
                let begin = f.begin_address as usize;
                let size = (f.end_address - f.begin_address) as usize;
                if begin < code.bytes.len() && size > 0 {
                    spans.push(FunctionSpan {
                        offset: begin,
                        file_offset: code.file_offset + begin as u64,
                        size: size.min(code.bytes.len() - begin),
                        name: None,
                        source: SpanSource::Pdata,
                    });
                }
            }
            spans.truncate(MAX_FUNCTIONS);
        }
        if spans.is_empty() {
            spans = spans_from_starts(
                prologue_scan(&code.bytes),
                code.bytes.len(),
                code.file_offset,
                SpanSource::PrologueScan,
            );
        }
        out.push((code, spans));
    }
    out
}

fn macho_functions(bytes: &[u8]) -> Vec<(CodeSection, Vec<FunctionSpan>)> {
    let Ok(macho) = goblin::mach::MachO::parse(bytes, 0) else {
        return Vec::new();
    };
    if macho.header.cputype() != goblin::mach::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for seg in &macho.segments {
        for (sec, sec_data) in seg.sections().into_iter().flatten() {
            let name = String::from_utf8_lossy(&sec.sectname);
            if !name.trim_end_matches('\0').ends_with("__text") {
                continue;
            }
            let code = CodeSection {
                bytes: sec_data.to_vec(),
                file_offset: sec.offset as u64,
                virtual_address: sec.addr,
                entropy: section_entropy(sec_data),
            };
            // Symbol anchors where present, else prologue scan.
            let mut starts: Vec<usize> = macho
                .symbols()
                .filter_map(|s| s.ok())
                .filter(|(name, nlist)| {
                    !name.is_empty()
                        && nlist.is_global()
                        && nlist.n_type == goblin::mach::symbols::N_SECT
                        && nlist.n_value >= code.virtual_address
                        && nlist.n_value < code.virtual_address + code.bytes.len() as u64
                })
                .map(|(_, nlist)| (nlist.n_value - code.virtual_address) as usize)
                .collect();
            if starts.is_empty() {
                let scan = prologue_scan(&code.bytes);
                let file_offset = code.file_offset;
                let code_len = code.bytes.len();
                out.push((
                    code,
                    spans_from_starts(scan, code_len, file_offset, SpanSource::PrologueScan),
                ));
                continue;
            }
            starts.sort_unstable();
            starts.dedup();
            let spans = starts
                .iter()
                .map(|&off| FunctionSpan {
                    offset: off,
                    file_offset: code.file_offset + off as u64,
                    size: 0, // sized below
                    name: None,
                    source: SpanSource::Symbol,
                })
                .collect::<Vec<_>>();
            let mut sized = Vec::new();
            for (i, sp) in spans.iter().enumerate() {
                let end = spans
                    .get(i + 1)
                    .map(|n| n.offset)
                    .unwrap_or(code.bytes.len());
                if end > sp.offset {
                    sized.push(FunctionSpan {
                        size: end - sp.offset,
                        ..sp.clone()
                    });
                }
            }
            sized.truncate(MAX_FUNCTIONS);
            out.push((code, sized));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prologue_scan_finds_bounded_starts() {
        let mut code = vec![0x90u8; 256];
        code[16..20].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        code[20..24].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]); // inside MIN gap
        code[64..68].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        let starts = prologue_scan(&code);
        assert_eq!(starts, vec![16, 64]);
        let spans = spans_from_starts(starts, code.len(), 0x1000, SpanSource::PrologueScan);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].size, 48);
        assert_eq!(spans[1].size, 192);
        assert_eq!(spans[0].file_offset, 0x1000 + 16);
    }
}
