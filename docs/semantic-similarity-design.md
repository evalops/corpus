# Semantic similarity design (M8): function-level matching without Ghidra

Spec 16.2/16.5 calls for Ghidra BSim. We implement the same *class* of
capability in pure Rust. This document records the research and the
deliberate simplifications.

**Thresholds in this document are generated from
`similarity::model::MODEL_V1`.** A unit test fails when the two diverge
(`design_doc_matches_model_config`). Change the model config, then update
this file — never the reverse.

## How BSim works conceptually

Ghidra's BSim extracts per-function feature vectors (instruction
features, structure, metadata), indexes them with LSH, and answers
nearest-function queries. Whole-binary similarity is an *aggregation*:
matched function pairs, weighted coverage in both directions, known-
library downweighting. The load-bearing ideas we keep:

1. Per-function signatures that survive recompilation of the same
   source.
2. Bidirectional weighted coverage so a small loader cannot "match" a
   large benign program (spec 16.5 step 4).
3. Ubiquitous/runtime function suppression before scoring (16.5 step 5).

What we deliberately do NOT do: JVM/Ghidra, a searchable LSH service,
decompilation to pseudocode, or calibrated scoring against large public
corpora.

## Disassembly: iced-x86 (v1.21, pure Rust)

- x86-64 only for v1. iced-x86 is maintained, fast, and has no C deps
  (Windows CI safe).
- aarch64: `yaxpeax-arm` exists but is lukewarm; `bad64` is a C++
  binding. Both rejected for v1 — arm64 is a documented follow-up (this
  Mac's native Mach-O fixtures must be compiled with
  `-target x86_64-apple-macos*` for semantic analysis).

## Function boundaries without a decompiler

Standard approach order, per format (goblin already parses all three):

1. **Symbols with sizes** (ELF `.symtab`/`STT_FUNC`, Mach-O `LC_SYMTAB`
   anchors): start + size where present.
2. **PE x64 `.pdata`** (goblin `pe::exception`): RUNTIME_FUNCTION entries
   give exact start/size for non-leaf functions in unhandled binaries.
3. **Prologue-pattern fallback** for stripped/minimal tables: scan
   `.text` for common x64 prologues (`55 48 89 e5`, `48 83 ec`,
   `f3 0f 1e fa` endbr64, `40 53`, `48 89 5c`), bounded to 512
   functions/artifact, min 8-byte gap. This is the same class of
   heuristic linear-sweep tools use (capa/rizin ecosystems) — lossy for
   tail-calls and jump tables, which the evidence labels reflect.

## Function signature

256-bit simhash over normalized features:

- mnemonic n-grams (n=2,3) with immediates/addresses/registers
  abstracted to mnemonic-only tokens,
- instruction-mix histogram buckets (data movement, arithmetic, branch,
  call, SSE, string),
- basic-block estimate (branch targets inside the function),
- call/callee degree bucket.

Primary pair score is Jaccard over sorted token hashes (not simhash
hamming). Match threshold τ = 0.35 (model v1, uncalibrated). Simhash
hamming is retained for future banded indexing.

## Aggregation (spec 16.4/16.5)

- Significance filter: ≥5 instructions, not a pure thunk (single jmp/ret
  tail-call stub). This is our v1 approximation of known-library
  suppression; a curated CRT signature set is a follow-up and is called
  out as such.
- Function matching is **one-to-one**: greedy max-weight assignment so a
  single target function cannot satisfy multiple source functions.
- For artifacts A,B: `cov(A→B) = assigned_A / significant_A`, and
  `cov(B→A)` likewise, using the same assigned pairs.
- `semantic_variant_strong`: both ≥ 0.60 AND ≥ 3 matched function pairs
  (merges variant groups). `semantic_variant_weak`: both ≥ 0.35 (lead
  only). Evidence stores the top-5 function pairs with offsets + scores,
  plus the model config digest and tau.
- Candidate generation: per-tenant bucket by artifact class; per-function
  band filter on the first signature byte before hamming comparison.
  Brute-force at M3 scale; banded LSH index is the follow-up.

## Packed / unsupported inputs

High-entropy `.text` (mean entropy > 7.2) or a failed parse records an
`analysis_limitation` feature and emits NO confident semantic edge
(spec 16.7: we must not claim variant discovery for packed binaries).

## Honest v1 limits

x86-64 only; no decompiler; opt-level drift (-O0 vs -O2) weakens
mnemonic n-grams for tiny functions (medium functions hold structure);
packed/virtualized binaries degrade to limitation records; thresholds
are hand-set, not calibrated.

## Re-analysis note

Edges under `similarity-model:v1` / `semantic:v1` used the thresholds
above (τ = 0.35, strong min pairs = 3). Bumping any threshold requires a
new model/extractor version and a backfill; existing v1 edges remain
valid under their original model identity.
