# Detonation adapter design (M10)

We orchestrate, the sandbox detonates. Static analysis remains the
default; dynamic evidence is opt-in per artifact.

## Provider landscape (research notes)

- **CAPEv2** (self-hosted default): free, mature, REST API
  (`POST /api/tasks/create/file/` multipart, `GET /api/tasks/view/{id}`
  status polling, `GET /api/tasks/report/{id}` JSON report with
  `signatures` and `ttps`). Bearer-token auth. Fits the spec's
  optional-enricher model (20.6: external analysis services must declare
  what they transmit).
- **Triage** (Hatching, SaaS example): documented REST submission API,
  token auth. Same shape (submit → poll → report). Viable later as a
  second provider behind the same trait; not implemented here.
- **Joe Sandbox / VMRay**: commercial; same adapter pattern applies.

## Interface

`DetonationProvider` trait: `capabilities()`, `submit(sample) -> Job`,
`poll(job) -> PollOutcome { Pending | Done(report) | Failed }`. Config
is explicit and **off by default** (`CORPUS_DETONATION_ENABLED=1`
required) — sample egress is a security decision, never implicit
(spec 20.6). The provider manifest declares `sampleBytes: true`.

## Evidence typing (spec 17.4)

CAPE report `signatures` map to findings with
`evidence_type = DYNAMIC_BEHAVIOR` — the first producer of that type in
the platform. ATT&CK-ish signature descriptions are phrased as
"behavior observed in sandbox", never `STATIC_CAPABILITY`. Static
evidence types are untouched.

## Flow

1. `corpusctl detonate <sha256>` (or auto policy, default OFF) → server
   loads bytes from the CAS, submits to CAPE, polls with backoff.
2. Result lands as an `analysis_run` (analyzer_name `cape`, version
   pinned) + `finding` rows (new table) with DYNAMIC_BEHAVIOR typing and
   a bounded report digest. Blast-radius artifacts surface findings
   alongside matched rules.
3. Every detonation request writes an `audit_event` (24.3) with actor,
   artifact, provider, and egress declaration.

## Honest boundary

We do not build a sandbox, and we do not trust CAPE results as ground
truth about the host: dynamic evidence means "observed in CAPE", which
is why it lands as analyzer findings, not occurrences or verdicts.
