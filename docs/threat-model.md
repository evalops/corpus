# Threat model

Scope: a self-hosted Corpus deployment (server + Postgres + CAS + agents).
This is an engineering threat model, not a compliance artifact.

## Assets

| Asset | Sensitivity | Store |
|-------|-------------|--------|
| Sample bytes (malware / dual-use code) | High | CAS filesystem |
| Occurrence ledger (host paths, agents) | High (privacy + IR value) | Postgres |
| Admin bearer token | Critical | Env / secret manager |
| Deployment CA + agent client certs | Critical | `CORPUS_CA_DIR`, agent state |
| Spool encryption keys | High | OS key wrap / 0600 file |
| Rule sources / intel indicators | Medium | Postgres |
| MCP token | High if exposed | Env |

## Actors

| Actor | Goal |
|-------|------|
| Compromised endpoint | Exfil agent credentials; flood server; read other hosts’ data (should fail) |
| Malicious sample author | Crash scanner/server; escape analysis sandbox; RCE via rule engine |
| Network attacker (path to admin port) | Call admin API without token; MITM agent traffic |
| Malicious tenant principal | Read other tenants’ artifacts (should fail) |
| Operator error | Bind admin without token; enable detonation toward untrusted CAPE |

## Controls (mapped)

| Risk | Control | Residual |
|------|---------|----------|
| Cross-tenant sample read | `tenant_id` on keys + SQL; CAS path namespaced | App bug could still join wrong; review SQL carefully |
| Admin API on network | Non-loopback refuses start without `CORPUS_ADMIN_TOKEN` | Token theft = full admin; use short-lived secrets + gateway |
| Agent impersonation | mTLS deployment CA; enrollment one-time | Stolen agent cert = that agent’s ingest rights |
| Malicious PE crashes host process | Out-of-process `corpus-scanner`; seatbelt/landlock or gVisor | **Not** a malware sandbox; assume escape is possible under determined exploit |
| Sample leaves org | Detonation default off; explicit enable | Misconfiguration enables CAPE egress |
| Spool theft on disk | XChaCha20-Poly1305 + OS key wrap | Linux file-key mode is weaker than Keychain/TPM |
| Path confusion / symlink | Stable read opens nofollow | Platform-specific edge cases |
| Tenant header spoofing | Header is **not** auth; auth is token/mTLS | Shared admin token sees all tenants it can address |

## Explicit non-claims

- Subprocess + landlock/seatbelt is **not** equivalent to a detonation VM.
- gVisor tier reduces risk; it is still not Kata/Firecracker-class isolation
  (documented as future in hardening notes).
- Similarity and YARA matches are leads, not ground truth about host compromise.
- CAPE findings mean “observed in that sandbox,” not “executed on the endpoint.”

## Logging & forensics

- `audit_event` for control actions (including detonation requests)
- `capture_attempt` for gaps
- `similarity_cleanup_log` for destructive derived-row cleanup
- Analysis receipts for “what model saw this artifact”

## Review triggers

Revisit this document when:

- Adding a new network listener or auth mode
- Enabling any sample egress path
- Changing scanner isolation tiers
- Introducing multi-tenant admin delegation

## Related

- [hardening-decisions.md](hardening-decisions.md)
- [deploy.md](deploy.md)
- [invariants.md](invariants.md) §14–15
