# Corpus documentation

| Doc | Purpose |
|-----|---------|
| [intent.md](intent.md) | Problem, thesis, users, non-goals |
| [architecture.md](architecture.md) | Processes, trust boundaries, data/control/analysis planes |
| [invariants.md](invariants.md) | Numbered guarantees the code must not violate |
| [data-model.md](data-model.md) | Glossary, tables, relationships |
| [spec-map.md](spec-map.md) | Product-spec section → code location |
| [threat-model.md](threat-model.md) | Assets, attackers, residual risk |
| [runbooks.md](runbooks.md) | Operator procedures for common failures |
| [adrs/](adrs/) | Architecture decision records |
| [deploy.md](deploy.md) | Env vars, auth policy, first hunt |
| [semantic-similarity-design.md](semantic-similarity-design.md) | Function-level matching design |
| [hardening-decisions.md](hardening-decisions.md) | mTLS, spool crypto, scanner tiers (research notes) |
| [detonation-design.md](detonation-design.md) | CAPE adapter design |
| [openapi.json](openapi.json) | HTTP surface (`GET /api/v1/openapi.json`) |

Read order for a new engineer: **intent → architecture → invariants → data-model → deploy**.

Decision history: start at [adrs/README.md](adrs/README.md). Milestone research notes (hardening, semantic, detonation) stay as standalone design docs; ADRs capture the cross-cutting choices in short form.
