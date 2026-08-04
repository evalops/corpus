# Operator runbooks

Assumes `corpusctl` pointed at the server (`CORPUS_SERVER_URL`,
`CORPUS_ADMIN_TOKEN`, optional `CORPUS_TENANT`).

## Hunt stuck in RUNNING

1. `corpusctl hunts` (or `GET /api/v1/hunts/{id}`) — note `scanned`,
   `timed_out`, `failed`, `error`.
2. Check server logs for scanner timeouts (`SCAN_TIMEOUT` default 10s per
   artifact).
3. If using async worker: confirm `hunt_job` claim loop is running (single
   node: server process must be up).
4. Poison artifact: identify last sha256 from logs; optional
   `CORPUS_HUNT_SYNC=1` for in-request runs during debug.
5. COMPLETED_PARTIAL is valid when timeouts/failures occurred — not a
   deadlock.

## Agent coverage gaps spiking

1. `GET /api/v1/coverage/gaps` or corpusctl fleet/gaps view.
2. Classify `capture_attempt.terminal_outcome` / detail codes:
   - mutation during read → writer churn; expected under installs
   - spool full / too large → raise limits or free disk
   - hash mismatch → client/server skew or corrupt stage
3. Confirm heartbeat: `GET /api/v1/agents/{id}` last_seen.
4. Sensor path: Linux fanotify privileges; Windows USN journal id change
   forces reconcile (expected after some volume ops).

## Missing similarity edges

1. Confirm artifact class is `pe`/`elf`/`macho` and storage committed.
2. Receipts: `GET /api/v1/artifacts/{id}/receipts` — status `limitation` with
   packed/virtualized summary means semantic was blocked by design
   ([invariants.md](invariants.md) §12).
3. Byte path: run `corpusctl similarity backfill` for the tenant.
4. Analyzers: `GET /api/v1/similarity/analyzers` — versions active.
5. Neighborhood: `corpusctl similarity neighborhood <sha256>` with
   `min_score=0` to see weak leads.

## Packed binary / no semantic match

Expected when triage `block_semantic` is true (high entropy, RWX+entropy,
packer markers + corroboration). Use byte_similar / intel / YARA instead.
Do not lower `packed_entropy_limit` without a model version bump
([invariants.md](invariants.md) §13).

## Legal hold blocked cleanup

`POST .../similarity-cleanup` returns conflict when
`artifact.provenance.legal_hold` is true. Dry-run still returns counts.
Clear hold only with dual-control process outside Corpus, then re-run
with `dry_run=false`.

## Rotate admin token

1. Generate new secret; set `CORPUS_ADMIN_TOKEN` on server; restart.
2. Update corpusctl/automation secrets.
3. Old token stops working immediately (no dual-token window in tree).

## Rotate deployment CA / agent certs

1. `corpusctl ca init` paths under `CORPUS_CA_DIR` (see deploy).
2. Re-enroll agents or use `POST /api/v1/agents/renew` on mTLS listener.
3. Agents with expired certs fail mTLS — expect gap until renewed.

## Enable detonation safely

1. Read [detonation-design.md](detonation-design.md) and threat model §sample egress.
2. Set `CORPUS_CAPE_URL` + `CORPUS_CAPE_TOKEN`.
3. Set `CORPUS_DETONATION_ENABLED=1` only when CAPE is authorized to
   receive org samples.
4. Keep `CORPUS_DETONATION_AUTO` off until opinion policy is reviewed.
5. Confirm `audit_event` rows on submit.

## Database / migrations

1. Server applies `sqlx` migrations at boot (`corpus_core::db::migrate`).
2. Take Postgres backup before upgrading builds that add migrations.
3. Dual `0010_*.sql` files are intentional (Merlin + receipts); both must apply.

## Postgres down

1. Server will fail health/DB operations; agents spool locally until upload
   succeeds (queue + encrypted spool).
2. Restore DB; restart server; agents drain backlog.
3. CAS files are independent of DB — do not delete `CORPUS_CAS_ROOT` when
   restoring DB or digests will 404 on read.

## Related

- [deploy.md](deploy.md)
- [architecture.md](architecture.md)
