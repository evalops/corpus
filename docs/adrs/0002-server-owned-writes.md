# ADR-0002: Server owns all durable writes

## Status

Accepted (M0).

## Context

Endpoints are untrusted. If agents could invent artifact ids or write
shared storage, multi-tenant integrity and rehash guarantees collapse.

## Decision

Only `corpus-server` writes Postgres catalog/ledger and CAS objects.
Agents and `corpusctl` are HTTP clients. Agents may write **local** SQLite
and spool only.

## Consequences

- All validation (rehash, classify, policy) centralizes on the server.
- Offline agent work is queue-and-forward, not peer-to-peer CAS.
- Offline import still goes through announce/finalize.

## References

- [architecture.md](../architecture.md)
- [invariants.md](../invariants.md) §1, §9
