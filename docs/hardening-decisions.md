# Hardening decisions (M6)

Research summary for the three dev-posture gaps closed in this milestone.
Crates/versions checked against crates.io/docs.rs in July 2026.

## 1. mTLS agent authentication

**Decision: rustls everywhere (tokio-rustls 0.26 / rustls 0.23), rcgen 0.13
for the deployment CA, x509-parser for peer-CN extraction.**

- rustls over native-tls: pure Rust (no OpenSSL link issues on macOS,
  musl, or the LXC), already in the tree via reqwest's `rustls-tls`
  feature, modern API for client-cert verification
  (`AllowAnyAuthenticatedClient` + `RootCertStore`). native-tls would pull
  platform TLS stores we explicitly do not want (agent auth must trust
  only the deployment CA, not the OS root store).
- `axum-server` does not expose peer certificates after the handshake
  (upstream issue 162; helper crates are thin and immature). Instead the
  agent listener runs `axum::serve` over a hand-built
  `tokio_rustls::TlsAcceptor` — full control of the verifier and of peer
  cert injection into request extensions.
- **Topology: two listeners.** Plain `:8080` for admin/CLI/dev traffic
  (unchanged) and mTLS `:8443` for agent traffic (`/agents/*` +
  authenticated ingest). Route-level auth can't be decided per-route at
  the TLS layer; separate listeners are the simplest sound design.
- **CA story**: on first run the server generates a self-signed
  deployment CA (`data/ca/ca.pem` + `ca-key.pem`, 0600, loud log line).
  `corpusctl ca init` prints/rotates it. Enrollment (one-time token over
  the plain listener — the documented bootstrap credential) returns a
  signed client cert (CN = agent UUID, 30-day TTL) plus the CA cert.
  Renewal via `POST /agents/renew` on the mTLS listener. Legacy bearer
  stays behind `CORPUS_AGENT_LEGACY_BEARER=1`, off by default.
- Client side: `reqwest::Identity::from_pem` + pinned root (rustls-tls).

## 2. Spool encryption

**Decision: XChaCha20-Poly1305 via the `chacha20poly1305` crate (0.10,
RustCrypto).**

- Over AES-256-GCM (`aes-gcm`): both are sound AEADs; XChaCha20 has a
  192-bit nonce safe for random-per-file nonces (no nonce-reuse
  catastrophe class that GCM carries), no platform dependence on AES-NI
  for timing safety, single small pure-Rust dep.
- Whole-file AEAD per spool object: `nonce(24B) || ciphertext || tag`.
  Files are bounded by `max_artifact_bytes`; chunked streaming AEAD is a
  documented follow-up (large-file tier).
- Chunked spool (v2, M9): per-chunk nonce = 16-byte random prefix ||
  8-byte little-endian chunk counter, prefix random from `OsRng` (no
  UUID-derived randomness anywhere). File layout: `[u8 version=2][16B
  prefix][u32 len][ct]...`. The v1 layout (8-byte prefix, no version
  byte) is rejected on read: the spool is transient, so pre-upgrade
  spool files are discarded rather than migrated — the affected
  candidates terminalize as gaps and are re-observed by the sensors.
- Key: 32 random bytes generated at enrollment. Wrapping:
  - macOS: Keychain generic-password item via `security-framework` 3.x
    (mature, servo-maintained).
  - Linux: `state_dir/spool.key` mode 0600 — documented fallback.
    Kernel keyring needs C bindings (keyutils); TPM2 is out of M6 scope.
- Plaintext lives in memory only during upload streaming; spool files are
  ciphertext at rest. Tamper → AEAD error → capture gap, never silent.

## 3. Analysis isolation (tiered)

**Decision: tiered runner interface; tier 1 lands now, tier 2 is config
with an honest error, tier 3 stays a production requirement doc.**

- Tier 1 (lands): `corpus-scanner` helper binary; the server invokes it
  as a subprocess with the sample path, output to stdout, enforced
  timeout and output cap.
  - macOS: `sandbox-exec` seatbelt — verified working here as
    `(allow default)(deny network*)(deny file-write* outside /tmp//dev)`.
    A strict `deny default` profile **aborts under dyld** on modern
    macOS, so the landed guarantees are network isolation and write
    confinement, NOT filesystem-read narrowing.
  - Linux: `landlock` crate (0.4, best-effort — read-only FS view minus
    the sample dir; downgraded with a clear log line when the kernel ABI
    is missing, e.g. containers).
  - Seatbelt/landlock are *containment hints*, not a hostile-malware
    boundary (shared kernel, no resource isolation).
- Tier 2 (config): `CORPUS_SCANNER_TIER=gvisor` runs the scanner under
  `docker run --runtime=runsc`. **Verified unavailable in Colima** (only
  `runc` is registered), so this tier errors loudly when selected
  without runsc; it is for real Linux hosts with gVisor installed.
- Tier 3 (doc): spec invariant #14 stands — microVM/Kata-class isolation
  is the production requirement for hostile samples. Not built here.

### Honesty statement

Subprocess+seatbelt (and subprocess+landlock) reduce blast radius of
parser bugs (no network, narrow filesystem view) but are **not** a safe
boundary for scanning live hostile malware in production. Production
deployments must select tier 2 (gVisor) or tier 3 (Kata/microVM).
