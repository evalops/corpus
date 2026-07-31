//! Encrypted spool (M6 hardening, spec 10.3): XChaCha20-Poly1305 at rest,
//! key generated at enrollment, wrapped by the OS store where available.
//!
//! macOS: Keychain generic-password item. Linux: 0600 key file (documented
//! fallback; kernel keyring/TPM are later scope).
//!
//! Chunked spool format v2 (M9 review fix): every random value comes from
//! OsRng (no UUID-derived material), and the per-chunk nonce is
//! `16-byte random prefix || 8-byte little-endian chunk counter`. The
//! prefix is stored in the spool file header after a one-byte format
//! version: `[u8 version=2][16B prefix][u32 len][ct]...`. Format v1
//! (8-byte prefix, no version byte) is REJECTED on read: the spool is
//! transient, so pre-upgrade spool files are discarded rather than
//! migrated — the affected candidates terminalize as gaps and are
//! re-observed by the sensors.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::path::Path;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "corpus";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "spool-key";

pub struct SpoolCipher {
    cipher: XChaCha20Poly1305,
}

/// Format version byte written at the start of every chunked spool file.
/// v1 (8-byte prefix, no version byte) is rejected on read; see module
/// docs for the discard-on-upgrade rationale.
pub const SPOOL_FORMAT_VERSION: u8 = 2;

/// Per-chunk nonce: 16-byte random prefix || 8-byte LE chunk counter.
fn chunk_nonce(prefix: &[u8; 16], index: u64) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..16].copy_from_slice(prefix);
    nonce_bytes[16..].copy_from_slice(&index.to_le_bytes());
    *XNonce::from_slice(&nonce_bytes)
}

/// Raw 32-byte key material from the OS RNG.
#[cfg(target_os = "windows")]
pub(crate) fn random_key_material() -> [u8; 32] {
    random_bytes::<32>()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

fn load_or_create_key_bytes(#[allow(unused_variables)] state_dir: &Path) -> Result<[u8; 32]> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(existing) =
            security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        {
            let key: [u8; 32] = existing
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt keychain spool key length"))?;
            return Ok(key);
        }
        let key = random_bytes::<32>();
        security_framework::passwords::set_generic_password(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            &key,
        )
        .context("storing spool key in macOS Keychain")?;
        Ok(key)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let path = state_dir.join("spool.key");
        if let Ok(existing) = std::fs::read(&path) {
            let key: [u8; 32] = existing
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt spool key file"))?;
            return Ok(key);
        }
        let key = random_bytes::<32>();
        std::fs::create_dir_all(state_dir)?;
        std::fs::write(&path, key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(key)
    }
    #[cfg(target_os = "windows")]
    {
        crate::win32_dpapi::load_or_create_key(state_dir)
    }
}

impl SpoolCipher {
    pub fn load_or_create(state_dir: &Path) -> Result<SpoolCipher> {
        let key = load_or_create_key_bytes(state_dir)?;
        Ok(SpoolCipher {
            cipher: XChaCha20Poly1305::new_from_slice(&key).context("key length")?,
        })
    }

    /// nonce (24B) || ciphertext || tag.
    /// Whole-file convenience API (used by tests and small payloads).
    #[allow(dead_code)]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes = random_bytes::<24>();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("AEAD encrypt is infallible");
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// Encrypt one stream chunk. Nonce = 16-byte random prefix ||
    /// 8-byte little-endian chunk counter, so chunks are independently
    /// verifiable and bounded-memory streaming works, and nonce reuse
    /// across objects requires a 128-bit prefix collision.
    pub fn encrypt_chunk(&self, prefix: &[u8; 16], index: u64, chunk: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(&chunk_nonce(prefix, index), chunk)
            .expect("AEAD encrypt is infallible")
    }

    pub fn decrypt_chunk(&self, prefix: &[u8; 16], index: u64, ct: &[u8]) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(&chunk_nonce(prefix, index), ct)
            .map_err(|_| {
                anyhow::anyhow!("spool chunk failed AEAD verification (tampered or wrong key)")
            })
    }

    /// New 16-byte random stream prefix identifying one spool object.
    pub fn stream_prefix() -> [u8; 16] {
        random_bytes::<16>()
    }

    #[allow(dead_code)]
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < 24 + 16 {
            anyhow::bail!("spool blob too short to be ciphertext");
        }
        let (nonce_bytes, ct) = blob.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);
        self.cipher.decrypt(nonce, ct).map_err(|_| {
            anyhow::anyhow!("spool chunk failed AEAD verification (tampered or wrong key)")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_rejection() {
        let dir = tempfile::tempdir().unwrap();
        // File backend: tests never touch the real OS key store.
        let cipher = load_or_create_file(dir.path()).unwrap();
        let plaintext = b"sample bytes for the spool";
        let blob = cipher.encrypt(plaintext);
        assert_ne!(&blob[24..], plaintext, "stored bytes must be ciphertext");
        assert_eq!(cipher.decrypt(&blob).unwrap(), plaintext);

        // Same key survives a "restart" (reload from the key file).
        let cipher2 = load_or_create_file(dir.path()).unwrap();
        assert_eq!(cipher2.decrypt(&blob).unwrap(), plaintext);

        // Tampered chunk is rejected, never silently accepted.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(cipher.decrypt(&tampered).is_err());
        let mut truncated = blob.clone();
        truncated.truncate(10);
        assert!(cipher.decrypt(&truncated).is_err());
    }

    #[test]
    fn chunked_stream_roundtrip_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let cipher = load_or_create_file(dir.path()).unwrap();
        let prefix = SpoolCipher::stream_prefix();
        let chunks: Vec<Vec<u8>> =
            vec![b"chunk one".to_vec(), vec![7u8; 100_000], b"tail".to_vec()];
        let encrypted: Vec<Vec<u8>> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| cipher.encrypt_chunk(&prefix, i as u64, c))
            .collect();
        for (i, (plain, ct)) in chunks.iter().zip(&encrypted).enumerate() {
            assert_ne!(plain.as_slice(), ct.as_slice());
            assert_eq!(cipher.decrypt_chunk(&prefix, i as u64, ct).unwrap(), *plain);
        }
        // Wrong index (reordering) and wrong prefix both fail.
        assert!(cipher.decrypt_chunk(&prefix, 9, &encrypted[0]).is_err());
        assert!(cipher.decrypt_chunk(&[0u8; 16], 0, &encrypted[0]).is_err());
    }

    #[test]
    fn nonce_is_prefix_counter_construction() {
        // The v2 nonce is 16-byte prefix || 8-byte LE counter (regression:
        // v1 used an 8-byte prefix padded with a 16-byte counter).
        let prefix = [0xABu8; 16];
        let nonce = chunk_nonce(&prefix, 0x0102);
        assert_eq!(&nonce[..16], &[0xABu8; 16]);
        assert_eq!(&nonce[16..], &0x0102u64.to_le_bytes());
        // Distinct prefixes give distinct ciphertexts for identical input.
        let dir = tempfile::tempdir().unwrap();
        let cipher = load_or_create_file(dir.path()).unwrap();
        let a = cipher.encrypt_chunk(&[1u8; 16], 0, b"same");
        let b = cipher.encrypt_chunk(&[2u8; 16], 0, b"same");
        assert_ne!(a, b);
    }
}

/// File backend for the key (Linux default; also used by tests so they
/// never touch the real Keychain).
#[allow(dead_code)]
pub fn load_or_create_file(state_dir: &std::path::Path) -> Result<SpoolCipher> {
    let path = state_dir.join("spool.key");
    if let Ok(existing) = std::fs::read(&path) {
        let key: [u8; 32] = existing
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt spool key file"))?;
        return Ok(SpoolCipher {
            cipher: XChaCha20Poly1305::new_from_slice(&key).context("key length")?,
        });
    }
    let key = random_bytes::<32>();
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(&path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(SpoolCipher {
        cipher: XChaCha20Poly1305::new_from_slice(&key).context("key length")?,
    })
}

/// Decrypt a chunked spool blob:
/// `[u8 version][16B prefix][u32 len][ct][u32 len][ct]...`.
/// Only `SPOOL_FORMAT_VERSION` is accepted; older chunks are rejected
/// outright (spool is transient — see module docs).
pub fn decrypt_file(cipher: &SpoolCipher, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 1 + 16 {
        anyhow::bail!("spool blob too short for header");
    }
    if blob[0] != SPOOL_FORMAT_VERSION {
        anyhow::bail!(
            "unsupported spool format version {} (expected {}); stale spool must be discarded",
            blob[0],
            SPOOL_FORMAT_VERSION
        );
    }
    let prefix: &[u8; 16] = blob[1..17].try_into().unwrap();
    let mut rest = &blob[17..];
    let mut out = Vec::new();
    let mut index: u64 = 0;
    while !rest.is_empty() {
        if rest.len() < 4 {
            anyhow::bail!("truncated spool chunk header");
        }
        let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        rest = &rest[4..];
        let ct_len = len + 16;
        if rest.len() < ct_len {
            anyhow::bail!("truncated spool chunk");
        }
        let (ct, next) = rest.split_at(ct_len);
        out.extend_from_slice(&cipher.decrypt_chunk(prefix, index, ct)?);
        rest = next;
        index += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod file_format_tests {
    use super::*;

    /// Serialize chunks into the on-disk v2 spool format.
    fn build_v2(cipher: &SpoolCipher, prefix: &[u8; 16], chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut blob = vec![SPOOL_FORMAT_VERSION];
        blob.extend_from_slice(prefix);
        for (i, c) in chunks.iter().enumerate() {
            blob.extend_from_slice(&(c.len() as u32).to_le_bytes());
            blob.extend_from_slice(&cipher.encrypt_chunk(prefix, i as u64, c));
        }
        blob
    }

    #[test]
    fn encrypted_spool_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cipher = load_or_create_file(dir.path()).unwrap();
        let prefix = SpoolCipher::stream_prefix();
        let chunks: Vec<Vec<u8>> = vec![b"hello".to_vec(), vec![42u8; 70_000], b"bye".to_vec()];
        let blob = build_v2(&cipher, &prefix, &chunks);
        let plaintext: Vec<u8> = chunks.concat();
        assert!(!blob.windows(5).any(|w| w == b"hello"));
        assert_eq!(decrypt_file(&cipher, &blob).unwrap(), plaintext);
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt_file(&cipher, &bad).is_err());
    }

    #[test]
    fn v1_spool_blobs_are_rejected() {
        // Format v1: [8B prefix][u32 len][ct]... — no version byte. The
        // first byte of a v1 blob is prefix data, not a version; whatever
        // it reads as, decrypt must refuse rather than misinterpret.
        let dir = tempfile::tempdir().unwrap();
        let cipher = load_or_create_file(dir.path()).unwrap();
        // Craft a v1-shaped blob whose first byte happens to equal the v2
        // version: still rejected at the prefix/chunk layer (AEAD or
        // truncation), never silently accepted.
        let mut v1 = vec![SPOOL_FORMAT_VERSION; 8];
        v1.extend_from_slice(&5u32.to_le_bytes());
        v1.extend_from_slice(&[0u8; 5 + 16]);
        assert!(decrypt_file(&cipher, &v1).is_err());
        // Any other leading byte is an explicit version rejection.
        let mut unknown = vec![0xEEu8; 64];
        unknown.extend_from_slice(&[0u8; 32]);
        let err = decrypt_file(&cipher, &unknown).unwrap_err().to_string();
        assert!(err.contains("unsupported spool format version"), "{err}");
        assert!(decrypt_file(&cipher, &[]).is_err());
    }
}
