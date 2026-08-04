//! Content-addressed storage backends.
//!
//! `CasBackend` is the trait every storage implementation must satisfy.
//! `FsCas` remains the default filesystem backend. A memory backend is
//! provided for conformance tests.

use crate::error::{Error, Result};
use crate::hash;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Content-addressed store interface.
///
/// Writes verify the declared digest before commit. Put-if-absent is safe
/// under concurrent uploads (last writer with identical bytes wins).
pub trait CasBackend: Send + Sync {
    /// Stage raw bytes under a server-generated staging key.
    fn stage(&self, staging_key: &str, bytes: &[u8]) -> Result<()>;

    /// Move staged bytes to an immutable object key (create-if-absent).
    fn commit(&self, staging_key: &str, object_key: &str) -> Result<()>;

    /// Discard a staging object if present.
    fn discard_staging(&self, staging_key: &str);

    /// Read an object by key. Callers must authorize tenant access first.
    fn read(&self, object_key: &str) -> Result<Vec<u8>>;

    /// True when the object key exists.
    fn exists(&self, object_key: &str) -> Result<bool>;

    /// Optional range read; default materializes full object then slices.
    fn read_range(&self, object_key: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let all = self.read(object_key)?;
        let start = offset as usize;
        if start >= all.len() {
            return Ok(Vec::new());
        }
        let end = (start + len).min(all.len());
        Ok(all[start..end].to_vec())
    }

    /// Metadata: (size_bytes, sha256_hex) if present.
    fn metadata(&self, object_key: &str) -> Result<Option<(u64, String)>> {
        if !self.exists(object_key)? {
            return Ok(None);
        }
        let bytes = self.read(object_key)?;
        Ok(Some((bytes.len() as u64, hash::sha256_hex(&bytes))))
    }

    /// Delete or tombstone an object. Filesystem backend unlinks.
    fn delete(&self, object_key: &str) -> Result<()>;
}

/// Opaque object key under a per-tenant namespace.
pub fn object_key(tenant_id: Uuid, sha256_hex: &str) -> String {
    format!("objects/{tenant_id}/{sha256_hex}")
}

/// Verify that `bytes` match `declared_sha256_hex` before commit.
pub fn verify_digest(bytes: &[u8], declared_sha256_hex: &str) -> Result<()> {
    let recomputed = hash::sha256_hex(bytes);
    if recomputed != declared_sha256_hex {
        return Err(Error::HashMismatch {
            announced: declared_sha256_hex.into(),
            recomputed,
        });
    }
    Ok(())
}

// ---------------- Filesystem backend ----------------

pub struct FsCas {
    root: PathBuf,
}

impl FsCas {
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let cas = FsCas { root: root.into() };
        std::fs::create_dir_all(cas.root.join("objects"))?;
        std::fs::create_dir_all(cas.root.join("staging"))?;
        Ok(cas)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Opaque-ish object key persisted in the artifact row.
    pub fn object_key(tenant_id: Uuid, sha256_hex: &str) -> String {
        object_key(tenant_id, sha256_hex)
    }

    fn staging_path(&self, staging_key: &str) -> PathBuf {
        assert!(!staging_key.contains('/') && !staging_key.contains(".."));
        self.root.join("staging").join(staging_key)
    }
}

impl CasBackend for FsCas {
    fn stage(&self, staging_key: &str, bytes: &[u8]) -> Result<()> {
        let path = self.staging_path(staging_key);
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn commit(&self, staging_key: &str, object_key: &str) -> Result<()> {
        let staging = self.staging_path(staging_key);
        let dest = self.root.join(object_key);
        if dest.exists() {
            let _ = std::fs::remove_file(&staging);
            return Ok(());
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::rename(&staging, &dest) {
            Ok(()) => Ok(()),
            Err(_) => {
                std::fs::copy(&staging, &dest)?;
                std::fs::remove_file(&staging)?;
                Ok(())
            }
        }
    }

    fn discard_staging(&self, staging_key: &str) {
        let _ = std::fs::remove_file(self.staging_path(staging_key));
    }

    fn read(&self, object_key: &str) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.root.join(object_key))?)
    }

    fn exists(&self, object_key: &str) -> Result<bool> {
        Ok(self.root.join(object_key).exists())
    }

    fn delete(&self, object_key: &str) -> Result<()> {
        let path = self.root.join(object_key);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

// Keep inherent methods used by existing call sites.
impl FsCas {
    pub fn stage(&self, staging_key: &str, bytes: &[u8]) -> Result<()> {
        CasBackend::stage(self, staging_key, bytes)
    }
    pub fn commit(&self, staging_key: &str, object_key: &str) -> Result<()> {
        CasBackend::commit(self, staging_key, object_key)
    }
    pub fn discard_staging(&self, staging_key: &str) {
        CasBackend::discard_staging(self, staging_key)
    }
    pub fn read(&self, object_key: &str) -> Result<Vec<u8>> {
        CasBackend::read(self, object_key)
    }
}

// ---------------- In-memory backend (tests) ----------------

#[derive(Default, Clone)]
pub struct MemoryCas {
    inner: Arc<Mutex<MemoryInner>>,
}

#[derive(Default)]
struct MemoryInner {
    staging: HashMap<String, Vec<u8>>,
    objects: HashMap<String, Vec<u8>>,
}

impl MemoryCas {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CasBackend for MemoryCas {
    fn stage(&self, staging_key: &str, bytes: &[u8]) -> Result<()> {
        assert!(!staging_key.contains('/') && !staging_key.contains(".."));
        self.inner
            .lock()
            .unwrap()
            .staging
            .insert(staging_key.into(), bytes.to_vec());
        Ok(())
    }

    fn commit(&self, staging_key: &str, object_key: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let bytes = g
            .staging
            .remove(staging_key)
            .ok_or_else(|| Error::NotFound(format!("staging {staging_key}")))?;
        g.objects.entry(object_key.into()).or_insert(bytes);
        Ok(())
    }

    fn discard_staging(&self, staging_key: &str) {
        self.inner.lock().unwrap().staging.remove(staging_key);
    }

    fn read(&self, object_key: &str) -> Result<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .objects
            .get(object_key)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("object {object_key}")))
    }

    fn exists(&self, object_key: &str) -> Result<bool> {
        Ok(self.inner.lock().unwrap().objects.contains_key(object_key))
    }

    fn delete(&self, object_key: &str) -> Result<()> {
        self.inner.lock().unwrap().objects.remove(object_key);
        Ok(())
    }
}

/// Conformance checks every backend must pass.
pub fn conformance_suite(cas: &dyn CasBackend) -> Result<()> {
    let tenant = Uuid::from_u128(42);
    let payload = b"conformance-payload-v1";
    let sha = hash::sha256_hex(payload);
    verify_digest(payload, &sha)?;
    let key = object_key(tenant, &sha);

    cas.stage("conf-1", payload)?;
    cas.commit("conf-1", &key)?;
    assert!(cas.exists(&key)?);
    assert_eq!(cas.read(&key)?, payload);
    assert_eq!(cas.read_range(&key, 0, 4)?, b"conf");
    let meta = cas.metadata(&key)?.expect("metadata");
    assert_eq!(meta.0, payload.len() as u64);
    assert_eq!(meta.1, sha);

    // Put-if-absent: second commit of same key does not fail.
    cas.stage("conf-2", payload)?;
    cas.commit("conf-2", &key)?;
    assert_eq!(cas.read(&key)?, payload);

    // Digest mismatch is caller-side; backend stores what it is given.
    // Delete and re-check.
    cas.delete(&key)?;
    assert!(!cas.exists(&key)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_commit_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cas = FsCas::new(dir.path()).unwrap();
        let tenant = Uuid::new_v4();
        let sha = crate::hash::sha256_hex(b"payload");
        let key = FsCas::object_key(tenant, &sha);
        cas.stage("sess-1", b"payload").unwrap();
        cas.commit("sess-1", &key).unwrap();
        assert_eq!(cas.read(&key).unwrap(), b"payload");
        assert!(!dir.path().join("staging/sess-1").exists());
    }

    #[test]
    fn commit_is_create_if_absent() {
        let dir = tempfile::tempdir().unwrap();
        let cas = FsCas::new(dir.path()).unwrap();
        let tenant = Uuid::new_v4();
        let sha = crate::hash::sha256_hex(b"same bytes");
        let key = FsCas::object_key(tenant, &sha);
        cas.stage("a", b"same bytes").unwrap();
        cas.commit("a", &key).unwrap();
        cas.stage("b", b"same bytes").unwrap();
        cas.commit("b", &key).unwrap();
        assert_eq!(cas.read(&key).unwrap(), b"same bytes");
    }

    #[test]
    fn memory_and_fs_pass_conformance() {
        let dir = tempfile::tempdir().unwrap();
        let fs = FsCas::new(dir.path()).unwrap();
        conformance_suite(&fs).unwrap();
        let mem = MemoryCas::new();
        conformance_suite(&mem).unwrap();
    }

    #[test]
    fn verify_digest_rejects_mismatch() {
        let err = verify_digest(b"abc", "deadbeef").unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }
}
