//! Filesystem content-addressed store for the development profile.
//!
//! Dev mode uses plain SHA-256 paths under a per-tenant namespace
//! (spec 11.3). Production HMAC keying is out of scope for M0.

use crate::error::Result;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

    /// Opaque-ish object key persisted in the artifact row. The DB maps the
    /// tenant artifact to this key; raw customer paths never appear in it.
    pub fn object_key(tenant_id: Uuid, sha256_hex: &str) -> String {
        format!("objects/{tenant_id}/{sha256_hex}")
    }

    fn staging_path(&self, staging_key: &str) -> PathBuf {
        // staging_key is a server-generated uuid; reject path traversal anyway.
        assert!(!staging_key.contains('/') && !staging_key.contains(".."));
        self.root.join("staging").join(staging_key)
    }

    pub fn stage(&self, staging_key: &str, bytes: &[u8]) -> Result<()> {
        let path = self.staging_path(staging_key);
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Move staged bytes to the immutable CAS object with create-if-absent
    /// semantics. Identical bytes already present simply win the race.
    pub fn commit(&self, staging_key: &str, object_key: &str) -> Result<()> {
        let staging = self.staging_path(staging_key);
        let dest = self.root.join(object_key);
        if dest.exists() {
            std::fs::remove_file(&staging)?;
            return Ok(());
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::rename(&staging, &dest) {
            Ok(()) => Ok(()),
            // rename can fail across filesystems; fall back to copy+remove.
            Err(_) => {
                std::fs::copy(&staging, &dest)?;
                std::fs::remove_file(&staging)?;
                Ok(())
            }
        }
    }

    pub fn discard_staging(&self, staging_key: &str) {
        let _ = std::fs::remove_file(self.staging_path(staging_key));
    }

    pub fn read(&self, object_key: &str) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.root.join(object_key))?)
    }
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
}
