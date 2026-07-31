//! Stable read algorithm (spec 10.5): open without following symlinks,
//! stream into the spool while hashing, re-stat, retry on mutation,
//! terminal CHANGED_DURING_READ.

use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StableReadError {
    DeletedBeforeRead,
    PermissionDenied,
    TooLarge { size: u64 },
    ChangedDuringRead,
    SpoolFull,
    Io(String),
}

#[derive(Debug)]
pub struct StableReadResult {
    pub sha256: String,
    pub size: u64,
    pub spool_path: PathBuf,
}

fn identity_of(file: &std::fs::File) -> std::io::Result<crate::fileid::FileKey> {
    #[cfg(unix)]
    {
        Ok(crate::fileid::file_key(&file.metadata()?))
    }
    #[cfg(windows)]
    {
        crate::fileid::key_for_file(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(crate::fileid::scan_key(&file.metadata()?))
    }
}

fn map_open_err(e: &std::io::Error) -> StableReadError {
    match e.kind() {
        std::io::ErrorKind::NotFound => StableReadError::DeletedBeforeRead,
        std::io::ErrorKind::PermissionDenied => StableReadError::PermissionDenied,
        _ => StableReadError::Io(e.to_string()),
    }
}

/// A test hook invoked right before the re-stat, allowing tests to mutate
/// the file mid-read. Always `None` in production paths.
pub type MutationHook<'a> = Option<&'a dyn Fn()>;

/// Copy `path` into `spool_dir` while hashing, verifying the file did not
/// change during the read. Retries up to `retries` times on mutation.
pub fn stable_read(
    path: &Path,
    spool_dir: &Path,
    max_artifact_bytes: u64,
    spool_free_bytes: u64,
    retries: u32,
    mutation_hook: MutationHook<'_>,
    cipher: Option<&crate::spool_crypto::SpoolCipher>,
) -> Result<StableReadResult, StableReadError> {
    let mut attempt = 0;
    loop {
        match read_once(
            path,
            spool_dir,
            max_artifact_bytes,
            spool_free_bytes,
            mutation_hook,
            cipher,
        ) {
            Err(StableReadError::ChangedDuringRead) if attempt < retries => {
                attempt += 1;
                continue;
            }
            other => return other,
        }
    }
}

fn read_once(
    path: &Path,
    spool_dir: &Path,
    max_artifact_bytes: u64,
    spool_free_bytes: u64,
    mutation_hook: MutationHook<'_>,
    cipher: Option<&crate::spool_crypto::SpoolCipher>,
) -> Result<StableReadResult, StableReadError> {
    // Step 2: open without following unexpected symlinks/reparse points.
    let mut file = open_nofollow(path).map_err(|e| map_open_err(&e))?;

    // Step 3: initial identity.
    let before = identity_of(&file).map_err(|e| map_open_err(&e))?;
    if before.size > max_artifact_bytes {
        return Err(StableReadError::TooLarge { size: before.size });
    }
    if before.size > spool_free_bytes {
        return Err(StableReadError::SpoolFull);
    }

    // Step 4: stream into the spool while hashing. When a cipher is
    // configured (M6), spool bytes are AEAD ciphertext at rest; the hash
    // is always over plaintext.
    let spool_path = spool_dir.join(format!("spool-{}", uuid::Uuid::new_v4()));
    let mut out = create_spool_file(&spool_path)?;

    let stream_prefix = cipher.map(|c| {
        let prefix = crate::spool_crypto::SpoolCipher::stream_prefix();
        let _ = c;
        prefix
    });
    if let Some(prefix) = &stream_prefix {
        // Spool format v2: [u8 version][16B prefix][u32 len][ct]...
        let write_header =
            std::io::Write::write_all(&mut out, &[crate::spool_crypto::SPOOL_FORMAT_VERSION])
                .and_then(|()| std::io::Write::write_all(&mut out, prefix));
        if let Err(e) = write_header {
            let _ = std::fs::remove_file(&spool_path);
            return Err(StableReadError::Io(e.to_string()));
        }
    }

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    let mut chunk_index: u64 = 0;
    let copy_result: Result<(), StableReadError> = loop {
        match file.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                hasher.update(&buf[..n]);
                total += n as u64;
                if total > max_artifact_bytes {
                    break Err(StableReadError::TooLarge { size: total });
                }
                let write_result = match (&cipher, &stream_prefix) {
                    (Some(cipher), Some(prefix)) => {
                        let ct = cipher.encrypt_chunk(prefix, chunk_index, &buf[..n]);
                        chunk_index += 1;
                        let len = (n as u32).to_le_bytes();
                        std::io::Write::write_all(&mut out, &len)
                            .and_then(|()| std::io::Write::write_all(&mut out, &ct))
                    }
                    _ => std::io::Write::write_all(&mut out, &buf[..n]),
                };
                if let Err(e) = write_result {
                    break Err(StableReadError::Io(e.to_string()));
                }
            }
            Err(e) => break Err(map_open_err(&e)),
        }
    };
    if let Err(e) = copy_result {
        let _ = std::fs::remove_file(&spool_path);
        return Err(e);
    }

    // A file that grew or shrank mid-read has mutated even if its metadata
    // happens to compare equal (e.g. coarse mtime granularity).
    if total != before.size {
        let _ = std::fs::remove_file(&spool_path);
        return Err(StableReadError::ChangedDuringRead);
    }

    // Test seam: mutate the file between read and re-stat.
    if let Some(hook) = mutation_hook {
        hook();
    }

    // Step 5: re-stat the open object and compare (spec 10.5).
    let after = identity_of(&file).map_err(|e| map_open_err(&e))?;
    if after != before {
        let _ = std::fs::remove_file(&spool_path);
        return Err(StableReadError::ChangedDuringRead);
    }

    Ok(StableReadResult {
        sha256: hex::encode(hasher.finalize()),
        size: total,
        spool_path,
    })
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    // FILE_FLAG_OPEN_REPARSE_POINT: open the reparse point itself, never
    // follow it (spec 10.5 step 2).
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn create_spool_file(path: &Path) -> Result<std::fs::File, StableReadError> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600) // spool bytes are never world/group accessible (10.3)
        .open(path)
        .map_err(|e| StableReadError::Io(e.to_string()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(f)
}

/// Windows: spool files live under the agent-owned state dir; NTFS ACLs
/// inherit from it (see run(): the dir is created by the service account).
/// Encrypted at rest (M6) regardless of filesystem ACLs.
#[cfg(not(unix))]
fn create_spool_file(path: &Path) -> Result<std::fs::File, StableReadError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| StableReadError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_hashes_stable_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.bin");
        std::fs::write(&target, b"stable content").unwrap();
        let r = stable_read(&target, spool.path(), 1 << 20, 1 << 20, 3, None, None).unwrap();
        assert_eq!(r.sha256, corpus_core::hash::sha256_hex(b"stable content"));
        assert_eq!(std::fs::read(&r.spool_path).unwrap(), b"stable content");
    }

    #[test]
    fn mutation_during_read_is_detected_and_retried_to_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let target = dir.path().join("mut.bin");
        std::fs::write(&target, b"version one of the file").unwrap();
        let t2 = target.clone();
        // Every attempt mutates: retries must exhaust to CHANGED_DURING_READ.
        let err = stable_read(
            &target,
            spool.path(),
            1 << 20,
            1 << 20,
            2,
            Some(&move || {
                // Windows filesystem timestamps have ~10-15ms granularity:
                // a content-identical rewrite inside the same tick is
                // undetectable by (size, mtime) alone. Cross the tick.
                #[cfg(windows)]
                std::thread::sleep(std::time::Duration::from_millis(30));
                std::fs::write(&t2, b"version two of the file!!").unwrap();
            }),
            None,
        )
        .unwrap_err();
        assert_eq!(err, StableReadError::ChangedDuringRead);
        // Partial spool copies must be discarded.
        assert_eq!(std::fs::read_dir(spool.path()).unwrap().count(), 0);
    }

    #[test]
    fn mutation_once_then_stable_retries_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let target = dir.path().join("mut2.bin");
        std::fs::write(&target, b"initial").unwrap();
        let mutated = std::sync::atomic::AtomicBool::new(false);
        let t2 = target.clone();
        let r = stable_read(
            &target,
            spool.path(),
            1 << 20,
            1 << 20,
            3,
            Some(&|| {
                if !mutated.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    std::fs::write(&t2, b"rewritten").unwrap();
                }
            }),
            None,
        )
        .unwrap();
        assert_eq!(r.sha256, corpus_core::hash::sha256_hex(b"rewritten"));
    }

    /// Unix-only: symlinks must be rejected, not followed. Windows
    /// equivalent (junctions/reparse points) is covered by
    /// FILE_FLAG_OPEN_REPARSE_POINT in open_nofollow; creating reparse
    /// points in a test needs privileges, so there is no Windows twin.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_rejected_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.bin");
        std::fs::write(&target, b"target bytes").unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = stable_read(&link, spool.path(), 1 << 20, 1 << 20, 3, None, None).unwrap_err();
        assert!(
            matches!(err, StableReadError::Io(_)),
            "symlink must be rejected (ELOOP -> Io), got {err:?}"
        );
        // And the spool must not contain the target's bytes via the link.
        assert_eq!(std::fs::read_dir(spool.path()).unwrap().count(), 0);
    }

    #[test]
    fn file_grown_during_read_is_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let target = dir.path().join("grow.bin");
        std::fs::write(&target, b"short").unwrap();
        let t2 = target.clone();
        let err = stable_read(
            &target,
            spool.path(),
            1 << 20,
            1 << 20,
            1,
            Some(&move || {
                std::fs::write(&t2, b"short but now much longer").unwrap();
            }),
            None,
        )
        .unwrap_err();
        assert_eq!(err, StableReadError::ChangedDuringRead);
    }

    #[test]
    fn too_large_and_missing_and_spool_full() {
        let dir = tempfile::tempdir().unwrap();
        let spool = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.bin");
        std::fs::write(&big, vec![0u8; 4096]).unwrap();
        assert!(matches!(
            stable_read(&big, spool.path(), 1024, 1 << 20, 3, None, None),
            Err(StableReadError::TooLarge { .. })
        ));
        assert!(matches!(
            stable_read(&big, spool.path(), 1 << 20, 100, 3, None, None),
            Err(StableReadError::SpoolFull)
        ));
        assert_eq!(
            stable_read(
                &dir.path().join("gone.bin"),
                spool.path(),
                1 << 20,
                1 << 20,
                3,
                None,
                None
            )
            .unwrap_err(),
            StableReadError::DeletedBeforeRead
        );
    }
}
