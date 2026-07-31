//! Cross-platform file identity (spec 10.5 step 1): the OS-stable
//! identity of a file for mutation detection during stable reads.
//!
//! Unix: (dev, inode, size, mtime, ctime). Windows: (volume serial
//! number, file index, size, mtime) via GetFileInformationByHandle,
//! surfaced by std::os::windows::fs::MetadataExt. Windows has no ctime
//! analog, so it is zeroed there.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileKey {
    pub volume: u64,
    pub index: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

#[cfg(unix)]
pub fn file_key(md: &std::fs::Metadata) -> FileKey {
    use std::os::unix::fs::MetadataExt;
    FileKey {
        volume: md.dev(),
        index: md.ino(),
        size: md.size(),
        mtime_ns: md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128,
        ctime_ns: md.ctime() as i128 * 1_000_000_000 + md.ctime_nsec() as i128,
    }
}

/// Stable identity from an open handle (stable-read path has one).
#[cfg(windows)]
pub fn key_for_file(file: &std::fs::File) -> std::io::Result<FileKey> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    let md = file.metadata()?;
    Ok(FileKey {
        volume: info.dwVolumeSerialNumber as u64,
        index,
        size: md.len(),
        mtime_ns: md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0),
        ctime_ns: 0, // no ctime analog on Windows
    })
}

#[cfg(not(any(unix, windows)))]
pub fn file_key(md: &std::fs::Metadata) -> FileKey {
    FileKey {
        volume: 0,
        index: 0,
        size: md.len(),
        mtime_ns: md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0),
        ctime_ns: 0,
    }
}


/// Cheap identity for snapshot-diff scans (reconcile/poll). Unix: full
/// (dev, inode, size, mtime). Elsewhere: (0, 0, size, mtime) — a rewrite
/// always bumps mtime, which is what the diff relies on.
pub fn scan_key(md: &std::fs::Metadata) -> FileKey {
    #[cfg(unix)]
    {
        file_key(md)
    }
    #[cfg(not(unix))]
    {
        FileKey {
            volume: 0,
            index: 0,
            size: md.len(),
            mtime_ns: md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i128)
                .unwrap_or(0),
            ctime_ns: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_changes_on_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"one").unwrap();
        let k1 = scan_key(&std::fs::metadata(&path).unwrap());
        std::fs::write(&path, b"two-longer").unwrap();
        let k2 = scan_key(&std::fs::metadata(&path).unwrap());
        assert_ne!(k1.size, k2.size);
        #[cfg(unix)]
        assert_eq!(k1.index, k2.index, "same inode on plain rewrite");
    }

    /// Windows-only: GetFileInformationByHandle gives volume + file index.
    #[cfg(windows)]
    #[test]
    fn handle_identity_windows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.bin");
        std::fs::write(&path, b"x").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let k = key_for_file(&f).unwrap();
        assert_ne!(k.volume, 0);
        assert_ne!(k.index, 0);
    }
}
