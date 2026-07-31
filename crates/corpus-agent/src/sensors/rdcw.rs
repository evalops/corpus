//! Windows user-mode sensor (spec 10.10 Windows, M2 "user-mode fallback
//! first"). Coverage gaps versus the future signed minifilter are
//! documented in the README; the short version:
//!
//! - ReadDirectoryChangesW for close-write/rename-create events
//!   (recursive watch on configured roots).
//! - USN change journal for downtime recovery where privileges allow
//!   (FSCTL_READ_JOURNAL requires volume read access; degrades to the
//!   periodic reconciliation scanner without admin).
//! - Process execution observation is NOT implemented in user mode:
//!   Win32_ProcessStartTrace requires admin + COM/WMI plumbing; that
//!   gap is documented and exec-priority candidates fall back to
//!   write-priority.

#![cfg(target_os = "windows")]

use crate::state::{priority, StateDb};
use std::path::PathBuf;
use std::sync::Arc;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const ACTION_NAMES: &[(u32, &str)] = &[
    (0x1, "added"),
    (0x2, "removed"),
    (0x3, "modified"),
    (0x4, "renamed_old"),
    (0x5, "renamed_new"),
];

/// Watch one root synchronously; intended to run on a dedicated thread.
pub fn watch_root(db: Arc<StateDb>, root: PathBuf, exclusions: Vec<String>, debounce_ms: u64) {
    let wide = to_wide(&root.to_string_lossy());
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            HANDLE::default(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        tracing::warn!(
            root = %root.display(),
            error = %std::io::Error::last_os_error(),
            "ReadDirectoryChangesW: cannot open watch root; poll sensor covers it"
        );
        return;
    }
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut returned: u32 = 0;
        let ok = unsafe {
            ReadDirectoryChangesW(
                handle,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                1, // recursive
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if ok == 0 {
            // ERROR_NOTIFY_ENUM_DIR (overflow) or handle failure. Overflow
            // must be a coverage gap, never a silent miss (spec 2.2).
            let err = std::io::Error::last_os_error();
            let _ = db.record_gap("rdcw", "SENSOR_OVERFLOW", None, None, Some("NOTIFY_ENUM_DIR"), &format!("{{\"error\":\"{err}\"}}"));
            let _ = db.increment_counter("SENSOR_OVERFLOW");
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }
        let mut offset = 0usize;
        loop {
            let info = unsafe { (buf.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION).read_unaligned() };
            let name_len = info.FileNameLength as usize / 2;
            let name = String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(info.FileName.as_ptr(), name_len)
            });
            let action = info.Action;
            let action_name = ACTION_NAMES.iter().find(|(a, _)| *a == action).map(|(_, n)| *n).unwrap_or("unknown");
            // Renames/creates/writes are priority-2 candidates (spec 10.8).
            let path = root.join(&name);
            let s = path.to_string_lossy();
            if action != 0x2 /* removed: nothing to capture */ && !crate::config::matches_exclusion(&exclusions, &s) {
                if let Err(e) = db.enqueue(&s, priority::WRITTEN_OR_RENAMED, action_name, debounce_ms) {
                    tracing::warn!(error = %e, path = %s, "failed to enqueue RDCW candidate");
                }
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset += info.NextEntryOffset as usize;
        }
    }
}

/// Spawn one watcher thread per root (RDCW is per-directory-handle).
pub fn start(db: Arc<StateDb>, roots: &[PathBuf], exclusions: Vec<String>, debounce_ms: u64) {
    for root in roots {
        let db = db.clone();
        let root = root.clone();
        let exclusions = exclusions.clone();
        std::thread::Builder::new()
            .name(format!("rdcw-{}", root.display()))
            .spawn(move || watch_root(db, root, exclusions, debounce_ms))
            .expect("spawn rdcw watcher");
    }
    tracing::info!(roots = roots.len(), "ReadDirectoryChangesW sensor active");
}
