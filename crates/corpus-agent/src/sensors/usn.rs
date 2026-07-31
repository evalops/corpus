//! USN change journal support (spec 10.10 Windows): downtime recovery
//! via FSCTL_READ_JOURNAL where privileges allow. The record parser, the
//! journal-info parser, and the cursor/resume decision logic are
//! platform-free and unit-tested; the readers are Windows-only and degrade
//! gracefully to the poll sensor without volume access.
//!
//! Cursor continuity (M9 review fix): FSCTL_READ_JOURNAL requires the
//! UsnJournalId of the CURRENT journal instance (queried via
//! FSCTL_QUERY_USN_JOURNAL), and the agent persists (journal_id,
//! next_usn) in its SQLite state so a restart resumes where it stopped
//! instead of re-reading from USN 0. Journal recreation (ID mismatch) or
//! a cursor older than the journal's first available record (truncation)
//! means continuity is lost: a full reconciliation is forced.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(dead_code)] // consumed by the cfg(windows) reader and by tests
pub struct UsnRecord {
    pub usn: i64,
    pub file_reference: u64,
    pub parent_reference: u64,
    pub reason: u32,
    pub file_name: String,
}

/// Identity of the current journal instance (fields of
/// USN_JOURNAL_DATA_V0 that the cursor logic needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the cfg(windows) reader and by tests
pub struct JournalInfo {
    pub journal_id: u64,
    /// Oldest USN still readable from the journal.
    pub first_usn: i64,
    /// USN that will be assigned to the next record.
    pub next_usn: i64,
}

/// Parse a USN_JOURNAL_DATA_V0 buffer as returned by
/// FSCTL_QUERY_USN_JOURNAL (needs the first 24 bytes; V1 appends fields
/// this code does not use).
#[allow(dead_code)] // consumed by the cfg(windows) reader and by tests
pub fn parse_journal_data(buf: &[u8]) -> Option<JournalInfo> {
    if buf.len() < 24 {
        return None;
    }
    Some(JournalInfo {
        journal_id: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        first_usn: i64::from_le_bytes(buf[8..16].try_into().unwrap()),
        next_usn: i64::from_le_bytes(buf[16..24].try_into().unwrap()),
    })
}

/// What to do at startup given a persisted cursor and the live journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the cfg(windows) reader and by tests
pub enum ResumePlan {
    /// No persisted cursor: record the current position. The baseline
    /// pass covers history, so there is nothing to resume.
    Initialize { journal_id: u64, next_usn: i64 },
    /// Cursor is continuous with the live journal: read forward from it.
    Resume { journal_id: u64, start_usn: i64 },
    /// Continuity lost (journal recreated or cursor truncated away):
    /// force a full reconciliation and re-anchor the cursor.
    Reconcile { journal_id: u64, next_usn: i64 },
}

/// Decide how to resume from a persisted `(journal_id, next_usn)` cursor
/// against the live journal identity.
#[allow(dead_code)] // consumed by the cfg(windows) reader and by tests
pub fn plan_resume(cursor: Option<(u64, i64)>, journal: &JournalInfo) -> ResumePlan {
    match cursor {
        None => ResumePlan::Initialize {
            journal_id: journal.journal_id,
            next_usn: journal.next_usn,
        },
        Some((id, usn))
            if id == journal.journal_id && usn >= journal.first_usn && usn <= journal.next_usn =>
        {
            ResumePlan::Resume {
                journal_id: id,
                start_usn: usn,
            }
        }
        Some(_) => ResumePlan::Reconcile {
            journal_id: journal.journal_id,
            next_usn: journal.next_usn,
        },
    }
}

/// Parse a buffer of packed USN_RECORD_V2 entries as returned by
/// FSCTL_READ_JOURNAL (after the 8-byte leading USN).
#[allow(dead_code)] // consumed by the cfg(windows) reader and by tests
pub fn parse_usn_records(buf: &[u8]) -> Vec<UsnRecord> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 60 <= buf.len() {
        let record_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        if record_len < 60 || offset + record_len > buf.len() {
            break;
        }
        let major = u16::from_le_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
        if major != 2 {
            break;
        }
        let file_reference = u64::from_le_bytes(buf[offset + 8..offset + 16].try_into().unwrap());
        let parent_reference =
            u64::from_le_bytes(buf[offset + 16..offset + 24].try_into().unwrap());
        let usn = i64::from_le_bytes(buf[offset + 24..offset + 32].try_into().unwrap());
        let reason = u32::from_le_bytes(buf[offset + 40..offset + 44].try_into().unwrap());
        let name_len =
            u16::from_le_bytes(buf[offset + 56..offset + 58].try_into().unwrap()) as usize;
        let name_off =
            u16::from_le_bytes(buf[offset + 58..offset + 60].try_into().unwrap()) as usize;
        if name_off + name_len <= record_len {
            let wide: Vec<u16> = buf[offset + name_off..offset + name_off + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push(UsnRecord {
                usn,
                file_reference,
                parent_reference,
                reason,
                file_name: String::from_utf16_lossy(&wide),
            });
        }
        offset += record_len;
    }
    out
}

/// Drive letter (no colon) of the volume hosting `root`; used as the
/// cursor key so multiple roots on one volume share one cursor.
#[cfg(target_os = "windows")]
fn volume_letter(root: &std::path::Path) -> String {
    root.components()
        .next()
        .map(|c| {
            c.as_os_str()
                .to_string_lossy()
                .trim_end_matches(':')
                .to_string()
        })
        .unwrap_or_else(|| "C".into())
}

#[cfg(target_os = "windows")]
fn open_volume(root: &std::path::Path) -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

    let volume = format!("\\\\.\\{}:", volume_letter(root));
    let wide: Vec<u16> = volume.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0x8000_0000, /* GENERIC_READ */
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            windows_sys::Win32::Foundation::HANDLE::default(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        tracing::warn!(
            volume,
            error = %std::io::Error::last_os_error(),
            "USN journal unavailable without admin; poll sensor covers recovery"
        );
        return None;
    }
    Some(handle)
}

/// Query the current journal identity (FSCTL_QUERY_USN_JOURNAL). Returns
/// None without volume read access; the poll sensor covers recovery.
#[cfg(target_os = "windows")]
pub fn query_journal(root: &std::path::Path) -> Option<JournalInfo> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // windows-sys 0.60 does not expose the USN journal IOCTLs; define the
    // documented constants (MSDN: winioctl.h).
    const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00B0;

    let handle = open_volume(root)?;
    // USN_JOURNAL_DATA_V0 is 56 bytes; V1 is larger. Size for V1 and parse
    // the V0 prefix so either succeeds.
    let mut out = vec![0u8; 128];
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            out.as_mut_ptr() as *mut _,
            out.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "FSCTL_QUERY_USN_JOURNAL failed; poll sensor covers recovery");
        return None;
    }
    parse_journal_data(&out[..returned as usize])
}

/// Read journal records for the volume hosting `root`, starting at
/// `start_usn` and matching the CURRENT `journal_id` (per the Microsoft
/// contract the read fails for any other instance). Returns the USN to
/// resume from plus the records; None on failure (poll sensor covers).
#[cfg(target_os = "windows")]
pub fn read_journal(
    root: &std::path::Path,
    journal_id: u64,
    start_usn: i64,
) -> Option<(i64, Vec<UsnRecord>)> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_READ_JOURNAL: u32 = 0x0009_00BB;
    // Bound the recovery read: the records only prove "something changed",
    // they are not enumerated individually.
    const MAX_PAGES: usize = 32;
    #[repr(C)]
    struct ReadJournalDataV0 {
        start_usn: i64,
        reason_mask: u32,
        return_only_on_close: u32,
        timeout: u64,
        bytes_to_read: u64,
        usn_journal_id: u64,
    }

    let handle = open_volume(root)?;
    let mut records = Vec::new();
    let mut next_usn = start_usn;
    for _ in 0..MAX_PAGES {
        let input = ReadJournalDataV0 {
            start_usn: next_usn,
            reason_mask: 0xffff_ffff,
            return_only_on_close: 0,
            timeout: 0,
            bytes_to_read: 64 * 1024,
            usn_journal_id: journal_id,
        };
        let mut out = vec![0u8; 64 * 1024 + 8];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_READ_JOURNAL,
                &input as *const _ as *const _,
                std::mem::size_of_val(&input) as u32,
                out.as_mut_ptr() as *mut _,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "FSCTL_READ_JOURNAL failed; poll sensor covers recovery");
            unsafe { CloseHandle(handle) };
            return None;
        }
        // First 8 bytes: the next USN. Records follow.
        if (returned as usize) <= 8 {
            break;
        }
        next_usn = i64::from_le_bytes(out[0..8].try_into().unwrap());
        let page = parse_usn_records(&out[8..returned as usize]);
        if page.is_empty() {
            break;
        }
        records.extend(page);
    }
    unsafe { CloseHandle(handle) };
    Some((next_usn, records))
}

/// Startup recovery decision for one watched root.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowntimeStatus {
    /// Journal not readable (privileges); poll sensor covers recovery.
    Unavailable,
    /// Cursor is continuous and nothing changed while we were down.
    NoChanges,
    /// Records exist since the cursor; a reconciliation pass was enqueued.
    Changes,
    /// Continuity lost (journal recreated or cursor truncated); a full
    /// reconciliation is mandatory and the cursor was re-anchored.
    ReconcileRequired,
}

/// Check the USN journal for downtime changes on the volume hosting
/// `root`, persisting the (journal_id, next_usn) cursor in the agent's
/// SQLite state so restarts resume instead of re-reading from USN 0.
#[cfg(target_os = "windows")]
pub fn check_downtime_changes(
    db: &crate::state::StateDb,
    root: &std::path::Path,
) -> DowntimeStatus {
    let Some(info) = query_journal(root) else {
        return DowntimeStatus::Unavailable;
    };
    let volume = volume_letter(root);
    let cursor = db.get_usn_cursor(&volume).ok().flatten();
    match plan_resume(cursor, &info) {
        ResumePlan::Initialize {
            journal_id,
            next_usn,
        } => {
            if let Err(e) = db.set_usn_cursor(&volume, journal_id, next_usn) {
                tracing::warn!(error = %e, "failed to persist USN cursor");
            }
            DowntimeStatus::NoChanges
        }
        ResumePlan::Resume {
            journal_id,
            start_usn,
        } => {
            if start_usn >= info.next_usn {
                return DowntimeStatus::NoChanges;
            }
            match read_journal(root, journal_id, start_usn) {
                Some((next_usn, records)) => {
                    if let Err(e) = db.set_usn_cursor(&volume, journal_id, next_usn) {
                        tracing::warn!(error = %e, "failed to persist USN cursor");
                    }
                    if records.is_empty() {
                        DowntimeStatus::NoChanges
                    } else {
                        tracing::info!(
                            records = records.len(),
                            "USN journal shows changes since last run"
                        );
                        DowntimeStatus::Changes
                    }
                }
                None => DowntimeStatus::Unavailable,
            }
        }
        ResumePlan::Reconcile {
            journal_id,
            next_usn,
        } => {
            tracing::warn!(
                volume,
                "USN journal recreated or cursor truncated; forcing full reconciliation"
            );
            if let Err(e) = db.set_usn_cursor(&volume, journal_id, next_usn) {
                tracing::warn!(error = %e, "failed to persist USN cursor");
            }
            DowntimeStatus::ReconcileRequired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usn_record(usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        let len = 60 + name_bytes.len();
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes()); // major v2
        b[8..16].copy_from_slice(&0xAAu64.to_le_bytes());
        b[16..24].copy_from_slice(&0xBBu64.to_le_bytes());
        b[24..32].copy_from_slice(&usn.to_le_bytes());
        b[40..44].copy_from_slice(&reason.to_le_bytes());
        b[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        b[58..60].copy_from_slice(&60u16.to_le_bytes());
        b[60..].copy_from_slice(&name_bytes);
        b
    }

    #[test]
    fn parses_packed_usn_records() {
        let mut buf = Vec::new();
        buf.extend(usn_record(100, 0x8000_0100, "evil.exe"));
        buf.extend(usn_record(101, 0x0000_0004, "notes.txt"));
        let records = parse_usn_records(&buf);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].usn, 100);
        assert_eq!(records[0].file_name, "evil.exe");
        assert_eq!(records[0].file_reference, 0xAA);
        assert_eq!(records[1].reason, 0x0000_0004);
    }

    #[test]
    fn truncated_buffer_yields_what_it_can() {
        let mut buf = usn_record(1, 0, "a.exe");
        buf.truncate(buf.len() - 3);
        assert!(parse_usn_records(&buf).is_empty());
        assert!(parse_usn_records(&[]).is_empty());
    }

    // ---- journal identity parsing (mocked FSCTL_QUERY_USN_JOURNAL data) ----

    fn journal_data(journal_id: u64, first_usn: i64, next_usn: i64) -> Vec<u8> {
        let mut b = vec![0u8; 56];
        b[0..8].copy_from_slice(&journal_id.to_le_bytes());
        b[8..16].copy_from_slice(&first_usn.to_le_bytes());
        b[16..24].copy_from_slice(&next_usn.to_le_bytes());
        b
    }

    #[test]
    fn parses_journal_data_v0() {
        let info = parse_journal_data(&journal_data(0xDEAD, 1000, 5000)).unwrap();
        assert_eq!(info.journal_id, 0xDEAD);
        assert_eq!(info.first_usn, 1000);
        assert_eq!(info.next_usn, 5000);
        assert!(parse_journal_data(&journal_data(1, 2, 3)[..23]).is_none());
        assert!(parse_journal_data(&[]).is_none());
    }

    // ---- cursor resume decisions (mocked journal records) ----

    fn live_journal() -> JournalInfo {
        JournalInfo {
            journal_id: 42,
            first_usn: 1000,
            next_usn: 5000,
        }
    }

    #[test]
    fn no_cursor_initializes_at_current_position() {
        let plan = plan_resume(None, &live_journal());
        assert_eq!(
            plan,
            ResumePlan::Initialize {
                journal_id: 42,
                next_usn: 5000
            }
        );
    }

    #[test]
    fn matching_cursor_resumes_from_it() {
        let plan = plan_resume(Some((42, 3000)), &live_journal());
        assert_eq!(
            plan,
            ResumePlan::Resume {
                journal_id: 42,
                start_usn: 3000
            }
        );
        // A cursor exactly at the head is still continuous (nothing new).
        let plan = plan_resume(Some((42, 5000)), &live_journal());
        assert!(matches!(
            plan,
            ResumePlan::Resume {
                start_usn: 5000,
                ..
            }
        ));
        // A cursor exactly at the first available record is continuous.
        let plan = plan_resume(Some((42, 1000)), &live_journal());
        assert!(matches!(
            plan,
            ResumePlan::Resume {
                start_usn: 1000,
                ..
            }
        ));
    }

    #[test]
    fn journal_id_mismatch_forces_reconciliation() {
        // Journal was deleted/recreated while the agent was down: the
        // persisted ID no longer matches the live instance.
        let plan = plan_resume(Some((7, 3000)), &live_journal());
        assert_eq!(
            plan,
            ResumePlan::Reconcile {
                journal_id: 42,
                next_usn: 5000
            }
        );
    }

    #[test]
    fn truncated_cursor_forces_reconciliation() {
        // Cursor predates the oldest record still in the journal (the
        // journal wrapped or was trimmed past it).
        let plan = plan_resume(Some((42, 500)), &live_journal());
        assert!(matches!(plan, ResumePlan::Reconcile { .. }));
        // A cursor past the journal head is corrupt; also reconcile.
        let plan = plan_resume(Some((42, 9000)), &live_journal());
        assert!(matches!(plan, ResumePlan::Reconcile { .. }));
    }

    #[test]
    fn cursor_persists_across_state_db_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::state::StateDb::open(&dir.path().join("s.db")).unwrap();
        assert_eq!(db.get_usn_cursor("C").unwrap(), None);
        db.set_usn_cursor("C", 42, 3000).unwrap();
        assert_eq!(db.get_usn_cursor("C").unwrap(), Some((42, 3000)));
        db.set_usn_cursor("C", 42, 4500).unwrap();
        drop(db);
        let db = crate::state::StateDb::open(&dir.path().join("s.db")).unwrap();
        assert_eq!(db.get_usn_cursor("C").unwrap(), Some((42, 4500)));
        // Distinct volumes hold distinct cursors.
        assert_eq!(db.get_usn_cursor("D").unwrap(), None);
    }
}
