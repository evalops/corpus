//! USN change journal support (spec 10.10 Windows): downtime recovery
//! via FSCTL_READ_JOURNAL where privileges allow. The record parser is
//! platform-free and unit-tested; the reader is Windows-only and degrades
//! gracefully to the poll sensor without volume access.

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
        let parent_reference = u64::from_le_bytes(buf[offset + 16..offset + 24].try_into().unwrap());
        let usn = i64::from_le_bytes(buf[offset + 24..offset + 32].try_into().unwrap());
        let reason = u32::from_le_bytes(buf[offset + 40..offset + 44].try_into().unwrap());
        let name_len = u16::from_le_bytes(buf[offset + 56..offset + 58].try_into().unwrap()) as usize;
        let name_off = u16::from_le_bytes(buf[offset + 58..offset + 60].try_into().unwrap()) as usize;
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

/// Read the USN journal of the volume hosting `root`, starting after
/// `start_usn`. Requires volume read access (admin or SE_MANAGE_VOLUME);
/// on failure returns an empty vec and the poll sensor covers recovery.
#[cfg(target_os = "windows")]
pub fn read_journal(root: &std::path::Path, start_usn: i64) -> Vec<UsnRecord> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // windows-sys 0.60 does not expose the USN journal IOCTLs; define the
    // documented constants/structs (MSDN: winioctl.h, FSCTL_READ_JOURNAL).
    const FSCTL_READ_JOURNAL: u32 = 0x0009_00BB;
    #[repr(C)]
    struct ReadJournalDataV0 {
        start_usn: i64,
        reason_mask: u32,
        return_only_on_close: u32,
        timeout: u64,
        bytes_to_read: u64,
        usn_journal_id: u64,
    }

    let volume = format!(
        "\\\\.\\{}:",
        root.components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().trim_end_matches(':').to_string())
            .unwrap_or_else(|| "C".into())
    );
    let wide: Vec<u16> = volume.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(wide.as_ptr(), 0x8000_0000 /* GENERIC_READ */, 0, std::ptr::null(), OPEN_EXISTING, 0, windows_sys::Win32::Foundation::HANDLE::default())
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        tracing::warn!(
            volume,
            error = %std::io::Error::last_os_error(),
            "USN journal unavailable without admin; poll sensor covers recovery"
        );
        return Vec::new();
    }
    let mut input = ReadJournalDataV0 {
        start_usn,
        reason_mask: 0xffff_ffff,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_read: 64 * 1024,
        usn_journal_id: 0,
    };
    let mut out = vec![0u8; 64 * 1024 + 8];
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_READ_JOURNAL,
            &mut input as *mut _ as *mut _,
            std::mem::size_of_val(&input) as u32,
            out.as_mut_ptr() as *mut _,
            out.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "FSCTL_READ_JOURNAL failed; poll sensor covers recovery");
        return Vec::new();
    }
    // First 8 bytes: the next USN. Records follow.
    if (returned as usize) <= 8 {
        return Vec::new();
    }
    parse_usn_records(&out[8..returned as usize])
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
}
