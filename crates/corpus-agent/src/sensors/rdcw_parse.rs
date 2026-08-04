//! Pure parsers for ReadDirectoryChangesW FILE_NOTIFY_INFORMATION buffers.
//!
//! Hardened against odd filename lengths, truncated records, and bogus
//! `NextEntryOffset` chains so a malformed buffer cannot loop forever.

/// One decoded change notification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the cfg(windows) watcher and by tests
pub struct NotifyRecord {
    /// FILE_ACTION_* value (1=added, 2=removed, 3=modified,
    /// 4=renamed_old, 5=renamed_new).
    pub action: u32,
    pub file_name: String,
}

/// Header of FILE_NOTIFY_INFORMATION: NextEntryOffset, Action,
/// FileNameLength (all u32). The variable-length FileName follows.
const HEADER_LEN: usize = 12;

/// Parse a buffer of packed FILE_NOTIFY_INFORMATION entries exactly as
/// returned by ReadDirectoryChangesW (`buf` must be limited to the
/// reported byte count). Malformed or truncated trailing records stop
/// parsing; records decoded so far are returned.
#[allow(dead_code)] // consumed by the cfg(windows) watcher and by tests
pub fn parse_notify_records(buf: &[u8]) -> Vec<NotifyRecord> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while buf.len() - offset >= HEADER_LEN {
        let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        let action = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        let name_len =
            u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap()) as usize;
        // Validate the WHOLE record against the buffer before reading the
        // filename: the name must fit after the header, and a chained
        // NextEntryOffset must cover this record and stay in bounds.
        if !name_len.is_multiple_of(2) || name_len > buf.len() - offset - HEADER_LEN {
            break;
        }
        if next != 0 && (next < HEADER_LEN + name_len || next > buf.len() - offset) {
            break;
        }
        let wide: Vec<u16> = buf[offset + HEADER_LEN..offset + HEADER_LEN + name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(NotifyRecord {
            action,
            file_name: String::from_utf16_lossy(&wide),
        });
        if next == 0 {
            break;
        }
        offset += next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one FILE_NOTIFY_INFORMATION record. `next` overrides
    /// NextEntryOffset when set; otherwise it is derived (0 for `last`,
    /// header + name otherwise).
    fn record(action: u32, name: &str, last: bool, next_override: Option<u32>) -> Vec<u8> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        let next = next_override.unwrap_or(if last {
            0
        } else {
            (HEADER_LEN + name_bytes.len()) as u32
        });
        let mut b = Vec::new();
        b.extend_from_slice(&next.to_le_bytes());
        b.extend_from_slice(&action.to_le_bytes());
        b.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        b.extend_from_slice(&name_bytes);
        b
    }

    #[test]
    fn parses_single_record() {
        let buf = record(0x1, "a.exe", true, None);
        let recs = parse_notify_records(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action, 0x1);
        assert_eq!(recs[0].file_name, "a.exe");
    }

    #[test]
    fn long_filenames_decode_fully() {
        // Regression: the old stack-copy parser read out of bounds for any
        // name longer than one UTF-16 unit.
        let long_name = "evil\\with a very long directory name\\payload-0123456789abcdef-\
                         0123456789abcdef-0123456789abcdef-0123456789abcdef-\
                         0123456789abcdef-0123456789abcdef-0123456789abcdef.exe";
        assert!(long_name.encode_utf16().count() > 128);
        let buf = record(0x5, long_name, true, None);
        let recs = parse_notify_records(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].file_name, long_name);
    }

    #[test]
    fn parses_chained_records() {
        let mut buf = record(0x1, "first.tmp", false, None);
        buf.extend(record(0x3, "second-longer-name.bin", false, None));
        buf.extend(record(0x5, "third.exe", true, None));
        let recs = parse_notify_records(&buf);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].file_name, "first.tmp");
        assert_eq!(recs[1].file_name, "second-longer-name.bin");
        assert_eq!(recs[2].file_name, "third.exe");
        assert_eq!(recs[2].action, 0x5);
    }

    #[test]
    fn truncated_record_stops_parsing() {
        // A complete record followed by a truncated one: keep the first,
        // never read past the buffer for the second.
        let mut buf = record(0x1, "ok.exe", false, None);
        let mut tail = record(
            0x3,
            "this-name-is-much-longer-than-the-bytes-kept.dll",
            true,
            None,
        );
        tail.truncate(HEADER_LEN + 8);
        buf.extend(&tail);
        let recs = parse_notify_records(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].file_name, "ok.exe");
    }

    #[test]
    fn truncated_header_yields_nothing() {
        let buf = record(0x1, "x.exe", true, None);
        assert!(parse_notify_records(&buf[..HEADER_LEN - 1]).is_empty());
        assert!(parse_notify_records(&[]).is_empty());
    }

    #[test]
    fn bogus_next_entry_offset_is_rejected() {
        // NextEntryOffset smaller than the record itself (would loop or
        // misalign) and one pointing out of bounds both stop parsing.
        let buf = record(0x1, "loop.exe", false, Some(4));
        assert!(parse_notify_records(&buf).is_empty());
        let buf = record(0x1, "oob.exe", false, Some(64 * 1024));
        assert!(parse_notify_records(&buf).is_empty());
    }

    #[test]
    fn odd_filename_length_is_rejected() {
        let mut buf = record(0x1, "ab", true, None);
        // FileNameLength is a byte count and must be even (UTF-16).
        buf[8..12].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse_notify_records(&buf).is_empty());
    }
}
