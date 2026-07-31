//! Alternate data stream (ADS) awareness at the enumeration/metadata
//! level (spec 10.10 Windows). Streams other than the default `::$DATA`
//! are recorded as capture metadata; content collection of ADS is
//! policy-controlled and not in M2 scope.

#![cfg(target_os = "windows")]

use std::path::Path;

/// List non-default ADS names for a file (empty for plain files).
pub fn list_ads(path: &Path) -> Vec<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstStreamW, FindNextStreamW, WIN32_FIND_STREAM_DATA,
    };

    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    let handle = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            0,
            &mut data as *mut _ as *mut core::ffi::c_void,
            0,
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE || handle.is_null() {
        return Vec::new();
    }
    let mut names = Vec::new();
    loop {
        let name = {
            let raw = &data.cStreamName;
            let len = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
            String::from_utf16_lossy(&raw[..len])
        };
        // Skip the default stream (":$DATA" on the unnamed stream).
        if !name.is_empty() && !name.starts_with("::$DATA") {
            names.push(name);
        }
        if unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut core::ffi::c_void) } == 0 {
            break;
        }
    }
    unsafe { CloseHandle(handle) };
    names
}
