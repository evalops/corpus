//! Windows DPAPI helpers for spool key protection.
//!
//! Wraps machine/user-scoped DPAPI so spool encryption keys are not
//! stored as plaintext on disk. Compiled only on `target_os = "windows"`.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use std::path::Path;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

#[allow(clippy::unnecessary_mut_passed)] // FFI: the signature requires *mut CRYPT_INTEGER_BLOB
fn protect(data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        if CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut output,
        ) == 0
        {
            anyhow::bail!(
                "CryptProtectData failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = windows_sys::Win32::Foundation::LocalFree(output.pbData as _);
        Ok(out)
    }
}

#[allow(clippy::unnecessary_mut_passed)] // FFI: the signature requires *mut CRYPT_INTEGER_BLOB
fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        if CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut output,
        ) == 0
        {
            anyhow::bail!(
                "CryptUnprotectData failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = windows_sys::Win32::Foundation::LocalFree(output.pbData as _);
        Ok(out)
    }
}

#[allow(dead_code)] // exercised by the DPAPI roundtrip test
pub fn protect_key_bytes(data: &[u8]) -> Result<Vec<u8>> {
    protect(data)
}

#[allow(dead_code)] // exercised by the DPAPI roundtrip test
pub fn unprotect_key_bytes(data: &[u8]) -> Result<Vec<u8>> {
    unprotect(data)
}

pub fn load_or_create_key(state_dir: &Path) -> Result<[u8; 32]> {
    let path = state_dir.join("spool.key.dpapi");
    if let Ok(blob) = std::fs::read(&path) {
        let raw = unprotect(&blob).context("unwrapping spool key")?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt wrapped spool key"))?;
        return Ok(key);
    }
    let key = crate::spool_crypto::random_key_material();
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(&path, protect(&key)?)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dpapi_roundtrip() {
        let data = [42u8; 32];
        let blob = super::protect_key_bytes(&data).unwrap();
        assert_ne!(blob.as_slice(), &data);
        assert_eq!(super::unprotect_key_bytes(&blob).unwrap(), data);
    }
}
