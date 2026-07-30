use sha2::{Digest, Sha256};

/// SHA-256 is the authoritative artifact identity (spec section 3).
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_raw(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

pub fn hex_to_raw(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

/// Core invariant #1: the server recomputes SHA-256 from the uploaded bytes.
/// The client-supplied hash is only a hint; a mismatch rejects the commit.
pub fn verify_upload(bytes: &[u8], announced_sha256_hex: &str) -> crate::error::Result<Vec<u8>> {
    let recomputed = sha256_hex(bytes);
    if recomputed.eq_ignore_ascii_case(announced_sha256_hex) {
        Ok(sha256_raw(bytes))
    } else {
        Err(crate::error::Error::HashMismatch {
            announced: announced_sha256_hex.to_string(),
            recomputed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recompute_matches_announced() {
        let bytes = b"hello corpus";
        let hint = sha256_hex(bytes);
        let raw = verify_upload(bytes, &hint).expect("matching hash must verify");
        assert_eq!(hex::encode(&raw), hint);
    }

    #[test]
    fn mismatch_is_rejected() {
        let bytes = b"actual bytes on the wire";
        let wrong_hint = sha256_hex(b"attacker-claimed bytes");
        let err = verify_upload(bytes, &wrong_hint).unwrap_err();
        match err {
            crate::error::Error::HashMismatch { announced, recomputed } => {
                assert_eq!(announced, wrong_hint);
                assert_eq!(recomputed, sha256_hex(bytes));
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn empty_bytes_verify() {
        let hint = sha256_hex(b"");
        assert!(verify_upload(b"", &hint).is_ok());
    }
}
