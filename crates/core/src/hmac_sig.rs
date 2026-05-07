//! HMAC-SHA256 over arbitrary bytes, with constant-time verify.
//!
//! Used to detect hand-edits to the persisted state file. The key lives in
//! /etc/frostbite/secret (mode 0600, root) and is generated once at install.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn sign(payload: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

pub fn verify(payload: &[u8], key: &[u8], expected: &[u8]) -> bool {
    if expected.len() != 32 {
        return false;
    }
    let actual = sign(payload, key);
    actual.ct_eq(expected).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = b"some-secret-key";
        let mac = sign(b"hello", key);
        assert!(verify(b"hello", key, &mac));
        assert!(!verify(b"hellp", key, &mac));
        assert!(!verify(b"hello", b"wrong-key", &mac));
    }

    #[test]
    fn rejects_wrong_length() {
        let key = b"k";
        assert!(!verify(b"x", key, &[0u8; 31]));
        assert!(!verify(b"x", key, &[0u8; 33]));
    }
}
