//! Settings-password hashing with Argon2.
//!
//! The password gate raises friction against pre-emptively weakening blocks
//! (deleting/editing them while nothing is active). It is not a defence
//! against a root adversary — root can edit the state file directly. We still
//! hash with Argon2 (memory-hard, salted) so the stored value never reveals
//! the password, and store the PHC string in the HMAC-protected state file.

use anyhow::anyhow;
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Hash a plaintext password into a PHC string (`$argon2id$...`).
pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))?
        .to_string();
    Ok(phc)
}

/// Verify a plaintext password against a stored PHC string. Returns `false`
/// on any parse/verify failure rather than erroring, so callers treat a
/// corrupt hash as "wrong password".
pub fn verify(password: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "stored password hash is unparseable");
            return false;
        }
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let phc = hash("correct horse").unwrap();
        assert!(verify("correct horse", &phc));
        assert!(!verify("Tr0ub4dor", &phc));
        assert!(!verify("", &phc));
    }

    #[test]
    fn rejects_garbage_hash() {
        assert!(!verify("anything", "not-a-phc-string"));
    }
}
