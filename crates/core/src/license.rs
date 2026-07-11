//! License token verification — the desktop half of the signing contract in
//! `grepfocus-web/lib/license.ts`.
//!
//! # Token format (FROZEN)
//!
//! ```text
//! token = base64url(claimsJSON) + "." + base64url(signature)
//! ```
//!
//! * Both segments are base64url **without padding** (Node `Buffer`'s
//!   `"base64url"` encoding). Padded input is rejected: the store never
//!   emits `=`.
//! * `signature` is a raw 64-byte Ed25519 signature over the **ASCII bytes
//!   of the first segment exactly as received**, JWT-style.
//! * The matching public key is the raw 32-byte Ed25519 key, embedded as
//!   base64url-no-pad in [`LICENSE_PUBKEY_B64URL`].
//!
//! # The one trap: the signed message is opaque bytes
//!
//! The signature covers the base64url payload string *as it arrived*, NOT
//! the JSON it decodes to. Never decode the claims, re-serialize them, and
//! verify over that: JSON serialization is not canonical (key order, escape
//! choices, number formatting all vary between serializers), so re-encoded
//! bytes will not match what was signed and every legitimate license would
//! be rejected — or a decode/encode quirk could let two different payloads
//! share one signature. Verification here runs over
//! `payload_segment.as_bytes()` and only *after* the signature checks out do
//! we look inside the payload.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The embedded license public key: raw 32-byte Ed25519 key, base64url
/// without padding.
///
/// Set at the keypair ceremony (2026-07-11, re-run same day after the first
/// private key leaked into tooling transcripts pre-sales and was burned)
/// from the `PUBLIC_KEY_BASE64URL` value printed by
/// `grepfocus-web/scripts/gen-keypair.ts` (the JWK `x` component of the
/// signing key). The private half lives only in the store's
/// `LICENSE_SIGNING_KEY` env (vaulted). NEVER regenerate the keypair once
/// licenses have been sold: rotating this key invalidates every one of them.
pub const LICENSE_PUBKEY_B64URL: &str = "irtPSr-CCq0JSd0UV_2RncGhBm6OUsJTBWWp0PjCu8o";

/// Claims carried inside a license token.
///
/// Field names are FROZEN: they deserialize verbatim from the JSON minted by
/// `grepfocus-web/lib/license.ts`.
///
/// Deserialization is deliberately permissive — no `deny_unknown_fields` —
/// because the web side may add new claims later and already-shipped app
/// builds must keep accepting those tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Stable license id (also the lookup key for online validation).
    pub license_id: String,
    pub email: String,
    /// Currently always `"premium"`. Kept as a string for forward
    /// compatibility; gate features on the value, don't assume it.
    pub tier: String,
    /// Currently `"perpetual"` or `"trial"`.
    pub kind: String,
    /// Feature keys this license grants — see [`features`].
    pub features: Vec<String>,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds, or `None` for perpetual licenses.
    pub expires_at: Option<i64>,
    pub max_devices: u32,
}

/// Why a license token was rejected. `Display` output is shown verbatim in
/// the GUI, so keep the messages human-readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseError {
    /// The token (or the public key) is structurally invalid.
    Malformed(&'static str),
    /// Structurally fine, but the Ed25519 signature does not verify.
    BadSignature,
    /// Signature is valid but `expires_at` is in the past.
    Expired,
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseError::Malformed(why) => write!(f, "license key is malformed ({why})"),
            LicenseError::BadSignature => write!(f, "license signature is invalid"),
            LicenseError::Expired => write!(f, "license has expired"),
        }
    }
}

impl std::error::Error for LicenseError {}

/// Verify `token` against the embedded [`LICENSE_PUBKEY_B64URL`] at time
/// `now` (unix seconds). See [`verify_token_with_key`].
pub fn verify_token(token: &str, now: i64) -> Result<LicenseClaims, LicenseError> {
    verify_token_with_key(LICENSE_PUBKEY_B64URL, token, now)
}

/// Verify `token` against `pubkey_b64url` (raw 32-byte Ed25519 key,
/// base64url no-pad) at time `now` (unix seconds), returning its claims.
///
/// Order of checks: structure → signature → claims JSON → expiry. The
/// signature is verified over the received ASCII of the payload segment
/// (see the module docs), so *any* payload tampering surfaces as
/// [`LicenseError::BadSignature`], never as a JSON error.
pub fn verify_token_with_key(
    pubkey_b64url: &str,
    token: &str,
    now: i64,
) -> Result<LicenseClaims, LicenseError> {
    if pubkey_b64url.is_empty() {
        return Err(LicenseError::Malformed("no public key embedded"));
    }

    // Exactly two non-empty dot-separated segments.
    let (payload_b64, sig_b64) = match token.split('.').collect::<Vec<_>>().as_slice() {
        [payload, sig] => (*payload, *sig),
        _ => {
            return Err(LicenseError::Malformed(
                "expected exactly two dot-separated segments",
            ))
        }
    };
    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(LicenseError::Malformed("empty segment"));
    }

    // The web side emits base64url WITHOUT padding, so URL_SAFE_NO_PAD is
    // load-bearing: padded input ("...=") must fail, it is not something the
    // store ever issued.
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| LicenseError::Malformed("signature segment is not valid base64url"))?
        .try_into()
        .map_err(|_| LicenseError::Malformed("signature must be exactly 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(pubkey_b64url)
        .map_err(|_| LicenseError::Malformed("public key is not valid base64url"))?
        .try_into()
        .map_err(|_| LicenseError::Malformed("public key must be exactly 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| LicenseError::Malformed("public key is not a valid Ed25519 key"))?;

    // THE load-bearing line: verify over the payload segment's bytes exactly
    // as received — never over re-serialized claims (module docs explain
    // why). `verify_strict` additionally rejects malleable/weak-key
    // signatures; everything Node's crypto.sign produces passes it.
    key.verify_strict(payload_b64.as_bytes(), &signature)
        .map_err(|_| LicenseError::BadSignature)?;

    // Only now — after authentication — look inside the payload.
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| LicenseError::Malformed("payload segment is not valid base64url"))?;
    let claims: LicenseClaims = serde_json::from_slice(&payload)
        .map_err(|_| LicenseError::Malformed("payload is not a valid claims object"))?;

    // Expiry rule (frozen): reject iff expires_at != null && expires_at <
    // now. `expires_at == now` is still valid, matching the web side's
    // `expires_at < nowUnix()`. Null means perpetual.
    if let Some(expires_at) = claims.expires_at {
        if expires_at < now {
            return Err(LicenseError::Expired);
        }
    }

    Ok(claims)
}

/// Feature keys baked into premium license tokens.
///
/// Must match `PREMIUM_FEATURES` in `grepfocus-web/lib/features.ts` exactly
/// — these strings travel inside the signed `features` claim.
pub mod features {
    pub const APP_BLOCKING: &str = "app_blocking";
    pub const SCHEDULES: &str = "schedules";
    pub const TAMPER_PROTECTION: &str = "tamper_protection";
    pub const UNLIMITED_BLOCKS: &str = "unlimited_blocks";
    pub const LOCK_MODES: &str = "lock_modes";
    pub const USAGE_STATS: &str = "usage_stats";
    pub const POMODORO: &str = "pomodoro";

    /// Every premium feature key, in the order the web side lists them.
    pub const ALL: [&str; 7] = [
        APP_BLOCKING,
        SCHEDULES,
        TAMPER_PROTECTION,
        UNLIMITED_BLOCKS,
        LOCK_MODES,
        USAGE_STATS,
        POMODORO,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_are_human_readable() {
        assert_eq!(
            LicenseError::Malformed("no public key embedded").to_string(),
            "license key is malformed (no public key embedded)"
        );
        assert_eq!(
            LicenseError::BadSignature.to_string(),
            "license signature is invalid"
        );
        assert_eq!(LicenseError::Expired.to_string(), "license has expired");
    }

    #[test]
    fn feature_keys_match_the_web_contract() {
        // Mirrors PREMIUM_FEATURES in grepfocus-web/lib/features.ts.
        assert_eq!(
            features::ALL,
            [
                "app_blocking",
                "schedules",
                "tamper_protection",
                "unlimited_blocks",
                "lock_modes",
                "usage_stats",
                "pomodoro",
            ]
        );
    }

    #[test]
    fn embedded_pubkey_is_a_valid_ed25519_key() {
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(LICENSE_PUBKEY_B64URL)
            .expect("embedded key must be base64url no-pad")
            .try_into()
            .expect("embedded key must be exactly 32 bytes");
        VerifyingKey::from_bytes(&bytes).expect("embedded key must be a valid Ed25519 point");
    }

    #[test]
    fn empty_pubkey_is_rejected_before_anything_else() {
        // Even total garbage reports the missing key, not a token error.
        assert_eq!(
            verify_token_with_key("", "not-even-a-token", 0),
            Err(LicenseError::Malformed("no public key embedded"))
        );
    }
}
