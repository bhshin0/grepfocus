//! Known-answer tests for license verification.
//!
//! The fixture (`fixtures/license_kat.json`) was minted through the REAL
//! web-side signer — `grepfocus-web/lib/license.ts` `signLicense()` — with a
//! throwaway keypair and fixed timestamps, so these tests pin the Rust
//! verifier to the exact byte-level contract the store produces.
//!
//! # Regenerating the fixture
//!
//! Save the script below as `gen-kat.mts`, then from inside the
//! grepfocus-web checkout:
//!
//! ```text
//! node --experimental-strip-types gen-kat.mts \
//!   > <grepfocus>/crates/core/tests/fixtures/license_kat.json
//! ```
//!
//! ```text
//! import crypto from "node:crypto";
//! import { registerHooks } from "node:module";
//!
//! // lib/license.ts imports "./features" without an extension, which Node's
//! // type-stripping loader can't resolve; retry relative specifiers with ".ts".
//! registerHooks({
//!   resolve(specifier: string, context: unknown, nextResolve: any) {
//!     try { return nextResolve(specifier, context); }
//!     catch (err) {
//!       if (specifier.startsWith("./") || specifier.startsWith("../"))
//!         return nextResolve(`${specifier}.ts`, context);
//!       throw err;
//!     }
//!   },
//! });
//!
//! // Throwaway key; must be in env before signLicense() runs (loadPrivateKey
//! // reads process.env at call time — import after setting anyway).
//! const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
//! process.env.LICENSE_SIGNING_KEY = privateKey
//!   .export({ type: "pkcs8", format: "der" }).toString("base64");
//!
//! const base = `file://${process.cwd()}/`;
//! const { signLicense } = await import(new URL("./lib/license.ts", base).href);
//! const { PREMIUM_FEATURES } = await import(new URL("./lib/features.ts", base).href);
//! const test_pubkey_b64url = publicKey.export({ format: "jwk" }).x as string;
//!
//! // NOT buildClaims(): it derives issued_at/expires_at from Date.now(),
//! // which would make the fixture non-deterministic. Fixed literals instead.
//! const common = { email: "kat@example.com", tier: "premium" as const,
//!   features: [...PREMIUM_FEATURES], max_devices: 3 };
//! const validPerpetualClaims = { license_id: "GF-KAT-PERP-0001", ...common,
//!   kind: "perpetual" as const, issued_at: 1752192000, expires_at: null };
//! const validTrialClaims = { license_id: "GF-KAT-TRIAL-0001", ...common,
//!   kind: "trial" as const, issued_at: 1752192000, expires_at: 4102444800 };
//! const expiredTrialClaims = { license_id: "GF-KAT-EXPIRED-0001", ...common,
//!   kind: "trial" as const, issued_at: 944956800, expires_at: 946684800 };
//! const unknownFieldKnownClaims = { ...validPerpetualClaims,
//!   license_id: "GF-KAT-FUTURE-0001" };
//!
//! console.log(JSON.stringify({
//!   note: "Generated via grepfocus-web lib/license.ts signLicense() ...",
//!   test_pubkey_b64url,
//!   valid_perpetual: { token: signLicense(validPerpetualClaims), claims: validPerpetualClaims },
//!   valid_trial: { token: signLicense(validTrialClaims), claims: validTrialClaims },
//!   expired_trial: { token: signLicense(expiredTrialClaims) },
//!   unknown_field: {
//!     token: signLicense({ ...unknownFieldKnownClaims, future_field: 1 } as any),
//!     claims: unknownFieldKnownClaims,
//!   },
//! }, null, 2));
//! ```
//!
//! (The claims objects must keep the frozen field names; the actual JSON
//! byte layout doesn't matter because verification treats the payload as
//! opaque signed bytes.)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use grepfocus_core::license::{
    features, verify_token, verify_token_with_key, LicenseClaims, LicenseError,
};
use serde_json::Value;

const KAT: &str = include_str!("fixtures/license_kat.json");

fn fixture() -> Value {
    serde_json::from_str(KAT).expect("fixture is valid JSON")
}

fn pubkey(fx: &Value) -> &str {
    fx["test_pubkey_b64url"].as_str().expect("pubkey present")
}

fn token<'a>(fx: &'a Value, entry: &str) -> &'a str {
    fx[entry]["token"].as_str().expect("token present")
}

fn fixture_claims(fx: &Value, entry: &str) -> LicenseClaims {
    serde_json::from_value(fx[entry]["claims"].clone()).expect("claims parse")
}

/// Flip one character, staying inside the base64url charset.
fn flip_char(s: &str, idx: usize) -> String {
    let mut bytes = s.as_bytes().to_vec();
    bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap()
}

// [1] A perpetual license (expires_at = null) verifies at ANY clock value,
// and every one of the 8 claim fields round-trips exactly.
#[test]
fn valid_perpetual_verifies_at_any_now() {
    let fx = fixture();
    let expected = fixture_claims(&fx, "valid_perpetual");
    for now in [i64::MIN, 0, 946684800, 4102444800, i64::MAX] {
        let claims = verify_token_with_key(pubkey(&fx), token(&fx, "valid_perpetual"), now)
            .expect("perpetual license must verify at any now");
        assert_eq!(claims, expected);
    }
    // Spot-check the contract values (all 8 fields, explicitly).
    assert_eq!(expected.license_id, "GF-KAT-PERP-0001");
    assert_eq!(expected.email, "kat@example.com");
    assert_eq!(expected.tier, "premium");
    assert_eq!(expected.kind, "perpetual");
    assert_eq!(expected.features, features::ALL);
    assert_eq!(expected.issued_at, 1752192000);
    assert_eq!(expected.expires_at, None);
    assert_eq!(expected.max_devices, 3);
}

// [2] A trial verifies up to and INCLUDING its expires_at instant (frozen
// rule: reject iff expires_at < now), and fails Expired one second later.
#[test]
fn valid_trial_expiry_boundary() {
    let fx = fixture();
    let key = pubkey(&fx);
    let tok = token(&fx, "valid_trial");
    let expected = fixture_claims(&fx, "valid_trial");
    let expires_at = expected.expires_at.expect("trial has expiry");

    let claims = verify_token_with_key(key, tok, expires_at - 1).expect("before expiry");
    assert_eq!(claims, expected);
    // expires_at == now is still valid (web side rejects only `<`).
    verify_token_with_key(key, tok, expires_at).expect("at expiry instant");
    assert_eq!(
        verify_token_with_key(key, tok, expires_at + 1),
        Err(LicenseError::Expired)
    );
}

// [3] An expired trial fails Expired — NOT BadSignature. Its signature is
// still valid, proven by verifying with a clock set before its expiry.
#[test]
fn expired_trial_fails_expired_not_bad_signature() {
    let fx = fixture();
    let key = pubkey(&fx);
    let tok = token(&fx, "expired_trial");

    assert_eq!(
        verify_token_with_key(key, tok, 1752192000),
        Err(LicenseError::Expired)
    );
    // Same token, clock rolled back before its expires_at (946684800): the
    // signature verifies fine, so Expired above was purely the expiry check.
    let claims = verify_token_with_key(key, tok, 0).expect("signature itself is valid");
    assert_eq!(claims.kind, "trial");
    assert_eq!(claims.expires_at, Some(946684800));
}

// [4] Tampering with the payload segment must surface as BadSignature (the
// signature is checked over the received bytes BEFORE the JSON is even
// decoded), never as a JSON/Malformed error and never as Ok.
#[test]
fn tampered_payload_fails_bad_signature() {
    let fx = fixture();
    let tok = token(&fx, "valid_perpetual");
    let dot = tok.find('.').unwrap();

    // Flip a character in the middle of segment 0 (stays legal base64url).
    let tampered = flip_char(tok, dot / 2);
    assert_ne!(tampered, tok);
    assert_eq!(
        verify_token_with_key(pubkey(&fx), &tampered, 0),
        Err(LicenseError::BadSignature)
    );
}

// [5] The right token under the WRONG key must fail. A one-char key
// mutation keeps 32 bytes; when the mutated key is still a valid curve
// point the result is BadSignature (and never Ok in any case).
#[test]
fn wrong_key_fails_bad_signature() {
    let fx = fixture();
    let key = pubkey(&fx);
    let tok = token(&fx, "valid_perpetual");

    let mut saw_bad_signature = false;
    // Skip the final char: its low bits are base64 padding bits, and a
    // mutation there can be rejected as non-canonical base64url instead.
    for idx in 0..key.len() - 1 {
        let mutated = flip_char(key, idx);
        match verify_token_with_key(&mutated, tok, 0) {
            Ok(_) => panic!("token verified under a mutated key (idx {idx})"),
            // Mutated key decodes to 32 bytes but may not be a valid point.
            Err(LicenseError::BadSignature) => saw_bad_signature = true,
            Err(LicenseError::Malformed(_)) => {}
            Err(e) => panic!("unexpected error under mutated key: {e:?}"),
        }
    }
    assert!(
        saw_bad_signature,
        "at least one mutated key must be a valid point and fail BadSignature"
    );
}

// [6] Padded base64 must be rejected: the web side never pads.
#[test]
fn padded_base64_is_rejected() {
    let fx = fixture();
    let key = pubkey(&fx);
    let tok = token(&fx, "valid_perpetual");

    // '=' appended to segment 1: the signature segment no longer decodes
    // under the no-pad alphabet.
    let padded_sig = format!("{tok}=");
    assert!(matches!(
        verify_token_with_key(key, &padded_sig, 0),
        Err(LicenseError::Malformed(_))
    ));

    // '=' appended to segment 0 changes the signed bytes, so the signature
    // check (which runs first, over the raw ASCII) already fails.
    let (payload, sig) = tok.split_once('.').unwrap();
    let padded_payload = format!("{payload}=.{sig}");
    assert_eq!(
        verify_token_with_key(key, &padded_payload, 0),
        Err(LicenseError::BadSignature)
    );
}

// [7] Structural garbage: wrong segment counts and empty segments.
#[test]
fn structural_garbage_is_malformed() {
    let fx = fixture();
    let key = pubkey(&fx);
    let tok = token(&fx, "valid_perpetual");
    let (payload, sig) = tok.split_once('.').unwrap();

    let three_segments = format!("{payload}.{sig}.{sig}");
    let missing_payload = format!(".{sig}");
    let missing_sig = format!("{payload}.");
    let cases: &[&str] = &[
        "",               // empty token
        "nodothere",      // no separator
        &three_segments,  // 3 segments
        &missing_payload, // empty segment 0
        &missing_sig,     // empty segment 1
        ".",              // both segments empty
        "..",             // 3 empty segments
        payload,          // payload alone
    ];
    for case in cases {
        assert!(
            matches!(
                verify_token_with_key(key, case, 0),
                Err(LicenseError::Malformed(_))
            ),
            "expected Malformed for {case:?}"
        );
    }
}

// [8] Byte-mutation sweep: flipping any single character anywhere in the
// token (charset kept legal) must yield Err — never a panic, never Ok.
#[test]
fn single_char_mutation_sweep_never_verifies() {
    let fx = fixture();
    let key = pubkey(&fx);
    let tok = token(&fx, "valid_trial");

    let step = (tok.len() / 20).max(1);
    let mut checked = 0;
    for idx in (0..tok.len()).step_by(step) {
        // flip_char always changes the byte; if it lands on the '.', the
        // mutant has one segment and must fail structurally — still Err.
        let mutated = flip_char(tok, idx);
        let res = verify_token_with_key(key, &mutated, 0);
        assert!(res.is_err(), "mutation at {idx} verified: {res:?}");
        checked += 1;
    }
    assert!(checked >= 20, "swept only {checked} positions");
}

// [9] Safe-by-default: the embedded key const is still empty, so the
// public wrapper rejects even a genuinely valid token.
#[test]
fn embedded_const_empty_means_everything_malformed() {
    let fx = fixture();
    assert_eq!(
        verify_token(token(&fx, "valid_perpetual"), 0),
        Err(LicenseError::Malformed("no public key embedded"))
    );
}

// [10] Forward compatibility: a token whose payload carries an extra,
// unknown claim ("future_field") still verifies, and the known fields
// parse out exactly.
#[test]
fn unknown_claim_field_is_tolerated() {
    let fx = fixture();
    let tok = token(&fx, "unknown_field");

    // Prove the fixture really carries the extra field inside the signed
    // payload (guards against a stale/regenerated-wrong fixture).
    let payload = URL_SAFE_NO_PAD
        .decode(tok.split_once('.').unwrap().0)
        .expect("payload decodes");
    assert!(
        String::from_utf8(payload).unwrap().contains("future_field"),
        "fixture payload must contain the unknown field"
    );

    let claims =
        verify_token_with_key(pubkey(&fx), tok, 0).expect("unknown claim fields must be tolerated");
    assert_eq!(claims, fixture_claims(&fx, "unknown_field"));
}
