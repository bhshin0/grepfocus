//! Persistent state: HMAC-signed JSON in /var/lib/grepfocus/state.json.
//!
//! The HMAC defends against hand-edits while the daemon is stopped. The key
//! lives in /etc/grepfocus/secret (mode 0600). If the state file is missing
//! or fails verification, the daemon starts fresh and clears any leftover
//! hosts-file block. If it *verifies* but does not parse, the daemon refuses
//! to start rather than overwrite authentic state — see [`UnparseableState`].

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{anyhow, Context};
use grepfocus_core::{hmac_sig, State};
use rand::RngCore;

use crate::paths;

/// State file name inside `STATE_DIR`. New format: a 32-byte HMAC-SHA256
/// prefix followed by the JSON body, written in a single atomic replace.
const STATE_JSON: &str = "state.json";
/// Legacy MAC sidecar. Read for backward compatibility; deleted on first save.
const STATE_MAC_SIDECAR: &str = "state.json.mac";

/// The state file's HMAC verified, but the body underneath it did not
/// deserialize into `State`.
///
/// This is a *categorically different* failure from a bad MAC, and the
/// difference is the whole point of the type. A bad MAC means the bytes are
/// not ours: hand-edited, truncated, restored from a mismatched secret. There
/// is nothing to recover, so starting fresh is correct. A good MAC means we
/// wrote these bytes ourselves — the content is authentic and simply cannot be
/// read by *this* build (a serialization bug, or state written by a newer
/// daemon whose schema we don't understand). Starting fresh there would
/// overwrite a perfectly good state file on the next save and destroy every
/// block, schedule, usage stat and the stored licence token. So this case is
/// fatal at startup instead: the daemon refuses to run and leaves the file on
/// disk for an operator (or a downgrade/upgrade) to sort out.
///
/// Callers detect it by downcasting through the `anyhow` chain — see
/// [`is_unparseable`] — rather than matching on message text.
#[derive(Debug)]
pub struct UnparseableState(serde_json::Error);

impl std::fmt::Display for UnparseableState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "state.json passed HMAC verification but its body could not be parsed"
        )
    }
}

impl std::error::Error for UnparseableState {
    /// Keep the `serde_json` error reachable: "expected a string at line 4
    /// column 18" is the entire diagnostic value of this failure.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// True if `err` came from [`load_in`] failing to parse an authentic
/// (HMAC-verified) state file, as opposed to genuine corruption or a missing
/// file. See [`UnparseableState`].
pub fn is_unparseable(err: &anyhow::Error) -> bool {
    err.chain().any(|e| e.is::<UnparseableState>())
}

pub fn load_or_create_secret() -> anyhow::Result<Vec<u8>> {
    match fs::read(paths::SECRET_FILE) {
        Ok(bytes) if bytes.len() >= 32 => Ok(bytes),
        Ok(_) => Err(anyhow!("secret file too short (must be at least 32 bytes)")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("generating new HMAC secret at {}", paths::SECRET_FILE);
            let mut buf = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut buf);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(paths::SECRET_FILE)
                .context("creating secret file")?;
            f.write_all(&buf)?;
            f.sync_all()?;
            Ok(buf.to_vec())
        }
        Err(e) => Err(e).context("reading secret file"),
    }
}

pub fn load(key: &[u8]) -> anyhow::Result<State> {
    load_in(Path::new(paths::STATE_DIR), key)
}

/// Load state from `dir/state.json`. Tries the new single-file format first
/// (32-byte HMAC prefix + JSON body), then falls back to the legacy two-file
/// scheme (whole file as body, MAC in `state.json.mac`).
///
/// Failure modes, all three distinguishable by the caller (see `main.rs`):
///   * missing `state.json` — a `NotFound` `io::Error` in the chain, i.e.
///     "first run";
///   * verifies under neither format — plain error, i.e. genuine corruption,
///     reported rather than silently accepted;
///   * verifies but does not deserialize — [`UnparseableState`], which must
///     never be treated as corruption because doing so overwrites authentic
///     state. Both formats report it the same way so the legacy path stays
///     coherent with the new one.
pub fn load_in(dir: &Path, key: &[u8]) -> anyhow::Result<State> {
    let raw = fs::read(dir.join(STATE_JSON)).context("reading state.json")?;

    // New format: 32-byte HMAC-SHA256 prefix, then the JSON body.
    if raw.len() >= 32 {
        let (mac, body) = raw.split_at(32);
        if hmac_sig::verify(body, key, mac) {
            // The MAC proves we wrote this body, so a parse failure here is
            // never corruption — do not fall through to the legacy branch and
            // end up reporting it as one.
            return serde_json::from_slice::<State>(body)
                .map_err(|e| anyhow::Error::new(UnparseableState(e)));
        }
    }

    // Legacy two-file scheme: the whole file is the body, MAC in the sidecar.
    // A new-format file whose MAC failed also lands here and fails this check
    // too, so genuine corruption still surfaces as an error.
    if let Ok(mac) = fs::read(dir.join(STATE_MAC_SIDECAR)) {
        if hmac_sig::verify(&raw, key, &mac) {
            return serde_json::from_slice(&raw)
                .map_err(|e| anyhow::Error::new(UnparseableState(e)))
                .context("parsing legacy state.json");
        }
    }

    Err(anyhow!(
        "state.json failed HMAC verification (new and legacy formats)"
    ))
}

/// Persist state atomically. Caller must hold the runtime state lock.
pub fn save(state: &State, key: &[u8]) -> anyhow::Result<()> {
    save_in(Path::new(paths::STATE_DIR), state, key)
}

/// Write `state` to `dir/state.json` in the single-file format: one tmp file
/// holding the 32-byte MAC prefix + JSON body, fsync, then a single rename.
/// This removes the crash window the old two-rename scheme had (a crash
/// between the two renames could leave body and MAC out of sync and wipe
/// state on the next boot). The legacy `state.json.mac` is removed afterward.
pub fn save_in(dir: &Path, state: &State, key: &[u8]) -> anyhow::Result<()> {
    let body = serde_json::to_vec_pretty(state)?;
    let mac = hmac_sig::sign(&body, key);

    let state_path = dir.join(STATE_JSON);
    let tmp = dir.join(format!("{}.tmp", STATE_JSON));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&mac)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &state_path)?;
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))?;
    // Persist the rename itself: without fsyncing the directory, a power loss
    // right after this returns could resurrect the old state.json on some
    // journaling filesystems. Best-effort — the file contents are already
    // durable from the sync_all above.
    if let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all()) {
        tracing::debug!(?e, "best-effort state directory fsync failed");
    }

    // Best-effort cleanup of the legacy sidecar; its absence is expected once
    // migrated.
    match fs::remove_file(dir.join(STATE_MAC_SIDECAR)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(?e, "failed to remove legacy state.json.mac"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use grepfocus_core::{Block, LockMode};

    fn sample_state() -> State {
        State {
            next_id: 3,
            next_schedule_id: 2,
            password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$abc$def".to_string()),
            blocks: vec![Block {
                id: 1,
                name: "reddit".into(),
                domains: vec!["reddit.com".into()],
                apps: vec![],
                allowance_secs_per_day: 600,
                lock: LockMode::Normal,
            }],
            license_token: Some("payload.signature".to_string()),
            high_water_unix: 1_752_192_000,
            ..Default::default()
        }
    }

    fn json(s: &State) -> String {
        serde_json::to_string(s).unwrap()
    }

    fn is_not_found(err: &anyhow::Error) -> bool {
        err.chain().any(|e| {
            e.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
        })
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"round-trip-test-key-0123456789ab";
        let st = sample_state();
        save_in(dir.path(), &st, key).unwrap();
        let loaded = load_in(dir.path(), key).unwrap();
        assert_eq!(json(&st), json(&loaded));
        // Single-file format: no legacy sidecar, and the file leads with the
        // 32-byte MAC prefix.
        assert!(!dir.path().join(STATE_MAC_SIDECAR).exists());
        let raw = fs::read(dir.path().join(STATE_JSON)).unwrap();
        assert!(raw.len() > 32);
    }

    #[test]
    fn migrates_legacy_two_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"legacy-migrate-key-0123456789abcd";
        let st = sample_state();
        // Hand-write the legacy layout: body in state.json, MAC in the sidecar.
        let body = serde_json::to_vec_pretty(&st).unwrap();
        let mac = hmac_sig::sign(&body, key);
        fs::write(dir.path().join(STATE_JSON), &body).unwrap();
        fs::write(dir.path().join(STATE_MAC_SIDECAR), mac).unwrap();
        // Legacy load still works.
        let loaded = load_in(dir.path(), key).unwrap();
        assert_eq!(json(&st), json(&loaded));
        // Saving migrates to the single-file format and drops the sidecar.
        save_in(dir.path(), &loaded, key).unwrap();
        assert!(!dir.path().join(STATE_MAC_SIDECAR).exists());
        let reloaded = load_in(dir.path(), key).unwrap();
        assert_eq!(json(&st), json(&reloaded));
    }

    #[test]
    fn old_state_json_without_license_fields_loads_with_defaults() {
        // A pre-license state.json — exactly the fields the daemon wrote
        // before license_token/high_water_unix existed — must load with
        // defaults. No migration step exists (State has no
        // deny_unknown_fields and the HMAC single-file format is unchanged).
        let old = r#"{
            "next_id": 2,
            "blocks": [],
            "active": [],
            "schedules": [],
            "next_schedule_id": 1,
            "password_hash": null,
            "allowance": []
        }"#;
        let st: State = serde_json::from_str(old).unwrap();
        assert_eq!(st.license_token, None);
        assert_eq!(st.high_water_unix, 0);
    }

    #[test]
    fn state_json_with_unknown_field_is_tolerated() {
        // The other direction: a state written by a NEWER daemon (carrying a
        // field this build doesn't know) still loads here.
        let future = r#"{
            "next_id": 2,
            "blocks": [],
            "license_token": "payload.signature",
            "high_water_unix": 42,
            "field_from_the_future": true
        }"#;
        let st: State = serde_json::from_str(future).unwrap();
        assert_eq!(st.license_token.as_deref(), Some("payload.signature"));
        assert_eq!(st.high_water_unix, 42);
    }

    #[test]
    fn missing_file_surfaces_as_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"missing-file-test-key-0123456789a";
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(
            is_not_found(&err),
            "a missing state.json must read as NotFound"
        );
    }

    #[test]
    fn rejects_short_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"short-corrupt-test-key-0123456789";
        // Present but garbage, shorter than the MAC prefix, no sidecar.
        fs::write(dir.path().join(STATE_JSON), b"garbage").unwrap();
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(
            !is_not_found(&err),
            "corruption must not be mistaken for a missing file"
        );
    }

    #[test]
    fn rejects_tampered_new_format() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"tamper-test-key-0123456789abcdef0";
        let st = sample_state();
        save_in(dir.path(), &st, key).unwrap();
        // Flip a byte in the body (past the 32-byte MAC prefix).
        let path = dir.path().join(STATE_JSON);
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        fs::write(&path, &raw).unwrap();
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(!is_not_found(&err));
        assert!(err.to_string().contains("HMAC"));
    }

    /// Write `body` to `dir/state.json` in the new single-file format with a
    /// MAC that genuinely verifies, whatever the body happens to contain.
    fn write_signed(dir: &Path, key: &[u8], body: &[u8]) {
        let mut raw = hmac_sig::sign(body, key).to_vec();
        raw.extend_from_slice(body);
        fs::write(dir.join(STATE_JSON), raw).unwrap();
    }

    #[test]
    fn verified_but_malformed_body_is_unparseable_not_corruption() {
        // The data-loss case: a file we signed ourselves whose body this build
        // cannot read. It must NOT come back as an HMAC failure, because the
        // caller answers that with "start fresh" and then saves over the file.
        let dir = tempfile::tempdir().unwrap();
        let key = b"unparseable-test-key-0123456789ab";
        write_signed(dir.path(), key, b"{ this is not json");
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(is_unparseable(&err), "got: {err:#}");
        assert!(!is_not_found(&err));
        assert!(
            !format!("{err:#}").contains("failed HMAC verification"),
            "must not be reported as corruption: {err:#}"
        );
    }

    #[test]
    fn verified_but_wrongly_typed_body_is_unparseable() {
        // Well-formed JSON, wrong shape — the realistic "newer daemon changed
        // a field's type" flavour of the same failure.
        let dir = tempfile::tempdir().unwrap();
        let key = b"typed-unparseable-key-0123456789a";
        write_signed(dir.path(), key, br#"{"next_id": "not-a-number"}"#);
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(is_unparseable(&err), "got: {err:#}");
        // The serde diagnostic survives into the chain — that detail is the
        // only thing an operator has to go on.
        assert!(
            format!("{err:#}").contains("invalid type: string \"not-a-number\""),
            "serde detail must be preserved: {err:#}"
        );
    }

    #[test]
    fn legacy_verified_but_malformed_body_is_unparseable() {
        // Same rule on the legacy two-file path: a valid sidecar MAC over an
        // unreadable body is our data, not corruption.
        let dir = tempfile::tempdir().unwrap();
        let key = b"legacy-unparseable-key-0123456789";
        let body = b"{ nope";
        fs::write(dir.path().join(STATE_JSON), body).unwrap();
        fs::write(
            dir.path().join(STATE_MAC_SIDECAR),
            hmac_sig::sign(body, key),
        )
        .unwrap();
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(is_unparseable(&err), "got: {err:#}");
        assert!(format!("{err:#}").contains("parsing legacy state.json"));
    }

    #[test]
    fn bad_mac_is_corruption_not_unparseable() {
        // The counterpart: a body this build could happily parse, but signed
        // with the wrong key. That is corruption, and must stay corruption.
        let dir = tempfile::tempdir().unwrap();
        let st = sample_state();
        save_in(dir.path(), &st, b"real-key-0123456789abcdef01234567").unwrap();
        let err = load_in(dir.path(), b"other-key-0123456789abcdef0123456").unwrap_err();
        assert!(!is_unparseable(&err), "got: {err:#}");
        assert!(err.to_string().contains("HMAC"));
    }

    #[test]
    fn missing_file_is_not_unparseable() {
        // NotFound still means "first run" and nothing else.
        let dir = tempfile::tempdir().unwrap();
        let key = b"missing-not-unparseable-key-01234";
        let err = load_in(dir.path(), key).unwrap_err();
        assert!(is_not_found(&err));
        assert!(!is_unparseable(&err), "got: {err:#}");
    }

    #[test]
    fn unparseable_load_leaves_state_file_untouched() {
        // load_in must never mutate the file; the caller's whole recovery
        // story depends on the bytes still being there afterwards.
        let dir = tempfile::tempdir().unwrap();
        let key = b"untouched-test-key-0123456789abc";
        write_signed(dir.path(), key, b"{ broken");
        let before = fs::read(dir.path().join(STATE_JSON)).unwrap();
        let _ = load_in(dir.path(), key).unwrap_err();
        assert_eq!(before, fs::read(dir.path().join(STATE_JSON)).unwrap());
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let st = sample_state();
        save_in(dir.path(), &st, b"correct-key-0123456789abcdef01234").unwrap();
        let err = load_in(dir.path(), b"wrong-key-0123456789abcdef0123456").unwrap_err();
        assert!(err.to_string().contains("HMAC"));
    }
}
