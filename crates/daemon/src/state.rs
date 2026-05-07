//! Persistent state: HMAC-signed JSON in /var/lib/frostbite/state.json.
//!
//! The HMAC defends against hand-edits while the daemon is stopped. The key
//! lives in /etc/frostbite/secret (mode 0600). If the state file is missing
//! or fails verification, the daemon starts fresh and clears any leftover
//! hosts-file block.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{anyhow, Context};
use frostbite_core::{hmac_sig, State};
use rand::RngCore;

use crate::paths;

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
    let body = fs::read(paths::STATE_FILE).context("reading state.json")?;
    let mac = fs::read(paths::STATE_MAC).context("reading state.json.mac")?;
    if !hmac_sig::verify(&body, key, &mac) {
        return Err(anyhow!("HMAC verification failed for state file"));
    }
    let state: State = serde_json::from_slice(&body).context("parsing state.json")?;
    Ok(state)
}

/// Write state atomically: write to .tmp, fsync, rename, then write the MAC.
/// Caller must hold the runtime state lock.
pub fn save(state: &State, key: &[u8]) -> anyhow::Result<()> {
    let body = serde_json::to_vec_pretty(state)?;
    let mac = hmac_sig::sign(&body, key);

    let tmp = format!("{}.tmp", paths::STATE_FILE);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, paths::STATE_FILE)?;
    fs::set_permissions(paths::STATE_FILE, fs::Permissions::from_mode(0o600))?;

    let tmp_mac = format!("{}.tmp", paths::STATE_MAC);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_mac)?;
        f.write_all(&mac)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_mac, paths::STATE_MAC)?;
    fs::set_permissions(paths::STATE_MAC, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
