//! Filesystem paths owned by the daemon, plus directory bootstrap.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const HOSTS: &str = "/etc/hosts";
/// Recovery copy of the unmanaged `/etc/hosts` content, written before every
/// managed-region edit so the real hosts file can be restored by hand.
pub const HOSTS_ORIG: &str = "/var/lib/frostbite/hosts.orig";
pub const STATE_DIR: &str = "/var/lib/frostbite";
pub const SECRET_DIR: &str = "/etc/frostbite";
pub const SECRET_FILE: &str = "/etc/frostbite/secret";
pub const RUN_DIR: &str = "/run/frostbite";
pub const SOCK: &str = "/run/frostbite/sock";

pub const HOSTS_BEGIN: &str = "# frostbite-begin (managed — do not edit)";
pub const HOSTS_END: &str = "# frostbite-end";

/// Create directories the daemon writes to. Idempotent.
/// The install script sets ownership/group; here we just ensure they exist
/// with safe modes.
pub fn ensure_dirs() -> anyhow::Result<()> {
    mkdir_mode(STATE_DIR, 0o700)?;
    mkdir_mode(SECRET_DIR, 0o700)?;
    mkdir_mode(RUN_DIR, 0o755)?;
    Ok(())
}

fn mkdir_mode(path: &str, mode: u32) -> anyhow::Result<()> {
    if !Path::new(path).exists() {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
