//! /etc/hosts manipulation, with chattr +i to make the block tamper-resistant.
//!
//! The managed region is delimited by `HOSTS_BEGIN` / `HOSTS_END` markers.
//! Any content outside that region is preserved verbatim.
//!
//! Degradation policy: the hosts CONTENT is the enforcement; the immutable
//! bit is hardening on top. A `write_atomic` failure is fatal — it propagates,
//! `enforce::sync` clears its memo, and the next 1s tick retries. A failed
//! `chattr +i` (SELinux, or a filesystem without immutable-flag support) only
//! logs a warning: the block is active, just not tamper-protected, and
//! refusing to enforce at all would be strictly worse. `chattr -i` in the
//! clear paths is likewise best-effort.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::Command;

use anyhow::{anyhow, Context};
use tracing::{debug, warn};

use crate::paths::{HOSTS, HOSTS_BEGIN, HOSTS_END, HOSTS_ORIG};

/// Standard mode for `/etc/hosts`: world-readable so the libc resolver works
/// for non-root processes.
pub(crate) const HOSTS_MODE: u32 = 0o644;
/// Recovery copy is root-only.
const HOSTS_ORIG_MODE: u32 = 0o600;

/// Apply the block: remove any existing managed region, append a fresh one
/// with all blocked domains, then (best-effort) mark /etc/hosts immutable.
pub fn apply_block(domains: &[String]) -> anyhow::Result<()> {
    chattr_immutable(HOSTS, false).ok(); // best-effort unlock if previously locked
    let original = fs::read_to_string(HOSTS).context("reading /etc/hosts")?;
    let stripped = strip_managed(&original);
    // Snapshot the unmanaged content before we touch /etc/hosts, so it can be
    // recovered by hand if a later edit corrupts the live file. Best-effort:
    // a state-dir write failure must not block the enforcement change itself.
    write_recovery_copy(&stripped);
    let new = if domains.is_empty() {
        stripped
    } else {
        format!(
            "{}\n{}\n{}{}\n",
            stripped.trim_end(),
            HOSTS_BEGIN,
            render_block(domains),
            HOSTS_END
        )
    };
    write_atomic(HOSTS, &new, HOSTS_MODE)?;
    // The immutable bit is hardening, not enforcement (see module docs): the
    // block is live once the write lands, so degrade gracefully here.
    if let Err(e) = chattr_immutable(HOSTS, true) {
        warn!(
            ?e,
            "chattr +i failed — hosts block is active but NOT tamper-protected \
             (SELinux or the filesystem may forbid the immutable flag)"
        );
    }
    Ok(())
}

/// Remove the managed region and clear the immutable bit.
pub fn clear_block() -> anyhow::Result<()> {
    chattr_immutable(HOSTS, false).ok();
    let original = match fs::read_to_string(HOSTS) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("reading /etc/hosts"),
    };
    let stripped = strip_managed(&original);
    // Refresh the recovery copy before editing (matches apply_block); best-effort.
    write_recovery_copy(&stripped);
    if stripped != original {
        write_atomic(HOSTS, &stripped, HOSTS_MODE)?;
    }
    Ok(())
}

fn render_block(domains: &[String]) -> String {
    let mut out = String::from("\n");
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        out.push_str(&format!("0.0.0.0 {}\n", d));
        if !d.starts_with("www.") {
            out.push_str(&format!("0.0.0.0 www.{}\n", d));
        }
    }
    out
}

pub(crate) fn strip_managed(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut inside = false;
    for line in s.lines() {
        if line.trim_start().starts_with(HOSTS_BEGIN) {
            inside = true;
            continue;
        }
        if inside {
            if line.trim_start().starts_with(HOSTS_END) {
                inside = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Write `content` to `path` durably: write a sibling tmp file, fsync it, then
/// rename over the target. Mirrors `state::save_in`. `mode` is the final file
/// mode (0644 for /etc/hosts so the resolver can read it, 0600 for the
/// root-only recovery copy).
pub(crate) fn write_atomic(path: &str, content: &str, mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = format!("{}.frostbite.tmp", path);
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("opening {}", tmp))?;
        f.write_all(content.as_bytes())
            .with_context(|| format!("writing {}", tmp))?;
        f.sync_all().with_context(|| format!("fsync {}", tmp))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming over {}", path))?;
    // Guarantee the final mode even if a stale tmp was reused (mode() only
    // applies on fresh creation).
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path))?;
    // Persist the rename itself: fsync the parent directory so the new entry
    // survives a power loss, not just the file's contents. Best-effort.
    fsync_parent_dir(std::path::Path::new(path));
    Ok(())
}

/// Best-effort recovery snapshot of the unmanaged hosts content. Failures are
/// logged, never propagated, so a full or read-only state dir cannot block the
/// actual `/etc/hosts` enforcement change.
fn write_recovery_copy(stripped: &str) {
    if let Err(e) = write_atomic(HOSTS_ORIG, stripped, HOSTS_ORIG_MODE) {
        warn!(?e, "failed to write hosts recovery copy (continuing)");
    }
}

/// Best-effort `fsync` of a path's parent directory, so a `rename` into it is
/// durable across power loss. A failure here doesn't undo the write.
fn fsync_parent_dir(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::File::open(parent).and_then(|d| d.sync_all()) {
            debug!(?e, "best-effort parent-dir fsync failed");
        }
    }
}

/// Set or clear the immutable bit by shelling out to `chattr`.
/// We rely on coreutils being installed (it always is on a Linux system).
pub(crate) fn chattr_immutable(path: &str, set: bool) -> anyhow::Result<()> {
    let flag = if set { "+i" } else { "-i" };
    let out = Command::new("/usr/bin/chattr")
        .args([flag, path])
        .output()
        .context("running chattr")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("chattr {} {} failed: {}", flag, path, stderr));
    }
    debug!(path, set, "chattr immutable applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_round_trip() {
        let input = format!(
            "127.0.0.1 localhost\n{}\n0.0.0.0 reddit.com\n{}\n::1 localhost\n",
            HOSTS_BEGIN, HOSTS_END
        );
        let stripped = strip_managed(&input);
        assert!(!stripped.contains("reddit.com"));
        assert!(stripped.contains("127.0.0.1 localhost"));
        assert!(stripped.contains("::1 localhost"));
    }

    #[test]
    fn renders_www_alias() {
        let r = render_block(&["reddit.com".to_string()]);
        assert!(r.contains("0.0.0.0 reddit.com"));
        assert!(r.contains("0.0.0.0 www.reddit.com"));
    }

    #[test]
    fn skips_www_alias_when_already_www() {
        let r = render_block(&["www.example.com".to_string()]);
        assert!(r.contains("0.0.0.0 www.example.com"));
        assert!(!r.contains("www.www.example.com"));
    }

    #[test]
    fn strip_unterminated_region_drops_to_eof() {
        // A begin marker with no matching end marker: everything from the
        // marker to EOF is treated as managed and dropped. Documents current
        // behavior — a truncated region can never leak stale block entries.
        let input = format!(
            "127.0.0.1 localhost\n{}\n0.0.0.0 reddit.com\n0.0.0.0 news.ycombinator.com\n",
            HOSTS_BEGIN
        );
        let stripped = strip_managed(&input);
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }

    #[test]
    fn strip_removes_multiple_regions() {
        let input = format!(
            "127.0.0.1 localhost\n{b}\n0.0.0.0 reddit.com\n{e}\n::1 localhost\n{b}\n0.0.0.0 x.com\n{e}\n# user comment\n",
            b = HOSTS_BEGIN,
            e = HOSTS_END
        );
        let stripped = strip_managed(&input);
        assert!(!stripped.contains("reddit.com"));
        assert!(!stripped.contains("x.com"));
        assert!(stripped.contains("127.0.0.1 localhost"));
        assert!(stripped.contains("::1 localhost"));
        assert!(stripped.contains("# user comment"));
    }

    #[test]
    fn strip_recognizes_indented_markers() {
        // Markers are matched after trim_start, so a hand-indented region is
        // still recognized and stripped.
        let input = format!(
            "127.0.0.1 localhost\n  {}\n0.0.0.0 reddit.com\n\t{}\n::1 localhost\n",
            HOSTS_BEGIN, HOSTS_END
        );
        let stripped = strip_managed(&input);
        assert!(!stripped.contains("reddit.com"));
        assert!(stripped.contains("127.0.0.1 localhost"));
        assert!(stripped.contains("::1 localhost"));
    }

    #[test]
    fn strip_region_only_file_yields_empty() {
        let input = format!("{}\n0.0.0.0 reddit.com\n{}\n", HOSTS_BEGIN, HOSTS_END);
        let stripped = strip_managed(&input);
        assert!(stripped.trim().is_empty());
    }

    #[test]
    fn empty_domains_keep_stripped_only() {
        let input = "127.0.0.1 localhost\n";
        // strip + render with empty list yields the unchanged input
        let stripped = strip_managed(input);
        let rendered = render_block(&[]);
        assert!(rendered.is_empty() || rendered.trim().is_empty());
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }
}
