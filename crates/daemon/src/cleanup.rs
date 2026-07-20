//! `grepfocusd cleanup` — offline teardown of every enforcement artifact.
//!
//! Recovery path for a wedged or half-uninstalled system: clears the
//! immutable bit, strips the managed `/etc/hosts` region (restoring from the
//! recovery copy if the live file is gone), removes stale atomic-write
//! orphans, drops the nftables DoH table, and clears persisted active blocks
//! so a later `systemctl start` doesn't re-apply them. Every step is
//! best-effort and idempotent, and the command copes with missing or corrupt
//! state. Only a failed hosts strip exits nonzero — that is the one artifact
//! that keeps blocking traffic on its own.

use std::fs;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use anyhow::Context;
use tracing::debug;

use crate::{hosts, nftables, paths, state};

/// Options for `grepfocusd cleanup`, parsed in `main`.
pub struct Opts {
    /// Also delete the state dir (/var/lib/grepfocus) and config dir
    /// (/etc/grepfocus) once everything else is torn down.
    pub purge: bool,
    /// Skip the running-daemon socket check.
    pub force: bool,
}

/// Per-step result, collected for the end-of-run summary.
#[derive(Debug)]
pub(crate) enum Outcome {
    Done(String),
    Skipped(String),
    Failed(String),
}

/// What `strip_or_restore` did to the hosts file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostsOutcome {
    /// Present and already free of a managed region — nothing written, so
    /// the file's bytes (encoding, line endings, trailing-newline style)
    /// stay exactly as they were.
    AlreadyClean,
    /// Managed region removed from the existing hosts file.
    Stripped,
    /// Hosts file missing; recovery copy written in its place.
    Restored,
    /// Hosts file and recovery copy both missing — nothing to restore from,
    /// but also no managed region left anywhere.
    MissingNoBackup,
}

/// Run all cleanup steps, print a summary, and return `Err` only if the
/// hosts strip step failed (everything else is best-effort).
pub fn run(opts: Opts) -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("grepfocusd cleanup must run as root");
    }

    // Refuse to fight a live daemon: its 1s reconcile tick would re-apply
    // enforcement right behind us. The socket probe alone can't be trusted:
    // under systemd's Restart=always a kill -9'd daemon respawns about a
    // second later and re-applies enforcement BEFORE binding its socket, so
    // a probe against the stale socket reads "not running" while the respawn
    // re-enforces behind us. So ask systemd first, then probe the socket.
    // A connect that succeeds means something holds the listener — even a
    // hung daemon might wake up mid-cleanup — so refuse either way. Only a
    // refused/missing socket (stale after kill -9, or never installed)
    // means not running; any other connect error is inconclusive, so bail.
    if !opts.force {
        let unit_active = Command::new("systemctl")
            .args(["is-active", "--quiet", "grepfocusd"])
            .status()
            .is_ok_and(|s| s.success());
        if unit_active {
            anyhow::bail!(
                "grepfocusd unit is active — stop it first \
                 (sudo systemctl stop grepfocusd) or pass --force"
            );
        }
        // Spawn error or nonzero exit: not running, or no systemd (chroot) —
        // fall through to the socket probe.
        match UnixStream::connect(paths::SOCK) {
            Ok(_) => anyhow::bail!(
                "grepfocusd appears to be running — stop it first \
                 (sudo systemctl stop grepfocusd) or pass --force"
            ),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                debug!(?e, "daemon socket not accepting — proceeding");
            }
            Err(e) => anyhow::bail!(
                "cannot tell whether grepfocusd is running (connecting to {}: {}) — \
                 stop it first or pass --force",
                paths::SOCK,
                e
            ),
        }
    }

    let mut steps: Vec<(&'static str, Outcome)> = Vec::new();
    let mut hosts_strip_error: Option<String> = None;

    // (b) Clear the immutable bit so the strip below can rename over
    // /etc/hosts. Best-effort: `chattr -i` on an already-mutable file
    // succeeds, and on filesystems without the flag the strip may still work.
    steps.push((
        "immutable bit",
        match hosts::chattr_immutable(paths::HOSTS, false) {
            Ok(()) => Outcome::Done("chattr -i /etc/hosts".into()),
            Err(e) => Outcome::Skipped(format!("chattr -i failed ({e:#}) — continuing")),
        },
    ));

    // (c) Strip the managed region, or restore from the recovery copy.
    steps.push((
        "hosts region",
        match strip_or_restore(paths::HOSTS, paths::HOSTS_ORIG) {
            Ok(HostsOutcome::AlreadyClean) => Outcome::Skipped("no managed region present".into()),
            Ok(HostsOutcome::Stripped) => Outcome::Done("managed region removed".into()),
            Ok(HostsOutcome::Restored) => Outcome::Done(format!(
                "{} missing — restored from {}",
                paths::HOSTS,
                paths::HOSTS_ORIG
            )),
            Ok(HostsOutcome::MissingNoBackup) => Outcome::Skipped(format!(
                "{} and {} both missing — nothing to strip or restore",
                paths::HOSTS,
                paths::HOSTS_ORIG
            )),
            Err(e) => {
                let msg = format!("{e:#}");
                hosts_strip_error = Some(msg.clone());
                Outcome::Failed(msg)
            }
        },
    ));

    // (d) Remove atomic-write orphans left by an interrupted write.
    steps.push(("stale tmp files", {
        let mut removed = Vec::new();
        let mut failed = Vec::new();
        for target in [paths::HOSTS, paths::HOSTS_ORIG] {
            match remove_stale_tmp(target) {
                Ok(true) => removed.push(write_atomic_tmp_path(target)),
                Ok(false) => {}
                Err(e) => failed.push(format!("{}: {}", write_atomic_tmp_path(target), e)),
            }
        }
        if !failed.is_empty() {
            Outcome::Failed(failed.join("; "))
        } else if removed.is_empty() {
            Outcome::Skipped("none present".into())
        } else {
            Outcome::Done(format!("removed {}", removed.join(", ")))
        }
    }));

    // (e) Drop the DoH/DoT block table. Already idempotent/silent-on-absent.
    steps.push((
        "nftables DoH table",
        match nftables::clear() {
            Ok(()) => Outcome::Done("cleared (no-op if absent)".into()),
            Err(e) => Outcome::Failed(format!("{e:#}")),
        },
    ));

    // (f) Clear persisted active blocks so a later `systemctl start` doesn't
    // re-apply them.
    steps.push((
        "state active blocks",
        clear_active_blocks(Path::new(paths::STATE_DIR), Path::new(paths::SECRET_FILE)),
    ));

    // (g) --purge: delete the state and config dirs. Last, because earlier
    // steps may write there (recovery copy refresh, state save). When the
    // hosts strip failed, /etc/hosts may still contain the managed region and
    // hosts.orig inside the state dir is the recovery copy needed to fix
    // exactly that — purging would burn the safety net, so keep everything.
    if opts.purge {
        steps.push((
            "purge dirs",
            if hosts_strip_error.is_some() {
                Outcome::Skipped("hosts strip failed — keeping state and recovery copy".into())
            } else {
                let mut removed = Vec::new();
                let mut failed = Vec::new();
                for dir in [paths::STATE_DIR, paths::SECRET_DIR] {
                    match fs::remove_dir_all(dir) {
                        Ok(()) => removed.push(dir),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => failed.push(format!("{}: {}", dir, e)),
                    }
                }
                if !failed.is_empty() {
                    Outcome::Failed(failed.join("; "))
                } else if removed.is_empty() {
                    Outcome::Skipped("already absent".into())
                } else {
                    Outcome::Done(format!("removed {}", removed.join(", ")))
                }
            },
        ));
    }

    println!("grepfocus cleanup summary:");
    for (name, outcome) in &steps {
        match outcome {
            Outcome::Done(d) => println!("  {name:<20} done    — {d}"),
            Outcome::Skipped(d) => println!("  {name:<20} skipped — {d}"),
            Outcome::Failed(d) => println!("  {name:<20} FAILED  — {d}"),
        }
    }

    if let Some(msg) = hosts_strip_error {
        anyhow::bail!(
            "hosts cleanup failed — /etc/hosts may still contain the managed region: {msg}"
        );
    }
    Ok(())
}

/// Remove the managed region from `hosts_path`, or, when `hosts_path` is
/// missing, restore it from the recovery copy at `orig_path`.
///
/// A present hosts file always wins over the recovery copy: user edits made
/// since the copy was taken must survive, so an existing file is only ever
/// *stripped* — and only when a managed region is actually present, so a
/// region-free file keeps its exact bytes (encoding, line endings,
/// trailing-newline style). A restore happens only when the live file is
/// confirmed *absent*; any other read error propagates rather than letting
/// the stale copy overwrite a live file we merely failed to read.
pub(crate) fn strip_or_restore(hosts_path: &str, orig_path: &str) -> anyhow::Result<HostsOutcome> {
    let read_err = match fs::read(hosts_path) {
        Ok(bytes) => {
            // Decode lossily: marker detection and stripping only care about
            // the ASCII marker lines, and hosts files can legally carry
            // non-UTF-8 bytes (e.g. latin-1 comments).
            let content = String::from_utf8_lossy(&bytes);
            if !hosts::contains_managed(&content) {
                return Ok(HostsOutcome::AlreadyClean);
            }
            // A region is present, so a rewrite is unavoidable anyway; only
            // on this path can lossy replacement touch unrelated invalid
            // bytes.
            let stripped = hosts::strip_managed(&content);
            hosts::write_atomic(hosts_path, &stripped, hosts::HOSTS_MODE)
                .with_context(|| format!("writing stripped {}", hosts_path))?;
            return Ok(HostsOutcome::Stripped);
        }
        Err(e) => e,
    };
    if read_err.kind() != io::ErrorKind::NotFound {
        return Err(anyhow::Error::new(read_err).context(format!(
            "reading {} — refusing to restore over it",
            hosts_path
        )));
    }
    match fs::read_to_string(orig_path) {
        Ok(orig) => {
            // Defensive: the recovery copy is written pre-stripped, but strip
            // again so an anomalous copy can never resurrect a managed region.
            let stripped = hosts::strip_managed(&orig);
            hosts::write_atomic(hosts_path, &stripped, hosts::HOSTS_MODE)
                .with_context(|| format!("restoring {} from {}", hosts_path, orig_path))?;
            Ok(HostsOutcome::Restored)
        }
        Err(orig_err) if orig_err.kind() == io::ErrorKind::NotFound => {
            Ok(HostsOutcome::MissingNoBackup)
        }
        Err(orig_err) => Err(anyhow::anyhow!(
            "hosts file missing ({read_err}) and recovery copy unusable ({orig_err})"
        )),
    }
}

/// Step (f) of `run`: clear persisted active blocks so a later
/// `systemctl start` doesn't re-apply them. Reads the secret directly —
/// cleanup must never create one (that's `state::load_or_create_secret`'s
/// job, on daemon startup). Everything short of a failed save is a skip:
/// with no secret or no verifiable state there is nothing trusted to clear,
/// and daemon startup fails open on corrupt state anyway.
pub(crate) fn clear_active_blocks(state_dir: &Path, secret_path: &Path) -> Outcome {
    match fs::read(secret_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Outcome::Skipped("no HMAC secret — no trusted state to clear".into())
        }
        Err(e) => Outcome::Skipped(format!("reading secret failed ({e}) — skipping")),
        Ok(key) => match state::load_in(state_dir, &key) {
            Err(e) => Outcome::Skipped(format!(
                "state missing or corrupt ({e:#}) — skipping; daemon startup fails open"
            )),
            Ok(st) if st.active.is_empty() => Outcome::Skipped("no active blocks recorded".into()),
            Ok(mut st) => {
                let n = st.active.len();
                st.active.clear();
                match state::save_in(state_dir, &st, &key) {
                    Ok(()) => Outcome::Done(format!("cleared {n} active block(s)")),
                    Err(e) => Outcome::Failed(format!("saving cleared state: {e:#}")),
                }
            }
        },
    }
}

/// Path of the scratch file `hosts::write_atomic` uses when writing `path`.
fn write_atomic_tmp_path(path: &str) -> String {
    format!("{}{}", path, hosts::TMP_SUFFIX)
}

/// Remove the stale atomic-write orphan for `path`, if present. Returns
/// whether a file was removed. Orphans appear when a write is interrupted
/// (kill -9, power loss) between creating the tmp file and renaming it.
pub(crate) fn remove_stale_tmp(path: &str) -> io::Result<bool> {
    match fs::remove_file(write_atomic_tmp_path(path)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::{HOSTS_BEGIN, HOSTS_END};
    use grepfocus_core::{ActiveBlock, Block, LockMode, Originator, State};
    use std::os::unix::fs::PermissionsExt;

    fn hosts_with_region() -> String {
        format!(
            "127.0.0.1 localhost\n# user comment\n{}\n0.0.0.0 reddit.com\n{}\n::1 localhost\n",
            HOSTS_BEGIN, HOSTS_END
        )
    }

    #[test]
    fn strip_removes_region_and_preserves_user_lines() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        fs::write(&hosts, hosts_with_region()).unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::Stripped);
        let after = fs::read_to_string(&hosts).unwrap();
        assert!(!after.contains("reddit.com"));
        assert!(after.contains("127.0.0.1 localhost"));
        assert!(after.contains("# user comment"));
        assert!(after.contains("::1 localhost"));
    }

    #[test]
    fn strip_twice_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        fs::write(&hosts, hosts_with_region()).unwrap();
        strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        let first = fs::read(&hosts).unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::AlreadyClean);
        assert_eq!(first, fs::read(&hosts).unwrap());
    }

    #[test]
    fn restores_from_orig_when_hosts_missing() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        fs::write(&orig, "127.0.0.1 localhost\n").unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::Restored);
        assert_eq!(fs::read_to_string(&hosts).unwrap(), "127.0.0.1 localhost\n");
        // Restored file must be world-readable so the resolver works.
        let mode = fs::metadata(&hosts).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn readable_hosts_is_never_overwritten_by_orig() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        // User edited /etc/hosts after install; the recovery copy is stale.
        fs::write(&hosts, "127.0.0.1 localhost\n10.0.0.5 nas.local\n").unwrap();
        fs::write(&orig, "127.0.0.1 localhost\n").unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::AlreadyClean);
        assert!(fs::read_to_string(&hosts).unwrap().contains("nas.local"));
    }

    #[test]
    fn both_missing_reports_no_backup() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::MissingNoBackup);
        assert!(!hosts.exists());
    }

    #[test]
    fn remove_stale_tmp_removes_only_the_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("hosts");
        let target_str = target.to_str().unwrap();
        let tmp = dir.path().join("hosts.grepfocus.tmp");
        let bystander = dir.path().join("hosts.orig");
        fs::write(&target, "keep\n").unwrap();
        fs::write(&tmp, "orphan\n").unwrap();
        fs::write(&bystander, "keep too\n").unwrap();
        assert!(remove_stale_tmp(target_str).unwrap());
        assert!(!tmp.exists());
        assert!(target.exists());
        assert!(bystander.exists());
        // Second run: nothing left to remove.
        assert!(!remove_stale_tmp(target_str).unwrap());
    }

    #[test]
    fn non_utf8_hosts_without_region_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        // Latin-1 comment: 0xe9 is not valid UTF-8.
        let bytes: &[u8] = b"127.0.0.1 localhost # caf\xe9\n10.0.0.5 nas.local\n";
        fs::write(&hosts, bytes).unwrap();
        fs::write(&orig, "127.0.0.1 localhost\n").unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::AlreadyClean);
        // Region-free: byte-for-byte untouched, never restored over.
        assert_eq!(fs::read(&hosts).unwrap(), bytes);
    }

    #[test]
    fn non_utf8_hosts_with_region_is_stripped() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        let mut bytes = b"10.0.0.5 nas.local # caf\xe9\n".to_vec();
        bytes.extend_from_slice(hosts_with_region().as_bytes());
        fs::write(&hosts, &bytes).unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::Stripped);
        let after = fs::read_to_string(&hosts).unwrap();
        assert!(!after.contains("reddit.com"));
        // User lines survive, including the (lossily decoded) non-UTF-8 one.
        assert!(after.contains("nas.local"));
        assert!(after.contains("127.0.0.1 localhost"));
        assert!(after.contains("# user comment"));
    }

    #[test]
    fn region_free_no_trailing_newline_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        let bytes: &[u8] = b"127.0.0.1 localhost";
        fs::write(&hosts, bytes).unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::AlreadyClean);
        assert_eq!(fs::read(&hosts).unwrap(), bytes);
    }

    #[test]
    fn region_free_crlf_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let orig = dir.path().join("hosts.orig");
        let bytes: &[u8] = b"127.0.0.1 localhost\r\n::1 localhost\r\n";
        fs::write(&hosts, bytes).unwrap();
        let out = strip_or_restore(hosts.to_str().unwrap(), orig.to_str().unwrap()).unwrap();
        assert_eq!(out, HostsOutcome::AlreadyClean);
        assert_eq!(fs::read(&hosts).unwrap(), bytes);
    }

    #[test]
    fn clear_active_blocks_clears_actives_and_keeps_config() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"cleanup-active-clear-key-0123456789";
        let secret = dir.path().join("secret");
        fs::write(&secret, key).unwrap();
        let block = Block {
            id: 1,
            name: "reddit".into(),
            domains: vec!["reddit.com".into()],
            apps: vec![],
            allowance_secs_per_day: 0,
            allowance: None,
            lock: LockMode::Unlocked,
        };
        let st = State {
            next_id: 2,
            blocks: vec![block.clone()],
            active: vec![ActiveBlock {
                block,
                started_at_unix: 100,
                ends_at_unix: u64::MAX,
                originator: Originator::Manual,
                break_until_unix: None,
                apps_enforced: false,
                lock: LockMode::Unlocked,
            }],
            ..Default::default()
        };
        state::save_in(dir.path(), &st, key).unwrap();
        let out = clear_active_blocks(dir.path(), &secret);
        assert!(matches!(out, Outcome::Done(_)), "{out:?}");
        let reloaded = state::load_in(dir.path(), key).unwrap();
        assert!(reloaded.active.is_empty());
        // Everything else survives — cleanup drops the actives, not the config.
        assert_eq!(reloaded.blocks.len(), 1);
        assert_eq!(reloaded.next_id, 2);
    }

    #[test]
    fn clear_active_blocks_skips_without_secret() {
        let dir = tempfile::tempdir().unwrap();
        let out = clear_active_blocks(dir.path(), &dir.path().join("secret"));
        assert!(matches!(out, Outcome::Skipped(_)), "{out:?}");
        assert!(!dir.path().join("state.json").exists());
    }

    #[test]
    fn clear_active_blocks_skips_corrupt_state() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        fs::write(&secret, b"cleanup-corrupt-state-key-01234567").unwrap();
        fs::write(dir.path().join("state.json"), b"garbage").unwrap();
        let out = clear_active_blocks(dir.path(), &secret);
        assert!(matches!(out, Outcome::Skipped(_)), "{out:?}");
        // The unverifiable file is left alone, not overwritten.
        assert_eq!(fs::read(dir.path().join("state.json")).unwrap(), b"garbage");
    }
}
