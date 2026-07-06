//! `frostbited cleanup` — offline teardown of every enforcement artifact.
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

use anyhow::Context;
use tracing::debug;

use crate::{hosts, nftables, paths, state};

/// Options for `frostbited cleanup`, parsed in `main`.
pub struct Opts {
    /// Also delete the state dir (/var/lib/frostbite) and config dir
    /// (/etc/frostbite) once everything else is torn down.
    pub purge: bool,
    /// Skip the running-daemon socket check.
    pub force: bool,
}

/// Per-step result, collected for the end-of-run summary.
enum Outcome {
    Done(String),
    Skipped(String),
    Failed(String),
}

/// What `strip_or_restore` did to the hosts file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostsOutcome {
    /// Readable and already free of a managed region — nothing written.
    AlreadyClean,
    /// Managed region removed from the readable hosts file.
    Stripped,
    /// Hosts file missing/unreadable; recovery copy written in its place.
    Restored,
    /// Hosts file and recovery copy both missing — nothing to restore from,
    /// but also no managed region left anywhere.
    MissingNoBackup,
}

/// Run all cleanup steps, print a summary, and return `Err` only if the
/// hosts strip step failed (everything else is best-effort).
pub fn run(opts: Opts) -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("frostbited cleanup must run as root");
    }

    // Refuse to fight a live daemon: its 1s reconcile tick would re-apply
    // enforcement right behind us. A connect that succeeds means something
    // holds the listener — even a hung daemon might wake up mid-cleanup — so
    // refuse either way. A refused/missing socket (stale after kill -9, or
    // never installed) means not running: proceed.
    if !opts.force {
        match UnixStream::connect(paths::SOCK) {
            Ok(_) => anyhow::bail!(
                "frostbited appears to be running — stop it first \
                 (sudo systemctl stop frostbited) or pass --force"
            ),
            Err(e) => debug!(?e, "daemon socket not accepting — proceeding"),
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
    // re-apply them. Read the secret directly — cleanup must never create
    // one (that's `state::load_or_create_secret`'s job, on daemon startup).
    steps.push((
        "state active blocks",
        match fs::read(paths::SECRET_FILE) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Outcome::Skipped("no HMAC secret — no trusted state to clear".into())
            }
            Err(e) => Outcome::Skipped(format!("reading secret failed ({e}) — skipping")),
            Ok(key) => match state::load(&key) {
                Err(e) => Outcome::Skipped(format!(
                    "state missing or corrupt ({e:#}) — skipping; daemon startup fails open"
                )),
                Ok(st) if st.active.is_empty() => {
                    Outcome::Skipped("no active blocks recorded".into())
                }
                Ok(mut st) => {
                    let n = st.active.len();
                    st.active.clear();
                    match state::save(&st, &key) {
                        Ok(()) => Outcome::Done(format!("cleared {n} active block(s)")),
                        Err(e) => Outcome::Failed(format!("saving cleared state: {e:#}")),
                    }
                }
            },
        },
    ));

    // (g) --purge: delete the state and config dirs. Last, because earlier
    // steps may write there (recovery copy refresh, state save).
    if opts.purge {
        steps.push(("purge dirs", {
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
        }));
    }

    println!("frostbite cleanup summary:");
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
/// missing/unreadable, restore it from the recovery copy at `orig_path`.
///
/// A readable hosts file always wins over the recovery copy: user edits made
/// since the copy was taken must survive, so a readable file is only ever
/// *stripped*, and a restore happens only when there is nothing to strip.
pub(crate) fn strip_or_restore(hosts_path: &str, orig_path: &str) -> anyhow::Result<HostsOutcome> {
    let read_err = match fs::read_to_string(hosts_path) {
        Ok(content) => {
            let stripped = hosts::strip_managed(&content);
            if stripped == content {
                return Ok(HostsOutcome::AlreadyClean);
            }
            hosts::write_atomic(hosts_path, &stripped, hosts::HOSTS_MODE)
                .with_context(|| format!("writing stripped {}", hosts_path))?;
            return Ok(HostsOutcome::Stripped);
        }
        Err(e) => e,
    };
    match fs::read_to_string(orig_path) {
        Ok(orig) => {
            // Defensive: the recovery copy is written pre-stripped, but strip
            // again so an anomalous copy can never resurrect a managed region.
            let stripped = hosts::strip_managed(&orig);
            hosts::write_atomic(hosts_path, &stripped, hosts::HOSTS_MODE)
                .with_context(|| format!("restoring {} from {}", hosts_path, orig_path))?;
            Ok(HostsOutcome::Restored)
        }
        Err(orig_err)
            if orig_err.kind() == io::ErrorKind::NotFound
                && read_err.kind() == io::ErrorKind::NotFound =>
        {
            Ok(HostsOutcome::MissingNoBackup)
        }
        Err(orig_err) => Err(anyhow::anyhow!(
            "hosts file unusable ({read_err}) and recovery copy unusable ({orig_err})"
        )),
    }
}

/// Path of the scratch file `hosts::write_atomic` uses when writing `path`.
/// Keep in lock-step with that function's `"{path}.frostbite.tmp"` naming —
/// if the convention changes there, it must change here too or cleanup will
/// miss the orphans.
fn write_atomic_tmp_path(path: &str) -> String {
    format!("{}.frostbite.tmp", path)
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
    use frostbite_core::{ActiveBlock, Block, Originator, State};
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
        let tmp = dir.path().join("hosts.frostbite.tmp");
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
    fn state_active_clear_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"cleanup-active-clear-key-0123456789";
        let block = Block {
            id: 1,
            name: "reddit".into(),
            domains: vec!["reddit.com".into()],
            apps: vec![],
            allowance_secs_per_day: 0,
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
            }],
            ..Default::default()
        };
        state::save_in(dir.path(), &st, key).unwrap();
        // The exact sequence cleanup's step (f) performs: load, clear, save.
        let mut loaded = state::load_in(dir.path(), key).unwrap();
        assert_eq!(loaded.active.len(), 1);
        loaded.active.clear();
        state::save_in(dir.path(), &loaded, key).unwrap();
        let reloaded = state::load_in(dir.path(), key).unwrap();
        assert!(reloaded.active.is_empty());
        // Everything else survives — cleanup drops the actives, not the config.
        assert_eq!(reloaded.blocks.len(), 1);
        assert_eq!(reloaded.next_id, 2);
    }
}
